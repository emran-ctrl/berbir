//! Job queue and scan orchestration.
//!
//! A tokio `mpsc` inbox feeds a worker loop. Each scan job acquires a slot on
//! a concurrency semaphore, then runs:
//!   * `Url`      → template engine
//!   * `PortScan` → RustScan subprocess (skipped if binary missing)
//!   * `Domain`   → crt.sh subdomain discovery, then a child scan per subdomain
//!
//! Live events are fanned out through per-scan `broadcast` channels via
//! [`EventBus`], which the WebSocket endpoint subscribes to.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use sqlx::SqlitePool;
use tokio::sync::{Mutex, Semaphore, broadcast, mpsc};
use uuid::Uuid;

use berbir_engine::Scanner;
use berbir_shared::{CreateScanRequest, Finding, Scan, ScanEvent, ScanKind, ScanStatus, Severity};

use crate::db;

const MAX_CONCURRENT_SCANS: usize = 2;
const MAX_SUBDOMAIN_SCANS: usize = 5;
const DEFAULT_PORT_RANGE: &str = "1-1000";

/// Per-scan event fan-out used by the WebSocket endpoint.
#[derive(Clone, Default)]
pub struct EventBus {
    channels: Arc<Mutex<HashMap<Uuid, broadcast::Sender<ScanEvent>>>>,
}

impl EventBus {
    pub async fn create(&self, scan_id: Uuid) {
        let (tx, _rx) = broadcast::channel(256);
        self.channels.lock().await.insert(scan_id, tx);
    }

    pub async fn send(&self, scan_id: Uuid, event: ScanEvent) {
        if let Some(tx) = self.channels.lock().await.get(&scan_id) {
            let _ = tx.send(event);
        }
    }

    pub async fn subscribe(&self, scan_id: Uuid) -> Option<broadcast::Receiver<ScanEvent>> {
        self.channels
            .lock()
            .await
            .get(&scan_id)
            .map(|tx| tx.subscribe())
    }
}

enum JobCommand {
    Run(Scan),
}

/// Submit new scans to the worker.
#[derive(Clone)]
pub struct JobManager {
    db: SqlitePool,
    tx: mpsc::Sender<JobCommand>,
    pub events: EventBus,
}

struct Worker {
    core: Arc<WorkerCore>,
    rx: mpsc::Receiver<JobCommand>,
}

#[derive(Clone)]
struct WorkerCore {
    db: SqlitePool,
    scanner: Scanner,
    events: EventBus,
    client: reqwest::Client,
    concurrency: Arc<Semaphore>,
}

impl JobManager {
    pub fn start(db: SqlitePool, scanner: Scanner, events: EventBus) -> Self {
        let (tx, rx) = mpsc::channel(64);
        let core = Arc::new(WorkerCore {
            db: db.clone(),
            scanner,
            events: events.clone(),
            client: reqwest::Client::new(),
            concurrency: Arc::new(Semaphore::new(MAX_CONCURRENT_SCANS)),
        });
        tokio::spawn(Worker { core, rx }.run());
        Self { db, tx, events }
    }

    /// Persist and enqueue a scan job. Returns the created scan.
    pub async fn submit(&self, req: CreateScanRequest) -> anyhow::Result<Scan> {
        validate(&req)?;
        let scan = Scan {
            id: Uuid::new_v4(),
            kind: req.kind,
            target: req.target.trim().to_string(),
            status: ScanStatus::Queued,
            parent_scan_id: None,
            created_at: Utc::now(),
            started_at: None,
            finished_at: None,
            finding_count: 0,
        };
        db::insert_scan(&self.db, &scan).await?;
        self.events.create(scan.id).await;
        self.events
            .send(
                scan.id,
                ScanEvent::StatusChange {
                    scan_id: scan.id,
                    status: scan.status,
                },
            )
            .await;
        self.tx
            .send(JobCommand::Run(scan.clone()))
            .await
            .map_err(|_| anyhow::anyhow!("job queue shut down"))?;
        Ok(scan)
    }
}

impl Worker {
    async fn run(mut self) {
        while let Some(cmd) = self.rx.recv().await {
            let JobCommand::Run(scan) = cmd;
            let permit = match self.core.concurrency.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let core = self.core.clone();
            tokio::spawn(async move {
                let _permit = permit;
                core.handle_scan(scan).await;
            });
        }
        tracing::info!("job worker stopped");
    }
}

impl WorkerCore {
    async fn handle_scan(&self, scan: Scan) {
        self.set_status(&scan, ScanStatus::Running).await;
        let result = match scan.kind {
            ScanKind::Url => self.run_url_scan(&scan, &scan.target).await,
            ScanKind::PortScan => self.run_port_scan(&scan).await,
            ScanKind::Domain => self.run_domain_scan(&scan).await,
        };
        let status = match result {
            Ok(()) => ScanStatus::Completed,
            Err(e) => {
                tracing::error!("scan {} ({}) failed: {e}", scan.id, scan.target);
                ScanStatus::Failed
            }
        };
        self.set_status(&scan, status).await;
    }

    /// Dedicated handler for subdomain child scans (always `Url` kind). Kept
    /// separate from [`handle_scan`] so the spawned task never re-enters the
    /// `Domain` branch (which would make the future's `Send` bound circular).
    async fn handle_child_url(&self, scan: Scan) {
        self.set_status(&scan, ScanStatus::Running).await;
        let result = self.run_url_scan(&scan, &scan.target).await;
        let status = match result {
            Ok(()) => ScanStatus::Completed,
            Err(e) => {
                tracing::error!("scan {} ({}) failed: {e}", scan.id, scan.target);
                ScanStatus::Failed
            }
        };
        self.set_status(&scan, status).await;
    }

    async fn run_url_scan(&self, scan: &Scan, base_url: &str) -> anyhow::Result<()> {
        let findings = self.scanner.run(scan.id, base_url).await;
        self.persist(scan, findings).await;
        Ok(())
    }

    async fn run_port_scan(&self, scan: &Scan) -> anyhow::Result<()> {
        let ports = berbir_engine::port_scanner::scan_ports(&scan.target, DEFAULT_PORT_RANGE).await;
        let ports = match ports {
            Ok(p) => p,
            Err(berbir_engine::EngineError::RustScanMissing) => {
                tracing::warn!(
                    "rustscan binary not found; skipping port scan for {}",
                    scan.target
                );
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };
        let findings: Vec<Finding> = ports
            .into_iter()
            .map(|port| Finding {
                id: Uuid::new_v4(),
                scan_id: scan.id,
                template_id: "port-scan".into(),
                name: "Open port detected".into(),
                severity: Severity::Info,
                url: format!("tcp://{}:{port}", scan.target),
                evidence: format!("port {port} is open"),
                detected_at: Utc::now(),
            })
            .collect();
        self.persist(scan, findings).await;
        Ok(())
    }

    async fn run_domain_scan(&self, scan: &Scan) -> anyhow::Result<()> {
        let domain = scan.target.clone();
        let subdomains =
            berbir_engine::discovery::enumerate_subdomains(&self.client, &domain).await?;
        self.events
            .send(
                scan.id,
                ScanEvent::SubdomainsFound {
                    domain: domain.clone(),
                    subdomains: subdomains.clone(),
                },
            )
            .await;
        tracing::info!(
            "domain scan {} found {} subdomains",
            domain,
            subdomains.len()
        );
        if subdomains.is_empty() {
            return Ok(());
        }

        let child_sem = Arc::new(Semaphore::new(MAX_SUBDOMAIN_SCANS));
        let mut tasks = Vec::new();
        for sub in subdomains {
            let child = Scan {
                id: Uuid::new_v4(),
                kind: ScanKind::Url,
                target: format!("https://{sub}"),
                status: ScanStatus::Queued,
                parent_scan_id: Some(scan.id),
                created_at: Utc::now(),
                started_at: None,
                finished_at: None,
                finding_count: 0,
            };
            if let Err(e) = db::insert_scan(&self.db, &child).await {
                tracing::error!("failed to persist child scan {sub}: {e}");
                continue;
            }
            self.events.create(child.id).await;

            let sem = child_sem.clone();
            let core = self.clone();
            tasks.push(tokio::spawn(async move {
                let _permit = match sem.acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                core.handle_child_url(child).await;
            }));
        }
        for task in tasks {
            let _ = task.await;
        }
        Ok(())
    }

    async fn persist(&self, scan: &Scan, findings: Vec<Finding>) {
        if findings.is_empty() {
            return;
        }
        if let Err(e) = db::insert_findings(&self.db, &findings).await {
            tracing::error!("failed to persist findings for {}: {e}", scan.id);
            return;
        }
        for f in &findings {
            self.events
                .send(scan.id, ScanEvent::Finding(f.clone()))
                .await;
        }
    }

    async fn set_status(&self, scan: &Scan, status: ScanStatus) {
        let (started, finished) = match status {
            ScanStatus::Running => (Some(Utc::now()), None),
            ScanStatus::Completed | ScanStatus::Failed => (None, Some(Utc::now())),
            _ => (None, None),
        };
        if let Err(e) = db::set_scan_status(&self.db, scan.id, status, started, finished).await {
            tracing::error!("failed to update status for {}: {e}", scan.id);
            return;
        }
        self.events
            .send(
                scan.id,
                ScanEvent::StatusChange {
                    scan_id: scan.id,
                    status,
                },
            )
            .await;
    }
}

fn validate(req: &CreateScanRequest) -> anyhow::Result<()> {
    if req.target.trim().is_empty() {
        return Err(anyhow::anyhow!("target must not be empty"));
    }
    match req.kind {
        ScanKind::Url => {
            let u = url::Url::parse(&req.target)
                .map_err(|_| anyhow::anyhow!("invalid URL target: {}", req.target))?;
            if !matches!(u.scheme(), "http" | "https") {
                return Err(anyhow::anyhow!("target URL must use http or https"));
            }
        }
        ScanKind::Domain => {
            if req.target.contains('/') || req.target.contains(':') {
                return Err(anyhow::anyhow!(
                    "domain target must be a bare hostname, e.g. example.com"
                ));
            }
        }
        ScanKind::PortScan => {
            if req.target.contains(':') {
                return Err(anyhow::anyhow!(
                    "port scan target must be a hostname or IP, not host:port"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_rejects_bad_targets() {
        let ok_url = CreateScanRequest {
            kind: ScanKind::Url,
            target: "https://example.com".into(),
            ports: None,
        };
        assert!(validate(&ok_url).is_ok());

        let bad = CreateScanRequest {
            kind: ScanKind::Url,
            target: "not a url".into(),
            ports: None,
        };
        assert!(validate(&bad).is_err());

        let domain = CreateScanRequest {
            kind: ScanKind::Domain,
            target: "example.com/path".into(),
            ports: None,
        };
        assert!(validate(&domain).is_err());

        let portscan = CreateScanRequest {
            kind: ScanKind::PortScan,
            target: "127.0.0.1:80".into(),
            ports: None,
        };
        assert!(validate(&portscan).is_err());
    }
}
