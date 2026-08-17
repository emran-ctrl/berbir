//! Shared serializable types used by the server and the frontend.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The class of target a scan runs against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanKind {
    /// A single URL scanned with the YAML template engine.
    Url,
    /// A host/IP port-scanned via RustScan (subprocess).
    PortScan,
    /// A domain whose subdomains are discovered (crt.sh) and batch-scanned.
    Domain,
}

impl ScanKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanKind::Url => "url",
            ScanKind::PortScan => "port_scan",
            ScanKind::Domain => "domain",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Queued,
    Running,
    Completed,
    Failed,
}

impl ScanStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanStatus::Queued => "queued",
            ScanStatus::Running => "running",
            ScanStatus::Completed => "completed",
            ScanStatus::Failed => "failed",
        }
    }
}

/// Severity of a finding, ordered low → high.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn rank(&self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

/// A scan record. Children (subdomain scans) reference their parent via `parent_scan_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scan {
    pub id: Uuid,
    pub kind: ScanKind,
    /// Human-readable target (URL, host:port range, or domain).
    pub target: String,
    pub status: ScanStatus,
    pub parent_scan_id: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Total findings across this scan (and, for domain scans, its children).
    #[serde(default)]
    pub finding_count: i64,
}

/// A single detected vulnerability / exposure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub template_id: String,
    pub name: String,
    pub severity: Severity,
    /// The exact URL that matched.
    pub url: String,
    /// What matched (e.g. the matched word/pattern or port number).
    pub evidence: String,
    pub detected_at: chrono::DateTime<chrono::Utc>,
}

/// Events streamed to the dashboard over WebSocket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScanEvent {
    /// A new finding was detected and persisted.
    Finding(Finding),
    /// Progress within a scan: (message).
    Progress { message: String },
    /// Subdomain discovery for a domain scan.
    SubdomainsFound {
        domain: String,
        subdomains: Vec<String>,
    },
    /// A scan transitioned to a new status.
    StatusChange { scan_id: Uuid, status: ScanStatus },
}

/// A scan plus its aggregated findings (includes child scans for domains).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDetail {
    pub scan: Scan,
    pub findings: Vec<Finding>,
}

/// Metadata about a built-in vulnerability template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateInfo {
    pub id: String,
    pub name: String,
    pub severity: String,
}

/// Payload for creating a new scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScanRequest {
    pub kind: ScanKind,
    /// URL (e.g. `https://example.com`), host for port scans, or domain.
    pub target: String,
    /// Optional port range for `PortScan` (default "1-1000").
    #[serde(default)]
    pub ports: Option<String>,
    /// Restrict a `Url` scan to specific template ids. Empty/absent runs the
    /// default (built-in) templates.
    #[serde(default)]
    pub template_ids: Option<Vec<String>>,
}
