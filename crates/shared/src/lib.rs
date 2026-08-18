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
    pub tags: Vec<String>,
}

/// Preset template selection modes. Resolved server-side to a template id set
/// via [`template_matches_mode`]; `Deep` matches every template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanMode {
    Simple,
    Medium,
    Deep,
}

impl ScanMode {
    /// Tags that select templates for this mode. `Deep` matches everything.
    pub fn tags(self) -> &'static [&'static str] {
        match self {
            ScanMode::Simple => &[
                "default-login",
                "exposure",
                "misconfig",
                "takeover",
                "debug",
                "unauth",
                "auth-bypass",
                "directory-listing",
            ],
            ScanMode::Medium => &[
                "default-login",
                "exposure",
                "misconfig",
                "takeover",
                "debug",
                "unauth",
                "auth-bypass",
                "directory-listing",
                "rce",
                "sqli",
                "lfi",
                "ssti",
                "xss",
                "ssrf",
                "file-upload",
                "cve",
                "disclosure",
                "config",
            ],
            ScanMode::Deep => &[],
        }
    }
}

/// Whether a template (given its `tags`) is part of a scan mode.
pub fn template_matches_mode(mode: ScanMode, tags: &[String]) -> bool {
    match mode {
        ScanMode::Deep => true,
        ScanMode::Simple | ScanMode::Medium => {
            tags.iter().any(|t| mode.tags().contains(&t.as_str()))
        }
    }
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
    /// Optional preset template selection. Resolved server-side; combined with
    /// `template_ids` if both are present. Absent keeps the `template_ids`
    /// behavior.
    #[serde(default)]
    pub mode: Option<ScanMode>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn mode_tags_are_curated() {
        assert!(!ScanMode::Simple.tags().contains(&"cve"));
        assert!(ScanMode::Medium.tags().contains(&"cve"));
    }

    #[test]
    fn simple_matches_only_its_tags() {
        assert!(template_matches_mode(
            ScanMode::Simple,
            &tags(&["exposure"])
        ));
        assert!(template_matches_mode(
            ScanMode::Simple,
            &tags(&["default-login"])
        ));
        assert!(!template_matches_mode(ScanMode::Simple, &tags(&["cve"])));
        assert!(!template_matches_mode(ScanMode::Simple, &tags(&["rce"])));
        assert!(!template_matches_mode(ScanMode::Simple, &tags(&[])));
    }

    #[test]
    fn medium_adds_vuln_classes() {
        assert!(template_matches_mode(ScanMode::Medium, &tags(&["cve"])));
        assert!(template_matches_mode(ScanMode::Medium, &tags(&["sqli"])));
        assert!(!template_matches_mode(ScanMode::Medium, &tags(&["osint"])));
    }

    #[test]
    fn deep_matches_everything() {
        assert!(template_matches_mode(ScanMode::Deep, &tags(&[])));
        assert!(template_matches_mode(ScanMode::Deep, &tags(&["anything"])));
    }
}
