//! On-demand Markdown report generation.

use std::collections::BTreeMap;

use berbir_shared::{Finding, Scan, Severity};

/// Render a scan (and, for domain scans, its aggregated findings) as Markdown.
pub fn render_markdown(scan: &Scan, findings: &[Finding]) -> String {
    let mut out = String::new();
    out.push_str("# Scan Report\n\n");
    out.push_str(&format!("- **Target:** {}\n", scan.target));
    out.push_str(&format!("- **Kind:** {}\n", scan.kind.as_str()));
    out.push_str(&format!("- **Status:** {}\n", scan.status.as_str()));
    out.push_str(&format!(
        "- **Created:** {}\n",
        scan.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    if let Some(t) = scan.started_at {
        out.push_str(&format!(
            "- **Started:** {}\n",
            t.format("%Y-%m-%d %H:%M:%S UTC")
        ));
    }
    if let Some(t) = scan.finished_at {
        out.push_str(&format!(
            "- **Finished:** {}\n",
            t.format("%Y-%m-%d %H:%M:%S UTC")
        ));
    }

    let counts = severity_counts(findings);
    out.push_str(&format!(
        "- **Findings:** {} (critical: {}, high: {}, medium: {}, low: {}, info: {})\n",
        findings.len(),
        counts.get(&Severity::Critical).copied().unwrap_or(0),
        counts.get(&Severity::High).copied().unwrap_or(0),
        counts.get(&Severity::Medium).copied().unwrap_or(0),
        counts.get(&Severity::Low).copied().unwrap_or(0),
        counts.get(&Severity::Info).copied().unwrap_or(0),
    ));

    out.push_str("\n## Findings\n\n");

    if findings.is_empty() {
        out.push_str("_No findings were detected._\n");
        return out;
    }

    out.push_str("| # | Severity | Template | URL | Evidence |\n");
    out.push_str("|---|----------|----------|-----|----------|\n");
    for (i, f) in findings.iter().enumerate() {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            i + 1,
            f.severity.as_str(),
            cell(&f.template_id),
            cell(&f.url),
            cell(&f.evidence),
        ));
    }
    out
}

fn severity_counts(findings: &[Finding]) -> BTreeMap<Severity, usize> {
    let mut counts = BTreeMap::new();
    for f in findings {
        *counts.entry(f.severity).or_insert(0) += 1;
    }
    counts
}

/// Escape a cell so it is safe inside a Markdown table row.
fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace(['\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn finding(severity: Severity) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            scan_id: Uuid::new_v4(),
            template_id: "env-file-exposure".into(),
            name: "Sensitive Environment File Exposed".into(),
            severity,
            url: "https://example.com/.env".into(),
            evidence: "DB_PASSWORD".into(),
            detected_at: Utc::now(),
        }
    }

    fn scan() -> Scan {
        Scan {
            id: Uuid::new_v4(),
            kind: berbir_shared::ScanKind::Url,
            target: "https://example.com".into(),
            status: berbir_shared::ScanStatus::Completed,
            parent_scan_id: None,
            created_at: Utc::now(),
            started_at: None,
            finished_at: None,
            finding_count: 1,
        }
    }

    #[test]
    fn report_includes_findings_and_counts() {
        let report = render_markdown(&scan(), &[finding(Severity::High)]);
        assert!(report.contains("# Scan Report"));
        assert!(report.contains("**Target:** https://example.com"));
        assert!(report.contains("(critical: 0, high: 1, medium: 0, low: 0, info: 0)"));
        assert!(report.contains("| 1 | high | env-file-exposure |"));
    }

    #[test]
    fn empty_report() {
        let report = render_markdown(&scan(), &[]);
        assert!(report.contains("_No findings were detected._"));
    }

    #[test]
    fn evidence_is_table_safe() {
        let mut f = finding(Severity::Medium);
        f.evidence = "a|b\nc".into();
        let report = render_markdown(&scan(), &[f]);
        assert!(report.contains("a\\|b c"));
        assert!(!report.contains("a|b\nc"));
    }
}
