//! SQLite data layer (sqlx). Manual row mapping keeps UUID/chrono handling explicit.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use berbir_shared::{Finding, Scan, ScanKind, ScanStatus, Severity};

pub async fn connect(url: &str) -> Result<SqlitePool> {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(8)
        .connect(url)
        .await
        .context("failed to open sqlite database")?;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("failed to run migrations")?;
    Ok(pool)
}

fn to_rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339()
}

fn from_rfc3339(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn row_to_scan(row: &sqlx::sqlite::SqliteRow) -> Scan {
    Scan {
        id: Uuid::parse_str(row.get("id")).unwrap_or_default(),
        kind: match row.get::<String, _>("kind").as_str() {
            "port_scan" => ScanKind::PortScan,
            "domain" => ScanKind::Domain,
            _ => ScanKind::Url,
        },
        target: row.get("target"),
        status: match row.get::<String, _>("status").as_str() {
            "running" => ScanStatus::Running,
            "completed" => ScanStatus::Completed,
            "failed" => ScanStatus::Failed,
            _ => ScanStatus::Queued,
        },
        parent_scan_id: row
            .get::<Option<String>, _>("parent_scan_id")
            .and_then(|s| Uuid::parse_str(&s).ok()),
        created_at: from_rfc3339(row.get("created_at")),
        started_at: row
            .get::<Option<String>, _>("started_at")
            .map(|s| from_rfc3339(&s)),
        finished_at: row
            .get::<Option<String>, _>("finished_at")
            .map(|s| from_rfc3339(&s)),
        finding_count: row.get("finding_count"),
    }
}

fn row_to_finding(row: &sqlx::sqlite::SqliteRow) -> Finding {
    Finding {
        id: Uuid::parse_str(row.get("id")).unwrap_or_default(),
        scan_id: Uuid::parse_str(row.get("scan_id")).unwrap_or_default(),
        template_id: row.get("template_id"),
        name: row.get("name"),
        severity: match row.get::<String, _>("severity").as_str() {
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => Severity::Info,
        },
        url: row.get("url"),
        evidence: row.get("evidence"),
        detected_at: from_rfc3339(row.get("detected_at")),
    }
}

pub async fn insert_scan(pool: &SqlitePool, scan: &Scan) -> Result<()> {
    sqlx::query(
        "INSERT INTO scans (id, kind, target, status, parent_scan_id, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(scan.id.to_string())
    .bind(scan.kind.as_str())
    .bind(&scan.target)
    .bind(scan.status.as_str())
    .bind(scan.parent_scan_id.map(|id| id.to_string()))
    .bind(to_rfc3339(scan.created_at))
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn set_scan_status(
    pool: &SqlitePool,
    scan_id: Uuid,
    status: ScanStatus,
    started_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
) -> Result<()> {
    sqlx::query(
        "UPDATE scans SET status = ?, started_at = COALESCE(?, started_at), finished_at = COALESCE(?, finished_at) WHERE id = ?",
    )
    .bind(status.as_str())
    .bind(started_at.map(to_rfc3339))
    .bind(finished_at.map(to_rfc3339))
    .bind(scan_id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn insert_findings(pool: &SqlitePool, findings: &[Finding]) -> Result<()> {
    let mut tx = pool.begin().await?;
    for f in findings {
        sqlx::query(
            "INSERT INTO findings (id, scan_id, template_id, name, severity, url, evidence, detected_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(f.id.to_string())
        .bind(f.scan_id.to_string())
        .bind(&f.template_id)
        .bind(&f.name)
        .bind(f.severity.as_str())
        .bind(&f.url)
        .bind(&f.evidence)
        .bind(to_rfc3339(f.detected_at))
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn list_scans(pool: &SqlitePool) -> Result<Vec<Scan>> {
    let rows = sqlx::query(
        "SELECT s.*, \
                (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS finding_count \
         FROM scans s \
         ORDER BY s.created_at DESC \
         LIMIT 200",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(row_to_scan).collect())
}

pub async fn get_scan(pool: &SqlitePool, scan_id: Uuid) -> Result<Option<Scan>> {
    let row = sqlx::query(
        "SELECT s.*, \
                (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS finding_count \
         FROM scans s WHERE s.id = ?",
    )
    .bind(scan_id.to_string())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| row_to_scan(&r)))
}

/// Findings for a scan, plus findings of all descendant scans (domain scans).
pub async fn get_findings_recursive(pool: &SqlitePool, scan_id: Uuid) -> Result<Vec<Finding>> {
    let rows = sqlx::query(
        "WITH RECURSIVE tree(id) AS ( \
             SELECT id FROM scans WHERE id = ? \
             UNION ALL \
             SELECT s.id FROM scans s JOIN tree t ON s.parent_scan_id = t.id \
         ) \
         SELECT f.* FROM findings f \
         WHERE f.scan_id IN (SELECT id FROM tree) \
         ORDER BY f.detected_at ASC",
    )
    .bind(scan_id.to_string())
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(row_to_finding).collect())
}

/// Delete a scan, every descendant scan (e.g. a domain scan's subdomain
/// children), and their findings. Returns `false` if the scan doesn't exist.
pub async fn delete_scan(pool: &SqlitePool, scan_id: Uuid) -> Result<bool> {
    let mut tx = pool.begin().await?;

    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scans WHERE id = ?")
        .bind(scan_id.to_string())
        .fetch_one(&mut *tx)
        .await?;
    if exists == 0 {
        return Ok(false);
    }

    // Recursively collect the scan and all descendants so children of a domain
    // scan (and any findings) are removed too.
    let tree = "WITH RECURSIVE tree(id) AS ( \
                    SELECT id FROM scans WHERE id = ? \
                    UNION ALL \
                    SELECT s.id FROM scans s JOIN tree t ON s.parent_scan_id = t.id \
                ) SELECT id FROM tree";
    sqlx::query(&format!("DELETE FROM findings WHERE scan_id IN ({tree})"))
        .bind(scan_id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query(&format!("DELETE FROM scans WHERE id IN ({tree})"))
        .bind(scan_id.to_string())
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn delete_scan_removes_descendants_and_findings() {
        let path = std::env::temp_dir().join(format!("berbir-delete-{}.db", Uuid::new_v4()));
        let pool = connect(&format!("sqlite:{}?mode=rwc", path.display()))
            .await
            .unwrap();

        let parent = Scan {
            id: Uuid::new_v4(),
            kind: ScanKind::Domain,
            target: "example.com".into(),
            status: ScanStatus::Completed,
            parent_scan_id: None,
            created_at: Utc::now(),
            started_at: Some(Utc::now()),
            finished_at: None,
            finding_count: 0,
        };
        let child = Scan {
            id: Uuid::new_v4(),
            kind: ScanKind::Url,
            target: "https://a.example.com".into(),
            status: ScanStatus::Completed,
            parent_scan_id: Some(parent.id),
            created_at: Utc::now(),
            started_at: Some(Utc::now()),
            finished_at: None,
            finding_count: 0,
        };
        insert_scan(&pool, &parent).await.unwrap();
        insert_scan(&pool, &child).await.unwrap();
        insert_findings(
            &pool,
            &[Finding {
                id: Uuid::new_v4(),
                scan_id: child.id,
                template_id: "t".into(),
                name: "n".into(),
                severity: Severity::Medium,
                url: "http://x".into(),
                evidence: "e".into(),
                detected_at: Utc::now(),
            }],
        )
        .await
        .unwrap();

        assert!(delete_scan(&pool, parent.id).await.unwrap());
        assert!(get_scan(&pool, parent.id).await.unwrap().is_none());
        assert!(get_scan(&pool, child.id).await.unwrap().is_none());
        assert!(
            get_findings_recursive(&pool, child.id)
                .await
                .unwrap()
                .is_empty()
        );
        // Deleting a scan that no longer exists reports false.
        assert!(!delete_scan(&pool, parent.id).await.unwrap());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
    }
}
