-- Scans: url / port_scan / domain targets, with a parent/child hierarchy
-- so a domain scan owns the subdomain scans it spawns.
CREATE TABLE IF NOT EXISTS scans (
    id             TEXT PRIMARY KEY,
    kind           TEXT NOT NULL,
    target         TEXT NOT NULL,
    status         TEXT NOT NULL,
    parent_scan_id TEXT REFERENCES scans(id),
    created_at     TEXT NOT NULL,
    started_at     TEXT,
    finished_at    TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    template_id TEXT NOT NULL,
    name        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    url         TEXT NOT NULL,
    evidence    TEXT NOT NULL,
    detected_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_parent_id ON scans(parent_scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
