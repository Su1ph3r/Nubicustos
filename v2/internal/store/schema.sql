-- Embedded SQLite schema for nubicustos v2. Pure-Go driver (modernc.org/sqlite),
-- no CGO, so it ships in the single static binary. Statements are idempotent.

CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    provider    TEXT NOT NULL,
    account     TEXT,
    identity    TEXT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    finding_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id            TEXT NOT NULL,
    scan_id       TEXT NOT NULL,
    check_id      TEXT NOT NULL,
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL,
    status        TEXT NOT NULL,
    provider      TEXT NOT NULL,
    service       TEXT NOT NULL,
    account       TEXT,
    region        TEXT,
    resource_id   TEXT,
    resource_type TEXT,
    description   TEXT,
    remediation   TEXT,
    poc           TEXT,
    reachable     TEXT,
    raw           TEXT NOT NULL,           -- full Finding JSON for lossless round-trip
    first_seen    TEXT,
    last_seen     TEXT,
    PRIMARY KEY (scan_id, id),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan     ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_account  ON findings(account);

-- Placeholder tables for later phases (graph, compliance) so the schema shape
-- is stable from the start.
CREATE TABLE IF NOT EXISTS principals (
    scan_id TEXT NOT NULL,
    id      TEXT NOT NULL,
    type    TEXT,
    account TEXT,
    raw     TEXT,
    PRIMARY KEY (scan_id, id)
);

CREATE TABLE IF NOT EXISTS edges (
    scan_id TEXT NOT NULL,
    src     TEXT NOT NULL,
    dst     TEXT NOT NULL,
    kind    TEXT NOT NULL,
    raw     TEXT
);

CREATE TABLE IF NOT EXISTS attack_paths (
    scan_id TEXT NOT NULL,
    id      TEXT NOT NULL,
    score   INTEGER,
    raw     TEXT,
    PRIMARY KEY (scan_id, id)
);

CREATE TABLE IF NOT EXISTS compliance_results (
    scan_id   TEXT NOT NULL,
    framework TEXT NOT NULL,
    control   TEXT NOT NULL,
    status    TEXT NOT NULL,
    raw       TEXT
);
