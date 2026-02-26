-- Privilege Escalation Detector — SQLite Schema

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id        TEXT    NOT NULL UNIQUE,
    rule_id         TEXT    NOT NULL,
    rule_name       TEXT    NOT NULL,
    severity        TEXT    NOT NULL,
    confidence      REAL,
    description     TEXT    NOT NULL,
    pid             INTEGER,
    ppid            INTEGER,
    uid             INTEGER,
    new_uid         INTEGER,
    comm            TEXT,
    parent_comm     TEXT,
    syscall         TEXT,
    filename        TEXT,
    timestamp       INTEGER,
    acknowledged    INTEGER DEFAULT 0,
    acknowledged_by TEXT,
    acknowledged_at TEXT,
    created_at      TEXT    NOT NULL,
    forwarded       INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id    ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_forwarded  ON alerts(forwarded);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type  TEXT,
    pid         INTEGER,
    uid         INTEGER,
    comm        TEXT,
    syscall     TEXT,
    filename    TEXT,
    timestamp   INTEGER,
    created_at  TEXT
);

CREATE TABLE IF NOT EXISTS statistics (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    events_processed    INTEGER DEFAULT 0,
    alerts_generated    INTEGER DEFAULT 0,
    rules_triggered     INTEGER DEFAULT 0,
    anomalies_detected  INTEGER DEFAULT 0,
    session_start       TEXT,
    updated_at          TEXT
);
