CREATE TABLE IF NOT EXISTS alerts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT NOT NULL,
    severity         TEXT NOT NULL,
    rule_name        TEXT NOT NULL,
    description      TEXT,
    src_ip           TEXT,
    src_user         TEXT,
    device_name      TEXT,
    process          TEXT,
    event_id         INTEGER,
    mitre_tactic     TEXT,
    mitre_technique  TEXT,
    raw_event        TEXT,
    enriched         INTEGER DEFAULT 0,
    vt_score         TEXT,
    abuse_score      INTEGER,
    status           TEXT DEFAULT 'OPEN'
);

CREATE TABLE IF NOT EXISTS incidents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    severity    TEXT,
    status      TEXT DEFAULT 'OPEN',
    analyst     TEXT DEFAULT 'rites',
    created_at  TEXT,
    updated_at  TEXT,
    summary     TEXT,
    timeline    TEXT,
    iocs        TEXT
);

CREATE TABLE IF NOT EXISTS iocs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT,
    value       TEXT UNIQUE,
    vt_score    TEXT,
    abuse_score INTEGER,
    first_seen  TEXT,
    last_seen   TEXT,
    tags        TEXT
);

CREATE TABLE IF NOT EXISTS network_alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    rule_name       TEXT NOT NULL,
    severity        TEXT NOT NULL,
    src_ip          TEXT,
    dest_port       INTEGER,
    protocol        TEXT,
    details         TEXT,
    mitre_technique TEXT
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address  TEXT UNIQUE,
    reason      TEXT,
    blocked_at  TEXT,
    active      INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS endpoints (
    hostname        TEXT PRIMARY KEY,
    ip_address      TEXT,
    os              TEXT,
    architecture    TEXT,
    agent_version   TEXT,
    last_heartbeat  TEXT,
    status          TEXT DEFAULT 'ONLINE',
    pending_command TEXT DEFAULT NULL,
    risk_score      INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS telemetry_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname     TEXT NOT NULL,
    timestamp    TEXT NOT NULL,
    log_type     TEXT NOT NULL,
    details      TEXT NOT NULL,
    event_id     INTEGER DEFAULT NULL,
    user_name    TEXT DEFAULT NULL,
    src_ip       TEXT DEFAULT NULL,
    process_name TEXT DEFAULT NULL,
    raw_json     TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS entity_risk_scores (
    entity_id    TEXT PRIMARY KEY,
    entity_type  TEXT NOT NULL,
    risk_score   INTEGER DEFAULT 0,
    risk_level   TEXT DEFAULT 'LOW',
    factors      TEXT,
    last_updated TEXT
);
