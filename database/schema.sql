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
    status           TEXT DEFAULT 'OPEN',
    threat_category  TEXT DEFAULT 'GENERAL',
    occurrence_count INTEGER DEFAULT 1,
    last_seen        TEXT
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
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address          TEXT UNIQUE,
    reason              TEXT,
    blocked_at          TEXT,
    active              INTEGER DEFAULT 1,
    containment_profile TEXT DEFAULT 'BIDIRECTIONAL_DROP'
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
    risk_score      INTEGER DEFAULT 0,
    profile         TEXT DEFAULT 'standard_workstation'
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

CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT UNIQUE NOT NULL,
    password     TEXT NOT NULL,
    role         TEXT DEFAULT 'analyst',
    display_name TEXT
);

-- High-Performance Enterprise Compound Indexes
CREATE INDEX IF NOT EXISTS idx_alerts_device_ts ON alerts(device_name, timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_user_ts ON alerts(src_user, timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(threat_category);
CREATE INDEX IF NOT EXISTS idx_telemetry_host_ts ON telemetry_logs(hostname, timestamp);
CREATE INDEX IF NOT EXISTS idx_telemetry_type ON telemetry_logs(log_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_network_alerts_ip ON network_alerts(src_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_active ON blocked_ips(active, ip_address);
CREATE INDEX IF NOT EXISTS idx_endpoints_heartbeat ON endpoints(last_heartbeat);
