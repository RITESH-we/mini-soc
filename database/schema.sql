CREATE TABLE IF NOT EXISTS alerts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT NOT NULL,
    severity         TEXT NOT NULL,
    rule_name        TEXT NOT NULL,
    description      TEXT,
    src_ip           TEXT,
    src_user         TEXT,
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