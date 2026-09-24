import sqlite3, os, hashlib, hmac

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'minisoc.db')
SCHEMA  = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'schema.sql')

# ── Password Hashing ──────────────────────────────────────────
_HASH_PREFIX = "minisoc2026:"  # cheap static salt prefix

def hash_password(plain: str) -> str:
    """Return a hex SHA-256 digest of (prefix + plain).  Not bcrypt but no extra deps."""
    return hashlib.sha256((_HASH_PREFIX + plain).encode()).hexdigest()

def check_password(plain: str, stored: str) -> bool:
    """Constant-time comparison of a plaintext attempt against a stored hash."""
    candidate = hash_password(plain)
    # Also accept legacy plaintext passwords so existing installations keep working
    # until migrated (they'll be hashed on next successful login — see app.py login route)
    return hmac.compare_digest(candidate, stored) or hmac.compare_digest(plain, stored)

def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=15.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA busy_timeout = 10000;")
    return conn

def init_db():
    conn = get_conn()
    # Auto-migrate columns if tables already exist
    try:
        cols = [r['name'] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()]
        if cols and 'threat_category' not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN threat_category TEXT DEFAULT 'GENERAL'")
            conn.commit()
    except Exception:
        pass

    try:
        ep_cols = [r['name'] for r in conn.execute("PRAGMA table_info(endpoints)").fetchall()]
        if ep_cols and 'profile' not in ep_cols:
            conn.execute("ALTER TABLE endpoints ADD COLUMN profile TEXT DEFAULT 'standard_workstation'")
            conn.commit()
    except Exception:
        pass

    try:
        block_cols = [r['name'] for r in conn.execute("PRAGMA table_info(blocked_ips)").fetchall()]
        if block_cols and 'containment_profile' not in block_cols:
            conn.execute("ALTER TABLE blocked_ips ADD COLUMN containment_profile TEXT DEFAULT 'BIDIRECTIONAL_DROP'")
            conn.commit()
    except Exception:
        pass

    try:
        alert_cols = [r['name'] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()]
        if alert_cols and 'occurrence_count' not in alert_cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN occurrence_count INTEGER DEFAULT 1")
            conn.commit()
        if alert_cols and 'last_seen' not in alert_cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN last_seen TEXT")
            conn.commit()
    except Exception:
        pass

    with open(SCHEMA, 'r', encoding='utf-8') as f:
        conn.executescript(f.read())

    # Seed default user accounts if empty
    try:
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count == 0:
            default_users = [
                ('admin',   hash_password('minisoc@admin'),  'admin',   'SOC Administrator'),
                ('analyst', hash_password('minisoc@analyst'), 'analyst', 'Tier 1/2 Analyst'),
                ('rites',   hash_password('password123'),    'admin',   'Ritesh (Lead SecOps)')
            ]
            conn.executemany("INSERT INTO users (username, password, role, display_name) VALUES (?, ?, ?, ?)", default_users)
            conn.commit()
    except Exception:
        pass

    # Migrate existing plaintext passwords to hashes (runs once per user)
    try:
        users = conn.execute("SELECT id, password FROM users").fetchall()
        for u in users:
            pw = u['password']
            # A SHA-256 hex digest is exactly 64 chars; shorter = plaintext
            if len(pw) != 64:
                conn.execute("UPDATE users SET password=? WHERE id=?", (hash_password(pw), u['id']))
        conn.commit()
    except Exception:
        pass

    conn.commit()
    conn.close()
    print('[DB] Database schema initialized, WAL enabled, and indexes synchronized.')
