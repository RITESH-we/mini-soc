import sqlite3, os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'minisoc.db')
SCHEMA  = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'schema.sql')

def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=15.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA busy_timeout = 10000;")
    return conn

def init_db():
    conn = get_conn()
    # Ensure threat_category exists in alerts table if it already exists
    try:
        cols = [r['name'] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()]
        if cols and 'threat_category' not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN threat_category TEXT DEFAULT 'GENERAL'")
            conn.commit()
    except Exception:
        pass

    with open(SCHEMA, 'r', encoding='utf-8') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    print('[DB] Database schema initialized, WAL enabled, and indexes synchronized.')
