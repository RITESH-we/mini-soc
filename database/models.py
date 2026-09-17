import sqlite3, os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'minisoc.db')
SCHEMA  = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'schema.sql')

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    with open(SCHEMA, 'r', encoding='utf-8') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    print('[DB] Database schema initialized and synchronized.')
