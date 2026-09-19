import sqlite3, os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'minisoc.db')
SCHEMA  = os.path.join(os.path.dirname(__file__), 'schema.sql')

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    conn.executescript(open(SCHEMA).read())
    conn.commit()
    conn.close()
    print('[DB] Database initialized.')
