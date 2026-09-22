import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from database.models import get_conn, check_password

conn = get_conn()
users = conn.execute('SELECT username, password FROM users').fetchall()
print("=== Password Hash Status ===")
for u in users:
    pw = u['password']
    is_hash = (len(pw) == 64)
    print(f"  {u['username']:12s} len={len(pw):3d}  hashed={is_hash}")

print()
print("=== Login verification ===")
test_cases = [
    ("admin",   "minisoc@admin"),
    ("analyst", "minisoc@analyst"),
    ("rites",   "password123"),
    ("admin",   "wrongpassword"),
]
for uname, pw in test_cases:
    row = conn.execute("SELECT * FROM users WHERE LOWER(username)=?", (uname,)).fetchone()
    ok = row and check_password(pw, row['password'])
    print(f"  login({uname!r}, {pw!r}) -> {'OK' if ok else 'FAIL'}")

conn.close()
