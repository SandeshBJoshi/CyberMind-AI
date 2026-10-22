import sqlite3

conn = sqlite3.connect('security.db')
conn.row_factory = sqlite3.Row
cur = conn.cursor()

cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [r[0] for r in cur.fetchall()]
print('Tables:', tables)

for t in tables:
    cur.execute(f"PRAGMA table_info({t})")
    cols = [r[1] for r in cur.fetchall()]
    print(f"\n{t} columns: {cols}")

print("\n=== SESSIONS (last 10) ===")
try:
    cur.execute("SELECT * FROM sessions ORDER BY rowid DESC LIMIT 10")
    rows = cur.fetchall()
    for r in rows:
        print(dict(r))
except Exception as e:
    print("Error:", e)

print("\n=== OPEN LOCKDOWNS ===")
try:
    cur.execute("SELECT * FROM lockdown_records WHERE resolved_at IS NULL")
    rows = cur.fetchall()
    for r in rows:
        print(dict(r))
    if not rows:
        print("None")
except Exception as e:
    print("Error:", e)

conn.close()
