import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DB_DIR = ROOT / "logs"
DB_DIR.mkdir(parents=True, exist_ok=True)  

DB_PATH = DB_DIR / "access_control.db"

with sqlite3.connect(DB_PATH.as_posix()) as conn:
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id TEXT UNIQUE NOT NULL
        )
    """)
    test_ids = [("12345",), ("67890",), ("ABCDE",)]
    cur.executemany("INSERT OR IGNORE INTO employees (employee_id) VALUES (?)", test_ids)
    conn.commit()

print(f"Database initialized successfully at {DB_PATH}")