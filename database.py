import sqlite3, json
from datetime import datetime

DB_NAME = "webguard.db"

def connect():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with connect() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            created_at TEXT NOT NULL,
            score INTEGER NOT NULL,
            result_json TEXT NOT NULL
        )""")

def save_scan(target, result):
    with connect() as conn:
        cur = conn.execute("INSERT INTO scans(target, created_at, score, result_json) VALUES (?, ?, ?, ?)",
            (target, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), result["score"], json.dumps(result)))
        return cur.lastrowid

def get_scans():
    with connect() as conn:
        return [dict(x) for x in conn.execute("SELECT id,target,created_at,score FROM scans ORDER BY id DESC").fetchall()]

def get_scan(scan_id):
    with connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None
