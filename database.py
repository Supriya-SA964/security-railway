import sqlite3
import os
from datetime import datetime

DB_PATH     = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security.db")
ADMIN_PHONE = "+916362126191"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT,
            phone         TEXT UNIQUE,
            otp           TEXT,
            verified      INTEGER DEFAULT 0,
            role          TEXT DEFAULT 'user',
            registered_at TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS intruders (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            image_path TEXT,
            confidence REAL,
            label      TEXT DEFAULT 'Unknown',
            timestamp  TEXT
        )
    """)
    conn.commit()
    conn.close()
    print("[DB] Ready.")

def save_user(name, phone, otp):
    role = "admin" if phone == ADMIN_PHONE else "user"
    try:
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO users
            (name, phone, otp, verified, role, registered_at)
            VALUES (?,?,?,0,?,?)
        """, (name, phone, otp, role,
              datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
        print(f"[DB] Saved: {name} {phone} role={role}")
    except Exception as e:
        print(f"[DB] Error: {e}")

def verify_user(phone, otp):
    try:
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute("SELECT otp FROM users WHERE phone=?", (phone,))
        row  = c.fetchone()
        if row and row[0] == otp:
            c.execute("UPDATE users SET verified=1 WHERE phone=?", (phone,))
            conn.commit()
            conn.close()
            return True
        conn.close()
        return False
    except:
        return False

def get_user(phone):
    try:
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute("""
            SELECT id, name, phone, verified, role, registered_at
            FROM users WHERE phone=?
        """, (phone,))
        row  = c.fetchone()
        conn.close()
        if row:
            return {
                "id":            row[0],
                "name":          row[1],
                "phone":         row[2],
                "verified":      bool(row[3]),
                "role":          row[4],
                "registered_at": row[5]
            }
        return None
    except:
        return None

def get_all_users():
    try:
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute("""
            SELECT id, name, phone, verified, role, registered_at
            FROM users ORDER BY id DESC
        """)
        rows = c.fetchall()
        conn.close()
        return [{
            "id":            r[0],
            "name":          r[1],
            "phone":         r[2],
            "verified":      bool(r[3]),
            "role":          r[4],
            "registered_at": r[5]
        } for r in rows]
    except:
        return []

def get_verified_phones():
    try:
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute("SELECT phone FROM users WHERE verified=1")
        rows = c.fetchall()
        conn.close()
        return [r[0] for r in rows]
    except:
        return []

def save_intruder(image_path, confidence, label="Unknown"):
    try:
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute("""
            INSERT INTO intruders
            (image_path, confidence, label, timestamp)
            VALUES (?,?,?,?)
        """, (image_path, float(confidence), label,
              datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] Error: {e}")

def get_all_intruders():
    try:
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute("""
            SELECT id, image_path, confidence, label, timestamp
            FROM intruders ORDER BY id DESC
        """)
        rows = c.fetchall()
        conn.close()
        return [{
            "id":         r[0],
            "image_path": r[1],
            "confidence": r[2],
            "label":      r[3],
            "timestamp":  r[4]
        } for r in rows]
    except:
        return []