import sqlite3
import os
from pathlib import Path
from datetime import datetime


DEFAULT_DB_PATH = Path.home() / ".malforge" / "malforge.db"


class Database:
    def __init__(self, db_path=None):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self._ensure_dir()
        self._init_db()

    def _ensure_dir(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS payloads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    format TEXT NOT NULL,
                    encryption_methods TEXT,
                    encryption_keys TEXT,
                    ivs TEXT,
                    target_settings TEXT,
                    output_file TEXT,
                    meta_chain TEXT
                )
            """)
            conn.commit()

    def log_payload(self, format, encryption_methods, encryption_keys, ivs, target_settings, output_file, meta_chain):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO payloads (
                    timestamp, format, encryption_methods, encryption_keys, ivs, target_settings, output_file, meta_chain
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                format,
                encryption_methods,
                encryption_keys,
                ivs,
                target_settings,
                output_file,
                meta_chain
            ))
            conn.commit()

    def get_payloads(self, limit=10):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM payloads ORDER BY timestamp DESC LIMIT ?", (limit,))
            return cursor.fetchall()
