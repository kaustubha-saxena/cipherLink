import os
import sqlite3
from pathlib import Path


DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "cipherlink.db"
DB_PATH = Path(os.environ.get("CIPHERLINK_DB_PATH", str(DEFAULT_DB_PATH)))


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                security_code_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('waiting', 'active', 'closed', 'expired')),
                creator_id TEXT NOT NULL,
                participant_id TEXT
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_sessions_code_hash ON sessions(security_code_hash)")

