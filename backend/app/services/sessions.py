import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

from app.database.db import connect
from app.security.codes import create_code, hash_code


SESSION_TTL_SECONDS = max(60, int(os.environ.get("SESSION_TTL_SECONDS", "600")))


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.isoformat()


def mark_expired(connection: sqlite3.Connection, session_id: str | None = None) -> None:
    query = "UPDATE sessions SET status = 'expired' WHERE status IN ('waiting', 'active') AND expires_at <= ?"
    params: tuple[str, ...] = (iso(now_utc()),)
    if session_id:
        query += " AND id = ?"
        params += (session_id,)
    connection.execute(query, params)


def public_session(row: sqlite3.Row) -> dict:
    return {"id": row["id"], "created_at": row["created_at"], "expires_at": row["expires_at"], "status": row["status"]}


def create_session(creator_id: str) -> dict:
    created_at = now_utc()
    expires_at = created_at + timedelta(seconds=SESSION_TTL_SECONDS)
    session_id = str(uuid.uuid4())
    with connect() as connection:
        mark_expired(connection)
        code = create_code()
        while connection.execute(
            "SELECT 1 FROM sessions WHERE security_code_hash = ? AND status IN ('waiting', 'active')",
            (hash_code(code),),
        ).fetchone():
            code = create_code()
        connection.execute(
            "INSERT INTO sessions (id, security_code_hash, created_at, expires_at, status, creator_id) VALUES (?, ?, ?, ?, 'waiting', ?)",
            (session_id, hash_code(code), iso(created_at), iso(expires_at), creator_id),
        )
    return {"id": session_id, "security_code": code, "created_at": iso(created_at), "expires_at": iso(expires_at), "status": "waiting"}


def join_session(code: str, participant_id: str) -> dict | None:
    with connect() as connection:
        mark_expired(connection)
        row = connection.execute(
            "SELECT * FROM sessions WHERE security_code_hash = ? AND status = 'waiting'", (hash_code(code),)
        ).fetchone()
        if not row or row["creator_id"] == participant_id:
            return None
        connection.execute("UPDATE sessions SET status = 'active', participant_id = ? WHERE id = ? AND status = 'waiting'", (participant_id, row["id"]))
        joined = connection.execute("SELECT * FROM sessions WHERE id = ?", (row["id"],)).fetchone()
        return public_session(joined)


def get_session(session_id: str) -> dict | None:
    with connect() as connection:
        mark_expired(connection, session_id)
        row = connection.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if not row:
            return None
        return {**public_session(row), "creator_id": row["creator_id"], "participant_id": row["participant_id"]}


def leave_session(session_id: str, participant_id: str) -> dict | None:
    with connect() as connection:
        mark_expired(connection, session_id)
        row = connection.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if not row or participant_id not in (row["creator_id"], row["participant_id"]):
            return None
        connection.execute("UPDATE sessions SET status = 'closed' WHERE id = ?", (session_id,))
        return {**public_session(connection.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()), "creator_id": row["creator_id"], "participant_id": row["participant_id"]}

