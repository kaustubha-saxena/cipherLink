import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

from app.database.db import connect
from app.security.codes import create_code, hash_code
from app.services.audit import append_audit_log


SESSION_TTL_SECONDS = max(60, int(os.environ.get("SESSION_TTL_SECONDS", "600")))


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.isoformat()


def mark_expired(connection: sqlite3.Connection, session_id: str | None = None) -> None:
    query_expired = "SELECT id FROM sessions WHERE status IN ('waiting', 'active') AND expires_at <= ?"
    expired_params: tuple[str, ...] = (iso(now_utc()),)
    if session_id:
        query_expired += " AND id = ?"
        expired_params += (session_id,)
    expired_rows = connection.execute(query_expired, expired_params).fetchall()
    for row in expired_rows:
        append_audit_log(row["id"], "SESSION_EXPIRED")

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
    append_audit_log(session_id, "SESSION_CREATED", creator_id)
    return {"id": session_id, "security_code": code, "created_at": iso(created_at), "expires_at": iso(expires_at), "status": "waiting"}


def join_session(code: str, participant_id: str) -> dict | None:
    audit_session_id = None
    audit_reason = None
    result = None
    with connect() as connection:
        mark_expired(connection)
        row = connection.execute("SELECT * FROM sessions WHERE security_code_hash = ?", (hash_code(code),)).fetchone()
        if not row:
            audit_reason = "invalid_or_expired_code"
        else:
            audit_session_id = row["id"]
            if row["status"] != "waiting" or row["creator_id"] == participant_id:
                audit_reason = "unavailable_or_same_participant"
            else:
                connection.execute("UPDATE sessions SET status = 'active', participant_id = ? WHERE id = ? AND status = 'waiting'", (participant_id, row["id"]))
                joined = connection.execute("SELECT * FROM sessions WHERE id = ?", (row["id"],)).fetchone()
                result = public_session(joined)
    if audit_session_id:
        append_audit_log(audit_session_id, "JOIN_ATTEMPT", participant_id)
    if audit_reason:
        append_audit_log(audit_session_id, "JOIN_FAILURE", participant_id, {"reason": audit_reason})
        return None
    if audit_session_id:
        append_audit_log(audit_session_id, "JOIN_SUCCESS", participant_id)
    return result


def get_session(session_id: str) -> dict | None:
    with connect() as connection:
        mark_expired(connection, session_id)
        row = connection.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if not row:
            return None
        return {**public_session(row), "creator_id": row["creator_id"], "participant_id": row["participant_id"]}


def leave_session(session_id: str, participant_id: str) -> dict | None:
    should_log = False
    with connect() as connection:
        mark_expired(connection, session_id)
        row = connection.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if not row or participant_id not in (row["creator_id"], row["participant_id"]):
            return None
        if row["status"] not in ("closed", "expired"):
            connection.execute("UPDATE sessions SET status = 'closed' WHERE id = ?", (session_id,))
            should_log = True
        result = {**public_session(connection.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()), "creator_id": row["creator_id"], "participant_id": row["participant_id"]}
    if should_log:
        append_audit_log(session_id, "USER_DISCONNECTED", participant_id)
    return result

