import hashlib
import json
from datetime import datetime, timezone

from app.database.db import connect


ZERO_HASH = "0" * 64


def _canonical_hash(record: dict) -> str:
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def append_audit_log(session_id: str | None, event_type: str, actor_id: str | None = None, details: dict | None = None) -> dict:
    chain_id = session_id or "global"
    created_at = datetime.now(timezone.utc).isoformat()
    details = details or {}
    details_json = json.dumps(details, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    with connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        latest = connection.execute(
            "SELECT sequence, entry_hash FROM audit_logs WHERE chain_id = ? ORDER BY sequence DESC LIMIT 1",
            (chain_id,),
        ).fetchone()
        sequence = latest["sequence"] + 1 if latest else 1
        previous_hash = latest["entry_hash"] if latest else ZERO_HASH
        record = {
            "sequence": sequence,
            "session_id": session_id,
            "created_at": created_at,
            "event_type": event_type,
            "actor_id": actor_id,
            "details": details,
            "previous_hash": previous_hash,
        }
        entry_hash = _canonical_hash(record)
        connection.execute(
            "INSERT INTO audit_logs (chain_id, sequence, session_id, created_at, event_type, actor_id, details_json, previous_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (chain_id, sequence, session_id, created_at, event_type, actor_id, details_json, previous_hash, entry_hash),
        )
    return {**record, "entry_hash": entry_hash}


def get_session_audit_log(session_id: str) -> dict:
    with connect() as connection:
        rows = connection.execute(
            "SELECT sequence, session_id, created_at, event_type, actor_id, details_json, previous_hash, entry_hash FROM audit_logs WHERE session_id = ? ORDER BY sequence",
            (session_id,),
        ).fetchall()

    records = []
    expected_previous_hash = ZERO_HASH
    first_bad_record = None
    for row in rows:
        details = json.loads(row["details_json"])
        record = {
            "sequence": row["sequence"],
            "session_id": row["session_id"],
            "created_at": row["created_at"],
            "event_type": row["event_type"],
            "actor_id": row["actor_id"],
            "details": details,
            "previous_hash": row["previous_hash"],
        }
        calculated_hash = _canonical_hash(record)
        if first_bad_record is None and (
            record["sequence"] != len(records) + 1
            or record["previous_hash"] != expected_previous_hash
            or calculated_hash != row["entry_hash"]
        ):
            first_bad_record = record["sequence"]
        expected_previous_hash = row["entry_hash"]
        records.append({**record, "entry_hash": row["entry_hash"]})

    return {
        "records": records,
        "integrity_valid": first_bad_record is None,
        "first_bad_record": first_bad_record,
    }
