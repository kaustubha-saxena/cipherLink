import base64
import binascii
import os
from datetime import datetime, timezone

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.api.sessions import router as sessions_router
from app.database.db import initialize_database
from app.services.audit import append_audit_log
from app.services.sessions import get_session, leave_session
from app.websocket.manager import manager


app = FastAPI(title="CipherLink API", version="0.1.0")
allowed_origins = [origin.strip() for origin in os.environ.get("CIPHERLINK_ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",") if origin.strip()]
app.add_middleware(CORSMiddleware, allow_origins=allowed_origins, allow_credentials=False, allow_methods=["GET", "POST"], allow_headers=["Content-Type"])
app.include_router(sessions_router)
MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_IMAGE_CHUNKS = 214
MAX_IMAGE_CHUNK_CIPHERTEXT_BYTES = 48 * 1024 + 16


def decode_base64(value: object) -> bytes:
    if not isinstance(value, str):
        return b""
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return b""


def valid_integer(value: object, minimum: int, maximum: int | None = None) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum and (maximum is None or value <= maximum)


@app.on_event("startup")
def startup() -> None:
    initialize_database()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.websocket("/ws/{session_id}")
async def room_socket(websocket: WebSocket, session_id: str, participant_id: str = Query(min_length=8, max_length=80)):
    session = get_session(session_id)
    creator_waiting = session and session["status"] == "waiting" and participant_id == session["creator_id"]
    participant_active = session and session["status"] == "active" and participant_id in (session["creator_id"], session["participant_id"])
    if not session or not (creator_waiting or participant_active):
        await websocket.close(code=1008, reason="Room is unavailable or participant is not authorized")
        return

    await manager.connect(session_id, websocket)
    if session["status"] == "active":
        await manager.broadcast(session_id, {"type": "participant_joined", "sent_at": datetime.now(timezone.utc).isoformat()})
    try:
        while True:
            payload = await websocket.receive_json()
            latest_session = get_session(session_id)
            if not latest_session or latest_session["status"] not in ("waiting", "active"):
                await websocket.close(code=1008, reason="Room has ended or expired")
                break
            if not isinstance(payload, dict):
                await websocket.send_json({"type": "error", "detail": "Unsupported message format."})
                continue

            payload_type = payload.get("type")
            if payload_type == "ping":
                await websocket.send_json({"type": "pong", "sent_at": datetime.now(timezone.utc).isoformat()})
                continue

            if payload_type == "key_exchange":
                public_key = payload.get("public_key")
                public_key_bytes = decode_base64(public_key)
                if len(public_key_bytes) != 32:
                    await websocket.send_json({"type": "error", "detail": "Invalid X25519 public key."})
                    continue
                is_new, exchange_complete = manager.record_key_exchange(session_id, participant_id)
                if is_new:
                    append_audit_log(session_id, "KEY_EXCHANGE", participant_id, {"algorithm": "X25519"})
                    if exchange_complete:
                        append_audit_log(session_id, "KEY_EXCHANGE_COMPLETE", participant_id, {"kdf": "HKDF-SHA-256", "cipher": "AES-256-GCM"})
                await manager.broadcast(session_id, {
                    "type": "key_exchange",
                    "sender_id": participant_id,
                    "public_key": public_key,
                    "sent_at": datetime.now(timezone.utc).isoformat(),
                })
                continue

            if payload_type == "security_event":
                event_type = payload.get("event")
                if event_type not in {"INTEGRITY_FAILURE", "REPLAY_DETECTED"}:
                    await websocket.send_json({"type": "error", "detail": "Unsupported security event."})
                    continue
                sequence = payload.get("sequence")
                details = {"sequence": sequence} if valid_integer(sequence, 1) else {}
                append_audit_log(session_id, event_type, participant_id, details)
                await manager.broadcast(session_id, {
                    "type": "security_event",
                    "event": event_type,
                    "actor_id": participant_id,
                    "details": details,
                    "sent_at": datetime.now(timezone.utc).isoformat(),
                })
                continue

            if payload_type not in {"message", "image_chunk"}:
                await websocket.send_json({"type": "error", "detail": "Unsupported message format."})
                continue
            if latest_session["status"] != "active":
                await websocket.send_json({"type": "error", "detail": "Waiting for the other participant to join."})
                continue

            sequence = payload.get("sequence")
            nonce = payload.get("nonce")
            ciphertext = payload.get("ciphertext")
            nonce_bytes = decode_base64(nonce)
            ciphertext_bytes = decode_base64(ciphertext)

            if not valid_integer(sequence, 1):
                await websocket.send_json({"type": "error", "detail": "Message sequence is invalid."})
                continue
            max_ciphertext = MAX_IMAGE_CHUNK_CIPHERTEXT_BYTES if payload_type == "image_chunk" else 20000
            if len(nonce_bytes) != 12 or not 16 <= len(ciphertext_bytes) <= max_ciphertext:
                await websocket.send_json({"type": "error", "detail": "Encrypted message format is invalid."})
                continue

            if payload_type == "image_chunk":
                transfer_id = payload.get("transfer_id")
                file_name = payload.get("file_name")
                mime_type = payload.get("mime_type")
                chunk_index = payload.get("chunk_index")
                total_chunks = payload.get("total_chunks")
                file_size = payload.get("file_size")
                metadata_valid = (
                    isinstance(transfer_id, str) and 8 <= len(transfer_id) <= 80
                    and isinstance(file_name, str) and 1 <= len(file_name) <= 255
                    and isinstance(mime_type, str) and mime_type.startswith("image/") and len(mime_type) <= 100
                    and valid_integer(chunk_index, 0)
                    and valid_integer(total_chunks, 1, MAX_IMAGE_CHUNKS)
                    and chunk_index < total_chunks
                    and valid_integer(file_size, 1, MAX_IMAGE_BYTES)
                )
                if not metadata_valid:
                    await websocket.send_json({"type": "error", "detail": "Image chunk metadata is invalid or exceeds the 10 MB limit."})
                    continue

            if not manager.accept_sequence(session_id, participant_id, sequence):
                append_audit_log(session_id, "REPLAY_DETECTED", participant_id, {"sequence": sequence})
                await manager.broadcast(session_id, {
                    "type": "security_event",
                    "event": "REPLAY_DETECTED",
                    "actor_id": participant_id,
                    "details": {"sequence": sequence},
                    "sent_at": datetime.now(timezone.utc).isoformat(),
                })
                await websocket.send_json({"type": "error", "code": "REPLAY_DETECTED", "detail": "Replay detected. The duplicate message was rejected."})
                continue

            sent_at = datetime.now(timezone.utc).isoformat()
            if payload_type == "message":
                append_audit_log(session_id, "MESSAGE_SENT", participant_id, {"sequence": sequence})
                await manager.broadcast(session_id, {
                    "type": "message",
                    "sender_id": participant_id,
                    "sequence": sequence,
                    "nonce": nonce,
                    "ciphertext": ciphertext,
                    "sent_at": sent_at,
                })
            else:
                if chunk_index == total_chunks - 1:
                    append_audit_log(session_id, "IMAGE_TRANSFER", participant_id, {"file_size": file_size, "total_chunks": total_chunks, "mime_type": mime_type})
                await manager.broadcast(session_id, {
                    "type": "image_chunk",
                    "sender_id": participant_id,
                    "sequence": sequence,
                    "transfer_id": transfer_id,
                    "file_name": file_name,
                    "mime_type": mime_type,
                    "chunk_index": chunk_index,
                    "total_chunks": total_chunks,
                    "file_size": file_size,
                    "nonce": nonce,
                    "ciphertext": ciphertext,
                    "sent_at": sent_at,
                })
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(session_id, websocket)
        leave_session(session_id, participant_id)
        await manager.broadcast(session_id, {"type": "participant_left", "sent_at": datetime.now(timezone.utc).isoformat()})

