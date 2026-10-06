import os
from datetime import datetime, timezone

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.api.sessions import router as sessions_router
from app.database.db import initialize_database
from app.services.sessions import get_session
from app.websocket.manager import manager


app = FastAPI(title="CipherLink API", version="0.1.0")
allowed_origins = [origin.strip() for origin in os.environ.get("CIPHERLINK_ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",") if origin.strip()]
app.add_middleware(CORSMiddleware, allow_origins=allowed_origins, allow_credentials=False, allow_methods=["GET", "POST"], allow_headers=["Content-Type"])
app.include_router(sessions_router)


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
    await manager.broadcast(session_id, {"type": "participant_joined", "sent_at": datetime.now(timezone.utc).isoformat()})
    try:
        while True:
            payload = await websocket.receive_json()
            latest_session = get_session(session_id)
            if not latest_session or latest_session["status"] not in ("waiting", "active"):
                await websocket.close(code=1008, reason="Room has ended or expired")
                break
            if latest_session["status"] == "waiting":
                await websocket.send_json({"type": "error", "detail": "Waiting for the other participant to join."})
                continue
            if not isinstance(payload, dict) or payload.get("type") != "message":
                await websocket.send_json({"type": "error", "detail": "Unsupported message format."})
                continue
            message = payload.get("message")
            if not isinstance(message, str) or not message.strip() or len(message) > 4000:
                await websocket.send_json({"type": "error", "detail": "Messages must contain 1–4000 characters."})
                continue
            await manager.broadcast(session_id, {
                "type": "message",
                "sender_id": participant_id,
                "message": message,
                "sent_at": datetime.now(timezone.utc).isoformat(),
            })
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(session_id, websocket)
        await manager.broadcast(session_id, {"type": "participant_left", "sent_at": datetime.now(timezone.utc).isoformat()})

