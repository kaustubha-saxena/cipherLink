from fastapi import APIRouter, HTTPException

from app.models.session import CreateSessionRequest, JoinSessionRequest, LeaveSessionRequest
from app.services.sessions import create_session, get_session, join_session, leave_session


router = APIRouter(prefix="/session", tags=["sessions"])


@router.post("/create")
def create(payload: CreateSessionRequest):
    return create_session(payload.creator_id)


@router.post("/join")
def join(payload: JoinSessionRequest):
    session = join_session(payload.security_code, payload.participant_id)
    if not session:
        raise HTTPException(status_code=404, detail="Invalid, expired, or unavailable room code.")
    return session


@router.get("/{session_id}")
def read(session_id: str):
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Room not found.")
    if session["status"] == "expired":
        raise HTTPException(status_code=410, detail="This room has expired.")
    return session


@router.post("/{session_id}/leave")
def leave(session_id: str, payload: LeaveSessionRequest):
    session = leave_session(session_id, payload.participant_id)
    if not session:
        raise HTTPException(status_code=404, detail="Room or participant not found.")
    return session

