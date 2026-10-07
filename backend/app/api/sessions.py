from fastapi import APIRouter, HTTPException, Request

from app.models.session import CreateSessionRequest, JoinSessionRequest, LeaveSessionRequest
from app.services.audit import append_audit_log, get_session_audit_log
from app.services.sessions import create_session, get_session, join_session, leave_session
from app.utils.rate_limit import anonymize_address, limiter


router = APIRouter(prefix="/session", tags=["sessions"])


def enforce_rate_limit(request: Request, route_name: str, limit: int) -> None:
    forwarded_for = request.headers.get("x-forwarded-for", "")
    address = forwarded_for.split(",", 1)[0].strip() if forwarded_for else ""
    if not address:
        address = request.client.host if request.client else "unknown"
    retry_after, should_log = limiter.consume(f"{route_name}:{address}", limit)
    if retry_after:
        if should_log:
            append_audit_log(None, "RATE_LIMIT_TRIGGERED", details={"route": route_name, "client_hash": anonymize_address(address)})
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please wait before trying again.",
            headers={"Retry-After": str(retry_after)},
        )


@router.post("/create")
def create(payload: CreateSessionRequest, request: Request):
    enforce_rate_limit(request, "session_create", 10)
    return create_session(payload.creator_id)


@router.post("/join")
def join(payload: JoinSessionRequest, request: Request):
    enforce_rate_limit(request, "session_join", 5)
    session = join_session(payload.security_code, payload.participant_id)
    if not session:
        raise HTTPException(status_code=404, detail="Invalid, expired, or unavailable room code.")
    return session


@router.get("/{session_id}/logs")
def read_logs(session_id: str, participant_id: str):
    session = get_session(session_id)
    if not session or participant_id not in (session["creator_id"], session["participant_id"]):
        raise HTTPException(status_code=403, detail="You are not a participant in this room.")
    return get_session_audit_log(session_id)


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

