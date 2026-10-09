"""Endpoints used by the VaultApp demo bank (the protected application).

A session is created here and the caller receives a signed `session_token`. Every later call for that session
must present it (X-Session-Token). That is what stops a stranger who learns a session id from reporting fake
events (and so locking a real user out) or from reading that session's status.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import models, schemas, security, auth
from ..database import get_db
from ..websocket_manager import manager
from .events_routes import _get_or_create_session, process_behavior_event

router = APIRouter(prefix="/user", tags=["user portal"])


@router.get("/my-ip")
def get_my_ip(request: Request):
    return {"ip": security.resolve_client_ip(request) or "127.0.0.1"}


@router.post("/session")
async def create_user_session(request: Request, payload: schemas.UserSessionRequest, db: Session = Depends(get_db)):
    ip = security.resolve_client_ip(request, payload.ip_address)
    if not security.session_create_by_ip.hit(ip or "unknown"):
        raise HTTPException(status_code=429, detail="Too many sessions from this address")
    session_id = str(uuid.uuid4())
    session = _get_or_create_session(db, session_id, payload.user_label.strip()[:60] or "VaultApp user", payload.ip_address, payload.device_info)
    await manager.broadcast({"type": "session_started", "session_id": session_id, "status": session.status})
    return {"session_id": session_id, "status": session.status, "session_token": security.session_token(session_id)}


@router.post("/behavior")
async def receive_behavior(request: Request, payload: schemas.BehaviorEvent, db: Session = Depends(get_db)):
    """Process sanitized telemetry through the rules, ML and baseline pipeline."""
    auth.require_ingest_auth(request, payload.session_id, db)
    real_ip = security.resolve_client_ip(request, payload.ip_address)
    if not security.ingest_by_source.hit(real_ip or "unknown"):
        raise HTTPException(status_code=429, detail="Too many events from this source")
    return await process_behavior_event(payload, db, request_ip=real_ip)


@router.get("/status/{session_id}")
def get_user_session_status(request: Request, session_id: str, db: Session = Depends(get_db)):
    auth.require_ingest_auth(request, session_id, db)
    session = db.query(models.SessionState).filter(models.SessionState.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Unknown session")
    open_lockdown = db.query(models.LockdownRecord).filter(
        models.LockdownRecord.session_id == session.session_id, models.LockdownRecord.unlocked_at.is_(None)).first()
    effective = "locked" if session.status == "locked" or open_lockdown else session.status
    return {
        "session_id": session.session_id,
        "status": {"active": "SAFE", "suspicious": "SUSPICIOUS", "locked": "LOCKDOWN"}.get(effective, "SAFE"),
        "tier": {"active": "allow", "suspicious": "step_up", "locked": "block"}.get(effective, "allow"),
        "last_ip": session.last_ip,
        "updated_at": session.updated_at,
    }
