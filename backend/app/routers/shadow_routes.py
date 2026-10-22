"""Feature 2: the admin review queue for shadow-mode sessions. Admin-only."""
import datetime as dt

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import auth, models, shadow
from ..config import settings
from ..database import get_db
from ..websocket_manager import manager

router = APIRouter(prefix="/api/shadow", tags=["shadow mode"], dependencies=[Depends(auth.get_current_admin)])


def _intent(db: Session, session_id: str) -> dict:
    transfers = db.query(models.ShadowTransfer).filter_by(session_id=session_id).order_by(models.ShadowTransfer.id).all()
    n_actions = db.query(func.count(models.ShadowAction.id)).filter_by(session_id=session_id).scalar() or 0
    return {"actions": int(n_actions), "transfers": len(transfers), "total_amount": round(sum(t.amount_cents for t in transfers) / 100, 2),
            "recipients": list(dict.fromkeys(t.recipient for t in transfers))[:6]}


def _row(db: Session, c: models.ShadowCase) -> dict:
    left = int((c.deadline - dt.datetime.utcnow()).total_seconds()) if c.status == "pending" else None
    return {"session_id": c.session_id, "user_label": c.user_label, "status": c.status, "entered_at": c.entered_at, "deadline": c.deadline,
            "seconds_left": left, "reasons": c.reasons or [], "ip": c.ip_address, "device": c.device_info, "resolved_at": c.resolved_at,
            "resolved_by": c.resolved_by, **_intent(db, c.session_id)}


@router.get("")
def queue(db: Session = Depends(get_db)):
    shadow.sweep(db)
    rows = db.query(models.ShadowCase).order_by(models.ShadowCase.entered_at.desc()).limit(100).all()
    st = shadow.stats(db)
    return {"enabled": settings.shadow_mode, "review_minutes": settings.shadow_review_minutes, "items": [_row(db, c) for c in rows],
            "counts": st, "false_positives": st["released"], "true_positives": st["confirmed"]}


@router.get("/{session_id}")
def detail(session_id: str, db: Session = Depends(get_db)):
    shadow.sweep(db)
    c = shadow.case_for(db, session_id)
    if not c:
        raise HTTPException(status_code=404, detail="No shadow case for that session")
    actions = db.query(models.ShadowAction).filter_by(session_id=session_id).order_by(models.ShadowAction.id).limit(200).all()
    transfers = db.query(models.ShadowTransfer).filter_by(session_id=session_id).order_by(models.ShadowTransfer.id).all()
    return {**_row(db, c), "intent_log": [{"t": a.timestamp, "action": a.action, "detail": a.detail} for a in actions],
            "shadow_transfers": [{"recipient": t.recipient, "amount": t.amount_cents / 100, "memo": t.memo, "at": t.created_at} for t in transfers]}


@router.post("/{session_id}/release")
async def release(session_id: str, db: Session = Depends(get_db), current=Depends(auth.get_current_admin)):
    try:
        out = shadow.release(db, session_id, current.username)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await manager.broadcast({"type": "shadow_released", "session_id": session_id, "by": current.username})
    return out


@router.post("/{session_id}/confirm")
async def confirm(session_id: str, db: Session = Depends(get_db), current=Depends(auth.get_current_admin)):
    try:
        out = shadow.confirm(db, session_id, current.username)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await manager.broadcast({"type": "lockdown", "session_id": session_id, "reason": ["shadow_confirmed"]})
    await manager.broadcast({"type": "shadow_confirmed", "session_id": session_id, "by": current.username})
    return out
