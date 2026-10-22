import datetime as dt
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas, auth
from ..database import get_db
from ..websocket_manager import manager

router = APIRouter(prefix="/api/lockdown", tags=["lockdown"])


@router.post("/unlock")
async def unlock_session(
    payload: schemas.UnlockRequest,
    db: Session = Depends(get_db),
    current=Depends(auth.get_current_admin),
):
    session = db.query(models.SessionState).filter(models.SessionState.session_id == payload.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Unknown session")
    record = (
        db.query(models.LockdownRecord)
        .filter(models.LockdownRecord.session_id == payload.session_id, models.LockdownRecord.unlocked_at.is_(None))
        .order_by(models.LockdownRecord.triggered_at.desc())
        .first()
    )
    if session.status != "locked" and not record:
        raise HTTPException(status_code=400, detail="Session is not currently locked")

    session.status = "active"
    session.locked_at = None

    if record:
        record.unlocked_at = dt.datetime.utcnow()
        record.unlocked_by = current.username

    db.commit()

    await manager.broadcast({"type": "unlocked", "session_id": payload.session_id, "unlocked_by": current.username})
    return {"session_id": payload.session_id, "status": "active", "unlocked_by": current.username}
