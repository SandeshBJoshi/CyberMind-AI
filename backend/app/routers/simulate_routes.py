import asyncio
import random

from fastapi import APIRouter, Depends

from .. import auth, schemas, simulator
from ..database import SessionLocal
from .events_routes import ingest_behavior_event, _get_or_create_session

# The simulator can create sessions and push events, so every route here is admin-only.
router = APIRouter(prefix="/api/simulate", tags=["simulate"], dependencies=[Depends(auth.get_current_admin)])

_normal_task: asyncio.Task | None = None


async def _safe_ingest(payload: schemas.BehaviorEvent, db):
    try:
        return await ingest_behavior_event(payload, db)
    except Exception as e:
        return {"session_id": payload.session_id, "status": "LOCKDOWN", "action_taken": "already_blocked", "detail": str(e)}


async def _normal_traffic_loop():
    session_ids = [f"demo-session-{i}" for i in range(1, 4)]
    while True:
        db = SessionLocal()
        try:
            sid = random.choice(session_ids)
            _get_or_create_session(db, sid, user_label=sid)
            event = simulator.normal_behavior_event(sid)
            await _safe_ingest(schemas.BehaviorEvent(**event), db)
        finally:
            db.close()
        await asyncio.sleep(random.uniform(1.5, 3.5))


@router.post("/start-normal")
async def start_normal_traffic():
    global _normal_task
    if _normal_task is None or _normal_task.done():
        _normal_task = asyncio.create_task(_normal_traffic_loop())
        return {"status": "started"}
    return {"status": "already_running"}


@router.post("/stop-normal")
async def stop_normal_traffic():
    global _normal_task
    if _normal_task and not _normal_task.done():
        _normal_task.cancel()
        return {"status": "stopped"}
    return {"status": "not_running"}


# IP change: proxy hopping / identity churn (MITRE T1090 is the closest ATT&CK technique)
@router.post("/manual/identity-churn")
async def manual_identity_churn(req: schemas.IdentityChurnRequest):
    """Spoofs a new IP address or device User-Agent to exercise the location / device change rules."""
    db = SessionLocal()
    try:
        session = _get_or_create_session(db, req.session_id, user_label=req.session_id)
        home_established = False
        if not session.last_ip:
            # A brand-new target has no "home" network yet, so there would be nothing to change away from.
            # Give it one first (a normal event from the owner's usual place), then perform the hop.
            await _safe_ingest(schemas.BehaviorEvent(
                session_id=req.session_id, event_type="behavior", ip_address="82.64.12.9",
                device_info="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0 Safari/537.36",
                keystroke_avg_interval_ms=220.0, keystroke_std_interval_ms=35.0, typing_speed_cpm=220.0,
                mouse_click_rate=1.2, mouse_move_entropy=0.6, session_duration_sec=120.0), db)
            db.refresh(session)
            home_established = True
        ev = schemas.BehaviorEvent(
            session_id=req.session_id,
            event_type="behavior",
            ip_address=req.new_ip,
            device_info=req.new_device,
            keystroke_avg_interval_ms=220.0,
            keystroke_std_interval_ms=35.0,
            typing_speed_cpm=220.0,
            mouse_click_rate=1.2,
            mouse_move_entropy=0.6,
            session_duration_sec=300.0,
            extra={"technique": "T1090-Proxy-Hopping-Identity-Churn"},
        )
        r = await _safe_ingest(ev, db)
    finally:
        db.close()

    return {
        "technique": "T1090 - Proxy Hopping & Identity Churn",
        "home_established": home_established,
        "session_id": req.session_id,
        "new_ip": req.new_ip,
        "new_device": req.new_device,
        "status": r.get("status"),
        "action_taken": r.get("action_taken"),
        "result": r,
    }
