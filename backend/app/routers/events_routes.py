import ipaddress
import uuid
import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import update
from sqlalchemy.orm import Session

from .. import models, schemas, security, auth, baseline, notify
from ..config import settings
from ..database import get_db
from .. import rule_engine, ml_engine, decision_engine, shadow as shadow_mod
from ..websocket_manager import manager

router = APIRouter(prefix="/api", tags=["events"])

# Actions that must not run while a session is only SUSPICIOUS (they need a completed step-up first)
SENSITIVE_ACTIONS = {"transfer_funds", "change_password", "export_data", "delete_account", "add_payee"}


def _is_public_ip(ip_value: str | None) -> bool:
    if not ip_value:
        return False
    ip_str = str(ip_value).strip()
    if not ip_str or ip_str.lower() in {"unknown", "detecting…", "detecting..."}:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


# kept for backwards compatibility with older imports
_resolve_client_ip = security.resolve_client_ip


def _get_or_create_session(db: Session, session_id: str, user_label="demo_user", ip=None, device=None) -> models.SessionState:
    s = db.query(models.SessionState).filter(models.SessionState.session_id == session_id).first()
    if not s:
        s = models.SessionState(session_id=session_id, user_label=user_label, last_ip=ip, last_device=device)
        db.add(s)
        db.commit()
        db.refresh(s)
    return s


def _trigger_ip_change_lockdown(db: Session, session: models.SessionState, real_ip: str) -> dict | None:
    """Hard-lock on a public IP change. Only used when IP_CHANGE_POLICY=lock (the original demo behaviour)."""
    if session.status == "locked" or not real_ip or not session.last_ip:
        return None
    if not _is_public_ip(real_ip) or not _is_public_ip(session.last_ip):
        return None
    if real_ip == session.last_ip:
        return None

    session.status = "locked"
    session.locked_at = dt.datetime.utcnow()
    db.add(models.LockdownRecord(session_id=session.session_id, reason=["ip_or_device_change"]))
    ev = models.SecurityEvent(
        session_id=session.session_id, event_type="ip_change", ip_address=real_ip, device_info=session.last_device,
        details={"trigger": "real_ip_mismatch", "stored_ip": session.last_ip, "observed_ip": real_ip,
                 "_decision": {"tier": "block", "reasons": [{"code": "ip_or_device_change", "points": 6.0, "text": "Public IP changed (policy: lock)"}]}},
        rule_flags=["ip_or_device_change"], ml_anomaly=False, internal_score=6.0, status="LOCKDOWN", action_taken="session_locked",
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)
    return {"session_id": session.session_id, "status": "LOCKDOWN", "action_taken": "session_locked", "event_id": ev.id,
            "rule_flags": ev.rule_flags, "timestamp": str(ev.timestamp)}


def _has_public_ip_mismatch(session: models.SessionState, payload_ip: str | None, request_ip: str | None) -> bool:
    candidate = request_ip or payload_ip
    if not candidate or not session.last_ip:
        return False
    if not _is_public_ip(candidate) or not _is_public_ip(session.last_ip):
        return False
    return candidate != session.last_ip


class _NullBroadcaster:
    @staticmethod
    async def broadcast(_payload):
        return None


# ---------------------------------------------------------------------------------------------
# The detection pipeline (no HTTP concerns, so tests and the attack lab can call it directly)
# ---------------------------------------------------------------------------------------------
async def process_behavior_event(payload: schemas.BehaviorEvent, db: Session, request_ip: str | None = None, quiet: bool = False):
    """quiet=True (used by the attack lab) skips the live broadcast and webhook so test traffic never reaches real consoles."""
    bc = _NullBroadcaster if quiet else manager
    session = _get_or_create_session(db, payload.session_id, ip=payload.ip_address, device=payload.device_info)

    if session.status == "locked":
        ev = models.SecurityEvent(
            session_id=session.session_id, event_type=payload.event_type, ip_address=payload.ip_address, device_info=payload.device_info,
            details=payload.model_dump(exclude={"session_id", "event_type", "ip_address", "device_info"}),
            rule_flags=["session_locked"], ml_anomaly=False, internal_score=0.0, status="LOCKDOWN", action_taken="blocked_session_locked",
        )
        db.add(ev)
        db.commit()
        await bc.broadcast({"type": "event_blocked", "session_id": session.session_id})
        raise HTTPException(status_code=423, detail="Session is locked. Admin authentication required to unlock.")

    public_mismatch = _has_public_ip_mismatch(session, payload.ip_address, request_ip)

    # Legacy policy: any public IP change is an immediate lockdown (kept as an option for demos)
    if public_mismatch and settings.ip_change_policy == "lock":
        ip_change = _trigger_ip_change_lockdown(db, session, request_ip or payload.ip_address or "")
        if ip_change:
            await bc.broadcast({"type": "security_event", "session_id": session.session_id, "event_type": "ip_change", "status": "LOCKDOWN",
                                     "rule_flags": ["ip_or_device_change"], "ml_anomaly": False, "action_taken": "session_locked",
                                     "tier": "block", "reasons": [{"code": "ip_or_device_change", "points": 6.0, "text": "Public IP changed (policy: lock)"}],
                                     "timestamp": ip_change["timestamp"]})
            await bc.broadcast({"type": "lockdown", "session_id": session.session_id, "reason": ["ip_or_device_change"]})
            return {"session_id": session.session_id, "status": "LOCKDOWN", "tier": "block", "action_taken": "session_locked"}

    # 1. Rule engine
    rule_flags = rule_engine.evaluate_rules(db, session, payload)
    extras: list[dict] = []
    if public_mismatch:
        if "ip_or_device_change" not in rule_flags:
            rule_flags.append("ip_or_device_change")
        extras.append({"code": "public_ip_change", "points": 2.0, "text": "Session now comes from a different public IP address"})

    # 2. Per-user baseline: is this far from THIS user's own normal?
    user_key = session.user_label
    dev = baseline.deviation(db, user_key, payload)
    if dev:
        pts = baseline.points_for(dev["max_z"])
        if pts:
            rule_flags.append("baseline_deviation")
            extras.append({"code": "baseline_deviation", "points": pts,
                           "text": f"{dev['feature']} is {dev['max_z']:.1f} standard deviations from this user's normal"})
        known_ips, known_devices = baseline.known_endpoints(db, user_key)
        if payload.device_info and payload.device_info not in known_devices and (not payload.ip_address or payload.ip_address not in known_ips):
            rule_flags.append("new_device_for_user")

    # 3. ML anomaly engine, only for events that actually carry all behaviour features
    ml_is_anomaly = False
    if payload.event_type == "behavior" and ml_engine.has_features(payload):
        ml_is_anomaly, _raw = ml_engine.get_ml_engine().is_anomaly(ml_engine.vectorize(payload))

    # 4. Decision: status + tier + reasons. The numeric score is for audit only.
    decision = decision_engine.decide_detailed(rule_flags, ml_is_anomaly, extras)
    status_label, internal_score = decision["status"], decision["score"]

    # Feature 2: an uncertain identity-change session may be contained in shadow mode instead of asked for step-up
    db.refresh(session)
    if session.status == "shadow":
        shadow_mod.sweep(db)                       # a case past its review deadline falls back to step-up
        db.refresh(session)
    shadow_now = session.status == "active" and shadow_mod.eligible(decision, rule_flags)
    if shadow_now:
        decision["reasons"].append({"code": "shadow_contained", "points": 0.0, "text": shadow_mod.REASON_TEXT})
    entered_shadow = False

    # Concurrent telemetry can finish out of order. Preserve a lockdown another request committed meanwhile.
    db.refresh(session)
    if session.status == "locked":
        status_label = "LOCKDOWN"
        action_taken = "blocked_session_locked"
    else:
        action_taken = "none"

    if status_label == "LOCKDOWN":
        if session.status != "locked":
            locked_at = dt.datetime.utcnow()
            result = db.execute(
                update(models.SessionState)
                .where(models.SessionState.session_id == session.session_id, models.SessionState.status != "locked")
                .values(status="locked", locked_at=locked_at)
            )
            if result.rowcount:
                db.add(models.LockdownRecord(session_id=session.session_id, reason=rule_flags + (["ml_anomaly"] if ml_is_anomaly else [])))
                shadow_mod.mark_escalated(db, session.session_id)
                action_taken = "session_locked"
            else:
                db.refresh(session)
                action_taken = "blocked_session_locked"
    elif shadow_now:
        result = db.execute(
            update(models.SessionState)
            .where(models.SessionState.session_id == session.session_id, models.SessionState.status == "active")
            .values(status="shadow")
        )
        if result.rowcount:
            shadow_mod.enter(db, session, decision, payload.ip_address, payload.device_info)
            status_label, action_taken, entered_shadow = "SHADOW", "shadow_contained", True
        else:
            db.refresh(session)
            status_label, action_taken = ("LOCKDOWN", "blocked_session_locked") if session.status == "locked" else ("SUSPICIOUS", "step_up_required")
    elif session.status == "shadow":
        status_label = "SHADOW"                    # sticky: only an admin decision (or the deadline) ends shadow mode
    elif status_label == "SUSPICIOUS":
        result = db.execute(
            update(models.SessionState)
            .where(models.SessionState.session_id == session.session_id, models.SessionState.status != "locked")
            .values(status="suspicious")
        )
        if result.rowcount:
            action_taken = "step_up_required"
        else:
            db.refresh(session)
            status_label = "LOCKDOWN"
            action_taken = "blocked_session_locked"
    elif session.status == "suspicious":
        # A pending step-up is sticky: clean-looking traffic must not clear it, only verification can
        # (customer re-authentication or an admin). Otherwise an intruder just behaves for one tick.
        status_label = "SUSPICIOUS"
    else:
        result = db.execute(
            update(models.SessionState)
            .where(models.SessionState.session_id == session.session_id, models.SessionState.status != "locked")
            .values(status="active")
        )
        if not result.rowcount:
            db.refresh(session)
            status_label = "LOCKDOWN"
            action_taken = "blocked_session_locked"

    tier = decision_engine.TIER_FOR_STATUS[status_label]

    if payload.ip_address and not public_mismatch:
        session.last_ip = payload.ip_address
    if payload.device_info and not (status_label != "SAFE" and "new_device_for_user" in rule_flags):
        session.last_device = payload.device_info

    # Only clean traffic teaches the baseline (otherwise an attacker could train it to accept them)
    if status_label == "SAFE" and payload.event_type == "behavior":
        baseline.update(db, user_key, payload, payload.ip_address, payload.device_info)

    details = payload.model_dump(exclude={"session_id", "event_type", "ip_address", "device_info"})
    details["_decision"] = {"tier": tier, "reasons": decision["reasons"]}
    ev = models.SecurityEvent(
        session_id=session.session_id, event_type=payload.event_type, ip_address=payload.ip_address, device_info=payload.device_info,
        details=details, rule_flags=rule_flags, ml_anomaly=ml_is_anomaly, internal_score=internal_score, status=status_label, action_taken=action_taken,
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)

    msg = {"type": "security_event", "session_id": session.session_id, "event_type": ev.event_type, "status": status_label, "tier": tier,
           "rule_flags": rule_flags, "ml_anomaly": ml_is_anomaly, "action_taken": action_taken, "reasons": decision["reasons"],
           "timestamp": str(ev.timestamp)}
    await bc.broadcast(msg)
    if entered_shadow:
        await bc.broadcast({"type": "session_shadowed", "session_id": session.session_id, "user_label": session.user_label, "reasons": decision["reasons"],
                            "ip": payload.ip_address})
    if status_label == "LOCKDOWN":
        await bc.broadcast({"type": "lockdown", "session_id": session.session_id, "reason": rule_flags})
        if action_taken == "session_locked" and not quiet:
            notify.send_webhook({"event": "session_locked", **msg})

    # Clients only ever learn the qualitative outcome, never the score or the reasons
    return {"session_id": session.session_id, "status": status_label, "tier": tier, "action_taken": action_taken}


# Backwards-compatible name (the simulator and the existing tests call this directly)
ingest_behavior_event = process_behavior_event


# ---------------------------------------------------------------------------------------------
# HTTP routes
# ---------------------------------------------------------------------------------------------
@router.post("/sessions/start")
async def start_session(payload: schemas.StartSessionRequest, db: Session = Depends(get_db), _admin=Depends(auth.get_current_admin)):
    session_id = str(uuid.uuid4())
    session = _get_or_create_session(db, session_id, payload.user_label, payload.ip_address, payload.device_info)
    await manager.broadcast({"type": "session_started", "session_id": session_id, "status": session.status})
    return {"session_id": session_id, "status": session.status, "session_token": security.session_token(session_id)}


@router.post("/events/behavior")
async def ingest_behavior_route(request: Request, payload: schemas.BehaviorEvent, db: Session = Depends(get_db)):
    auth.require_ingest_auth(request, payload.session_id, db)
    ip = security.resolve_client_ip(request, payload.ip_address)
    if not security.ingest_by_source.hit(ip or "unknown"):
        raise HTTPException(status_code=429, detail="Too many events from this source")
    return shadow_mod.client_view(await process_behavior_event(payload, db, request_ip=ip))


@router.post("/protected-action")
async def protected_action(request: Request, payload: schemas.ProtectedActionRequest, db: Session = Depends(get_db)):
    """The policy decision point a real app calls before a sensitive action."""
    auth.require_ingest_auth(request, payload.session_id, db)
    session = db.query(models.SessionState).filter(models.SessionState.session_id == payload.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Unknown session")
    if session.status == "locked":
        raise HTTPException(status_code=423, detail="Access blocked: session is in LOCKDOWN. Admin unlock required.")
    if session.status == "shadow":                  # the sandbox looks normal; the attempt is recorded, nothing real happens
        shadow_mod.log_action(db, session.session_id, "protected_action", {"action": payload.action})
        db.commit()
    elif session.status == "suspicious" and payload.action in SENSITIVE_ACTIONS:
        raise HTTPException(status_code=428, detail="Step-up verification required before this action.")
    return {"session_id": session.session_id, "action": payload.action, "result": "executed"}


@router.get("/sessions/{session_id}/verify")
def verify_session(request: Request, session_id: str, db: Session = Depends(get_db)):
    """Policy decision point: should the app let this session continue? allow | step_up | deny."""
    auth.require_ingest_auth(request, session_id, db)
    s = db.query(models.SessionState).filter_by(session_id=session_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Unknown session")
    decision = {"locked": "deny", "suspicious": "step_up"}.get(s.status, "allow")
    return {"session_id": session_id, "decision": decision}


@router.post("/sessions/{session_id}/step-up/clear")
async def clear_step_up(session_id: str, db: Session = Depends(get_db), current=Depends(auth.get_current_admin)):
    """Record that extra verification (MFA, call-back, analyst review) succeeded. This is where a real MFA provider plugs in."""
    s = db.query(models.SessionState).filter_by(session_id=session_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Unknown session")
    if s.status != "suspicious":
        raise HTTPException(status_code=400, detail="Session is not waiting for step-up")
    s.status = "active"
    db.add(models.SecurityEvent(session_id=session_id, event_type="step_up_cleared", status="SAFE", rule_flags=[], action_taken=f"cleared_by_{current.username}",
                                details={"_decision": {"tier": "allow", "reasons": [{"code": "step_up_cleared", "points": 0, "text": f"Verified by {current.username}"}]}}))
    db.commit()
    await manager.broadcast({"type": "step_up_cleared", "session_id": session_id, "by": current.username})
    return {"session_id": session_id, "status": "active"}


@router.get("/sessions")
def list_sessions(db: Session = Depends(get_db), _admin=Depends(auth.get_current_admin)):
    shadow_mod.sweep(db)
    sessions = db.query(models.SessionState).order_by(models.SessionState.updated_at.desc()).all()
    open_ids = {r.session_id for r in db.query(models.LockdownRecord.session_id).filter(models.LockdownRecord.unlocked_at.is_(None)).all()}
    result = []
    for session in sessions:
        locked = session.status == "locked" or session.session_id in open_ids
        result.append({
            "session_id": session.session_id, "user_label": session.user_label,
            "status": "locked" if locked else session.status,
            "last_ip": session.last_ip, "last_device": session.last_device,
            "updated_at": session.updated_at, "locked_at": session.locked_at,
        })
    return result
