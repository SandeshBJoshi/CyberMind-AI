"""Feature 2: shadow mode, a fourth verdict between step-up and block.

Blocking a suspected session tells the attacker they were caught, and wrongly blocking a real customer is costly. For sessions that are
suspicious but NOT certain, CYBERMIND serves the session from a sandbox: balances look normal, transfers appear to succeed, nothing real
moves, and every action is recorded as the attacker-intent log.

Rules that keep it safe:
  * Entered only when the evidence includes an IDENTITY-CHANGE signal (new device and network, or a large departure from the user's
    own baseline). Volume alone (bursts, typing speed) never qualifies.
  * Decoy, poison and lockdown-level evidence never enter shadow: those are blocked as before.
  * An admin must review it before a deadline. Release = the customer is restored and told exactly which transfers did NOT execute;
    confirm = frozen through the existing lockdown path. Past the deadline it falls back to the earlier step-up behaviour.
  * The flag SHADOW_MODE=false restores the exact earlier behaviour.
"""
import datetime as dt

from sqlalchemy import func
from sqlalchemy.orm import Session

from . import models
from .config import settings

IDENTITY_FLAGS = {"ip_or_device_change", "new_device_for_user"}
BLOCKING_CODES = {"decoy_touched", "poison_credential_used"}
MAX_ACTIONS = 300
REASON_TEXT = "Contained in shadow mode: the identity changed but the evidence is not conclusive, so nothing real can move while an admin decides"


def eligible(decision: dict, rule_flags: list[str]) -> bool:
    """Is this suspicious-but-uncertain decision one that shadow mode should handle?"""
    if not settings.shadow_mode or decision["status"] != "SUSPICIOUS":
        return False
    codes = {r["code"] for r in decision["reasons"]}
    if codes & BLOCKING_CODES:
        return False
    large_deviation = any(r["code"] == "baseline_deviation" and r["points"] >= 2.5 for r in decision["reasons"])
    return bool(IDENTITY_FLAGS & set(rule_flags)) or "public_ip_change" in codes or large_deviation


def client_view(result: dict) -> dict:
    """What the session's own browser is told: a shadowed session must look completely normal."""
    if result.get("status") == "SHADOW":
        return {**result, "status": "SAFE", "tier": "allow", "action_taken": "none"}
    return result


def log_action(db: Session, session_id: str, action: str, detail: dict | None = None) -> None:
    if db.query(func.count(models.ShadowAction.id)).filter_by(session_id=session_id).scalar() < MAX_ACTIONS:
        db.add(models.ShadowAction(session_id=session_id, action=action, detail=detail or {}))


def case_for(db: Session, session_id: str) -> models.ShadowCase | None:
    return db.query(models.ShadowCase).filter_by(session_id=session_id).first()


def enter(db: Session, session: models.SessionState, decision: dict, ip: str | None, device: str | None) -> models.ShadowCase:
    now = dt.datetime.utcnow()
    reasons = [{"code": r["code"], "points": r["points"], "text": r["text"]} for r in decision["reasons"]]
    case = case_for(db, session.session_id)
    if case is None:
        case = models.ShadowCase(session_id=session.session_id)
        db.add(case)
    case.user_label, case.entered_at, case.status = session.user_label, now, "pending"
    case.deadline = now + dt.timedelta(minutes=settings.shadow_review_minutes)
    case.reasons, case.ip_address, case.device_info = reasons, ip, (device or "")[:240]
    case.resolved_at = case.resolved_by = case.notice = None
    case.notice_dismissed = False
    return case


def _sum_transfers(db: Session, session_id: str) -> int:
    return int(db.query(func.coalesce(func.sum(models.ShadowTransfer.amount_cents), 0)).filter_by(session_id=session_id).scalar() or 0)


def shadow_balance_cents(db: Session, customer: models.Customer, session_id: str) -> int:
    return customer.balance_cents - _sum_transfers(db, session_id)


def merged_transactions(db: Session, customer: models.Customer, session_id: str, real_rows: list[dict]) -> list[dict]:
    """What the sandbox shows: the real history plus the pretend transfers, so it all looks consistent to whoever is in it."""
    fake = [{"id": -t.id, "name": t.recipient, "category": "Transfer", "amount": -t.amount_cents / 100, "memo": t.memo, "date": t.created_at.strftime("%b %d, %Y"),
             "_at": t.created_at} for t in db.query(models.ShadowTransfer).filter_by(session_id=session_id).order_by(models.ShadowTransfer.id.desc()).all()]
    return [{k: v for k, v in f.items() if k != "_at"} for f in fake] + real_rows


def sweep(db: Session) -> list[str]:
    """Pending cases past their deadline fall back to step-up (the earlier behaviour). Returns the session ids that were changed."""
    now = dt.datetime.utcnow()
    changed = []
    for case in db.query(models.ShadowCase).filter(models.ShadowCase.status == "pending", models.ShadowCase.deadline < now).all():
        s = db.query(models.SessionState).filter_by(session_id=case.session_id).first()
        case.status, case.resolved_at, case.resolved_by = "expired", now, "deadline"
        if s is not None and s.status == "shadow":
            s.status = "suspicious"
        changed.append(case.session_id)
    if changed:
        db.commit()
    return changed


def _trust_endpoint(db: Session, user_key: str | None, ip: str | None, device: str | None) -> None:
    """After 'this is the real customer', learn the new device and network so the same person is not shadowed again on the next event."""
    if not user_key:
        return
    b = db.query(models.UserBaseline).filter_by(user_key=user_key).first()
    if b is None:
        b = models.UserBaseline(user_key=user_key, n=0, mean=[], m2=[], ips=[], devices=[])
        db.add(b)
    if ip and ip not in (b.ips or []):
        b.ips = [*(b.ips or []), ip][-20:]
    if device and device not in (b.devices or []):
        b.devices = [*(b.devices or []), device][-10:]


def release(db: Session, session_id: str, admin: str) -> dict:
    """The admin says: this is the real customer. Restore the session and record which transfers did not execute."""
    case = case_for(db, session_id)
    s = db.query(models.SessionState).filter_by(session_id=session_id).first()
    if case is None or s is None:
        raise LookupError("No shadow case for that session")
    if case.status != "pending" and not (case.status == "expired" and s.status != "locked"):
        raise ValueError(f"The case is already {case.status}")
    transfers = [{"recipient": t.recipient, "amount": t.amount_cents / 100, "memo": t.memo, "at": t.created_at.isoformat()}
                 for t in db.query(models.ShadowTransfer).filter_by(session_id=session_id).order_by(models.ShadowTransfer.id).all()]
    case.status, case.resolved_at, case.resolved_by = "released", dt.datetime.utcnow(), admin
    case.notice = {"transfers": transfers, "message": "We could not confirm it was you, so while we checked, nothing was actually sent. These transfers were NOT executed and must be done again."} if transfers else None
    case.notice_dismissed = not transfers
    s.status = "active"
    _trust_endpoint(db, s.user_label, case.ip_address, case.device_info)
    db.commit()
    return {"session_id": session_id, "status": "released", "unexecuted_transfers": len(transfers)}


def confirm(db: Session, session_id: str, admin: str) -> dict:
    """The admin says: this is an attacker. Freeze through the existing lockdown path."""
    case = case_for(db, session_id)
    s = db.query(models.SessionState).filter_by(session_id=session_id).first()
    if case is None or s is None:
        raise LookupError("No shadow case for that session")
    if case.status in ("released", "confirmed"):
        raise ValueError(f"The case is already {case.status}")
    now = dt.datetime.utcnow()
    case.status, case.resolved_at, case.resolved_by = "confirmed", now, admin
    s.status, s.locked_at = "locked", now
    db.add(models.LockdownRecord(session_id=session_id, reason=["shadow_confirmed"] + [r["code"] for r in (case.reasons or [])][:6]))
    db.commit()
    return {"session_id": session_id, "status": "confirmed"}


def mark_escalated(db: Session, session_id: str) -> None:
    """Lockdown-level evidence arrived for a shadowed session: it is blocked as before, and the case records that."""
    case = case_for(db, session_id)
    if case is not None and case.status == "pending":
        case.status, case.resolved_at, case.resolved_by = "confirmed", dt.datetime.utcnow(), "engine"


def pending_notice(db: Session, session_id: str) -> dict | None:
    case = case_for(db, session_id)
    if case is not None and case.status == "released" and case.notice and not case.notice_dismissed:
        return case.notice
    return None


def dismiss_notice(db: Session, session_id: str) -> None:
    case = case_for(db, session_id)
    if case is not None:
        case.notice_dismissed = True
        db.commit()


def stats(db: Session) -> dict:
    rows = dict(db.query(models.ShadowCase.status, func.count(models.ShadowCase.id)).group_by(models.ShadowCase.status).all())
    return {k: int(rows.get(k, 0)) for k in ("pending", "released", "confirmed", "expired")}
