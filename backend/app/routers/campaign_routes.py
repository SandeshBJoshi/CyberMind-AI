"""Login-endpoint protection: client-app API, campaign view, decoy accounts, posture and ML management."""
import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import alerts, auth, campaign_engine, ml_engine, models, notify, schemas, security
from ..config import SECURITY_WARNINGS, DEV_APP_KEY, settings
from ..database import get_db
from ..websocket_manager import manager

router = APIRouter(tags=["login protection"])


# ----------------------------------------------------------------------------- client-app API (X-App-Key)
@router.post("/api/auth-events/check")
def auth_check(request: Request, body: schemas.AuthEventCheck, db: Session = Depends(get_db)):
    """Call BEFORE verifying a password. Returns allow | step_up | deny."""
    auth.require_app_key(request)
    if not security.ingest_by_source.hit(f"app:{body.ip_address}"):
        raise HTTPException(status_code=429, detail="Too many checks")
    return campaign_engine.precheck(
        db, username=body.username, ip=body.ip_address, user_agent=body.user_agent,
        header_fp=campaign_engine.header_order_fp(body.header_order), tls_fp=body.tls_fingerprint, password_sha1=body.password_sha1,
    )


@router.post("/api/auth-events/login-attempt")
async def login_attempt(request: Request, body: schemas.LoginAttemptEvent, db: Session = Depends(get_db)):
    """Call AFTER the outcome is known. Stores the attempt, rescoring the client fingerprint's campaign."""
    auth.require_app_key(request)
    res = campaign_engine.record_and_evaluate(
        db, username=body.username, success=body.success, ip=body.ip_address, user_agent=body.user_agent,
        header_fp=campaign_engine.header_order_fp(body.header_order), tls_fp=body.tls_fingerprint, password_sha1=body.password_sha1,
    )
    await alerts.announce_campaign(res)
    return {k: res[k] for k in ("decision", "signature", "campaign_id", "campaign_status", "score", "reasons")}


# ----------------------------------------------------------------------------- admin: campaigns
@router.get("/api/campaigns")
def list_campaigns(status: str | None = None, db: Session = Depends(get_db), _a=Depends(auth.get_current_admin)):
    q = db.query(models.Campaign).order_by(models.Campaign.last_seen.desc())
    if status:
        q = q.filter(models.Campaign.status == status)
    rows = q.limit(200).all()
    out = []
    for c in rows:
        d = campaign_engine.campaign_dict(c)
        d["participant_ips"] = db.query(models.LoginAttempt.ip_address).filter(models.LoginAttempt.campaign_id == c.id).distinct().count()
        out.append(d)
    return {"items": out, "active_blocked": sum(1 for c in rows if c.status == "blocked")}


@router.post("/api/campaigns/{campaign_id}/release")
def release_campaign(campaign_id: str, db: Session = Depends(get_db), _a=Depends(auth.get_current_admin)):
    if not campaign_engine.release(db, campaign_id):
        raise HTTPException(status_code=404, detail="Unknown campaign")
    return {"id": campaign_id, "status": "released"}


@router.get("/api/auth-events/recent")
def recent_attempts(limit: int = 100, db: Session = Depends(get_db), _a=Depends(auth.get_current_admin)):
    rows = db.query(models.LoginAttempt).order_by(models.LoginAttempt.timestamp.desc()).limit(min(limit, 500)).all()
    return [{"timestamp": r.timestamp, "username": r.username, "success": r.success, "ip_address": r.ip_address, "network_type": r.network_type,
             "signature": r.signature, "breached": r.breached, "decoy": r.decoy, "campaign_id": r.campaign_id, "decision": r.decision} for r in rows]


# ----------------------------------------------------------------------------- admin: decoy accounts
@router.get("/api/decoys")
def list_decoys(db: Session = Depends(get_db), _a=Depends(auth.get_current_admin)):
    return [{"username": d.username, "note": d.note, "hits": d.hits, "last_hit": d.last_hit, "created_at": d.created_at}
            for d in db.query(models.DecoyAccount).order_by(models.DecoyAccount.username).all()]


@router.post("/api/decoys")
def add_decoy(body: schemas.DecoyCreate, db: Session = Depends(get_db), _a=Depends(auth.get_current_admin)):
    name = body.username.strip().lower()
    if not name or len(name) > 80:
        raise HTTPException(status_code=400, detail="Invalid username")
    if db.query(models.DecoyAccount).filter_by(username=name).first():
        raise HTTPException(status_code=409, detail="Decoy already exists")
    db.add(models.DecoyAccount(username=name, note=body.note))
    db.commit()
    return {"username": name}


@router.delete("/api/decoys/{username}")
def delete_decoy(username: str, db: Session = Depends(get_db), _a=Depends(auth.get_current_admin)):
    d = db.query(models.DecoyAccount).filter_by(username=username.lower()).first()
    if not d:
        raise HTTPException(status_code=404, detail="Unknown decoy")
    db.delete(d)
    db.commit()
    return {"deleted": username}


# ----------------------------------------------------------------------------- admin: posture + ML
@router.get("/api/security/status")
def security_status(_a=Depends(auth.get_current_admin)):
    checks = [
        {"id": "jwt_secret", "label": "Strong JWT signing secret", "ok": not any(w["code"].startswith("jwt_secret") for w in SECURITY_WARNINGS)},
        {"id": "admin_password", "label": "Strong admin password", "ok": not any(w["code"].startswith("admin_password") for w in SECURITY_WARNINGS)},
        {"id": "cors", "label": "CORS limited to the console origin", "ok": "*" not in settings.cors_list},
        {"id": "client_ip", "label": "Client IP header NOT trusted", "ok": not settings.allow_client_ip_header},
        {"id": "ws_auth", "label": "Live feed requires admin token", "ok": True},
        {"id": "signed_telemetry", "label": "Telemetry needs a signed session token", "ok": True},
        {"id": "login_limit", "label": "Admin login rate-limited", "ok": True},
    ]
    return {
        "mode": "production" if settings.is_production else "development",
        "checks": checks,
        "warnings": SECURITY_WARNINGS,
        "app_key_hint": DEV_APP_KEY["value"],        # only populated when a dev key was generated
        "demo_mode": settings.demo_mode, "ip_change_policy": settings.ip_change_policy,
        "typing_bot_cpm_threshold": settings.typing_bot_cpm_threshold,
        "ml_source": ml_engine.get_ml_engine().source,
    }


@router.get("/api/ml/status")
def ml_status(db: Session = Depends(get_db), _a=Depends(auth.get_current_admin)):
    real = db.query(models.SecurityEvent).filter(models.SecurityEvent.event_type == "behavior", models.SecurityEvent.status == "SAFE").count()
    return {"source": ml_engine.get_ml_engine().source, "contamination": settings.ml_contamination, "real_safe_events": real, "needed_to_retrain": ml_engine.MIN_REAL_ROWS}


@router.post("/api/ml/retrain")
def ml_retrain(db: Session = Depends(get_db), _a=Depends(auth.get_current_admin)):
    """Replace the synthetic baseline with a model learned from real SAFE traffic in the audit log."""
    return ml_engine.retrain_from_db(db)
