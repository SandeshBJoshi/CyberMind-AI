"""Feature 1: phishing poison tracing. Admin-only.

An analyst who has confirmed a suspicious or phishing email can plant a unique FAKE credential tied to it. CYBERMIND never submits
it anywhere; the analyst enters it manually on a clearly fictional page. If that credential ever appears at one of our logins, the
login guard refuses it, blocks the attacker's whole fingerprint campaign and records the time from phishing to use.
Only a hash of the planted password is stored, and the clear password is shown exactly once, at creation.
"""
import secrets

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import auth, breach, models
from ..config import settings
from ..database import get_db

router = APIRouter(prefix="/api/poison", tags=["poison tracing"], dependencies=[Depends(auth.get_current_admin)])

FIRST = ["maria", "rahul", "ananya", "kiran", "sophie", "daniel", "priyanka", "arjun", "elena", "marcus", "neha", "tomas", "farah", "liam", "isha", "omar"]
LAST = ["fernandes", "kulkarni", "okafor", "brandt", "sethi", "moreau", "iyer", "novak", "haddad", "pereira", "joshi", "lindqvist", "ahmed", "rossi"]
ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"


class MintBody(BaseModel):
    analysis_id: int


def _require_on():
    if not settings.poison_tracing:
        raise HTTPException(status_code=403, detail="Poison tracing is switched off (POISON_TRACING=false).")


def _username_taken(db: Session, name: str) -> bool:
    return any(db.query(model).filter(col == name).first() for model, col in (
        (models.PoisonCredential, models.PoisonCredential.username), (models.DecoyAccount, models.DecoyAccount.username),
        (models.Customer, models.Customer.username), (models.AdminUser, models.AdminUser.username)))


def _new_username(db: Session) -> str:
    for _ in range(50):
        name = f"{secrets.choice(FIRST)}.{secrets.choice(LAST)}{secrets.randbelow(90) + 10}"
        if not _username_taken(db, name):
            return name
    raise HTTPException(status_code=500, detail="Could not find an unused username.")


def _new_password() -> str:
    raw = "".join(secrets.choice(ALPHABET) for _ in range(14))
    return f"{raw[:7]}-{raw[7:]}"


def _campaign(db: Session, cid):
    return db.query(models.Campaign).filter_by(id=cid).first() if cid else None


def _summary(db: Session, p: models.PoisonCredential) -> dict:
    a = db.query(models.EmailAnalysis).filter_by(id=p.analysis_id).first()
    c = _campaign(db, p.campaign_id)
    return {"id": p.id, "analysis_id": p.analysis_id, "subject": a.subject if a else None, "verdict": a.verdict if a else None, "username": p.username,
            "status": p.status, "created_at": p.created_at, "uses": p.uses or 0, "first_used_at": p.first_used_at, "last_ip": p.last_ip,
            "seconds_to_first_use": int((p.first_used_at - p.created_at).total_seconds()) if p.first_used_at and p.created_at else None,
            "campaign_id": p.campaign_id, "campaign_status": c.status if c else None}


@router.get("/status")
def status():
    return {"enabled": settings.poison_tracing}


@router.post("/mint")
def mint(body: MintBody, db: Session = Depends(get_db)):
    _require_on()
    a = db.query(models.EmailAnalysis).filter_by(id=body.analysis_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Analysis not found")
    if a.verdict not in ("SUSPICIOUS", "PHISHING"):
        raise HTTPException(status_code=400, detail="Credentials can only be planted from a suspicious or phishing email.")
    if db.query(models.PoisonCredential).filter(models.PoisonCredential.analysis_id == a.id, models.PoisonCredential.status != "retired").first():
        raise HTTPException(status_code=409, detail="A credential is already planted for this email. Retire it first to plant a new one.")
    username, password = _new_username(db), _new_password()
    row = models.PoisonCredential(analysis_id=a.id, username=username, password_sha1=breach.sha1_hex(password))
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "analysis_id": a.id, "username": username, "password": password,
            "warning": "This password is shown only once and is not stored. CYBERMIND never submits it anywhere: enter it yourself, manually, "
                       "only on a clearly fictional page you control."}


@router.get("")
def list_poison(analysis_id: int | None = None, db: Session = Depends(get_db)):
    q = db.query(models.PoisonCredential).order_by(models.PoisonCredential.id.desc())
    if analysis_id is not None:
        q = q.filter(models.PoisonCredential.analysis_id == analysis_id)
    rows = q.limit(100).all()
    return {"enabled": settings.poison_tracing, "items": [_summary(db, p) for p in rows],
            "counts": {"planted": sum(1 for p in rows if p.status == "planted"), "used": sum(1 for p in rows if p.status == "used"),
                       "retired": sum(1 for p in rows if p.status == "retired")}}


@router.get("/{poison_id}")
def detail(poison_id: int, db: Session = Depends(get_db)):
    p = db.query(models.PoisonCredential).filter_by(id=poison_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Not found")
    a = db.query(models.EmailAnalysis).filter_by(id=p.analysis_id).first()
    events = []
    if a:
        events.append({"t": a.created_at, "kind": "analysed", "text": f"Email analysed: \"{a.subject}\" rated {a.verdict} ({a.score})"})
    events.append({"t": p.created_at, "kind": "planted", "text": f"Fake credential planted ({p.username})"})
    for t in db.query(models.PoisonTrace).filter_by(poison_id=p.id).order_by(models.PoisonTrace.timestamp).limit(50).all():
        events.append({"t": t.timestamp, "kind": "used", "text": f"Used at the login from {t.ip_address or 'unknown IP'}"
                       + (" with the planted password" if t.exact else " (username only)")})
    c = _campaign(db, p.campaign_id)
    if c and c.blocked_at:
        events.append({"t": c.blocked_at, "kind": "campaign_blocked", "text": f"Attacker's campaign {c.id} blocked ({c.attempts} attempts, {c.distinct_ips} IPs)"})
    if p.retired_at:
        events.append({"t": p.retired_at, "kind": "retired", "text": "Credential retired by an analyst"})
    events.sort(key=lambda e: e["t"])
    return {**_summary(db, p), "timeline": events}


@router.post("/{poison_id}/retire")
def retire(poison_id: int, db: Session = Depends(get_db)):
    import datetime as dt
    p = db.query(models.PoisonCredential).filter_by(id=poison_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Not found")
    p.status, p.retired_at = "retired", dt.datetime.utcnow()
    db.commit()
    return {"id": p.id, "status": p.status}
