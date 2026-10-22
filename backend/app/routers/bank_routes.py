"""VaultApp, the demo bank that CYBERMIND protects.

Written the way a real customer app would integrate: the bank owns its customers and passwords; CYBERMIND sees the
login attempts (campaign / decoy / breached-password checks) and the behaviour of the signed-in session, and the bank
enforces what CYBERMIND decides (block = 423, step-up = 428).
"""
import re
import uuid
import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import alerts, models, auth, security, campaign_engine, breach, shadow as shadow_mod
from ..config import settings
from ..database import get_db
from ..websocket_manager import manager
from .events_routes import _get_or_create_session

router = APIRouter(prefix="/bank", tags=["vaultapp bank"])

_DUMMY_HASH = auth.hash_password("not-a-real-password")
_USERNAME = re.compile(r"^[a-z0-9._-]{3,32}$")
register_by_ip = security.SlidingWindowLimiter(10, 3600)

SEED_TRANSACTIONS = [
    ("Salary Deposit", "Income", 485000, 1), ("Mortgage Payment", "Housing", -210000, 3), ("Whole Foods Market", "Groceries", -8743, 4),
    ("Electric Bill", "Utilities", -12400, 5), ("Dividend Credit", "Investment", 21820, 6),
]


class RegisterBody(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    full_name: str = Field(min_length=2, max_length=60)
    password: str = Field(min_length=8, max_length=128)


class LoginBody(BaseModel):
    username: str
    password: str
    device_info: str | None = None


class TransferBody(BaseModel):
    session_id: str
    recipient: str = Field(min_length=2, max_length=80)
    amount: float
    memo: str | None = Field(default=None, max_length=140)


class StepUpBody(BaseModel):
    session_id: str
    password: str


def _client(request: Request):
    return security.resolve_client_ip(request), request.headers.get("user-agent"), campaign_engine.header_order_fp(list(request.headers.keys()))


def _customer_for(request: Request, session_id: str, db: Session):
    auth.require_ingest_auth(request, session_id, db)
    link = db.query(models.CustomerSession).filter_by(session_id=session_id).first()
    session = db.query(models.SessionState).filter_by(session_id=session_id).first()
    customer = db.query(models.Customer).filter_by(id=link.customer_id).first() if link else None
    if not customer or not session:
        raise HTTPException(status_code=404, detail="Unknown session")
    return customer, session


def _profile(c: models.Customer) -> dict:
    return {"username": c.username, "full_name": c.full_name, "account_no": c.account_no, "balance": c.balance_cents / 100}


def _tx_rows(db: Session, c: models.Customer, limit=25) -> list:
    q = db.query(models.BankTransaction).filter_by(customer_id=c.id)
    rows = q.order_by(models.BankTransaction.created_at.desc(), models.BankTransaction.id.desc()).limit(limit).all()
    return [{"id": r.id, "name": r.name, "category": r.category, "amount": r.amount_cents / 100, "memo": r.memo,
             "date": r.created_at.strftime("%b %d, %Y")} for r in rows]


@router.post("/register")
def register(request: Request, body: RegisterBody, db: Session = Depends(get_db)):
    ip, _, _ = _client(request)
    if not register_by_ip.hit(ip or "?"):
        raise HTTPException(status_code=429, detail="Too many sign-ups from this address")
    uname = body.username.strip().lower()
    if not _USERNAME.match(uname):
        raise HTTPException(status_code=422, detail="Username: 3-32 characters, letters, numbers, dot, dash or underscore")
    if breach.is_breached(breach.sha1_hex(body.password)):
        raise HTTPException(status_code=422, detail="That password appears in known data breaches. Choose a different one.")
    decoys = {d.username.lower() for d in db.query(models.DecoyAccount).all()} | {u.lower() for u in settings.decoys}
    if uname in decoys or db.query(models.Customer).filter_by(username=uname).first():
        raise HTTPException(status_code=409, detail="That username is not available")
    c = models.Customer(username=uname, full_name=body.full_name.strip(), hashed_password=auth.hash_password(body.password),
                        account_no="**** " + str(uuid.uuid4().int)[:4], balance_cents=1248060)
    db.add(c)
    db.commit()
    db.refresh(c)
    now = dt.datetime.utcnow()
    for name, cat, cents, days in SEED_TRANSACTIONS:
        db.add(models.BankTransaction(customer_id=c.id, name=name, category=cat, amount_cents=cents, created_at=now - dt.timedelta(days=days)))
    db.commit()
    return {"status": "created", "username": uname}


@router.post("/login")
async def bank_login(request: Request, body: LoginBody, db: Session = Depends(get_db)):
    ip, ua, hfp = _client(request)
    uname = body.username.strip().lower()
    sha1 = breach.sha1_hex(body.password)
    ukey = "bank:" + uname

    if security.login_fail_by_ip.blocked(ip or "?") or security.login_fail_by_user.blocked(ukey):
        retry = max(security.login_fail_by_ip.retry_after(ip or "?"), security.login_fail_by_user.retry_after(ukey))
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again later.", headers={"Retry-After": str(retry)})

    pre = campaign_engine.precheck(db, username=uname, ip=ip, user_agent=ua, header_fp=hfp, password_sha1=sha1)
    if pre["decision"] == "deny":
        res = campaign_engine.record_and_evaluate(db, username=uname, success=False, ip=ip, user_agent=ua, header_fp=hfp, password_sha1=sha1)
        await alerts.announce_campaign(res)
        raise HTTPException(status_code=429, detail="Sign-in is temporarily unavailable from this device. Contact support.")

    c = db.query(models.Customer).filter_by(username=uname).first()
    ok = auth.verify_password(body.password, c.hashed_password if c else _DUMMY_HASH) and c is not None
    res = campaign_engine.record_and_evaluate(db, username=uname, success=ok, ip=ip, user_agent=ua, header_fp=hfp, password_sha1=sha1)
    await alerts.announce_campaign(res)
    if not ok:
        security.login_fail_by_ip.hit(ip or "?")
        security.login_fail_by_user.hit(ukey)
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    security.login_fail_by_user.reset(ukey)

    session_id = str(uuid.uuid4())
    session = _get_or_create_session(db, session_id, c.username, ip, (body.device_info or ua or "")[:240])
    db.add(models.CustomerSession(session_id=session_id, customer_id=c.id))
    stepped_up = pre["decision"] == "step_up"          # e.g. the password is in a known breach: allow, but gate sensitive actions
    if stepped_up:
        session.status = "suspicious"
    db.commit()
    await manager.broadcast({"type": "session_started", "session_id": session_id, "status": session.status})
    return {"session_id": session_id, "session_token": security.session_token(session_id), "status": session.status,
            "step_up_required": stepped_up, "profile": _profile(c)}


@router.get("/account")
def account(request: Request, session_id: str, db: Session = Depends(get_db)):
    c, s = _customer_for(request, session_id, db)
    rows = _tx_rows(db, c)
    if s.status == "shadow":
        # Shadow mode: a consistent sandbox copy of the account. Nothing here is real, and nothing in it reveals that.
        shadow_mod.log_action(db, session_id, "view_account")
        db.commit()
        return {"profile": {**_profile(c), "balance": shadow_mod.shadow_balance_cents(db, c, session_id) / 100},
                "transactions": shadow_mod.merged_transactions(db, c, session_id, rows), "step_up_required": False, "locked": False, "notice": None}
    return {"profile": _profile(c), "transactions": rows, "step_up_required": s.status == "suspicious", "locked": s.status == "locked",
            "notice": shadow_mod.pending_notice(db, session_id)}


class NoticeBody(BaseModel):
    session_id: str


@router.post("/notice/dismiss")
def dismiss_notice(request: Request, body: NoticeBody, db: Session = Depends(get_db)):
    _customer_for(request, body.session_id, db)
    shadow_mod.dismiss_notice(db, body.session_id)
    return {"status": "dismissed"}


@router.post("/transfer")
async def transfer(request: Request, body: TransferBody, db: Session = Depends(get_db)):
    c, s = _customer_for(request, body.session_id, db)
    # CYBERMIND's decision, enforced by the bank (this is the integration point)
    if s.status == "locked":
        raise HTTPException(status_code=423, detail="This session is frozen by CYBERMIND. Contact your administrator.")
    if s.status == "suspicious":
        raise HTTPException(status_code=428, detail="We need to verify it is you before moving money. Please re-enter your password.")
    cents = round(body.amount * 100)
    if cents <= 0:
        raise HTTPException(status_code=422, detail="Enter an amount greater than zero")
    if s.status == "shadow":
        # Shadow mode: the transfer "succeeds" in a sandbox ledger, so balances stay consistent for whoever is in it. Real money never moves.
        if cents > shadow_mod.shadow_balance_cents(db, c, body.session_id):
            raise HTTPException(status_code=422, detail="Insufficient funds")
        db.add(models.ShadowTransfer(session_id=body.session_id, customer_id=c.id, recipient=body.recipient.strip(), amount_cents=cents,
                                     memo=(body.memo or "").strip() or None))
        shadow_mod.log_action(db, body.session_id, "transfer", {"recipient": body.recipient.strip(), "amount": cents / 100, "memo": (body.memo or "").strip()})
        db.commit()
        return {"status": "sent", "balance": shadow_mod.shadow_balance_cents(db, c, body.session_id) / 100,
                "transactions": shadow_mod.merged_transactions(db, c, body.session_id, _tx_rows(db, c))}
    if cents > c.balance_cents:
        raise HTTPException(status_code=422, detail="Insufficient funds")
    c.balance_cents -= cents
    db.add(models.BankTransaction(customer_id=c.id, name=body.recipient.strip(), category="Transfer", amount_cents=-cents,
                                  memo=(body.memo or "").strip() or None))
    db.commit()
    return {"status": "sent", "balance": c.balance_cents / 100, "transactions": _tx_rows(db, c)}


@router.post("/step-up/verify")
async def step_up_verify(request: Request, body: StepUpBody, db: Session = Depends(get_db)):
    """Re-authenticate with the password to clear a step-up. A stolen session without the password cannot do this."""
    c, s = _customer_for(request, body.session_id, db)
    if s.status == "locked":
        raise HTTPException(status_code=423, detail="This session is frozen by CYBERMIND. Contact your administrator.")
    if s.status == "shadow":
        shadow_mod.log_action(db, body.session_id, "verify_attempt")      # the sandbox answers like a normal session; the attempt is logged
        db.commit()
        return {"status": "verified"}
    key = "bank-stepup:" + c.username
    if security.login_fail_by_user.blocked(key):
        raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")
    if not auth.verify_password(body.password, c.hashed_password):
        security.login_fail_by_user.hit(key)
        raise HTTPException(status_code=401, detail="Incorrect password")
    if s.status == "suspicious":
        s.status = "active"
        db.add(models.SecurityEvent(session_id=body.session_id, event_type="step_up_cleared", status="SAFE", rule_flags=[],
                                    action_taken="cleared_by_customer_reauth",
                                    details={"_decision": {"tier": "allow", "reasons": [{"code": "step_up_cleared", "points": 0,
                                                                                          "text": "Customer re-entered their password"}]}}))
        db.commit()
        await manager.broadcast({"type": "step_up_cleared", "session_id": body.session_id, "by": "customer"})
    return {"status": "verified"}
