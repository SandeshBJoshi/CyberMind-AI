import time

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .. import alerts, models, schemas, auth, security, campaign_engine, breach
from ..database import get_db

router = APIRouter(prefix="/auth", tags=["auth"])

# Verifying against this when the username does not exist keeps response time the same either way,
# so an attacker cannot learn which usernames are real.
_DUMMY_HASH = auth.hash_password("not-a-real-password")


def _client_info(request: Request):
    ip = security.resolve_client_ip(request)
    ua = request.headers.get("user-agent")
    hfp = campaign_engine.header_order_fp(list(request.headers.keys()))
    return ip, ua, hfp


@router.post("/login", response_model=schemas.TokenResponse)
async def login(request: Request, payload: schemas.LoginRequest, db: Session = Depends(get_db)):
    ip, ua, hfp = _client_info(request)
    uname = payload.username.strip().lower()

    # 1. brute-force limits on FAILED attempts, per IP and per username
    if security.login_fail_by_ip.blocked(ip or "?") or security.login_fail_by_user.blocked(uname):
        retry = max(security.login_fail_by_ip.retry_after(ip or "?"), security.login_fail_by_user.retry_after(uname))
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again later.", headers={"Retry-After": str(retry)})

    # 2. campaign / decoy check: the admin login is itself a protected login endpoint
    pre = campaign_engine.precheck(db, username=uname, ip=ip, user_agent=ua, header_fp=hfp, password_sha1=breach.sha1_hex(payload.password))
    if pre["decision"] == "deny":
        res = campaign_engine.record_and_evaluate(db, username=uname, success=False, ip=ip, user_agent=ua, header_fp=hfp, password_sha1=breach.sha1_hex(payload.password))
        await alerts.announce_campaign(res)
        raise HTTPException(status_code=429, detail="This client was blocked as part of a suspected attack. Contact the administrator.")

    # 3. verify (constant work whether or not the user exists)
    user = db.query(models.AdminUser).filter(models.AdminUser.username == payload.username).first()
    ok = auth.verify_password(payload.password, user.hashed_password if user else _DUMMY_HASH) and user is not None

    res = campaign_engine.record_and_evaluate(db, username=uname, success=ok, ip=ip, user_agent=ua, header_fp=hfp, password_sha1=breach.sha1_hex(payload.password))
    await alerts.announce_campaign(res)
    if not ok:
        security.login_fail_by_ip.hit(ip or "?")
        security.login_fail_by_user.hit(uname)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    security.login_fail_by_user.reset(uname)
    return schemas.TokenResponse(access_token=auth.create_access_token(subject=user.username))


@router.post("/logout")
def logout(request: Request, current=Depends(auth.get_current_admin)):
    """Revoke this exact token so a stolen copy stops working immediately."""
    try:
        claims = auth.decode_token(auth.bearer_token(request))
        security.revoke_token(claims.get("jti"), float(claims.get("exp", time.time() + 3600)))
    except Exception:
        pass
    return {"status": "logged_out"}


@router.get("/me")
def me(current=Depends(auth.get_current_admin)):
    return {"username": current.username}
