import datetime as dt
import uuid

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from . import models, security
from .config import settings
from .database import get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)


def hash_password(pw: str) -> str:
    return pwd_context.hash(pw)


def verify_password(pw: str, hashed: str) -> bool:
    return pwd_context.verify(pw, hashed)


def create_access_token(subject: str) -> str:
    now = dt.datetime.utcnow()
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + dt.timedelta(minutes=settings.jwt_expire_minutes),
        "jti": uuid.uuid4().hex,          # lets us revoke this exact token on logout
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])


def _unauthorized(detail="Could not validate admin credentials"):
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail, headers={"WWW-Authenticate": "Bearer"})


def admin_from_token(token: str | None, db: Session) -> models.AdminUser | None:
    """Return the AdminUser for a valid, non-revoked token, else None (never raises)."""
    if not token:
        return None
    try:
        payload = decode_token(token)
    except JWTError:
        return None
    if security.is_revoked(payload.get("jti")):
        return None
    username = payload.get("sub")
    if not username:
        return None
    return db.query(models.AdminUser).filter(models.AdminUser.username == username).first()


def get_current_admin(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> models.AdminUser:
    user = admin_from_token(token, db)
    if user is None:
        raise _unauthorized()
    return user


def bearer_token(request: Request) -> str | None:
    h = request.headers.get("authorization", "")
    return h[7:].strip() if h.lower().startswith("bearer ") else None


def require_ingest_auth(request: Request, session_id: str, db: Session) -> str:
    """Who may report events for / act on a session?
      * an authenticated admin (the console, the Attacker Terminal, the simulator), or
      * the holder of that session's signed token (the app that created the session).
    Returns 'admin' or 'session'. Raises 401 otherwise."""
    if admin_from_token(bearer_token(request), db) is not None:
        return "admin"
    if security.verify_session_token(session_id, request.headers.get("x-session-token")):
        return "session"
    raise _unauthorized("A valid admin token or session token is required")


def require_app_key(request: Request) -> str:
    """Client apps that use the login-protection API identify themselves with X-App-Key."""
    key = request.headers.get("x-app-key", "")
    for k in settings.app_key_set:
        if security.hmac.compare_digest(k, key):
            return k
    raise HTTPException(status_code=401, detail="Invalid or missing X-App-Key")
