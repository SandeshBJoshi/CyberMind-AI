"""Shared security helpers: signed session tokens, client-IP resolution, rate limiting, token revocation."""
import base64
import hashlib
import hmac
import threading
import time
from collections import defaultdict, deque

from .config import settings


# ---------------------------------------------------------------------------
# Signed per-session tokens
# A session id alone is NOT enough to report events for that session. The party that created the
# session receives a token = HMAC(secret, session_id). Without it, nobody can forge events or lock
# someone else's session by guessing / learning a session id.
# ---------------------------------------------------------------------------
def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def session_token(session_id: str) -> str:
    mac = hmac.new(settings.jwt_secret.encode(), f"sess:{session_id}".encode(), hashlib.sha256).digest()
    return _b64(mac)


def verify_session_token(session_id: str, token: str | None) -> bool:
    if not token or not session_id:
        return False
    return hmac.compare_digest(session_token(session_id), token)


# ---------------------------------------------------------------------------
# Client IP
# ---------------------------------------------------------------------------
def resolve_client_ip(request, fallback: str | None = None) -> str | None:
    """Return the client IP we are willing to believe.

    * Behind one of our TRUSTED_PROXIES: use the right-most X-Forwarded-For entry that is not a trusted proxy.
    * Otherwise: the TCP peer address. A client-supplied X-Forwarded-For is only honoured when
      ALLOW_CLIENT_IP_HEADER is on (development only), because anyone can forge that header.
    """
    if request is None:
        return fallback
    peer = request.client.host if getattr(request, "client", None) else None
    headers = request.headers
    trusted = settings.trusted_proxy_set

    if peer and peer in trusted:
        fwd = headers.get("x-forwarded-for")
        if fwd:
            parts = [p.strip() for p in fwd.split(",") if p.strip()]
            for p in reversed(parts):
                if p not in trusted:
                    return p
            if parts:
                return parts[0]
        real = headers.get("x-real-ip")
        if real:
            return real.strip()
    elif settings.allow_client_ip_header:
        fwd = headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
        real = headers.get("x-real-ip")
        if real:
            return real.strip()
    return peer or fallback


# ---------------------------------------------------------------------------
# Sliding-window rate limiter (in memory; use Redis if you ever run several workers)
# ---------------------------------------------------------------------------
class SlidingWindowLimiter:
    def __init__(self, limit: int, window_sec: int):
        self.limit, self.window = limit, window_sec
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def _trim(self, q: deque, now: float):
        while q and q[0] <= now - self.window:
            q.popleft()

    def blocked(self, key: str) -> bool:
        """True if the key already used up its allowance (does not count a hit)."""
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            self._trim(q, now)
            return len(q) >= self.limit

    def hit(self, key: str) -> bool:
        """Register one hit. Returns True if it was allowed, False if the limit was exceeded."""
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            self._trim(q, now)
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True

    def retry_after(self, key: str) -> int:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            self._trim(q, now)
            return int(max(1, self.window - (now - q[0]))) if q else 1

    def reset(self, key: str | None = None):
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)


# Admin login: count FAILED attempts only
login_fail_by_ip = SlidingWindowLimiter(settings.login_rate_limit_ip, settings.login_rate_window_sec)
login_fail_by_user = SlidingWindowLimiter(settings.login_rate_limit_user, settings.login_rate_window_sec)
# Public demo endpoints that mint sessions
session_create_by_ip = SlidingWindowLimiter(30, 60)
# Generic per-key cap for event ingestion (stops one source flooding the database)
ingest_by_source = SlidingWindowLimiter(600, 60)


# ---------------------------------------------------------------------------
# JWT revocation (logout). Tokens carry a unique jti; revoked ids are remembered until they expire.
# ---------------------------------------------------------------------------
_revoked: dict[str, float] = {}
_revoked_lock = threading.Lock()


def revoke_token(jti: str, exp_ts: float):
    with _revoked_lock:
        _revoked[jti] = exp_ts
        now = time.time()
        for k in [k for k, v in _revoked.items() if v < now]:
            _revoked.pop(k, None)


def is_revoked(jti: str | None) -> bool:
    if not jti:
        return False
    with _revoked_lock:
        return jti in _revoked
