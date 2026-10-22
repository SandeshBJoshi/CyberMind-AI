import datetime as dt
from typing import Optional, Any
from pydantic import BaseModel

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class BehaviorEvent(BaseModel):
    """Non-sensitive behavioral telemetry. Never include raw keystrokes/passwords."""
    session_id: str
    event_type: str = "behavior"          # behavior | login_success | login_failed | api_call | resource_access
    ip_address: Optional[str] = None
    device_info: Optional[str] = None
    keystroke_avg_interval_ms: Optional[float] = None
    keystroke_std_interval_ms: Optional[float] = None
    typing_speed_cpm: Optional[float] = None
    mouse_click_rate: Optional[float] = None
    mouse_move_entropy: Optional[float] = None
    session_duration_sec: Optional[float] = None
    resource_accessed: Optional[str] = None
    extra: Optional[dict[str, Any]] = None

class ProtectedActionRequest(BaseModel):
    session_id: str
    action: str

class UnlockRequest(BaseModel):
    session_id: str
    reason_note: Optional[str] = None

class StartSessionRequest(BaseModel):
    user_label: Optional[str] = "demo_user"
    ip_address: Optional[str] = None
    device_info: Optional[str] = None

class UserSessionRequest(BaseModel):
    """Initial session details supplied by the separate user portal."""
    user_label: str
    ip_address: Optional[str] = None
    device_info: Optional[str] = None

class IdentityChurnRequest(BaseModel):
    session_id: str
    new_ip: str = "192.0.2.201"
    new_device: str = "Tor-Browser/12.5"


class AuthEventCheck(BaseModel):
    """Sent by a protected app's backend BEFORE it verifies a password."""
    username: str
    ip_address: str
    user_agent: Optional[str] = None
    header_order: Optional[list[str]] = None     # names of the request headers, in the order received
    tls_fingerprint: Optional[str] = None        # e.g. a JA3 / JA4 hash computed by the proxy
    password_sha1: Optional[str] = None          # SHA-1 of the password (never the password itself)

class LoginAttemptEvent(AuthEventCheck):
    """Sent AFTER the app knows whether the credentials were right."""
    success: bool

class DecoyCreate(BaseModel):
    username: str
    note: Optional[str] = None
