import datetime as dt
from sqlalchemy import Column, Integer, String, DateTime, Boolean, JSON, Float
from .database import Base

def now():
    return dt.datetime.utcnow()

class AdminUser(Base):
    __tablename__ = "admin_users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=now)

class SessionState(Base):
    __tablename__ = "sessions"
    session_id = Column(String, primary_key=True, index=True)
    user_label = Column(String, default="demo_user")
    status = Column(String, default="active")  # active | suspicious | locked
    last_ip = Column(String, nullable=True)
    last_device = Column(String, nullable=True)
    created_at = Column(DateTime, default=now)
    updated_at = Column(DateTime, default=now, onupdate=now)
    locked_at = Column(DateTime, nullable=True)

class SecurityEvent(Base):
    __tablename__ = "security_events"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=now, index=True)
    session_id = Column(String, index=True)
    event_type = Column(String)          # behavior | login | api_call | resource_access
    ip_address = Column(String, nullable=True)
    device_info = Column(String, nullable=True)
    details = Column(JSON, default=dict)         # raw non-sensitive behavioral metadata
    rule_flags = Column(JSON, default=list)       # list of triggered rule names
    ml_anomaly = Column(Boolean, default=False)
    internal_score = Column(Float, default=0.0)   # never exposed via API to non-admins as a "score"
    status = Column(String, default="SAFE")       # SAFE | SUSPICIOUS | LOCKDOWN
    action_taken = Column(String, default="none")

class LockdownRecord(Base):
    __tablename__ = "lockdown_records"
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True)
    triggered_at = Column(DateTime, default=now)
    reason = Column(JSON, default=list)
    unlocked_at = Column(DateTime, nullable=True)
    unlocked_by = Column(String, nullable=True)


# ---------------------------------------------------------------------------
# Login-endpoint protection (campaign detection) and per-user baselines
# ---------------------------------------------------------------------------
class LoginAttempt(Base):
    """One attempt to log in to a protected app (success or failure), as reported by that app."""
    __tablename__ = "login_attempts"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=now, index=True)
    username = Column(String, index=True)
    success = Column(Boolean, default=False)
    ip_address = Column(String, index=True, nullable=True)
    network_type = Column(String, nullable=True)       # loopback | private | public | datacenter | residential
    user_agent = Column(String, nullable=True)
    signature = Column(String, index=True)             # client fingerprint: UA family + header order + TLS fingerprint
    breached = Column(Boolean, default=False)          # password appears in a known breach list
    decoy = Column(Boolean, default=False)             # username is a decoy account
    campaign_id = Column(String, index=True, nullable=True)
    decision = Column(String, default="allow")         # allow | step_up | deny


class Campaign(Base):
    """A cluster of login attempts that share a client fingerprint and look coordinated."""
    __tablename__ = "campaigns"
    id = Column(String, primary_key=True)
    signature = Column(String, index=True)
    status = Column(String, default="watching")        # watching | blocked | released
    first_seen = Column(DateTime, default=now)
    last_seen = Column(DateTime, default=now)
    blocked_at = Column(DateTime, nullable=True)
    attempts = Column(Integer, default=0)
    distinct_ips = Column(Integer, default=0)
    distinct_usernames = Column(Integer, default=0)
    failure_ratio = Column(Float, default=0.0)
    breached_share = Column(Float, default=0.0)
    decoy_hits = Column(Integer, default=0)
    score = Column(Float, default=0.0)
    reasons = Column(JSON, default=list)
    sample_user_agent = Column(String, nullable=True)


class DecoyAccount(Base):
    """A fake account nobody legitimate uses. Any attempt on it is hostile."""
    __tablename__ = "decoy_accounts"
    username = Column(String, primary_key=True)
    created_at = Column(DateTime, default=now)
    note = Column(String, nullable=True)
    hits = Column(Integer, default=0)
    last_hit = Column(DateTime, nullable=True)


class UserBaseline(Base):
    """Running statistics (Welford) of a user's normal behaviour, plus the IPs / devices they usually use."""
    __tablename__ = "user_baselines"
    user_key = Column(String, primary_key=True)
    n = Column(Integer, default=0)
    mean = Column(JSON, default=list)
    m2 = Column(JSON, default=list)
    ips = Column(JSON, default=list)
    devices = Column(JSON, default=list)
    updated_at = Column(DateTime, default=now, onupdate=now)


# ---- VaultApp demo bank: real customer accounts for the protected application ----
class Customer(Base):
    __tablename__ = "bank_customers"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    account_no = Column(String, nullable=False)
    balance_cents = Column(Integer, default=0)
    created_at = Column(DateTime, default=now)


class CustomerSession(Base):
    """Links a monitored security session to the customer who signed in."""
    __tablename__ = "bank_customer_sessions"
    session_id = Column(String, primary_key=True, index=True)
    customer_id = Column(Integer, index=True, nullable=False)
    created_at = Column(DateTime, default=now)


class BankTransaction(Base):
    __tablename__ = "bank_transactions"
    id = Column(Integer, primary_key=True, index=True)
    customer_id = Column(Integer, index=True, nullable=False)
    name = Column(String, nullable=False)
    category = Column(String, default="Transfer")
    amount_cents = Column(Integer, nullable=False)        # negative = money out
    memo = Column(String, nullable=True)
    created_at = Column(DateTime, default=now, index=True)
