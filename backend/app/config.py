"""Application settings.

Security posture is decided here:
  APP_ENV=development (default)  -> weak/missing secrets only WARN (so the demo still runs)
  APP_ENV=production             -> weak/missing secrets REFUSE TO START
"""
import logging
import os
import secrets
from typing import Optional

from pydantic_settings import BaseSettings

log = logging.getLogger("cybermind.config")

_WEAK_SECRETS = {"", "secret", "changeme", "change_me", "dev_secret", "admin", "password"}
_WEAK_PASSWORDS = {"", "admin", "admin123", "password", "123456", "changeme", "letmein"}


def _csv(value: str) -> list[str]:
    return [p.strip() for p in (value or "").split(",") if p.strip()]


class Settings(BaseSettings):
    # ---- environment ----
    app_env: str = "development"          # development | production

    # ---- database ----
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./security.db")

    # ---- auth ----
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    admin_username: str = "admin"
    admin_password: str = ""

    # ---- transport / browser safety ----
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    trusted_proxies: str = ""             # comma list of proxy IPs whose X-Forwarded-For we believe
    allow_client_ip_header: Optional[bool] = None   # DEV ONLY: believe a client-supplied X-Forwarded-For
    app_api_keys: str = ""                # comma list: keys that client apps use for /api/auth-events/*

    # ---- detection tuning ----
    lockdown_threshold: float = 6.0
    failed_login_limit: int = 5
    failed_login_window_min: int = 10
    request_burst_limit: int = 60
    request_burst_window_min: int = 1
    resource_access_limit: int = 8
    resource_access_window_min: int = 2
    typing_bot_cpm_threshold: float = 600.0   # humans rarely sustain this; scripts do (~900)
    demo_mode: bool = False                   # True restores the old "typing > 100 cpm = high risk" demo rule
    ip_change_policy: str = "step_up"         # step_up | lock
    ml_contamination: float = 0.01
    baseline_min_events: int = 20             # events before a per-user baseline is trusted

    # ---- campaign detection (login endpoint) ----
    campaign_window_min: int = 5
    campaign_block_threshold: float = 6.0
    campaign_watch_threshold: float = 3.0
    campaign_block_ttl_min: int = 30
    decoy_usernames: str = "jessica.patel,svc_backup,test_admin,j.wilson.old"
    enable_hibp: bool = False                 # online breached-password lookup (k-anonymity); off for offline demos
    geoip_asn_db: str = ""                    # optional path to a GeoLite2-ASN .mmdb file
    login_rate_limit_ip: int = 10             # failed admin logins per IP per window
    login_rate_limit_user: int = 6            # failed admin logins per username per window
    login_rate_window_sec: int = 300
    webhook_url: str = ""                     # optional: POST lockdown / campaign events here

    # ---- feature flags (each new feature can be switched off to get the exact earlier behaviour) ----
    poison_tracing: bool = True               # Feature 1: planted credentials from phishing emails are traced when used at login
    shadow_mode: bool = True                  # Feature 2: uncertain identity-change sessions are contained in a sandbox instead of step-up
    shadow_review_minutes: int = 30           # an admin must review a shadow session within this time or it falls back to step-up
    network_enabled: bool = False             # Feature 3: share / receive blocked-campaign fingerprints through a hub
    network_hub_url: str = ""
    network_member_id: str = ""
    network_member_key: str = ""              # this member's secret for talking to the hub
    network_hash_key: str = ""                # secret shared by ALL members (never the hub): keys the fingerprint hash so the hub cannot reverse it
    network_signal_points: float = 2.0         # watch-level weight of a received indicator (never enough to block by itself)

    # ---- CYBERMIND Intel ----
    cybermind_chroma_dir: str = "./data/cybermind_chroma"
    cybermind_model: str = "gemini-1.5-flash"
    cybermind_max_upload_mb: int = 20
    gemini_api_key: str = ""
    groq_api_key: str = ""

    class Config:
        env_file = ".env"
        extra = "ignore"

    # ---- derived helpers ----
    @property
    def is_production(self) -> bool:
        return self.app_env.strip().lower() in {"production", "prod"}

    @property
    def cors_list(self) -> list[str]:
        return _csv(self.cors_origins)

    @property
    def trusted_proxy_set(self) -> set[str]:
        return set(_csv(self.trusted_proxies))

    @property
    def app_key_set(self) -> set[str]:
        return set(_csv(self.app_api_keys))

    @property
    def decoys(self) -> list[str]:
        return [d.lower() for d in _csv(self.decoy_usernames)]


settings = Settings()

# Warnings the console can display (see /api/security/status)
SECURITY_WARNINGS: list[dict] = []
DEV_APP_KEY: dict = {"value": None}   # generated client-app key (development only)


def _warn(code: str, message: str, fatal_in_prod: bool = True):
    SECURITY_WARNINGS.append({"code": code, "message": message})
    if settings.is_production and fatal_in_prod:
        raise RuntimeError(f"Refusing to start in production: {message}")
    log.warning("SECURITY: %s", message)


def harden() -> None:
    """Apply safe defaults and flag weak configuration. Called once at import time."""
    SECURITY_WARNINGS.clear()

    # JWT signing key
    s = settings.jwt_secret or ""
    if not s:
        _warn("jwt_secret_missing", "JWT_SECRET is not set; using a random per-process key (tokens reset on restart).")
        settings.jwt_secret = secrets.token_urlsafe(48)
    elif len(s) < 32 or s.lower() in _WEAK_SECRETS or s.lower().startswith("dev_secret"):
        _warn("jwt_secret_weak", "JWT_SECRET is weak or a known default; anyone who guesses it can forge admin tokens.")

    # Admin password
    pw = settings.admin_password or ""
    if not pw:
        _warn("admin_password_missing", "ADMIN_PASSWORD is not set; generated a one-time random password (printed below).")
        settings.admin_password = secrets.token_urlsafe(12)
        print(f"[CYBERMIND] Generated admin password for '{settings.admin_username}': {settings.admin_password}", flush=True)
    elif pw.lower() in _WEAK_PASSWORDS or len(pw) < 10:
        _warn("admin_password_weak", "ADMIN_PASSWORD is weak or a known default.")

    # Client IP header trust (a client can write any X-Forwarded-For)
    if settings.allow_client_ip_header is None:
        settings.allow_client_ip_header = not settings.is_production
    if settings.allow_client_ip_header:
        _warn("client_ip_header_trusted",
              "DEV MODE: a client-supplied X-Forwarded-For header is trusted (needed for the IP-change demo). Set ALLOW_CLIENT_IP_HEADER=false.",
              fatal_in_prod=True)

    # CORS
    if "*" in settings.cors_list:
        _warn("cors_wildcard", "CORS_ORIGINS contains '*'; any website could call this API from a browser.")

    # Client app keys for the login-protection API
    if not settings.app_key_set:
        key = "cm_dev_" + secrets.token_urlsafe(18)
        settings.app_api_keys = key
        DEV_APP_KEY["value"] = key
        _warn("app_key_generated",
              "APP_API_KEYS not set; generated a dev key (visible to the admin at /api/security/status).",
              fatal_in_prod=True)


harden()
