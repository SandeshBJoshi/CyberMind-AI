"""Deterministic security rules over recent SecurityEvent history for a session.
Each rule that fires contributes a fixed weight toward the decision score (decision_engine.py) and its
name is stored in rule_flags for the audit log, which also makes every decision explainable.
"""
import datetime as dt

from sqlalchemy.orm import Session

from . import models
from .config import settings

RULE_WEIGHTS = {
    "excessive_failed_logins": 3.0,
    "unusual_login_hour": 1.0,
    "ip_or_device_change": 1.5,
    "request_burst": 3.0,            # a flood of requests is abnormal on its own: alone = SUSPICIOUS (step-up)
    "excessive_resource_access": 2.0,
    "typing_speed_threshold_exceeded": 4.0,   # scripted typing; alone = SUSPICIOUS, with any second signal = LOCKDOWN
    "baseline_deviation": 0.0,                # points come from the size of the deviation (see baseline.points_for)
    "new_device_for_user": 1.5,
    "decoy_touched": 6.0,
}

RULE_TEXT = {
    "excessive_failed_logins": "Many failed logins in a short time",
    "unusual_login_hour": "Login at an unusual hour",
    "ip_or_device_change": "IP address or device changed during the session",
    "request_burst": "Burst of API requests faster than a person could send",
    "excessive_resource_access": "Touched an unusually large number of different resources",
    "typing_speed_threshold_exceeded": "Typing speed beyond human range (scripted input)",
    "baseline_deviation": "Behaviour far from this user's own normal",
    "new_device_for_user": "Device and network never seen for this user",
    "decoy_touched": "A decoy account was touched",
}


def typing_threshold() -> tuple[float, float]:
    """(characters per minute, weight). Demo mode restores the old low threshold so a class demo locks easily."""
    if settings.demo_mode:
        return 100.0, 6.0
    return settings.typing_bot_cpm_threshold, RULE_WEIGHTS["typing_speed_threshold_exceeded"]


def weight_of(flag: str) -> float:
    if flag == "typing_speed_threshold_exceeded":
        return typing_threshold()[1]
    return RULE_WEIGHTS.get(flag, 0.0)


def _recent_events(db: Session, session_id: str, minutes: int, event_type: str | None = None, now: dt.datetime | None = None):
    cutoff = (now or dt.datetime.utcnow()) - dt.timedelta(minutes=minutes)
    q = db.query(models.SecurityEvent).filter(
        models.SecurityEvent.session_id == session_id,
        models.SecurityEvent.timestamp >= cutoff,
    )
    if event_type:
        q = q.filter(models.SecurityEvent.event_type == event_type)
    return q.all()


def evaluate_rules(db: Session, session: models.SessionState, event) -> list[str]:
    flags: list[str] = []

    # 1. Excessive failed logins
    failed = _recent_events(db, session.session_id, settings.failed_login_window_min, "login_failed")
    if len(failed) >= settings.failed_login_limit:
        flags.append("excessive_failed_logins")

    # 2. Unusual login hour (outside 05:00-23:00 UTC)
    if event.event_type in ("login_success", "login_failed"):
        hour = dt.datetime.utcnow().hour
        if hour < 5 or hour >= 23:
            flags.append("unusual_login_hour")

    # 3. IP or device change vs last known
    if event.ip_address and session.last_ip and event.ip_address != session.last_ip:
        flags.append("ip_or_device_change")
    elif event.device_info and session.last_device and event.device_info != session.last_device:
        flags.append("ip_or_device_change")

    # 4. Request burst (api_call events)
    api_calls = _recent_events(db, session.session_id, settings.request_burst_window_min, "api_call")
    if len(api_calls) >= settings.request_burst_limit:
        flags.append("request_burst")

    # 5. Excessive distinct resource access
    resource_events = _recent_events(db, session.session_id, settings.resource_access_window_min, "resource_access")
    distinct = {e.details.get("resource_accessed") for e in resource_events if e.details}
    if len(distinct) >= settings.resource_access_limit:
        flags.append("excessive_resource_access")

    # 6. Scripted typing speed. Only aggregated timing is inspected; raw input is never used.
    limit, _ = typing_threshold()
    if event.typing_speed_cpm is not None and event.typing_speed_cpm > limit:
        flags.append("typing_speed_threshold_exceeded")

    return flags


def rule_score(flags: list[str]) -> float:
    return sum(weight_of(f) for f in flags)
