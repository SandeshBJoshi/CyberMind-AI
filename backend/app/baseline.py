"""Per-user behavioural baselines (running mean / variance, Welford's algorithm).

A population model only knows what a "typical user" looks like. A baseline knows what THIS user looks
like, which is what you need to notice that a different person is now driving someone's account.
"""
import math

from sqlalchemy.orm import Session

from . import models
from .config import settings

FEATURES = [
    "keystroke_avg_interval_ms", "keystroke_std_interval_ms", "typing_speed_cpm",
    "mouse_click_rate", "mouse_move_entropy", "session_duration_sec",
]
# session duration just grows during a session, so it is a poor identity signal; weight it out
IDENTITY_FEATURES = FEATURES[:5]
MAX_KNOWN = 20


def _vec(event) -> list[float] | None:
    vals = [getattr(event, f, None) for f in FEATURES]
    return None if any(v is None for v in vals) else [float(v) for v in vals]


def update(db: Session, user_key: str, event, ip: str | None, device: str | None) -> None:
    """Fold one SAFE event into the user's baseline. Never call this for suspicious / locked traffic
    (that would let an attacker teach the baseline their own behaviour: "poisoning")."""
    if not user_key:
        return
    b = db.query(models.UserBaseline).filter_by(user_key=user_key).first()
    if b is None:
        b = models.UserBaseline(user_key=user_key, n=0, mean=[0.0] * len(FEATURES), m2=[0.0] * len(FEATURES), ips=[], devices=[])
        db.add(b)
    vec = _vec(event)
    if vec is not None:
        n = (b.n or 0) + 1
        mean, m2 = list(b.mean or [0.0] * len(FEATURES)), list(b.m2 or [0.0] * len(FEATURES))
        for i, x in enumerate(vec):
            d = x - mean[i]
            mean[i] += d / n
            m2[i] += d * (x - mean[i])
        b.n, b.mean, b.m2 = n, mean, m2
    for field, val in (("ips", ip), ("devices", device)):
        if val:
            known = list(getattr(b, field) or [])
            if val not in known:
                known.append(val)
                setattr(b, field, known[-MAX_KNOWN:])
    db.add(b)


def deviation(db: Session, user_key: str, event) -> dict | None:
    """How far is this event from the user's own normal? Returns None until the baseline is trusted."""
    b = db.query(models.UserBaseline).filter_by(user_key=user_key).first() if user_key else None
    vec = _vec(event)
    if b is None or vec is None or (b.n or 0) < settings.baseline_min_events:
        return None
    worst, name = 0.0, None
    for i, f in enumerate(FEATURES):
        if f not in IDENTITY_FEATURES:
            continue
        var = (b.m2[i] / max(1, b.n - 1)) if b.m2 else 0.0
        std = max(math.sqrt(max(var, 0.0)), abs(b.mean[i]) * 0.05, 1e-3)    # std floor stops tiny variances exploding z
        z = abs(vec[i] - b.mean[i]) / std
        if z > worst:
            worst, name = z, f
    return {"max_z": round(worst, 2), "feature": name, "n": b.n}


def points_for(z: float) -> float:
    if z < 4:
        return 0.0
    if z < 6:
        return 1.5
    if z < 9:
        return 2.5
    return 3.0


def known_endpoints(db: Session, user_key: str) -> tuple[list[str], list[str]]:
    b = db.query(models.UserBaseline).filter_by(user_key=user_key).first()
    return (list(b.ips or []), list(b.devices or [])) if b else ([], [])
