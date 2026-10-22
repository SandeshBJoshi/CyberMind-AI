"""Combines rule flags, the ML signal and per-user baseline evidence into a decision.

Output is a qualitative STATUS (SAFE / SUSPICIOUS / LOCKDOWN), a response TIER (allow / step_up / block)
and a list of human-readable REASONS. The numeric score is stored for audit but never sent to clients.
"""
from .config import settings
from . import rule_engine

ML_ANOMALY_WEIGHT = 2.5
SUSPICIOUS_THRESHOLD_RATIO = 0.5   # fraction of the lockdown threshold that counts as "suspicious"

TIER_FOR_STATUS = {"SAFE": "allow", "SUSPICIOUS": "step_up", "SHADOW": "shadow", "LOCKDOWN": "block"}


def _status_for(score: float) -> str:
    if score >= settings.lockdown_threshold:
        return "LOCKDOWN"
    if score >= settings.lockdown_threshold * SUSPICIOUS_THRESHOLD_RATIO:
        return "SUSPICIOUS"
    return "SAFE"


def decide(rule_flags: list[str], ml_is_anomaly: bool, extra_points: float = 0.0) -> tuple[str, float]:
    score = rule_engine.rule_score(rule_flags) + extra_points
    if ml_is_anomaly:
        score += ML_ANOMALY_WEIGHT
    return _status_for(score), score


def decide_detailed(rule_flags: list[str], ml_is_anomaly: bool, extras: list[dict] | None = None) -> dict:
    """extras: [{"code", "points", "text"}] for evidence that is not a fixed-weight rule (e.g. baseline deviation)."""
    extras = extras or []
    reasons = []
    for f in rule_flags:
        w = rule_engine.weight_of(f)
        if w:
            reasons.append({"code": f, "points": w, "text": rule_engine.RULE_TEXT.get(f, f)})
    for e in extras:
        reasons.append({"code": e["code"], "points": e["points"], "text": e["text"]})
    if ml_is_anomaly:
        reasons.append({"code": "ml_anomaly", "points": ML_ANOMALY_WEIGHT, "text": "Behaviour is statistically unusual (Isolation Forest)"})
    score = sum(r["points"] for r in reasons)
    status = _status_for(score)
    reasons.sort(key=lambda r: -r["points"])
    return {"status": status, "score": score, "tier": TIER_FOR_STATUS[status], "reasons": reasons}
