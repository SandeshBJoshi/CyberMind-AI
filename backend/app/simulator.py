"""Generates realistic demo/simulation behavioral telemetry so the system can
be exercised end-to-end without needing real user traffic or real attacks.

Two profiles:
  - normal traffic: gaussian-ish human typing/mouse behavior, stable IP/device
  - attack traffic: uniform (bot-like) keystroke timing, IP/device churn,
    rapid API bursts, and repeated failed logins - designed to trip both the
    rule engine and the Isolation Forest.
"""
import random
import numpy as np

NORMAL_IPS = ["203.0.113.10", "203.0.113.10", "203.0.113.10"]
ATTACK_IPS = ["198.51.100.7", "198.51.100.44", "192.0.2.88", "192.0.2.201"]
DEVICES_NORMAL = ["Chrome/MacOS-A1"]
DEVICES_ATTACK = ["curl/7.88.0", "python-requests/2.31", "unknown-bot-agent"]


def normal_behavior_event(session_id: str) -> dict:
    return {
        "session_id": session_id,
        "event_type": "behavior",
        "ip_address": random.choice(NORMAL_IPS),
        "device_info": random.choice(DEVICES_NORMAL),
        "keystroke_avg_interval_ms": float(np.random.normal(220, 25)),
        "keystroke_std_interval_ms": float(np.random.normal(35, 6)),
        "typing_speed_cpm": float(np.random.normal(220, 25)),
        "mouse_click_rate": float(np.random.normal(1.2, 0.25)),
        "mouse_move_entropy": float(np.random.normal(0.6, 0.08)),
        "session_duration_sec": float(np.random.uniform(60, 900)),
    }


def attack_behavior_event(session_id: str) -> dict:
    # Bot-like: very low keystroke variance (too regular), high typing speed,
    # low mouse entropy (little/no real mouse movement), churn IP/device.
    return {
        "session_id": session_id,
        "event_type": "behavior",
        "ip_address": random.choice(ATTACK_IPS),
        "device_info": random.choice(DEVICES_ATTACK),
        "keystroke_avg_interval_ms": float(np.random.normal(40, 2)),
        "keystroke_std_interval_ms": float(np.random.normal(2, 0.5)),
        "typing_speed_cpm": float(np.random.normal(900, 20)),
        "mouse_click_rate": float(np.random.normal(0.05, 0.02)),
        "mouse_move_entropy": float(np.random.normal(0.02, 0.01)),
        "session_duration_sec": float(np.random.uniform(1, 15)),
    }


def failed_login_event(session_id: str) -> dict:
    return {
        "session_id": session_id,
        "event_type": "login_failed",
        "ip_address": random.choice(ATTACK_IPS),
        "device_info": random.choice(DEVICES_ATTACK),
    }


def api_burst_event(session_id: str) -> dict:
    return {
        "session_id": session_id,
        "event_type": "api_call",
        "ip_address": random.choice(ATTACK_IPS),
        "device_info": random.choice(DEVICES_ATTACK),
    }


def resource_access_event(session_id: str, resource: str) -> dict:
    return {
        "session_id": session_id,
        "event_type": "resource_access",
        "resource_accessed": resource,
    }


def training_feature_matrix(n=400) -> np.ndarray:
    """Synthetic 'normal' baseline for (re)training the Isolation Forest."""
    from .ml_engine import FEATURE_ORDER
    rows = []
    for _ in range(n):
        e = normal_behavior_event("bootstrap")
        rows.append([e.get(f, 0.0) or 0.0 for f in FEATURE_ORDER])
    return np.array(rows, dtype=float)
