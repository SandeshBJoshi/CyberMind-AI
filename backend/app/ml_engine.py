"""ML anomaly detection engine (Isolation Forest on behavioural feature vectors).

Design notes
  * The model sits behind a tiny interface (fit / is_anomaly) so One-Class SVM, an autoencoder etc. can replace it.
  * It is only meaningful for events that actually carry all six behaviour features; callers must check
    `has_features(event)` first (a missing feature used to become 0.0 and look wildly "anomalous").
  * The model is loaded from disk, NOT retrained on synthetic data at every start. A bootstrap model is built once
    from a wide synthetic baseline; call `retrain_from_db` to learn from real SAFE traffic instead.
"""
import os

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from .config import settings

FEATURE_ORDER = [
    "keystroke_avg_interval_ms",
    "keystroke_std_interval_ms",
    "typing_speed_cpm",
    "mouse_click_rate",
    "mouse_move_entropy",
    "session_duration_sec",
]

MODEL_PATH = os.path.join(os.path.dirname(__file__), "isolation_forest_v2.joblib")
MIN_REAL_ROWS = 200


class AnomalyModel:
    """Common interface every anomaly model should implement."""

    def fit(self, X: np.ndarray):
        raise NotImplementedError

    def is_anomaly(self, x: np.ndarray) -> tuple[bool, float]:
        raise NotImplementedError


class IsolationForestModel(AnomalyModel):
    def __init__(self):
        self.model = IsolationForest(n_estimators=200, contamination=settings.ml_contamination, random_state=42)
        self._fitted = False
        self.source = "unfitted"

    def fit(self, X: np.ndarray, source: str = "synthetic"):
        self.model = IsolationForest(n_estimators=200, contamination=settings.ml_contamination, random_state=42)
        self.model.fit(X)
        self._fitted = True
        self.source = source
        joblib.dump({"model": self.model, "source": source}, MODEL_PATH)

    def load_if_available(self) -> bool:
        if os.path.exists(MODEL_PATH):
            blob = joblib.load(MODEL_PATH)
            self.model, self.source = blob["model"], blob.get("source", "synthetic")
            self._fitted = True
            return True
        return False

    def is_anomaly(self, x: np.ndarray) -> tuple[bool, float]:
        if not self._fitted:
            return False, 0.0
        pred = self.model.predict(x.reshape(1, -1))[0]               # -1 anomaly, 1 normal
        score = self.model.decision_function(x.reshape(1, -1))[0]    # higher = more normal
        return pred == -1, float(-score)                              # flipped: higher = more anomalous


def has_features(event) -> bool:
    return all(getattr(event, f, None) is not None for f in FEATURE_ORDER)


def vectorize(event) -> np.ndarray | None:
    """Feature vector, or None when any feature is missing (never silently substitute zeros)."""
    if not has_features(event):
        return None
    return np.array([float(getattr(event, f)) for f in FEATURE_ORDER], dtype=float)


def bootstrap_matrix(n: int = 1500) -> np.ndarray:
    """A deliberately WIDE synthetic 'normal' so real people are not flagged just for being different from
    the simulator. It is a stop-gap until enough real SAFE traffic exists (see retrain_from_db)."""
    rng = np.random.default_rng(0)
    return rng.normal(
        loc=[230, 38, 230, 1.3, 0.6, 400],
        scale=[75, 20, 90, 0.7, 0.2, 400],
        size=(n, len(FEATURE_ORDER)),
    ).clip(min=0.01)


_engine: IsolationForestModel | None = None


def get_ml_engine() -> IsolationForestModel:
    global _engine
    if _engine is None:
        _engine = IsolationForestModel()
        if not _engine.load_if_available():
            _engine.fit(bootstrap_matrix(), source="synthetic-bootstrap")
    return _engine


def retrain(X: np.ndarray, source: str = "synthetic"):
    get_ml_engine().fit(X, source=source)


def retrain_from_db(db) -> dict:
    """Learn 'normal' from real traffic: the behaviour vectors of SAFE events already in the audit log."""
    from . import models
    rows = (
        db.query(models.SecurityEvent)
        .filter(models.SecurityEvent.event_type == "behavior", models.SecurityEvent.status == "SAFE")
        .order_by(models.SecurityEvent.timestamp.desc()).limit(5000).all()
    )
    X = []
    for r in rows:
        d = r.details or {}
        if all(d.get(f) is not None for f in FEATURE_ORDER):
            X.append([float(d[f]) for f in FEATURE_ORDER])
    if len(X) < MIN_REAL_ROWS:
        return {"retrained": False, "reason": f"need at least {MIN_REAL_ROWS} real SAFE behaviour events, found {len(X)}", "found": len(X)}
    retrain(np.array(X), source="real-traffic")
    return {"retrained": True, "rows": len(X), "source": "real-traffic"}
