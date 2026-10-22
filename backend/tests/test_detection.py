"""Rules, ML gating, decision tiers and per-user baselines."""
import asyncio
import unittest
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import baseline, decision_engine, ml_engine, rule_engine
from app.config import settings
from app.database import Base
from app.routers.events_routes import process_behavior_event
from app.schemas import BehaviorEvent


def behaviour(**over):
    base = dict(keystroke_avg_interval_ms=220, keystroke_std_interval_ms=35, typing_speed_cpm=230, mouse_click_rate=1.2, mouse_move_entropy=0.6, session_duration_sec=300)
    base.update(over)
    return base


class DecisionTests(unittest.TestCase):
    def test_tiers_and_thresholds(self):
        self.assertEqual(decision_engine.decide_detailed([], False)["tier"], "allow")
        # one bot-typing flag alone is only a step-up, not a lockdown
        d = decision_engine.decide_detailed(["typing_speed_threshold_exceeded"], False)
        self.assertEqual((d["status"], d["tier"]), ("SUSPICIOUS", "step_up"))
        # with a second signal (ML) it is a lockdown
        d = decision_engine.decide_detailed(["typing_speed_threshold_exceeded"], True)
        self.assertEqual((d["status"], d["tier"]), ("LOCKDOWN", "block"))

    def test_every_decision_explains_itself(self):
        d = decision_engine.decide_detailed(["request_burst", "ip_or_device_change"], True)
        codes = {r["code"] for r in d["reasons"]}
        self.assertTrue({"request_burst", "ip_or_device_change", "ml_anomaly"} <= codes)
        self.assertAlmostEqual(d["score"], sum(r["points"] for r in d["reasons"]))

    def test_demo_mode_restores_low_typing_threshold(self):
        old = settings.demo_mode
        settings.demo_mode = True
        try:
            self.assertEqual(rule_engine.typing_threshold(), (100.0, 6.0))
        finally:
            settings.demo_mode = old
        self.assertEqual(rule_engine.typing_threshold()[0], settings.typing_bot_cpm_threshold)


class MlGatingTests(unittest.TestCase):
    def test_missing_features_are_not_turned_into_zeros(self):
        ev = SimpleNamespace(typing_speed_cpm=500)           # an api_call or login event carries no behaviour numbers
        self.assertFalse(ml_engine.has_features(ev))
        self.assertIsNone(ml_engine.vectorize(ev))

    def test_human_not_flagged_but_bot_is(self):
        eng = ml_engine.get_ml_engine()
        human = BehaviorEvent(session_id="s", **behaviour())
        bot = BehaviorEvent(session_id="s", **behaviour(keystroke_avg_interval_ms=40, keystroke_std_interval_ms=2, typing_speed_cpm=900,
                                                         mouse_click_rate=0.05, mouse_move_entropy=0.02, session_duration_sec=5))
        self.assertFalse(eng.is_anomaly(ml_engine.vectorize(human))[0])
        self.assertTrue(eng.is_anomaly(ml_engine.vectorize(bot))[0])


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=self.engine)
        self.db = sessionmaker(bind=self.engine)()

    def tearDown(self):
        self.db.close()

    def run_event(self, **kw):
        return asyncio.run(process_behavior_event(BehaviorEvent(**kw), self.db, quiet=True))

    def test_api_call_events_are_not_scored_by_ml(self):
        res = self.run_event(session_id="s1", event_type="api_call", ip_address="41.1.1.1", device_info="x")
        self.assertEqual(res["status"], "SAFE")          # previously an all-zero vector made every API call look anomalous

    def test_normal_typing_is_safe(self):
        res = self.run_event(session_id="s2", event_type="behavior", **behaviour(typing_speed_cpm=240))
        self.assertEqual(res["status"], "SAFE")

    def test_scripted_typing_plus_anomaly_locks_the_session(self):
        res = self.run_event(session_id="s3", event_type="behavior", **behaviour(keystroke_avg_interval_ms=40, keystroke_std_interval_ms=2, typing_speed_cpm=900,
                                                                               mouse_click_rate=0.05, mouse_move_entropy=0.02, session_duration_sec=5))
        self.assertEqual(res["status"], "LOCKDOWN")
        with self.assertRaises(Exception):                # a locked session is rejected (HTTP 423)
            self.run_event(session_id="s3", event_type="behavior", **behaviour())

    def test_baseline_notices_a_different_person_in_the_same_session(self):
        from app.routers.events_routes import _get_or_create_session
        _get_or_create_session(self.db, "s4", user_label="priya", ip="82.1.1.1", device="Chrome-A")
        for i in range(25):                                   # Priya's normal life builds her baseline
            r = self.run_event(session_id="s4", event_type="behavior", ip_address="82.1.1.1", device_info="Chrome-A",
                               **behaviour(typing_speed_cpm=225 + (i % 5), keystroke_avg_interval_ms=220 + (i % 4)))
            self.assertEqual(r["status"], "SAFE")
        # same session, but typing nothing like Priya, from a new device and network
        r = self.run_event(session_id="s4", event_type="behavior", ip_address="185.5.5.5", device_info="Firefox-B",
                           **behaviour(typing_speed_cpm=430, keystroke_avg_interval_ms=95, keystroke_std_interval_ms=9, mouse_click_rate=2.6, mouse_move_entropy=0.25))
        self.assertNotEqual(r["status"], "SAFE")

    def test_suspicious_traffic_does_not_poison_the_baseline(self):
        from app.routers.events_routes import _get_or_create_session
        _get_or_create_session(self.db, "s5", user_label="ravi", ip="82.2.2.2", device="Chrome-A")
        self.run_event(session_id="s5", event_type="behavior", ip_address="82.2.2.2", device_info="Chrome-A", **behaviour())
        n_before = self.db.query(baseline.models.UserBaseline).filter_by(user_key="ravi").one().n
        # a flagged event must not be folded into the baseline
        self.run_event(session_id="s5", event_type="behavior", ip_address="82.2.2.2", device_info="Chrome-A",
                       **behaviour(keystroke_avg_interval_ms=40, keystroke_std_interval_ms=2, typing_speed_cpm=900, mouse_click_rate=0.05, mouse_move_entropy=0.02))
        self.assertEqual(self.db.query(baseline.models.UserBaseline).filter_by(user_key="ravi").one().n, n_before)


if __name__ == "__main__":
    unittest.main()
