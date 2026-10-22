"""Feature 4: adaptive attack-lab stress test (lab only)."""
import unittest

from app import adaptive, models
from app.database import Base, SessionLocal, engine


class AdaptiveTests(unittest.TestCase):
    NOISY = {"attempts": 300, "ips": 300, "duration_s": 600, "ua_mode": 1, "breached_pct": 10}
    STEALTH = {"attempts": 60, "ips": 60, "duration_s": 10800, "ua_mode": 2, "breached_pct": 0}

    def test_a_loud_attack_is_stopped_and_a_stealthy_one_slips_through(self):
        loud, quiet = adaptive.evaluate(self.NOISY), adaptive.evaluate(self.STEALTH)
        self.assertFalse(loud["slipped"])
        self.assertGreater(loud["peak_score"], 6.0)
        self.assertTrue(quiet["slipped"])             # the known limit of behaviour-only detection, found automatically
        self.assertLess(quiet["expected_harvest"], loud["expected_harvest"] + 5)

    def test_normal_users_are_not_harmed_by_the_attacks(self):
        self.assertEqual(adaptive.evaluate(self.NOISY)["normal_denied"], 0)

    def test_the_search_is_repeatable_and_reports_honestly(self):
        a = adaptive.search(4, 2, seed=3)
        self.assertEqual(adaptive.evaluate(self.STEALTH), adaptive.evaluate(self.STEALTH))      # same attacker, same result
        self.assertTrue(a["limits"])
        self.assertIn("block", a["thresholds"])
        if a["slipped_count"]:
            self.assertEqual(a["first_slip_at_variation"] is None, False)
            self.assertTrue(a["best_evader"]["description"])
        else:
            self.assertIsNone(a["best_evader"])
            self.assertTrue(a["verdict"].startswith("held"))

    def test_genomes_are_always_kept_inside_the_attacker_budget(self):
        g = adaptive._clip({"attempts": 99999, "ips": 99999, "duration_s": 0, "ua_mode": 9, "breached_pct": 99})
        self.assertLessEqual(g["attempts"], adaptive.BUDGET)
        self.assertLessEqual(g["ips"], g["attempts"])
        self.assertEqual(g["ua_mode"], 2)

    def test_it_never_touches_the_live_database_or_the_network_feature(self):
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            before = db.query(models.LoginAttempt).count(), db.query(models.Campaign).count()
        adaptive.evaluate(self.NOISY)
        with SessionLocal() as db:
            self.assertEqual((db.query(models.LoginAttempt).count(), db.query(models.Campaign).count()), before)

    def test_the_run_is_exposed_to_admins_only(self):
        from fastapi.testclient import TestClient
        from app.main import app
        with TestClient(app) as c:
            self.assertEqual(c.post("/api/lab/adaptive/run", json={}).status_code, 401)
            self.assertEqual(c.get("/api/lab/adaptive/results").status_code, 401)


if __name__ == "__main__":
    unittest.main()
