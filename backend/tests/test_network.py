"""Feature 3: CyberMind Network. Hub rules (min members, expiry, mute, auth) and the local watch-level signal."""
import datetime as dt
import os
import tempfile
import unittest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import campaign_engine, models, network
from app.config import settings
from app.database import Base

import importlib.util  # noqa: E402

# the backend package is also called "app", so the hub is loaded from its file under its own name
_spec = importlib.util.spec_from_file_location("cm_hub", os.path.join(os.path.dirname(__file__), "..", "..", "hub", "app.py"))
hub = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hub)

T0 = dt.datetime(2026, 1, 1, 12, 0, 0)
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"
SIG = campaign_engine.fingerprint(UA, "script-x")


class NetworkTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp()
        hub.DB_PATH, hub.ADMIN_KEY, hub.MIN_MEMBERS = os.path.join(tmp, "hub.db"), "admin-test-key", 2
        self.hub = TestClient(hub.app)
        self.admin = {"X-Admin-Key": "admin-test-key"}
        self.members = [self.hub.post("/v1/admin/members", json={"label": f"m{i}"}, headers=self.admin).json() for i in range(3)]
        self.saved = {k: getattr(settings, k) for k in ("network_enabled", "network_hub_url", "network_member_id", "network_member_key",
                                                         "network_hash_key", "network_signal_points")}
        settings.network_enabled, settings.network_hub_url, settings.network_hash_key = True, "http://hub.invalid", "shared-hash-secret-for-tests"
        self.use_member(0)
        network._cache.clear()
        network._http = self._route_to_hub
        network.share_async = lambda sig, codes: network._do_share(sig, codes)      # synchronous in tests
        self.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=self.engine)
        self.db = sessionmaker(bind=self.engine)()
        self.hub_down = False

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(settings, k, v)
        network._cache.clear()
        self.db.close()

    def use_member(self, i):
        settings.network_member_id, settings.network_member_key = self.members[i]["member_id"], self.members[i]["member_key"]

    def _route_to_hub(self, method, path, body=None, timeout=3.0):
        if self.hub_down:
            raise OSError("hub unreachable")
        h = {"X-Member-Id": settings.network_member_id, "X-Member-Key": settings.network_member_key}
        r = self.hub.request(method, path, json=body, headers=h)
        if r.status_code >= 400:
            raise OSError(f"hub said {r.status_code}")
        return r.json()

    def report_as(self, i, sig=SIG):
        self.use_member(i)
        network._do_share(sig, ["high_failure_ratio", "many_failing_ips"])

    def attempt(self, i, user, ip, success=False, sec=None, **kw):
        return campaign_engine.record_and_evaluate(self.db, username=user, success=success, ip=ip, user_agent=UA, header_fp="script-x",
                                                   now=T0 + dt.timedelta(seconds=sec if sec is not None else i * 0.5), **kw)

    # ------------------------------------------------------------------ hub rules
    def test_one_member_alone_is_not_enough_two_distinct_members_are(self):
        self.report_as(0)
        self.use_member(1)
        self.assertEqual(network.refresh(), 0)
        self.report_as(0)                              # the same member again does not count twice
        self.assertEqual(network.refresh(), 0)
        self.report_as(2)
        self.assertEqual(network.refresh(), 1)
        self.assertEqual(network.lookup(SIG)["members"], 2)

    def test_the_hub_only_ever_sees_a_keyed_hash(self):
        self.report_as(0)
        stored = hub._db().execute("SELECT indicator FROM reports").fetchone()[0]
        self.assertEqual(len(stored), 64)
        self.assertNotIn(SIG, stored)
        self.assertEqual(stored, network.hash_fp(SIG))
        settings.network_hash_key = "a-different-network"
        self.assertNotEqual(network.hash_fp(SIG), stored)       # without the shared secret the hash cannot be reproduced

    def test_unknown_members_and_bad_payloads_are_rejected(self):
        bad = {"X-Member-Id": "m_nope", "X-Member-Key": "x"}
        self.assertEqual(self.hub.get("/v1/indicators", headers=bad).status_code, 401)
        good = {"X-Member-Id": self.members[0]["member_id"], "X-Member-Key": self.members[0]["member_key"]}
        self.assertEqual(self.hub.post("/v1/report", json={"indicator": "not-a-hash"}, headers=good).status_code, 422)
        self.assertEqual(self.hub.post("/v1/admin/mute", json={"indicator": "a" * 64}, headers={"X-Admin-Key": "wrong"}).status_code, 403)

    def test_an_operator_can_mute_an_indicator_and_remove_a_member(self):
        self.report_as(0)
        self.report_as(1)
        self.use_member(2)
        self.assertEqual(network.refresh(), 1)
        self.hub.post("/v1/admin/mute", json={"indicator": network.hash_fp(SIG)}, headers=self.admin)
        self.assertEqual(network.refresh(), 0)
        self.hub.delete(f"/v1/admin/mute/{network.hash_fp(SIG)}", headers=self.admin)
        self.assertEqual(network.refresh(), 1)
        self.hub.delete(f"/v1/admin/members/{self.members[1]['member_id']}", headers=self.admin)      # their report stops counting
        self.assertEqual(network.refresh(), 0)

    # ------------------------------------------------------------------ the local signal
    def listed(self):
        self.report_as(0)
        self.report_as(1)
        self.use_member(2)
        network.refresh()

    def test_a_listed_fingerprint_tips_a_borderline_pattern_into_watch_with_an_explained_reason(self):
        for i in range(10):                                    # 50% failures = 1.5 points: below the watch line on its own
            res = self.attempt(i, f"user{i}", f"10.0.0.{i}", success=i % 2 == 0)
        self.assertIsNone(res["campaign_id"])
        self.db.query(models.LoginAttempt).delete()
        self.db.commit()
        self.listed()
        for i in range(10):
            res = self.attempt(i, f"user{i}", f"10.0.0.{i}", success=i % 2 == 0)
        self.assertEqual(res["campaign_status"], "watching")
        net = [r for r in res["reasons"] if r["code"] == "network_indicator"]
        self.assertEqual(len(net), 1)
        self.assertIn("2 other installs", net[0]["text"])

    def test_the_network_can_never_block_on_its_own(self):
        self.listed()
        settings.network_signal_points = 100.0                 # even an absurd weight is capped below the block line
        for i in range(12):
            res = self.attempt(i, f"user{i}", f"10.0.0.{i}", success=False)
        self.assertNotEqual(res["campaign_status"], "blocked")
        self.assertLess(res["score"], settings.campaign_block_threshold)

    def test_ordinary_customers_on_a_listed_fingerprint_are_untouched(self):
        self.listed()
        for i in range(8):
            res = self.attempt(i, f"customer{i}", f"10.1.0.{i}", success=True)
            self.assertEqual(res["decision"], "allow")
        self.assertIsNone(res["campaign_id"])
        self.assertEqual(campaign_engine.precheck(self.db, username="customer1", ip="10.1.0.1", user_agent=UA, header_fp="script-x", now=T0)["decision"], "allow")

    def test_a_local_block_is_shared_with_the_hub(self):
        self.use_member(0)
        for i in range(60):
            res = self.attempt(i, f"v{i}", f"20.0.{i // 250}.{i % 250}", success=False, sec=i * 0.5)
            if res["newly_blocked"]:
                break
        self.assertTrue(res["newly_blocked"])
        self.assertEqual(hub._db().execute("SELECT COUNT(*) FROM reports").fetchone()[0], 1)
        shared = hub._db().execute("SELECT reasons FROM reports").fetchone()[0]
        self.assertNotIn("network_indicator", shared)           # never echo the network's own hint back as evidence

    def test_flag_off_nothing_is_shared_or_used(self):
        self.listed()
        settings.network_enabled = False
        self.assertIsNone(network.lookup(SIG))
        for i in range(10):
            res = self.attempt(i, f"user{i}", f"10.0.0.{i}", success=i % 2 == 0)
        self.assertFalse([r for r in res["reasons"] if r["code"] == "network_indicator"])
        self.assertEqual(network.refresh(), 0)

    def test_the_lab_never_uses_or_feeds_the_network(self):
        self.listed()
        for i in range(10):
            res = self.attempt(i, f"user{i}", f"10.0.0.{i}", success=i % 2 == 0, network_aware=False)
        self.assertFalse([r for r in res["reasons"] if r["code"] == "network_indicator"])

    def test_a_dead_hub_never_breaks_logins(self):
        self.hub_down = True
        self.assertEqual(network.refresh(), 0)
        self.assertIn("unreachable", network.status()["last_error"])
        res = self.attempt(0, "alice", "10.2.0.1", success=True)
        self.assertEqual(res["decision"], "allow")


if __name__ == "__main__":
    unittest.main()
