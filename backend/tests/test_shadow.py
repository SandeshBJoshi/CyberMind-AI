"""Feature 2: shadow mode. Uncertain identity-change sessions are contained in a sandbox; nothing real moves; an admin decides."""
import datetime as dt
import random
import unittest
import uuid

from fastapi.testclient import TestClient

from app import models, security
from app.config import settings
from app.database import SessionLocal
from app.main import app
from app.routers import bank_routes

ADMIN = {"username": "admin", "password": "Test-Admin-Pass-2026!"}
PASSWORD = "Vault-Test-Pass-91x!"
OWNER_IP, OWNER_DEV = "82.64.12.9", "Mozilla/5.0 (Windows NT 10.0) Chrome/130"
THIEF_IP, THIEF_DEV = "185.23.9.4", "Mozilla/5.0 (X11; Linux) Firefox/128"
rng = random.Random(5)


def calm():
    return dict(keystroke_avg_interval_ms=rng.gauss(220, 12), keystroke_std_interval_ms=rng.gauss(35, 3), typing_speed_cpm=rng.gauss(230, 12),
                mouse_click_rate=max(0.3, rng.gauss(1.2, 0.1)), mouse_move_entropy=max(0.2, rng.gauss(0.6, 0.03)), session_duration_sec=rng.uniform(60, 600))


def robot():
    return dict(keystroke_avg_interval_ms=70, keystroke_std_interval_ms=6, typing_speed_cpm=760, mouse_click_rate=3.5, mouse_move_entropy=0.12, session_duration_sec=15)


class ShadowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._ctx = TestClient(app)
        cls.client = cls._ctx.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls._ctx.__exit__(None, None, None)

    def setUp(self):
        security.login_fail_by_ip.reset(); security.login_fail_by_user.reset(); security.ingest_by_source.reset(); bank_routes.register_by_ip.reset()
        settings.shadow_mode = True
        name = "cust" + uuid.uuid4().hex[:8]
        self.assertEqual(self.client.post("/bank/register", json={"username": name, "full_name": "Shadow Test", "password": PASSWORD}).status_code, 200)
        j = self.client.post("/bank/login", json={"username": name, "password": PASSWORD, "device_info": OWNER_DEV}).json()
        self.sid, self.hdr, self.name = j["session_id"], {"X-Session-Token": j["session_token"]}, name
        for _ in range(35):                                   # the owner's normal life builds their baseline
            self.event(OWNER_IP, OWNER_DEV, **calm())
        self.assertEqual(self.status_in_db(), "active")

    def tearDown(self):
        settings.shadow_mode = True

    # ---- helpers
    def event(self, ip, dev, event_type="behavior", **fields):
        r = self.client.post("/user/behavior", json={"session_id": self.sid, "event_type": event_type, "ip_address": ip, "device_info": dev, **fields}, headers=self.hdr)
        return r

    def thief_event(self):
        return self.event(THIEF_IP, THIEF_DEV, **calm())      # new device and network, but the owner's rhythm: uncertain, not conclusive

    def status_in_db(self, sid=None):
        with SessionLocal() as db:
            return db.query(models.SessionState).filter_by(session_id=sid or self.sid).first().status

    def admin(self):
        r = self.client.post("/auth/login", json=ADMIN)
        return {"Authorization": "Bearer " + r.json()["access_token"]}

    def transfer(self, recipient, amount):
        return self.client.post("/bank/transfer", json={"session_id": self.sid, "recipient": recipient, "amount": amount}, headers=self.hdr)

    def account(self):
        return self.client.get("/bank/account", params={"session_id": self.sid}, headers=self.hdr).json()

    def shadowed(self):
        r = self.thief_event()
        self.assertEqual(r.status_code, 200, r.text)
        return r

    # ---- entering shadow
    def test_an_uncertain_identity_change_enters_shadow_and_looks_completely_normal_to_the_client(self):
        r = self.shadowed()
        self.assertEqual(self.status_in_db(), "shadow")
        self.assertEqual((r.json()["status"], r.json()["tier"], r.json()["action_taken"]), ("SAFE", "allow", "none"))       # the browser is not told
        self.assertEqual(self.client.get(f"/user/status/{self.sid}", headers=self.hdr).json()["status"], "SAFE")
        with SessionLocal() as db:
            e = db.query(models.SecurityEvent).filter_by(session_id=self.sid, status="SHADOW").first()
            self.assertIsNotNone(e)
            self.assertIn("shadow_contained", [x["code"] for x in e.details["_decision"]["reasons"]])
            self.assertEqual(e.details["_decision"]["tier"], "shadow")
            self.assertEqual(db.query(models.ShadowCase).filter_by(session_id=self.sid, status="pending").count(), 1)

    def test_shadow_is_sticky_clean_looking_traffic_does_not_end_it(self):
        self.shadowed()
        for _ in range(3):
            self.event(OWNER_IP, OWNER_DEV, **calm())
        self.assertEqual(self.status_in_db(), "shadow")

    # ---- the sandbox
    def test_transfers_succeed_in_the_sandbox_but_real_money_never_moves(self):
        real = self.account()["profile"]["balance"]
        self.shadowed()
        r = self.transfer("Mule Account", 500)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["balance"], real - 500)                                   # balances stay consistent for whoever is inside
        acc = self.account()
        self.assertEqual(acc["profile"]["balance"], real - 500)
        self.assertEqual(acc["transactions"][0]["name"], "Mule Account")
        self.assertEqual((acc["step_up_required"], acc["locked"], acc["notice"]), (False, False, None))
        self.assertEqual(self.transfer("Too Much", real).status_code, 422)                   # insufficient funds in the sandbox too
        with SessionLocal() as db:
            cust = db.query(models.Customer).filter_by(username=self.name).first()
            self.assertEqual(cust.balance_cents / 100, real)                                 # the real balance is untouched
            self.assertEqual(db.query(models.BankTransaction).filter_by(customer_id=cust.id, category="Transfer").count(), 0)
            self.assertEqual(db.query(models.ShadowTransfer).filter_by(session_id=self.sid).count(), 1)

    def test_the_admin_queue_shows_the_attacker_intent_in_order(self):
        self.shadowed()
        self.transfer("Alpha", 100)
        self.transfer("Beta", 200)
        h = self.admin()
        item = [i for i in self.client.get("/api/shadow", headers=h).json()["items"] if i["session_id"] == self.sid][0]
        self.assertEqual((item["status"], item["transfers"], item["total_amount"], item["recipients"]), ("pending", 2, 300.0, ["Alpha", "Beta"]))
        self.assertGreater(item["seconds_left"], 0)
        d = self.client.get(f"/api/shadow/{self.sid}", headers=h).json()
        sent = [a["detail"]["recipient"] for a in d["intent_log"] if a["action"] == "transfer"]
        self.assertEqual(sent, ["Alpha", "Beta"])
        self.assertIn("new_device_for_user", [r["code"] for r in d["reasons"]])

    # ---- resolving it
    def test_release_restores_the_customer_and_tells_them_which_transfers_did_not_run(self):
        real = self.account()["profile"]["balance"]
        self.shadowed()
        self.transfer("Landlord", 250)
        h = self.admin()
        r = self.client.post(f"/api/shadow/{self.sid}/release", headers=h)
        self.assertEqual((r.status_code, r.json()["unexecuted_transfers"]), (200, 1))
        self.assertEqual(self.status_in_db(), "active")
        acc = self.account()
        self.assertEqual(acc["profile"]["balance"], real)                                    # back to the real account
        self.assertEqual(acc["notice"]["transfers"][0]["recipient"], "Landlord")             # told clearly what must be redone
        self.assertIn("NOT executed", acc["notice"]["message"])
        self.client.post("/bank/notice/dismiss", json={"session_id": self.sid}, headers=self.hdr)
        self.assertIsNone(self.account()["notice"])
        self.thief_event()                                                                   # the same new device is now trusted: no second shadowing
        self.assertEqual(self.status_in_db(), "active")
        self.assertEqual(self.client.post(f"/api/shadow/{self.sid}/release", headers=h).status_code, 400)

    def test_confirm_freezes_the_session_through_the_existing_lockdown_path(self):
        self.shadowed()
        h = self.admin()
        self.assertEqual(self.client.post(f"/api/shadow/{self.sid}/confirm", headers=h).status_code, 200)
        self.assertEqual(self.status_in_db(), "locked")
        self.assertEqual(self.transfer("Anyone", 5).status_code, 423)
        with SessionLocal() as db:
            rec = db.query(models.LockdownRecord).filter_by(session_id=self.sid).first()
            self.assertIn("shadow_confirmed", rec.reason)
        self.assertEqual(self.client.post("/api/lockdown/unlock", json={"session_id": self.sid}, headers=h).status_code, 200)

    def test_past_the_review_deadline_it_falls_back_to_step_up(self):
        self.shadowed()
        with SessionLocal() as db:
            c = db.query(models.ShadowCase).filter_by(session_id=self.sid).first()
            c.deadline = dt.datetime.utcnow() - dt.timedelta(minutes=1)
            db.commit()
        item = [i for i in self.client.get("/api/shadow", headers=self.admin()).json()["items"] if i["session_id"] == self.sid][0]
        self.assertEqual(item["status"], "expired")
        self.assertEqual(self.status_in_db(), "suspicious")
        self.assertEqual(self.transfer("Anyone", 5).status_code, 428)                        # exactly the earlier step-up behaviour

    # ---- what must NOT enter shadow
    def test_volume_alone_never_enters_shadow(self):
        for _ in range(66):
            self.event(OWNER_IP, OWNER_DEV, event_type="api_call", extra={"target_endpoint": "/api/x"})
        self.assertEqual(self.status_in_db(), "suspicious")                                  # step-up, not shadow
        with SessionLocal() as db:
            self.assertEqual(db.query(models.ShadowCase).filter_by(session_id=self.sid).count(), 0)

    def test_lockdown_level_evidence_is_blocked_not_shadowed(self):
        r = self.event(THIEF_IP, THIEF_DEV, **robot())
        self.assertIn(r.status_code, (200, 423))
        self.assertEqual(self.status_in_db(), "locked")
        with SessionLocal() as db:
            self.assertEqual(db.query(models.ShadowCase).filter_by(session_id=self.sid).count(), 0)

    def test_a_shadowed_session_that_then_shows_lockdown_level_evidence_is_blocked(self):
        self.shadowed()
        self.event(THIEF_IP, THIEF_DEV, **robot())
        self.assertEqual(self.status_in_db(), "locked")
        with SessionLocal() as db:
            self.assertEqual(db.query(models.ShadowCase).filter_by(session_id=self.sid).first().status, "confirmed")

    def test_with_the_flag_off_the_behaviour_is_exactly_the_earlier_step_up(self):
        settings.shadow_mode = False
        r = self.thief_event()
        self.assertEqual(r.json()["status"], "SUSPICIOUS")
        self.assertEqual(self.status_in_db(), "suspicious")
        self.assertEqual(self.transfer("Anyone", 5).status_code, 428)
        with SessionLocal() as db:
            self.assertEqual(db.query(models.ShadowCase).filter_by(session_id=self.sid).count(), 0)


if __name__ == "__main__":
    unittest.main()
