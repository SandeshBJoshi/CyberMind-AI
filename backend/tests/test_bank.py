"""VaultApp, the protected demo bank: real accounts, protected login, and CYBERMIND's decisions enforced on transfers."""
import unittest
import uuid

from fastapi.testclient import TestClient

from app import security
from app.database import SessionLocal
from app import models
from app.main import app
from app.routers import bank_routes

PASSWORD = "Vault-Test-Pass-91x!"


class BankTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._ctx = TestClient(app)
        cls.client = cls._ctx.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls._ctx.__exit__(None, None, None)

    def setUp(self):
        security.login_fail_by_ip.reset()
        security.login_fail_by_user.reset()
        bank_routes.register_by_ip.reset()

    def make_customer(self):
        name = "cust" + uuid.uuid4().hex[:8]
        r = self.client.post("/bank/register", json={"username": name, "full_name": "Test Customer", "password": PASSWORD})
        self.assertEqual(r.status_code, 200, r.text)
        return name

    def login(self, name, password=PASSWORD):
        return self.client.post("/bank/login", json={"username": name, "password": password})

    def hdr(self, login_json):
        return {"X-Session-Token": login_json["session_token"]}

    def test_register_login_and_account(self):
        name = self.make_customer()
        r = self.login(name)
        self.assertEqual(r.status_code, 200, r.text)
        j = r.json()
        self.assertFalse(j["step_up_required"])
        acc = self.client.get("/bank/account", params={"session_id": j["session_id"]}, headers=self.hdr(j))
        self.assertEqual(acc.status_code, 200)
        self.assertEqual(acc.json()["profile"]["balance"], 12480.60)
        self.assertEqual(len(acc.json()["transactions"]), 5)

    def test_wrong_password_and_unknown_user_look_the_same(self):
        name = self.make_customer()
        a = self.login(name, "wrong-password-1")
        b = self.login("nobody" + uuid.uuid4().hex[:6], "wrong-password-1")
        self.assertEqual((a.status_code, a.json()["detail"]), (b.status_code, b.json()["detail"]))
        self.assertEqual(a.status_code, 401)

    def test_account_needs_the_session_token(self):
        name = self.make_customer()
        j = self.login(name).json()
        r = self.client.get("/bank/account", params={"session_id": j["session_id"]})
        self.assertEqual(r.status_code, 401)

    def test_transfer_moves_money_and_checks_balance(self):
        name = self.make_customer()
        j = self.login(name).json()
        ok = self.client.post("/bank/transfer", json={"session_id": j["session_id"], "recipient": "Alex", "amount": 100.5}, headers=self.hdr(j))
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertEqual(ok.json()["balance"], 12380.10)
        big = self.client.post("/bank/transfer", json={"session_id": j["session_id"], "recipient": "Alex", "amount": 10 ** 7}, headers=self.hdr(j))
        self.assertEqual(big.status_code, 422)

    def test_locked_session_cannot_transfer(self):
        name = self.make_customer()
        j = self.login(name).json()
        with SessionLocal() as db:
            s = db.query(models.SessionState).filter_by(session_id=j["session_id"]).first()
            s.status = "locked"
            db.commit()
        r = self.client.post("/bank/transfer", json={"session_id": j["session_id"], "recipient": "Alex", "amount": 5}, headers=self.hdr(j))
        self.assertEqual(r.status_code, 423)

    def test_step_up_blocks_transfer_until_password_reentered(self):
        name = self.make_customer()
        j = self.login(name).json()
        with SessionLocal() as db:
            s = db.query(models.SessionState).filter_by(session_id=j["session_id"]).first()
            s.status = "suspicious"
            db.commit()
        body = {"session_id": j["session_id"], "recipient": "Alex", "amount": 5}
        self.assertEqual(self.client.post("/bank/transfer", json=body, headers=self.hdr(j)).status_code, 428)
        bad = self.client.post("/bank/step-up/verify", json={"session_id": j["session_id"], "password": "nope-nope-nope"}, headers=self.hdr(j))
        self.assertEqual(bad.status_code, 401)
        good = self.client.post("/bank/step-up/verify", json={"session_id": j["session_id"], "password": PASSWORD}, headers=self.hdr(j))
        self.assertEqual(good.status_code, 200)
        self.assertEqual(self.client.post("/bank/transfer", json=body, headers=self.hdr(j)).status_code, 200)

    def test_clean_telemetry_does_not_clear_a_pending_step_up(self):
        name = self.make_customer()
        j = self.login(name).json()
        with SessionLocal() as db:
            s = db.query(models.SessionState).filter_by(session_id=j["session_id"]).first()
            s.status = "suspicious"
            db.commit()
        calm = dict(session_id=j["session_id"], event_type="behavior", keystroke_avg_interval_ms=220, keystroke_std_interval_ms=35,
                    typing_speed_cpm=230, mouse_click_rate=1.2, mouse_move_entropy=0.6, session_duration_sec=300)
        for _ in range(3):
            r = self.client.post("/user/behavior", json=calm, headers=self.hdr(j))
            self.assertEqual(r.json()["status"], "SUSPICIOUS")
        acc = self.client.get("/bank/account", params={"session_id": j["session_id"]}, headers=self.hdr(j))
        self.assertTrue(acc.json()["step_up_required"])

    def test_decoy_touch_on_bank_login_alerts_the_console_live(self):
        admin = self.client.post("/auth/login", json={"username": "admin", "password": "Test-Admin-Pass-2026!"}).json()["access_token"]
        with self.client.websocket_connect("/ws/live?token=" + admin) as ws:
            self.login("svc_backup", "whatever-123")
            seen = []
            for _ in range(10):
                msg = ws.receive_json()
                seen.append(msg.get("type"))
                if msg.get("type") in ("decoy_touched", "campaign_blocked"):
                    break
        self.assertTrue({"decoy_touched", "campaign_blocked"} & set(seen), seen)
        with SessionLocal() as db:       # reset: the decoy touch blocked this test client
            db.query(models.LoginAttempt).delete()
            db.query(models.Campaign).delete()
            db.commit()

    def test_decoy_username_cannot_be_registered_and_login_attempt_is_flagged(self):
        r = self.client.post("/bank/register", json={"username": "svc_backup", "full_name": "Mallory", "password": PASSWORD})
        self.assertEqual(r.status_code, 409)
        self.login("svc_backup", "whatever-123")
        with SessionLocal() as db:
            hit = db.query(models.LoginAttempt).filter_by(username="svc_backup").order_by(models.LoginAttempt.id.desc()).first()
            self.assertTrue(hit and hit.decoy)
            # the decoy touch blocked this test client, as designed; reset so the other tests are unaffected
            db.query(models.LoginAttempt).delete()
            db.query(models.Campaign).delete()
            db.commit()

    def test_weak_or_breached_password_rejected(self):
        r = self.client.post("/bank/register", json={"username": "u" + uuid.uuid4().hex[:6], "full_name": "Test", "password": "password1"})
        self.assertEqual(r.status_code, 422)
        short = self.client.post("/bank/register", json={"username": "u" + uuid.uuid4().hex[:6], "full_name": "Test", "password": "short"})
        self.assertEqual(short.status_code, 422)


if __name__ == "__main__":
    unittest.main()
