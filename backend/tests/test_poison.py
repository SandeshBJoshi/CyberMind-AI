"""Feature 1: phishing poison tracing. Planted credentials are traced at the login, normal users are untouched, and the flag works."""
import json
import unittest
import uuid

from fastapi.testclient import TestClient

from app import models, security
from app.config import settings
from app.database import SessionLocal
from app.main import app
from app.routers import bank_routes

ADMIN = {"username": "admin", "password": "Test-Admin-Pass-2026!"}
GOOD_PASSWORD = "Vault-Test-Pass-91x!"


class PoisonTests(unittest.TestCase):
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
        security.ingest_by_source.reset()
        bank_routes.register_by_ip.reset()
        settings.poison_tracing = True

    def tearDown(self):
        settings.poison_tracing = True
        with SessionLocal() as db:        # a poison hit blocks this test client's fingerprint (by design); reset for the other tests
            for model in (models.PoisonTrace, models.PoisonCredential, models.LoginAttempt, models.Campaign):
                db.query(model).delete()
            db.commit()

    def admin(self):
        r = self.client.post("/auth/login", json=ADMIN)
        self.assertEqual(r.status_code, 200, r.text)
        return {"Authorization": "Bearer " + r.json()["access_token"]}

    def analysis(self, sample, h):
        r = self.client.post("/api/email/analyze-sample", json={"name": sample}, headers=h)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["id"]

    def mint(self, h, sample="phish_bank_login"):
        r = self.client.post("/api/poison/mint", json={"analysis_id": self.analysis(sample, h)}, headers=h)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def bank_login(self, username, password):
        return self.client.post("/bank/login", json={"username": username, "password": password})

    # ------------------------------------------------------------------ planting
    def test_only_suspicious_or_phishing_emails_can_be_planted_from(self):
        h = self.admin()
        r = self.client.post("/api/poison/mint", json={"analysis_id": self.analysis("legit_newsletter", h)}, headers=h)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.client.post("/api/poison/mint", json={"analysis_id": 999999}, headers=h).status_code, 404)
        self.assertEqual(self.client.post("/api/poison/mint", json={"analysis_id": 1}).status_code, 401)

    def test_the_password_is_shown_once_and_never_stored_in_clear(self):
        h = self.admin()
        minted = self.mint(h)
        pw = minted["password"]
        with SessionLocal() as db:
            row = db.query(models.PoisonCredential).filter_by(id=minted["id"]).first()
            self.assertNotEqual(row.password_sha1, pw)
            self.assertNotIn(pw, json.dumps({c.name: str(getattr(row, c.name)) for c in row.__table__.columns}))
        for url in ("/api/poison", f"/api/poison/{minted['id']}"):
            self.assertNotIn(pw, self.client.get(url, headers=h).text)

    def test_one_active_credential_per_email_until_retired(self):
        h = self.admin()
        aid = self.analysis("phish_password_expiry", h)
        first = self.client.post("/api/poison/mint", json={"analysis_id": aid}, headers=h)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(self.client.post("/api/poison/mint", json={"analysis_id": aid}, headers=h).status_code, 409)
        self.client.post(f"/api/poison/{first.json()['id']}/retire", headers=h)
        self.assertEqual(self.client.post("/api/poison/mint", json={"analysis_id": aid}, headers=h).status_code, 200)

    # ------------------------------------------------------------------ a hit
    def test_using_the_planted_credential_is_refused_blocks_the_campaign_and_shows_the_timeline(self):
        h = self.admin()
        m = self.mint(h)
        r = self.bank_login(m["username"], m["password"])
        self.assertEqual(r.status_code, 429)                                   # refused like a decoy touch: the attacker learns nothing
        d = self.client.get(f"/api/poison/{m['id']}", headers=h).json()
        self.assertEqual((d["status"], d["uses"]), ("used", 1))
        self.assertIsNotNone(d["seconds_to_first_use"])
        self.assertEqual(d["campaign_status"], "blocked")                       # the attacker's whole fingerprint campaign is blocked
        self.assertEqual([e["kind"] for e in d["timeline"]], ["analysed", "planted", "used", "campaign_blocked"])
        camps = self.client.get("/api/campaigns", headers=h).json()["items"]
        blocked = [c for c in camps if c["id"] == d["campaign_id"]][0]
        self.assertIn("poison_credential_used", [x["code"] for x in blocked["reasons"]])   # an explained reason, not a bare score
        self.assertNotIn("decoy_touched", [x["code"] for x in blocked["reasons"]])

    def test_the_admin_login_is_protected_the_same_way(self):
        h = self.admin()
        m = self.mint(h)
        r = self.client.post("/auth/login", json={"username": m["username"], "password": m["password"]})
        self.assertEqual(r.status_code, 429)
        self.assertEqual(self.client.get(f"/api/poison/{m['id']}", headers=h).json()["status"], "used")

    def test_the_username_with_a_wrong_password_is_traced_but_marked_not_exact(self):
        h = self.admin()
        m = self.mint(h)
        self.assertEqual(self.bank_login(m["username"], "some-other-guess-1").status_code, 429)
        with SessionLocal() as db:
            self.assertFalse(db.query(models.PoisonTrace).filter_by(poison_id=m["id"]).first().exact)

    def test_the_hit_reaches_the_live_feed(self):
        h = self.admin()
        m = self.mint(h)
        token = h["Authorization"].split()[1]
        with self.client.websocket_connect("/ws/live?token=" + token) as ws:
            self.bank_login(m["username"], m["password"])
            seen = []
            for _ in range(12):
                msg = ws.receive_json()
                seen.append(msg.get("type"))
                if msg.get("type") == "poison_traced":
                    self.assertEqual(msg["poison_id"], m["id"])
                    self.assertTrue(msg["exact"])
                    break
        self.assertIn("poison_traced", seen)

    # ------------------------------------------------------------------ false-positive guard and flag
    def test_normal_customers_and_unknown_usernames_are_unaffected(self):
        h = self.admin()
        self.mint(h)
        name = "cust" + uuid.uuid4().hex[:8]
        self.assertEqual(self.client.post("/bank/register", json={"username": name, "full_name": "Normal Customer", "password": GOOD_PASSWORD}).status_code, 200)
        self.assertEqual(self.bank_login(name, GOOD_PASSWORD).status_code, 200)
        self.assertEqual(self.bank_login("someone.else99", "whatever-123").status_code, 401)   # unknown user: plain failure, not a poison hit
        with SessionLocal() as db:
            self.assertEqual(db.query(models.PoisonTrace).count(), 0)

    def test_a_retired_credential_no_longer_traces(self):
        h = self.admin()
        m = self.mint(h)
        self.client.post(f"/api/poison/{m['id']}/retire", headers=h)
        self.assertEqual(self.bank_login(m["username"], m["password"]).status_code, 401)
        with SessionLocal() as db:
            self.assertEqual(db.query(models.PoisonTrace).count(), 0)

    def test_with_the_flag_off_nothing_changes(self):
        h = self.admin()
        m = self.mint(h)
        settings.poison_tracing = False
        self.assertEqual(self.client.post("/api/poison/mint", json={"analysis_id": m["analysis_id"]}, headers=h).status_code, 403)
        self.assertEqual(self.bank_login(m["username"], m["password"]).status_code, 401)        # exactly like any unknown user
        with SessionLocal() as db:
            self.assertEqual(db.query(models.PoisonTrace).count(), 0)
            self.assertEqual(db.query(models.Campaign).count(), 0)


if __name__ == "__main__":
    unittest.main()
