"""The security of the security tool itself: authentication, signed telemetry, rate limits, header trust, CORS."""
import unittest
from types import SimpleNamespace

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app import security
from app.config import settings
from app.main import app

ADMIN = {"username": "admin", "password": "Test-Admin-Pass-2026!"}


def behaviour(**over):
    d = dict(keystroke_avg_interval_ms=220, keystroke_std_interval_ms=35, typing_speed_cpm=230, mouse_click_rate=1.2, mouse_move_entropy=0.6, session_duration_sec=300)
    d.update(over)
    return d


class ApiHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._ctx = TestClient(app)
        cls.client = cls._ctx.__enter__()          # runs the lifespan: creates tables, seeds admin + decoys

    @classmethod
    def tearDownClass(cls):
        cls._ctx.__exit__(None, None, None)

    def setUp(self):
        security.login_fail_by_ip.reset()
        security.login_fail_by_user.reset()

    def admin_headers(self):
        r = self.client.post("/auth/login", json=ADMIN)
        self.assertEqual(r.status_code, 200, r.text)
        return {"Authorization": "Bearer " + r.json()["access_token"]}

    def new_session(self, label="bank-user"):
        r = self.client.post("/user/session", json={"user_label": label})
        self.assertEqual(r.status_code, 200)
        return r.json()["session_id"], r.json()["session_token"]

    # ---- the doors that used to be open ----
    def test_session_list_requires_admin(self):
        self.assertEqual(self.client.get("/api/sessions").status_code, 401)
        self.assertEqual(self.client.get("/api/sessions", headers=self.admin_headers()).status_code, 200)

    def test_live_feed_requires_admin_token(self):
        with self.assertRaises(WebSocketDisconnect):
            with self.client.websocket_connect("/ws/live"):
                pass
        token = self.admin_headers()["Authorization"].split()[1]
        with self.client.websocket_connect(f"/ws/live?token={token}"):
            pass

    def test_simulator_and_session_creation_by_admin_only(self):
        self.assertEqual(self.client.post("/api/simulate/start-normal").status_code, 401)
        self.assertEqual(self.client.post("/api/sessions/start", json={"user_label": "x"}).status_code, 401)
        self.assertEqual(self.client.post("/api/sessions/start", json={"user_label": "x"}, headers=self.admin_headers()).status_code, 200)

    # ---- signed telemetry: knowing a session id is not enough ----
    def test_events_need_that_sessions_signed_token(self):
        sid, token = self.new_session()
        body = {"session_id": sid, "event_type": "behavior", **behaviour()}
        self.assertEqual(self.client.post("/user/behavior", json=body).status_code, 401)                                   # no token
        self.assertEqual(self.client.post("/user/behavior", json=body, headers={"X-Session-Token": "forged"}).status_code, 401)
        self.assertEqual(self.client.post("/user/behavior", json=body, headers={"X-Session-Token": token}).status_code, 200)

    def test_one_sessions_token_cannot_act_for_another_session(self):
        victim, _ = self.new_session("victim")
        _, attacker_token = self.new_session("attacker")
        body = {"session_id": victim, "event_type": "behavior", **behaviour(typing_speed_cpm=900)}
        self.assertEqual(self.client.post("/user/behavior", json=body, headers={"X-Session-Token": attacker_token}).status_code, 401)
        self.assertEqual(self.client.get(f"/user/status/{victim}", headers={"X-Session-Token": attacker_token}).status_code, 401)

    # ---- the admin login ----
    def test_login_is_rate_limited(self):
        for _ in range(settings.login_rate_limit_user):
            self.assertEqual(self.client.post("/auth/login", json={"username": "ghost", "password": "wrong"}).status_code, 401)
        self.assertEqual(self.client.post("/auth/login", json={"username": "ghost", "password": "wrong"}).status_code, 429)

    def test_logout_revokes_the_token(self):
        h = self.admin_headers()
        self.assertEqual(self.client.get("/auth/me", headers=h).status_code, 200)
        self.assertEqual(self.client.post("/auth/logout", headers=h).status_code, 200)
        self.assertEqual(self.client.get("/auth/me", headers=h).status_code, 401)

    def test_forged_token_is_rejected(self):
        self.assertEqual(self.client.get("/auth/me", headers={"Authorization": "Bearer abc.def.ghi"}).status_code, 401)

    # ---- the client-app (login protection) API ----
    def test_app_key_required_for_login_protection_api(self):
        body = {"username": "u", "ip_address": "41.1.1.1", "success": False, "user_agent": "x"}
        self.assertEqual(self.client.post("/api/auth-events/login-attempt", json=body).status_code, 401)
        ok = self.client.post("/api/auth-events/login-attempt", json=body, headers={"X-App-Key": "test-app-key"})
        self.assertEqual(ok.status_code, 200)
        self.assertIn(ok.json()["decision"], {"allow", "step_up", "deny"})

    # ---- CORS: only the console may call from a browser ----
    def test_cors_blocks_foreign_origins(self):
        evil = self.client.options("/auth/login", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
        self.assertNotIn("access-control-allow-origin", evil.headers)
        good = self.client.options("/auth/login", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"})
        self.assertEqual(good.headers.get("access-control-allow-origin"), "http://localhost:5173")

    # ---- protected action = the policy decision point ----
    def test_suspicious_sessions_need_step_up_for_sensitive_actions(self):
        h = self.admin_headers()
        sid = self.client.post("/api/sessions/start", json={"user_label": "pdp"}, headers=h).json()["session_id"]
        # put the session into SUSPICIOUS: scripted typing alone is a step-up
        self.client.post("/api/events/behavior", json={"session_id": sid, "event_type": "behavior",
                         **behaviour(keystroke_avg_interval_ms=40, keystroke_std_interval_ms=2, typing_speed_cpm=650, mouse_click_rate=1.0, mouse_move_entropy=0.5)}, headers=h)
        v = self.client.get(f"/api/sessions/{sid}/verify", headers=h).json()["decision"]
        if v == "step_up":
            r = self.client.post("/api/protected-action", json={"session_id": sid, "action": "transfer_funds"}, headers=h)
            self.assertEqual(r.status_code, 428)
            self.assertEqual(self.client.post("/api/protected-action", json={"session_id": sid, "action": "view_balance"}, headers=h).status_code, 200)
            self.assertEqual(self.client.post(f"/api/sessions/{sid}/step-up/clear", headers=h).status_code, 200)
            self.assertEqual(self.client.post("/api/protected-action", json={"session_id": sid, "action": "transfer_funds"}, headers=h).status_code, 200)
        else:
            self.assertIn(v, {"deny"})      # the ML model also flagged it: locked, which is stricter still

    def test_posture_report_is_admin_only(self):
        self.assertEqual(self.client.get("/api/security/status").status_code, 401)
        r = self.client.get("/api/security/status", headers=self.admin_headers())
        self.assertEqual(r.status_code, 200)
        self.assertTrue(all(c["ok"] for c in r.json()["checks"] if c["id"] in {"client_ip", "cors", "jwt_secret", "admin_password"}))


class ClientIpTrustTests(unittest.TestCase):
    def req(self, peer, xff=None):
        return SimpleNamespace(client=SimpleNamespace(host=peer), headers={"x-forwarded-for": xff} if xff else {})

    def test_forged_forwarded_for_is_ignored_by_default(self):
        self.assertFalse(settings.allow_client_ip_header)
        self.assertEqual(security.resolve_client_ip(self.req("203.0.113.9", xff="8.8.8.8")), "203.0.113.9")

    def test_forwarded_for_is_honoured_only_from_a_trusted_proxy(self):
        old = settings.trusted_proxies
        settings.trusted_proxies = "10.0.0.5"
        try:
            self.assertEqual(security.resolve_client_ip(self.req("10.0.0.5", xff="forged, 41.2.3.4")), "41.2.3.4")   # right-most untrusted hop
            self.assertEqual(security.resolve_client_ip(self.req("203.0.113.9", xff="8.8.8.8")), "203.0.113.9")        # not from the proxy
        finally:
            settings.trusted_proxies = old


class ConfigHardeningTests(unittest.TestCase):
    def test_production_refuses_weak_secrets(self):
        from app import config
        saved = (config.settings.app_env, config.settings.jwt_secret, config.settings.admin_password, config.settings.allow_client_ip_header)
        try:
            config.settings.app_env, config.settings.jwt_secret, config.settings.admin_password = "production", "dev_secret_change_me", "admin123"
            config.settings.allow_client_ip_header = False
            with self.assertRaises(RuntimeError):
                config.harden()
        finally:
            config.settings.app_env, config.settings.jwt_secret, config.settings.admin_password, config.settings.allow_client_ip_header = saved
            config.harden()


if __name__ == "__main__":
    unittest.main()
