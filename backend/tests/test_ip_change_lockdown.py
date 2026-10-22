import asyncio
import unittest
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.database import Base
from app.models import SessionState
from app.routers.events_routes import ingest_behavior_event
from app.schemas import BehaviorEvent


class FakeRequest:
    def __init__(self, forwarded_for=None, real_ip=None, host=None):
        self.headers = {}
        if forwarded_for:
            self.headers["x-forwarded-for"] = forwarded_for
        if real_ip:
            self.headers["x-real-ip"] = real_ip
        self.client = SimpleNamespace(host=host) if host else SimpleNamespace(host="203.0.113.5")


class IPChangeLockdownTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()

    def tearDown(self):
        self.db.close()

    def test_real_ip_mismatch_is_contained_in_shadow_mode_by_default(self):
        """With shadow mode on (the default), an uncertain public IP change is contained in a sandbox instead of asking for step-up."""
        session = SessionState(session_id="sess-ip-shadow", user_label="demo-user", last_ip="8.8.4.4", status="active")
        self.db.add(session)
        self.db.commit()
        payload = BehaviorEvent(session_id="sess-ip-shadow", event_type="behavior", ip_address="8.8.4.4", device_info="Mozilla/5.0")
        result = asyncio.run(ingest_behavior_event(payload, self.db, request_ip="1.1.1.1"))
        self.db.expire_all()
        self.assertEqual((result["status"], result["tier"]), ("SHADOW", "shadow"))
        self.assertEqual(self.db.query(SessionState).filter_by(session_id="sess-ip-shadow").one().status, "shadow")

    def test_real_ip_mismatch_steps_up_when_shadow_mode_is_off(self):
        """SHADOW_MODE=false restores the earlier default: a public IP change asks for extra proof (SUSPICIOUS) instead of hard-locking the user."""
        old, settings.shadow_mode = settings.shadow_mode, False
        self.addCleanup(setattr, settings, "shadow_mode", old)
        session = SessionState(session_id="sess-ip-step", user_label="demo-user", last_ip="8.8.4.4", status="active")
        self.db.add(session)
        self.db.commit()
        payload = BehaviorEvent(session_id="sess-ip-step", event_type="behavior", ip_address="8.8.4.4", device_info="Mozilla/5.0")
        result = asyncio.run(ingest_behavior_event(payload, self.db, request_ip="1.1.1.1"))
        self.db.expire_all()
        session = self.db.query(SessionState).filter_by(session_id="sess-ip-step").one()
        self.assertEqual(result["status"], "SUSPICIOUS")
        self.assertEqual(result["tier"], "step_up")
        self.assertEqual(session.status, "suspicious")

    def test_real_ip_mismatch_triggers_lockdown(self):
        """IP_CHANGE_POLICY=lock restores the original hard-lockdown behaviour."""
        old, settings.ip_change_policy = settings.ip_change_policy, "lock"
        self.addCleanup(setattr, settings, "ip_change_policy", old)
        session = SessionState(session_id="sess-ip-change", user_label="demo-user", last_ip="8.8.4.4", status="active")
        self.db.add(session)
        self.db.commit()

        payload = BehaviorEvent(
            session_id="sess-ip-change",
            event_type="behavior",
            ip_address="8.8.4.4",
            device_info="Mozilla/5.0",
        )

        async def runner():
            return await ingest_behavior_event(payload, self.db, request_ip="1.1.1.1")

        result = asyncio.run(runner())
        self.db.expire_all()
        session = self.db.query(SessionState).filter_by(session_id="sess-ip-change").one()

        self.assertEqual(result["status"], "LOCKDOWN")
        self.assertEqual(session.status, "locked")
        self.assertEqual(session.last_ip, "8.8.4.4")

    def test_private_ip_mismatch_is_ignored(self):
        session = SessionState(session_id="sess-local-ip", user_label="demo-user", last_ip="198.51.100.44", status="active")
        self.db.add(session)
        self.db.commit()

        payload = BehaviorEvent(
            session_id="sess-local-ip",
            event_type="behavior",
            ip_address="198.51.100.44",
            device_info="Mozilla/5.0",
        )

        async def runner():
            return await ingest_behavior_event(payload, self.db, request_ip="127.0.0.1")

        result = asyncio.run(runner())
        self.db.expire_all()
        session = self.db.query(SessionState).filter_by(session_id="sess-local-ip").one()

        self.assertEqual(result["status"], "SAFE")
        self.assertEqual(session.status, "active")
        self.assertEqual(session.last_ip, "198.51.100.44")


if __name__ == "__main__":
    unittest.main()
