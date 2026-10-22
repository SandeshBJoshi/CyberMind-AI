"""Campaign (fingerprint) detection, decoys and the breached-password check."""
import datetime as dt
import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import breach, campaign_engine, models
from app.database import Base

T0 = dt.datetime(2026, 1, 1, 12, 0, 0)
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=self.engine)
        self.db = sessionmaker(bind=self.engine)()
        self.db.add(models.DecoyAccount(username="svc_backup"))
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def attempt(self, i, user, ip, success=False, hfp="script-x", ua=UA, pw=None, sec=None):
        return campaign_engine.record_and_evaluate(self.db, username=user, success=success, ip=ip, user_agent=ua, header_fp=hfp,
                                                   password_sha1=pw, now=T0 + dt.timedelta(seconds=sec if sec is not None else i * 0.5))

    def test_rotating_ips_are_caught_although_no_single_ip_repeats(self):
        decisions = [self.attempt(i, f"victim{i}", f"41.{i // 250}.{i % 250}.7")["decision"] for i in range(300)]
        self.assertTrue(any(d != "allow" for d in decisions), "a 300-IP, one-try-each campaign must be noticed")
        self.assertEqual(self.db.query(models.LoginAttempt.ip_address).distinct().count(), 300)       # truly one attempt per IP
        self.assertEqual(self.db.query(models.Campaign).filter_by(status="blocked").count(), 1)

    def test_decoy_account_is_an_instant_hostile_signal(self):
        res = self.attempt(0, "svc_backup", "5.5.5.5")
        self.assertEqual(res["decision"], "deny")
        self.assertTrue(res["decoy"])
        # the same client is then blocked everywhere, even on a real username
        self.assertEqual(campaign_engine.precheck(self.db, username="real.user", ip="5.5.5.5", user_agent=UA, header_fp="script-x", now=T0)["decision"], "deny")

    def test_normal_users_are_never_blocked(self):
        for i in range(120):                                  # ordinary people, a few typos, all different browsers
            res = self.attempt(i, f"user{i}", f"90.{i}.1.1", success=(i % 15 != 0), hfp="hdr-chrome", sec=i * 20)
            self.assertEqual(res["decision"], "allow")
        self.assertEqual(self.db.query(models.Campaign).count(), 0)

    def test_returning_user_is_not_stepped_up_during_a_campaign(self):
        self.attempt(0, "priya", "82.9.9.9", success=True, hfp="hdr-chrome", sec=-86400)           # logged in yesterday from home
        for i in range(300):
            self.attempt(i, f"v{i}", f"41.{i // 250}.{i % 250}.9", hfp="hdr-chrome")                 # attack shares Priya's fingerprint
        pre = campaign_engine.precheck(self.db, username="priya", ip="82.9.9.9", user_agent=UA, header_fp="hdr-chrome", now=T0 + dt.timedelta(seconds=200))
        self.assertEqual(pre["decision"], "allow")
        stranger = campaign_engine.precheck(self.db, username="newbie", ip="73.3.3.3", user_agent=UA, header_fp="hdr-chrome", now=T0 + dt.timedelta(seconds=200))
        self.assertEqual(stranger["decision"], "step_up")

    def test_breached_password_check_never_needs_the_password(self):
        self.assertTrue(breach.is_breached(breach.sha1_hex("123456")))
        self.assertFalse(breach.is_breached(breach.sha1_hex("a-long-random-passphrase-9f3k2")))
        self.assertFalse(breach.is_breached("not-a-hash"))

    def test_fingerprint_ignores_the_ip_address(self):
        a = campaign_engine.fingerprint(UA, "h1", None)
        self.assertEqual(a, campaign_engine.fingerprint(UA, "h1", None))
        self.assertNotEqual(a, campaign_engine.fingerprint("python-requests/2.31", "h1", None))


if __name__ == "__main__":
    unittest.main()
