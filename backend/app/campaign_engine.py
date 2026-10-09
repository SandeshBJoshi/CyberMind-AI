"""Campaign-level login protection.

Per-IP rules fail against rotating-IP credential stuffing: 5,000 IPs x 4 tries each never crosses a per-IP
threshold. This engine groups attempts by CLIENT FINGERPRINT (the expensive thing to change) instead of by IP
(the cheap thing to change), then scores the group as a whole.

Two entry points (both take an injectable `now`, which is what lets the attack lab replay hours in seconds):
  precheck(...)             before the app verifies a password: what should we do with this client?
  record_and_evaluate(...)  after the app knows the outcome: store the attempt, rescore its campaign.
Decisions: "allow" | "step_up" (ask for extra proof) | "deny".
"""
import datetime as dt
import hashlib
import statistics
import uuid

from sqlalchemy import case, distinct, func
from sqlalchemy.orm import Session

from . import breach, models, netinfo
from .config import settings

# ----------------------------------------------------------------------------- fingerprinting


def ua_family(ua: str | None) -> str:
    u = (ua or "").lower()
    if not u:
        return "none"
    for key, name in (("python-requests", "python-requests"), ("python-urllib", "python-urllib"), ("curl/", "curl"), ("go-http", "go-http"),
                      ("okhttp", "okhttp"), ("headlesschrome", "headless-chrome"), ("httpclient", "httpclient"), ("axios", "axios"), ("node-fetch", "node-fetch"),
                      ("tor", "tor-browser")):
        if key in u:
            return name
    mobile = "-mobile" if ("mobile" in u or "android" in u or "iphone" in u) else ""
    for key, name in (("edg/", "edge"), ("firefox/", "firefox"), ("chrome/", "chrome"), ("safari/", "safari")):
        if key in u:
            return name + mobile
    return "other"


def fingerprint(user_agent: str | None, header_fp: str | None = None, tls_fp: str | None = None) -> str:
    """Stable id for 'the same client software', whatever IP it comes from."""
    raw = f"{ua_family(user_agent)}|{header_fp or ''}|{tls_fp or ''}"
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


def header_order_fp(header_names: list[str] | None) -> str | None:
    """Real browsers send headers in a characteristic order; scripts usually do not."""
    if not header_names:
        return None
    return hashlib.sha1(",".join(h.lower() for h in header_names).encode()).hexdigest()[:8]


# ----------------------------------------------------------------------------- scoring


def _window_stats(db: Session, sig: str, since: dt.datetime, until: dt.datetime) -> dict:
    A = models.LoginAttempt
    base = (A.signature == sig, A.timestamp >= since, A.timestamp <= until)
    n, ips, users, fails, breached, decoys = db.query(
        func.count(A.id), func.count(distinct(A.ip_address)), func.count(distinct(A.username)),
        func.coalesce(func.sum(case((A.success == False, 1), else_=0)), 0),    # noqa: E712
        func.coalesce(func.sum(case((A.breached == True, 1), else_=0)), 0),    # noqa: E712
        func.coalesce(func.sum(case((A.decoy == True, 1), else_=0)), 0),       # noqa: E712
    ).filter(*base).one()
    f_ips, f_users = db.query(func.count(distinct(A.ip_address)), func.count(distinct(A.username))).filter(*base, A.success == False).one()  # noqa: E712
    dc = db.query(func.count(A.id)).filter(*base, A.network_type == "datacenter").scalar() or 0
    stamps = [r[0] for r in db.query(A.timestamp).filter(*base).order_by(A.timestamp.desc()).limit(80).all()]
    cv = None
    if len(stamps) >= 20:
        gaps = [(stamps[i] - stamps[i + 1]).total_seconds() for i in range(len(stamps) - 1)]
        mean = statistics.mean(gaps)
        cv = (statistics.pstdev(gaps) / mean) if mean > 0 else 0.0
    return {
        "attempts": n, "distinct_ips": ips, "distinct_usernames": users, "fails": int(fails), "fail_ips": f_ips, "fail_users": f_users,
        "failure_ratio": (fails / n) if n else 0.0, "breached_share": (breached / n) if n else 0.0, "decoy_hits": int(decoys),
        "datacenter_share": (dc / n) if n else 0.0, "timing_cv": cv,
    }


def score_stats(s: dict) -> tuple[float, list[dict]]:
    reasons: list[dict] = []

    def add(code, pts, text):
        reasons.append({"code": code, "points": pts, "text": text})

    if s["attempts"] >= 100:
        add("campaign_volume", 2.0, f"{s['attempts']} attempts from one client fingerprint in {settings.campaign_window_min} min")
    elif s["attempts"] >= 20:
        add("campaign_volume", 1.0, f"{s['attempts']} attempts from one client fingerprint in {settings.campaign_window_min} min")
    if s["attempts"] >= 10 and s["failure_ratio"] >= 0.8:
        add("high_failure_ratio", 3.0, f"{s['failure_ratio']:.0%} of attempts failed (normal sites see a few percent)")
    elif s["attempts"] >= 10 and s["failure_ratio"] >= 0.5:
        add("high_failure_ratio", 1.5, f"{s['failure_ratio']:.0%} of attempts failed")
    if s["fail_ips"] >= 60 and s["failure_ratio"] >= 0.3:
        add("many_failing_ips", 3.0, f"failures arrived from {s['fail_ips']} different IPs (rotation)")
    elif s["fail_ips"] >= 15 and s["failure_ratio"] >= 0.5:
        add("many_failing_ips", 2.0, f"failures arrived from {s['fail_ips']} different IPs")
    if s["fails"] >= 10 and s["fail_users"] >= 10 and s["fail_users"] / max(1, s["fails"]) >= 0.7:
        add("many_usernames_one_try_each", 2.0, f"{s['fail_users']} different usernames each failed about once (stuffing / spraying)")
    if s["fails"] >= 100:
        add("failure_spike", 2.0, f"{s['fails']} failed logins in {settings.campaign_window_min} min")
    if s["attempts"] >= 5 and s["breached_share"] >= 0.2:
        add("breached_passwords", 2.0, f"{s['breached_share']:.0%} of attempts used a known-breached password")
    if s["decoy_hits"] >= 1:
        add("decoy_touched", 6.0, f"{s['decoy_hits']} attempt(s) on decoy accounts nobody legitimate uses")
    if s["timing_cv"] is not None and s["attempts"] >= 20 and s["timing_cv"] < 0.35:
        add("machine_timing", 1.0, "attempts arrive at machine-regular intervals")
    if s["attempts"] >= 20 and s["datacenter_share"] >= 0.6:
        add("datacenter_network", 1.0, "most attempts come from hosting / data-centre networks")
    return sum(r["points"] for r in reasons), reasons


# ----------------------------------------------------------------------------- helpers


def _decoy_set(db: Session) -> set[str]:
    return {d.username for d in db.query(models.DecoyAccount.username).all()}


def _active_campaign(db: Session, sig: str, now: dt.datetime) -> models.Campaign | None:
    c = (db.query(models.Campaign).filter(models.Campaign.signature == sig, models.Campaign.status.in_(("watching", "blocked")))
         .order_by(models.Campaign.last_seen.desc()).first())
    if c is None:
        return None
    ttl = dt.timedelta(minutes=settings.campaign_block_ttl_min)
    if c.status == "blocked" and c.blocked_at and now - c.blocked_at > ttl and now - c.last_seen > dt.timedelta(minutes=settings.campaign_window_min):
        c.status = "released"
        db.commit()
        return None
    return c


def _known_good(db: Session, camp: models.Campaign, uname: str, ip: str | None) -> bool:
    """A returning user: this username already logged in successfully from this IP before the campaign began."""
    if not uname or not ip:
        return False
    A = models.LoginAttempt
    return db.query(A.id).filter(A.username == uname, A.ip_address == ip, A.success == True, A.timestamp < camp.first_seen).first() is not None  # noqa: E712


def _is_participant(db: Session, camp: models.Campaign, ip: str | None) -> bool:
    """An IP that hammered the login with several FAILURES inside this campaign. (One typo is not participation:
    a rotating-IP attacker is caught by the fingerprint, not by remembering single-use IPs.)"""
    if not ip:
        return False
    A = models.LoginAttempt
    n = db.query(func.count(A.id)).filter(A.campaign_id == camp.id, A.ip_address == ip, A.success == False).scalar() or 0  # noqa: E712
    touched_decoy = db.query(A.id).filter(A.ip_address == ip, A.decoy == True).first() is not None                      # noqa: E712
    return n >= 3 or touched_decoy       # touching a decoy is enough: no legitimate person ever does


# ----------------------------------------------------------------------------- public API


def precheck(db: Session, *, username: str | None, ip: str | None, user_agent: str | None, header_fp: str | None = None,
             tls_fp: str | None = None, password_sha1: str | None = None, now: dt.datetime | None = None) -> dict:
    """Decide BEFORE the app verifies the password. Stateless: does not store anything."""
    now = now or dt.datetime.utcnow()
    uname = (username or "").strip().lower()
    sig = fingerprint(user_agent, header_fp, tls_fp)
    if uname and uname in _decoy_set(db):
        return {"decision": "deny", "reason": "decoy_touched", "signature": sig, "campaign_id": None}
    camp = _active_campaign(db, sig, now)
    if camp and camp.status == "blocked":
        if _is_participant(db, camp, ip):
            return {"decision": "deny", "reason": "blocked_campaign", "signature": sig, "campaign_id": camp.id}
        if _known_good(db, camp, uname, ip):
            return {"decision": "allow", "reason": "known_good_user", "signature": sig, "campaign_id": camp.id}
        return {"decision": "step_up", "reason": "fingerprint_under_active_campaign", "signature": sig, "campaign_id": camp.id}
    return {"decision": "allow", "reason": None, "signature": sig, "campaign_id": camp.id if camp else None}


def record_and_evaluate(db: Session, *, username: str | None, success: bool, ip: str | None, user_agent: str | None,
                        header_fp: str | None = None, tls_fp: str | None = None, password_sha1: str | None = None,
                        now: dt.datetime | None = None) -> dict:
    now = now or dt.datetime.utcnow()
    uname = (username or "").strip().lower()
    sig = fingerprint(user_agent, header_fp, tls_fp)
    decoy_row = db.query(models.DecoyAccount).filter_by(username=uname).first() if uname else None
    is_decoy = decoy_row is not None
    if decoy_row:
        decoy_row.hits = (decoy_row.hits or 0) + 1
        decoy_row.last_hit = now
    is_breached = breach.is_breached(password_sha1)

    attempt = models.LoginAttempt(
        timestamp=now, username=uname, success=bool(success), ip_address=ip, network_type=netinfo.network_type(ip),
        user_agent=(user_agent or "")[:300], signature=sig, breached=is_breached, decoy=is_decoy, decision="allow",
    )
    db.add(attempt)
    db.flush()

    since = now - dt.timedelta(minutes=settings.campaign_window_min)
    stats = _window_stats(db, sig, since, now)
    score, reasons = score_stats(stats)

    camp = _active_campaign(db, sig, now)
    newly_blocked = False
    if score >= settings.campaign_watch_threshold:
        if camp is None:
            camp = models.Campaign(id=uuid.uuid4().hex[:10], signature=sig, status="watching", first_seen=now, sample_user_agent=(user_agent or "")[:200])
            db.add(camp)
        camp.last_seen = now
        camp.attempts, camp.distinct_ips, camp.distinct_usernames = stats["attempts"], stats["distinct_ips"], stats["distinct_usernames"]
        camp.failure_ratio, camp.breached_share, camp.decoy_hits = stats["failure_ratio"], stats["breached_share"], stats["decoy_hits"]
        camp.score, camp.reasons = score, reasons
        if score >= settings.campaign_block_threshold and camp.status != "blocked":
            camp.status, camp.blocked_at, newly_blocked = "blocked", now, True
        A = models.LoginAttempt
        db.query(A).filter(A.signature == sig, A.timestamp >= since, A.campaign_id.is_(None),
                           (A.success == False) | (A.breached == True) | (A.decoy == True)  # noqa: E712
                           ).update({"campaign_id": camp.id}, synchronize_session=False)
        if (not success) or is_breached or is_decoy:
            attempt.campaign_id = camp.id

    # what should this actor face next?
    decision = "allow"
    if is_decoy:
        decision = "deny"
    elif camp is not None and camp.status == "blocked":
        if _is_participant(db, camp, ip):
            decision = "deny"
        elif _known_good(db, camp, uname, ip):
            decision = "allow"
        else:
            decision = "step_up"
    elif camp is not None and camp.status == "watching" and (is_breached or not success):
        decision = "step_up"
    attempt.decision = decision
    db.commit()
    return {
        "decision": decision, "signature": sig, "campaign_id": camp.id if camp else None, "campaign_status": camp.status if camp else None,
        "score": round(score, 2), "reasons": reasons, "newly_blocked": newly_blocked, "decoy": is_decoy, "breached": is_breached, "stats": stats,
    }


def campaign_dict(c: models.Campaign) -> dict:
    return {
        "id": c.id, "signature": c.signature, "status": c.status, "first_seen": c.first_seen, "last_seen": c.last_seen, "blocked_at": c.blocked_at,
        "attempts": c.attempts, "distinct_ips": c.distinct_ips, "distinct_usernames": c.distinct_usernames,
        "failure_ratio": round(c.failure_ratio or 0, 3), "breached_share": round(c.breached_share or 0, 3), "decoy_hits": c.decoy_hits,
        "score": round(c.score or 0, 2), "reasons": c.reasons or [], "sample_user_agent": c.sample_user_agent,
    }


def release(db: Session, campaign_id: str) -> bool:
    c = db.query(models.Campaign).filter_by(id=campaign_id).first()
    if not c:
        return False
    c.status = "released"
    db.commit()
    return True
