"""Realistic attack lab.

Replays scripted attacks (plus a population of normal users) through the REAL detection code, against a
throwaway in-memory database, using a simulated clock so hours of traffic run in seconds. It never touches the
live database or the live consoles.

Every scenario reports honest numbers: was the attack caught, how many attempts got through first, how many
normal users were wrongly denied or asked for extra proof. Two scenarios are EXPECTED to be missed; they are
there to show the limits of behaviour-based detection, not to flatter the system.
"""
import asyncio
import datetime as dt
import random
import threading
import time

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from . import breach, campaign_engine, models
from .config import settings
from .database import Base

BASE_TIME = dt.datetime(2026, 1, 1, 12, 0, 0)
P_SUCCESS = 0.02       # chance a stolen credential works if nothing stops the attempt

UA_CHROME_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
UA_SAFARI_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"
UA_CHROME_AND = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36"
UA_FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
UA_PY = "python-requests/2.31.0"

# (user agent, header-order fingerprint a real browser would produce, popularity)
BROWSERS = [(UA_CHROME_WIN, "hdr-chrome-win", 0.45), (UA_SAFARI_MAC, "hdr-safari-mac", 0.20), (UA_CHROME_AND, "hdr-chrome-and", 0.22), (UA_FIREFOX, "hdr-firefox", 0.13)]

SCENARIOS = {
    "normal_only": {"title": "Control: normal users only", "expected": "nothing flagged",
                    "about": "Hundreds of ordinary people logging in, with the occasional typo. Nothing here should be blocked."},
    "naive_burst": {"title": "Naive burst (one IP, fast)", "expected": "caught",
                    "about": "A script hammers the login page from a single IP with a default Python client."},
    "rotating_ips": {"title": "Rotating IPs (thousands of IPs, 1 try each)", "expected": "caught",
                     "about": "Credential stuffing through a proxy pool. No single IP ever exceeds one attempt. A per-IP rule sees nothing."},
    "low_and_slow": {"title": "Low and slow (hours, few tries per IP)", "expected": "caught, but later",
                     "about": "The same attack spread over three hours to stay under rate limits."},
    "password_spraying": {"title": "Password spraying", "expected": "caught",
                          "about": "One notorious password tried against hundreds of different usernames."},
    "human_like_bot": {"title": "Human-like bot (copies a real browser fingerprint)", "expected": "caught if volume is high",
                       "about": "Spoofs Chrome's header order exactly, so it shares a fingerprint with real users. Detection must rely on failures and volume."},
    "stealth_diluted": {"title": "Stealth, diluted (blends into normal traffic)", "expected": "MISSED (known limit)",
                        "about": "Few attempts, spread widely, using a real-browser fingerprint. Stays below every threshold. Included to show what this design cannot see."},
    "decoy_touch": {"title": "Decoy account touched", "expected": "caught instantly",
                    "about": "An attacker tries a decoy username that no real person would ever use."},
    "session_thief_different_rhythm": {"title": "Session thief with a different typing rhythm", "expected": "caught",
                                       "about": "A stolen session used from a new device and network, typing nothing like the real owner."},
    "session_thief_mimic": {"title": "Session thief copying the owner perfectly", "expected": "MISSED (by design)",
                            "about": "Same device, same network, same rhythm. Behaviour alone cannot see this; it needs device-bound tokens."},
    "session_thief_new_device_calm": {"title": "Session thief on a new device, owner-like rhythm", "expected": "contained in shadow mode",
                                      "about": "A stolen session used from a new device and network, typing like the owner. The evidence is uncertain, so it is served from a sandbox "
                                               "(nothing real moves) while an admin decides."},
    "session_owner_new_device": {"title": "The real owner on a new laptop (a false positive)", "expected": "shadowed by mistake, bounded by review",
                                 "about": "The genuine owner signs in from a new device and network. Shadow mode cannot tell them from a thief, so it contains the session until an "
                                          "admin releases it. Counted as a false positive: that is the cost this feature has to be judged on."},
}
LOGIN_SCENARIOS = [k for k in SCENARIOS if not k.startswith("session_")]


# ----------------------------------------------------------------------------- traffic generators
def _public_ip(rng):
    return f"{rng.randint(11, 99)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _pick_browser(rng):
    r, acc = rng.random(), 0.0
    for ua, hfp, w in BROWSERS:
        acc += w
        if r <= acc:
            return ua, hfp
    return BROWSERS[0][0], BROWSERS[0][1]


def normal_traffic(rng, n_users, duration):
    cgnat = [_public_ip(rng) for _ in range(10)]
    users = [f"user{i:04d}" for i in range(n_users)]
    events = []
    for u in users:
        ua, hfp = _pick_browser(rng)
        ip = rng.choice(cgnat) if rng.random() < 0.10 else _public_ip(rng)
        weak = rng.random() < 0.03               # a few real people do use a famously weak password
        pw = breach.sha1_hex("123456" if weak else f"correct-horse-{rng.random()}")
        t = rng.uniform(0, duration)
        if rng.random() < 0.06:                  # a typo first
            events.append({"t": t, "kind": "normal", "username": u, "success": False, "ip": ip, "ua": ua, "hfp": hfp, "pw": pw})
            t += rng.uniform(5, 40)
        events.append({"t": t, "kind": "normal", "username": u, "success": True, "ip": ip, "ua": ua, "hfp": hfp, "pw": pw})
    return events, users


def _atk(t, user, ip, ua, hfp, pw, success=False):
    return {"t": t, "kind": "attacker", "username": user, "success": success, "ip": ip, "ua": ua, "hfp": hfp, "pw": pw}


def build_login_scenario(name, rng, scale, users):
    n = lambda base: max(10, int(base * scale))
    guessed = lambda: breach.sha1_hex("pw-%d" % rng.randint(0, 10**6)) if rng.random() > 0.15 else breach.sha1_hex("qwerty")
    pick_user = lambda: rng.choice(users) if rng.random() < 0.7 else f"someone{rng.randint(0, 99999)}"
    ev = []
    if name == "naive_burst":
        ip = _public_ip(rng)
        ev = [_atk(rng.uniform(0, 120), pick_user(), ip, UA_PY, "hdr-py", guessed()) for _ in range(n(600))]
        duration = 120
    elif name == "rotating_ips":
        ev = [_atk(rng.uniform(0, 600), pick_user(), _public_ip(rng), UA_CHROME_WIN, "hdr-script-x", guessed()) for _ in range(n(3000))]
        duration = 600
    elif name == "low_and_slow":
        pool = [_public_ip(rng) for _ in range(n(400))]
        ev = [_atk(rng.uniform(0, 10800), pick_user(), rng.choice(pool), UA_CHROME_WIN, "hdr-script-x", guessed()) for _ in range(n(1200))]
        duration = 10800
    elif name == "password_spraying":
        pool = [_public_ip(rng) for _ in range(60)]
        pw = breach.sha1_hex("Summer2026!")
        ev = [_atk(rng.uniform(0, 900), f"user{i:04d}" if i < len(users) else f"x{i}", rng.choice(pool), UA_PY, "hdr-py", pw) for i in range(n(500))]
        duration = 900
    elif name == "human_like_bot":
        ev = [_atk(rng.uniform(0, 1200), pick_user(), _public_ip(rng), UA_CHROME_WIN, "hdr-chrome-win", guessed()) for _ in range(n(2000))]
        duration = 1200
    elif name == "stealth_diluted":
        ev = [_atk(rng.uniform(0, 10800), pick_user(), _public_ip(rng), UA_CHROME_WIN, "hdr-chrome-win", guessed()) for _ in range(n(150))]
        duration = 10800
    elif name == "decoy_touch":
        pool = [_public_ip(rng) for _ in range(5)]
        ev = [_atk(rng.uniform(0, 60), pick_user(), rng.choice(pool), UA_PY, "hdr-py", guessed()) for _ in range(24)]
        ev.append(_atk(30.0, settings.decoys[0] if settings.decoys else "svc_backup", rng.choice(pool), UA_PY, "hdr-py", guessed()))
        duration = 60
    else:   # normal_only
        duration = 600
    return ev, duration


# ----------------------------------------------------------------------------- runners
def _fresh_db():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    for d in settings.decoys:
        db.add(models.DecoyAccount(username=d, note="lab"))
    db.commit()
    return db, eng


def _summary(name, atk_total, first_i, first_t, blocked, compromised, normal_total, denied, stepped, extra=None):
    meta = SCENARIOS[name]
    caught = first_i is not None and atk_total > 0
    blocked_share = (blocked / atk_total) if atk_total else 0.0
    after = (blocked / max(1, atk_total - first_i + 1)) if first_i else 0.0     # share stopped once the defence reacted
    if name == "normal_only":
        verdict = "clean" if denied == 0 else "false alarms"
    elif not caught:
        verdict = "missed"
    elif after >= 0.8 and (first_i or 0) <= max(30, 0.15 * atk_total):
        verdict = "caught"
    else:
        verdict = "caught late"
    undefended = round(atk_total * P_SUCCESS, 1)
    out = {
        "scenario": name, "title": meta["title"], "about": meta["about"], "expected": meta["expected"], "verdict": verdict,
        "attacker_attempts": atk_total, "first_response_at_attempt": first_i, "first_response_after_sec": None if first_t is None else round(first_t, 1),
        "attacker_blocked_share": round(blocked_share, 3), "blocked_after_response": round(after, 3),
        "compromised_accounts": compromised, "compromised_if_undefended": undefended,
        "normal_attempts": normal_total, "normal_denied": denied, "normal_step_up": stepped,
        "false_deny_rate": round(denied / normal_total, 4) if normal_total else 0.0,
        "friction_rate": round((denied + stepped) / normal_total, 4) if normal_total else 0.0,
    }
    if extra:
        out.update(extra)
    return out


def run_login_scenario(name, scale=1.0, seed=7):
    rng = random.Random(f"{seed}:{name}")
    db, eng = _fresh_db()
    try:
        # build the attack first to know its duration, then lay normal traffic over the same period
        _, users = normal_traffic(random.Random(seed), max(50, int(400 * scale)), 100)
        atk, duration = build_login_scenario(name, rng, scale, users)
        duration = max(duration, 300)
        normal, _ = normal_traffic(random.Random(seed + 1), max(50, int(400 * scale)), duration)
        events = sorted(atk + normal, key=lambda e: e["t"])

        atk_total = blocked = compromised = normal_total = denied = stepped = 0
        first_i = first_t = None
        for e in events:
            now = BASE_TIME + dt.timedelta(seconds=e["t"])
            pre = campaign_engine.precheck(db, username=e["username"], ip=e["ip"], user_agent=e["ua"], header_fp=e["hfp"], password_sha1=e["pw"], now=now)
            dec, success = pre["decision"], e["success"]
            if e["kind"] == "attacker":
                atk_total += 1
                if dec == "allow":
                    success = rng.random() < P_SUCCESS
                    compromised += 1 if success else 0
                else:
                    success = False
                    blocked += 1
                    if first_i is None:
                        first_i, first_t = atk_total, e["t"]
            else:
                normal_total += 1
                if dec == "deny":
                    denied += 1
                    success = False
                elif dec == "step_up":
                    stepped += 1            # assume a real person completes the extra check; it still costs them friction
            campaign_engine.record_and_evaluate(db, username=e["username"], success=success, ip=e["ip"], user_agent=e["ua"], header_fp=e["hfp"], password_sha1=e["pw"], now=now, network_aware=False)
        campaigns = db.query(models.Campaign).filter_by(status="blocked").count()
        return _summary(name, atk_total, first_i, first_t, blocked, compromised, normal_total, denied, stepped, {"campaigns_blocked": campaigns})
    finally:
        db.close()
        eng.dispose()


def run_session_scenario(name, scale=1.0, seed=7):
    """Session theft, run through the real session pipeline (rules + ML + per-user baseline)."""
    from . import schemas
    from .routers.events_routes import process_behavior_event, _get_or_create_session
    from fastapi import HTTPException

    rng = random.Random(f"{seed}:{name}")
    db, eng = _fresh_db()
    owner_ip, owner_dev = "82.64.12.9", "Mozilla/5.0 (Windows NT 10.0) Chrome/130"
    new_device = ("session_thief_different_rhythm", "session_thief_new_device_calm", "session_owner_new_device")
    thief_ip, thief_dev = ("185.23.9.4", "Mozilla/5.0 (X11; Linux) Firefox/128") if name in new_device else (owner_ip, owner_dev)
    sid = "lab-session-" + name

    def owner_event():
        return dict(keystroke_avg_interval_ms=rng.gauss(220, 25), keystroke_std_interval_ms=rng.gauss(35, 6), typing_speed_cpm=rng.gauss(230, 25),
                    mouse_click_rate=max(0.1, rng.gauss(1.2, 0.25)), mouse_move_entropy=max(0.05, rng.gauss(0.6, 0.08)), session_duration_sec=rng.uniform(60, 900))

    def thief_event():
        if name in ("session_thief_mimic", "session_thief_new_device_calm", "session_owner_new_device"):
            return owner_event()
        return dict(keystroke_avg_interval_ms=rng.gauss(90, 8), keystroke_std_interval_ms=rng.gauss(10, 2), typing_speed_cpm=rng.gauss(430, 20),
                    mouse_click_rate=max(0.1, rng.gauss(2.6, 0.3)), mouse_move_entropy=max(0.05, rng.gauss(0.25, 0.05)), session_duration_sec=rng.gauss(20, 5))

    async def go():
        owner_flagged = atk_total = blocked = shadowed = 0
        first_i = None
        _get_or_create_session(db, sid, user_label='lab-owner', ip=owner_ip, device=owner_dev)
        for _ in range(40):                                   # the owner's normal life; builds the baseline
            ev = schemas.BehaviorEvent(session_id=sid, event_type="behavior", ip_address=owner_ip, device_info=owner_dev, **owner_event())
            res = await process_behavior_event(ev, db, quiet=True)
            owner_flagged += 1 if res["status"] != "SAFE" else 0
        for _ in range(int(15)):                              # the thief takes over the same session
            atk_total += 1
            ev = schemas.BehaviorEvent(session_id=sid, event_type="behavior", ip_address=thief_ip, device_info=thief_dev, **thief_event())
            try:
                res = await process_behavior_event(ev, db, quiet=True)
                flagged = res["status"] != "SAFE"
                shadowed += 1 if res["status"] == "SHADOW" else 0
            except HTTPException:
                flagged = True
            if flagged:
                blocked += 1
                if first_i is None:
                    first_i = atk_total
        return atk_total, first_i, blocked, owner_flagged, shadowed

    try:
        atk_total, first_i, blocked, owner_flagged, shadowed = asyncio.run(go())
        if name == "session_owner_new_device":     # these "attack" events are really the genuine owner: they count as normal traffic
            out = _summary(name, 0, None, None, 0, 0, 40 + atk_total, 0, blocked, {"kind": "session", "shadowed_events": shadowed})
            out.update(verdict="false positive" if blocked else "clean", shadowed_sessions=1 if shadowed else 0, false_positive_sessions=1 if blocked else 0)
            return out
        out = _summary(name, atk_total, first_i, None, blocked, 0, 40, owner_flagged, 0, {"kind": "session", "shadowed_events": shadowed})
        if name == "session_thief_new_device_calm":
            out["verdict"] = "contained" if shadowed else ("caught" if blocked else "missed")
        out["shadowed_sessions"] = 1 if shadowed else 0
        return out
    finally:
        db.close()
        eng.dispose()


# ----------------------------------------------------------------------------- background runner
STATE = {"running": False, "progress": 0.0, "current": None, "results": [], "started": None, "finished": None, "error": None, "scale": 1.0}
_lock = threading.Lock()


def _worker(names, scale):
    try:
        for i, n in enumerate(names):
            STATE["current"] = n
            res = run_session_scenario(n, scale) if n.startswith("session_") else run_login_scenario(n, scale)
            STATE["results"].append(res)
            STATE["progress"] = (i + 1) / len(names)
    except Exception as exc:        # surface the error to the console instead of dying silently
        STATE["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        STATE["running"], STATE["current"], STATE["finished"] = False, None, time.time()


def start(names=None, scale=0.5) -> dict:
    names = [n for n in (names or list(SCENARIOS)) if n in SCENARIOS]
    with _lock:
        if STATE["running"]:
            return {"started": False, "reason": "A lab run is already in progress"}
        STATE.update(running=True, progress=0.0, current=None, results=[], started=time.time(), finished=None, error=None, scale=scale)
    threading.Thread(target=_worker, args=(names, scale), daemon=True).start()
    return {"started": True, "scenarios": names, "scale": scale}
