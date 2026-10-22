"""Feature 4: adaptive attack-lab stress test (LAB ONLY).

The fixed lab scenarios answer "do we catch these attacks?". This asks the harder question: "how much do you have to change an attack
before it slips past?". A small genetic search tunes a credential-stuffing attacker (how many tries, how many IPs, how slowly, which
browser fingerprint, how many known-breached passwords) against the REAL detection code in a throw-away database, rewarding the attacker
for harvesting accounts and punishing slowness. The output is a robustness report: how many variations were tried before one slipped
through, what the best evader looked like, which rule it learned to stay under, and how much more effort a successful attack needed.

Honest limits: the attacker is a parameter search over six knobs, not a human adversary; it only attacks the login guard (not sessions,
phishing or the network feature); results depend on the lab's synthetic normal traffic. A clean report is evidence, not proof.
It never touches the live database, never sends network traffic and never contacts the CyberMind Network.
"""
import datetime as dt
import random
import threading
import time
from collections import Counter

from . import breach, campaign_engine, lab
from .config import settings

BUDGET = 400                # an attacker may spend at most this many attempts per run
BOUNDS = {"attempts": (60, BUDGET), "ips": (1, 400), "duration_s": (30, 10800), "ua_mode": (0, 2), "breached_pct": (0, 30)}
UA_MODES = ["python client", "scripted Chrome (odd headers)", "copies a real Chrome fingerprint"]
STATE = {"running": False, "progress": 0.0, "report": None, "error": None, "started": None, "finished": None}
_lock = threading.Lock()


def _clip(g: dict) -> dict:
    out = {k: int(min(max(g[k], lo), hi)) for k, (lo, hi) in BOUNDS.items()}
    out["ips"] = min(out["ips"], out["attempts"])
    return out


def random_genome(rng: random.Random) -> dict:
    return _clip({"attempts": rng.randint(*BOUNDS["attempts"]), "ips": int(10 ** rng.uniform(0, 2.6)), "duration_s": int(10 ** rng.uniform(1.5, 4.03)),
                  "ua_mode": rng.randint(0, 2), "breached_pct": rng.randint(0, 30)})


def describe(g: dict) -> str:
    h = g["duration_s"] / 3600
    span = f"{g['duration_s'] // 60} min" if g["duration_s"] < 7200 else f"{h:.1f} h"
    return f"{g['attempts']} tries from {g['ips']} IP{'s' if g['ips'] != 1 else ''} over {span}, {UA_MODES[g['ua_mode']]}, {g['breached_pct']}% breached passwords"


def evaluate(g: dict, seed: int = 7) -> dict:
    """Replay this attacker (plus normal customers) through the real login guard in a throw-away database."""
    g = _clip(g)
    rng = random.Random(f"{seed}:{sorted(g.items())}")
    db, eng = lab._fresh_db()
    try:
        users = [f"user{i:04d}" for i in range(80)]
        normal, _ = lab.normal_traffic(random.Random(seed + 1), 80, max(300, g["duration_s"]))
        ua, hfp = [(lab.UA_PY, "hdr-py"), (lab.UA_CHROME_WIN, "hdr-script-x"), (lab.UA_CHROME_WIN, "hdr-chrome-win")][g["ua_mode"]]
        pool = [lab._public_ip(rng) for _ in range(g["ips"])]
        atk = []
        for _ in range(g["attempts"]):
            pw = breach.sha1_hex("qwerty") if rng.random() < g["breached_pct"] / 100 else breach.sha1_hex("pw-%d" % rng.randint(0, 10**6))
            atk.append(lab._atk(rng.uniform(0, g["duration_s"]), rng.choice(users) if rng.random() < 0.7 else f"someone{rng.randint(0, 99999)}",
                                rng.choice(pool), ua, hfp, pw))
        allowed = blocked = normal_total = normal_denied = 0
        peak, rules = 0.0, Counter()
        for e in sorted(atk + normal, key=lambda x: x["t"]):
            now = lab.BASE_TIME + dt.timedelta(seconds=e["t"])
            pre = campaign_engine.precheck(db, username=e["username"], ip=e["ip"], user_agent=e["ua"], header_fp=e["hfp"], password_sha1=e["pw"], now=now)
            success = e["success"]
            if e["kind"] == "attacker":
                if pre["decision"] == "allow":
                    allowed += 1
                else:
                    blocked += 1
                success = False
            else:
                normal_total += 1
                if pre["decision"] == "deny":
                    normal_denied += 1
                    success = False
            res = campaign_engine.record_and_evaluate(db, username=e["username"], success=success, ip=e["ip"], user_agent=e["ua"], header_fp=e["hfp"],
                                                      password_sha1=e["pw"], now=now, network_aware=False)
            if e["kind"] == "attacker":
                peak = max(peak, res["score"])
                for r in res["reasons"]:
                    rules[r["code"]] = max(rules[r["code"]], r["points"])
        share = allowed / max(1, g["attempts"])
        harvest = allowed * lab.P_SUCCESS                                   # expected accounts taken (no randomness: keeps the search stable)
        return {"genome": g, "allowed": allowed, "blocked": blocked, "allowed_share": round(share, 3), "expected_harvest": round(harvest, 2),
                "fitness": round(harvest / (1 + g["duration_s"] / 3600), 3), "peak_score": round(peak, 2), "rules": dict(rules),
                "normal_denied": normal_denied, "normal_total": normal_total, "slipped": share >= 0.5}
    finally:
        db.close()
        eng.dispose()


def _mutate(g: dict, rng: random.Random) -> dict:
    c = dict(g)
    for k in rng.sample(list(BOUNDS), rng.choice((1, 2))):
        lo, hi = BOUNDS[k]
        if k in ("ua_mode",):
            c[k] = rng.randint(lo, hi)
        elif k in ("ips", "duration_s"):
            c[k] = int(max(lo, c[k] * 10 ** rng.uniform(-0.4, 0.4)))
        else:
            c[k] = int(c[k] + rng.gauss(0, (hi - lo) * 0.15))
    return _clip(c)


def _cross(a: dict, b: dict, rng: random.Random) -> dict:
    return _clip({k: (a if rng.random() < 0.5 else b)[k] for k in BOUNDS})


def search(population: int = 10, generations: int = 4, seed: int = 7, progress=None) -> dict:
    rng = random.Random(seed)
    pop = [random_genome(rng) for _ in range(population)]
    history: list[dict] = []                    # every variation tried, in order
    cache: dict = {}

    def score(g):
        key = tuple(sorted(g.items()))
        if key not in cache:
            cache[key] = evaluate(g, seed)
            history.append(cache[key])
        return cache[key]

    total_steps = population * generations
    for gen in range(generations):
        scored = sorted((score(g) for g in pop), key=lambda r: r["fitness"], reverse=True)
        if progress:
            progress((gen + 1) / generations)
        elite = [r["genome"] for r in scored[:2]]
        parents = [r["genome"] for r in scored[: max(3, population // 2)]]
        pop = elite + [_mutate(_cross(rng.choice(parents), rng.choice(parents), rng), rng) for _ in range(population - 2)]
    best = max(history, key=lambda r: r["fitness"])
    return _report(history, best, seed)


def _report(history: list[dict], best: dict, seed: int) -> dict:
    slips = [i for i, r in enumerate(history, 1) if r["slipped"]]
    caught = [r for r in history if not r["slipped"]]
    slipped = [r for r in history if r["slipped"]]
    fired_in_caught = Counter(code for r in caught for code, pts in r["rules"].items() if pts > 0)
    fired_in_slipped = Counter(code for r in slipped for code, pts in r["rules"].items() if pts > 0)
    best_slip = max(slipped, key=lambda r: r["expected_harvest"], default=None)
    # the rule that stops most attacks but that the best evader learned to stay under
    weakest = None
    if best_slip:
        for code, n in fired_in_caught.most_common():
            if best_slip["rules"].get(code, 0) <= 0 and n / max(1, len(caught)) >= 0.5:
                weakest = {"rule": code, "fires_in_caught_attacks": round(n / max(1, len(caught)), 2), "fires_in_best_evader": 0,
                           "meaning": "most blocked attacks tripped this rule; the best evader's settings never did"}
                break
    undefended = lambda r: r["genome"]["attempts"] * lab.P_SUCCESS
    attempts_per_account = None
    if best_slip and best_slip["expected_harvest"] > 0:
        attempts_per_account = round(best_slip["genome"]["attempts"] / best_slip["expected_harvest"], 1)
    baseline = round(1 / lab.P_SUCCESS, 1)
    false_alarms = sum(r["normal_denied"] for r in history)
    return {
        "seed": seed, "variations_tried": len(history), "slipped_count": len(slipped), "slip_rate": round(len(slipped) / max(1, len(history)), 3),
        "first_slip_at_variation": slips[0] if slips else None,
        "verdict": ("held: no tested variation got more than half its attempts through" if not slipped
                    else f"evaded: {len(slipped)} of {len(history)} variations slipped through (first at variation {slips[0]})"),
        "best_evader": None if not best_slip else {
            **best_slip, "description": describe(best_slip["genome"]), "defended_harvest": best_slip["expected_harvest"],
            "undefended_harvest": round(undefended(best_slip), 1), "attempts_per_account": attempts_per_account,
            "attempts_per_account_undefended": baseline, "cost_multiplier": round(attempts_per_account / baseline, 2) if attempts_per_account else None,
            "eventually_blocked": best_slip["peak_score"] >= settings.campaign_block_threshold,
        },
        "highest_fitness": {**best, "description": describe(best["genome"])},
        "weakest_rule": weakest,
        "rules_that_caught": [{"rule": c, "in_share_of_caught": round(n / max(1, len(caught)), 2)} for c, n in fired_in_caught.most_common(5)],
        "false_alarms_on_normal_users": false_alarms,
        "top": [{**r, "description": describe(r["genome"])} for r in sorted(history, key=lambda r: r["fitness"], reverse=True)[:5]],
        "thresholds": {"watch": settings.campaign_watch_threshold, "block": settings.campaign_block_threshold},
        "limits": ["A parameter search over six attacker settings, not a human adversary.",
                   "Only the login guard is attacked (not sessions, phishing or the network feature).",
                   "Normal traffic is synthetic. A clean result is evidence, not proof."],
    }


def _worker(population, generations, seed):
    try:
        STATE["report"] = search(population, generations, seed, progress=lambda p: STATE.update(progress=p))
    except Exception as exc:                    # shown in the console instead of dying silently
        STATE["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        STATE.update(running=False, finished=time.time(), progress=1.0 if not STATE["error"] else STATE["progress"])


def start(population: int = 8, generations: int = 4, seed: int = 7) -> dict:
    with _lock:
        if STATE["running"]:
            return {"started": False, "reason": "A stress test is already running"}
        STATE.update(running=True, progress=0.0, report=None, error=None, started=time.time(), finished=None)
    threading.Thread(target=_worker, args=(min(max(population, 4), 16), min(max(generations, 2), 8), seed), daemon=True).start()
    return {"started": True}
