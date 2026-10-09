"""LIVE DEMO 2: a stolen session. The attacker has the victim's valid session token but not their rhythm.

1. A fresh customer signs up and logs in; CYBERMIND learns how they type (calm, steady, same device and network).
2. A "thief" reuses the stolen session from a new network and device, typing like a machine.
3. The thief then tries to move money. CYBERMIND's verdict is enforced by the bank (HTTP 428 step-up or 423 frozen).

    python demo/session_hijack.py                    (backend on http://127.0.0.1:8000)

Watch the console while it runs: Overview (live events), Detections (the reasons), Active Sessions (status).
Needs development mode so the script can present a different IP address (ALLOW_CLIENT_IP_HEADER=true).
"""
import argparse
import json
import random
import time
import urllib.error
import urllib.request
import uuid

OWNER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0 Safari/537.36"
THIEF_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
PASSWORD = "Demo-Victim-Pass-2026!"
rng = random.Random()


def call(base, path, body=None, headers=None):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", **(headers or {})}, method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def owner_event(sid):
    return dict(session_id=sid, event_type="behavior", keystroke_avg_interval_ms=rng.gauss(220, 18), keystroke_std_interval_ms=rng.gauss(35, 5),
                typing_speed_cpm=rng.gauss(230, 20), mouse_click_rate=max(0.3, rng.gauss(1.2, 0.2)), mouse_move_entropy=max(0.2, rng.gauss(0.6, 0.05)),
                session_duration_sec=rng.uniform(60, 600))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    a = ap.parse_args()
    b = a.base

    name = "victim" + uuid.uuid4().hex[:6]
    st, _ = call(b, "/bank/register", {"username": name, "full_name": "Demo Victim", "password": PASSWORD}, {"X-Forwarded-For": "82.64.12.9"})
    print(f"1. Created customer '{name}' (HTTP {st})")
    st, j = call(b, "/bank/login", {"username": name, "password": PASSWORD, "device_info": OWNER_UA}, {"X-Forwarded-For": "82.64.12.9", "User-Agent": OWNER_UA})
    if st != 200:
        print("   login failed:", st, j); return
    sid, tok = j["session_id"], {"X-Session-Token": j["session_token"]}
    print(f"2. Victim signed in. Session {sid[:8]} (find it under Active Sessions as '{name}')")

    print("3. The real owner uses the app normally (35 events: calm typing, same laptop, same network)...")
    for _ in range(35):
        call(b, "/user/behavior", {**owner_event(sid), "ip_address": "82.64.12.9", "device_info": OWNER_UA}, {**tok, "X-Forwarded-For": "82.64.12.9"})
        time.sleep(0.05)
    st, r = call(b, "/bank/transfer", {"session_id": sid, "recipient": "Landlord", "amount": 120}, {**tok, "X-Forwarded-For": "82.64.12.9"})
    print(f"   owner sends $120 -> HTTP {st} ({'allowed' if st == 200 else r.get('detail')})")

    print("\n4. THE THIEF steals the session token and replays it from another country, another browser, typing like a machine...")
    verdicts = []
    for _ in range(4):
        st, r = call(b, "/user/behavior", {**owner_event(sid), "ip_address": "185.23.9.4", "device_info": THIEF_UA, "typing_speed_cpm": 760,
                     "keystroke_avg_interval_ms": 70, "keystroke_std_interval_ms": 6, "mouse_click_rate": 3.5, "mouse_move_entropy": 0.12},
                     {**tok, "X-Forwarded-For": "185.23.9.4"})
        verdicts.append(r.get("status") or f"HTTP {st}")
        time.sleep(0.2)
    print("   CYBERMIND verdicts for the thief's events:", " -> ".join(verdicts))

    st, r = call(b, "/bank/transfer", {"session_id": sid, "recipient": "Offshore Account", "amount": 9000}, {**tok, "X-Forwarded-For": "185.23.9.4"})
    meaning = {428: "STEP-UP required (needs the owner's password)", 423: "FROZEN (only an admin can unlock)", 200: "went through (!)"}.get(st, "")
    print(f"\n5. The thief tries to send $9,000 -> HTTP {st}  {meaning}\n   bank says: {r.get('detail', r)}")
    print("\nNow look at the console: Detections shows the reasons, Active Sessions shows the status and the Unlock / Clear step-up button.")


if __name__ == "__main__":
    main()
