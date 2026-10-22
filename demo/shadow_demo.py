"""LIVE DEMO (Feature 2): shadow mode. A stolen session that is UNCERTAIN (new device and network, owner-like rhythm) is not blocked,
which would tell the attacker they were caught. It is served from a sandbox: everything looks normal, but nothing real moves.

    python demo/shadow_demo.py                       (backend on http://127.0.0.1:8000)
    python demo/shadow_demo.py --base http://127.0.0.1:8100

What happens: a customer signs up and uses the app normally; then the same session is replayed from another country and another browser,
typing like the owner. The "attacker" is told everything is fine and "sends" $4,000, but the real balance never changes.
Then in the console: Active Sessions -> Shadow queue shows the case with the attacker's recorded intent. Press "Attacker: freeze" or
"Real customer: release" (a released customer is told which transfers did not run). Needs development mode (see the other demos).
"""
import argparse
import json
import random
import urllib.error
import urllib.request
import uuid

OWNER_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"   # not the Chrome fingerprint the other demos use
THIEF_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
PASSWORD = "Demo-Shadow-Pass-2026!"
rng = random.Random()


def call(base, path, body=None, headers=None):
    req = urllib.request.Request(base + path, json.dumps(body).encode() if body is not None else None,
                                 {"Content-Type": "application/json", **(headers or {})}, method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def calm(sid):
    return dict(session_id=sid, event_type="behavior", keystroke_avg_interval_ms=rng.gauss(220, 12), keystroke_std_interval_ms=rng.gauss(35, 3),
                typing_speed_cpm=rng.gauss(230, 12), mouse_click_rate=max(0.3, rng.gauss(1.2, 0.1)), mouse_move_entropy=max(0.2, rng.gauss(0.6, 0.03)),
                session_duration_sec=rng.uniform(60, 600))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    b = ap.parse_args().base
    name = "shadow" + uuid.uuid4().hex[:6]
    call(b, "/bank/register", {"username": name, "full_name": "Shadow Demo", "password": PASSWORD}, {"X-Forwarded-For": "82.64.12.9"})
    st, j = call(b, "/bank/login", {"username": name, "password": PASSWORD, "device_info": OWNER_UA}, {"X-Forwarded-For": "82.64.12.9", "User-Agent": OWNER_UA})
    if st != 200:
        print("login failed:", st, j)
        return
    if j.get("step_up_required"):
        print("   NOTE: this sign-in came from a fingerprint under an ACTIVE blocked campaign (an earlier demo), so the session starts in step-up and "
              "shadow mode will not apply. Release that campaign in Detections -> Campaigns & Decoys, or wait about 30 minutes, then run this again.")
    sid, tok = j["session_id"], {"X-Session-Token": j["session_token"]}
    print(f"1. Customer '{name}' signed in. Session {sid[:8]}.")
    for _ in range(35):
        call(b, "/user/behavior", {**calm(sid), "ip_address": "82.64.12.9", "device_info": OWNER_UA}, {**tok, "X-Forwarded-For": "82.64.12.9"})
    st, acc = call(b, f"/bank/account?session_id={sid}", None, {**tok, "X-Forwarded-For": "82.64.12.9"})
    print(f"2. The owner used the app normally for a while. Real balance: ${acc['profile']['balance']:,.2f}")

    print("\n3. THE SAME SESSION is now used from another country and another browser, typing like the owner...")
    st, r = call(b, "/user/behavior", {**calm(sid), "ip_address": "185.23.9.4", "device_info": THIEF_UA}, {**tok, "X-Forwarded-For": "185.23.9.4"})
    print(f"   what the attacker is told: status={r.get('status')}, action={r.get('action_taken')}   (nothing alarming: they do not know)")
    st, t = call(b, "/bank/transfer", {"session_id": sid, "recipient": "Offshore Account", "amount": 4000, "memo": "invoice"}, {**tok, "X-Forwarded-For": "185.23.9.4"})
    print(f"4. The attacker sends $4,000 -> HTTP {st} {t.get('status')}, balance shown to them: ${t.get('balance', 0):,.2f}")
    print("   In reality NO money moved: it went to a sandbox ledger and the attempt was recorded.")
    print("\nNow open the console: Active Sessions -> SHADOW QUEUE. You will see this case, why it was shadowed, and what the attacker tried.")
    print(f"Press 'Attacker: freeze' to lock it, or 'Real customer: release' to restore it. (customer: {name} / {PASSWORD})")


if __name__ == "__main__":
    main()
