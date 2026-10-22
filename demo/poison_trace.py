"""LIVE DEMO (Feature 1): an attacker tries the credential that was planted from a phishing email.

Self-test only, against your own local demo app. The "stolen" credential here is one YOU planted: in the console open
Email Analysis, analyse a phishing email (paste any sample), press "Plant credential" and copy the username and password
(they are shown only once). Then run:

    python demo/poison_trace.py --username marcus.moreau75 --password GZ5TwqS-j3BzvJL
    python demo/poison_trace.py ... --base http://127.0.0.1:8100     (the experiment copy)

Expected: the login is refused (HTTP 429, like a decoy touch), the attacker's whole fingerprint campaign is blocked, the console
shows "Planted credential used" and, under Detections -> Poison traces, the timeline email analysed -> planted -> used -> campaign blocked.
Needs development mode (ALLOW_CLIENT_IP_HEADER=true) so the script can present a different IP address.
"""
import argparse
import json
import urllib.error
import urllib.request

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0 Safari/537.36"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--username", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--ip", default="185.220.101.5", help="the address the attacker appears to come from")
    a = ap.parse_args()
    req = urllib.request.Request(a.base + "/bank/login", json.dumps({"username": a.username, "password": a.password}).encode(),
                                 {"Content-Type": "application/json", "X-Forwarded-For": a.ip, "User-Agent": UA})
    print(f"Attacker ({a.ip}) tries the harvested credential '{a.username}' at {a.base}/bank/login ...")
    try:
        with urllib.request.urlopen(req, timeout=20):
            print("  signed in (the credential was NOT traced: is poison tracing on, and was it planted on this server?)")
    except urllib.error.HTTPError as e:
        detail = json.loads(e.read() or b"{}").get("detail")
        print(f"  HTTP {e.code}: {detail}")
        print("  429 = refused and traced. Now look at the console: Detections -> Poison traces, and the red banner.")
    except urllib.error.URLError:
        print("  cannot reach the server")


if __name__ == "__main__":
    main()
