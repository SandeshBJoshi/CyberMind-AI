# CyberMind Network hub

A small separate service (own folder, own database) that lets independent CyberMind installs warn each other about a
blocked login campaign, **without sharing any customer data**.

* Shares only: a keyed hash of the attacker's *client fingerprint*, reason codes, an expiry. No usernames, IPs or passwords.
* The hash is an HMAC under `NETWORK_HASH_KEY`, a secret shared by the members and **never given to the hub**, so the hub cannot reverse or guess fingerprints.
* An indicator is handed out only when **at least `HUB_MIN_MEMBERS` distinct members** reported it (default 2), so one hacked or mistaken member cannot poison the others.
* Everything expires (default 60 min, max 24 h). The operator can **mute** an indicator and **remove** a member (their reports vanish).
* A receiving CyberMind treats an indicator as a **watch-level hint only**; it never blocks anyone on its own.

## Run

```bash
cd hub
pip install -r ../backend/requirements.txt
HUB_ADMIN_KEY=choose-a-long-secret uvicorn app:app --port 8200
```

Create a member key for each install (shown once):

```bash
curl -X POST localhost:8200/v1/admin/members -H "X-Admin-Key: $HUB_ADMIN_KEY" -H "Content-Type: application/json" -d '{"label":"BEC lab"}'
```

Then in each CyberMind `.env`: `NETWORK_ENABLED=true`, `NETWORK_HUB_URL=http://hub:8200`, `NETWORK_MEMBER_ID=...`,
`NETWORK_MEMBER_KEY=...`, `NETWORK_HASH_KEY=<the same secret on every member>`.

Mute a wrong indicator: `POST /v1/admin/mute {"indicator": "<hash>"}`.

`docker compose --profile network up` starts the hub next to the demo database (see the compose file).

## Honest limits

* A shared client fingerprint (e.g. "Chrome with these headers") is not an identity; legitimate users can share it. That is why it is only a hint.
* With 2 members and a low threshold a coordinated pair could still push a hint. Use more members or a higher `HUB_MIN_MEMBERS` in practice.
* Fingerprint hashes of low-entropy values can be guessed by anyone holding `NETWORK_HASH_KEY`; treat that key as a member-only secret.
* This is a research prototype of the idea behind threat-intel sharing (compare MISP and CrowdSec), not a hardened product.
