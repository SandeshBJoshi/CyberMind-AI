"""CyberMind Network hub: a tiny, separate service that lets independent CyberMind installs warn each other.

What it stores: a KEYED HASH of a client fingerprint (the members share a secret the hub never sees, so the hub cannot reverse it),
the reason codes, who (member id) reported it, and an expiry. No usernames, no IPs, no passwords, no customer data.

Rules that keep it from becoming a weapon:
  * an indicator is only handed out once >= HUB_MIN_MEMBERS DISTINCT members reported it (one bad or hacked member cannot poison the rest)
  * every indicator expires (default 60 min, max 24 h)
  * an operator can mute an indicator at any time (false-positive escape hatch)
  * members are rate-limited
Run:  HUB_ADMIN_KEY=... uvicorn app:app --port 8200      (see hub/README.md)
"""
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

DB_PATH = os.environ.get("HUB_DB", os.path.join(os.path.dirname(__file__), "hub.db"))
ADMIN_KEY = os.environ.get("HUB_ADMIN_KEY", "")
MIN_MEMBERS = int(os.environ.get("HUB_MIN_MEMBERS", "2"))
MAX_TTL_MIN = 24 * 60
RATE_PER_HOUR = int(os.environ.get("HUB_RATE_PER_HOUR", "300"))
HEX64 = re.compile(r"^[0-9a-f]{64}$")
CODE = re.compile(r"^[a-z_]{3,40}$")

_lock = threading.Lock()
app = FastAPI(title="CyberMind Network hub")


def _db() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    c.executescript("""
        CREATE TABLE IF NOT EXISTS members (id TEXT PRIMARY KEY, key_hash TEXT NOT NULL, label TEXT, active INTEGER DEFAULT 1, created_at TEXT);
        CREATE TABLE IF NOT EXISTS reports (indicator TEXT NOT NULL, member_id TEXT NOT NULL, reasons TEXT, created_at TEXT, expires_at TEXT,
                                            PRIMARY KEY (indicator, member_id));
        CREATE TABLE IF NOT EXISTS muted (indicator TEXT PRIMARY KEY, note TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS hits (member_id TEXT, at TEXT);
    """)
    return c


def _now() -> dt.datetime:
    return dt.datetime.utcnow()


def _iso(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S")


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _member(c: sqlite3.Connection, member_id: str | None, key: str | None) -> str:
    row = c.execute("SELECT * FROM members WHERE id=? AND active=1", (member_id or "",)).fetchone()
    ok = row is not None and hmac.compare_digest(row["key_hash"], _hash_key(key or ""))
    if not ok:
        raise HTTPException(401, "unknown member or wrong key")
    return row["id"]


def _admin(key: str | None) -> None:
    if not ADMIN_KEY or not hmac.compare_digest(ADMIN_KEY, key or ""):
        raise HTTPException(403, "admin key required")


class Report(BaseModel):
    indicator: str
    reasons: list[str] = Field(default_factory=list)
    ttl_min: int = 60


@app.get("/health")
def health():
    return {"ok": True, "min_members": MIN_MEMBERS}


@app.post("/v1/report")
def report(r: Report, x_member_id: str | None = Header(None), x_member_key: str | None = Header(None)):
    if not HEX64.match(r.indicator or ""):
        raise HTTPException(422, "indicator must be a 64-char lowercase hex keyed hash")
    codes = sorted({c for c in r.reasons if CODE.match(c or "")})[:8]
    ttl = max(5, min(int(r.ttl_min), MAX_TTL_MIN))
    with _lock, _db() as c:
        mid = _member(c, x_member_id, x_member_key)
        since = _iso(_now() - dt.timedelta(hours=1))
        c.execute("DELETE FROM hits WHERE at < ?", (since,))
        if c.execute("SELECT COUNT(*) FROM hits WHERE member_id=?", (mid,)).fetchone()[0] >= RATE_PER_HOUR:
            raise HTTPException(429, "rate limit")
        c.execute("INSERT INTO hits VALUES (?,?)", (mid, _iso(_now())))
        c.execute("INSERT OR REPLACE INTO reports VALUES (?,?,?,?,?)",
                  (r.indicator, mid, json.dumps(codes), _iso(_now()), _iso(_now() + dt.timedelta(minutes=ttl))))
    return {"ok": True}


@app.get("/v1/indicators")
def indicators(x_member_id: str | None = Header(None), x_member_key: str | None = Header(None)):
    now = _iso(_now())
    with _lock, _db() as c:
        _member(c, x_member_id, x_member_key)
        c.execute("DELETE FROM reports WHERE expires_at < ?", (now,))
        rows = c.execute("SELECT indicator, member_id, reasons, expires_at FROM reports WHERE indicator NOT IN (SELECT indicator FROM muted)").fetchall()
    grouped: dict[str, dict] = {}
    for r in rows:
        g = grouped.setdefault(r["indicator"], {"members": set(), "reasons": set(), "expires_at": r["expires_at"]})
        g["members"].add(r["member_id"])
        g["reasons"].update(json.loads(r["reasons"] or "[]"))
        g["expires_at"] = max(g["expires_at"], r["expires_at"])
    out = [{"indicator": k, "members": len(g["members"]), "reasons": sorted(g["reasons"]), "expires_at": g["expires_at"]}
           for k, g in grouped.items() if len(g["members"]) >= MIN_MEMBERS]      # member ids are never shared, only the count
    return {"min_members": MIN_MEMBERS, "indicators": out}


# ---------------------------------------------------------------- operator endpoints (X-Admin-Key)


class NewMember(BaseModel):
    label: str = ""


@app.post("/v1/admin/members")
def add_member(m: NewMember, x_admin_key: str | None = Header(None)):
    _admin(x_admin_key)
    mid, key = "m_" + secrets.token_hex(4), secrets.token_urlsafe(24)
    with _lock, _db() as c:
        c.execute("INSERT INTO members VALUES (?,?,?,1,?)", (mid, _hash_key(key), m.label[:80], _iso(_now())))
    return {"member_id": mid, "member_key": key, "note": "shown once; the hub only stores a hash"}


@app.delete("/v1/admin/members/{member_id}")
def remove_member(member_id: str, x_admin_key: str | None = Header(None)):
    _admin(x_admin_key)
    with _lock, _db() as c:
        c.execute("UPDATE members SET active=0 WHERE id=?", (member_id,))
        c.execute("DELETE FROM reports WHERE member_id=?", (member_id,))       # a removed member's reports stop counting immediately
    return {"ok": True}


class Mute(BaseModel):
    indicator: str
    note: str = ""


@app.post("/v1/admin/mute")
def mute(m: Mute, x_admin_key: str | None = Header(None)):
    _admin(x_admin_key)
    if not HEX64.match(m.indicator):
        raise HTTPException(422, "bad indicator")
    with _lock, _db() as c:
        c.execute("INSERT OR REPLACE INTO muted VALUES (?,?,?)", (m.indicator, m.note[:200], _iso(_now())))
    return {"ok": True}


@app.delete("/v1/admin/mute/{indicator}")
def unmute(indicator: str, x_admin_key: str | None = Header(None)):
    _admin(x_admin_key)
    with _lock, _db() as c:
        c.execute("DELETE FROM muted WHERE indicator=?", (indicator,))
    return {"ok": True}


@app.get("/v1/admin/overview")
def overview(x_admin_key: str | None = Header(None)):
    _admin(x_admin_key)
    with _lock, _db() as c:
        return {"members": c.execute("SELECT COUNT(*) FROM members WHERE active=1").fetchone()[0],
                "reports": c.execute("SELECT COUNT(*) FROM reports").fetchone()[0],
                "muted": [dict(r) for r in c.execute("SELECT * FROM muted")]}
