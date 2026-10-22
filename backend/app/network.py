"""CyberMind Network client (Feature 3): share and receive blocked-campaign fingerprints through a hub.

Safety rules baked in:
  * Login never waits for the hub. Receiving is a background refresh into a local cache; sharing is fire-and-forget in a thread.
  * Only a keyed hash (HMAC under NETWORK_HASH_KEY) of the client fingerprint leaves this server, plus reason codes. No usernames or IPs.
  * A received indicator is a WATCH-LEVEL hint (a few points, reason "network_indicator"); it can never block on its own.
"""
import datetime as dt
import hashlib
import hmac
import json
import threading
import time
import urllib.request

from .config import settings

_cache: dict[str, dict] = {}           # keyed hash -> {members, reasons, expires_at}
_state = {"last_sync": None, "last_error": None, "shared": 0, "received": 0, "share_errors": 0}
_lock = threading.Lock()
_thread: threading.Thread | None = None


def enabled() -> bool:
    return bool(settings.network_enabled and settings.network_hub_url and settings.network_member_id and settings.network_hash_key)


def hash_fp(signature: str) -> str:
    return hmac.new(settings.network_hash_key.encode(), signature.encode(), hashlib.sha256).hexdigest()


def _http(method: str, path: str, body: dict | None = None, timeout: float = 3.0) -> dict:
    """The one place that talks to the hub (tests replace it)."""
    req = urllib.request.Request(settings.network_hub_url.rstrip("/") + path, json.dumps(body).encode() if body is not None else None, method=method,
                                 headers={"Content-Type": "application/json", "X-Member-Id": settings.network_member_id, "X-Member-Key": settings.network_member_key})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read() or b"{}")


def refresh() -> int:
    """Pull the current indicators into the cache. Returns how many. Never raises (the hub being down must not matter)."""
    if not enabled():
        return 0
    try:
        data = _http("GET", "/v1/indicators")
        fresh = {i["indicator"]: i for i in data.get("indicators", [])}
        with _lock:
            _cache.clear()
            _cache.update(fresh)
            _state.update(last_sync=dt.datetime.utcnow().isoformat(timespec="seconds"), last_error=None, received=len(fresh))
        return len(fresh)
    except Exception as e:                       # noqa: BLE001 - any failure is just "no news"
        with _lock:
            _state["last_error"] = str(e)[:160]
        return 0


def lookup(signature: str) -> dict | None:
    """Is this client fingerprint on the network's list right now? Pure local cache read: no network call on the login path."""
    if not enabled() or not _cache:
        return None
    with _lock:
        hit = _cache.get(hash_fp(signature))
    if not hit:
        return None
    if str(hit.get("expires_at") or "9999") < dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"):
        return None
    return hit


def _do_share(signature: str, reason_codes: list[str]) -> None:
    try:
        _http("POST", "/v1/report", {"indicator": hash_fp(signature), "reasons": reason_codes, "ttl_min": settings.campaign_block_ttl_min})
        with _lock:
            _state["shared"] += 1
    except Exception as e:                       # noqa: BLE001
        with _lock:
            _state.update(share_errors=_state["share_errors"] + 1, last_error=str(e)[:160])


def share_async(signature: str, reason_codes: list[str]) -> None:
    """Tell the hub we blocked this fingerprint, without delaying the caller."""
    if enabled():
        threading.Thread(target=_do_share, args=(signature, reason_codes), daemon=True).start()


def start_background(interval_s: int = 60) -> None:
    global _thread
    if not enabled() or (_thread and _thread.is_alive()):
        return

    def loop():
        while True:
            refresh()
            time.sleep(interval_s)

    _thread = threading.Thread(target=loop, daemon=True)
    _thread.start()


def status() -> dict:
    with _lock:
        items = [{"indicator": k[:10] + "…", "members": v.get("members"), "reasons": v.get("reasons", []), "expires_at": v.get("expires_at")} for k, v in _cache.items()]
        return {"enabled": enabled(), "flag": bool(settings.network_enabled), "hub_url": settings.network_hub_url, "member_id": settings.network_member_id,
                **_state, "indicators": items}
