"""Live alerts for login-protection results, shared by every route that records a login attempt."""
from . import notify
from .websocket_manager import manager

REMINDER_EVERY = 50      # while an attack on an already-blocked campaign continues, remind the console every N attempts


async def announce_campaign(res: dict) -> None:
    """Tell the console (WebSocket) and the optional webhook when a campaign is newly blocked, a decoy is touched,
    or an already-blocked campaign is still going (so a re-run or a long attack is never silent)."""
    attempts = res.get("stats", {}).get("attempts", 0)
    ongoing = res.get("campaign_status") == "blocked" and attempts and attempts % REMINDER_EVERY == 0
    if not (res.get("newly_blocked") or res.get("decoy") or ongoing):
        return
    kind = "decoy_touched" if (res.get("decoy") and not res.get("newly_blocked")) else "campaign_blocked"
    event = {"type": kind, "campaign_id": res["campaign_id"], "score": res["score"], "reasons": res["reasons"],
             "attempts": attempts, "distinct_ips": res["stats"]["distinct_ips"], "ongoing": bool(ongoing and not res.get("newly_blocked"))}
    await manager.broadcast(event)
    if not ongoing:
        notify.send_webhook(event)
