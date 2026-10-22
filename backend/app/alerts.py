"""Live alerts for login-protection results, shared by every route that records a login attempt."""
from . import notify
from .websocket_manager import manager

REMINDER_EVERY = 50      # while an attack on an already-blocked campaign continues, remind the console every N attempts


async def announce_poison(res: dict) -> None:
    info = res.get("poison")
    if not info:
        return
    from .database import SessionLocal
    from . import models
    with SessionLocal() as db:
        subject = db.query(models.EmailAnalysis.subject).filter_by(id=info["analysis_id"]).scalar() or ""
    await manager.broadcast({"type": "poison_traced", "poison_id": info["id"], "analysis_id": info["analysis_id"], "subject": subject[:90],
                             "username": info["username"], "campaign_id": res.get("campaign_id"), "ip": info["ip"], "exact": info["exact"],
                             "seconds_since_planted": info["seconds_since_planted"], "first_use": info["first_use"]})


async def announce_campaign(res: dict) -> None:
    """Campaign / decoy alert first, then the poison alert, so the most specific message is the one left on screen."""
    await _announce_campaign_only(res)
    await announce_poison(res)


async def _announce_campaign_only(res: dict) -> None:
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
