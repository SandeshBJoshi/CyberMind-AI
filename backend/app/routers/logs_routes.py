import csv
import io
import json

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from .. import models, auth
from ..database import get_db

router = APIRouter(prefix="/api/logs", tags=["logs"])


def _row(r: models.SecurityEvent) -> dict:
    decision = (r.details or {}).get("_decision") or {}
    return {
        "id": r.id,
        "timestamp": r.timestamp,
        "session_id": r.session_id,
        "event_type": r.event_type,
        "ip_address": r.ip_address,
        "device_info": r.device_info,
        "rule_flags": r.rule_flags,
        "ml_anomaly": r.ml_anomaly,
        "status": r.status,
        "action_taken": r.action_taken,
        "tier": decision.get("tier"),
        "reasons": decision.get("reasons", []),
    }


def _query(db: Session, session_id=None, status_filter=None):
    q = db.query(models.SecurityEvent).order_by(models.SecurityEvent.timestamp.desc())
    if session_id:
        q = q.filter(models.SecurityEvent.session_id == session_id)
    if status_filter:
        q = q.filter(models.SecurityEvent.status == status_filter)
    return q


@router.get("")
def get_logs(
    limit: int = Query(100, le=500),
    offset: int = 0,
    session_id: str | None = None,
    status_filter: str | None = None,
    db: Session = Depends(get_db),
    current=Depends(auth.get_current_admin),
):
    q = _query(db, session_id, status_filter)
    total = q.count()
    rows = q.offset(offset).limit(limit).all()
    return {"total": total, "items": [_row(r) for r in rows]}


@router.get("/export")
def export_logs(
    format: str = Query("jsonl", pattern="^(jsonl|csv)$"),
    limit: int = Query(5000, le=50000),
    status_filter: str | None = None,
    db: Session = Depends(get_db),
    current=Depends(auth.get_current_admin),
):
    """Machine-readable export for a SIEM (Splunk, Sentinel, Wazuh...) or a spreadsheet."""
    rows = [_row(r) for r in _query(db, None, status_filter).limit(limit).all()]
    if format == "jsonl":
        body = "\n".join(json.dumps(r, default=str) for r in rows)
        return Response(body, media_type="application/x-ndjson", headers={"Content-Disposition": "attachment; filename=cybermind-events.jsonl"})
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp", "session_id", "event_type", "ip_address", "device_info", "status", "tier", "rule_flags", "ml_anomaly", "action_taken", "reasons"])
    for r in rows:
        w.writerow([r["timestamp"], r["session_id"], r["event_type"], r["ip_address"], r["device_info"], r["status"], r["tier"],
                    "|".join(r["rule_flags"] or []), r["ml_anomaly"], r["action_taken"], "; ".join(x["text"] for x in r["reasons"])])
    return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=cybermind-events.csv"})


@router.get("/lockdowns")
def get_lockdowns(db: Session = Depends(get_db), current=Depends(auth.get_current_admin)):
    rows = db.query(models.LockdownRecord).order_by(models.LockdownRecord.triggered_at.desc()).all()
    return [
        {
            "id": r.id,
            "session_id": r.session_id,
            "triggered_at": r.triggered_at,
            "reason": r.reason,
            "unlocked_at": r.unlocked_at,
            "unlocked_by": r.unlocked_by,
        }
        for r in rows
    ]
