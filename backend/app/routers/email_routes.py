"""Email (phishing) analysis API. Admin-only. Only the analysis result is stored, never the raw email or attachments."""
import asyncio
import datetime as dt
import os

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import auth, models, phish_ai, phish_engine, phish_report, security
from ..database import get_db
from ..email_parser import MAX_BYTES
from ..websocket_manager import manager

router = APIRouter(prefix="/api/email", tags=["email analysis"], dependencies=[Depends(auth.get_current_admin)])

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "email_samples")


class TextBody(BaseModel):
    text: str = Field(min_length=10, max_length=MAX_BYTES)
    ai: bool = False
    model: str | None = None


class SampleBody(BaseModel):
    name: str
    ai: bool = False
    model: str | None = None


def _rate_limit(request: Request):
    ip = security.resolve_client_ip(request) or "unknown"
    if not security.ingest_by_source.hit("email:" + ip):
        raise HTTPException(status_code=429, detail="Too many analyses. Try again in a minute.")


def _summary(row: models.EmailAnalysis) -> dict:
    return {"id": row.id, "created_at": row.created_at, "source": row.source, "subject": row.subject, "sender": row.sender,
            "verdict": row.verdict, "score": row.score}


def _record(row: models.EmailAnalysis) -> dict:
    return {"id": row.id, "created_at": row.created_at, "source": row.source, "verdict": row.verdict, "score": row.score, "result": row.result}


async def _store(db: Session, raw: bytes, source: str, ai: bool = False, model: str | None = None) -> dict:
    try:
        result, parsed = phish_engine.analyze_full(raw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if ai:      # optional second opinion from the Groq model; the rule verdict stays the official one
        result["ai"] = await asyncio.to_thread(phish_ai.run, parsed, result, model)
    e = result["email"]
    row = models.EmailAnalysis(source=source, subject=e["subject"][:300], sender=(e["from_addr"] or e["from_name"])[:200], verdict=result["verdict"],
                               score=result["score"], raw_sha256=e["raw_sha256"], result=result)
    db.add(row)
    db.commit()
    db.refresh(row)
    if row.verdict in ("PHISHING", "SUSPICIOUS"):
        await manager.broadcast({"type": "email_phishing", "id": row.id, "verdict": row.verdict, "score": row.score, "subject": row.subject, "sender": row.sender})
    return _record(row)


@router.post("/analyze")
async def analyze_upload(request: Request, file: UploadFile = File(...), ai: bool = Form(False), model: str | None = Form(None), db: Session = Depends(get_db)):
    _rate_limit(request)
    name = (file.filename or "").lower()
    if not name.endswith((".eml", ".txt", ".msg", ".mbox")) and file.content_type not in ("message/rfc822", "text/plain", "application/octet-stream", None):
        raise HTTPException(status_code=400, detail="Upload a raw email file (.eml) or a text file with the full message source.")
    raw = await file.read(MAX_BYTES + 1)
    return await _store(db, raw, "upload", ai, model)


@router.post("/analyze-text")
async def analyze_text(request: Request, body: TextBody, db: Session = Depends(get_db)):
    _rate_limit(request)
    return await _store(db, body.text.encode("utf-8", "replace"), "paste", body.ai, body.model)


def _samples() -> list[dict]:
    names = sorted(f[:-4] for f in os.listdir(SAMPLES_DIR) if f.endswith(".eml")) if os.path.isdir(SAMPLES_DIR) else []
    return [{"name": n, "kind": "legitimate" if n.startswith("legit_") else "phishing", "title": n.split("_", 1)[1].replace("_", " ")} for n in names]


@router.get("/samples")
def list_samples():
    return _samples()


@router.post("/analyze-sample")
async def analyze_sample(request: Request, body: SampleBody, db: Session = Depends(get_db)):
    _rate_limit(request)
    if body.name not in {s["name"] for s in _samples()}:          # only bundled files; never a path from the client
        raise HTTPException(status_code=404, detail="Unknown sample")
    with open(os.path.join(SAMPLES_DIR, body.name + ".eml"), "rb") as fh:
        return await _store(db, fh.read(), "sample", body.ai, body.model)


@router.get("/ai-status")
def ai_status():
    return {"available": phish_ai.available(), "model": phish_ai.default_model(), "models": phish_ai.MODELS, "provider": "Groq"}


@router.get("/history")
def history(limit: int = 50, db: Session = Depends(get_db)):
    rows = db.query(models.EmailAnalysis).order_by(models.EmailAnalysis.id.desc()).limit(max(1, min(limit, 200))).all()
    return [_summary(r) for r in rows]


@router.get("/stats")
def stats(db: Session = Depends(get_db)):
    q = db.query(models.EmailAnalysis)
    day = dt.datetime.utcnow() - dt.timedelta(hours=24)
    return {"total": q.count(), "phishing": q.filter_by(verdict="PHISHING").count(), "suspicious": q.filter_by(verdict="SUSPICIOUS").count(),
            "safe": q.filter_by(verdict="SAFE").count(), "last_24h": q.filter(models.EmailAnalysis.created_at >= day).count()}


def _get(db: Session, analysis_id: int) -> models.EmailAnalysis:
    row = db.query(models.EmailAnalysis).filter_by(id=analysis_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return row


@router.get("/{analysis_id}")
def get_analysis(analysis_id: int, db: Session = Depends(get_db)):
    return _record(_get(db, analysis_id))


@router.get("/{analysis_id}/report")
def report(analysis_id: int, format: str = "pdf", db: Session = Depends(get_db)):
    rec = _record(_get(db, analysis_id))
    if format == "md":
        return Response(phish_report.build_markdown(rec), media_type="text/markdown",
                        headers={"Content-Disposition": f'attachment; filename="phishing-report-{analysis_id}.md"'})
    if format != "pdf":
        raise HTTPException(status_code=400, detail="format must be pdf or md")
    try:
        data = phish_report.build_pdf(rec)
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="PDF export needs the 'reportlab' package. Run pip install reportlab, or download the Markdown report.") from exc
    return Response(data, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="phishing-report-{analysis_id}.pdf"'})


@router.delete("/{analysis_id}")
def delete_analysis(analysis_id: int, db: Session = Depends(get_db)):
    db.delete(_get(db, analysis_id))
    db.commit()
    return {"deleted": analysis_id}
