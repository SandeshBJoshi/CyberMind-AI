"""Authenticated API boundary for the embedded CyberMind Intel workflow."""
import asyncio
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, ConfigDict, Field

from ..auth import get_current_admin
from ..config import settings

router = APIRouter(prefix="/api/cybermind", tags=["CyberMind Intel"])
_store = None


class QueryRequest(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    query: str = Field(min_length=3, max_length=6000)
    model_choice: str | None = None


def _service():
    global _store
    try:
        from ..cybermind.vector_store import ChromaDBService
        if _store is None:
            _store = ChromaDBService(settings.cybermind_chroma_dir)
        return _store
    except ImportError as exc:
        raise HTTPException(503, "CyberMind Intel dependencies are not installed. Run pip install -r requirements.txt.") from exc


@router.get("/status")
def status(_: object = Depends(get_current_admin)):
    store = _service()
    return {"status": "ready", "documents": store.get_ingested_files(), "count": store.get_document_count(),
            "default_model": settings.cybermind_model}


@router.post("/ingest")
async def ingest(file: UploadFile = File(...), _: object = Depends(get_current_admin)):
    if not file.filename or Path(file.filename).suffix.lower() != ".pdf":
        raise HTTPException(400, "Only PDF cybersecurity reports are supported.")
    content = await file.read()
    if not content:
        raise HTTPException(400, "The uploaded PDF is empty.")
    if len(content) > settings.cybermind_max_upload_mb * 1024 * 1024:
        raise HTTPException(413, f"PDF exceeds the {settings.cybermind_max_upload_mb} MB upload limit.")
    safe_name = Path(file.filename).name
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as temp:
            temp.write(content); temp_path = temp.name
        from ..cybermind.pdf_loader import load_pdf, chunk_documents
        pages = await asyncio.to_thread(load_pdf, temp_path)
        for page in pages:
            page.metadata["source"] = safe_name
            page.metadata["title"] = safe_name
        chunks = await asyncio.to_thread(chunk_documents, pages)
        for chunk in chunks:
            chunk.metadata["source"] = safe_name
        ids = await asyncio.to_thread(_service().add_documents, chunks)
        return {"success": True, "message": f"Indexed {safe_name}", "chunks": len(ids)}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"PDF ingestion failed: {exc}") from exc
    finally:
        if temp_path:
            Path(temp_path).unlink(missing_ok=True)


@router.post("/query")
async def query(request: QueryRequest, _: object = Depends(get_current_admin)):
    try:
        from ..cybermind.workflow import run_workflow
        result = await asyncio.to_thread(run_workflow, request.query, _service(), request.model_choice or settings.cybermind_model)
        return {
            "plan": result.get("plan", ""), "response": result.get("response", ""),
            "sources": result.get("sources", []), "steps": result.get("steps", []),
            "web_results": result.get("web_results", []), "validation_result": result.get("validation_result", {}),
            "report": result.get("report"), "cves": result.get("cves", []), "trace": result.get("trace", []), "model": result.get("model", ""),
        }
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"CyberMind Intel workflow failed: {exc}") from exc


@router.post("/clear")
def clear(_: object = Depends(get_current_admin)):
    _service().clear_database()
    return {"success": True, "message": "CyberMind Intel vector store cleared."}
