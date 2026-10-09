from fastapi import APIRouter, Depends
from pydantic import BaseModel

from .. import auth, lab

router = APIRouter(prefix="/api/lab", tags=["attack lab"], dependencies=[Depends(auth.get_current_admin)])


class RunRequest(BaseModel):
    scenarios: list[str] | None = None
    scale: float = 0.5          # 0.5 = quick (about 15 s); 1.0 = full size


@router.get("/scenarios")
def scenarios():
    return [{"id": k, **{x: v[x] for x in ("title", "expected", "about")}} for k, v in lab.SCENARIOS.items()]


@router.post("/run")
def run(body: RunRequest):
    scale = min(max(body.scale, 0.1), 2.0)
    return lab.start(body.scenarios, scale)


@router.get("/results")
def results():
    return {k: lab.STATE[k] for k in ("running", "progress", "current", "results", "error", "scale")}
