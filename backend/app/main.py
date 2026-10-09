from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from .config import settings, SECURITY_WARNINGS
from .database import Base, engine, SessionLocal
from .routers import (auth_routes, events_routes, logs_routes, lockdown_routes, ws_routes, simulate_routes,
                      user_routes, cybermind_routes, campaign_routes, lab_routes, bank_routes)
from . import ml_engine, models
from .seed_admin import main as seed_admin_main


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    seed_admin_main()
    db = SessionLocal()
    try:                       # make sure the configured decoy accounts exist
        for name in settings.decoys:
            if not db.query(models.DecoyAccount).filter_by(username=name).first():
                db.add(models.DecoyAccount(username=name, note="seeded from DECOY_USERNAMES"))
        db.commit()
    finally:
        db.close()
    ml_engine.get_ml_engine()   # load the saved model (builds a bootstrap one only the first time); NO retrain on every start
    yield


app = FastAPI(
    title="CYBERMIND AI — Real-Time ML Behavioral Threat Detection & Automated Lockdown System",
    lifespan=lifespan,
)

# Only the console's own origin(s) may call this API from a browser (was: any origin, with credentials)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Session-Token", "X-App-Key", "X-Forwarded-For", "X-Real-IP"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


for r in (auth_routes, events_routes, logs_routes, lockdown_routes, ws_routes, simulate_routes, user_routes,
          cybermind_routes, campaign_routes, lab_routes, bank_routes):
    app.include_router(r.router)


@app.get("/")
def root():
    return {"service": "CYBERMIND AI", "status": "online"}


@app.get("/health")
def health():
    return {"status": "ok", "mode": "production" if settings.is_production else "development", "warnings": len(SECURITY_WARNINGS)}
