"""Open-Source Security Alert Management Platform — FastAPI application."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from . import config
from .database import init_db
from .routers import alerts
from .schemas import HealthOut

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title=config.APP_NAME,
    version=config.VERSION,
    description=(
        "SOC alert triage and management: ingest alerts from any SIEM/EDR, triage through a status lifecycle, "
        "classify as FP/BTP/TP, tag MITRE ATT&CK, enrich IOCs with VirusTotal/AbuseIPDB, and keep an analyst "
        "timeline. OpenAPI docs live at /docs."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # dev default; restrict behind a reverse proxy in production
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/healthz", response_model=HealthOut, tags=["meta"])
def healthz() -> HealthOut:
    return HealthOut(status="ok", app=config.APP_NAME, version=config.VERSION)


app.include_router(alerts.router)
app.mount("/", StaticFiles(directory="app/static", html=True), name="static")