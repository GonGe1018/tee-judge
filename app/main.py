"""TEE-Judge FastAPI Application."""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.core.config import settings
from app.db.database import init_db
from app.api.routers import api_router
from app.api.ws.router import router as ws_router

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("tee-judge")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    docs_url="/docs" if settings.is_dev else None,
    redoc_url="/redoc" if settings.is_dev else None,
)

# WebSocket routes (before CORS middleware)
app.include_router(ws_router)

# CORS
cors_origins = settings.cors_origins
if cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
elif settings.is_dev:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
# Production without CORS_ORIGINS: no CORS middleware (same-origin only)


@app.on_event("startup")
def startup():
    init_db()
    logger.info(f"{settings.PROJECT_NAME} v{settings.VERSION} started")
    logger.info(f"Environment: {settings.TEE_JUDGE_ENV}")


# API routes
app.include_router(api_router)


# Frontend static files
@app.get("/", include_in_schema=False)
def serve_index():
    return FileResponse(settings.FRONTEND_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(settings.FRONTEND_DIR)), name="static")
