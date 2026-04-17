"""TEE-Judge FastAPI Application."""

import logging
import os

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

_env = os.environ.get("TEE_JUDGE_ENV", "dev")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    docs_url="/docs" if _env == "dev" else None,
    redoc_url="/redoc" if _env == "dev" else None,
)

# WebSocket routes (must be before CORS middleware and static mount)
app.include_router(ws_router)

# CORS (does not apply to WebSocket)
CORS_ORIGINS = os.environ.get("TEE_JUDGE_CORS_ORIGINS", "*").split(",")
if "*" in CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


@app.on_event("startup")
def startup():
    init_db()
    logger.info(f"{settings.PROJECT_NAME} v{settings.VERSION} started")
    env = os.environ.get("TEE_JUDGE_ENV", "dev")
    logger.info(f"Environment: {env}")


# API routes
app.include_router(api_router)


# Frontend static files
@app.get("/", include_in_schema=False)
def serve_index():
    return FileResponse(settings.FRONTEND_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(settings.FRONTEND_DIR)), name="static")
