"""Central router aggregation."""

from fastapi import APIRouter

from app.api.users.router import router as users_router
from app.api.problems.router import router as problems_router
from app.api.submissions.router import router as submissions_router
from app.api.judge.router import router as judge_router

api_router = APIRouter()
api_router.include_router(users_router)
api_router.include_router(problems_router)
api_router.include_router(submissions_router)
api_router.include_router(judge_router)
