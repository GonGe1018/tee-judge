"""Problems API router."""

from fastapi import APIRouter, HTTPException

from app.core.schemas import ProblemSummary, ProblemDetail
from app.db.database import db_conn

router = APIRouter(prefix="/api/problems", tags=["problems"])


@router.get("", response_model=list[ProblemSummary])
def list_problems():
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT id, title, time_limit_ms, memory_limit_kb FROM problems ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]


@router.get("/{problem_id}", response_model=ProblemDetail)
def get_problem(problem_id: int):
    with db_conn() as conn:
        row = conn.execute(
            "SELECT * FROM problems WHERE id = ?", (problem_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Problem not found")
        return dict(row)
