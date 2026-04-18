"""Problems API router."""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, HTTPException

from app.api.problems.dto import ProblemSummary, ProblemDetail
from app.db.database import db_conn
from app.db import problems_crud

router = APIRouter(prefix="/api/problems", tags=["problems"])


@router.get("", response_model=List[ProblemSummary])
def list_problems_route():
    with db_conn() as conn:
        rows = problems_crud.list_problems(conn)
        return [dict(r) for r in rows]


@router.get("/{problem_id}", response_model=ProblemDetail)
def get_problem(problem_id: int):
    with db_conn() as conn:
        row = problems_crud.get_problem_by_id(conn, problem_id)
        if not row:
            raise HTTPException(404, "Problem not found")
        return dict(row)
