"""Submissions API router."""

from __future__ import annotations

import hashlib

from fastapi import APIRouter, HTTPException, Depends

from app.api.submissions.dto import (
    SubmitRequest,
    SubmitResponse,
    StatusResponse,
    ResultResponse,
)
from app.core.auth import get_current_user
from app.core.security import rate_limit
from app.core.ws import judge_manager
from app.db.database import db_conn
from app.db import submissions_crud, problems_crud, results_crud

router = APIRouter(prefix="/api", tags=["submissions"])


@router.post(
    "/submit", response_model=SubmitResponse, dependencies=[Depends(rate_limit)]
)
async def submit_code(req: SubmitRequest, user: dict = Depends(get_current_user)):
    with db_conn() as conn:
        if not problems_crud.get_problem_by_id(conn, req.problem_id):
            raise HTTPException(404, "Problem not found")

        code_hash = hashlib.sha256(req.code.encode()).hexdigest()
        submission_id = submissions_crud.create_submission(
            conn, user["user_id"], req.problem_id, req.language, req.code, code_hash
        )

    await judge_manager.notify(
        user["user_id"],
        {
            "type": "new_task",
            "submission_id": submission_id,
            "problem_id": req.problem_id,
        },
    )

    return SubmitResponse(
        submission_id=submission_id,
        status="PENDING",
        message="제출 완료. Judge Client가 채점을 시작합니다.",
    )


@router.get("/status/{submission_id}", response_model=StatusResponse)
def get_status(submission_id: int, user: dict = Depends(get_current_user)):
    with db_conn() as conn:
        sub = submissions_crud.get_submission_by_id(conn, submission_id)
        if not sub:
            raise HTTPException(404, "Submission not found")
        if sub["user_id"] != user["user_id"]:
            raise HTTPException(403, "Cannot view another user's submission")

        result = results_crud.get_result_by_submission_id(conn, submission_id)

    return StatusResponse(
        submission_id=sub["id"],
        status=sub["status"],
        attestation_verified=bool(result["attestation_verified"]) if result else False,
    )


@router.get("/result/{submission_id}", response_model=ResultResponse)
def get_result(submission_id: int, user: dict = Depends(get_current_user)):
    with db_conn() as conn:
        sub = submissions_crud.get_submission_by_id(conn, submission_id)
        if not sub:
            raise HTTPException(404, "Submission not found")
        if sub["user_id"] != user["user_id"]:
            raise HTTPException(403, "Cannot view another user's result")

        row = results_crud.get_result_with_submission(conn, submission_id)

    if not row:
        raise HTTPException(404, "Result not found. Judging may still be in progress.")

    return dict(row)
