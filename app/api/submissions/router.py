"""Submissions API router."""

import hashlib

from fastapi import APIRouter, HTTPException, Depends

from app.core.schemas import (
    SubmitRequest,
    SubmitResponse,
    StatusResponse,
    ResultResponse,
)
from app.core.auth import get_current_user
from app.core.security import rate_limit
from app.core.ws import judge_manager
from app.db.database import db_conn

router = APIRouter(prefix="/api", tags=["submissions"])


@router.post(
    "/submit", response_model=SubmitResponse, dependencies=[Depends(rate_limit)]
)
async def submit_code(req: SubmitRequest, user: dict = Depends(get_current_user)):
    with db_conn() as conn:
        problem = conn.execute(
            "SELECT id FROM problems WHERE id = ?", (req.problem_id,)
        ).fetchone()
        if not problem:
            raise HTTPException(404, "Problem not found")

        code_hash = hashlib.sha256(req.code.encode()).hexdigest()

        cursor = conn.execute(
            "INSERT INTO submissions (user_id, problem_id, language, code, code_hash, status) VALUES (?, ?, ?, ?, ?, 'PENDING')",
            (user["user_id"], req.problem_id, req.language, req.code, code_hash),
        )
        submission_id = cursor.lastrowid
        conn.commit()

    # Notify Judge Client via WebSocket
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
        sub = conn.execute(
            "SELECT id, status, user_id FROM submissions WHERE id = ?", (submission_id,)
        ).fetchone()
        if not sub:
            raise HTTPException(404, "Submission not found")

        if sub["user_id"] != user["user_id"]:
            raise HTTPException(403, "Cannot view another user's submission")

        result = conn.execute(
            "SELECT attestation_verified FROM results WHERE submission_id = ?",
            (submission_id,),
        ).fetchone()

        return StatusResponse(
            submission_id=sub["id"],
            status=sub["status"],
            attestation_verified=bool(result["attestation_verified"])
            if result
            else False,
        )


@router.get("/result/{submission_id}", response_model=ResultResponse)
def get_result(submission_id: int, user: dict = Depends(get_current_user)):
    with db_conn() as conn:
        # Check ownership
        sub = conn.execute(
            "SELECT user_id FROM submissions WHERE id = ?", (submission_id,)
        ).fetchone()
        if not sub:
            raise HTTPException(404, "Submission not found")
        if sub["user_id"] != user["user_id"]:
            raise HTTPException(403, "Cannot view another user's result")

        row = conn.execute(
            """
            SELECT s.id as submission_id, s.problem_id, r.verdict, r.time_ms, r.memory_kb,
                   r.test_passed, r.test_total, r.attestation_verified, r.nonce, r.judged_at
            FROM submissions s
            JOIN results r ON r.submission_id = s.id
            WHERE s.id = ?
            """,
            (submission_id,),
        ).fetchone()

        if not row:
            raise HTTPException(
                404, "Result not found. Judging may still be in progress."
            )

        return dict(row)
