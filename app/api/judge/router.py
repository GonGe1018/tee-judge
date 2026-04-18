"""Judge Client API router — server-side verdict determination (v4).

Security model:
- Server NEVER sends expected_output to client
- Client (enclave) compiles + runs code via libtcc, sends actual_outputs + outputs_hash
- Server compares actual vs expected, determines verdict
- sign_payload = {sid}:{pid}:{nonce}:{code_hash}:{outputs_hash}
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import sqlite3

from fastapi import APIRouter, HTTPException, Depends

from app.api.judge.dto import JudgeTask, JudgeResultRequest
from app.core.auth import require_judge_role
from app.core.config import settings
from app.core.ws import browser_manager
from app.db.database import db_conn
from app.db import submissions_crud, problems_crud, results_crud, users_crud

logger = logging.getLogger("tee-judge")

router = APIRouter(prefix="/api/judge", tags=["judge"])


def _compute_outputs_hash(outputs: list[dict]) -> str:
    """Canonical hash of outputs — must match client's compute_outputs_hash."""
    if not outputs:
        return hashlib.sha256(b"CE").hexdigest()
    canonical_parts = [
        f"{o['order']}:{o['status']}:{o['output']}"
        for o in sorted(outputs, key=lambda x: x["order"])
    ]
    return hashlib.sha256("\n".join(canonical_parts).encode()).hexdigest()


def _determine_verdict(
    actual_outputs: list[dict], expected_testcases: list
) -> tuple[str, int, int]:
    """Compare actual outputs vs expected. Returns (verdict, test_passed, test_total)."""
    test_total = len(expected_testcases)

    if not actual_outputs:
        return "CE", 0, test_total

    expected_map = {
        tc["order_num"]: tc["expected_output"].strip() for tc in expected_testcases
    }
    test_passed = 0
    verdict = "AC"

    for output in sorted(actual_outputs, key=lambda x: x["order"]):
        order = output["order"]
        status = output.get("status", "OK")
        actual = output.get("output", "").strip()

        if status == "TLE":
            if verdict == "AC":
                verdict = "TLE"
        elif status == "RE":
            if verdict == "AC":
                verdict = "RE"
        elif order in expected_map:
            if actual == expected_map[order]:
                test_passed += 1
            elif verdict == "AC":
                verdict = "WA"
        elif verdict == "AC":
            verdict = "WA"

    return verdict, test_passed, test_total


def _verify_attestation(
    req: JudgeResultRequest, problem_id: int, public_key_pem: str, code_hash: str
) -> tuple[bool, str]:
    """Verify ECDSA signature + attestation quote."""
    if not req.verdict_signature:
        return False, "No verdict signature provided"

    sign_payload = (
        f"{req.submission_id}:{problem_id}:{req.nonce}:{code_hash}:{req.outputs_hash}"
    )

    try:
        from app.core.quote_verify import verify_verdict_signature

        if not verify_verdict_signature(
            public_key_pem, sign_payload, req.verdict_signature
        ):
            return False, "ECDSA signature verification failed"
    except Exception as e:
        return False, f"Signature verification error: {e}"

    computed_hash = _compute_outputs_hash(req.actual_outputs)
    if not hmac.compare_digest(computed_hash, req.outputs_hash):
        return False, f"outputs_hash mismatch: computed={computed_hash[:16]}..."

    if not req.attestation_quote:
        return False, "No attestation quote provided"

    try:
        quote_data = json.loads(req.attestation_quote)
    except (json.JSONDecodeError, TypeError):
        return False, "Invalid attestation quote format"

    sgx_mode = quote_data.get("sgx_mode", "unknown")

    if sgx_mode == "mock":
        if not settings.allow_mock:
            return False, "Mock attestation not allowed in production"
        logger.warning(
            f"Accepting mock attestation for submission #{req.submission_id}"
        )
        expected_hash = hashlib.sha256(sign_payload.encode()).hexdigest()
        quote_hash = quote_data.get("user_report_data", "")
        if not hmac.compare_digest(expected_hash, quote_hash):
            return False, "user_report_data mismatch in mock quote"

    elif sgx_mode == "hardware":
        quote_b64 = quote_data.get("quote_b64", "")
        if not quote_b64:
            return False, "No quote_b64 in hardware attestation"
        from app.core.quote_verify import verify_quote_full

        ok, reason = verify_quote_full(
            quote_b64=quote_b64,
            expected_sign_payload=sign_payload,
            expected_mrenclave=settings.TEE_JUDGE_MRENCLAVE,
        )
        if not ok:
            return False, reason
    else:
        return False, f"Unknown SGX mode: {sgx_mode}"

    return True, "OK"


@router.get("/poll")
def poll_task(user: dict = Depends(require_judge_role)):
    """Judge Client polls for a pending task."""
    user_id = user["user_id"]

    with db_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            sub = submissions_crud.get_pending_submission_for_user(conn, user_id)
            if not sub:
                conn.rollback()
                return {"task": None}

            nonce = secrets.token_hex(32)
            submissions_crud.update_submission_status(conn, sub["id"], "JUDGING", nonce)
            conn.commit()
        except Exception:
            conn.rollback()
            raise

        problem = problems_crud.get_problem_by_id(conn, sub["problem_id"])
        testcases = problems_crud.get_testcases_for_problem(conn, sub["problem_id"])

    task = JudgeTask(
        submission_id=sub["id"],
        problem_id=sub["problem_id"],
        language=sub["language"],
        code=sub["code"],
        time_limit_ms=problem["time_limit_ms"] if problem else 2000,
        memory_limit_kb=problem["memory_limit_kb"] if problem else 262144,
        testcases=[
            {"order": tc["order_num"], "input": tc["input_data"]} for tc in testcases
        ],
        nonce=nonce,
    )

    logger.info(f"Task dispatched: submission #{sub['id']} for user #{user_id}")
    return {"task": task}


@router.post("/report")
async def report_result(
    req: JudgeResultRequest, user: dict = Depends(require_judge_role)
):
    """Judge Client reports execution outputs. Server determines verdict."""
    user_id = user["user_id"]

    with db_conn() as conn:
        sub = submissions_crud.get_submission_by_id(conn, req.submission_id)
        if not sub:
            raise HTTPException(404, "Submission not found")
        if sub["user_id"] != user_id:
            raise HTTPException(
                403, "Cannot report result for another user's submission"
            )
        if sub["status"] != "JUDGING":
            raise HTTPException(
                409, f"Submission not in JUDGING state: {sub['status']}"
            )

        if not sub["nonce"] or not req.nonce:
            raise HTTPException(403, "Nonce is required")
        if not hmac.compare_digest(sub["nonce"], req.nonce):
            logger.warning(f"Nonce mismatch for submission #{req.submission_id}")
            raise HTTPException(403, "Nonce mismatch - possible replay attack")

        if results_crud.get_result_by_submission_id(conn, req.submission_id):
            raise HTTPException(409, "Result already reported")

        public_key_pem = users_crud.get_enclave_public_key(conn, user_id)
        if not public_key_pem:
            raise HTTPException(403, "No enclave public key registered.")

        code_hash = hashlib.sha256(sub["code"].encode()).hexdigest()[:16]

        attestation_verified, reason = _verify_attestation(
            req, sub["problem_id"], public_key_pem, code_hash
        )
        if not attestation_verified:
            logger.warning(f"Attestation failed for #{req.submission_id}: {reason}")
            if not settings.is_dev:
                raise HTTPException(403, "Attestation verification failed")
            logger.warning(
                f"Dev mode: accepting unverified attestation for #{req.submission_id}"
            )

        testcases = problems_crud.get_testcases_for_problem(conn, sub["problem_id"])

        if req.actual_outputs:
            verdict, test_passed, test_total = _determine_verdict(
                req.actual_outputs, testcases
            )
        else:
            verdict, test_passed, test_total = "CE", 0, len(testcases)

        from app.core.reverify import verify_execution_time

        time_ok, time_reason = verify_execution_time(req.time_ms, test_total, verdict)
        if not time_ok:
            logger.warning(f"Time check failed for #{req.submission_id}: {time_reason}")
            if not settings.is_dev:
                raise HTTPException(
                    403, f"Execution time verification failed: {time_reason}"
                )

        try:
            results_crud.insert_result(
                conn,
                submission_id=req.submission_id,
                verdict=verdict,
                time_ms=req.time_ms,
                memory_kb=req.memory_kb,
                test_passed=test_passed,
                test_total=test_total,
                attestation_quote=req.attestation_quote,
                attestation_verified=attestation_verified,
                verdict_signature=req.verdict_signature,
                nonce=req.nonce,
            )
            submissions_crud.update_submission_status(conn, req.submission_id, "DONE")
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Result already reported")

    logger.info(
        f"Result: submission #{req.submission_id} = {verdict} "
        f"({test_passed}/{test_total}) verified={attestation_verified} by judge #{user_id}"
    )

    await browser_manager.notify(
        user_id,
        {
            "type": "result",
            "submission_id": req.submission_id,
            "verdict": verdict,
            "test_passed": test_passed,
            "test_total": test_total,
            "attestation_verified": attestation_verified,
        },
    )

    return {
        "status": "ok",
        "verdict": verdict,
        "test_passed": test_passed,
        "test_total": test_total,
        "attestation_verified": attestation_verified,
    }
