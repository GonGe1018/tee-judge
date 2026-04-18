"""Judge Client API router — server-side verdict determination (v3).

Security model:
- Server NEVER sends expected_output to client
- Client sends actual_outputs + outputs_hash signed by enclave
- Server compares actual vs expected, determines verdict
- sign_payload = {sid}:{pid}:{nonce}:{code_hash}:{outputs_hash}
"""

import os
import json
import hmac
import hashlib
import secrets
import sqlite3
import logging

from fastapi import APIRouter, HTTPException, Depends

from app.core.schemas import JudgeTask, JudgeResultRequest
from app.core.auth import require_judge_role
from app.core.ws import browser_manager
from app.db.database import db_conn

logger = logging.getLogger("tee-judge")

router = APIRouter(prefix="/api/judge", tags=["judge"])

# Expected MRENCLAVE (set after building enclave, or via env)
EXPECTED_MRENCLAVE = os.environ.get("TEE_JUDGE_MRENCLAVE", "")

# Allow mock attestation (dev only)
ALLOW_MOCK = os.environ.get("TEE_JUDGE_ALLOW_MOCK", "0") == "1"


def _compute_outputs_hash(outputs: list[dict]) -> str:
    """Compute canonical hash of outputs — must match client's compute_outputs_hash.

    Empty outputs (CE) → SHA256("CE").
    """
    if not outputs:
        return hashlib.sha256(b"CE").hexdigest()
    canonical_parts = []
    for o in sorted(outputs, key=lambda x: x["order"]):
        canonical_parts.append(f"{o['order']}:{o['status']}:{o['output']}")
    canonical = "\n".join(canonical_parts)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _determine_verdict(
    actual_outputs: list[dict], expected_testcases: list[dict]
) -> tuple[str, int, int]:
    """Compare actual outputs vs expected. Returns (verdict, test_passed, test_total).

    Server-side verdict determination — client never knows expected outputs.
    """
    test_total = len(expected_testcases)

    if not actual_outputs:
        return "CE", 0, test_total

    # Build expected lookup by order
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
            else:
                if verdict == "AC":
                    verdict = "WA"
        else:
            if verdict == "AC":
                verdict = "WA"

    return verdict, test_passed, test_total


def _verify_attestation(
    req: JudgeResultRequest, problem_id: int, public_key_pem: str, code_hash: str
) -> tuple[bool, str]:
    """Verify ECDSA signature + attestation quote (v3: outputs_hash in sign_payload)."""

    # 1. Verify ECDSA signature with registered public key
    if not req.verdict_signature:
        return False, "No verdict signature provided"

    if not public_key_pem:
        return False, "No enclave public key registered for this user"

    # v3 sign_payload: no verdict — just identity + outputs_hash
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

    # 2. Verify outputs_hash matches actual_outputs
    computed_hash = _compute_outputs_hash(req.actual_outputs)
    if not hmac.compare_digest(computed_hash, req.outputs_hash):
        return (
            False,
            f"outputs_hash mismatch: computed={computed_hash[:16]}... vs reported={req.outputs_hash[:16]}...",
        )

    # 3. Verify attestation quote
    if not req.attestation_quote:
        return False, "No attestation quote provided"

    try:
        quote_data = json.loads(req.attestation_quote)
    except (json.JSONDecodeError, TypeError):
        return False, "Invalid attestation quote format"

    sgx_mode = quote_data.get("sgx_mode", "unknown")

    if sgx_mode == "mock":
        if not ALLOW_MOCK:
            return False, "Mock attestation not allowed in production"
        logger.warning(
            f"Accepting mock attestation for submission #{req.submission_id}"
        )
        # Still verify user_report_data in mock mode
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
            expected_mrenclave=EXPECTED_MRENCLAVE,
        )
        if not ok:
            return False, reason

    else:
        return False, f"Unknown SGX mode: {sgx_mode}"

    return True, "OK"


@router.get("/poll")
def poll_task(user: dict = Depends(require_judge_role)):
    """Judge Client가 본인 유저의 대기 중인 채점 작업을 가져감."""
    user_id = user["user_id"]

    with db_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            sub = conn.execute(
                "SELECT * FROM submissions WHERE status = 'PENDING' AND user_id = ? ORDER BY id LIMIT 1",
                (user_id,),
            ).fetchone()

            if not sub:
                conn.rollback()
                return {"task": None}

            nonce = secrets.token_hex(32)

            conn.execute(
                "UPDATE submissions SET status = 'JUDGING', nonce = ? WHERE id = ?",
                (nonce, sub["id"]),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise

        problem = conn.execute(
            "SELECT * FROM problems WHERE id = ?", (sub["problem_id"],)
        ).fetchone()

        testcases = conn.execute(
            "SELECT order_num, input_data, expected_output FROM testcases WHERE problem_id = ? ORDER BY order_num",
            (sub["problem_id"],),
        ).fetchall()

    task = JudgeTask(
        submission_id=sub["id"],
        problem_id=sub["problem_id"],
        language=sub["language"],
        code=sub["code"],
        time_limit_ms=problem["time_limit_ms"],
        memory_limit_kb=problem["memory_limit_kb"],
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
        sub = conn.execute(
            "SELECT id, status, nonce, user_id, problem_id, code, language FROM submissions WHERE id = ?",
            (req.submission_id,),
        ).fetchone()
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

        # Nonce MUST match
        if not sub["nonce"] or not req.nonce:
            raise HTTPException(403, "Nonce is required")
        if not hmac.compare_digest(sub["nonce"], req.nonce):
            logger.warning(f"Nonce mismatch for submission #{req.submission_id}")
            raise HTTPException(403, "Nonce mismatch - possible replay attack")

        # Check duplicate
        existing = conn.execute(
            "SELECT id FROM results WHERE submission_id = ?", (req.submission_id,)
        ).fetchone()
        if existing:
            raise HTTPException(409, "Result already reported")

        # Get registered public key for this user
        user_row = conn.execute(
            "SELECT enclave_public_key FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        public_key_pem = user_row["enclave_public_key"] if user_row else None

        if not public_key_pem:
            raise HTTPException(
                403,
                "No enclave public key registered. Register via /api/auth/register-enclave-key first.",
            )

        # Compute code hash for signature binding
        code_hash = hashlib.sha256(sub["code"].encode()).hexdigest()[:16]

        # Verify attestation, ECDSA signature, outputs_hash binding
        attestation_verified, reason = _verify_attestation(
            req, sub["problem_id"], public_key_pem, code_hash
        )
        if not attestation_verified:
            logger.warning(
                f"Attestation failed for submission #{req.submission_id}: {reason}"
            )
            if os.environ.get("TEE_JUDGE_ENV", "production") != "dev":
                raise HTTPException(403, f"Attestation verification failed: {reason}")
            else:
                logger.warning(
                    f"Dev mode: accepting unverified attestation for #{req.submission_id}"
                )

        # Server-side verdict determination
        testcases = conn.execute(
            "SELECT order_num, input_data, expected_output FROM testcases WHERE problem_id = ? ORDER BY order_num",
            (sub["problem_id"],),
        ).fetchall()

        if req.actual_outputs:
            verdict, test_passed, test_total = _determine_verdict(
                req.actual_outputs, testcases
            )
        else:
            # Empty outputs = CE
            verdict = "CE"
            test_passed = 0
            test_total = len(testcases)

        # Time-based verification
        from app.core.reverify import verify_execution_time

        time_ok, time_reason = verify_execution_time(req.time_ms, test_total, verdict)
        if not time_ok:
            logger.warning(f"Time check failed for #{req.submission_id}: {time_reason}")
            if os.environ.get("TEE_JUDGE_ENV", "production") != "dev":
                raise HTTPException(
                    403, f"Execution time verification failed: {time_reason}"
                )

        # Server-side random re-verification (compile + run on server)
        from app.core.reverify import reverify_submission

        tc_list = [
            {
                "order": tc["order_num"],
                "input": tc["input_data"],
                "expected": tc["expected_output"],
            }
            for tc in testcases
        ]

        problem = conn.execute(
            "SELECT time_limit_ms FROM problems WHERE id = ?", (sub["problem_id"],)
        ).fetchone()
        problem_time_limit = problem["time_limit_ms"] if problem else 2000

        rv_ok, rv_reason = reverify_submission(
            code=sub["code"],
            language=sub["language"],
            testcases=tc_list,
            reported_verdict=verdict,
            reported_test_passed=test_passed,
            reported_time_ms=req.time_ms,
            time_limit_ms=problem_time_limit,
        )
        if not rv_ok:
            logger.warning(
                f"Reverification failed for #{req.submission_id}: {rv_reason}"
            )
            if os.environ.get("TEE_JUDGE_ENV", "production") != "dev":
                raise HTTPException(403, f"Server re-verification failed: {rv_reason}")
            else:
                logger.warning(
                    f"Dev mode: accepting unverified result for #{req.submission_id}"
                )

        logger.info(f"Reverification: {rv_reason}")

        # Insert result + update status atomically
        try:
            conn.execute(
                """
                INSERT INTO results (submission_id, verdict, time_ms, memory_kb, test_passed, test_total,
                                     attestation_quote, attestation_verified, verdict_signature, nonce)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    req.submission_id,
                    verdict,
                    req.time_ms,
                    req.memory_kb,
                    test_passed,
                    test_total,
                    req.attestation_quote,
                    attestation_verified,
                    req.verdict_signature,
                    req.nonce,
                ),
            )
            conn.execute(
                "UPDATE submissions SET status = 'DONE' WHERE id = ?",
                (req.submission_id,),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Result already reported")

    logger.info(
        f"Result: submission #{req.submission_id} = {verdict} "
        f"({test_passed}/{test_total}) verified={attestation_verified} by judge #{user_id}"
    )

    # Notify browser
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
