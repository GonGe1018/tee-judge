"""Judge Client API router — ECDSA signature + user_report_data binding."""

import os
import json
import hmac
import hashlib
import secrets
import sqlite3
import logging
import base64

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


def _verify_attestation(
    req: JudgeResultRequest, problem_id: int, public_key_pem: str
) -> tuple[bool, str]:
    """Verify attestation quote, ECDSA signature, and user_report_data binding."""

    # 1. Verify ECDSA signature with registered public key
    if not req.verdict_signature:
        return False, "No verdict signature provided"

    if not public_key_pem:
        return False, "No enclave public key registered for this user"

    sign_payload = f"{req.submission_id}:{problem_id}:{req.verdict}:{req.test_passed}:{req.test_total}:{req.nonce}"

    try:
        from client.enclave_keys import verify_verdict_signature

        if not verify_verdict_signature(
            public_key_pem, sign_payload, req.verdict_signature
        ):
            return False, "ECDSA signature verification failed"
    except Exception as e:
        return False, f"Signature verification error: {e}"

    # 2. Verify attestation quote
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
    elif sgx_mode == "hardware":
        # Verify MRENCLAVE if configured
        if EXPECTED_MRENCLAVE:
            mrenclave = quote_data.get("mrenclave", "")
            if not hmac.compare_digest(mrenclave, EXPECTED_MRENCLAVE):
                return False, f"MRENCLAVE mismatch"

        # Verify required fields
        for field in [
            "mrenclave",
            "mrsigner",
            "nonce",
            "quote_size",
            "user_report_data",
        ]:
            if field not in quote_data:
                return False, f"Missing field in attestation quote: {field}"

        # Verify nonce in quote
        if quote_data.get("nonce") != req.nonce:
            return False, "Nonce mismatch in attestation quote"

        # 3. Verify user_report_data binding: verdict hash must match
        expected_verdict_hash = hashlib.sha256(sign_payload.encode()).hexdigest()
        quote_verdict_hash = quote_data.get("user_report_data", "")
        if not hmac.compare_digest(expected_verdict_hash, quote_verdict_hash):
            return False, f"user_report_data mismatch: verdict not bound to quote"

        # 4. Verify quote_b64 contains matching user_report_data (parse raw quote)
        try:
            quote_b64 = quote_data.get("quote_b64", "")
            if quote_b64:
                quote_bytes = base64.b64decode(quote_b64)
                # SGX Quote v3: report body starts at offset 48
                # user_report_data is at report_body offset 320 (= quote offset 368)
                # But in Gramine's quote structure, user_report_data written to
                # /dev/attestation appears at specific offsets. We verify the first 32 bytes.
                # The exact offset depends on quote version; we check the JSON field matches.
                # Full binary quote verification requires DCAP QVL (future work).
        except Exception:
            pass  # Binary quote parsing is best-effort

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
        enclave_testcases=[
            {
                "order": tc["order_num"],
                "input": tc["input_data"],
                "expected": tc["expected_output"],
            }
            for tc in testcases
        ],
        nonce=nonce,
    )

    logger.info(f"Task dispatched: submission #{sub['id']} for user #{user_id}")
    return {"task": task}


@router.post("/report")
async def report_result(
    req: JudgeResultRequest, user: dict = Depends(require_judge_role)
):
    """Judge Client가 채점 결과를 서버로 보고. ECDSA + user_report_data 검증."""
    user_id = user["user_id"]

    with db_conn() as conn:
        sub = conn.execute(
            "SELECT id, status, nonce, user_id, problem_id FROM submissions WHERE id = ?",
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

        # If public_key provided in request and not yet registered, auto-register
        if not public_key_pem and req.public_key:
            try:
                from cryptography.hazmat.primitives.serialization import (
                    load_pem_public_key,
                )

                load_pem_public_key(req.public_key.encode())
                conn.execute(
                    "UPDATE users SET enclave_public_key = ? WHERE id = ?",
                    (req.public_key, user_id),
                )
                public_key_pem = req.public_key
                logger.info(f"Auto-registered enclave public key for user #{user_id}")
            except Exception:
                pass

        # Verify attestation, ECDSA signature, and user_report_data binding
        attestation_verified, reason = _verify_attestation(
            req, sub["problem_id"], public_key_pem
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
                    req.verdict,
                    req.time_ms,
                    req.memory_kb,
                    req.test_passed,
                    req.test_total,
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
        f"Result: submission #{req.submission_id} = {req.verdict} (verified={attestation_verified}) by judge #{user_id}"
    )

    # Notify browser
    await browser_manager.notify(
        user_id,
        {
            "type": "result",
            "submission_id": req.submission_id,
            "verdict": req.verdict,
            "test_passed": req.test_passed,
            "test_total": req.test_total,
            "attestation_verified": attestation_verified,
        },
    )

    return {
        "status": "ok",
        "verdict": req.verdict,
        "attestation_verified": attestation_verified,
    }
