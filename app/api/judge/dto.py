from __future__ import annotations

from typing import Optional
from pydantic import BaseModel


class JudgeTask(BaseModel):
    submission_id: int
    problem_id: int
    language: str
    code: str
    time_limit_ms: int
    memory_limit_kb: int
    testcases: list[dict]  # input only (plaintext) — for non-SGX fallback
    encrypted_testcases: Optional[dict] = (
        None  # ECDH+AES-GCM encrypted inputs (SGX mode)
    )
    nonce: str


class JudgeResultRequest(BaseModel):
    submission_id: int
    actual_outputs: list[dict]
    outputs_hash: str
    time_ms: int
    memory_kb: int
    attestation_quote: Optional[str] = None
    verdict_signature: Optional[str] = None
    nonce: str
