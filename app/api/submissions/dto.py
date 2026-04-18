from pydantic import BaseModel
from typing import Optional


class SubmitRequest(BaseModel):
    problem_id: int
    language: str
    code: str


class SubmitResponse(BaseModel):
    submission_id: int
    status: str
    message: str


class StatusResponse(BaseModel):
    submission_id: int
    status: str
    attestation_verified: bool = False


class ResultResponse(BaseModel):
    submission_id: int
    problem_id: int
    verdict: str
    time_ms: Optional[int] = None
    memory_kb: Optional[int] = None
    test_passed: Optional[int] = None
    test_total: Optional[int] = None
    attestation_verified: bool = False
    nonce: Optional[str] = None
    judged_at: Optional[str] = None
