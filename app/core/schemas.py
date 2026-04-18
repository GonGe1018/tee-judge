"""Pydantic schemas for the API."""

from pydantic import BaseModel, field_validator
from typing import Optional

VALID_LANGUAGES = ("c", "cpp")
VALID_VERDICTS = ("AC", "WA", "TLE", "RE", "CE")


# --- Auth ---


class RegisterRequest(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        v = v.strip()
        if len(v) < 2 or len(v) > 32:
            raise ValueError("username must be 2-32 characters")
        if not v.isalnum() and not all(c.isalnum() or c in "-_" for c in v):
            raise ValueError(
                "username must be alphanumeric (hyphens and underscores allowed)"
            )
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("password must be at least 8 characters")
        if not any(c.isdigit() for c in v):
            raise ValueError("password must contain at least one digit")
        if not any(c.isalpha() for c in v):
            raise ValueError("password must contain at least one letter")
        return v


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    token: str
    user_id: int
    username: str


# --- Problems ---


class ProblemSummary(BaseModel):
    id: int
    title: str
    time_limit_ms: int
    memory_limit_kb: int


class ProblemDetail(BaseModel):
    id: int
    title: str
    description: str
    input_desc: Optional[str]
    output_desc: Optional[str]
    sample_input: Optional[str]
    sample_output: Optional[str]
    time_limit_ms: int
    memory_limit_kb: int


# --- Submissions ---


class SubmitRequest(BaseModel):
    problem_id: int
    language: str
    code: str

    @field_validator("language")
    @classmethod
    def validate_language(cls, v):
        if v not in VALID_LANGUAGES:
            raise ValueError(f"language must be one of {VALID_LANGUAGES}")
        return v

    @field_validator("code")
    @classmethod
    def validate_code(cls, v):
        if not v.strip():
            raise ValueError("code cannot be empty")
        if len(v) > 65536:
            raise ValueError("code too long (max 64KB)")
        return v


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
    time_ms: Optional[int]
    memory_kb: Optional[int]
    test_passed: Optional[int]
    test_total: Optional[int]
    attestation_verified: bool = False
    nonce: Optional[str] = None
    judged_at: Optional[str] = None


# --- Judge ---


class JudgeTask(BaseModel):
    submission_id: int
    problem_id: int
    language: str
    code: str
    time_limit_ms: int
    memory_limit_kb: int
    testcases: list[dict]
    nonce: str


class JudgeResultRequest(BaseModel):
    submission_id: int
    actual_outputs: list[
        dict
    ]  # [{"order": 1, "output": "3", "time_ms": 5, "status": "OK"}, ...]
    outputs_hash: str  # SHA256 of canonical outputs (enclave-signed)
    time_ms: int
    memory_kb: int
    attestation_quote: Optional[str] = None
    verdict_signature: Optional[str] = None
    nonce: str
