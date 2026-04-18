"""Pydantic schemas — re-exports from domain dto files.

All schemas are defined in app/api/*/dto.py and re-exported here
for backward compatibility with existing imports.
"""

from __future__ import annotations

# Auth
from app.api.users.dto import (
    RegisterRequest,
    LoginRequest,
    TokenResponse,
    JudgeTokenRequest,
    JudgeTokenResponse,
    RegisterKeyRequest,
)

# Problems
from app.api.problems.dto import ProblemSummary, ProblemDetail

# Submissions
from app.api.submissions.dto import (
    SubmitRequest,
    SubmitResponse,
    StatusResponse,
    ResultResponse,
)

# Judge
from app.api.judge.dto import JudgeTask, JudgeResultRequest

VALID_LANGUAGES = ("c", "cpp")
VALID_VERDICTS = ("AC", "WA", "TLE", "RE", "CE")

__all__ = [
    "RegisterRequest",
    "LoginRequest",
    "TokenResponse",
    "JudgeTokenRequest",
    "JudgeTokenResponse",
    "RegisterKeyRequest",
    "ProblemSummary",
    "ProblemDetail",
    "SubmitRequest",
    "SubmitResponse",
    "StatusResponse",
    "ResultResponse",
    "JudgeTask",
    "JudgeResultRequest",
    "VALID_LANGUAGES",
    "VALID_VERDICTS",
]
