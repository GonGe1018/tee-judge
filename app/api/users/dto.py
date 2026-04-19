from __future__ import annotations

from typing import Optional
from pydantic import BaseModel


class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    token: str
    user_id: int
    username: str


class JudgeTokenRequest(BaseModel):
    judge_key: str


class JudgeTokenResponse(BaseModel):
    token: str
    user_id: int
    username: str
    role: str


class RegisterKeyRequest(BaseModel):
    public_key: str
    ratls_cert_der_b64: Optional[str] = (
        None  # RA-TLS certificate (required in production)
    )
