"""Users API router: register, login, judge token."""

import logging

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from app.core.schemas import RegisterRequest, LoginRequest, TokenResponse
from app.core.auth import (
    hash_password,
    verify_password,
    create_token,
    verify_judge_key,
    get_current_user,
)
from app.db.database import db_conn

logger = logging.getLogger("tee-judge")

router = APIRouter(prefix="/api/auth", tags=["auth"])


class JudgeTokenRequest(BaseModel):
    judge_key: str


class JudgeTokenResponse(BaseModel):
    token: str
    user_id: int
    username: str
    role: str


@router.post("/register", response_model=TokenResponse)
def register(req: RegisterRequest):
    with db_conn() as conn:
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?", (req.username,)
        ).fetchone()
        if existing:
            raise HTTPException(409, "Username already taken")

        pw_hash = hash_password(req.password)
        cursor = conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (req.username, pw_hash),
        )
        user_id = cursor.lastrowid
        conn.commit()

    token = create_token(user_id, req.username, role="user")
    logger.info(f"User registered: {req.username} (#{user_id})")
    return TokenResponse(token=token, user_id=user_id, username=req.username)


@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest):
    with db_conn() as conn:
        user = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (req.username,),
        ).fetchone()

    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(401, "Invalid username or password")

    token = create_token(user["id"], user["username"], role="user")
    logger.info(f"User logged in: {req.username}")
    return TokenResponse(token=token, user_id=user["id"], username=user["username"])


@router.post("/judge-token", response_model=JudgeTokenResponse)
def get_judge_token(req: JudgeTokenRequest, user: dict = Depends(get_current_user)):
    """Get a judge-role token. Requires valid user token + judge_key.
    This separates the judge role from normal users."""
    if not verify_judge_key(req.judge_key):
        raise HTTPException(403, "Invalid judge key")

    token = create_token(user["user_id"], user["username"], role="judge")
    logger.info(f"Judge token issued for: {user['username']}")
    return JudgeTokenResponse(
        token=token,
        user_id=user["user_id"],
        username=user["username"],
        role="judge",
    )


class RegisterKeyRequest(BaseModel):
    public_key: str


@router.post("/register-enclave-key")
def register_enclave_key(
    req: RegisterKeyRequest, user: dict = Depends(get_current_user)
):
    """Register enclave's ECDSA public key. Judge role required. One-time only."""
    # Must have judge role
    if user.get("role") != "judge":
        raise HTTPException(403, "Judge role required to register enclave key")

    # Validate PEM
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        load_pem_public_key(req.public_key.encode())
    except Exception:
        raise HTTPException(400, "Invalid PEM public key")

    with db_conn() as conn:
        # Check if key already registered (one-time only)
        existing = conn.execute(
            "SELECT enclave_public_key FROM users WHERE id = ?", (user["user_id"],)
        ).fetchone()
        if existing and existing["enclave_public_key"]:
            raise HTTPException(
                409, "Enclave public key already registered. Cannot overwrite."
            )

        conn.execute(
            "UPDATE users SET enclave_public_key = ? WHERE id = ?",
            (req.public_key, user["user_id"]),
        )
        conn.commit()

    logger.info(f"Enclave public key registered for user #{user['user_id']}")
    return {"status": "ok"}
