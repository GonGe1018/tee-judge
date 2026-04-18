"""Users API router: register, login, judge token."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Depends

from app.api.users.dto import (
    RegisterRequest,
    LoginRequest,
    TokenResponse,
    JudgeTokenRequest,
    JudgeTokenResponse,
    RegisterKeyRequest,
)
from app.core.auth import (
    hash_password,
    verify_password,
    create_token,
    verify_judge_key,
    get_current_user,
)
from app.db.database import db_conn
from app.db import users_crud

logger = logging.getLogger("tee-judge")

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse)
def register(req: RegisterRequest):
    with db_conn() as conn:
        if users_crud.get_user_by_username(conn, req.username):
            raise HTTPException(409, "Username already taken")
        pw_hash = hash_password(req.password)
        user_id = users_crud.create_user(conn, req.username, pw_hash)

    token = create_token(user_id, req.username, role="user")
    logger.info(f"User registered: {req.username} (#{user_id})")
    return TokenResponse(token=token, user_id=user_id, username=req.username)


@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest):
    with db_conn() as conn:
        user = users_crud.get_user_by_username(conn, req.username)

    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(401, "Invalid username or password")

    token = create_token(user["id"], user["username"], role="user")
    logger.info(f"User logged in: {req.username}")
    return TokenResponse(token=token, user_id=user["id"], username=user["username"])


@router.post("/judge-token", response_model=JudgeTokenResponse)
def get_judge_token(req: JudgeTokenRequest, user: dict = Depends(get_current_user)):
    """Get a judge-role token. Requires valid user token + judge_key."""
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


@router.post("/register-enclave-key")
def register_enclave_key(
    req: RegisterKeyRequest, user: dict = Depends(get_current_user)
):
    """Register enclave's ECDSA public key. Judge role required. One-time only."""
    if user.get("role") != "judge":
        raise HTTPException(403, "Judge role required to register enclave key")

    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.backends import default_backend

        load_pem_public_key(req.public_key.encode(), backend=default_backend())
    except Exception:
        raise HTTPException(400, "Invalid PEM public key")

    with db_conn() as conn:
        existing_key = users_crud.get_enclave_public_key(conn, user["user_id"])
        if existing_key:
            raise HTTPException(
                409, "Enclave public key already registered. Cannot overwrite."
            )
        users_crud.set_user_enclave_key(conn, user["user_id"], req.public_key)

    logger.info(f"Enclave public key registered for user #{user['user_id']}")
    return {"status": "ok"}
