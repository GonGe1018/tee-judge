"""Authentication: JWT tokens, password hashing, user/judge role management."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time

import bcrypt
from fastapi import HTTPException, Request

from app.core.config import settings

logger = logging.getLogger("tee-judge")


def _secret_key() -> str:
    key = settings.TEE_JUDGE_SECRET
    if not key:
        if not settings.is_dev:
            raise RuntimeError("TEE_JUDGE_SECRET must be set in production")
        logger.warning(
            "Using insecure dev SECRET_KEY. Set TEE_JUDGE_SECRET for production."
        )
        return "dev-only-insecure-key"
    return key


def _judge_key() -> str:
    key = settings.TEE_JUDGE_JUDGE_KEY
    if not key:
        if not settings.is_dev:
            raise RuntimeError("TEE_JUDGE_JUDGE_KEY must be set in production")
        logger.warning(
            "Using insecure dev JUDGE_KEY. Set TEE_JUDGE_JUDGE_KEY for production."
        )
        return "dev-only-judge-key"
    return key


# --- Password Hashing ---


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, stored: str) -> bool:
    return bcrypt.checkpw(password.encode(), stored.encode())


# --- Token Management ---


def create_token(user_id: int, username: str, role: str = "user") -> str:
    payload = json.dumps(
        {
            "user_id": user_id,
            "username": username,
            "role": role,
            "exp": int(time.time()) + settings.TEE_JUDGE_TOKEN_EXPIRY,
        }
    )
    signature = hmac.new(
        _secret_key().encode(), payload.encode(), hashlib.sha256
    ).hexdigest()
    token_data = base64.urlsafe_b64encode(payload.encode()).decode()
    return f"{token_data}.{signature}"


def decode_token(token: str) -> dict:
    try:
        token_data, signature = token.rsplit(".", 1)
        payload = base64.urlsafe_b64decode(token_data).decode()
        expected_sig = hmac.new(
            _secret_key().encode(), payload.encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            raise ValueError("Invalid signature")
        data = json.loads(payload)
        if data["exp"] < time.time():
            raise ValueError("Token expired")
        return data
    except Exception as e:
        raise ValueError(f"Invalid token: {e}")


def get_current_user(request: Request) -> dict:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header")
    try:
        return decode_token(auth[7:])
    except ValueError as e:
        raise HTTPException(401, str(e))


def require_judge_role(request: Request) -> dict:
    user = get_current_user(request)
    if user.get("role") != "judge":
        raise HTTPException(403, "Judge role required. Use judge token.")
    return user


def verify_judge_key(key: str) -> bool:
    return hmac.compare_digest(key, _judge_key())
