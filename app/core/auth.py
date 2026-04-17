"""Authentication: JWT tokens, password hashing, user/judge role management."""

import os
import hmac
import hashlib
import time
import json
import logging
import sys
from fastapi import HTTPException, Request, Depends

logger = logging.getLogger("tee-judge")

# --- Secret Key (REQUIRED in production) ---

SECRET_KEY = os.environ.get("TEE_JUDGE_SECRET", "")
if not SECRET_KEY:
    if os.environ.get("TEE_JUDGE_ENV", "dev") != "dev":
        print("FATAL: TEE_JUDGE_SECRET must be set in production", file=sys.stderr)
        sys.exit(1)
    SECRET_KEY = "dev-only-insecure-key"
    logger.warning(
        "Using insecure dev SECRET_KEY. Set TEE_JUDGE_SECRET for production."
    )

TOKEN_EXPIRY = int(os.environ.get("TEE_JUDGE_TOKEN_EXPIRY", "86400"))  # 24h default

# --- Judge Key (separate auth for judge clients) ---

JUDGE_KEY = os.environ.get("TEE_JUDGE_JUDGE_KEY", "")
if not JUDGE_KEY:
    if os.environ.get("TEE_JUDGE_ENV", "dev") != "dev":
        print("FATAL: TEE_JUDGE_JUDGE_KEY must be set in production", file=sys.stderr)
        sys.exit(1)
    JUDGE_KEY = "dev-only-judge-key"
    logger.warning(
        "Using insecure dev JUDGE_KEY. Set TEE_JUDGE_JUDGE_KEY for production."
    )


# --- Password Hashing (bcrypt) ---

try:
    import bcrypt

    def hash_password(password: str) -> str:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def verify_password(password: str, stored: str) -> bool:
        return bcrypt.checkpw(password.encode(), stored.encode())

except ImportError:
    logger.warning(
        "bcrypt not installed, falling back to SHA-256 (NOT recommended for production)"
    )

    def hash_password(password: str) -> str:
        salt = os.urandom(16).hex()
        hashed = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
        return f"{salt}:{hashed}"

    def verify_password(password: str, stored: str) -> bool:
        salt, hashed = stored.split(":", 1)
        computed = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
        return hmac.compare_digest(computed, hashed)


# --- Token Management ---


def create_token(user_id: int, username: str, role: str = "user") -> str:
    """Create a signed token with role."""
    import base64

    payload = json.dumps(
        {
            "user_id": user_id,
            "username": username,
            "role": role,
            "exp": int(time.time()) + TOKEN_EXPIRY,
        }
    )
    signature = hmac.new(
        SECRET_KEY.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()
    token_data = base64.urlsafe_b64encode(payload.encode()).decode()
    return f"{token_data}.{signature}"


def decode_token(token: str) -> dict:
    """Decode and verify a token."""
    import base64

    try:
        token_data, signature = token.rsplit(".", 1)
        payload = base64.urlsafe_b64decode(token_data).decode()
        expected_sig = hmac.new(
            SECRET_KEY.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            raise ValueError("Invalid signature")
        data = json.loads(payload)
        if data["exp"] < time.time():
            raise ValueError("Token expired")
        return data
    except Exception as e:
        raise ValueError(f"Invalid token: {e}")


# --- FastAPI Dependencies ---


def get_current_user(request: Request) -> dict:
    """Extract user from Authorization header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header")
    try:
        return decode_token(auth[7:])
    except ValueError as e:
        raise HTTPException(401, str(e))


def require_judge_role(request: Request) -> dict:
    """Extract user and verify judge role."""
    user = get_current_user(request)
    if user.get("role") != "judge":
        raise HTTPException(403, "Judge role required. Use judge token.")
    return user


def verify_judge_key(key: str) -> bool:
    """Verify the judge registration key."""
    return hmac.compare_digest(key, JUDGE_KEY)
