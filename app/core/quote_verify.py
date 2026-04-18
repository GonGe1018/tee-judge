"""SGX Quote v3 binary parser and Azure MAA verification.

Parses raw SGX DCAP quote binary to extract:
- MRENCLAVE, MRSIGNER, user_report_data
- Verifies quote via Azure MAA REST API

SGX Quote v3 layout:
  Offset 0-47:    Header (48 bytes)
  Offset 48-431:  Report Body (384 bytes)
    - Offset 112-143: MRENCLAVE (32 bytes)
    - Offset 176-207: MRSIGNER (32 bytes)
    - Offset 368-431: report_data (64 bytes, first 32 = user_report_data)
  Offset 432-435: signature_data_len (4 bytes)
  Offset 436+:    signature_data (variable)
"""

from __future__ import annotations

import os
import json
import base64
import hashlib
import logging
import struct
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger("tee-judge")

# SGX Quote v3 offsets
HEADER_SIZE = 48
REPORT_BODY_OFFSET = HEADER_SIZE  # 48
MRENCLAVE_OFFSET = 112  # header(48) + cpusvn(16) + misc_select(4) + reserved(28) + attributes(16) = 112
MRSIGNER_OFFSET = 176  # MRENCLAVE_OFFSET + 32 + reserved(32) = 176
REPORT_DATA_OFFSET = 368  # header(48) + report_body fields up to report_data
REPORT_DATA_SIZE = 64
SIGNATURE_DATA_LEN_OFFSET = 432
MIN_QUOTE_SIZE = 436


@dataclass
class ParsedQuote:
    """Parsed fields from SGX Quote v3 binary."""

    version: int
    att_key_type: int
    mrenclave: str  # hex
    mrsigner: str  # hex
    user_report_data: bytes  # 64 bytes
    signature_data_len: int
    raw_bytes: bytes


def parse_quote_binary(quote_bytes: bytes) -> ParsedQuote:
    """Parse SGX Quote v3 binary and extract key fields."""
    if len(quote_bytes) < MIN_QUOTE_SIZE:
        raise ValueError(
            f"Quote too short: {len(quote_bytes)} bytes (min {MIN_QUOTE_SIZE})"
        )

    version = struct.unpack_from("<H", quote_bytes, 0)[0]
    att_key_type = struct.unpack_from("<H", quote_bytes, 2)[0]

    mrenclave = quote_bytes[MRENCLAVE_OFFSET : MRENCLAVE_OFFSET + 32].hex()
    mrsigner = quote_bytes[MRSIGNER_OFFSET : MRSIGNER_OFFSET + 32].hex()
    user_report_data = quote_bytes[
        REPORT_DATA_OFFSET : REPORT_DATA_OFFSET + REPORT_DATA_SIZE
    ]
    signature_data_len = struct.unpack_from(
        "<I", quote_bytes, SIGNATURE_DATA_LEN_OFFSET
    )[0]

    return ParsedQuote(
        version=version,
        att_key_type=att_key_type,
        mrenclave=mrenclave,
        mrsigner=mrsigner,
        user_report_data=user_report_data,
        signature_data_len=signature_data_len,
        raw_bytes=quote_bytes,
    )


def verify_user_report_data(
    parsed: ParsedQuote, expected_payload: str
) -> tuple[bool, str]:
    """Verify that user_report_data in quote matches SHA256(expected_payload)."""
    expected_hash = hashlib.sha256(expected_payload.encode()).digest()
    # user_report_data is 64 bytes, first 32 bytes should match SHA256 hash
    actual_hash = parsed.user_report_data[:32]

    if expected_hash != actual_hash:
        return False, (
            f"user_report_data mismatch: "
            f"expected={expected_hash.hex()[:16]}..., "
            f"got={actual_hash.hex()[:16]}..."
        )
    return True, "OK"


def verify_verdict_signature(
    public_key_pem: str, payload: str, signature_hex: str
) -> bool:
    """Verify ECDSA signature with registered public key. Used by server."""
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        public_key.verify(
            bytes.fromhex(signature_hex),
            payload.encode(),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except (InvalidSignature, Exception):
        return False


# --- Azure MAA Verification ---

# Azure MAA endpoint (configurable via env)
MAA_ENDPOINT = os.environ.get("TEE_JUDGE_MAA_ENDPOINT", "")


def verify_quote_with_maa(quote_bytes: bytes) -> tuple[bool, str, dict]:
    """Verify SGX quote using Azure MAA REST API (anonymous, no OAuth2 needed).

    Returns (verified, reason, maa_claims).
    """
    if not MAA_ENDPOINT:
        return False, "MAA endpoint not configured (set TEE_JUDGE_MAA_ENDPOINT)", {}

    try:
        import requests

        quote_b64url = base64.urlsafe_b64encode(quote_bytes).rstrip(b"=").decode()

        url = f"{MAA_ENDPOINT}/attest/SgxEnclave?api-version=2022-08-01"
        r = requests.post(
            url,
            json={"quote": quote_b64url},
            headers={"Content-Type": "application/json"},
            timeout=30,
        )

        if r.status_code == 200:
            result = r.json()
            maa_token = result.get("token", "")
            # Decode JWT payload (MAA already verified the quote)
            parts = maa_token.split(".")
            if len(parts) >= 2:
                payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
                claims = json.loads(base64.urlsafe_b64decode(payload_b64))
                logger.info(
                    f"MAA verification succeeded: mrenclave={claims.get('x-ms-sgx-mrenclave', '?')[:16]}..."
                )
                return True, "OK", claims
            return True, "OK (no claims parsed)", {}
        else:
            return False, f"MAA returned {r.status_code}: {r.text[:300]}", {}

    except Exception as e:
        return False, f"MAA verification error: {e}", {}


def verify_quote_full(
    quote_b64: str,
    expected_sign_payload: str,
    expected_mrenclave: str = "",
) -> tuple[bool, str]:
    """Full quote verification: parse binary + verify user_report_data + MAA.

    In production, MAA verification is REQUIRED.
    Returns (verified, reason).
    """
    # 1. Decode and parse quote binary
    try:
        quote_bytes = base64.b64decode(quote_b64)
        parsed = parse_quote_binary(quote_bytes)
    except Exception as e:
        return False, f"Quote binary parse error: {e}"

    # 2. Verify MRENCLAVE if expected
    if expected_mrenclave:
        import hmac as _hmac

        if not _hmac.compare_digest(parsed.mrenclave, expected_mrenclave):
            return (
                False,
                f"MRENCLAVE mismatch: expected={expected_mrenclave[:16]}..., got={parsed.mrenclave[:16]}...",
            )

    # 3. Verify user_report_data binding
    ok, reason = verify_user_report_data(parsed, expected_sign_payload)
    if not ok:
        return False, reason

    # 4. Azure MAA verification (Intel signature chain)
    if MAA_ENDPOINT:
        ok, reason, claims = verify_quote_with_maa(quote_bytes)
        if not ok:
            return False, f"MAA verification failed: {reason}"
        # Cross-check MAA claims with our expectations
        if claims:
            maa_mrenclave = claims.get("x-ms-sgx-mrenclave", "")
            if expected_mrenclave and maa_mrenclave != expected_mrenclave:
                return False, f"MAA MRENCLAVE mismatch: {maa_mrenclave[:16]}..."

            # Reject debug enclaves in production
            is_debuggable = claims.get("x-ms-sgx-is-debuggable", True)
            is_prod = os.environ.get("TEE_JUDGE_ENV", "production") != "dev"
            if is_debuggable and is_prod:
                return (
                    False,
                    "Debug enclave not allowed in production (x-ms-sgx-is-debuggable=true)",
                )
            if is_debuggable:
                logger.warning("Accepting debug enclave in dev mode")
    else:
        # Production REQUIRES MAA
        is_prod = os.environ.get("TEE_JUDGE_ENV", "production") != "dev"
        if is_prod:
            return (
                False,
                "MAA endpoint not configured. Required in production for Intel signature verification.",
            )
        logger.warning(
            "MAA not configured — skipping Intel signature verification (dev mode only)"
        )

    return True, "OK"
