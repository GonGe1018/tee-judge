"""Enclave key management: ECDSA key pair generation and sealed storage.

In SGX mode:
  - Private key is sealed to enclave (only this enclave can unseal)
  - Public key is exported for server registration

In non-SGX mode:
  - Key pair stored in a local file (dev only)
"""

import os
import json
import hashlib
import logging
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger("tee-judge")

# Sealed key storage path (default to /tmp for Gramine allowed_files compatibility)
SEALED_KEY_PATH = os.environ.get(
    "TEE_JUDGE_SEALED_KEY",
    "/tmp/.tee-judge-sealed-key.pem",
)


def _generate_keypair() -> ec.EllipticCurvePrivateKey:
    """Generate a new ECDSA P-256 key pair."""
    return ec.generate_private_key(ec.SECP256R1())


def _serialize_private_key(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _serialize_public_key(key: ec.EllipticCurvePrivateKey) -> str:
    """Export public key as PEM string."""
    return (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )


def _load_private_key(data: bytes) -> ec.EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(data, password=None)


def load_or_create_keypair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    """Load existing key pair or create new one.

    If file write fails (e.g., inside SGX enclave), keeps key in memory only.
    Returns (private_key, public_key_pem).
    """
    sealed_path = Path(SEALED_KEY_PATH)

    if sealed_path.exists():
        try:
            key_data = sealed_path.read_bytes()
            if key_data:  # not empty
                private_key = _load_private_key(key_data)
                public_pem = _serialize_public_key(private_key)
                logger.info(f"Loaded existing enclave key pair from {sealed_path}")
                return private_key, public_pem
        except Exception as e:
            logger.warning(f"Failed to load sealed key: {e}. Generating new pair.")

    # Generate new key pair
    private_key = _generate_keypair()
    key_data = _serialize_private_key(private_key)

    # Try to save (may fail inside SGX enclave)
    try:
        sealed_path.parent.mkdir(parents=True, exist_ok=True)
        sealed_path.write_bytes(key_data)
        os.chmod(str(sealed_path), 0o600)
        logger.info(f"Generated new enclave key pair, saved to {sealed_path}")
    except (PermissionError, OSError) as e:
        logger.warning(
            f"Cannot save key to {sealed_path}: {e}. Using in-memory key only."
        )

    public_pem = _serialize_public_key(private_key)
    logger.info(f"Generated new enclave key pair, saved to {sealed_path}")

    return private_key, public_pem


def sign_verdict(private_key: ec.EllipticCurvePrivateKey, payload: str) -> str:
    """Sign verdict payload with ECDSA P-256. Returns hex-encoded signature."""
    signature = private_key.sign(
        payload.encode(),
        ec.ECDSA(hashes.SHA256()),
    )
    return signature.hex()


def verify_verdict_signature(
    public_key_pem: str, payload: str, signature_hex: str
) -> bool:
    """Verify ECDSA signature. Used by server."""
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
