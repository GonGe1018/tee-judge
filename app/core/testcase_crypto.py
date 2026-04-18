"""Testcase input encryption using ECDH + AES-GCM.

Server encrypts testcase inputs with enclave's RA-TLS public key.
Only the enclave (holding the private key) can decrypt.
"""

from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    generate_private_key,
    SECP256R1,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def encrypt_testcases(testcases: list[dict], enclave_public_key_pem: str) -> dict:
    """Encrypt testcase inputs with enclave's public key via ECDH + AES-GCM.

    Args:
        testcases: [{"order": int, "input": str}, ...]
        enclave_public_key_pem: enclave's EC public key (PEM)

    Returns dict with encrypted payload that only the enclave can decrypt.
    """
    # Load enclave public key
    enclave_pub = serialization.load_pem_public_key(
        enclave_public_key_pem.encode(), backend=default_backend()
    )

    # Generate ephemeral EC key pair using SAME curve as enclave key
    curve = enclave_pub.curve
    ephemeral_priv = generate_private_key(curve, default_backend())
    ephemeral_pub = ephemeral_priv.public_key()

    # ECDH shared secret
    shared_secret = ephemeral_priv.exchange(ECDH(), enclave_pub)

    # HKDF → AES-256 key
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"tee-judge-testcase",
        backend=default_backend(),
    ).derive(shared_secret)

    # Serialize testcases to JSON
    plaintext = json.dumps(testcases).encode()

    # AES-GCM encrypt
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)

    # Split ciphertext and tag (last 16 bytes)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    # Serialize ephemeral public key
    ephemeral_pub_der = ephemeral_pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return {
        "ephemeral_pub_b64": base64.b64encode(ephemeral_pub_der).decode(),
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
        "nonce_b64": base64.b64encode(nonce).decode(),
        "tag_b64": base64.b64encode(tag).decode(),
    }
