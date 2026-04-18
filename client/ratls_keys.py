"""RA-TLS key management using libra_tls_attest.so.

Generates an RA-TLS certificate inside SGX enclave.
The private key never leaves the enclave memory.
The certificate contains an SGX quote — server can verify it via Azure MAA.
"""

from __future__ import annotations

import ctypes
import os
from typing import Optional

LIBRA_TLS_PATH = "/usr/lib/x86_64-linux-gnu/libra_tls_attest.so"

_lib = None
_der_key: Optional[bytes] = None
_der_crt: Optional[bytes] = None


def _get_lib():
    global _lib
    if _lib is None:
        _lib = ctypes.CDLL(LIBRA_TLS_PATH)
        _lib.ra_tls_create_key_and_crt_der.restype = ctypes.c_int
        _lib.ra_tls_create_key_and_crt_der.argtypes = [
            ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
            ctypes.POINTER(ctypes.c_size_t),
        ]
    return _lib


def generate_ratls_keypair() -> tuple[bytes, bytes]:
    """Generate RA-TLS key + certificate inside enclave.

    Returns (der_key, der_crt).
    der_key: DER-encoded private key (stays in enclave memory)
    der_crt: DER-encoded certificate with embedded SGX quote
    """
    global _der_key, _der_crt

    if _der_key and _der_crt:
        return _der_key, _der_crt

    lib = _get_lib()

    der_key_ptr = ctypes.POINTER(ctypes.c_uint8)()
    der_key_size = ctypes.c_size_t(0)
    der_crt_ptr = ctypes.POINTER(ctypes.c_uint8)()
    der_crt_size = ctypes.c_size_t(0)

    ret = lib.ra_tls_create_key_and_crt_der(
        ctypes.byref(der_key_ptr),
        ctypes.byref(der_key_size),
        ctypes.byref(der_crt_ptr),
        ctypes.byref(der_crt_size),
    )

    if ret != 0:
        raise RuntimeError(f"ra_tls_create_key_and_crt_der failed: {ret}")

    _der_key = bytes(der_key_ptr[: der_key_size.value])
    _der_crt = bytes(der_crt_ptr[: der_crt_size.value])

    return _der_key, _der_crt


def get_ratls_public_key_pem() -> str:
    """Extract public key PEM from RA-TLS certificate."""
    from cryptography.hazmat.primitives.serialization import (
        load_der_private_key,
        Encoding,
        PublicFormat,
    )
    from cryptography.hazmat.backends import default_backend

    der_key, _ = generate_ratls_keypair()
    private_key = load_der_private_key(
        der_key, password=None, backend=default_backend()
    )
    return (
        private_key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


def get_ratls_cert_der_b64() -> str:
    """Return RA-TLS certificate as base64 (for server registration)."""
    import base64

    _, der_crt = generate_ratls_keypair()
    return base64.b64encode(der_crt).decode()


def decrypt_with_ratls_key(encrypted_data: dict) -> bytes:
    """Decrypt data encrypted with ECDH + AES-GCM using RA-TLS private key.

    encrypted_data: {
        "ephemeral_pub_b64": str,  # ephemeral EC public key (DER, base64)
        "ciphertext_b64": str,     # AES-GCM ciphertext (base64)
        "nonce_b64": str,          # AES-GCM nonce (base64)
        "tag_b64": str,            # AES-GCM tag (base64)
    }
    """
    import base64
    from cryptography.hazmat.primitives.serialization import load_der_private_key
    from cryptography.hazmat.primitives.asymmetric.ec import ECDH
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend

    der_key, _ = generate_ratls_keypair()
    private_key = load_der_private_key(
        der_key, password=None, backend=default_backend()
    )

    ephemeral_pub_der = base64.b64decode(encrypted_data["ephemeral_pub_b64"])
    ephemeral_pub = load_der_public_key(ephemeral_pub_der, backend=default_backend())

    # ECDH shared secret
    shared_secret = private_key.exchange(ECDH(), ephemeral_pub)

    # HKDF → AES-256 key
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"tee-judge-testcase",
        backend=default_backend(),
    ).derive(shared_secret)

    # AES-GCM decrypt
    nonce = base64.b64decode(encrypted_data["nonce_b64"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext_b64"])
    tag = base64.b64decode(encrypted_data["tag_b64"])

    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext + tag, None)
