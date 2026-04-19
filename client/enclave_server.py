"""Long-running SGX enclave server — length-prefixed JSON-RPC.

Runs inside Gramine SGX. Starts once, handles multiple tasks.
RA-TLS key is generated once and reused for all tasks in the session.

Protocol:
  Request:  4-byte big-endian length + UTF-8 JSON
  Response: 4-byte big-endian length + UTF-8 JSON

Request format:
  {"id": str, "type": "task", "params": {
      "submission_id": int,
      "problem_id": int,
      "code": str,
      "testcases": [{"order": int, "input": str}],  # plaintext fallback
      "encrypted_testcases": {...} | null,           # ECDH+AES-GCM encrypted
      "nonce": str,
      "time_limit_ms": int
  }}

Response format:
  {"id": str, "result": {
      "submission_id": int,
      "actual_outputs": [...],
      "outputs_hash": str,
      "time_ms": int,
      "memory_kb": int,
      "attestation_quote": str,
      "verdict_signature": str,
      "nonce": str
  }}
  or
  {"id": str, "error": {"code": str, "message": str}}
"""

from __future__ import annotations

import json
import os
import sys
import traceback

# Setup path
PYTHONPATH = os.environ.get("PYTHONPATH", "/home/judgeclient/tee-judge")
sys.path.insert(0, PYTHONPATH)
os.chdir(PYTHONPATH)


# --- Wire protocol ---


def read_message() -> dict:
    """Read one length-prefixed JSON message from stdin."""
    len_bytes = sys.stdin.buffer.read(4)
    if len(len_bytes) < 4:
        raise EOFError("stdin closed")
    length = int.from_bytes(len_bytes, "big")
    payload = sys.stdin.buffer.read(length)
    if len(payload) < length:
        raise EOFError("truncated message")
    return json.loads(payload.decode("utf-8"))


def write_message(msg: dict) -> None:
    """Write one length-prefixed JSON message to stdout."""
    payload = json.dumps(msg, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(len(payload).to_bytes(4, "big"))
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


# --- RA-TLS key (session-scoped, generated once) ---

_session_private_key = None
_session_public_key_pem = None


def _init_session_key():
    """Generate RA-TLS key pair once for this enclave session."""
    global _session_private_key, _session_public_key_pem

    try:
        from client.ratls_keys import (
            generate_ratls_keypair,
            get_ratls_public_key_pem,
            get_ratls_cert_der_b64,
        )
        from cryptography.hazmat.primitives.serialization import load_der_private_key
        from cryptography.hazmat.backends import default_backend

        der_key, _ = generate_ratls_keypair()
        _session_private_key = load_der_private_key(
            der_key, password=None, backend=default_backend()
        )
        _session_public_key_pem = get_ratls_public_key_pem()
        ratls_cert_b64 = get_ratls_cert_der_b64()
        return True, _session_public_key_pem, ratls_cert_b64
    except Exception as e:
        # Fallback to ECDSA key (non-SGX / dev mode)
        try:
            from client.enclave_keys import load_or_create_keypair

            _session_private_key, _session_public_key_pem = load_or_create_keypair()
            return True, _session_public_key_pem, None
        except Exception as e2:
            return False, str(e2), None


# --- Task processing ---


def _resolve_testcases(params: dict) -> list[dict]:
    """Decrypt testcases if encrypted, else return plaintext."""
    encrypted = params.get("encrypted_testcases")
    if encrypted:
        try:
            from client.ratls_keys import decrypt_with_ratls_key

            decrypted_bytes = decrypt_with_ratls_key(encrypted)
            return json.loads(decrypted_bytes)
        except Exception as e:
            # Fallback to plaintext
            pass
    return params.get("testcases", [])


def _process_task(params: dict) -> dict:
    """Compile + run + sign inside enclave."""
    from client.tcc_runner import compile_and_run_all
    from client.enclave_judge import compute_outputs_hash
    from client.enclave_keys import sign_verdict
    import hashlib
    import time

    testcases = _resolve_testcases(params)
    code = params["code"]
    time_limit_ms = params.get("time_limit_ms", 2000)
    submission_id = params["submission_id"]
    problem_id = params["problem_id"]
    nonce = params["nonce"]

    # Compile + run
    run_result = compile_and_run_all(
        code=code,
        testcases=testcases,
        time_limit_ms=time_limit_ms,
    )

    if run_result["status"] == "CE":
        outputs = []
        outputs_hash = compute_outputs_hash([])
        max_time = 0
    else:
        outputs = run_result["outputs"]
        outputs_hash = compute_outputs_hash(outputs)
        max_time = max((o["time_ms"] for o in outputs), default=0)

    # Build sign payload
    code_hash = hashlib.sha256(code.encode()).hexdigest()[:16]
    sign_payload = f"{submission_id}:{problem_id}:{nonce}:{code_hash}:{outputs_hash}"
    payload_hash = hashlib.sha256(sign_payload.encode()).digest()

    # Sign with session key
    signature = sign_verdict(_session_private_key, sign_payload)

    # Attestation quote
    attestation_quote = _get_attestation_quote(payload_hash, nonce)

    return {
        "submission_id": submission_id,
        "actual_outputs": outputs,
        "outputs_hash": outputs_hash,
        "time_ms": max_time,
        "memory_kb": 0,
        "attestation_quote": attestation_quote,
        "verdict_signature": signature,
        "nonce": nonce,
    }


def _get_attestation_quote(payload_hash: bytes, nonce: str) -> str:
    """Get SGX attestation quote or mock."""
    import json
    import hashlib
    import time

    try:
        import binascii

        attestation_dir = "/dev/attestation"

        if os.path.exists(attestation_dir):
            report_data = payload_hash + b"\x00" * (64 - len(payload_hash))
            with open(f"{attestation_dir}/user_report_data", "wb") as f:
                f.write(report_data)
            with open(f"{attestation_dir}/attestation_type", "r") as f:
                att_type = f.read().strip()
            with open(f"{attestation_dir}/quote", "rb") as f:
                quote_bytes = f.read()

            mrenclave = binascii.hexlify(quote_bytes[112:144]).decode()
            mrsigner = binascii.hexlify(quote_bytes[176:208]).decode()

            return json.dumps(
                {
                    "type": att_type,
                    "quote_size": len(quote_bytes),
                    "quote_b64": binascii.b2a_base64(quote_bytes).decode(),
                    "mrenclave": mrenclave,
                    "mrsigner": mrsigner,
                    "user_report_data": binascii.hexlify(payload_hash).decode(),
                    "nonce": nonce,
                    "timestamp": time.time(),
                    "sgx_mode": "hardware",
                }
            )
    except Exception:
        pass

    # Mock fallback
    allow_mock = os.environ.get("TEE_JUDGE_ALLOW_MOCK", "0") == "1"
    if not allow_mock:
        raise RuntimeError(
            "SGX attestation required but /dev/attestation not available"
        )

    import binascii

    mrenclave = hashlib.sha256(b"tee-judge-enclave-mock").hexdigest()
    return json.dumps(
        {
            "type": "mock",
            "mrenclave": mrenclave,
            "mrsigner": hashlib.sha256(b"tee-judge-signer-mock").hexdigest(),
            "user_report_data": binascii.hexlify(payload_hash).decode(),
            "nonce": nonce,
            "timestamp": time.time(),
            "sgx_mode": "mock",
        }
    )


# --- Main loop ---


def main():
    # Initialize session key
    ok, pub_key_or_err, ratls_cert_b64 = _init_session_key()

    # Send ready message with public key + RA-TLS certificate
    write_message(
        {
            "type": "ready",
            "public_key_pem": pub_key_or_err if ok else None,
            "ratls_cert_der_b64": ratls_cert_b64,  # None in non-SGX/dev mode
            "error": None if ok else pub_key_or_err,
        }
    )

    if not ok:
        return

    # Main message loop
    while True:
        try:
            msg = read_message()
        except EOFError:
            # Daemon closed connection — normal shutdown
            break
        except Exception as e:
            write_message(
                {"id": None, "error": {"code": "READ_ERROR", "message": str(e)}}
            )
            break

        msg_id = msg.get("id")
        msg_type = msg.get("type")

        if msg_type == "shutdown":
            write_message({"id": msg_id, "result": {"status": "bye"}})
            break

        if msg_type != "task":
            write_message(
                {
                    "id": msg_id,
                    "error": {
                        "code": "BAD_REQUEST",
                        "message": f"Unknown type: {msg_type}",
                    },
                }
            )
            continue

        try:
            result = _process_task(msg.get("params", {}))
            write_message({"id": msg_id, "result": result})
        except Exception as e:
            write_message(
                {
                    "id": msg_id,
                    "error": {
                        "code": "TASK_FAILED",
                        "message": str(e),
                        "trace": traceback.format_exc(),
                    },
                }
            )


if __name__ == "__main__":
    main()
