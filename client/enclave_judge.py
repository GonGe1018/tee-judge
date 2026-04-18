"""Two-phase judge: compile+run outside enclave, hash+sign inside enclave.

Security model (v3 — server-side comparison):
- Server NEVER sends expected_output to client (prevents answer leakage)
- Phase 1 (host): compile + run → collect raw stdout outputs
- Phase 2 (enclave): hash outputs + sign with ECDSA + attestation quote
- Server: compares actual_outputs vs expected, determines verdict
- Enclave proves "these outputs came from this code" via attestation
- sign_payload = {sid}:{pid}:{nonce}:{code_hash}:{outputs_hash}
"""

from __future__ import annotations

import sys
import os
import json
import subprocess
import tempfile
import time
import hashlib
import platform
from pathlib import Path

from client.enclave_keys import load_or_create_keypair, sign_verdict

# Phase 1: Host-side (outside enclave)
# Compile and run user code, collect raw outputs

# Sandbox limits
MAX_MEMORY_BYTES = 512 * 1024 * 1024  # 512MB
MAX_OUTPUT_BYTES = 64 * 1024  # 64KB
MAX_PROCESSES = 64


def _get_sandbox_preexec(for_compiler=False):
    """Return a preexec_fn that applies resource limits on Linux."""
    if platform.system() != "Linux":
        import logging

        logging.getLogger("tee-judge").warning(
            "Non-Linux platform: sandbox disabled. User code runs without resource limits."
        )
        return None

    def _sandbox():
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (MAX_MEMORY_BYTES, MAX_MEMORY_BYTES))
        cpu_limit = (60, 90) if for_compiler else (10, 15)
        resource.setrlimit(resource.RLIMIT_CPU, cpu_limit)
        resource.setrlimit(resource.RLIMIT_NPROC, (MAX_PROCESSES, MAX_PROCESSES))
        fsize = 10 * 1024 * 1024 if for_compiler else MAX_OUTPUT_BYTES
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    return _sandbox


def host_compile_and_run(task):
    """Compile code and run against testcases with sandboxing. Returns raw results."""
    with tempfile.TemporaryDirectory(prefix="tee-judge-") as tmpdir:
        tmpdir = Path(tmpdir)

        ext = ".c" if task["language"] == "c" else ".cpp"
        source = tmpdir / f"solution{ext}"
        source.write_text(task["code"], encoding="utf-8")

        exe = tmpdir / "solution"
        compiler = "gcc" if task["language"] == "c" else "g++"
        cmd = [compiler, "-O2", "-o", str(exe), str(source)]
        if task["language"] == "cpp":
            cmd.insert(1, "-std=c++17")

        # Compile (with sandbox)
        compiler_sandbox = _get_sandbox_preexec(for_compiler=True)
        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                preexec_fn=compiler_sandbox,
                cwd=str(tmpdir),
            )
            if r.returncode != 0:
                return {"status": "CE", "outputs": []}
        except FileNotFoundError:
            return {"status": "CE", "outputs": []}

        sandbox = _get_sandbox_preexec()
        outputs = []

        for tc in task["testcases"]:
            try:
                start = time.perf_counter()
                r = subprocess.run(
                    [str(exe)],
                    input=tc["input"],
                    capture_output=True,
                    text=True,
                    timeout=task["time_limit_ms"] / 1000.0 + 0.5,
                    preexec_fn=sandbox,
                    cwd=str(tmpdir),
                )
                elapsed_ms = int((time.perf_counter() - start) * 1000)

                if r.returncode != 0:
                    outputs.append(
                        {
                            "order": tc["order"],
                            "output": "",
                            "time_ms": elapsed_ms,
                            "status": "RE",
                        }
                    )
                elif elapsed_ms > task["time_limit_ms"]:
                    outputs.append(
                        {
                            "order": tc["order"],
                            "output": "",
                            "time_ms": elapsed_ms,
                            "status": "TLE",
                        }
                    )
                else:
                    outputs.append(
                        {
                            "order": tc["order"],
                            "output": r.stdout.strip()[:MAX_OUTPUT_BYTES],
                            "time_ms": elapsed_ms,
                            "status": "OK",
                        }
                    )
            except subprocess.TimeoutExpired:
                outputs.append(
                    {
                        "order": tc["order"],
                        "output": "",
                        "time_ms": task["time_limit_ms"],
                        "status": "TLE",
                    }
                )
            except Exception:
                outputs.append(
                    {
                        "order": tc["order"],
                        "output": "",
                        "time_ms": 0,
                        "status": "RE",
                    }
                )

        return {"status": "OK", "outputs": outputs}


# Phase 2: Enclave-side (inside SGX)
# Hash outputs and sign — NO comparison, NO verdict determination


def compute_outputs_hash(outputs: list[dict]) -> str:
    """Compute canonical hash of outputs for signing.

    Canonical form: sorted by order, each entry = "order:status:output".
    Empty outputs (CE) → SHA256("CE").
    """
    if not outputs:
        return hashlib.sha256(b"CE").hexdigest()
    canonical_parts = []
    for o in sorted(outputs, key=lambda x: x["order"]):
        canonical_parts.append(f"{o['order']}:{o['status']}:{o['output']}")
    canonical = "\n".join(canonical_parts)
    return hashlib.sha256(canonical.encode()).hexdigest()


def enclave_hash_and_sign(task, host_results):
    """Hash outputs and sign inside enclave. Does NOT determine verdict.

    Server will compare actual outputs vs expected to determine verdict.
    """

    # Load key: prefer stdin-injected key (via env), fallback to file
    injected_pem = os.environ.get("_TEE_JUDGE_PRIVATE_KEY_PEM", "")
    if injected_pem:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.backends import default_backend

        private_key = load_pem_private_key(
            injected_pem.encode(), password=None, backend=default_backend()
        )
        from client.enclave_keys import _serialize_public_key

        public_key_pem = _serialize_public_key(private_key)
    else:
        private_key, public_key_pem = load_or_create_keypair()

    if host_results["status"] == "CE":
        outputs = []
        outputs_hash = compute_outputs_hash([])
        max_time = 0
    else:
        outputs = host_results["outputs"]
        outputs_hash = compute_outputs_hash(outputs)
        max_time = max((o["time_ms"] for o in outputs), default=0)

    # Build sign payload (no verdict — server decides)
    nonce = task["nonce"]
    code_hash = hashlib.sha256(task.get("code", "").encode()).hexdigest()[:16]
    sign_payload = f"{task['submission_id']}:{task['problem_id']}:{nonce}:{code_hash}:{outputs_hash}"

    # Compute payload hash for user_report_data binding
    payload_hash = hashlib.sha256(sign_payload.encode()).digest()

    # Sign with ECDSA private key
    signature = sign_verdict(private_key, sign_payload)

    # Try real SGX attestation via /dev/attestation
    attestation_quote = None

    try:
        import binascii

        attestation_dir = "/dev/attestation"

        if os.path.exists(attestation_dir):
            # user_report_data = payload_hash (32 bytes) + padding
            report_data = payload_hash + b"\x00" * (64 - len(payload_hash))

            with open(f"{attestation_dir}/user_report_data", "wb") as f:
                f.write(report_data)

            with open(f"{attestation_dir}/attestation_type", "r") as f:
                att_type = f.read().strip()

            with open(f"{attestation_dir}/quote", "rb") as f:
                quote_bytes = f.read()

            mrenclave = binascii.hexlify(quote_bytes[112:144]).decode()
            mrsigner = binascii.hexlify(quote_bytes[176:208]).decode()

            attestation_quote = json.dumps(
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
        else:
            raise FileNotFoundError("/dev/attestation not found")

    except Exception:
        # Fallback to mock attestation (dev only, default OFF)
        import binascii

        allow_mock = os.environ.get("TEE_JUDGE_ALLOW_MOCK", "0") == "1"
        if not allow_mock:
            raise RuntimeError(
                "SGX attestation required but /dev/attestation not available"
            )

        mrenclave = hashlib.sha256(b"tee-judge-enclave-mock").hexdigest()
        attestation_quote = json.dumps(
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

    return {
        "submission_id": task["submission_id"],
        "actual_outputs": outputs,
        "outputs_hash": outputs_hash,
        "time_ms": max_time,
        "memory_kb": 0,
        "attestation_quote": attestation_quote,
        "verdict_signature": signature,
        "nonce": nonce,
    }


def enclave_compile_run_and_sign(task):
    """Full enclave execution: compile + run + hash + sign + attestation.

    v4 (RA-TLS): testcases are encrypted with enclave's RA-TLS public key.
    Enclave decrypts testcases, runs via libtcc, signs outputs hash.
    Host never sees testcase inputs or outputs.
    """
    from client.tcc_runner import compile_and_run_all

    # Resolve testcases: decrypt if encrypted, else use plaintext
    encrypted_testcases = task.get("encrypted_testcases")
    if encrypted_testcases:
        try:
            from client.ratls_keys import decrypt_with_ratls_key
            import json as _json

            decrypted = decrypt_with_ratls_key(encrypted_testcases)
            testcases = _json.loads(decrypted)
        except Exception as e:
            # Fallback to plaintext if decryption fails (e.g., not in SGX)
            testcases = task.get("testcases", [])
    else:
        testcases = task.get("testcases", [])

    # Load signing key: prefer RA-TLS key (enclave-only), fallback to ECDSA
    try:
        from client.ratls_keys import generate_ratls_keypair
        from cryptography.hazmat.primitives.serialization import load_der_private_key
        from cryptography.hazmat.backends import default_backend

        der_key, _ = generate_ratls_keypair()
        private_key = load_der_private_key(
            der_key, password=None, backend=default_backend()
        )
    except Exception:
        # Fallback to ECDSA key (non-SGX mode)
        injected_pem = os.environ.get("_TEE_JUDGE_PRIVATE_KEY_PEM", "")
        if injected_pem:
            from cryptography.hazmat.primitives.serialization import (
                load_pem_private_key,
            )
            from cryptography.hazmat.backends import default_backend

            private_key = load_pem_private_key(
                injected_pem.encode(), password=None, backend=default_backend()
            )
        else:
            private_key, _ = load_or_create_keypair()

    # Compile and run all testcases inside enclave via libtcc
    run_result = compile_and_run_all(
        code=task["code"],
        testcases=testcases,
        time_limit_ms=task.get("time_limit_ms", 2000),
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
    nonce = task["nonce"]
    code_hash = hashlib.sha256(task.get("code", "").encode()).hexdigest()[:16]
    sign_payload = f"{task['submission_id']}:{task['problem_id']}:{nonce}:{code_hash}:{outputs_hash}"

    # Compute payload hash for user_report_data binding
    payload_hash = hashlib.sha256(sign_payload.encode()).digest()

    # Sign with ECDSA
    signature = sign_verdict(private_key, sign_payload)

    # Attestation quote
    attestation_quote = None
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

            attestation_quote = json.dumps(
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
        else:
            raise FileNotFoundError("/dev/attestation not found")

    except Exception:
        import binascii

        allow_mock = os.environ.get("TEE_JUDGE_ALLOW_MOCK", "0") == "1"
        if not allow_mock:
            raise RuntimeError(
                "SGX attestation required but /dev/attestation not available"
            )

        mrenclave = hashlib.sha256(b"tee-judge-enclave-mock").hexdigest()
        attestation_quote = json.dumps(
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

    return {
        "submission_id": task["submission_id"],
        "actual_outputs": outputs,
        "outputs_hash": outputs_hash,
        "time_ms": max_time,
        "memory_kb": 0,
        "attestation_quote": attestation_quote,
        "verdict_signature": signature,
        "nonce": nonce,
    }


if __name__ == "__main__":
    # Read task from stdin (TOCTOU-safe: no file-based input)
    task = json.loads(sys.stdin.read())

    # v4 mode: if no host_results provided, run everything inside enclave
    host_results_raw = os.environ.get("HOST_RESULTS", "")
    if host_results_raw:
        host_results = json.loads(host_results_raw)
        result = enclave_hash_and_sign(task, host_results)
    else:
        # Full enclave execution (libtcc)
        result = enclave_compile_run_and_sign(task)

    print(json.dumps(result))
