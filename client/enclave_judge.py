"""Two-phase judge: compile+run outside enclave, verify+sign inside enclave."""

import sys
import os
import json
import subprocess
import tempfile
import time
import hashlib
import hmac
import platform
from pathlib import Path

# Phase 1: Host-side (outside enclave)
# Compile and run user code, collect raw outputs

# Sandbox limits
MAX_MEMORY_BYTES = 512 * 1024 * 1024  # 512MB
MAX_OUTPUT_BYTES = 64 * 1024  # 64KB
MAX_PROCESSES = 16

# Signing key from environment (REQUIRED in production)
_raw_key = os.environ.get("TEE_JUDGE_ENCLAVE_KEY", "")
if not _raw_key:
    if os.environ.get("TEE_JUDGE_ENV", "production") != "dev":
        print("FATAL: TEE_JUDGE_ENCLAVE_KEY must be set", file=sys.stderr)
        sys.exit(1)
    _raw_key = "dev-only-enclave-key"
ENCLAVE_KEY = _raw_key.encode()


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

        # Memory limit
        resource.setrlimit(resource.RLIMIT_AS, (MAX_MEMORY_BYTES, MAX_MEMORY_BYTES))
        # CPU time limit
        cpu_limit = (60, 90) if for_compiler else (10, 15)
        resource.setrlimit(resource.RLIMIT_CPU, cpu_limit)
        # Max processes (prevent fork bomb)
        resource.setrlimit(resource.RLIMIT_NPROC, (MAX_PROCESSES, MAX_PROCESSES))
        # Max file size (prevent disk fill)
        fsize = (
            10 * 1024 * 1024 if for_compiler else MAX_OUTPUT_BYTES
        )  # 10MB for compiler
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
        # No core dumps
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
                    cwd=str(tmpdir),  # restrict working directory
                )
                elapsed_ms = int((time.perf_counter() - start) * 1000)

                if r.returncode != 0:
                    outputs.append(
                        {
                            "order": tc["order"],
                            "actual": "",
                            "time_ms": elapsed_ms,
                            "status": "RE",
                        }
                    )
                elif elapsed_ms > task["time_limit_ms"]:
                    outputs.append(
                        {
                            "order": tc["order"],
                            "actual": "",
                            "time_ms": elapsed_ms,
                            "status": "TLE",
                        }
                    )
                else:
                    outputs.append(
                        {
                            "order": tc["order"],
                            "actual": r.stdout.strip()[:MAX_OUTPUT_BYTES],
                            "time_ms": elapsed_ms,
                            "status": "OK",
                        }
                    )
            except subprocess.TimeoutExpired:
                outputs.append(
                    {
                        "order": tc["order"],
                        "actual": "",
                        "time_ms": task["time_limit_ms"],
                        "status": "TLE",
                    }
                )
            except Exception:
                outputs.append(
                    {
                        "order": tc["order"],
                        "actual": "",
                        "time_ms": 0,
                        "status": "RE",
                    }
                )

        return {"status": "OK", "outputs": outputs}


# Phase 2: Enclave-side (inside SGX)
# Compare outputs with expected, generate verdict + signature


def enclave_verify_and_sign(task, host_results):
    """Verify results and sign verdict inside enclave."""
    if host_results["status"] == "CE":
        verdict = "CE"
        test_passed = 0
        test_total = len(task["testcases"])
        max_time = 0
    else:
        test_passed = 0
        test_total = len(task["testcases"])
        max_time = 0
        verdict = "AC"

        for output, tc in zip(host_results["outputs"], task["testcases"]):
            max_time = max(max_time, output["time_ms"])

            if output["status"] == "TLE":
                if verdict == "AC":
                    verdict = "TLE"
            elif output["status"] == "RE":
                if verdict == "AC":
                    verdict = "RE"
            elif output["actual"] == tc["expected"].strip():
                test_passed += 1
            else:
                if verdict == "AC":
                    verdict = "WA"

    # Generate attestation data
    nonce = task["nonce"]
    sign_payload = f"{task['submission_id']}:{task['problem_id']}:{verdict}:{test_passed}:{test_total}:{nonce}"

    # Try real SGX attestation via /dev/attestation
    attestation_quote = None

    try:
        import binascii

        attestation_dir = "/dev/attestation"

        if os.path.exists(attestation_dir):
            report_data = hashlib.sha256(sign_payload.encode()).digest()
            report_data = report_data + b"\x00" * (64 - len(report_data))

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
                    "user_report_data": binascii.hexlify(report_data[:32]).decode(),
                    "nonce": nonce,
                    "timestamp": time.time(),
                    "sgx_mode": "hardware",
                }
            )
        else:
            raise FileNotFoundError("/dev/attestation not found")

    except Exception:
        # Fallback to mock attestation (dev only, default OFF)
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
                "nonce": nonce,
                "timestamp": time.time(),
                "sgx_mode": "mock",
            }
        )

    # Sign verdict
    signature = hmac.new(ENCLAVE_KEY, sign_payload.encode(), hashlib.sha256).hexdigest()

    return {
        "submission_id": task["submission_id"],
        "verdict": verdict,
        "time_ms": max_time,
        "memory_kb": 0,
        "test_passed": test_passed,
        "test_total": test_total,
        "attestation_quote": attestation_quote,
        "verdict_signature": signature,
        "nonce": nonce,
    }


if __name__ == "__main__":
    task = json.loads(sys.stdin.read())
    host_results = json.loads(os.environ.get("HOST_RESULTS", "{}"))
    result = enclave_verify_and_sign(task, host_results)
    print(json.dumps(result))
