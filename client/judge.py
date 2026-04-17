"""TEE-Judge Client - Windows Judge Client with SGX mock mode.

Usage:
    python -m client.judge --server http://localhost:8000 [--mock]

Polls the server for pending submissions, compiles and runs them locally,
and reports results back. In --mock mode, simulates SGX attestation.
In real SGX mode (future), runs inside an SGX enclave on Linux.
"""

import argparse
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests


# --- Configuration ---

POLL_INTERVAL = 2  # seconds between polls
MOCK_ENCLAVE_KEY = b"tee-judge-mock-enclave-secret-key"  # Mock signing key


def main():
    parser = argparse.ArgumentParser(description="TEE-Judge Client")
    parser.add_argument("--server", default="http://localhost:8000", help="Server URL")
    parser.add_argument(
        "--mock", action="store_true", default=True, help="Use mock SGX mode (default)"
    )
    args = parser.parse_args()

    print(f"[TEE-Judge Client] Server: {args.server}")
    print(f"[TEE-Judge Client] Mode: {'Mock SGX' if args.mock else 'Real SGX'}")
    print(f"[TEE-Judge Client] Polling for tasks...\n")

    while True:
        try:
            task = poll_task(args.server)
            if task:
                print(
                    f"[Task] Submission #{task['submission_id']} - Problem #{task['problem_id']}"
                )
                result = judge(task, mock=args.mock)
                report_result(args.server, result)
                print(
                    f"[Done] Verdict: {result['verdict']} ({result['test_passed']}/{result['test_total']})\n"
                )
            else:
                time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            print("\n[TEE-Judge Client] Stopped.")
            break
        except Exception as e:
            print(f"[Error] {e}")
            time.sleep(POLL_INTERVAL)


def poll_task(server: str) -> dict | None:
    """Poll server for a pending judge task."""
    res = requests.get(f"{server}/api/judge/poll", timeout=10)
    res.raise_for_status()
    data = res.json()
    return data.get("task")


def report_result(server: str, result: dict):
    """Report judge result back to server."""
    res = requests.post(f"{server}/api/judge/report", json=result, timeout=10)
    res.raise_for_status()


def judge(task: dict, mock: bool = True) -> dict:
    """Compile and judge a submission against testcases."""
    with tempfile.TemporaryDirectory(prefix="tee-judge-") as tmpdir:
        tmpdir = Path(tmpdir)

        # Write source code
        ext = ".c" if task["language"] == "c" else ".cpp"
        source_path = tmpdir / f"solution{ext}"
        source_path.write_text(task["code"], encoding="utf-8")

        # Compile
        exe_path = tmpdir / "solution.exe"
        compile_ok, compile_msg = compile_code(source_path, exe_path, task["language"])

        if not compile_ok:
            return make_result(
                task,
                verdict="CE",
                time_ms=0,
                memory_kb=0,
                test_passed=0,
                test_total=len(task["testcases"]),
                mock=mock,
            )

        # Run testcases
        test_passed = 0
        test_total = len(task["testcases"])
        max_time_ms = 0
        max_memory_kb = 0
        verdict = "AC"

        for tc in task["testcases"]:
            tc_result = run_testcase(
                exe_path,
                tc["input"],
                tc["expected"],
                time_limit_ms=task["time_limit_ms"],
            )

            if tc_result["status"] == "AC":
                test_passed += 1
            elif verdict == "AC":
                verdict = tc_result["status"]

            max_time_ms = max(max_time_ms, tc_result["time_ms"])
            max_memory_kb = max(max_memory_kb, tc_result["memory_kb"])

            print(
                f"  Test #{tc['order']}: {tc_result['status']} ({tc_result['time_ms']}ms)"
            )

        return make_result(
            task,
            verdict=verdict,
            time_ms=max_time_ms,
            memory_kb=max_memory_kb,
            test_passed=test_passed,
            test_total=test_total,
            mock=mock,
        )


def compile_code(source: Path, output: Path, language: str) -> tuple[bool, str]:
    """Compile source code using GCC/G++."""
    compiler = "gcc" if language == "c" else "g++"
    cmd = [compiler, "-O2", "-o", str(output), str(source)]

    if language == "cpp":
        cmd.insert(1, "-std=c++17")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            print(f"  [CE] {result.stderr[:200]}")
            return False, result.stderr
        return True, ""
    except FileNotFoundError:
        print(f"  [CE] Compiler '{compiler}' not found. Install MinGW or GCC.")
        return False, f"Compiler '{compiler}' not found"
    except subprocess.TimeoutExpired:
        return False, "Compilation timeout"


def run_testcase(exe: Path, input_data: str, expected: str, time_limit_ms: int) -> dict:
    """Run executable with input and compare output."""
    time_limit_sec = time_limit_ms / 1000.0

    try:
        start = time.perf_counter()
        result = subprocess.run(
            [str(exe)],
            input=input_data,
            capture_output=True,
            text=True,
            timeout=time_limit_sec + 0.5,  # small buffer
        )
        elapsed_ms = int((time.perf_counter() - start) * 1000)

        if result.returncode != 0:
            return {"status": "RE", "time_ms": elapsed_ms, "memory_kb": 0}

        if elapsed_ms > time_limit_ms:
            return {"status": "TLE", "time_ms": elapsed_ms, "memory_kb": 0}

        actual = result.stdout.strip()
        if actual == expected.strip():
            return {"status": "AC", "time_ms": elapsed_ms, "memory_kb": 0}
        else:
            return {"status": "WA", "time_ms": elapsed_ms, "memory_kb": 0}

    except subprocess.TimeoutExpired:
        return {"status": "TLE", "time_ms": time_limit_ms, "memory_kb": 0}
    except Exception as e:
        return {"status": "RE", "time_ms": 0, "memory_kb": 0}


def make_result(
    task: dict,
    verdict: str,
    time_ms: int,
    memory_kb: int,
    test_passed: int,
    test_total: int,
    mock: bool,
) -> dict:
    """Create result dict with optional mock attestation."""
    nonce = task["nonce"]

    # Mock attestation
    attestation_quote = None
    verdict_signature = None

    if mock:
        # Simulate MRENCLAVE and attestation quote
        mrenclave = hashlib.sha256(b"tee-judge-enclave-v0.1").hexdigest()
        quote_data = json.dumps(
            {
                "mrenclave": mrenclave,
                "mrsigner": hashlib.sha256(b"tee-judge-signer").hexdigest(),
                "nonce": nonce,
                "timestamp": time.time(),
            }
        )
        attestation_quote = quote_data

        # Sign the verdict
        sign_payload = f"{task['submission_id']}:{task['problem_id']}:{verdict}:{test_passed}:{test_total}:{nonce}"
        verdict_signature = hmac.new(
            MOCK_ENCLAVE_KEY, sign_payload.encode(), hashlib.sha256
        ).hexdigest()

    return {
        "submission_id": task["submission_id"],
        "verdict": verdict,
        "time_ms": time_ms,
        "memory_kb": memory_kb,
        "test_passed": test_passed,
        "test_total": test_total,
        "attestation_quote": attestation_quote,
        "verdict_signature": verdict_signature,
        "nonce": nonce,
    }


if __name__ == "__main__":
    main()
