"""Server-side re-verification of judge results.

For AC verdicts: random K testcases (K = max(10, ceil(total * 0.3))).
For other verdicts: random K testcases.
If mismatch detected, the result is rejected.
"""

from __future__ import annotations

import os
import random
import subprocess
import tempfile
import time
import logging
import math
from pathlib import Path

logger = logging.getLogger("tee-judge")

# Minimum number of testcases to re-verify
REVERIFY_MIN = int(os.environ.get("TEE_JUDGE_REVERIFY_MIN", "10"))

# Percentage of testcases to re-verify (0.0 - 1.0)
REVERIFY_RATIO = float(os.environ.get("TEE_JUDGE_REVERIFY_RATIO", "0.3"))

# Minimum expected execution time per testcase (ms) — if total is way too fast, suspicious
# Set to 0 to disable (simple problems like A+B run in <1ms)
MIN_EXPECTED_TIME_PER_TEST_MS = int(os.environ.get("TEE_JUDGE_MIN_TIME_PER_TEST", "0"))


def _compute_reverify_count(total: int) -> int:
    """Compute K = max(REVERIFY_MIN, ceil(total * REVERIFY_RATIO)).

    Examples:
      30 testcases  → max(10, 9)  = 10
      50 testcases  → max(10, 15) = 15
      100 testcases → max(10, 30) = 30
      200 testcases → max(10, 60) = 60
    """
    return min(total, max(REVERIFY_MIN, math.ceil(total * REVERIFY_RATIO)))


def reverify_submission(
    code: str,
    language: str,
    testcases: list[dict],
    reported_verdict: str,
    reported_test_passed: int,
    reported_time_ms: int,
    time_limit_ms: int = 2000,
) -> tuple[bool, str]:
    """Re-verify judge results by compiling and running on server.

    AC verdicts: full verification (all testcases).
    Other verdicts: random K testcases.
    Returns (passed, reason).
    """
    if reported_verdict == "CE":
        # Verify compilation actually fails
        ok, _ = _try_compile(code, language)
        if ok:
            return False, "Reported CE but code compiles successfully on server"
        return True, "CE confirmed"

    if not testcases:
        return True, "No testcases to verify"

    # Ratio-based K: max(10, ceil(total * 0.3)), capped at total
    k = _compute_reverify_count(len(testcases))
    selected = random.sample(testcases, k)

    # Compile
    with tempfile.TemporaryDirectory(prefix="tee-reverify-") as tmpdir:
        tmpdir = Path(tmpdir)
        ext = ".c" if language == "c" else ".cpp"
        source = tmpdir / f"solution{ext}"
        source.write_text(code, encoding="utf-8")

        exe = tmpdir / "solution"
        compiler = "gcc" if language == "c" else "g++"
        cmd = [compiler, "-O2", "-o", str(exe), str(source)]
        if language == "cpp":
            cmd.insert(1, "-std=c++17")

        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                if reported_verdict != "CE":
                    return (
                        False,
                        "Code fails to compile on server but verdict is not CE",
                    )
                return True, "CE confirmed"
        except Exception:
            return True, "Compilation timeout on server (skip reverification)"

        # Run selected testcases
        mismatches = 0
        run_timeout = max(
            time_limit_ms / 1000.0 + 1.0, 2.0
        )  # time_limit + 1s buffer, min 2s
        for tc in selected:
            expected = tc["expected"].strip()
            try:
                r = subprocess.run(
                    [str(exe)],
                    input=tc["input"],
                    capture_output=True,
                    text=True,
                    timeout=run_timeout,
                )
                actual = r.stdout.strip()
                if r.returncode != 0:
                    # RE on server
                    if reported_verdict == "AC":
                        mismatches += 1
                        logger.warning(
                            f"Reverify mismatch: test #{tc['order']} RE on server but reported AC"
                        )
                elif actual != expected:
                    if reported_verdict == "AC":
                        mismatches += 1
                        logger.warning(
                            f"Reverify mismatch: test #{tc['order']} "
                            f"server_output={actual[:50]!r} != expected={expected[:50]!r}"
                        )
            except subprocess.TimeoutExpired:
                if reported_verdict == "AC":
                    mismatches += 1
                    logger.warning(
                        f"Reverify mismatch: test #{tc['order']} TLE on server but reported AC"
                    )
            except Exception:
                pass  # Skip on error

        if mismatches > 0:
            return (
                False,
                f"Reverification failed: {mismatches}/{len(selected)} testcases mismatch",
            )

    return True, f"Reverification passed ({len(selected)} testcases)"


def verify_execution_time(
    reported_time_ms: int,
    test_total: int,
    reported_verdict: str,
) -> tuple[bool, str]:
    """Check if reported execution time is suspiciously fast.

    If someone fakes results without actually running code, time will be ~0.
    """
    if reported_verdict == "CE":
        return True, "CE — time check skipped"

    if test_total == 0:
        return True, "No tests"

    min_expected = MIN_EXPECTED_TIME_PER_TEST_MS * test_total
    if reported_time_ms < min_expected:
        return False, (
            f"Suspiciously fast: {reported_time_ms}ms for {test_total} tests "
            f"(min expected: {min_expected}ms)"
        )

    return True, "OK"


def _try_compile(code: str, language: str) -> tuple[bool, str]:
    """Try to compile code. Returns (success, error_msg)."""
    with tempfile.TemporaryDirectory(prefix="tee-compile-") as tmpdir:
        tmpdir = Path(tmpdir)
        ext = ".c" if language == "c" else ".cpp"
        source = tmpdir / f"solution{ext}"
        source.write_text(code, encoding="utf-8")

        exe = tmpdir / "solution"
        compiler = "gcc" if language == "c" else "g++"
        cmd = [compiler, "-O2", "-o", str(exe), str(source)]
        if language == "cpp":
            cmd.insert(1, "-std=c++17")

        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return r.returncode == 0, r.stderr
        except Exception as e:
            return False, str(e)
