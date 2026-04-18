"""TCC in-memory compiler and runner via ctypes.

Compiles and executes C code inside the enclave using libtcc.
No subprocess needed — everything runs in-process.
"""

from __future__ import annotations

import ctypes
import os
import sys
import time

# Path to libtcc.so (must be in trusted_files for SGX)
LIBTCC_PATH = os.environ.get(
    "TEE_JUDGE_LIBTCC_PATH", "/home/judgeclient/tee-judge/client/libtcc.so"
)
TCC_LIB_PATH = os.environ.get("TEE_JUDGE_TCC_LIB_PATH", "/usr/lib/x86_64-linux-gnu/tcc")
TCC_INCLUDE_PATHS = [
    "/usr/lib/x86_64-linux-gnu/tcc/include",  # TCC's own headers (override system)
    "/usr/include",
    "/usr/include/x86_64-linux-gnu",
]

# TCC constants
TCC_OUTPUT_MEMORY = 1

# Max output size per testcase
MAX_OUTPUT_BYTES = 64 * 1024


def _load_libtcc():
    """Load and configure libtcc shared library."""
    lib = ctypes.CDLL(LIBTCC_PATH)

    lib.tcc_new.restype = ctypes.c_void_p
    lib.tcc_delete.argtypes = [ctypes.c_void_p]
    lib.tcc_set_output_type.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.tcc_compile_string.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.tcc_compile_string.restype = ctypes.c_int
    lib.tcc_set_lib_path.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.tcc_add_include_path.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.tcc_relocate.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.tcc_relocate.restype = ctypes.c_int
    lib.tcc_get_symbol.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.tcc_get_symbol.restype = ctypes.c_void_p

    return lib


# Lazy-load libtcc
_libtcc = None
_libc = None


def _get_libtcc():
    global _libtcc
    if _libtcc is None:
        _libtcc = _load_libtcc()
    return _libtcc


def _get_libc():
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL("libc.so.6")
    return _libc


def compile_code(code: str) -> tuple[bool, ctypes.c_void_p, int]:
    """Compile C code in-memory using libtcc.

    Returns (success, tcc_state, func_addr).
    Caller must call tcc_delete(tcc_state) when done.
    """
    lib = _get_libtcc()

    # Rename main to solve to avoid symbol conflicts
    code_bytes = code.encode()
    # Handle various main signatures
    for pattern in [b"int main(", b"int main (", b"void main(", b"void main ("]:
        code_bytes = code_bytes.replace(pattern, b"int solve(", 1)

    s = lib.tcc_new()
    if not s:
        return False, None, 0

    lib.tcc_set_lib_path(s, TCC_LIB_PATH.encode())
    for inc_path in TCC_INCLUDE_PATHS:
        lib.tcc_add_include_path(s, inc_path.encode())
    lib.tcc_set_output_type(s, TCC_OUTPUT_MEMORY)

    ret = lib.tcc_compile_string(s, code_bytes)
    if ret == -1:
        lib.tcc_delete(s)
        return False, None, 0

    TCC_RELOCATE_AUTO = ctypes.cast(1, ctypes.c_void_p)
    ret = lib.tcc_relocate(s, TCC_RELOCATE_AUTO)
    if ret < 0:
        lib.tcc_delete(s)
        return False, None, 0

    addr = lib.tcc_get_symbol(s, b"solve")
    if not addr:
        # Try "main" as fallback (in case rename didn't match)
        addr = lib.tcc_get_symbol(s, b"main")
    if not addr:
        lib.tcc_delete(s)
        return False, None, 0

    return True, s, addr


def run_with_input(func_addr: int, input_data: str, time_limit_ms: int = 2000) -> dict:
    """Run compiled function with given stdin input, capture stdout.

    Returns {"output": str, "time_ms": int, "status": "OK"|"RE"|"TLE"}.
    Uses fork() for isolation + time limit enforcement.
    Child process runs the code, parent waits with timeout.

    Note: SGX fork() has ~1-2s overhead. We add a buffer to avoid false TLE.
    The reported time_ms reflects actual execution time, not fork overhead.
    """
    libc = _get_libc()

    # Add fork overhead buffer for SGX (fork is slow inside enclave)
    # Actual execution time is measured separately
    FORK_OVERHEAD_MS = 2000  # SGX fork overhead buffer
    wall_timeout_ms = time_limit_ms + FORK_OVERHEAD_MS

    input_bytes = input_data.encode()
    if not input_bytes.endswith(b"\n"):
        input_bytes += b"\n"

    # Create pipe for child→parent output communication
    out_read, out_write = os.pipe()

    start = time.perf_counter()
    pid = os.fork()

    if pid == 0:
        # Child process: run the code
        os.close(out_read)
        try:
            # Redirect stdin from input
            stdin_read, stdin_write = os.pipe()
            os.write(stdin_write, input_bytes)
            os.close(stdin_write)

            # Redirect stdout to pipe
            os.dup2(stdin_read, 0)
            os.dup2(out_write, 1)
            os.close(stdin_read)
            os.close(out_write)

            FUNC_TYPE = ctypes.CFUNCTYPE(ctypes.c_int)
            func = FUNC_TYPE(func_addr)
            func()

            libc.fflush(None)
            os._exit(0)
        except Exception:
            os._exit(1)
    else:
        # Parent process: wait with timeout (use wall_timeout for SGX fork overhead)
        os.close(out_write)
        import select

        deadline = time.perf_counter() + (wall_timeout_ms / 1000.0)
        status_code = None

        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                # Timeout — kill child
                import signal

                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
                elapsed_ms = time_limit_ms  # report as time_limit, not wall time
                os.close(out_read)
                return {"output": "", "time_ms": elapsed_ms, "status": "TLE"}

            # Check if child finished
            result = os.waitpid(pid, os.WNOHANG)
            if result[0] != 0:
                status_code = result[1]
                break
            time.sleep(0.01)

        wall_elapsed_ms = int((time.perf_counter() - start) * 1000)
        # Subtract fork overhead to get actual execution time
        elapsed_ms = max(0, wall_elapsed_ms - FORK_OVERHEAD_MS)

        # Read output from pipe
        output = b""
        while True:
            ready, _, _ = select.select([out_read], [], [], 0)
            if ready:
                chunk = os.read(out_read, MAX_OUTPUT_BYTES)
                if not chunk:
                    break
                output += chunk
            else:
                break
        os.close(out_read)

        output_str = output.decode(errors="replace").strip()

        if os.WIFSIGNALED(status_code):
            return {"output": "", "time_ms": elapsed_ms, "status": "RE"}
        elif os.WEXITSTATUS(status_code) != 0:
            return {"output": "", "time_ms": elapsed_ms, "status": "RE"}
        elif elapsed_ms > time_limit_ms:
            return {"output": "", "time_ms": elapsed_ms, "status": "TLE"}
        else:
            return {"output": output_str, "time_ms": elapsed_ms, "status": "OK"}


def compile_and_run_all(
    code: str, testcases: list[dict], time_limit_ms: int = 2000
) -> dict:
    """Compile code and run against all testcases.

    Returns {"status": "OK"|"CE", "outputs": [{"order": int, "output": str, "time_ms": int, "status": str}]}.
    """
    lib = _get_libtcc()

    ok, tcc_state, func_addr = compile_code(code)
    if not ok:
        return {"status": "CE", "outputs": []}

    outputs = []
    for tc in testcases:
        result = run_with_input(func_addr, tc["input"], time_limit_ms)
        outputs.append(
            {
                "order": tc["order"],
                "output": result["output"],
                "time_ms": result["time_ms"],
                "status": result["status"],
            }
        )

    lib.tcc_delete(tcc_state)
    return {"status": "OK", "outputs": outputs}
