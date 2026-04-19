"""End-to-end test: submit code for all problems, judge, check results.

v4 architecture: enclave compiles+runs via libtcc, server determines verdict.
Falls back to v3 (host compile + enclave sign) if libtcc unavailable.
"""

import os
import time
import threading
import requests
import uvicorn

# Set env vars BEFORE importing app modules (pydantic-settings reads at import time)
os.environ.setdefault("TEE_JUDGE_ENV", "dev")
os.environ.setdefault("TEE_JUDGE_ALLOW_MOCK", "1")

# Import settings after env vars are set
from app.core.config import settings


# Start server in background thread
def run_server():
    uvicorn.run("app.main:app", host="127.0.0.1", port=18080, log_level="warning")


server_thread = threading.Thread(target=run_server, daemon=True)
server_thread.start()
time.sleep(2)

BASE = "http://127.0.0.1:18080"

# Detect execution mode
import platform

SGX_AVAILABLE = os.path.exists("/dev/sgx_enclave")
USE_SGX_BRIDGE = False
USE_LIBTCC = False
sgx_bridge = None

if SGX_AVAILABLE:
    try:
        from client.daemon import EnclaveBridge

        sgx_bridge = EnclaveBridge()
        USE_SGX_BRIDGE = True
        print("[0] SGX available — using long-running enclave (RA-TLS mode)")
    except Exception as e:
        print(f"[0] SGX bridge failed ({e}), falling back to libtcc")

if not USE_SGX_BRIDGE:
    try:
        from client.tcc_runner import compile_and_run_all
        from client.enclave_judge import enclave_compile_run_and_sign

        USE_LIBTCC = True
        print("[0] libtcc available — using v4 native (no SGX)")
    except (ImportError, OSError):
        from client.enclave_judge import host_compile_and_run, enclave_hash_and_sign

        print(
            "[0] libtcc unavailable — using v3 fallback (host compile + enclave sign)"
        )

# Register a test user and get token
res = requests.post(
    f"{BASE}/api/auth/register",
    json={"username": "testuser", "password": "testPass1234"},
)
if res.status_code == 409:
    res = requests.post(
        f"{BASE}/api/auth/login",
        json={"username": "testuser", "password": "testPass1234"},
    )
assert res.status_code == 200, f"Auth failed: {res.text}"
USER_TOKEN = res.json()["token"]
AUTH_HEADERS = {
    "Authorization": f"Bearer {USER_TOKEN}",
    "Content-Type": "application/json",
}

# Get judge token (requires judge_key)
import os

# Use actual judge key from settings (reads .env + env vars)
_judge_key = settings.TEE_JUDGE_JUDGE_KEY or "dev-only-judge-key"

res = requests.post(
    f"{BASE}/api/auth/judge-token",
    json={"judge_key": _judge_key},
    headers=AUTH_HEADERS,
)
assert res.status_code == 200, f"Judge token failed: {res.text}"
JUDGE_TOKEN = res.json()["token"]
JUDGE_HEADERS = {
    "Authorization": f"Bearer {JUDGE_TOKEN}",
    "Content-Type": "application/json",
}
print(f"[0] Authenticated as testuser (user + judge tokens)")

# Register enclave public key (judge token required, one-time)
if USE_SGX_BRIDGE:
    # SGX mode: use RA-TLS public key + certificate from long-running enclave
    _public_key_pem = sgx_bridge.public_key_pem
    _ratls_cert = sgx_bridge.ratls_cert_der_b64
else:
    # Non-SGX mode: use ECDSA key
    from client.enclave_keys import load_or_create_keypair

    _private_key, _public_key_pem = load_or_create_keypair()
    _ratls_cert = None

_reg_payload = {"public_key": _public_key_pem}
if _ratls_cert:
    _reg_payload["ratls_cert_der_b64"] = _ratls_cert

res = requests.post(
    f"{BASE}/api/auth/register-enclave-key",
    json=_reg_payload,
    headers=JUDGE_HEADERS,
)
assert res.status_code in (200, 409), f"Key registration failed: {res.text}"
print(
    f"[0] Enclave public key registered ({'RA-TLS+MAA' if _ratls_cert else 'ECDSA/dev'})"
)


def submit_and_judge(problem_id, code, expected_verdict):
    """Submit code, 2-phase judge it, verify verdict."""
    res = requests.post(
        f"{BASE}/api/submit",
        json={
            "problem_id": problem_id,
            "language": "c",
            "code": code,
        },
        headers=AUTH_HEADERS,
    )
    assert res.status_code == 200, f"Submit failed: {res.status_code} {res.text}"
    sub = res.json()

    res = requests.get(f"{BASE}/api/judge/poll", headers=JUDGE_HEADERS)
    task = res.json()["task"]
    assert task is not None

    # Phase: compile + run + sign
    if USE_SGX_BRIDGE:
        # v4 SGX: use long-running enclave via EnclaveBridge
        result = sgx_bridge.submit_task(task, timeout=120)
    elif USE_LIBTCC:
        # v4 native: full enclave execution (non-SGX)
        result = enclave_compile_run_and_sign(task)
    else:
        # v3 fallback: host compile + enclave sign
        hr = host_compile_and_run(task)
        result = enclave_hash_and_sign(task, hr)

    # Report to server — server determines verdict
    resp = requests.post(f"{BASE}/api/judge/report", json=result, headers=JUDGE_HEADERS)
    assert resp.status_code == 200, f"Report failed: {resp.status_code} {resp.text}"
    server_result = resp.json()

    # Also check via result API
    res = requests.get(
        f"{BASE}/api/result/{sub['submission_id']}", headers=AUTH_HEADERS
    )
    final = res.json()

    status = "PASS" if final["verdict"] == expected_verdict else "FAIL"
    print(
        f"  [{status}] Problem {problem_id}: {final['verdict']} ({final.get('test_passed', 0)}/{final.get('test_total', 0)}) expected={expected_verdict}"
    )
    assert final["verdict"] == expected_verdict, (
        f"Expected {expected_verdict}, got {final['verdict']}"
    )
    return final


# 1. Check problems
res = requests.get(f"{BASE}/api/problems")
problems = res.json()
print(f"[1] Problems loaded: {len(problems)}")
for p in problems:
    print(f"    #{p['id']}: {p['title']}")

# 2. Problem 1000: A+B
print("\n[2] Problem 1000: A+B")
submit_and_judge(
    1000,
    """
#include <stdio.h>
int main() { int a,b; scanf("%d %d",&a,&b); printf("%d",a+b); return 0; }
""",
    "AC",
)

submit_and_judge(
    1000,
    """
#include <stdio.h>
int main() { int a,b; scanf("%d %d",&a,&b); printf("%d",a-b); return 0; }
""",
    "WA",
)

# 3. Problem 1001: A-B
print("\n[3] Problem 1001: A-B")
submit_and_judge(
    1001,
    """
#include <stdio.h>
int main() { int a,b; scanf("%d %d",&a,&b); printf("%d",a-b); return 0; }
""",
    "AC",
)

submit_and_judge(
    1001,
    """
#include <stdio.h>
int main() { int a,b; scanf("%d %d",&a,&b); printf("%d",a+b); return 0; }
""",
    "WA",
)

# 4. Problem 1002: A*B
print("\n[4] Problem 1002: A*B")
submit_and_judge(
    1002,
    """
#include <stdio.h>
int main() { long long a,b; scanf("%lld %lld",&a,&b); printf("%lld",a*b); return 0; }
""",
    "AC",
)

submit_and_judge(
    1002,
    """
#include <stdio.h>
int main() { int a,b; scanf("%d %d",&a,&b); printf("%d",a+b); return 0; }
""",
    "WA",
)

# 5. Problem 1003: Max of N
print("\n[5] Problem 1003: Max of N")
submit_and_judge(
    1003,
    """
#include <stdio.h>
int main() {
    int n, x, mx; scanf("%d",&n);
    for(int i=0;i<n;i++) { scanf("%d",&x); if(i==0||x>mx) mx=x; }
    printf("%d",mx); return 0;
}
""",
    "AC",
)

submit_and_judge(
    1003,
    """
#include <stdio.h>
int main() {
    int n, x, mn=1000001; scanf("%d",&n);
    for(int i=0;i<n;i++) { scanf("%d",&x); if(x<mn) mn=x; }
    printf("%d",mn); return 0;
}
""",
    "WA",
)

# 6. Problem 1004: Sum of N
print("\n[6] Problem 1004: Sum of N")
submit_and_judge(
    1004,
    """
#include <stdio.h>
int main() {
    int n, x; long long s=0; scanf("%d",&n);
    for(int i=0;i<n;i++) { scanf("%d",&x); s+=x; }
    printf("%lld",s); return 0;
}
""",
    "AC",
)

submit_and_judge(
    1004,
    """
#include <stdio.h>
int main() { printf("0"); return 0; }
""",
    "WA",
)

# 7. Compilation error test
print("\n[7] Compilation Error test")
submit_and_judge(
    1000,
    """
#include <stdio.h>
int main() { this is not valid c code }
""",
    "CE",
)

# 8. TLE test
print("\n[8] TLE test")
submit_and_judge(
    1000,
    """
#include <stdio.h>
int main() { while(1); return 0; }
""",
    "TLE",
)

print("\n=== ALL TESTS PASSED ===")
