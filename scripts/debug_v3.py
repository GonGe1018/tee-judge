"""Debug script for v3 architecture flow."""

import os
import json
import time
import threading
import requests
import uvicorn

os.environ["TEE_JUDGE_ENV"] = "dev"
os.environ["TEE_JUDGE_ALLOW_MOCK"] = "1"


def run_server():
    uvicorn.run("app.main:app", host="127.0.0.1", port=18081, log_level="warning")


t = threading.Thread(target=run_server, daemon=True)
t.start()
time.sleep(3)

BASE = "http://127.0.0.1:18081"
from client.enclave_judge import host_compile_and_run, enclave_hash_and_sign
from client.enclave_keys import load_or_create_keypair

# Register
r = requests.post(
    f"{BASE}/api/auth/register", json={"username": "dbg", "password": "testPass1234"}
)
token = r.json()["token"]
hdr = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

# Judge token
r = requests.post(
    f"{BASE}/api/auth/judge-token",
    json={"judge_key": "dev-only-judge-key"},
    headers=hdr,
)
jtoken = r.json()["token"]
jhdr = {"Authorization": f"Bearer {jtoken}", "Content-Type": "application/json"}

# Register key
pk, pub = load_or_create_keypair()
requests.post(
    f"{BASE}/api/auth/register-enclave-key", json={"public_key": pub}, headers=jhdr
)

# Submit AC code - use real multiline
code = """
#include <stdio.h>
int main() { int a,b; scanf("%d %d",&a,&b); printf("%d",a+b); return 0; }
"""
r = requests.post(
    f"{BASE}/api/submit",
    json={"problem_id": 1000, "language": "c", "code": code},
    headers=hdr,
)
print("Submit:", r.json())

# Poll
r = requests.get(f"{BASE}/api/judge/poll", headers=jhdr)
task = r.json()["task"]
print("Task keys:", list(task.keys()))
print("TC count:", len(task["testcases"]))
print("TC[0] keys:", list(task["testcases"][0].keys()))

# Phase 1
hr = host_compile_and_run(task)
print("Phase1 status:", hr["status"])
print("Phase1 num_outputs:", len(hr["outputs"]))
if hr["outputs"]:
    print("Phase1 out[0]:", hr["outputs"][0])
else:
    print("Phase1: NO OUTPUTS - checking code...")
    print("Code first 100 chars:", repr(task["code"][:100]))

# Phase 2
result = enclave_hash_and_sign(task, hr)
print("Phase2 hash:", result["outputs_hash"][:32])
print("Phase2 num_outputs:", len(result["actual_outputs"]))
if result["actual_outputs"]:
    print("Phase2 out[0]:", result["actual_outputs"][0])

# Report
resp = requests.post(f"{BASE}/api/judge/report", json=result, headers=jhdr)
print("Report status:", resp.status_code)
print("Report body:", resp.json())
