"""Enclave entry point — runs inside SGX via Gramine.

Reads task + host_results + private_key_pem from stdin.
Signs verdict with the provided key (same key daemon registered with server).
No file-based key loading — key comes via stdin to avoid Gramine file issues.
"""

import sys
import os
import json

sys.path.insert(0, os.environ.get("PYTHONPATH", "/home/judgeclient/tee-judge"))
os.chdir(os.environ.get("PYTHONPATH", "/home/judgeclient/tee-judge"))

data = json.loads(sys.stdin.read())

# If private key is provided via stdin, inject it so enclave_judge uses it
if "private_key_pem" in data:
    os.environ["_TEE_JUDGE_PRIVATE_KEY_PEM"] = data["private_key_pem"]

from client.enclave_judge import enclave_verify_and_sign

r = enclave_verify_and_sign(data["task"], data["host_results"])
print("ENCLAVE_RESULT:" + json.dumps(r))
