"""Enclave entry point — runs inside SGX via Gramine.

v4: Full enclave execution with libtcc.
- Reads task (code + inputs + nonce) from stdin
- Compiles C code inside enclave using libtcc (no subprocess)
- Runs against all testcases inside enclave
- Signs outputs hash with ECDSA + attestation quote
- Host never sees testcase inputs or outputs

Fallback (v3): If private_key_pem + host_results provided, uses hash+sign only.
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

if "host_results" in data:
    # v3 fallback: host already ran the code, enclave just signs
    from client.enclave_judge import enclave_hash_and_sign

    r = enclave_hash_and_sign(data["task"], data["host_results"])
else:
    # v4: full enclave execution (compile + run + sign)
    from client.enclave_judge import enclave_compile_run_and_sign

    r = enclave_compile_run_and_sign(data["task"])

print("ENCLAVE_RESULT:" + json.dumps(r))
