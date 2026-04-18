"""Enclave entry point — runs inside SGX via Gramine.

v4 (RA-TLS): Full enclave execution with RA-TLS keys.
- Generates RA-TLS key pair on first run (key stays in enclave memory)
- Decrypts testcase inputs using RA-TLS private key (ECDH+AES-GCM)
- Compiles C code via libtcc inside enclave
- Signs outputs hash with RA-TLS private key + attestation quote

Fallback (v3): If private_key_pem + host_results provided, uses ECDSA key.
"""

import sys
import os
import json

sys.path.insert(0, os.environ.get("PYTHONPATH", "/home/judgeclient/tee-judge"))
os.chdir(os.environ.get("PYTHONPATH", "/home/judgeclient/tee-judge"))

data = json.loads(sys.stdin.read())

# If private key is provided via stdin (v3 fallback), inject it
if "private_key_pem" in data:
    os.environ["_TEE_JUDGE_PRIVATE_KEY_PEM"] = data["private_key_pem"]

if "host_results" in data:
    # v3 fallback: host already ran the code, enclave just signs
    from client.enclave_judge import enclave_hash_and_sign

    r = enclave_hash_and_sign(data["task"], data["host_results"])
elif "task" in data:
    # v4: full enclave execution (compile + run + sign with RA-TLS key)
    from client.enclave_judge import enclave_compile_run_and_sign

    r = enclave_compile_run_and_sign(data["task"])
    print("ENCLAVE_RESULT:" + json.dumps(r))
    sys.exit(0)
else:
    # Key registration mode: return RA-TLS public key
    from client.ratls_keys import get_ratls_public_key_pem

    print("RATLS_PUBKEY:" + get_ratls_public_key_pem())
    sys.exit(0)

print("ENCLAVE_RESULT:" + json.dumps(r))
