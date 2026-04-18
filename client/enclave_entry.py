"""Enclave entry point — runs inside SGX via Gramine.

This script is specified in the Gramine manifest argv and is a trusted_file.
It reads task + host_results from stdin, runs verification, outputs result to stdout.
"""

import sys
import os
import json

sys.path.insert(0, os.environ.get("PYTHONPATH", "/home/judgeclient/tee-judge"))
os.chdir(os.environ.get("PYTHONPATH", "/home/judgeclient/tee-judge"))

from client.enclave_judge import enclave_verify_and_sign

data = json.loads(sys.stdin.read())
r = enclave_verify_and_sign(data["task"], data["host_results"])
print("ENCLAVE_RESULT:" + json.dumps(r))
