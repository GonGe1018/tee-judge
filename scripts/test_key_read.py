"""Test if enclave can read the key file."""

import paramiko
import json

HOST = "172.192.154.85"
USER = "judgeclient"
PASS = "judgeclient1234!!"

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=USER, password=PASS, timeout=10)

# Test: can enclave read /tmp/.tee-judge-sealed-key.pem?
test_input = json.dumps(
    {
        "task": {
            "testcases": [],
            "nonce": "test",
            "submission_id": 1,
            "problem_id": 1000,
        },
        "host_results": {"status": "CE", "outputs": []},
    }
)

# Simple test script that just tries to read the key
sftp = c.open_sftp()
sftp.file("/tmp/test_read_key.py", "w").write(
    "import os\n"
    "path = '/tmp/.tee-judge-sealed-key.pem'\n"
    "print(f'exists: {os.path.exists(path)}')\n"
    "try:\n"
    "    data = open(path, 'rb').read()\n"
    "    print(f'read OK: {len(data)} bytes')\n"
    "    print(f'starts with: {data[:30]}')\n"
    "except Exception as e:\n"
    "    print(f'read FAIL: {e}')\n"
)
sftp.close()

# Run in enclave - but argv is hardcoded to enclave_entry.py
# So we need to test via the entry script
# Actually, let's just check if the key loads inside enclave_verify_and_sign
stdin, stdout, stderr = c.exec_command(
    f"cd ~/tee-judge && echo '{test_input}' | timeout 20 gramine-sgx python3 2>&1",
    timeout=30,
)
out = stdout.read().decode()
err = stderr.read().decode()
print("=== stdout ===")
print(out[-1500:] if len(out) > 1500 else out)
print("=== stderr (filtered) ===")
for line in err.split("\n"):
    if (
        line.strip()
        and "Gramine" not in line
        and "---" not in line
        and "Parsing" not in line
        and "allowed" not in line
        and "insecure" not in line
    ):
        print(line)

c.close()
