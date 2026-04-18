"""Test enclave with encrypted sealed storage."""

import paramiko
import json

HOST = "172.192.154.85"
USER = "judgeclient"
PASS = "judgeclient1234!!"

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=USER, password=PASS, timeout=10)

# Clean sealed key
c.exec_command("rm -f ~/tee-judge/.sealed/enclave_key.pem")

# Create test input
test_input = json.dumps(
    {
        "task": {
            "testcases": [],
            "nonce": "test123",
            "submission_id": 1,
            "problem_id": 1000,
        },
        "host_results": {
            "status": "CE",
            "outputs": [],
        },
    }
)

stdin, stdout, stderr = c.exec_command(
    "cd ~/tee-judge && timeout 30 gramine-sgx python3",
    timeout=40,
)
stdin.write(test_input)
stdin.channel.shutdown_write()

out = stdout.read().decode()
err = stderr.read().decode()
c.close()

print("=== stdout ===")
print(out[-2000:] if len(out) > 2000 else out)
print("=== stderr (filtered) ===")
for line in err.split("\n"):
    if (
        line.strip()
        and "insecure" not in line.lower()
        and "Gramine detected" not in line
        and "---" not in line
        and "Gramine will continue" not in line
        and "Parsing" not in line
    ):
        print(line)
