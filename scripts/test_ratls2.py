"""Test gramine-ratls with proper manifest."""

import paramiko
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

HOST = "172.192.154.85"
USER = "judgeclient"
PASS = "judgeclient1234!!"


def ssh_run(cmd, timeout=120):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    c.close()
    print(out[-2000:] if len(out) > 2000 else out, end="")
    for line in err.split("\n"):
        if line.strip() and not any(
            x in line
            for x in [
                "Gramine detected",
                "---",
                "Gramine will continue",
                "Parsing",
                "insecure",
                "allowed_files",
                "debug enclave",
            ]
        ):
            print(line)


# gramine-ratls wraps gramine-sgx, so it needs the manifest
# It runs: gramine-sgx <entrypoint> with RA-TLS cert generation before the command
# The manifest must already exist for the entrypoint

# Test: use existing python3 manifest
print("=== Test gramine-ratls with existing manifest ===")
ssh_run(
    "cd ~/tee-judge && gramine-ratls -D /tmp/ratls-cert.pem /tmp/ratls-key.pem python3 -c 'print(\"hello from RA-TLS\")' 2>&1 | tail -15",
    timeout=60,
)

# Check if it's a manifest issue
print("\n=== Check what gramine-ratls does ===")
ssh_run("file $(which gramine-ratls) && cat $(which gramine-ratls) | head -30")

print("\nDone")
