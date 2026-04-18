"""Test Gramine Secret Provisioning on Azure VM."""

import paramiko
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

HOST = "172.192.154.85"
USER = "judgeclient"
PASS = "judgeclient1234!!"


def ssh_run(cmd, timeout=60):
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
            ]
        ):
            print(line)


# Check what gramine-ratls actually does
print("=== gramine-ratls usage ===")
ssh_run("gramine-ratls 2>&1 | head -10")

# Check Gramine attestation docs
print("\n=== Check secret provisioning libs ===")
ssh_run("ls -la /usr/lib/x86_64-linux-gnu/gramine/runtime/glibc/libsecret_prov*")

# Check if there's a secret provisioning helper
print("\n=== Check gramine tools ===")
ssh_run(
    "which gramine-sgx gramine-direct gramine-ratls gramine-sgx-sign gramine-manifest"
)

# gramine-ratls generates cert INSIDE gramine-sgx
# It wraps gramine-sgx and generates RA-TLS cert before running the command
print("\n=== Test gramine-ratls inside SGX ===")
ssh_run(
    'cd ~/tee-judge && gramine-ratls -D /tmp/ratls-cert.pem /tmp/ratls-key.pem -- python3 -c \'import os; print("inside SGX with RA-TLS cert"); print(os.path.exists("/tmp/ratls-cert.pem"))\' 2>&1 | tail -10',
    timeout=30,
)

# Check if cert was generated
print("\n=== Check cert ===")
ssh_run("ls -la /tmp/ratls-cert.pem /tmp/ratls-key.pem 2>&1")

print("\nDone")
