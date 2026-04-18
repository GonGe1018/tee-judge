"""Test gramine-ratls: generate cert then run enclave."""

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
                "debug enclave",
                "cmdline_argv",
            ]
        ):
            print(line)


# gramine-ratls -D CERTPATH KEYPATH COMMAND
# COMMAND = the gramine-sgx entrypoint (python3 in our case)
# It generates cert BEFORE running the command inside SGX

# First, we need a manifest that allows RA-TLS
# Our current manifest has remote_attestation = "dcap" which is needed

# Test 1: gramine-ratls without extra args (just generate cert + run manifest's argv)
print("=== Test 1: gramine-ratls with manifest entrypoint ===")
ssh_run(
    "cd ~/tee-judge && echo '{}' | gramine-ratls -D /tmp/ratls-cert.pem /tmp/ratls-key.pem python3 2>&1 | tail -10",
    timeout=30,
)

# Check cert
print("\n=== Check cert ===")
ssh_run("ls -la /tmp/ratls-cert.pem /tmp/ratls-key.pem 2>&1")

# Test 2: Maybe gramine-ratls needs insecure__use_cmdline_argv?
# Let's check the Gramine docs for gramine-ratls behavior
print("\n=== Test 2: gramine-ratls help ===")
ssh_run("gramine-ratls 2>&1")

print("\nDone")
