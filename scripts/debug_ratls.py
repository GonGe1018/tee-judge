"""Debug gramine-ratls error -10496."""

import paramiko
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

HOST = "172.192.154.85"
USER = "judgeclient"
PASS = "judgeclient1234!!"

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=USER, password=PASS, timeout=10)

# Check current manifest for remote_attestation
stdin, stdout, stderr = c.exec_command(
    "grep -i 'remote_attestation\\|attestation\\|debug' ~/tee-judge/python3.manifest"
)
print("=== Manifest attestation settings ===")
print(stdout.read().decode("utf-8", errors="replace"))

# Check if AESM is running
stdin, stdout, stderr = c.exec_command(
    "echo 'judgeclient1234!!' | sudo -S systemctl status aesmd 2>&1 | head -5"
)
print("=== AESM status ===")
print(stdout.read().decode("utf-8", errors="replace"))

# Check SGX devices
stdin, stdout, stderr = c.exec_command("ls -la /dev/sgx*")
print("=== SGX devices ===")
print(stdout.read().decode("utf-8", errors="replace"))

# Try gramine-sgx directly (not gramine-ratls) to see if basic SGX works
stdin, stdout, stderr = c.exec_command(
    "cd ~/tee-judge && echo '{}' | timeout 15 gramine-sgx python3 2>&1 | tail -5"
)
print("=== gramine-sgx basic test ===")
print(stdout.read().decode("utf-8", errors="replace"))

# Check if the error is about DCAP specifically
# -10496 in hex is -0x2900 which might be SGX_ERROR_UNEXPECTED
stdin, stdout, stderr = c.exec_command("python3.11 -c 'print(hex(-10496))'")
print("=== Error code ===")
print(stdout.read().decode("utf-8", errors="replace"))

c.close()
print("Done")
