"""Direct test: can subprocess.run execute a binary inside Gramine SGX?"""

import paramiko
import json

HOST = "172.192.154.85"
USER = "judgeclient"
PASS = "judgeclient1234!!"

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=USER, password=PASS, timeout=10)

# Save original entry, replace with subprocess test
sftp = c.open_sftp()

# Backup
try:
    sftp.rename(
        "/home/judgeclient/tee-judge/client/enclave_entry.py",
        "/home/judgeclient/tee-judge/client/enclave_entry.py.bak",
    )
except:
    pass

# Write test entry
sftp.file("/home/judgeclient/tee-judge/client/enclave_entry.py", "w").write(
    "import subprocess, json, sys\n"
    "sys.stdin.read()  # consume stdin\n"
    "try:\n"
    '    r = subprocess.run(["/tmp/hello_static"], capture_output=True, text=True, timeout=5)\n'
    '    print("EXEC_OK: stdout=" + repr(r.stdout) + " rc=" + str(r.returncode))\n'
    "except Exception as e:\n"
    '    print("EXEC_FAIL: " + str(e))\n'
)
sftp.close()

# Rebuild manifest
stdin, stdout, stderr = c.exec_command(
    "cd ~/tee-judge && gramine-manifest -Darch_libdir=/lib/x86_64-linux-gnu -Dentrypoint=/usr/local/bin/python3.11 python3.manifest.template python3.manifest && gramine-sgx-sign --manifest python3.manifest --output python3.manifest.sgx 2>&1 | tail -2",
    timeout=120,
)
print("Rebuild:", stdout.read().decode())

# Run test
stdin, stdout, stderr = c.exec_command(
    "cd ~/tee-judge && echo 'x' | timeout 20 gramine-sgx python3 2>&1",
    timeout=30,
)
out = stdout.read().decode()
print("=== Result ===")
for line in out.split("\n"):
    if "EXEC_" in line:
        print(line)
    elif "Error" in line or "error" in line:
        print(line)

# Restore original entry
sftp2 = c.open_sftp()
try:
    sftp2.rename(
        "/home/judgeclient/tee-judge/client/enclave_entry.py.bak",
        "/home/judgeclient/tee-judge/client/enclave_entry.py",
    )
except:
    pass
sftp2.close()

# Rebuild with original
stdin, stdout, stderr = c.exec_command(
    "cd ~/tee-judge && gramine-manifest -Darch_libdir=/lib/x86_64-linux-gnu -Dentrypoint=/usr/local/bin/python3.11 python3.manifest.template python3.manifest && gramine-sgx-sign --manifest python3.manifest --output python3.manifest.sgx 2>&1 | tail -2",
    timeout=120,
)
print("Restored:", stdout.read().decode())

c.close()
