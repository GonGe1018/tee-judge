"""Test: can Gramine enclave execute a binary via subprocess?"""

import paramiko
import json

HOST = "172.192.154.85"
USER = "judgeclient"
PASS = "judgeclient1234!!"

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=USER, password=PASS, timeout=10)

# Create and compile a static binary
sftp = c.open_sftp()
sftp.file("/tmp/hello.c", "w").write(
    '#include <stdio.h>\nint main(){printf("hello from binary\\n");return 0;}\n'
)
sftp.close()

stdin, stdout, stderr = c.exec_command(
    "gcc -static -o /tmp/hello_static /tmp/hello.c && echo 'Compiled OK'", timeout=30
)
print(stdout.read().decode())

# Create a test script that runs the binary inside enclave
sftp = c.open_sftp()
sftp.file("/tmp/test_exec_in_enclave.py", "w").write(
    "import subprocess, sys\n"
    'r = subprocess.run(["/tmp/hello_static"], capture_output=True, text=True, timeout=5)\n'
    'print(f"stdout: {r.stdout}")\n'
    'print(f"returncode: {r.returncode}")\n'
)
sftp.close()

# Run inside Gramine SGX enclave
# Note: manifest argv is hardcoded, so we need to use enclave_entry.py approach
# But for this test, let's check if the manifest allows it
stdin, stdout, stderr = c.exec_command(
    "cd ~/tee-judge && echo '{}' | timeout 20 gramine-sgx python3 2>&1",
    timeout=30,
)
out = stdout.read().decode()
err = stderr.read().decode()
print("=== Enclave test ===")
print(out[-500:] if len(out) > 500 else out)

# Also test: can subprocess work at all in Gramine?
sftp = c.open_sftp()
sftp.file("/home/judgeclient/tee-judge/client/test_subprocess.py", "w").write(
    "import subprocess, json, sys\n"
    "data = json.loads(sys.stdin.read())\n"
    "try:\n"
    '    r = subprocess.run(["/tmp/hello_static"], capture_output=True, text=True, timeout=5)\n'
    '    print("ENCLAVE_RESULT:" + json.dumps({"stdout": r.stdout, "rc": r.returncode}))\n'
    "except Exception as e:\n"
    '    print("ENCLAVE_RESULT:" + json.dumps({"error": str(e)}))\n'
)
sftp.close()

# Rebuild manifest to include test script
stdin, stdout, stderr = c.exec_command(
    "cd ~/tee-judge && gramine-manifest -Darch_libdir=/lib/x86_64-linux-gnu -Dentrypoint=/usr/local/bin/python3.11 python3.manifest.template python3.manifest && gramine-sgx-sign --manifest python3.manifest --output python3.manifest.sgx 2>&1 | tail -2",
    timeout=120,
)
print("=== Rebuild ===")
print(stdout.read().decode())

# Now test with the subprocess script via enclave_entry
# We need to modify enclave_entry temporarily... or just test directly
stdin, stdout, stderr = c.exec_command(
    'cd ~/tee-judge && echo \'{"task":{},"host_results":{}}\' | timeout 20 gramine-sgx python3 2>&1',
    timeout=30,
)
out = stdout.read().decode()
print("=== Subprocess in enclave ===")
print(out[-500:] if len(out) > 500 else out)

c.close()
