"""Test: what subprocess operations work in Gramine SGX?"""

import paramiko

HOST = "172.192.154.85"
USER = "judgeclient"
PASS = "judgeclient1234!!"

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=USER, password=PASS, timeout=10)

sftp = c.open_sftp()

# Backup
try:
    sftp.rename(
        "/home/judgeclient/tee-judge/client/enclave_entry.py",
        "/home/judgeclient/tee-judge/client/enclave_entry.py.bak",
    )
except:
    pass

# Test various exec methods
sftp.file("/home/judgeclient/tee-judge/client/enclave_entry.py", "w").write(
    "import sys, os\n"
    "sys.stdin.read()\n"
    "\n"
    "# Test 1: os.path.exists\n"
    'print("exists /tmp/hello_static:", os.path.exists("/tmp/hello_static"))\n'
    'print("exists /bin/echo:", os.path.exists("/bin/echo"))\n'
    'print("exists /usr/bin/gcc:", os.path.exists("/usr/bin/gcc"))\n'
    "\n"
    "# Test 2: os.listdir /tmp\n"
    "try:\n"
    '    print("/tmp contents:", os.listdir("/tmp")[:10])\n'
    "except Exception as e:\n"
    '    print("/tmp listdir fail:", e)\n'
    "\n"
    "# Test 3: subprocess with /bin/echo\n"
    "import subprocess\n"
    "try:\n"
    '    r = subprocess.run(["/bin/echo", "hello"], capture_output=True, text=True, timeout=5)\n'
    '    print("echo result:", repr(r.stdout), "rc:", r.returncode)\n'
    "except Exception as e:\n"
    '    print("echo fail:", e)\n'
    "\n"
    "# Test 4: subprocess with /bin/ls\n"
    "try:\n"
    '    r = subprocess.run(["/bin/ls", "/tmp/"], capture_output=True, text=True, timeout=5)\n'
    '    print("ls /tmp:", repr(r.stdout[:200]), "rc:", r.returncode)\n'
    "except Exception as e:\n"
    '    print("ls fail:", e)\n'
)
sftp.close()

# Rebuild
stdin, stdout, stderr = c.exec_command(
    "cd ~/tee-judge && gramine-manifest -Darch_libdir=/lib/x86_64-linux-gnu -Dentrypoint=/usr/local/bin/python3.11 python3.manifest.template python3.manifest && gramine-sgx-sign --manifest python3.manifest --output python3.manifest.sgx 2>&1 | tail -2",
    timeout=120,
)
print("Rebuild:", stdout.read().decode())

# Run
stdin, stdout, stderr = c.exec_command(
    "cd ~/tee-judge && echo 'x' | timeout 20 gramine-sgx python3 2>&1",
    timeout=30,
)
out = stdout.read().decode()
print("=== Result ===")
for line in out.split("\n"):
    if any(x in line for x in ["exists", "contents", "result", "fail", "echo", "ls"]):
        print(line)

# Restore
sftp2 = c.open_sftp()
try:
    sftp2.rename(
        "/home/judgeclient/tee-judge/client/enclave_entry.py.bak",
        "/home/judgeclient/tee-judge/client/enclave_entry.py",
    )
except:
    pass
sftp2.close()

stdin, stdout, stderr = c.exec_command(
    "cd ~/tee-judge && gramine-manifest -Darch_libdir=/lib/x86_64-linux-gnu -Dentrypoint=/usr/local/bin/python3.11 python3.manifest.template python3.manifest && gramine-sgx-sign --manifest python3.manifest --output python3.manifest.sgx 2>&1 | tail -2",
    timeout=120,
)
print("Restored:", stdout.read().decode())

c.close()
