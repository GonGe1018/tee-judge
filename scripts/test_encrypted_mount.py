"""Test: can Gramine encrypted mount create new files?"""

import paramiko
import json

HOST = "172.192.154.85"
USER = "judgeclient"
PASS = "judgeclient1234!!"

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=USER, password=PASS, timeout=10)

# Test writing to encrypted mount
stdin, stdout, stderr = c.exec_command(
    "cd ~/tee-judge && timeout 15 gramine-sgx python3 -c \"open('/home/judgeclient/tee-judge/.sealed/test.txt','w').write('hello')\" 2>&1",
    timeout=20,
)
# Wait - but argv is hardcoded, so -c won't work
# Need to use the entry script approach
out = stdout.read().decode()
err = stderr.read().decode()
print("stdout:", out[:500])
print("stderr:", err[:500])

# Alternative: test with allowed_files /tmp/
stdin2, stdout2, stderr2 = c.exec_command(
    "cd ~/tee-judge && echo 'test' | timeout 15 gramine-sgx python3 2>&1 | tail -5",
    timeout=20,
)
print("\n/tmp test:", stdout2.read().decode())

c.close()
