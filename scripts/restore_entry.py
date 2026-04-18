"""Restore enclave_entry.py and rebuild (no print issues)."""

import paramiko

HOST = "172.192.154.85"
USER = "judgeclient"
PASS = "judgeclient1234!!"

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=USER, password=PASS, timeout=10)

for cmd in [
    "cd ~/tee-judge && git checkout -- client/enclave_entry.py",
    "cd ~/tee-judge && gramine-manifest -Darch_libdir=/lib/x86_64-linux-gnu -Dentrypoint=/usr/local/bin/python3.11 python3.manifest.template python3.manifest && gramine-sgx-sign --manifest python3.manifest --output python3.manifest.sgx",
]:
    stdin, stdout, stderr = c.exec_command(cmd, timeout=120)
    stdout.read()
    stderr.read()

stdin, stdout, stderr = c.exec_command("head -1 ~/tee-judge/client/enclave_entry.py")
print("entry:", stdout.read().decode(errors="replace").strip())
c.close()
print("Done")
