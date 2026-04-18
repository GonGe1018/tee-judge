import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

script = '''
import sys, subprocess, tempfile, resource, platform
from pathlib import Path

code = """
#include <stdio.h>
int main() { int a,b; scanf("%d %d",&a,&b); printf("%d",a+b); return 0; }
"""

def sandbox():
    resource.setrlimit(resource.RLIMIT_AS, (512*1024*1024, 512*1024*1024))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 90))
    resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))
    resource.setrlimit(resource.RLIMIT_FSIZE, (10*1024*1024, 10*1024*1024))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

with tempfile.TemporaryDirectory(prefix="tee-sandbox-") as tmpdir:
    tmpdir = Path(tmpdir)
    source = tmpdir / "solution.c"
    source.write_text(code, encoding="utf-8")
    exe = tmpdir / "solution"
    
    # Without sandbox
    r1 = subprocess.run(["gcc", "-O2", "-o", str(exe), str(source)], capture_output=True, text=True, timeout=30)
    print("Without sandbox: returncode=", r1.returncode, "stderr=", r1.stderr[:200])
    
    # With sandbox
    try:
        r2 = subprocess.run(["gcc", "-O2", "-o", str(exe), str(source)], capture_output=True, text=True, timeout=30, preexec_fn=sandbox)
        print("With sandbox: returncode=", r2.returncode, "stderr=", r2.stderr[:200])
    except Exception as e:
        print("With sandbox EXCEPTION:", e)
'''

sftp = ssh.open_sftp()
with sftp.file("/home/judgeclient/tee-judge/debug_sandbox.py", "w") as f:
    f.write(script)
sftp.close()

stdin, stdout, stderr = ssh.exec_command(
    "cd ~/tee-judge && python3 debug_sandbox.py 2>&1", timeout=30
)
print(stdout.read().decode())
ssh.close()
