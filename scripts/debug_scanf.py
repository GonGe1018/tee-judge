import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

script = '''
import sys, os, subprocess, tempfile, resource, time, threading
from pathlib import Path
import uvicorn

os.environ["TEE_JUDGE_ENV"] = "dev"
os.environ["TEE_JUDGE_ALLOW_MOCK"] = "1"

def run_server():
    uvicorn.run("app.main:app", host="127.0.0.1", port=18086, log_level="warning")
t = threading.Thread(target=run_server, daemon=True)
t.start()
time.sleep(3)

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

with tempfile.TemporaryDirectory(prefix="tee-test-") as tmpdir:
    tmpdir = Path(tmpdir)
    source = tmpdir / "solution.c"
    source.write_text(code, encoding="utf-8")
    exe = tmpdir / "solution"
    cmd = ["gcc", "-O2", "-o", str(exe), str(source)]
    
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, preexec_fn=sandbox, cwd=str(tmpdir))
    print(f"returncode: {r.returncode}")
    print(f"FULL stderr: [{r.stderr}]")
    print(f"exe exists: {exe.exists()}")
'''

sftp = ssh.open_sftp()
with sftp.file("/home/judgeclient/tee-judge/debug_scanf.py", "w") as f:
    f.write(script)
sftp.close()

stdin, stdout, stderr = ssh.exec_command(
    "cd ~/tee-judge && rm -f data/judge.db && python3 debug_scanf.py 2>&1", timeout=60
)
print(stdout.read().decode())
ssh.close()
