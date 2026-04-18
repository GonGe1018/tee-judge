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
    uvicorn.run("app.main:app", host="127.0.0.1", port=18085, log_level="warning")
t = threading.Thread(target=run_server, daemon=True)
t.start()
time.sleep(3)

code = """
#include <stdio.h>
int main() { return 0; }
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
    print(f"FULL stdout: [{r.stdout}]")
    print(f"exe exists: {exe.exists()}")
    
    # Try each limit individually
    limits = [
        ("RLIMIT_AS", resource.RLIMIT_AS, (512*1024*1024, 512*1024*1024)),
        ("RLIMIT_CPU", resource.RLIMIT_CPU, (60, 90)),
        ("RLIMIT_NPROC", resource.RLIMIT_NPROC, (16, 16)),
        ("RLIMIT_FSIZE", resource.RLIMIT_FSIZE, (10*1024*1024, 10*1024*1024)),
        ("RLIMIT_CORE", resource.RLIMIT_CORE, (0, 0)),
    ]
    for name, lim, val in limits:
        def mk_sandbox(l=lim, v=val):
            def fn():
                resource.setrlimit(l, v)
            return fn
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, preexec_fn=mk_sandbox(), cwd=str(tmpdir))
        status = "OK" if r.returncode == 0 else "FAIL"
        print(f"  {name} only: {status} (rc={r.returncode})")
        if r.returncode != 0:
            print(f"    stderr: {r.stderr}")
'''

sftp = ssh.open_sftp()
with sftp.file("/home/judgeclient/tee-judge/debug_limits.py", "w") as f:
    f.write(script)
sftp.close()

stdin, stdout, stderr = ssh.exec_command(
    "cd ~/tee-judge && rm -f data/judge.db && python3 debug_limits.py 2>&1", timeout=60
)
print(stdout.read().decode())
ssh.close()
