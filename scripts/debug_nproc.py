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

# Start server like test_e2e does
def run_server():
    uvicorn.run("app.main:app", host="127.0.0.1", port=18083, log_level="warning")
t = threading.Thread(target=run_server, daemon=True)
t.start()
time.sleep(3)

# Now check process count and try compile with sandbox
print("Current PID:", os.getpid())
# Count processes for current user
import subprocess as sp
r = sp.run(["ps", "-u", os.getenv("USER", "judgeclient"), "--no-headers"], capture_output=True, text=True)
proc_count = len(r.stdout.strip().split("\\n")) if r.stdout.strip() else 0
print(f"Current process count for user: {proc_count}")

# Try NPROC limits
soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
print(f"Current RLIMIT_NPROC: soft={soft}, hard={hard}")

code = """
#include <stdio.h>
int main() { return 0; }
"""

def sandbox():
    resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))

with tempfile.TemporaryDirectory(prefix="tee-test-") as tmpdir:
    tmpdir = Path(tmpdir)
    source = tmpdir / "solution.c"
    source.write_text(code, encoding="utf-8")
    exe = tmpdir / "solution"
    
    try:
        r = subprocess.run(["gcc", "-O2", "-o", str(exe), str(source)], 
                          capture_output=True, text=True, timeout=30, preexec_fn=sandbox)
        print(f"With NPROC=16: returncode={r.returncode}")
        if r.returncode != 0:
            print(f"  stderr: {r.stderr[:300]}")
    except Exception as e:
        print(f"With NPROC=16: EXCEPTION: {e}")
'''

sftp = ssh.open_sftp()
with sftp.file("/home/judgeclient/tee-judge/debug_nproc.py", "w") as f:
    f.write(script)
sftp.close()

stdin, stdout, stderr = ssh.exec_command(
    "cd ~/tee-judge && rm -f data/judge.db && python3 debug_nproc.py 2>&1", timeout=30
)
print(stdout.read().decode())
ssh.close()
