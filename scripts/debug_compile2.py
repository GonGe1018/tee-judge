import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

# Simulate exactly what test_e2e does
script = '''
import sys, os, json, time, threading, requests, uvicorn
sys.path.insert(0, '.')
os.environ["TEE_JUDGE_ENV"] = "dev"
os.environ["TEE_JUDGE_ALLOW_MOCK"] = "1"

def run_server():
    uvicorn.run("app.main:app", host="127.0.0.1", port=18082, log_level="warning")
t = threading.Thread(target=run_server, daemon=True)
t.start()
time.sleep(3)

BASE = "http://127.0.0.1:18082"
from client.enclave_judge import host_compile_and_run

# Register + login
r = requests.post(f"{BASE}/api/auth/register", json={"username":"dbg2","password":"testPass1234"})
token = r.json()["token"]
hdr = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
r = requests.post(f"{BASE}/api/auth/judge-token", json={"judge_key":"dev-only-judge-key"}, headers=hdr)
jhdr = {"Authorization": f"Bearer {r.json()['token']}", "Content-Type": "application/json"}

# Submit
code = """
#include <stdio.h>
int main() { int a,b; scanf("%d %d",&a,&b); printf("%d",a+b); return 0; }
"""
r = requests.post(f"{BASE}/api/submit", json={"problem_id":1000,"language":"c","code":code}, headers=hdr)
print("Submit:", r.json())

# Poll
r = requests.get(f"{BASE}/api/judge/poll", headers=jhdr)
task = r.json()["task"]
print("Task code repr:", repr(task["code"][:80]))

# Phase 1 with verbose error
import subprocess, tempfile
from pathlib import Path

with tempfile.TemporaryDirectory(prefix="tee-debug-") as tmpdir:
    tmpdir = Path(tmpdir)
    source = tmpdir / "solution.c"
    source.write_text(task["code"], encoding="utf-8")
    exe = tmpdir / "solution"
    cmd = ["gcc", "-O2", "-o", str(exe), str(source)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    print("GCC returncode:", r.returncode)
    print("GCC stderr:", r.stderr[:500] if r.stderr else "(none)")
    print("GCC stdout:", r.stdout[:200] if r.stdout else "(none)")

# Now try via host_compile_and_run
hr = host_compile_and_run(task)
print("host_compile_and_run status:", hr["status"])
print("host_compile_and_run outputs:", len(hr["outputs"]))
'''

sftp = ssh.open_sftp()
with sftp.file("/home/judgeclient/tee-judge/debug_compile2.py", "w") as f:
    f.write(script)
sftp.close()

stdin, stdout, stderr = ssh.exec_command(
    "cd ~/tee-judge && rm -f data/judge.db && python3 debug_compile2.py 2>&1",
    timeout=60,
)
print(stdout.read().decode())
ssh.close()
