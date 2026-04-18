import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

script = '''
import sys, os, json, time, threading, requests, uvicorn, subprocess, tempfile, platform
from pathlib import Path

os.environ["TEE_JUDGE_ENV"] = "dev"
os.environ["TEE_JUDGE_ALLOW_MOCK"] = "1"

def run_server():
    uvicorn.run("app.main:app", host="127.0.0.1", port=18084, log_level="warning")
t = threading.Thread(target=run_server, daemon=True)
t.start()
time.sleep(3)

BASE = "http://127.0.0.1:18084"

# Register
r = requests.post(f"{BASE}/api/auth/register", json={"username":"dbg3","password":"testPass1234"})
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

# Poll
r = requests.get(f"{BASE}/api/judge/poll", headers=jhdr)
task = r.json()["task"]

# Manual host_compile_and_run with verbose logging
with tempfile.TemporaryDirectory(prefix="tee-judge-") as tmpdir:
    tmpdir = Path(tmpdir)
    ext = ".c"
    source = tmpdir / f"solution{ext}"
    source.write_text(task["code"], encoding="utf-8")
    print("Source written:", source, "size:", source.stat().st_size)
    print("Source content first 100:", repr(source.read_text()[:100]))

    exe = tmpdir / "solution"
    cmd = ["gcc", "-O2", "-o", str(exe), str(source)]
    
    def sandbox():
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (512*1024*1024, 512*1024*1024))
        resource.setrlimit(resource.RLIMIT_CPU, (60, 90))
        resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))
        resource.setrlimit(resource.RLIMIT_FSIZE, (10*1024*1024, 10*1024*1024))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    print("Compiling with sandbox...")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, preexec_fn=sandbox, cwd=str(tmpdir))
        print(f"  returncode: {r.returncode}")
        print(f"  stderr: {r.stderr[:300]}")
        print(f"  exe exists: {exe.exists()}")
    except FileNotFoundError as e:
        print(f"  FileNotFoundError: {e}")
    except Exception as e:
        print(f"  Exception: {type(e).__name__}: {e}")

    print("Compiling WITHOUT sandbox...")
    r2 = subprocess.run(cmd, capture_output=True, text=True, timeout=30, cwd=str(tmpdir))
    print(f"  returncode: {r2.returncode}")
    print(f"  stderr: {r2.stderr[:300]}")
'''

sftp = ssh.open_sftp()
with sftp.file("/home/judgeclient/tee-judge/debug_compile3.py", "w") as f:
    f.write(script)
sftp.close()

stdin, stdout, stderr = ssh.exec_command(
    "cd ~/tee-judge && rm -f data/judge.db && python3 debug_compile3.py 2>&1",
    timeout=60,
)
print(stdout.read().decode())
ssh.close()
