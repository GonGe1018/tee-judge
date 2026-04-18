"""Clean test: kill all, start one daemon, test."""

import paramiko
import time
import requests as http_req

HOST = "172.192.154.85"
USER = "judgeclient"
PASS = "judgeclient1234!!"
SERVER = f"http://{HOST}"


def ssh_run(cmd, timeout=30):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode()
    c.close()
    if out:
        print(out[-2000:] if len(out) > 2000 else out, end="")


def start_bg(cmd):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)
    c.exec_command(cmd)
    c.close()


# Kill ALL
print("=== Kill all daemons ===")
ssh_run(
    "pkill -9 -f daemon.py 2>/dev/null; sleep 2; ps aux | grep daemon | grep python | grep -v grep || echo 'all killed'"
)

# Get judge key from .env
print("\n=== Read judge key ===")
ssh_run("grep JUDGE_KEY ~/tee-judge/.env | head -1")

# Login + judge token
r = http_req.post(
    f"{SERVER}/api/auth/login", json={"username": "demo", "password": "demoPass1234"}
)
user_token = r.json()["token"]
headers = {"Authorization": f"Bearer {user_token}", "Content-Type": "application/json"}

# Read judge key
import paramiko as pm

c = pm.SSHClient()
c.set_missing_host_key_policy(pm.AutoAddPolicy())
c.connect(HOST, username=USER, password=PASS, timeout=10)
stdin, stdout, stderr = c.exec_command("grep TEE_JUDGE_JUDGE_KEY ~/tee-judge/.env")
judge_key = stdout.read().decode().strip().split("=")[1]
c.close()

r = http_req.post(
    f"{SERVER}/api/auth/judge-token", json={"judge_key": judge_key}, headers=headers
)
judge_token = r.json()["token"]
print(f"Judge token OK")

# Start ONE daemon
print("\n=== Start daemon ===")
start_bg(
    f"cd ~/tee-judge && TEE_JUDGE_TOKEN='{judge_token}' TEE_JUDGE_SERVER='{SERVER}' TEE_JUDGE_ALLOW_MOCK=0 python3.11 client/daemon.py > /tmp/daemon.log 2>&1 &"
)
time.sleep(6)
ssh_run("tail -10 /tmp/daemon.log")

# Submit
print("\n=== Submit ===")
code = '#include <stdio.h>\nint main(){int a,b;scanf("%d %d",&a,&b);printf("%d",a+b);return 0;}'
r = http_req.post(
    f"{SERVER}/api/submit",
    json={"problem_id": 1000, "language": "c", "code": code},
    headers=headers,
)
sid = r.json()["submission_id"]
print(f"Submitted #{sid}")

for i in range(15):
    time.sleep(3)
    r = http_req.get(f"{SERVER}/api/result/{sid}", headers=headers)
    if r.status_code == 200 and r.json().get("verdict"):
        d = r.json()
        print(
            f"Result: {d['verdict']} ({d['test_passed']}/{d['test_total']}) attestation={d['attestation_verified']}"
        )
        break
    print(f"  Waiting... ({i + 1})")
else:
    print("Timeout")

print("\n=== Daemon log ===")
ssh_run("tail -20 /tmp/daemon.log")

# Server log
print("\n=== Server log ===")
ssh_run("sg docker -c 'docker logs tee-judge-server-1 2>&1' | tail -10")

print("\nDone")
