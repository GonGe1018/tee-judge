"""Clean restart: kill all daemons, start one, test with debug."""

import paramiko
import time
import secrets
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
        print(out[-3000:] if len(out) > 3000 else out, end="")


def start_bg(cmd):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)
    c.exec_command(cmd)
    c.close()


# Kill ALL daemons
print("=== Kill all ===")
ssh_run(
    "pkill -9 -f daemon.py 2>/dev/null; sleep 2; ps aux | grep daemon | grep -v grep; echo 'cleaned'"
)

# Login
r = http_req.post(
    f"{SERVER}/api/auth/login", json={"username": "demo", "password": "demoPass1234"}
)
user_token = r.json()["token"]
user_headers = {
    "Authorization": f"Bearer {user_token}",
    "Content-Type": "application/json",
}

# Get judge token
r = http_req.post(
    f"{SERVER}/api/auth/judge-token",
    json={"judge_key": "33bde09ab043bbb6b299e1e2396ccc82"},
    headers=user_headers,
)
if r.status_code != 200:
    # Try with new key from .env
    ssh_run("grep JUDGE_KEY ~/tee-judge/.env")
    print(f"Judge token failed: {r.status_code} {r.text[:200]}")
    exit(1)
judge_token = r.json()["token"]
judge_headers = {
    "Authorization": f"Bearer {judge_token}",
    "Content-Type": "application/json",
}
print("Judge token OK")

# Start ONE daemon
print("\n=== Start daemon ===")
start_bg(
    f"cd ~/tee-judge && TEE_JUDGE_TOKEN='{judge_token}' TEE_JUDGE_SERVER='{SERVER}' TEE_JUDGE_ALLOW_MOCK=0 python3.11 client/daemon.py > /tmp/daemon.log 2>&1 &"
)
time.sleep(5)
ssh_run("tail -10 /tmp/daemon.log")

# Submit
print("\n=== Submit ===")
code = '#include <stdio.h>\nint main(){int a,b;scanf("%d %d",&a,&b);printf("%d",a+b);return 0;}'
r = http_req.post(
    f"{SERVER}/api/submit",
    json={"problem_id": 1000, "language": "c", "code": code},
    headers=user_headers,
)
sid = r.json()["submission_id"]
print(f"Submitted #{sid}")

for i in range(15):
    time.sleep(3)
    r = http_req.get(f"{SERVER}/api/result/{sid}", headers=user_headers)
    if r.status_code == 200 and r.json().get("verdict"):
        d = r.json()
        print(
            f"Result: {d['verdict']} ({d['test_passed']}/{d['test_total']}) attestation={d['attestation_verified']}"
        )
        break
    print(f"  Waiting... ({i + 1})")
else:
    print("Timeout")

# Show daemon log
print("\n=== Daemon log ===")
ssh_run("tail -20 /tmp/daemon.log")

print("\nDone")
