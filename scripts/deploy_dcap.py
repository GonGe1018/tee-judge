"""Deploy DCAP verification branch on Azure VM."""

import paramiko
import time
import secrets
import requests as http_req

HOST = "172.192.154.85"
USER = "judgeclient"
PASS = "judgeclient1234!!"
SERVER = f"http://{HOST}"


def ssh_run(cmd, timeout=600):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode()
    c.close()
    if out:
        print(out[-3000:] if len(out) > 3000 else out, end="")


def sftp_write(remote_path, content):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)
    sftp = c.open_sftp()
    with sftp.file(remote_path, "w") as f:
        f.write(content)
    sftp.close()
    c.close()


def start_bg(cmd):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)
    c.exec_command(cmd)
    c.close()


# Generate secrets
secret_key = secrets.token_hex(32)
judge_key = secrets.token_hex(16)
enclave_key = secrets.token_hex(32)

# Create .env
print("=== Create .env ===")
env_content = f"""TEE_JUDGE_SECRET={secret_key}
TEE_JUDGE_JUDGE_KEY={judge_key}
TEE_JUDGE_ENCLAVE_KEY={enclave_key}
TEE_JUDGE_ENV=dev
TEE_JUDGE_ALLOW_MOCK=1
TEE_JUDGE_CORS_ORIGINS=*
"""
sftp_write("/home/judgeclient/tee-judge/.env", env_content)
print("Created .env")

# Stop old processes
print("\n=== Stop old ===")
ssh_run(
    "pkill -f uvicorn 2>/dev/null; pkill -f daemon.py 2>/dev/null; sleep 1; echo stopped"
)

# Install cryptography on VM
print("\n=== Install deps ===")
ssh_run("python3.11 -m pip install -q cryptography 2>&1 | tail -2")

# Docker deploy
print("\n=== Docker deploy ===")
ssh_run(
    "sg docker -c 'cd ~/tee-judge && docker compose down -v 2>&1 && docker compose up -d --build 2>&1' | tail -5"
)
time.sleep(5)

# Rebuild Gramine
print("\n=== Rebuild Gramine ===")
ssh_run(
    "cd ~/tee-judge && gramine-manifest -Darch_libdir=/lib/x86_64-linux-gnu -Dentrypoint=/usr/local/bin/python3.11 python3.manifest.template python3.manifest 2>&1 && gramine-sgx-sign --manifest python3.manifest --output python3.manifest.sgx 2>&1 | tail -2"
)

# Register user
print("\n=== Auth ===")
r = http_req.post(
    f"{SERVER}/api/auth/register", json={"username": "demo", "password": "demoPass1234"}
)
if r.status_code == 409:
    r = http_req.post(
        f"{SERVER}/api/auth/login",
        json={"username": "demo", "password": "demoPass1234"},
    )
user_token = r.json()["token"]
user_headers = {
    "Authorization": f"Bearer {user_token}",
    "Content-Type": "application/json",
}
print(f"User: demo")

# Get judge token
r = http_req.post(
    f"{SERVER}/api/auth/judge-token",
    json={"judge_key": judge_key},
    headers=user_headers,
)
judge_token = r.json()["token"]
judge_headers = {
    "Authorization": f"Bearer {judge_token}",
    "Content-Type": "application/json",
}
print("Judge token acquired")

# Remove old sealed key so enclave generates fresh one
ssh_run("rm -f ~/tee-judge/client/.sealed_key.pem; echo 'sealed key removed'")

# Start daemon with judge token
print("\n=== Start daemon ===")
start_bg(
    f"cd ~/tee-judge && TEE_JUDGE_TOKEN='{judge_token}' TEE_JUDGE_SERVER='{SERVER}' TEE_JUDGE_ALLOW_MOCK=1 python3.11 client/daemon.py &>/tmp/daemon.log &"
)
time.sleep(5)
ssh_run("tail -10 /tmp/daemon.log")

# Test
print("\n=== Test ===")
code = '#include <stdio.h>\nint main(){int a,b;scanf("%d %d",&a,&b);printf("%d",a+b);return 0;}'
r = http_req.post(
    f"{SERVER}/api/submit",
    json={"problem_id": 1000, "language": "c", "code": code},
    headers=user_headers,
)
sid = r.json()["submission_id"]
print(f"Submitted #{sid}")

for i in range(20):
    time.sleep(2)
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
    ssh_run("tail -30 /tmp/daemon.log")

# Check server logs
print("\n=== Server logs ===")
ssh_run(
    "sg docker -c 'docker logs tee-judge-server-1 2>&1' | grep -i 'attest\|verif\|ecdsa\|quote\|error' | tail -10"
)

print(f"\nJUDGE_KEY: {judge_key}")
print("Done")
