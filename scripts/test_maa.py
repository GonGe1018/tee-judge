"""Test Azure MAA with real SGX quote from Azure VM."""

import paramiko
import json
import base64
import requests

HOST = "172.192.154.85"
USER = "judgeclient"
PASS = "judgeclient1234!!"
MAA_ENDPOINT = "https://judge.jpw.attest.azure.net"


def sftp_write(remote_path, content):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)
    sftp = c.open_sftp()
    with sftp.file(remote_path, "w") as f:
        f.write(content)
    sftp.close()
    c.close()


def sftp_read_bytes(remote_path):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)
    sftp = c.open_sftp()
    with sftp.file(remote_path, "rb") as f:
        data = f.read()
    sftp.close()
    c.close()
    return data


def ssh_run(cmd, timeout=120):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode()
    err = stderr.read().decode()
    c.close()
    if out:
        print(out[-3000:] if len(out) > 3000 else out, end="")
    return out


# Step 1: Generate a real SGX quote on Azure VM
print("=== Generate SGX quote ===")
sftp_write(
    "/tmp/gen_quote.py",
    "import os, hashlib\n"
    "att_dir = '/dev/attestation'\n"
    "report_data = hashlib.sha256(b'test-payload').digest()\n"
    "report_data = report_data + b'\\x00' * (64 - len(report_data))\n"
    "with open(f'{att_dir}/user_report_data', 'wb') as f:\n"
    "    f.write(report_data)\n"
    "with open(f'{att_dir}/quote', 'rb') as f:\n"
    "    quote = f.read()\n"
    "with open('/tmp/test_quote.bin', 'wb') as f:\n"
    "    f.write(quote)\n"
    "print(f'Quote generated: {len(quote)} bytes')\n",
)
ssh_run("cd ~/tee-judge && gramine-sgx python3 /tmp/gen_quote.py 2>/dev/null")

# Step 2: Download quote
print("\n=== Download quote ===")
quote_bytes = sftp_read_bytes("/tmp/test_quote.bin")
print(f"Quote size: {len(quote_bytes)} bytes")

# Step 3: Send to MAA
print("\n=== Send to Azure MAA ===")
quote_b64url = base64.urlsafe_b64encode(quote_bytes).rstrip(b"=").decode()

url = f"{MAA_ENDPOINT}/attest/SgxEnclave?api-version=2022-08-01"
payload = {"quote": quote_b64url}
r = requests.post(
    url, json=payload, headers={"Content-Type": "application/json"}, timeout=30
)

print(f"Status: {r.status_code}")
if r.status_code == 200:
    result = r.json()
    token = result.get("token", "")
    # Decode JWT claims
    parts = token.split(".")
    if len(parts) >= 2:
        pad = parts[1] + "=" * (4 - len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(pad))
        print(f"\nMAA VERIFIED!")
        print(f"  x-ms-sgx-is-debuggable: {claims.get('x-ms-sgx-is-debuggable')}")
        print(f"  x-ms-sgx-mrenclave: {claims.get('x-ms-sgx-mrenclave')}")
        print(f"  x-ms-sgx-mrsigner: {claims.get('x-ms-sgx-mrsigner')}")
        print(f"  x-ms-sgx-product-id: {claims.get('x-ms-sgx-product-id')}")
        print(f"  x-ms-ver: {claims.get('x-ms-ver')}")
        print(f"  iss: {claims.get('iss')}")
else:
    print(f"Body: {r.text[:500]}")

print("\n=== Done ===")
