"""Test RA-TLS certificate generation and basic TLS communication."""

import paramiko
import json
import ssl
import socket
import threading
import time

HOST = "172.192.154.85"
USER = "judgeclient"
PASS = "judgeclient1234!!"


def ssh_run(cmd, timeout=60):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    c.close()
    if out:
        print(out[-2000:] if len(out) > 2000 else out, end="")
    if err:
        for line in err.split("\n"):
            if (
                line.strip()
                and "Gramine" not in line
                and "---" not in line
                and "Parsing" not in line
                and "insecure" not in line
                and "allowed" not in line
            ):
                print(line)


def sftp_write(remote_path, content):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)
    sftp = c.open_sftp()
    with sftp.file(remote_path, "w") as f:
        f.write(content)
    sftp.close()
    c.close()


# Step 1: Generate RA-TLS certificate inside SGX enclave
print("=== Step 1: Generate RA-TLS cert ===")
ssh_run(
    "cd ~/tee-judge && gramine-ratls -D /tmp/ratls-cert.pem /tmp/ratls-key.pem echo 'cert generated' 2>&1 | tail -5"
)

# Check cert
ssh_run("ls -la /tmp/ratls-cert.pem /tmp/ratls-key.pem 2>&1")
ssh_run("openssl x509 -in /tmp/ratls-cert.pem -noout -subject -issuer 2>&1")

# Step 2: Create a simple TLS server script that runs inside enclave
print("\n=== Step 2: Create TLS server ===")
TLS_SERVER = """import ssl, socket, json

HOST = '0.0.0.0'
PORT = 9443
CERTFILE = '/tmp/ratls-cert.pem'
KEYFILE = '/tmp/ratls-key.pem'

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(1)
    with ctx.wrap_socket(sock, server_side=True) as ssock:
        print(f"RA-TLS server listening on {HOST}:{PORT}")
        conn, addr = ssock.accept()
        with conn:
            print(f"Connection from {addr}")
            # Receive request
            data = conn.recv(4096).decode()
            print(f"Received: {data[:100]}")
            # Send secret (testcases)
            secret = json.dumps({"testcases": [{"input": "1 2", "expected": "3"}]})
            conn.sendall(secret.encode())
            print("Secret sent")
"""
sftp_write("/tmp/ratls_server.py", TLS_SERVER)

# Step 3: Test - generate cert and run server inside enclave
print("\n=== Step 3: Test RA-TLS ===")
print("Generating cert inside SGX enclave...")
ssh_run(
    "cd ~/tee-judge && gramine-ratls -D /tmp/ratls-cert.pem /tmp/ratls-key.pem python3.11 -c 'print(\"RA-TLS cert generated inside SGX\")' 2>&1 | tail -3"
)

print("\nDone")
