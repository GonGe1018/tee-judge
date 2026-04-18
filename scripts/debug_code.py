"""Debug: check what code the daemon receives."""

import paramiko
import json

HOST = "172.192.154.85"
USER = "judgeclient"
PASS = "judgeclient1234!!"

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=USER, password=PASS, timeout=10)

# Check DB for latest submission code
stdin, stdout, stderr = c.exec_command(
    "cd ~/tee-judge && python3.11 -c '"
    'import sqlite3; conn=sqlite3.connect("data/judge.db"); '
    'r=conn.execute("SELECT id,code FROM submissions ORDER BY id DESC LIMIT 1").fetchone(); '
    'print(f"ID: {r[0]}"); print(f"Code repr: {repr(r[1])}"); print(f"Code:\\n{r[1]}")'
    "'",
    timeout=10,
)
print(stdout.read().decode())
print(stderr.read().decode()[:300])
c.close()
