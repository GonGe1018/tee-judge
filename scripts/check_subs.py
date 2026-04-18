"""Check all submissions in DB."""

import paramiko

HOST = "172.192.154.85"
USER = "judgeclient"
PASS = "judgeclient1234!!"

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=USER, password=PASS, timeout=10)

stdin, stdout, stderr = c.exec_command(
    "cd ~/tee-judge && python3.11 -c '"
    'import sqlite3; conn=sqlite3.connect("data/judge.db"); '
    'rows=conn.execute("SELECT id,status,code FROM submissions ORDER BY id").fetchall(); '
    '[print(f"#{r[0]} [{r[1]}] code_len={len(r[2])} first50={repr(r[2][:50])}") for r in rows]'
    "'",
    timeout=10,
)
print(stdout.read().decode())
c.close()
