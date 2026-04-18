"""Check results for my submissions."""

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
    'rows=conn.execute("SELECT r.submission_id, r.verdict, r.test_passed, r.test_total, r.attestation_verified FROM results r ORDER BY r.submission_id DESC LIMIT 5").fetchall(); '
    '[print(f"#{r[0]}: {r[1]} ({r[2]}/{r[3]}) attest={r[4]}") for r in rows]'
    "'",
    timeout=10,
)
print(stdout.read().decode())
c.close()
