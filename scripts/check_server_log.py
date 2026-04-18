import paramiko, sys, io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)
stdin, stdout, stderr = c.exec_command(
    "sg docker -c 'docker logs tee-judge-server-1 2>&1' | grep -iE 'attest|verif|403|Reverif|time check|code_hash|failed' | tail -15",
    timeout=15,
)
print(stdout.read().decode("utf-8", errors="replace"))
c.close()
