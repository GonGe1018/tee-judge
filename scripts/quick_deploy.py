import paramiko, sys, io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)
for cmd in [
    "cd ~/tee-judge && git pull origin feature/dcap-verification",
    "sg docker -c 'cd ~/tee-judge && docker compose down -v && docker compose up -d --build'",
]:
    stdin, stdout, stderr = c.exec_command(cmd, timeout=300)
    stdout.read()
    stderr.read()
print("Deployed")
c.close()
