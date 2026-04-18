import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

# Check current manifest to understand argv setup
stdin, stdout, stderr = ssh.exec_command(
    'cat ~/tee-judge/python3.manifest.template | grep -A5 "argv\|entrypoint\|libos.entrypoint"',
    timeout=10,
)
print(stdout.read().decode())
print("---")
# Also check if there's a way to pass script as argument
stdin, stdout, stderr = ssh.exec_command(
    "cat ~/tee-judge/python3.manifest.template | head -50", timeout=10
)
print(stdout.read().decode())
ssh.close()
