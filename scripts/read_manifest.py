import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

# Check full manifest for allowed_files and sgx.trusted_files
stdin, stdout, stderr = ssh.exec_command(
    "cat ~/tee-judge/python3.manifest.template", timeout=10
)
print(stdout.read().decode())
ssh.close()
