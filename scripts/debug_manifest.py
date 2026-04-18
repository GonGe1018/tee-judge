import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

# Check if manifest template is valid
stdin, stdout, stderr = ssh.exec_command(
    "cd ~/tee-judge && gramine-manifest -Darch_libdir=/usr/lib/x86_64-linux-gnu -Dentrypoint=/usr/local/bin/python3.11 python3.manifest.template 2>&1 | head -20",
    timeout=15,
)
print("Output:", stdout.read().decode())
print("Stderr:", stderr.read().decode())

# Check if there's already a working python3.manifest.sgx
stdin, stdout, stderr = ssh.exec_command(
    "cd ~/tee-judge && ls -la python3.manifest* 2>&1", timeout=5
)
print("Files:", stdout.read().decode())

ssh.close()
