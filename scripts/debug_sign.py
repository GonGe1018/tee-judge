import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

# Check what went wrong with signing
stdin, stdout, stderr = ssh.exec_command(
    "cd ~/tee-judge && "
    'gramine-manifest -Darch_libdir=/usr/lib/x86_64-linux-gnu -Dentrypoint=/usr/local/bin/python3.11 python3.manifest.template > python3.manifest 2>&1; echo "EXIT:$?"',
    timeout=15,
)
out = stdout.read().decode()
err = stderr.read().decode()
print("manifest gen:", out)
if err:
    print("STDERR:", err)

stdin, stdout, stderr = ssh.exec_command(
    "cd ~/tee-judge && "
    'gramine-sgx-sign --manifest python3.manifest --output python3.manifest.sgx 2>&1; echo "EXIT:$?"',
    timeout=30,
)
out = stdout.read().decode()
err = stderr.read().decode()
print("sgx-sign:", out[-500:])
if err:
    print("STDERR:", err[-300:])

ssh.close()
