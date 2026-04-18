import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

cmds = """
# Find libtcc1.a location
find / -name "libtcc1.a" 2>/dev/null
echo "==="
# Find tcc include path
find / -name "tcc" -type d 2>/dev/null | head -5
echo "==="
ls /usr/lib/x86_64-linux-gnu/tcc/ 2>/dev/null
"""

stdin, stdout, stderr = ssh.exec_command(cmds, timeout=15)
print(stdout.read().decode())
ssh.close()
