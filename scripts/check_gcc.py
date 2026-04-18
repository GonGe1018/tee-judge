import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)
stdin, stdout, stderr = ssh.exec_command(
    'which gcc; gcc --version 2>&1; echo "#include <stdio.h>" > /tmp/test.c; echo "int main(){return 0;}" >> /tmp/test.c; gcc -O2 -o /tmp/test /tmp/test.c 2>&1 && echo COMPILE_OK || echo COMPILE_FAIL'
)
print(stdout.read().decode())
print(stderr.read().decode())
ssh.close()
