"""Test GCC compilation on Azure VM."""

import paramiko

HOST = "172.192.154.85"
USER = "judgeclient"
PASS = "judgeclient1234!!"

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=USER, password=PASS, timeout=10)

sftp = c.open_sftp()
sftp.file("/tmp/test_gcc.c", "w").write(
    '#include <stdio.h>\nint main(){int a,b;scanf("%d %d",&a,&b);printf("%d",a+b);return 0;}\n'
)
sftp.close()

stdin, stdout, stderr = c.exec_command(
    "gcc -O2 -o /tmp/test_gcc /tmp/test_gcc.c && echo 'GCC OK' && echo '1 2' | /tmp/test_gcc",
    timeout=10,
)
print(stdout.read().decode())
print(stderr.read().decode())
c.close()
