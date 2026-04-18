import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

# Direct compile test via host_compile_and_run
script = '''
import sys, json
sys.path.insert(0, '.')
from client.enclave_judge import host_compile_and_run

code = """
#include <stdio.h>
int main() { int a,b; scanf("%d %d",&a,&b); printf("%d",a+b); return 0; }
"""

task = {
    "language": "c",
    "code": code,
    "testcases": [{"order": 1, "input": "1 2"}],
    "time_limit_ms": 2000,
}

try:
    hr = host_compile_and_run(task)
    print("Result:", json.dumps(hr))
except Exception as e:
    print("ERROR:", e)
    import traceback
    traceback.print_exc()
'''

sftp = ssh.open_sftp()
with sftp.file("/home/judgeclient/tee-judge/debug_compile.py", "w") as f:
    f.write(script)
sftp.close()

stdin, stdout, stderr = ssh.exec_command(
    "cd ~/tee-judge && python3 debug_compile.py 2>&1", timeout=30
)
print(stdout.read().decode())
ssh.close()
