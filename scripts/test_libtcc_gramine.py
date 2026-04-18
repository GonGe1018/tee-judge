import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

# Test libtcc inside Gramine SGX enclave
script = r"""
import ctypes
import os
import sys
import json

libtcc = ctypes.CDLL("/tmp/tcc-0.9.27/libtcc.so")

TCC_OUTPUT_MEMORY = 1
TCC_RELOCATE_AUTO = ctypes.cast(1, ctypes.c_void_p)

libtcc.tcc_new.restype = ctypes.c_void_p
libtcc.tcc_delete.argtypes = [ctypes.c_void_p]
libtcc.tcc_set_output_type.argtypes = [ctypes.c_void_p, ctypes.c_int]
libtcc.tcc_compile_string.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
libtcc.tcc_compile_string.restype = ctypes.c_int
libtcc.tcc_relocate.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
libtcc.tcc_relocate.restype = ctypes.c_int
libtcc.tcc_get_symbol.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
libtcc.tcc_get_symbol.restype = ctypes.c_void_p
libtcc.tcc_set_lib_path.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
libtcc.tcc_add_include_path.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

# Read task from stdin
data = json.loads(sys.stdin.read())
code = data["code"].encode()
test_input = data["input"].encode() + b"\n"

# Wrap user code: rename main to solve
code = code.replace(b"int main(", b"int solve(")

s = libtcc.tcc_new()
libtcc.tcc_set_lib_path(s, b"/usr/lib/x86_64-linux-gnu/tcc")
libtcc.tcc_add_include_path(s, b"/usr/include")
libtcc.tcc_add_include_path(s, b"/usr/include/x86_64-linux-gnu")
libtcc.tcc_set_output_type(s, TCC_OUTPUT_MEMORY)

ret = libtcc.tcc_compile_string(s, code)
if ret == -1:
    print(json.dumps({"status": "CE", "output": ""}))
    sys.exit(0)

ret = libtcc.tcc_relocate(s, TCC_RELOCATE_AUTO)
if ret < 0:
    print(json.dumps({"status": "CE", "output": ""}))
    sys.exit(0)

addr = libtcc.tcc_get_symbol(s, b"solve")
if not addr:
    print(json.dumps({"status": "error", "output": "no solve symbol"}))
    sys.exit(0)

# Redirect stdin/stdout
stdin_read, stdin_write = os.pipe()
stdout_read, stdout_write = os.pipe()
os.write(stdin_write, test_input)
os.close(stdin_write)

orig_stdin = os.dup(0)
orig_stdout = os.dup(1)
os.dup2(stdin_read, 0)
os.dup2(stdout_write, 1)

FUNC_TYPE = ctypes.CFUNCTYPE(ctypes.c_int)
solve_func = FUNC_TYPE(addr)
solve_func()

libc = ctypes.CDLL("libc.so.6")
libc.fflush(None)

os.dup2(orig_stdin, 0)
os.dup2(orig_stdout, 1)
os.close(stdin_read)
os.close(stdout_write)
os.close(orig_stdin)
os.close(orig_stdout)

output = os.read(stdout_read, 4096).decode().strip()
os.close(stdout_read)

libtcc.tcc_delete(s)
print(json.dumps({"status": "OK", "output": output}))
"""

# Upload the enclave test script
sftp = ssh.open_sftp()
with sftp.file("/home/judgeclient/tee-judge/test_tcc_enclave.py", "w") as f:
    f.write(script)
sftp.close()

# First test without Gramine (sanity check)
import json

test_data = json.dumps(
    {
        "code": '#include <stdio.h>\nint main() { int a,b; scanf("%d %d",&a,&b); printf("%d",a+b); return 0; }',
        "input": "3 5",
    }
)

stdin, stdout, stderr = ssh.exec_command(
    f"cd ~/tee-judge && echo '{test_data}' | python3 test_tcc_enclave.py 2>&1",
    timeout=15,
)
out = stdout.read().decode()
print("Without Gramine:", out)

# Now test WITH Gramine SGX
stdin, stdout, stderr = ssh.exec_command(
    f"cd ~/tee-judge && echo '{test_data}' | gramine-sgx python3 test_tcc_enclave.py 2>&1",
    timeout=30,
)
out = stdout.read().decode()
err = stderr.read().decode()
print("With Gramine SGX:", out[-500:] if len(out) > 500 else out)
if err:
    print("STDERR:", err[-300:])

ssh.close()
