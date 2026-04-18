import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

script = r"""
import ctypes
import os
import sys

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

user_code = b'#include <stdio.h>\nint solve() {\n    int a, b;\n    scanf("%d %d", &a, &b);\n    printf("%d\\n", a + b);\n    return 0;\n}\n'

s = libtcc.tcc_new()
libtcc.tcc_set_lib_path(s, b"/usr/lib/x86_64-linux-gnu/tcc")
libtcc.tcc_add_include_path(s, b"/usr/include")
libtcc.tcc_add_include_path(s, b"/usr/include/x86_64-linux-gnu")
libtcc.tcc_set_output_type(s, TCC_OUTPUT_MEMORY)

ret = libtcc.tcc_compile_string(s, user_code)
if ret == -1:
    print("ERROR: compile failed")
    libtcc.tcc_delete(s)
    sys.exit(1)
print("Compile OK")

ret = libtcc.tcc_relocate(s, TCC_RELOCATE_AUTO)
if ret < 0:
    print(f"ERROR: relocate failed (ret={ret})")
    libtcc.tcc_delete(s)
    sys.exit(1)
print("Relocate OK")

addr = libtcc.tcc_get_symbol(s, b"solve")
if not addr:
    print("ERROR: get_symbol failed")
    libtcc.tcc_delete(s)
    sys.exit(1)
print(f"Symbol 'solve' at: {hex(addr)}")

# Redirect stdin/stdout using pipes
stdin_read, stdin_write = os.pipe()
stdout_read, stdout_write = os.pipe()

# Write input
input_data = b"3 5\n"
os.write(stdin_write, input_data)
os.close(stdin_write)

# Save original fds
orig_stdin = os.dup(0)
orig_stdout = os.dup(1)

# Redirect
os.dup2(stdin_read, 0)
os.dup2(stdout_write, 1)

# Call
FUNC_TYPE = ctypes.CFUNCTYPE(ctypes.c_int)
solve_func = FUNC_TYPE(addr)
ret = solve_func()

# Flush C stdout buffer
libc = ctypes.CDLL("libc.so.6")
libc.fflush(None)

# Restore
os.dup2(orig_stdin, 0)
os.dup2(orig_stdout, 1)
os.close(stdin_read)
os.close(stdout_write)
os.close(orig_stdin)
os.close(orig_stdout)

# Read output
output = os.read(stdout_read, 4096).decode().strip()
os.close(stdout_read)

print(f"Output: [{output}]")
print(f"Expected: 8, Match: {output == '8'}")

libtcc.tcc_delete(s)
print("SUCCESS!")
"""

sftp = ssh.open_sftp()
with sftp.file("/home/judgeclient/tee-judge/test_tcc_stdio.py", "w") as f:
    f.write(script)
sftp.close()

stdin, stdout, stderr = ssh.exec_command(
    "cd ~/tee-judge && python3 test_tcc_stdio.py 2>&1", timeout=30
)
print(stdout.read().decode())
ssh.close()
