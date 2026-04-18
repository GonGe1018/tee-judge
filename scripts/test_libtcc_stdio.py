import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

# Test in-memory execution with stdin/stdout redirection via pipes
cmds = '''
cd ~/tee-judge

python3 << 'PYEOF'
import ctypes
import os
import sys
import io

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

user_code = b"""
#include <stdio.h>
int solve() {
    int a, b;
    scanf("%d %d", &a, &b);
    printf("%d\\n", a + b);
    return 0;
}
"""

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
# Create pipes for stdin
stdin_read, stdin_write = os.pipe()
# Create pipes for stdout
stdout_read, stdout_write = os.pipe()

# Write input to stdin pipe
input_data = b"3 5\n"
os.write(stdin_write, input_data)
os.close(stdin_write)

# Save original fds
orig_stdin = os.dup(0)
orig_stdout = os.dup(1)

# Redirect
os.dup2(stdin_read, 0)
os.dup2(stdout_write, 1)

# Call the function
FUNC_TYPE = ctypes.CFUNCTYPE(ctypes.c_int)
solve_func = FUNC_TYPE(addr)
ret = solve_func()

# Flush stdout (C library buffer)
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
print("In-memory stdin/stdout execution SUCCESS!")
PYEOF
'''

stdin, stdout, stderr = ssh.exec_command(cmds, timeout=30)
print(stdout.read().decode())
err = stderr.read().decode()
if err:
    print("STDERR:", err[-500:])
ssh.close()
