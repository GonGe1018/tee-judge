import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

# Test TCC_OUTPUT_MEMORY mode - compile and run in-process
cmds = '''
cd ~/tee-judge

python3 << 'PYEOF'
import ctypes
import ctypes.util
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

# Simple code that doesn't use stdin (test basic in-memory execution)
user_code = b"""
int add(int a, int b) {
    return a + b;
}
"""

s = libtcc.tcc_new()
libtcc.tcc_set_lib_path(s, b"/usr/lib/x86_64-linux-gnu/tcc")
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

addr = libtcc.tcc_get_symbol(s, b"add")
if not addr:
    print("ERROR: get_symbol failed")
    libtcc.tcc_delete(s)
    sys.exit(1)
print(f"Symbol 'add' at: {hex(addr)}")

# Call the function
FUNC_TYPE = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int)
add_func = FUNC_TYPE(addr)
result = add_func(3, 5)
print(f"add(3, 5) = {result}")
print(f"Expected: 8, Match: {result == 8}")

libtcc.tcc_delete(s)
print("In-memory execution SUCCESS!")
PYEOF
'''

stdin, stdout, stderr = ssh.exec_command(cmds, timeout=30)
print(stdout.read().decode())
err = stderr.read().decode()
if err:
    print("STDERR:", err[-500:])
ssh.close()
