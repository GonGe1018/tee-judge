import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

# Test full compile+run from Python ctypes with stdin/stdout capture
cmds = '''
cd ~/tee-judge

python3 << 'PYEOF'
import ctypes
import ctypes.util
import os
import sys
import tempfile

# Load libtcc
libtcc = ctypes.CDLL("/tmp/tcc-0.9.27/libtcc.so")

# Define constants
TCC_OUTPUT_MEMORY = 1
TCC_OUTPUT_EXE = 3
TCC_RELOCATE_AUTO = 1

# Setup function signatures
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

# User code
user_code = b"""
#include <stdio.h>
int main() {
    int a, b;
    scanf("%d %d", &a, &b);
    printf("%d\\n", a + b);
    return 0;
}
"""

# Compile to executable file (since in-memory execution with stdin is tricky)
s = libtcc.tcc_new()
if not s:
    print("ERROR: tcc_new failed")
    sys.exit(1)

# Set lib path for tcc runtime
libtcc.tcc_set_lib_path(s, b"/tmp/tcc-0.9.27")

libtcc.tcc_set_output_type(s, TCC_OUTPUT_EXE)

ret = libtcc.tcc_compile_string(s, user_code)
if ret == -1:
    print("ERROR: compile failed")
    libtcc.tcc_delete(s)
    sys.exit(1)

print("Compilation successful!")

# Output to file
with tempfile.NamedTemporaryFile(suffix="", prefix="tcc_out_", delete=False) as f:
    exe_path = f.name

libtcc.tcc_output_file = libtcc.tcc_output_file
libtcc.tcc_output_file.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
libtcc.tcc_output_file.restype = ctypes.c_int

ret = libtcc.tcc_output_file(s, exe_path.encode())
if ret == -1:
    print("ERROR: output_file failed")
    libtcc.tcc_delete(s)
    sys.exit(1)

libtcc.tcc_delete(s)

# Make executable
os.chmod(exe_path, 0o755)
print(f"Executable: {exe_path}, size: {os.path.getsize(exe_path)}")

# Run with stdin
import subprocess
r = subprocess.run([exe_path], input="3 5", capture_output=True, text=True, timeout=5)
print(f"Return code: {r.returncode}")
print(f"stdout: [{r.stdout.strip()}]")
print(f"Expected: 8")
print(f"Match: {r.stdout.strip() == '8'}")

# Cleanup
os.unlink(exe_path)
print("Done!")
PYEOF
'''

stdin, stdout, stderr = ssh.exec_command(cmds, timeout=30)
print(stdout.read().decode())
err = stderr.read().decode()
if err:
    print("STDERR:", err[-500:])
ssh.close()
