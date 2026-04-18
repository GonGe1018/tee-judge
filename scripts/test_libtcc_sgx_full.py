import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

# Full test: compile C code with stdio, redirect stdin/stdout, run inside SGX
test_entry = """import sys
import os
import json
import ctypes

sys.path.insert(0, os.environ.get("PYTHONPATH", "/home/judgeclient/tee-judge"))
os.chdir(os.environ.get("PYTHONPATH", "/home/judgeclient/tee-judge"))

try:
    libtcc = ctypes.CDLL("/home/judgeclient/tee-judge/client/libtcc.so")
    libc = ctypes.CDLL("libc.so.6")
    
    libtcc.tcc_new.restype = ctypes.c_void_p
    libtcc.tcc_delete.argtypes = [ctypes.c_void_p]
    libtcc.tcc_set_output_type.argtypes = [ctypes.c_void_p, ctypes.c_int]
    libtcc.tcc_compile_string.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    libtcc.tcc_compile_string.restype = ctypes.c_int
    libtcc.tcc_set_lib_path.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    libtcc.tcc_add_include_path.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    libtcc.tcc_relocate.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    libtcc.tcc_relocate.restype = ctypes.c_int
    libtcc.tcc_get_symbol.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    libtcc.tcc_get_symbol.restype = ctypes.c_void_p

    # Read task from stdin
    data = json.loads(sys.stdin.read())
    user_code = data["code"].encode()
    test_input = data["input"].encode()
    if not test_input.endswith(b"\\n"):
        test_input += b"\\n"
    
    # Rename main to solve to avoid conflict
    user_code = user_code.replace(b"int main(", b"int solve(")
    
    # Compile
    s = libtcc.tcc_new()
    libtcc.tcc_set_lib_path(s, b"/usr/lib/x86_64-linux-gnu/tcc")
    libtcc.tcc_add_include_path(s, b"/usr/include")
    libtcc.tcc_add_include_path(s, b"/usr/include/x86_64-linux-gnu")
    libtcc.tcc_set_output_type(s, 1)  # TCC_OUTPUT_MEMORY
    
    ret = libtcc.tcc_compile_string(s, user_code)
    if ret == -1:
        print("ENCLAVE_RESULT:" + json.dumps({"status": "CE", "output": ""}))
        sys.exit(0)
    
    TCC_RELOCATE_AUTO = ctypes.cast(1, ctypes.c_void_p)
    ret = libtcc.tcc_relocate(s, TCC_RELOCATE_AUTO)
    if ret < 0:
        print("ENCLAVE_RESULT:" + json.dumps({"status": "CE", "output": "relocate failed"}))
        sys.exit(0)
    
    addr = libtcc.tcc_get_symbol(s, b"solve")
    if not addr:
        print("ENCLAVE_RESULT:" + json.dumps({"status": "CE", "output": "no solve symbol"}))
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
    
    # Execute
    FUNC_TYPE = ctypes.CFUNCTYPE(ctypes.c_int)
    solve_func = FUNC_TYPE(addr)
    solve_func()
    
    # Flush C stdout
    libc.fflush(None)
    
    # Restore
    os.dup2(orig_stdin, 0)
    os.dup2(orig_stdout, 1)
    os.close(stdin_read)
    os.close(stdout_write)
    os.close(orig_stdin)
    os.close(orig_stdout)
    
    output = os.read(stdout_read, 65536).decode().strip()
    os.close(stdout_read)
    
    libtcc.tcc_delete(s)
    
    print("ENCLAVE_RESULT:" + json.dumps({"status": "OK", "output": output}))

except Exception as e:
    import traceback
    print("ENCLAVE_RESULT:" + json.dumps({"error": str(e), "trace": traceback.format_exc()}))
"""

sftp = ssh.open_sftp()
with sftp.file("/home/judgeclient/tee-judge/client/enclave_entry.py", "w") as f:
    f.write(test_entry)
sftp.close()

# Re-sign
stdin, stdout, stderr = ssh.exec_command(
    "cd ~/tee-judge && "
    "gramine-manifest -Darch_libdir=/usr/lib/x86_64-linux-gnu -Dentrypoint=/usr/local/bin/python3.11 python3.manifest.template > python3.manifest 2>&1 && "
    "gramine-sgx-sign --manifest python3.manifest --output python3.manifest.sgx 2>&1 | tail -3",
    timeout=30,
)
print("Sign:", stdout.read().decode())

# Run with A+B test
import json

test_data = json.dumps(
    {
        "code": '#include <stdio.h>\nint main() { int a,b; scanf("%d %d",&a,&b); printf("%d",a+b); return 0; }',
        "input": "3 5",
    }
)

stdin, stdout, stderr = ssh.exec_command(
    f"cd ~/tee-judge && echo '{test_data}' | gramine-sgx python3 2>&1", timeout=30
)
out = stdout.read().decode()
for line in out.split("\n"):
    if "ENCLAVE_RESULT" in line:
        print(line)
        break
else:
    print("No ENCLAVE_RESULT. Tail:")
    print(out[-500:])

ssh.close()
