import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

# Copy libtcc.so to a trusted path (e.g., /usr/lib/x86_64-linux-gnu/ or the project dir)
# Project dir is trusted: "file:/home/judgeclient/tee-judge/client/"
# Let's put it in the project lib dir
stdin, stdout, stderr = ssh.exec_command(
    "cp /tmp/tcc-0.9.27/libtcc.so /home/judgeclient/tee-judge/client/libtcc.so && "
    "ls -la /home/judgeclient/tee-judge/client/libtcc.so",
    timeout=10,
)
print(stdout.read().decode())

# Update enclave_entry.py to use the new path
test_entry = """import sys
import os
import json
import ctypes

sys.path.insert(0, os.environ.get("PYTHONPATH", "/home/judgeclient/tee-judge"))
os.chdir(os.environ.get("PYTHONPATH", "/home/judgeclient/tee-judge"))

try:
    libtcc = ctypes.CDLL("/home/judgeclient/tee-judge/client/libtcc.so")
    result = {"libtcc_loaded": True}
    
    libtcc.tcc_new.restype = ctypes.c_void_p
    s = libtcc.tcc_new()
    result["tcc_new"] = s is not None and s != 0
    
    if s:
        libtcc.tcc_set_output_type.argtypes = [ctypes.c_void_p, ctypes.c_int]
        libtcc.tcc_compile_string.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        libtcc.tcc_compile_string.restype = ctypes.c_int
        libtcc.tcc_set_lib_path.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        libtcc.tcc_relocate.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        libtcc.tcc_relocate.restype = ctypes.c_int
        libtcc.tcc_get_symbol.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        libtcc.tcc_get_symbol.restype = ctypes.c_void_p
        libtcc.tcc_delete.argtypes = [ctypes.c_void_p]
        
        libtcc.tcc_set_lib_path(s, b"/usr/lib/x86_64-linux-gnu/tcc")
        libtcc.tcc_set_output_type(s, 1)
        
        code = b"int add(int a, int b) { return a + b; }"
        ret = libtcc.tcc_compile_string(s, code)
        result["compile"] = ret == 0
        
        if ret == 0:
            TCC_RELOCATE_AUTO = ctypes.cast(1, ctypes.c_void_p)
            ret = libtcc.tcc_relocate(s, TCC_RELOCATE_AUTO)
            result["relocate"] = ret >= 0
            
            if ret >= 0:
                addr = libtcc.tcc_get_symbol(s, b"add")
                result["get_symbol"] = addr is not None and addr != 0
                
                if addr:
                    FUNC_TYPE = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int)
                    add_func = FUNC_TYPE(addr)
                    val = add_func(3, 5)
                    result["execution"] = val == 8
                    result["value"] = val
        
        libtcc.tcc_delete(s)
    
    print("ENCLAVE_RESULT:" + json.dumps(result))
    
except Exception as e:
    import traceback
    print("ENCLAVE_RESULT:" + json.dumps({"error": str(e), "trace": traceback.format_exc()}))
"""

sftp = ssh.open_sftp()
with sftp.file("/home/judgeclient/tee-judge/client/enclave_entry.py", "w") as f:
    f.write(test_entry)
sftp.close()

# Re-sign (enclave_entry.py changed + libtcc.so added to client/)
stdin, stdout, stderr = ssh.exec_command(
    "cd ~/tee-judge && "
    "gramine-manifest -Darch_libdir=/usr/lib/x86_64-linux-gnu -Dentrypoint=/usr/local/bin/python3.11 python3.manifest.template > python3.manifest 2>&1 && "
    "gramine-sgx-sign --manifest python3.manifest --output python3.manifest.sgx 2>&1 | tail -3",
    timeout=30,
)
print("Sign:", stdout.read().decode())

# Run
stdin, stdout, stderr = ssh.exec_command(
    'cd ~/tee-judge && echo "{}" | gramine-sgx python3 2>&1', timeout=30
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
