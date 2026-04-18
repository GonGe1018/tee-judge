import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

# Copy libtcc.so to /tmp (allowed_files) and test inside gramine
# Also need to temporarily modify enclave_entry.py to test libtcc
cmds = """
cd ~/tee-judge

# Copy libtcc.so to /tmp
cp /tmp/tcc-0.9.27/libtcc.so /tmp/libtcc.so

# Also copy tcc include files to /tmp/tcc-include
mkdir -p /tmp/tcc-include
cp -r /usr/include/stdio.h /usr/include/stdlib.h /usr/include/string.h /tmp/tcc-include/ 2>/dev/null

# Backup enclave_entry.py
cp client/enclave_entry.py client/enclave_entry.py.bak2

# Write a test version of enclave_entry.py
cat > client/enclave_entry.py << 'EOF'
import sys
import os
import json
import ctypes

sys.path.insert(0, os.environ.get("PYTHONPATH", "/home/judgeclient/tee-judge"))
os.chdir(os.environ.get("PYTHONPATH", "/home/judgeclient/tee-judge"))

# Try to load libtcc
try:
    libtcc = ctypes.CDLL("/tmp/libtcc.so")
    result = {"libtcc_loaded": True}
    
    # Try tcc_new
    libtcc.tcc_new.restype = ctypes.c_void_p
    s = libtcc.tcc_new()
    result["tcc_new"] = s is not None and s != 0
    
    if s:
        # Try compile simple code
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
        libtcc.tcc_set_output_type(s, 1)  # TCC_OUTPUT_MEMORY
        
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
    print("ENCLAVE_RESULT:" + json.dumps({"error": str(e)}))
EOF

# Re-sign manifest
gramine-manifest -Darch_libdir=/usr/lib/x86_64-linux-gnu -Dentrypoint=/usr/local/bin/python3.11 python3.manifest.template > python3.manifest 2>&1
gramine-sgx-sign --manifest python3.manifest --output python3.manifest.sgx 2>&1 | tail -3

# Run in SGX
echo '{}' | gramine-sgx python3 2>&1 | grep -E "ENCLAVE_RESULT|error|Error"
"""

stdin, stdout, stderr = ssh.exec_command(cmds, timeout=60)
print(stdout.read().decode())
err = stderr.read().decode()
if err:
    print("STDERR:", err[-500:])
ssh.close()
