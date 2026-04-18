import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

# Install libtcc and test basic functionality
cmds = """
# Check if libtcc is available
dpkg -l | grep tcc 2>/dev/null
echo "---"

# Install tcc (includes libtcc)
sudo apt-get install -y tcc libtcc-dev 2>&1 | tail -5
echo "---"

# Find libtcc.so
find /usr -name "libtcc*" 2>/dev/null
echo "---"

# Test libtcc from C
cat > /tmp/test_libtcc.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libtcc.h>

int main() {
    TCCState *s = tcc_new();
    if (!s) { printf("tcc_new failed\\n"); return 1; }
    
    tcc_set_output_type(s, TCC_OUTPUT_MEMORY);
    
    const char *code = 
        "#include <stdio.h>\\n"
        "int main() { printf(\\"hello from tcc\\\\n\\"); return 0; }";
    
    if (tcc_compile_string(s, code) == -1) {
        printf("compile failed\\n");
        tcc_delete(s);
        return 1;
    }
    
    int size = tcc_relocate(s, TCC_RELOCATE_AUTO);
    if (size < 0) {
        printf("relocate failed\\n");
        tcc_delete(s);
        return 1;
    }
    
    int (*func)(void);
    func = tcc_get_symbol(s, "main");
    if (!func) {
        printf("get_symbol failed\\n");
        tcc_delete(s);
        return 1;
    }
    
    printf("Calling compiled function...\\n");
    func();
    
    tcc_delete(s);
    printf("libtcc works!\\n");
    return 0;
}
EOF

gcc -o /tmp/test_libtcc /tmp/test_libtcc.c -ltcc -ldl 2>&1
echo "---"
/tmp/test_libtcc 2>&1
"""

stdin, stdout, stderr = ssh.exec_command(cmds, timeout=60)
print(stdout.read().decode())
err = stderr.read().decode()
if err:
    print("STDERR:", err[-500:])
ssh.close()
