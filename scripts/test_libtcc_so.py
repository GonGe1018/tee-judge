import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

# Test libtcc from Python ctypes (this is what we'll use in enclave)
cmds = """
cd ~/tee-judge

# First check if there's a shared lib or only static
ls -la /usr/lib/x86_64-linux-gnu/libtcc* 2>&1

echo "==="

# libtcc is static only (.a). We need to build a shared .so from it
# Or use tcc source to build libtcc.so
# Let's try building from source
cd /tmp
if [ ! -d tcc-0.9.27 ]; then
    wget -q http://download.savannah.gnu.org/releases/tinycc/tcc-0.9.27.tar.bz2
    tar xjf tcc-0.9.27.tar.bz2
fi
cd tcc-0.9.27
./configure --prefix=/usr/local 2>&1 | tail -3
make libtcc.so 2>&1 | tail -5
echo "==="
ls -la libtcc.so 2>&1
echo "==="

# Test from Python ctypes
python3 -c "
import ctypes, os
os.chdir('/tmp/tcc-0.9.27')
lib = ctypes.CDLL('./libtcc.so')
print('libtcc.so loaded successfully')
print('tcc_new:', lib.tcc_new)
" 2>&1
"""

stdin, stdout, stderr = ssh.exec_command(cmds, timeout=120)
print(stdout.read().decode())
err = stderr.read().decode()
if err:
    print("STDERR:", err[-500:])
ssh.close()
