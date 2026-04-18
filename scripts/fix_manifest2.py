import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

# Read current template and fix ALL /usr/{{ arch_libdir }} occurrences
stdin, stdout, stderr = ssh.exec_command(
    "cat ~/tee-judge/python3.manifest.template", timeout=5
)
template = stdout.read().decode()

# The issue: arch_libdir = "/usr/lib/x86_64-linux-gnu" (already has /usr prefix)
# So "/usr/{{ arch_libdir }}" becomes "/usr//usr/lib/x86_64-linux-gnu"
# Fix: replace all "/usr/{{ arch_libdir }}" with "{{ arch_libdir }}"
fixed = template.replace("/usr/{{ arch_libdir }}", "{{ arch_libdir }}")

# Also fix LD_LIBRARY_PATH
fixed = fixed.replace(
    '"/lib:{{ arch_libdir }}:{{ arch_libdir }}:/usr/local/lib"',
    '"/lib:{{ arch_libdir }}:/usr/local/lib"',
)

print("Fixed template:")
print(fixed)

sftp = ssh.open_sftp()
with sftp.file("/home/judgeclient/tee-judge/python3.manifest.template", "w") as f:
    f.write(fixed)
sftp.close()

# Re-generate, sign, run
stdin, stdout, stderr = ssh.exec_command(
    "cd ~/tee-judge && "
    "gramine-manifest -Darch_libdir=/usr/lib/x86_64-linux-gnu -Dentrypoint=/usr/local/bin/python3.11 python3.manifest.template > python3.manifest 2>&1 && echo MANIFEST_OK || echo MANIFEST_FAIL",
    timeout=15,
)
out = stdout.read().decode()
print("Manifest:", out[-100:])

if "MANIFEST_OK" in out:
    stdin, stdout, stderr = ssh.exec_command(
        "cd ~/tee-judge && "
        "gramine-sgx-sign --manifest python3.manifest --output python3.manifest.sgx 2>&1 | tail -3 && echo SIGN_OK",
        timeout=30,
    )
    out = stdout.read().decode()
    print("Sign:", out[-200:])

    if "SIGN_OK" in out:
        stdin, stdout, stderr = ssh.exec_command(
            'cd ~/tee-judge && echo "{}" | gramine-sgx python3 2>&1', timeout=30
        )
        out = stdout.read().decode()
        for line in out.split("\n"):
            if "ENCLAVE_RESULT" in line:
                print("RESULT:", line)
                break
        else:
            print("No ENCLAVE_RESULT. Tail:")
            print(out[-500:])

ssh.close()
