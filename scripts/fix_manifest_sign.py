import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

# Fix the manifest template URI issue and re-sign
# The problem is "file:/usr//usr/lib/x86_64-linux-gnu/" - double path
# This happens because arch_libdir already includes the full path

# Read current template
stdin, stdout, stderr = ssh.exec_command(
    "cat ~/tee-judge/python3.manifest.template", timeout=5
)
template = stdout.read().decode()
print("Current template trusted_files section:")
for line in template.split("\n"):
    if "usr" in line and "trusted" not in line.lower():
        print(f"  {line}")

# The issue: "file:/usr/{{ arch_libdir }}/" where arch_libdir = "/usr/lib/x86_64-linux-gnu"
# Results in "file:/usr//usr/lib/x86_64-linux-gnu/"
# Fix: change to "file:{{ arch_libdir }}/" in trusted_files

# Fix the template
fixed = template.replace(
    '"file:/usr/{{ arch_libdir }}/"',
    '"file:{{ arch_libdir }}/"',  # arch_libdir already has full path
)

# Write fixed template
sftp = ssh.open_sftp()
with sftp.file("/home/judgeclient/tee-judge/python3.manifest.template", "w") as f:
    f.write(fixed)
sftp.close()

# Now re-generate and sign
stdin, stdout, stderr = ssh.exec_command(
    "cd ~/tee-judge && "
    "gramine-manifest -Darch_libdir=/usr/lib/x86_64-linux-gnu -Dentrypoint=/usr/local/bin/python3.11 python3.manifest.template > python3.manifest 2>&1 && echo MANIFEST_OK",
    timeout=15,
)
out = stdout.read().decode()
print("Manifest gen:", out[-200:])

if "MANIFEST_OK" in out:
    stdin, stdout, stderr = ssh.exec_command(
        "cd ~/tee-judge && "
        "gramine-sgx-sign --manifest python3.manifest --output python3.manifest.sgx 2>&1 && echo SIGN_OK",
        timeout=30,
    )
    out = stdout.read().decode()
    print("Sign:", out[-200:])

ssh.close()
