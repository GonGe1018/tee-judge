import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(
    "172.192.154.85", username="judgeclient", password="judgeclient1234!!", timeout=10
)

# Read current template
stdin, stdout, stderr = ssh.exec_command(
    "cat ~/tee-judge/python3.manifest.template", timeout=5
)
template = stdout.read().decode()

# Add /usr/include mount and trusted_files entry
# Insert mount before the [sgx] section
mount_entry = """
[[fs.mounts]]
uri = "file:/usr/include"
path = "/usr/include"
type = "chroot"
"""

# Add to trusted_files
# Insert before the closing ]
template = template.replace(
    '[[fs.mounts]]\nuri = "file:/etc"',
    '[[fs.mounts]]\nuri = "file:/usr/include"\npath = "/usr/include"\ntype = "chroot"\n\n[[fs.mounts]]\nuri = "file:/etc"',
)

# Add to trusted_files list
template = template.replace(
    '    "file:/etc/gai.conf",\n]',
    '    "file:/etc/gai.conf",\n    "file:/usr/include/",\n]',
)

print("Updated template (relevant parts):")
for line in template.split("\n"):
    if "include" in line.lower() or "gai" in line:
        print(f"  {line}")

sftp = ssh.open_sftp()
with sftp.file("/home/judgeclient/tee-judge/python3.manifest.template", "w") as f:
    f.write(template)
sftp.close()

# Re-sign
stdin, stdout, stderr = ssh.exec_command(
    "cd ~/tee-judge && "
    "gramine-manifest -Darch_libdir=/usr/lib/x86_64-linux-gnu -Dentrypoint=/usr/local/bin/python3.11 python3.manifest.template > python3.manifest 2>&1 && "
    "gramine-sgx-sign --manifest python3.manifest --output python3.manifest.sgx 2>&1 | tail -3 && echo SIGN_OK",
    timeout=60,
)
out = stdout.read().decode()
print("Sign:", out[-300:])

if "SIGN_OK" in out:
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
