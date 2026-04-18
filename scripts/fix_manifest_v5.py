"""Fix manifest: remove TEE_JUDGE_SEALED_KEY env override, use default /tmp path."""

import paramiko

HOST = "172.192.154.85"
USER = "judgeclient"
PASS = "judgeclient1234!!"


def sftp_write(remote_path, content):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)
    sftp = c.open_sftp()
    with sftp.file(remote_path, "w") as f:
        f.write(content)
    sftp.close()
    c.close()


def ssh_run(cmd, timeout=120):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode()
    c.close()
    if out:
        print(out[-2000:] if len(out) > 2000 else out, end="")


MANIFEST = r"""[libos]
entrypoint = "{{ entrypoint }}"

[loader]
entrypoint.uri = "file:{{ gramine.libos }}"
log_level = "error"
argv = ["python3", "/home/judgeclient/tee-judge/client/enclave_entry.py"]
env.LD_LIBRARY_PATH = "/lib:{{ arch_libdir }}:/usr/{{ arch_libdir }}:/usr/local/lib"
env.HOME = "/home/judgeclient"
env.PATH = "/usr/local/bin:/usr/bin:/bin"
env.PYTHONPATH = "/home/judgeclient/tee-judge"

[fs]
start_dir = "/home/judgeclient/tee-judge"

[[fs.mounts]]
uri = "file:{{ gramine.runtimedir() }}"
path = "/lib"
type = "chroot"

[[fs.mounts]]
uri = "file:{{ arch_libdir }}"
path = "{{ arch_libdir }}"
type = "chroot"

[[fs.mounts]]
uri = "file:/usr/{{ arch_libdir }}"
path = "/usr/{{ arch_libdir }}"
type = "chroot"

[[fs.mounts]]
uri = "file:/usr/local/lib/python3.11"
path = "/usr/local/lib/python3.11"
type = "chroot"

[[fs.mounts]]
uri = "file:/usr/local/lib"
path = "/usr/local/lib"
type = "chroot"

[[fs.mounts]]
uri = "file:/usr/local/bin/python3.11"
path = "/usr/local/bin/python3.11"
type = "chroot"

[[fs.mounts]]
uri = "file:/home/judgeclient/.local/lib/python3.11/site-packages"
path = "/home/judgeclient/.local/lib/python3.11/site-packages"
type = "chroot"

[[fs.mounts]]
uri = "file:/home/judgeclient/tee-judge"
path = "/home/judgeclient/tee-judge"
type = "chroot"

[[fs.mounts]]
uri = "file:/usr/bin"
path = "/usr/bin"
type = "chroot"

[[fs.mounts]]
uri = "file:/bin"
path = "/bin"
type = "chroot"

[[fs.mounts]]
uri = "file:/etc"
path = "/etc"
type = "chroot"

[sgx]
debug = false
edmm_enable = false
enclave_size = "1G"
max_threads = 8
remote_attestation = "dcap"

trusted_files = [
    "file:{{ entrypoint }}",
    "file:{{ gramine.libos }}",
    "file:{{ gramine.runtimedir() }}/",
    "file:{{ arch_libdir }}/",
    "file:/usr/{{ arch_libdir }}/",
    "file:/usr/local/lib/python3.11/",
    "file:/usr/local/bin/python3.11",
    "file:/home/judgeclient/.local/lib/python3.11/site-packages/",
    "file:/home/judgeclient/tee-judge/client/",
    "file:/etc/ld.so.cache",
    "file:/etc/resolv.conf",
    "file:/etc/hosts",
    "file:/etc/nsswitch.conf",
    "file:/etc/host.conf",
    "file:/etc/gai.conf",
]

allowed_files = [
    "file:/tmp/",
]
"""

print("=== Upload manifest ===")
sftp_write("/home/judgeclient/tee-judge/python3.manifest.template", MANIFEST)

# Delete old key so daemon + enclave start fresh with same key
print("\n=== Clean keys ===")
ssh_run("rm -f /tmp/.tee-judge-sealed-key.pem; echo done")

print("\n=== Build + sign ===")
ssh_run(
    "cd ~/tee-judge && gramine-manifest -Darch_libdir=/lib/x86_64-linux-gnu -Dentrypoint=/usr/local/bin/python3.11 python3.manifest.template python3.manifest && gramine-sgx-sign --manifest python3.manifest --output python3.manifest.sgx 2>&1 | tail -2"
)

print("\n=== Done ===")
