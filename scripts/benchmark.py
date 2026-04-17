"""Performance benchmark: native vs SGX enclave execution."""

import paramiko
import time

HOST = "***REMOVED***"
USER = "judgeclient"
PASS = "***REMOVED***"


def ssh_run(cmd, timeout=300):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASS, timeout=10)
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode()
    err = stderr.read().decode()
    code = stdout.channel.recv_exit_status()
    client.close()
    if out:
        print(out[-8000:] if len(out) > 8000 else out, end="")
    if err:
        for line in err.split("\n"):
            if line.strip() and not any(
                x in line
                for x in [
                    "insecure",
                    "Gramine detected",
                    "---",
                    "Gramine will continue",
                    "debug enclave",
                    "cmdline_argv",
                    "allowed_files",
                    "Gramine is starting",
                    "Parsing TOML",
                ]
            ):
                print(line)
    return code


def sftp_write(remote_path, content):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASS, timeout=10)
    sftp = client.open_sftp()
    with sftp.file(remote_path, "w") as f:
        f.write(content)
    sftp.close()
    client.close()


# Fresh start
print("=" * 60)
print("  TEE-Judge Performance Benchmark")
print("  Native vs SGX Enclave")
print("=" * 60)

ssh_run(
    "pkill -f uvicorn 2>/dev/null; sleep 1; rm -f ~/tee-judge/data/judge.db*; echo cleaned"
)

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=USER, password=PASS, timeout=10)
c.exec_command(
    "cd ~/tee-judge && python3.11 -m uvicorn server.main:app --host 127.0.0.1 --port 8000 &>/tmp/server.log &"
)
c.close()
time.sleep(5)

BENCH_SCRIPT = r'''import sys, os, json, subprocess, time, statistics
sys.path.insert(0, '/home/judgeclient/tee-judge')
os.chdir('/home/judgeclient/tee-judge')
from client.enclave_judge import host_compile_and_run, enclave_verify_and_sign
import requests

SERVER = "http://127.0.0.1:8000"
RUNS = 5  # Number of runs for each benchmark

code_ac = '#include <stdio.h>\nint main(){int a,b;scanf("%d %d",&a,&b);printf("%d",a+b);return 0;}'

def bench_native():
    """Benchmark: compile + run + verify all natively (no SGX)."""
    sid = requests.post(f'{SERVER}/api/submit', json={'problem_id':1000,'language':'c','code':code_ac}).json()['submission_id']
    task = requests.get(f'{SERVER}/api/judge/poll').json()['task']

    start = time.perf_counter()
    hr = host_compile_and_run(task)
    result = enclave_verify_and_sign(task, hr)  # runs locally, no SGX
    elapsed = time.perf_counter() - start

    requests.post(f'{SERVER}/api/judge/report', json=result)
    return elapsed, result['verdict'], result['test_passed'], result['test_total']

def bench_sgx():
    """Benchmark: compile on host + verify in SGX enclave."""
    sid = requests.post(f'{SERVER}/api/submit', json={'problem_id':1000,'language':'c','code':code_ac}).json()['submission_id']
    task = requests.get(f'{SERVER}/api/judge/poll').json()['task']

    start_total = time.perf_counter()

    # Phase 1: Host
    start_p1 = time.perf_counter()
    hr = host_compile_and_run(task)
    p1_time = time.perf_counter() - start_p1

    # Phase 2: SGX Enclave
    start_p2 = time.perf_counter()
    with open('/tmp/enc_task.json','w') as f: json.dump(task,f)
    with open('/tmp/enc_hr.json','w') as f: json.dump(hr,f)
    enc = (
        'import sys,os,json\n'
        'sys.path.insert(0,"/home/judgeclient/tee-judge")\n'
        'os.chdir("/home/judgeclient/tee-judge")\n'
        'from client.enclave_judge import enclave_verify_and_sign\n'
        'task=json.load(open("/tmp/enc_task.json"))\n'
        'hr=json.load(open("/tmp/enc_hr.json"))\n'
        'r=enclave_verify_and_sign(task,hr)\n'
        'json.dump(r,open("/tmp/enc_result.json","w"))\n'
    )
    with open('/tmp/enc_run.py','w') as f: f.write(enc)
    subprocess.run(['gramine-sgx','python3','/tmp/enc_run.py'],
        capture_output=True,text=True,timeout=120,cwd='/home/judgeclient/tee-judge')
    p2_time = time.perf_counter() - start_p2

    total_time = time.perf_counter() - start_total

    result = json.load(open('/tmp/enc_result.json'))
    requests.post(f'{SERVER}/api/judge/report', json=result)
    return total_time, p1_time, p2_time, result['verdict']

# ============================================================
# Benchmark: Native (no SGX)
# ============================================================
print("\n" + "=" * 60)
print("  Benchmark 1: Native Execution (no SGX)")
print(f"  {RUNS} runs, Problem 1000 (A+B), 30 testcases")
print("=" * 60)

native_times = []
for i in range(RUNS):
    elapsed, verdict, passed, total = bench_native()
    native_times.append(elapsed)
    print(f"  Run {i+1}: {elapsed*1000:.1f}ms ({verdict} {passed}/{total})")

native_avg = statistics.mean(native_times) * 1000
native_std = statistics.stdev(native_times) * 1000 if len(native_times) > 1 else 0
print(f"\n  Average: {native_avg:.1f}ms (std: {native_std:.1f}ms)")

# ============================================================
# Benchmark: SGX Enclave
# ============================================================
print("\n" + "=" * 60)
print("  Benchmark 2: SGX Enclave Execution (2-phase)")
print(f"  {RUNS} runs, Problem 1000 (A+B), 30 testcases")
print("=" * 60)

sgx_times = []
p1_times = []
p2_times = []
for i in range(RUNS):
    total, p1, p2, verdict = bench_sgx()
    sgx_times.append(total)
    p1_times.append(p1)
    p2_times.append(p2)
    print(f"  Run {i+1}: {total*1000:.1f}ms (P1:{p1*1000:.1f}ms P2:{p2*1000:.1f}ms) [{verdict}]")

sgx_avg = statistics.mean(sgx_times) * 1000
sgx_std = statistics.stdev(sgx_times) * 1000 if len(sgx_times) > 1 else 0
p1_avg = statistics.mean(p1_times) * 1000
p2_avg = statistics.mean(p2_times) * 1000

print(f"\n  Total Average:   {sgx_avg:.1f}ms (std: {sgx_std:.1f}ms)")
print(f"  Phase 1 (Host):  {p1_avg:.1f}ms")
print(f"  Phase 2 (SGX):   {p2_avg:.1f}ms")

# ============================================================
# Comparison
# ============================================================
print("\n" + "=" * 60)
print("  PERFORMANCE COMPARISON")
print("=" * 60)
overhead = sgx_avg - native_avg
overhead_pct = (overhead / native_avg) * 100 if native_avg > 0 else 0
print(f"  Native Average:     {native_avg:.1f}ms")
print(f"  SGX Average:        {sgx_avg:.1f}ms")
print(f"  Overhead:           {overhead:.1f}ms ({overhead_pct:.1f}%)")
print(f"  Phase 1 (Host):     {p1_avg:.1f}ms (compile + run)")
print(f"  Phase 2 (Enclave):  {p2_avg:.1f}ms (verify + sign + attestation)")
print(f"  Enclave startup is the main overhead (Python + Gramine init)")
print("=" * 60)
'''

sftp_write("/tmp/benchmark.py", BENCH_SCRIPT)
print("\n=== Running Benchmark ===")
ssh_run("cd ~/tee-judge && python3.11 /tmp/benchmark.py", timeout=600)

# Cleanup
print("\n=== Cleanup ===")
ssh_run("pkill -f uvicorn 2>/dev/null; echo done")

print("\n=== DONE ===")
