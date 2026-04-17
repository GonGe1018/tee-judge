"""2-phase SGX Judge Client daemon - WebSocket notifications + HTTP data fetch.

Connects to server via WebSocket for instant task notifications.
Falls back to HTTP polling if WebSocket is unavailable.
"""

import sys
import os
import json
import subprocess
import tempfile
import time
import logging
import getpass
import threading

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)

from client.enclave_judge import host_compile_and_run, enclave_verify_and_sign
import requests

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("judge-daemon")

SERVER = os.environ.get("TEE_JUDGE_SERVER", "http://127.0.0.1:8000")
POLL_INTERVAL = int(os.environ.get("TEE_JUDGE_POLL_INTERVAL", "2"))
SGX_ENABLED = os.path.exists("/dev/sgx_enclave")


# --- Authentication ---


def authenticate(server: str) -> str:
    """Login or register and return auth token."""
    token = os.environ.get("TEE_JUDGE_TOKEN", "")
    if token:
        log.info("Using token from TEE_JUDGE_TOKEN")
        return token

    token_file = os.path.expanduser("~/.tee-judge-token")
    if os.path.exists(token_file):
        with open(token_file) as f:
            saved = json.load(f)
        try:
            r = requests.get(
                f"{server}/api/judge/poll",
                headers={"Authorization": f"Bearer {saved['token']}"},
                timeout=5,
            )
            if r.status_code != 401:
                log.info(f"Logged in as {saved['username']} (saved token)")
                return saved["token"]
        except Exception:
            pass

    print("\n=== TEE-Judge Authentication ===")
    print("1. Login")
    print("2. Register")
    choice = input("Choose (1/2): ").strip()

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    if choice == "2":
        r = requests.post(
            f"{server}/api/auth/register",
            json={
                "username": username,
                "password": password,
            },
        )
        if r.status_code == 409:
            print("Username already taken. Trying login...")
            r = requests.post(
                f"{server}/api/auth/login",
                json={
                    "username": username,
                    "password": password,
                },
            )
    else:
        r = requests.post(
            f"{server}/api/auth/login",
            json={
                "username": username,
                "password": password,
            },
        )

    if r.status_code != 200:
        log.error(f"Authentication failed: {r.json().get('detail', r.text)}")
        sys.exit(1)

    data = r.json()
    token = data["token"]

    with open(token_file, "w") as f:
        json.dump(
            {"token": token, "username": data["username"], "user_id": data["user_id"]},
            f,
        )
    os.chmod(token_file, 0o600)

    log.info(f"Authenticated as {data['username']} (#{data['user_id']})")
    return token


# --- SGX Judging ---


def judge_in_sgx(task, hr):
    """Run enclave verification inside SGX using unique temp files."""
    with tempfile.TemporaryDirectory(prefix="tee-enclave-") as tmpdir:
        task_path = os.path.join(tmpdir, "task.json")
        hr_path = os.path.join(tmpdir, "hr.json")
        result_path = os.path.join(tmpdir, "result.json")

        with open(task_path, "w") as f:
            json.dump(task, f)
        with open(hr_path, "w") as f:
            json.dump(hr, f)

        enc_script = (
            "import sys,os,json\n"
            f"sys.path.insert(0,{PROJECT_DIR!r})\n"
            f"os.chdir({PROJECT_DIR!r})\n"
            "from client.enclave_judge import enclave_verify_and_sign\n"
            f"task=json.load(open({task_path!r}))\n"
            f"hr=json.load(open({hr_path!r}))\n"
            "r=enclave_verify_and_sign(task,hr)\n"
            f"json.dump(r,open({result_path!r},'w'))\n"
        )
        script_path = os.path.join(tmpdir, "enc_run.py")
        with open(script_path, "w") as f:
            f.write(enc_script)

        proc = subprocess.run(
            ["gramine-sgx", "python3", script_path],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=PROJECT_DIR,
        )

        if os.path.exists(result_path):
            with open(result_path) as f:
                return json.load(f)

        log.error(f"Enclave returned no result. stderr: {proc.stderr[-300:]}")
        return None


def judge_native(task, hr):
    """Run verification natively (no SGX)."""
    return enclave_verify_and_sign(task, hr)


# --- Task Processing ---


def process_task(headers: dict):
    """Fetch and process one task via HTTP."""
    res = requests.get(f"{SERVER}/api/judge/poll", headers=headers, timeout=10)

    if res.status_code == 401:
        log.error("Token expired")
        return "auth_error"

    task = res.json().get("task")
    if not task:
        return "no_task"

    sid = task["submission_id"]
    tc_count = len(task["testcases"])
    log.info(f"Task: submission #{sid}, {tc_count} testcases")

    # Phase 1: Host compile + run
    hr = host_compile_and_run(task)
    if hr["status"] == "CE":
        log.info("  Phase 1: CE")
    else:
        log.info(f"  Phase 1: {len(hr['outputs'])} tests executed")

    # Phase 2: Enclave verify + sign
    enclave_task = {**task, "testcases": task["enclave_testcases"]}
    del enclave_task["enclave_testcases"]

    if SGX_ENABLED:
        result = judge_in_sgx(enclave_task, hr)
    else:
        result = judge_native(enclave_task, hr)

    if result:
        att = json.loads(result["attestation_quote"])
        log.info(
            f"  Phase 2: {result['verdict']} ({result['test_passed']}/{result['test_total']}) "
            f"[{att.get('sgx_mode', 'unknown')}]"
        )
        requests.post(
            f"{SERVER}/api/judge/report", json=result, headers=headers, timeout=10
        )
        log.info(f"  Reported: {result['verdict']}")
    else:
        log.error(f"  Enclave returned no result for #{sid}")

    return "done"


# --- WebSocket Mode ---


def run_websocket(token: str, headers: dict):
    """Connect via WebSocket and process tasks on notification."""
    try:
        import websocket
    except ImportError:
        log.warning("websocket-client not installed. pip install websocket-client")
        return False

    ws_url = (
        SERVER.replace("http://", "ws://").replace("https://", "wss://") + "/ws/judge"
    )
    log.info(f"Connecting WebSocket: {ws_url}")

    ws = None
    try:
        ws = websocket.create_connection(ws_url, timeout=10)

        # Send auth
        ws.send(json.dumps({"token": f"Bearer {token}"}))

        # Wait for welcome
        welcome = json.loads(ws.recv())
        if welcome.get("type") != "connected":
            log.error(f"WS auth failed: {welcome}")
            return False

        log.info(f"WebSocket connected (user #{welcome.get('user_id')})")

        # Main loop: wait for notifications
        ws.settimeout(35)  # slightly longer than server ping interval
        while True:
            try:
                raw = ws.recv()
                if not raw:
                    continue
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                if msg.get("type") == "ping":
                    ws.send(json.dumps({"type": "pong"}))
                    continue

                if msg.get("type") == "new_task":
                    log.info(
                        f"WS notification: new task (submission #{msg.get('submission_id')})"
                    )
                    result = process_task(headers)
                    if result == "auth_error":
                        return False
                    continue

                if msg.get("type") == "pong":
                    continue

            except websocket.WebSocketTimeoutException:
                # Send heartbeat
                try:
                    ws.send(json.dumps({"type": "ping"}))
                except Exception:
                    log.warning("WS heartbeat failed, reconnecting...")
                    return True  # Signal to reconnect

    except Exception as e:
        log.warning(f"WebSocket error: {e}")
        return True  # Signal to reconnect
    finally:
        if ws:
            try:
                ws.close()
            except Exception:
                pass


# --- Polling Fallback ---


def run_polling(token: str, headers: dict):
    """Fallback: poll server for tasks."""
    log.info("Running in polling mode")
    while True:
        try:
            result = process_task(headers)
            if result == "auth_error":
                return
            if result == "no_task":
                time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            break
        except Exception as e:
            log.error(f"Error: {e}")
            time.sleep(POLL_INTERVAL)


# --- Main ---


def main():
    log.info(f"Server: {SERVER}")
    log.info(f"SGX: {'enabled' if SGX_ENABLED else 'disabled (mock mode)'}")

    token = authenticate(SERVER)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # Try WebSocket first, fall back to polling
    ws_available = True
    try:
        import websocket
    except ImportError:
        log.info("websocket-client not installed, using polling mode")
        ws_available = False

    if ws_available:
        reconnect_delay = 1
        while True:
            try:
                should_reconnect = run_websocket(token, headers)
                if should_reconnect:
                    log.info(f"Reconnecting in {reconnect_delay}s...")
                    time.sleep(reconnect_delay)
                    reconnect_delay = min(reconnect_delay * 2, 30)
                else:
                    # Auth error or clean exit
                    break
            except KeyboardInterrupt:
                log.info("Stopped.")
                break
    else:
        try:
            run_polling(token, headers)
        except KeyboardInterrupt:
            log.info("Stopped.")


if __name__ == "__main__":
    main()
