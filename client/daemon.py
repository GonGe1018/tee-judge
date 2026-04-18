"""2-phase SGX Judge Client daemon — v4 full enclave execution.

Security model (v4):
- Server sends code + testcase inputs (no expected outputs)
- Enclave compiles + runs code via libtcc (host never sees inputs/outputs)
- Enclave signs outputs hash + attestation quote
- Server compares actual vs expected, determines verdict
- Testcase inputs are protected inside enclave memory
"""

import sys
import os
import json
import subprocess
import tempfile
import time
import logging
import getpass

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)

from client.enclave_judge import host_compile_and_run, enclave_hash_and_sign
from client.enclave_keys import load_or_create_keypair
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


def register_public_key(server: str, headers: dict, public_key_pem: str):
    """Register enclave's public key with server (ECDSA or RA-TLS)."""
    try:
        r = requests.post(
            f"{server}/api/auth/register-enclave-key",
            json={"public_key": public_key_pem},
            headers=headers,
            timeout=10,
        )
        if r.status_code == 200:
            log.info("Enclave public key registered with server")
        elif r.status_code == 409:
            log.info("Enclave public key already registered")
        else:
            log.warning(
                f"Failed to register public key: {r.status_code} {r.text[:200]}"
            )
    except Exception as e:
        log.warning(f"Failed to register public key: {e}")


def get_enclave_public_key_in_sgx() -> str:
    """Get RA-TLS public key from inside SGX enclave."""
    enc_script = (
        "import sys,os,json\n"
        f"sys.path.insert(0,{PROJECT_DIR!r})\n"
        f"os.chdir({PROJECT_DIR!r})\n"
        "from client.ratls_keys import get_ratls_public_key_pem\n"
        "print('RATLS_PUBKEY:'+get_ratls_public_key_pem())\n"
    )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", prefix="tee-init-", delete=False, dir="/tmp"
    ) as f:
        f.write(enc_script)
        script_path = f.name

    try:
        proc = subprocess.run(
            ["gramine-sgx", "python3", script_path],
            input="{}",
            capture_output=True,
            text=True,
            timeout=60,
            cwd=PROJECT_DIR,
            env={**os.environ},
        )
        for line in proc.stdout.split("\n"):
            if line.startswith("RATLS_PUBKEY:"):
                return line[len("RATLS_PUBKEY:") :]
        log.error(f"Failed to get RA-TLS key. stderr: {proc.stderr[-300:]}")
        return None
    finally:
        try:
            os.unlink(script_path)
        except Exception:
            pass


# --- SGX Judging (stdin/stdout — TOCTOU-safe) ---


def judge_in_sgx(task, hr=None):
    """Run inside SGX enclave. v4: full execution with RA-TLS keys."""
    if hr is None:
        # v4: full enclave execution — enclave uses its own RA-TLS key
        input_data = json.dumps({"task": task})
    else:
        # v3 fallback: host already ran, enclave just signs
        from client.enclave_keys import SEALED_KEY_PATH
        from pathlib import Path

        key_pem = Path(SEALED_KEY_PATH).read_text()
        input_data = json.dumps(
            {
                "task": task,
                "host_results": hr,
                "private_key_pem": key_pem,
            }
        )

    # Enclave script reads from stdin, writes result to stdout
    enc_script = (
        "import sys,os,json\n"
        f"sys.path.insert(0,{PROJECT_DIR!r})\n"
        f"os.chdir({PROJECT_DIR!r})\n"
        "from client.enclave_judge import enclave_compile_run_and_sign, enclave_hash_and_sign\n"
        "data=json.loads(sys.stdin.read())\n"
        "if 'private_key_pem' in data: os.environ['_TEE_JUDGE_PRIVATE_KEY_PEM']=data['private_key_pem']\n"
        "if 'host_results' in data:\n"
        "    r=enclave_hash_and_sign(data['task'],data['host_results'])\n"
        "else:\n"
        "    r=enclave_compile_run_and_sign(data['task'])\n"
        "print('ENCLAVE_RESULT:'+json.dumps(r))\n"
    )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", prefix="tee-enc-", delete=False, dir="/tmp"
    ) as f:
        f.write(enc_script)
        script_path = f.name

    try:
        proc = subprocess.run(
            ["gramine-sgx", "python3", script_path],
            input=input_data,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=PROJECT_DIR,
            env={**os.environ},
        )

        # Parse result from stdout
        for line in proc.stdout.split("\n"):
            if line.startswith("ENCLAVE_RESULT:"):
                return json.loads(line[len("ENCLAVE_RESULT:") :])

        log.error(f"Enclave returned no result. stdout: {proc.stdout[-300:]}")
        log.error(f"stderr: {proc.stderr[-300:]}")
        return None
    finally:
        try:
            os.unlink(script_path)
        except Exception:
            pass


def judge_native(task, hr=None):
    """Run natively (no SGX). v4: full execution, v3 fallback: hash+sign."""
    if hr is None:
        from client.enclave_judge import enclave_compile_run_and_sign

        return enclave_compile_run_and_sign(task)
    else:
        return enclave_hash_and_sign(task, hr)


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
    tc_count = len(task.get("testcases") or []) or (
        "encrypted" if task.get("encrypted_testcases") else 0
    )
    log.info(
        f"Task: submission #{sid}, testcases={'encrypted' if task.get('encrypted_testcases') else tc_count}"
    )

    if SGX_ENABLED:
        # v4: Full enclave execution — host never sees inputs/outputs
        log.info("  v4 mode: full enclave execution (libtcc)")
        result = judge_in_sgx(task)
    else:
        # Non-SGX: try libtcc native, fallback to host compile + enclave sign
        try:
            from client.tcc_runner import compile_and_run_all

            log.info("  v4 mode: native libtcc execution")
            result = judge_native(task)
        except (ImportError, OSError):
            # libtcc not available — fallback to v3 (host compile + enclave sign)
            log.info("  v3 fallback: host compile + enclave sign")
            hr = host_compile_and_run(task)
            if hr["status"] == "CE":
                log.info("  Phase 1: CE")
            else:
                log.info(f"  Phase 1: {len(hr['outputs'])} tests executed")
            result = judge_native(task, hr)

    if result:
        att = json.loads(result["attestation_quote"])
        log.info(
            f"  Result: outputs_hash={result['outputs_hash'][:16]}... "
            f"[{att.get('sgx_mode', 'unknown')}]"
        )
        resp = requests.post(
            f"{SERVER}/api/judge/report", json=result, headers=headers, timeout=30
        )
        server_verdict = (
            resp.json().get("verdict", "?")
            if resp.status_code == 200
            else f"ERROR {resp.status_code}"
        )
        log.info(f"  Server verdict: {server_verdict}")
    else:
        log.error(f"  Enclave returned no result for #{sid}")

    return "done"


# --- WebSocket Mode ---


def run_websocket(token: str, headers: dict):
    """Connect via WebSocket and process tasks on notification."""
    try:
        import websocket
    except ImportError:
        log.warning("websocket-client not installed")
        return False

    ws_url = (
        SERVER.replace("http://", "ws://").replace("https://", "wss://") + "/ws/judge"
    )
    log.info(f"Connecting WebSocket: {ws_url}")

    ws = None
    try:
        ws = websocket.create_connection(ws_url, timeout=10)
        ws.send(json.dumps({"token": f"Bearer {token}"}))

        welcome = json.loads(ws.recv())
        if welcome.get("type") != "connected":
            log.error(f"WS auth failed: {welcome}")
            return False

        log.info(f"WebSocket connected (user #{welcome.get('user_id')})")

        ws.settimeout(35)
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
                try:
                    ws.send(json.dumps({"type": "ping"}))
                except Exception:
                    log.warning("WS heartbeat failed, reconnecting...")
                    return True

    except Exception as e:
        log.warning(f"WebSocket error: {e}")
        return True
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

    # Register enclave public key
    if SGX_ENABLED:
        # v4: get RA-TLS public key from inside enclave (key never leaves enclave)
        log.info("Getting RA-TLS public key from SGX enclave...")
        public_key_pem = get_enclave_public_key_in_sgx()
        if public_key_pem:
            log.info("RA-TLS public key obtained from enclave")
            register_public_key(SERVER, headers, public_key_pem)
        else:
            log.warning("Failed to get RA-TLS key, falling back to ECDSA")
            _, public_key_pem = load_or_create_keypair()
            register_public_key(SERVER, headers, public_key_pem)
    else:
        # Non-SGX: use ECDSA key (dev/mock mode)
        _, public_key_pem = load_or_create_keypair()
        log.info(f"Enclave key pair loaded (public key: {public_key_pem[:40]}...)")
        register_public_key(SERVER, headers, public_key_pem)

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
