#!/usr/bin/env python3
"""CrackSentinel HomeServer 24/7 Tunnel Bridge Daemon (KlipForge-hardened pattern).

- Runs `cloudflared tunnel --no-autoupdate --protocol http2 --url http://127.0.0.1:8797`
- Continuously drains cloudflared stdout in a daemon thread (never deadlocks pipe buffer)
- Waits for BOTH tunnel URL AND "Registered tunnel connection"
- Uses Cloudflare 1.1.1.1 DoH + curl --resolve for readiness/health probes and edge registration
  so ISP/MagicDNS negative caching NEVER causes false restarts or registration failures
- Re-registers every 6 hours and self-heals on 3 consecutive probe failures
"""

import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

ROOT = pathlib.Path(os.environ.get("SENTINEL_ROOT", os.path.dirname(os.path.abspath(__file__))))
LOCAL_URL = os.environ.get("SENTINEL_LOCAL_URL", "http://127.0.0.1:8797").rstrip("/")
EDGE_URL = os.environ.get("SENTINEL_EDGE_URL", "https://sentinel.breakthematrix.id").rstrip("/")
BRIDGE_SECRET = os.environ.get("BRIDGE_SECRET", "").strip()
CLOUDFLARED = os.environ.get("CLOUDFLARED_BIN", "/usr/local/bin/cloudflared")
STATE_FILE = ROOT / ".tunnel-url"
TUNNEL_RE = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com", re.IGNORECASE)

stop_flag = False
child_proc = None


def handle_sig(*_):
    global stop_flag
    stop_flag = True
    if child_proc and child_proc.poll() is None:
        try:
            child_proc.terminate()
        except Exception:
            pass


signal.signal(signal.SIGTERM, handle_sig)
signal.signal(signal.SIGINT, handle_sig)


def check_local_engine(timeout=5):
    try:
        with urllib.request.urlopen(f"{LOCAL_URL}/api/health", timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def doh_resolve_a(host):
    url = f"https://1.1.1.1/dns-query?name={urllib.parse.quote(host)}&type=A"
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": "curl/8.5.0"})
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for ans in data.get("Answer", []):
                if ans.get("type") == 1 and ans.get("data"):
                    return ans["data"]
    except Exception:
        pass
    return ""


def check_tunnel_url(tunnel_url, timeout=10):
    host = urllib.parse.urlparse(tunnel_url).hostname or ""
    if not host:
        return False
    ip = doh_resolve_a(host)
    if not ip:
        return False
    try:
        proc = subprocess.run(
            [
                "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                "--max-time", str(timeout),
                "--resolve", f"{host}:443:{ip}",
                "-A", "CrackSentinel-Bridge/1.0",
                f"{tunnel_url}/api/health",
            ],
            text=True,
            capture_output=True,
            timeout=timeout + 3,
        )
        return proc.returncode == 0 and proc.stdout.strip() == "200"
    except Exception:
        return False


def register_origin(tunnel_url):
    edge_host = urllib.parse.urlparse(EDGE_URL).hostname or ""
    ip = doh_resolve_a(edge_host)
    body = json.dumps({"origin": tunnel_url})
    # Pass secret via stdin curl config (-K -) so secret never appears in ps args
    cfg = f'header = "X-Bridge-Secret: {BRIDGE_SECRET}"\nheader = "Content-Type: application/json"\nheader = "User-Agent: CrackSentinel-Bridge/1.0"\n'
    cmd = ["curl", "-sS", "--max-time", "15", "-X", "POST", "-K", "-", "--data-raw", body]
    if ip:
        cmd += ["--resolve", f"{edge_host}:443:{ip}"]
    cmd.append(f"{EDGE_URL}/_edge-register")
    for attempt in range(1, 6):
        try:
            proc = subprocess.run(cmd, input=cfg, text=True, capture_output=True, timeout=20)
            if proc.returncode == 0:
                data = json.loads(proc.stdout.strip() or "{}")
                if data.get("ok"):
                    return True, data
            print(f"[SentinelBridge] register attempt {attempt} failed: rc={proc.returncode} out={proc.stdout.strip()[:120]}", flush=True)
        except Exception as e:
            print(f"[SentinelBridge] register attempt {attempt} error: {e}", flush=True)
        time.sleep(3)
    return False, None


def run_once():
    global child_proc

    for _ in range(30):
        if stop_flag:
            return
        if check_local_engine(timeout=4):
            break
        time.sleep(1)

    print(f"[SentinelBridge] Starting cloudflared tunnel (http2) -> {LOCAL_URL}", flush=True)
    child_proc = subprocess.Popen(
        [CLOUDFLARED, "tunnel", "--no-autoupdate", "--protocol", "http2", "--url", LOCAL_URL],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    state = {"url": "", "registered_conn": False}
    ev_ready = threading.Event()

    def reader(pipe):
        try:
            for line in pipe:
                if not state["url"]:
                    m = TUNNEL_RE.search(line)
                    if m:
                        state["url"] = m.group(0)
                        print("[SentinelBridge] Tunnel URL acquired:", state["url"], flush=True)
                if "Registered tunnel connection" in line:
                    if not state["registered_conn"]:
                        state["registered_conn"] = True
                        print("[SentinelBridge] Edge tunnel connection established", flush=True)
                if state["url"] and state["registered_conn"]:
                    ev_ready.set()
        except Exception:
            pass

    threading.Thread(target=reader, args=(child_proc.stdout,), daemon=True).start()

    ev_ready.wait(timeout=45)
    tunnel_url = state["url"]
    if not tunnel_url or not state["registered_conn"] or child_proc.poll() is not None:
        print("[SentinelBridge] Failed to establish tunnel connection, restarting...", flush=True)
        try:
            child_proc.terminate()
            child_proc.wait(timeout=5)
        except Exception:
            try:
                child_proc.kill()
            except Exception:
                pass
        return

    ready = False
    for _ in range(20):
        if stop_flag or child_proc.poll() is not None:
            return
        if check_tunnel_url(tunnel_url, timeout=10):
            ready = True
            break
        time.sleep(2)

    if not ready:
        print("[SentinelBridge] Tunnel failed 1.1.1.1 DoH probe, restarting...", flush=True)
        child_proc.terminate()
        return

    ok, res = register_origin(tunnel_url)
    if ok:
        try:
            STATE_FILE.write_text(tunnel_url + "\n", encoding="utf-8")
        except Exception:
            pass
        print("[SentinelBridge] Registered origin:", res, flush=True)
    else:
        print("[SentinelBridge] Registration failed, restarting...", flush=True)
        child_proc.terminate()
        return

    fails = 0
    last_reg = time.time()
    while not stop_flag:
        if child_proc.poll() is not None:
            print("[SentinelBridge] cloudflared exited:", child_proc.returncode, flush=True)
            return
        time.sleep(45)
        if stop_flag:
            break
        if check_tunnel_url(tunnel_url, timeout=10):
            fails = 0
            if time.time() - last_reg >= 21600:
                ok2, _ = register_origin(tunnel_url)
                if ok2:
                    last_reg = time.time()
        else:
            fails += 1
            print(f"[SentinelBridge] Health check failed ({fails}/3)", flush=True)
            if fails >= 3:
                print("[SentinelBridge] 3 consecutive failures -> restarting cloudflared", flush=True)
                child_proc.terminate()
                try:
                    child_proc.wait(timeout=8)
                except Exception:
                    child_proc.kill()
                return


def main():
    if not BRIDGE_SECRET:
        print("[SentinelBridge] ERROR: BRIDGE_SECRET env var missing", file=sys.stderr, flush=True)
        sys.exit(1)
    while not stop_flag:
        try:
            run_once()
        except Exception as e:
            print("[SentinelBridge] Unexpected error:", e, flush=True)
        if not stop_flag:
            time.sleep(4)


if __name__ == "__main__":
    main()
