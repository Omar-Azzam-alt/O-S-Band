from flask import Flask, jsonify, request, Response
from pathlib import Path
import os
import signal
import socket
import time

app = Flask(__name__)

DEFAULT_VAULT = Path.home() / "Desktop" / "obb-circuit-breaker-isef-edition" / "captured_threat_dossiers"
VAULT_DIR = Path(os.environ.get("OBB_VAULT_DIR", str(DEFAULT_VAULT)))
ALARM_FILE = Path(os.environ.get("OBB_ALARM_FILE", "/tmp/obb_alarm"))
PID_FILE = Path(os.environ.get("OBB_PID_FILE", "/tmp/obb_target.pid"))
API_TOKEN = os.environ.get("OBB_API_TOKEN", "isef-lab-token")
THRESHOLD_PCT = float(os.environ.get("OBB_THRESHOLD_PCT", "90.0"))
PORT = int(os.environ.get("OBB_PORT", "5000"))


def read_physical_memory() -> dict:
    mem_kb = {}
    with open("/proc/meminfo", "r", encoding="utf-8") as f:
        for line in f:
            if ":" in line:
                key, rest = line.split(":", 1)
                parts = rest.strip().split()
                if parts and parts[0].isdigit():
                    mem_kb[key.strip()] = int(parts[0])

    total_kb = mem_kb.get("MemTotal", 0)
    avail_kb = mem_kb.get("MemAvailable", mem_kb.get("MemFree", 0))
    free_kb = mem_kb.get("MemFree", 0)
    buffers_kb = mem_kb.get("Buffers", 0)
    cached_kb = mem_kb.get("Cached", 0)
    swap_total_kb = mem_kb.get("SwapTotal", 0)
    swap_free_kb = mem_kb.get("SwapFree", 0)

    used_kb = max(0, total_kb - avail_kb)
    ram_used_pct = round((used_kb / total_kb) * 100.0, 2) if total_kb > 0 else 0.0
    swap_used_kb = max(0, swap_total_kb - swap_free_kb)
    swap_used_pct = round((swap_used_kb / swap_total_kb) * 100.0, 2) if swap_total_kb > 0 else 0.0

    return {
        "ram_total_mb": round(total_kb / 1024.0, 1),
        "ram_available_mb": round(avail_kb / 1024.0, 1),
        "ram_used_mb": round(used_kb / 1024.0, 1),
        "ram_free_mb": round(free_kb / 1024.0, 1),
        "buffers_cached_mb": round((buffers_kb + cached_kb) / 1024.0, 1),
        "ram_used_pct": ram_used_pct,
        "swap_total_mb": round(swap_total_kb / 1024.0, 1),
        "swap_used_mb": round(swap_used_kb / 1024.0, 1),
        "swap_used_pct": swap_used_pct,
    }


def get_target_pid() -> int | None:
    env_pid = os.environ.get("OBB_TARGET_PID", "").strip()
    if env_pid.isdigit():
        return int(env_pid)
    if PID_FILE.exists():
        raw = PID_FILE.read_text(encoding="utf-8").strip()
        if raw.isdigit():
            return int(raw)
    return None


def inspect_pid(pid: int | None) -> dict | None:
    if not pid or pid <= 1:
        return None
    proc_dir = Path(f"/proc/{pid}")
    if not proc_dir.exists():
        return {"pid": pid, "alive": False}

    name = ""
    state = ""
    rss_kb = 0
    try:
        status_text = (proc_dir / "status").read_text(encoding="utf-8", errors="replace")
        for line in status_text.splitlines():
            if line.startswith("Name:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("State:"):
                state = line.split(":", 1)[1].strip()
            elif line.startswith("VmRSS:"):
                parts = line.split(":", 1)[1].strip().split()
                if parts and parts[0].isdigit():
                    rss_kb = int(parts[0])
    except OSError:
        return {"pid": pid, "alive": False}

    return {
        "pid": pid,
        "alive": True,
        "name": name,
        "state": state,
        "rss_mb": round(rss_kb / 1024.0, 2),
    }


def is_authorized() -> bool:
    token = request.headers.get("X-OBB-Token") or request.args.get("token")
    return token == API_TOKEN


HTML_UI = """<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OBB Sentinel Universal Agent</title>
<style>
  body { font-family: sans-serif; background: #0b1120; color: #f8fafc; margin: 14px; }
  .card { background: #1e293b; padding: 14px; border-radius: 10px; margin-bottom: 12px; }
  button { padding: 11px 14px; font-size: 14px; border: 0; border-radius: 8px; margin: 4px 6px 4px 0; cursor: pointer; }
  .cont { background: #15803d; color: #fff; }
  .kill { background: #b91c1c; color: #fff; }
  .sync { background: #2563eb; color: #fff; }
  input { width: 100%; padding: 8px; margin: 6px 0 10px; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: #fff; box-sizing: border-box; }
  pre { white-space: pre-wrap; word-break: break-word; font-size: 13px; background: #0f172a; padding: 10px; border-radius: 8px; }
</style>
</head>
<body>
  <h2>OBB Sentinel — Universal Host Agent</h2>
  <div class="card">
    <label>Host Base URL</label>
    <input id="baseUrl">
    <label>API Token (X-OBB-Token)</label>
    <input id="tok" value="isef-lab-token">
    <label>Target PID (overrides /tmp/obb_target.pid if set)</label>
    <input id="pid" placeholder="e.g. 4821">
    <button class="sync" onclick="refreshAll()">Refresh Now</button>
  </div>
  <div class="card">
    <h3>Physical RAM &amp; Alert Telemetry</h3>
    <pre id="statusBox">Connecting...</pre>
  </div>
  <div class="card">
    <h3>Real Process Signal Control</h3>
    <button class="cont" onclick="sendCmd('SIGCONT')">Send SIGCONT</button>
    <button class="kill" onclick="confirmKill()">Send SIGKILL</button>
    <pre id="cmdBox">Ready.</pre>
  </div>
  <div class="card">
    <h3>Dossiers (0444 Read-Only Check)</h3>
    <pre id="dosBox">Loading...</pre>
  </div>
<script>
document.getElementById("baseUrl").value = window.location.origin;
function getBase() {
  return document.getElementById("baseUrl").value.trim().replace(/\/+$/, "");
}
function hdrs() {
  return {
    "X-OBB-Token": document.getElementById("tok").value.trim(),
    "Content-Type": "application/json"
  };
}
async function refreshAll() {
  const base = getBase();
  try {
    const r = await fetch(base + "/api/status", { headers: hdrs() });
    const d = await r.json();
    document.getElementById("statusBox").textContent = JSON.stringify(d, null, 2);
  } catch (e) {
    document.getElementById("statusBox").textContent = "Status error: " + e;
  }
  try {
    const r2 = await fetch(base + "/api/dossiers", { headers: hdrs() });
    const d2 = await r2.json();
    document.getElementById("dosBox").textContent = JSON.stringify(d2, null, 2);
  } catch (e) {
    document.getElementById("dosBox").textContent = "Dossiers error: " + e;
  }
}
function confirmKill() {
  const pidVal = document.getElementById("pid").value.trim() || "(default target PID)";
  if (confirm("Send SIGKILL to PID " + pidVal + "? This terminates the process immediately.")) {
    sendCmd("SIGKILL");
  }
}
async function sendCmd(action) {
  const pidVal = document.getElementById("pid").value.trim();
  const payload = { action };
  if (pidVal) payload.pid = Number(pidVal);
  try {
    const r = await fetch(getBase() + "/api/command", {
      method: "POST",
      headers: hdrs(),
      body: JSON.stringify(payload)
    });
    const out = await r.json();
    document.getElementById("cmdBox").textContent = JSON.stringify(out, null, 2);
  } catch (e) {
    document.getElementById("cmdBox").textContent = "Command error: " + e;
  }
  refreshAll();
}
refreshAll();
setInterval(refreshAll, 2000);
</script>
</body>
</html>
"""


@app.get("/")
def index():
    return Response(HTML_UI, mimetype="text/html")


@app.get("/api/status")
def api_status():
    if not is_authorized():
        return jsonify({"error": "unauthorized"}), 401
    mem = read_physical_memory()
    alarm_file_active = ALARM_FILE.exists()
    ram_breach = mem["ram_used_pct"] >= THRESHOLD_PCT
    alert_active = alarm_file_active or ram_breach
    target_pid = get_target_pid()
    return jsonify({
        "hostname": socket.gethostname(),
        "memory": mem,
        "threshold_pct": THRESHOLD_PCT,
        "alarm_file_active": alarm_file_active,
        "ram_threshold_breach": ram_breach,
        "alert_active": alert_active,
        "state": "ALERT" if alert_active else "NORMAL",
        "target_pid": target_pid,
        "target_process": inspect_pid(target_pid),
        "timestamp": int(time.time()),
    })


@app.get("/api/dossiers")
def api_dossiers():
    if not is_authorized():
        return jsonify({"error": "unauthorized"}), 401
    items = []
    if VAULT_DIR.exists():
        for entry in sorted(VAULT_DIR.iterdir(), reverse=True)[:30]:
            if entry.is_file():
                st = entry.stat()
                perms = oct(st.st_mode & 0o777)
                items.append({
                    "name": entry.name,
                    "size_bytes": st.st_size,
                    "permissions": perms,
                    "read_only_0444": perms == "0o444",
                    "modified": int(st.st_mtime),
                })
    return jsonify({"vault_dir": str(VAULT_DIR), "dossiers": items})


@app.post("/api/command")
def api_command():
    if not is_authorized():
        return jsonify({"error": "unauthorized"}), 401
    payload = request.get_json(silent=True) or {}
    action = str(payload.get("action", "")).upper().strip()
    if action in {"CONT", "SIGCONT"}:
        sig = signal.SIGCONT
        norm_action = "SIGCONT"
    elif action in {"KILL", "SIGKILL"}:
        sig = signal.SIGKILL
        norm_action = "SIGKILL"
    else:
        return jsonify({"error": "action must be CONT/SIGCONT or KILL/SIGKILL"}), 400

    req_pid = payload.get("pid")
    pid = int(req_pid) if str(req_pid).isdigit() else get_target_pid()
    if not pid or pid <= 1:
        return jsonify({"error": "no valid target pid provided or found in PID file"}), 400

    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        return jsonify({"error": f"process {pid} not found"}), 404
    except PermissionError:
        return jsonify({"error": f"permission denied signaling pid {pid}"}), 403

    return jsonify({
        "ok": True,
        "action": norm_action,
        "pid": pid,
        "process_after": inspect_pid(pid),
        "timestamp": int(time.time()),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)
