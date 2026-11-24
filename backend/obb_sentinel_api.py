from flask import Flask, jsonify, request, Response
from pathlib import Path
import os
import signal
import time
import urllib.request

app = Flask(__name__)

PROJECT_DIR = Path.home() / "Desktop" / "obb-circuit-breaker-isef-edition"
VAULT_DIR = PROJECT_DIR / "captured_threat_dossiers"
ALARM_FILE = Path("/tmp/obb_alarm")
PID_FILE = Path("/tmp/obb_target.pid")
NTFY_CMD_URL = os.environ.get("OBB_NTFY_CMD_URL", "https://ntfy.sh/oob-breaker-8779-cmd")
API_TOKEN = os.environ.get("OBB_API_TOKEN", "isef-lab-token")


def read_ram_pct() -> float:
    info = {}
    with open("/proc/meminfo", "r", encoding="utf-8") as f:
        for line in f:
            if ":" in line:
                k, v = line.split(":", 1)
                parts = v.strip().split()
                if parts and parts[0].isdigit():
                    info[k.strip()] = int(parts[0])
    total = info.get("MemTotal", 1)
    avail = info.get("MemAvailable", total)
    return round(((total - avail) / total) * 100.0, 2)


def get_target_pid() -> int | None:
    env_pid = os.environ.get("OBB_TARGET_PID", "").strip()
    if env_pid.isdigit():
        return int(env_pid)
    if PID_FILE.exists():
        raw = PID_FILE.read_text(encoding="utf-8").strip()
        if raw.isdigit():
            return int(raw)
    return None


def is_authorized() -> bool:
    token = request.headers.get("X-OBB-Token") or request.args.get("token")
    return token == API_TOKEN


HTML_UI = """<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OBB Sentinel Live</title>
<style>
  body { font-family: sans-serif; background: #0f172a; color: #f8fafc; margin: 16px; }
  .card { background: #1e293b; padding: 14px; border-radius: 10px; margin-bottom: 12px; }
  button { padding: 12px 14px; font-size: 15px; border: 0; border-radius: 8px; margin-right: 8px; cursor: pointer; }
  .cont { background: #15803d; color: #fff; }
  .kill { background: #b91c1c; color: #fff; }
  .sync { background: #2563eb; color: #fff; }
  input { width: 100%; padding: 8px; margin: 6px 0 10px; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: #fff; box-sizing: border-box; }
  pre { white-space: pre-wrap; word-break: break-word; font-size: 13px; }
</style>
</head>
<body>
  <h2>OBB Sentinel — Live Host Control</h2>
  <div class="card">
    <label>API Token (X-OBB-Token)</label>
    <input id="tok" value="isef-lab-token">
    <label>Target PID (optional if /tmp/obb_target.pid exists)</label>
    <input id="pid" placeholder="e.g. 12345">
    <button class="sync" onclick="refreshAll()">Sync Now</button>
  </div>
  <div class="card">
    <h3>Live Telemetry &amp; Alerts</h3>
    <pre id="statusBox">Waiting for first sync...</pre>
  </div>
  <div class="card">
    <h3>Real Process Signal Control</h3>
    <button class="cont" onclick="sendCmd('SIGCONT')">Send SIGCONT</button>
    <button class="kill" onclick="confirmKill()">Send SIGKILL</button>
    <pre id="cmdBox"></pre>
  </div>
  <div class="card">
    <h3>Vault Dossiers (0444 Check)</h3>
    <pre id="dosBox">Loading...</pre>
  </div>
<script>
function hdrs() {
  return { "X-OBB-Token": document.getElementById("tok").value.trim(), "Content-Type": "application/json" };
}
async function refreshAll() {
  const base = window.location.origin;
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
  if (confirm("Send SIGKILL to the target process?")) sendCmd("SIGKILL");
}
async function sendCmd(action) {
  const pidVal = document.getElementById("pid").value.trim();
  const payload = { action };
  if (pidVal) payload.pid = Number(pidVal);
  const r = await fetch(window.location.origin + "/api/command", {
    method: "POST", headers: hdrs(), body: JSON.stringify(payload)
  });
  const out = await r.json();
  document.getElementById("cmdBox").textContent = JSON.stringify(out, null, 2);
  refreshAll();
}
refreshAll();
setInterval(refreshAll, 2500);
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
    alarm_active = ALARM_FILE.exists()
    target_pid = get_target_pid()
    return jsonify({
        "ram_used_pct": read_ram_pct(),
        "threshold_pct": 90.0,
        "alarm_active": alarm_active,
        "state": "FROZEN_ALERT" if alarm_active else "NORMAL",
        "target_pid": target_pid,
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
    return jsonify({"dossiers": items})


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
        return jsonify({"error": "no valid target pid provided or found in /tmp/obb_target.pid"}), 400

    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        return jsonify({"error": f"process {pid} not found"}), 404
    except PermissionError:
        return jsonify({"error": f"permission denied signaling pid {pid}"}), 403

    return jsonify({"ok": True, "action": norm_action, "pid": pid})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
