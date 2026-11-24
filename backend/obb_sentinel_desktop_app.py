import glob
import os
from pathlib import Path
import signal
import socket
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

DEFAULT_VAULT = Path.home() / "Desktop" / "obb-circuit-breaker-isef-edition" / "captured_threat_dossiers"
VAULT_DIR = Path(os.environ.get("OBB_VAULT_DIR", str(DEFAULT_VAULT)))
ALARM_FILE = Path(os.environ.get("OBB_ALARM_FILE", "/tmp/obb_alarm"))
PID_FILE = Path(os.environ.get("OBB_PID_FILE", "/tmp/obb_target.pid"))
THRESHOLD_PCT = float(os.environ.get("OBB_THRESHOLD_PCT", "90.0"))


def read_physical_memory() -> dict:
    mem_kb = {}
    with open("/proc/meminfo", "r", encoding="utf-8") as f:
        for line in f:
            if ":" in line:
                k, v = line.split(":", 1)
                parts = v.strip().split()
                if parts and parts[0].isdigit():
                    mem_kb[k.strip()] = int(parts[0])
    total = mem_kb.get("MemTotal", 0)
    avail = mem_kb.get("MemAvailable", mem_kb.get("MemFree", 0))
    used = max(0, total - avail)
    swap_total = mem_kb.get("SwapTotal", 0)
    swap_free = mem_kb.get("SwapFree", 0)
    swap_used = max(0, swap_total - swap_free)
    pct = round((used / total) * 100.0, 2) if total > 0 else 0.0
    swap_pct = round((swap_used / swap_total) * 100.0, 2) if swap_total > 0 else 0.0
    return {
        "ram_total_mb": round(total / 1024.0, 1),
        "ram_available_mb": round(avail / 1024.0, 1),
        "ram_used_mb": round(used / 1024.0, 1),
        "ram_used_pct": pct,
        "swap_total_mb": round(swap_total / 1024.0, 1),
        "swap_used_mb": round(swap_used / 1024.0, 1),
        "swap_used_pct": swap_pct,
    }


def detect_pico_ports() -> list[str]:
    return sorted(glob.glob("/dev/ttyACM*") + glob.glob("/dev/ttyUSB*"))


def pid_alive(pid: int | None) -> bool:
    return bool(pid and pid > 1 and Path(f"/proc/{pid}").exists())


def inspect_pid(pid: int | None) -> dict | None:
    if not pid_alive(pid):
        return None
    pdir = Path(f"/proc/{pid}")
    name = "?"
    state = "?"
    rss_kb = 0
    try:
        for line in (pdir / "status").read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("Name:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("State:"):
                state = line.split(":", 1)[1].strip()
            elif line.startswith("VmRSS:"):
                parts = line.split(":", 1)[1].strip().split()
                if parts and parts[0].isdigit():
                    rss_kb = int(parts[0])
    except OSError:
        return None
    return {"pid": pid, "name": name, "state": state, "rss_mb": round(rss_kb / 1024.0, 1)}


def read_target_pid(override_text: str = "") -> int | None:
    s = override_text.strip()
    if s.isdigit():
        return int(s)
    if PID_FILE.exists():
        raw = PID_FILE.read_text(encoding="utf-8").strip()
        if raw.isdigit():
            return int(raw)
    return None


class SentinelCommandCenter:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"OBB Sentinel Command Center — {socket.gethostname()}")
        self.root.geometry("760x580")
        self.root.configure(bg="#0b1120")

        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("TNotebook", background="#0b1120", borderwidth=0)
        style.configure("TNotebook.Tab", background="#1e293b", foreground="#e2e8f0", padding=[14, 8])
        style.map("TNotebook.Tab", background=[("selected", "#2563eb")], foreground=[("selected", "#ffffff")])
        style.configure("TFrame", background="#0b1120")

        self.known_ports: set[str] = set()
        self.last_missing_pid: int | None = None
        self.running = True

        # Top status banner
        top = tk.Frame(root, bg="#111827", padx=14, pady=10)
        top.pack(fill="x")
        self.pico_lbl = tk.Label(top, text="Pico: Scanning...", bg="#111827", fg="#38bdf8", font=("Sans", 11, "bold"))
        self.pico_lbl.pack(side="left")
        self.alert_lbl = tk.Label(top, text="Alert: NORMAL", bg="#111827", fg="#22c55e", font=("Sans", 11, "bold"))
        self.alert_lbl.pack(side="right")

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        tab_dash = ttk.Frame(notebook)
        tab_proc = ttk.Frame(notebook)
        tab_vault = ttk.Frame(notebook)
        notebook.add(tab_dash, text="Telemetry & Hardware")
        notebook.add(tab_proc, text="Process & Signals")
        notebook.add(tab_vault, text="Vault (0444) & Logs")

        # --- Tab 1: Telemetry & Hardware ---
        ram_card = tk.LabelFrame(tab_dash, text="Physical Memory & Swap (/proc/meminfo)", bg="#1e293b", fg="#f8fafc",
                                 font=("Sans", 10, "bold"), padx=12, pady=10)
        ram_card.pack(fill="x", padx=6, pady=6)
        self.ram_text = tk.Label(ram_card, text="Reading...", bg="#1e293b", fg="#e2e8f0",
                                 font=("Monospace", 10), justify="left", anchor="w")
        self.ram_text.pack(fill="x")
        self.ram_bar = ttk.Progressbar(ram_card, length=400, mode="determinate", maximum=100)
        self.ram_bar.pack(fill="x", pady=(8, 0))

        hw_card = tk.LabelFrame(tab_dash, text="Raspberry Pi Pico & Alert Controls", bg="#1e293b", fg="#f8fafc",
                                font=("Sans", 10, "bold"), padx=12, pady=10)
        hw_card.pack(fill="x", padx=6, pady=6)
        self.hw_detail = tk.Label(hw_card, text="Watching /dev/ttyACM* and /dev/ttyUSB*...",
                                  bg="#1e293b", fg="#cbd5e1", font=("Monospace", 10), justify="left", anchor="w")
        self.hw_detail.pack(fill="x", pady=(0, 8))

        hw_btns = tk.Frame(hw_card, bg="#1e293b")
        hw_btns.pack(fill="x")
        tk.Button(hw_btns, text="Trigger Test Alert", bg="#d97706", fg="#fff", font=("Sans", 10, "bold"),
                  command=self.trigger_alert).pack(side="left", padx=(0, 8))
        tk.Button(hw_btns, text="Clear Alert", bg="#2563eb", fg="#fff", font=("Sans", 10, "bold"),
                  command=self.clear_alert).pack(side="left")

        # --- Tab 2: Process & Signals ---
        sig_card = tk.LabelFrame(tab_proc, text="Target Process & Real POSIX Signal Dispatch", bg="#1e293b", fg="#f8fafc",
                                 font=("Sans", 10, "bold"), padx=12, pady=10)
        sig_card.pack(fill="x", padx=6, pady=6)

        row = tk.Frame(sig_card, bg="#1e293b")
        row.pack(fill="x", pady=(0, 8))
        tk.Label(row, text="Target PID (blank uses /tmp/obb_target.pid):", bg="#1e293b", fg="#e2e8f0",
                 font=("Sans", 10)).pack(side="left")
        self.pid_entry = tk.Entry(row, width=14, bg="#0f172a", fg="#ffffff", insertbackground="#ffffff", font=("Monospace", 10))
        self.pid_entry.pack(side="left", padx=8)

        self.proc_info_lbl = tk.Label(sig_card, text="Target process: none", bg="#1e293b", fg="#93c5fd",
                                      font=("Monospace", 10), anchor="w")
        self.proc_info_lbl.pack(fill="x", pady=(0, 8))

        sig_btns = tk.Frame(sig_card, bg="#1e293b")
        sig_btns.pack(fill="x")
        tk.Button(sig_btns, text="Send SIGCONT", bg="#15803d", fg="#fff", font=("Sans", 10, "bold"),
                  command=lambda: self.send_signal(signal.SIGCONT, "SIGCONT")).pack(side="left", padx=(0, 8))
        tk.Button(sig_btns, text="Send SIGSTOP", bg="#475569", fg="#fff", font=("Sans", 10, "bold"),
                  command=lambda: self.send_signal(signal.SIGSTOP, "SIGSTOP")).pack(side="left", padx=(0, 8))
        tk.Button(sig_btns, text="Send SIGKILL", bg="#b91c1c", fg="#fff", font=("Sans", 10, "bold"),
                  command=self.confirm_kill).pack(side="left", padx=(0, 8))
        tk.Button(sig_btns, text="Spawn Test sleep 600", bg="#0284c7", fg="#fff", font=("Sans", 10),
                  command=self.spawn_test_pid).pack(side="right")

        # --- Tab 3: Vault (0444) & Logs ---
        vault_card = tk.LabelFrame(tab_vault, text=f"Dossiers Directory ({VAULT_DIR})", bg="#1e293b", fg="#f8fafc",
                                   font=("Sans", 10, "bold"), padx=10, pady=8)
        vault_card.pack(fill="x", padx=6, pady=6)
        self.vault_box = tk.Listbox(vault_card, height=5, bg="#0f172a", fg="#e2e8f0", font=("Monospace", 9))
        self.vault_box.pack(fill="x")

        log_card = tk.LabelFrame(tab_vault, text="Live System & Signal Event Log", bg="#1e293b", fg="#f8fafc",
                                 font=("Sans", 10, "bold"), padx=10, pady=8)
        log_card.pack(fill="both", expand=True, padx=6, pady=6)
        self.log_box = scrolledtext.ScrolledText(log_card, height=10, bg="#020617", fg="#cbd5e1", font=("Monospace", 9))
        self.log_box.pack(fill="both", expand=True)

        self.log("OBB Sentinel Command Center initialized.")
        threading.Thread(target=self.serial_loop, daemon=True).start()
        self.refresh_ui()

    def log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        self.log_box.insert("end", f"[{ts}] {msg}\n")
        self.log_box.see("end")

    def serial_loop(self):
        while self.running:
            ports = set(detect_pico_ports())
            for p in sorted(ports - self.known_ports):
                self.root.after(0, self.log, f"Pico / USB serial plugged in: {p}")
            for p in sorted(self.known_ports - ports):
                self.root.after(0, self.log, f"Pico / USB serial unplugged: {p}")
            self.known_ports = ports

            for port in sorted(ports):
                try:
                    with open(port, "r", encoding="utf-8", errors="ignore") as f:
                        line = f.readline().strip()
                        if line == "ALERT":
                            ALARM_FILE.touch()
                            self.root.after(0, self.log, f"[{port}] Serial ALERT -> {ALARM_FILE} created")
                        elif line == "CLEAR":
                            ALARM_FILE.unlink(missing_ok=True)
                            self.root.after(0, self.log, f"[{port}] Serial CLEAR -> {ALARM_FILE} removed")
                        elif line.startswith("PID:") and line[4:].strip().isdigit():
                            pid_str = line[4:].strip()
                            PID_FILE.write_text(pid_str + "\n", encoding="utf-8")
                            self.root.after(0, self.log, f"[{port}] Serial PID:{pid_str} -> saved to {PID_FILE}")
                except OSError:
                    pass
            time.sleep(1.0)

    def refresh_ui(self):
        if not self.running:
            return
        ports = detect_pico_ports()
        if ports:
            self.pico_lbl.config(text=f"Pico Detected: {', '.join(ports)}", fg="#38bdf8")
            self.hw_detail.config(text=f"Active USB serial device(s): {', '.join(ports)}\nAlert file: {ALARM_FILE}")
        else:
            self.pico_lbl.config(text="Pico: Not Plugged In", fg="#94a3b8")
            self.hw_detail.config(text="No /dev/ttyACM* or /dev/ttyUSB* device detected.\nPlug in Pico over USB to auto-detect.")

        mem = read_physical_memory()
        self.ram_text.config(
            text=f"RAM Used: {mem['ram_used_mb']} / {mem['ram_total_mb']} MB ({mem['ram_used_pct']}%) | Available: {mem['ram_available_mb']} MB\n"
                 f"Swap Used: {mem['swap_used_mb']} / {mem['swap_total_mb']} MB ({mem['swap_used_pct']}%)"
        )
        self.ram_bar["value"] = min(100.0, mem["ram_used_pct"])

        alert = ALARM_FILE.exists() or (mem["ram_used_pct"] >= THRESHOLD_PCT)
        self.alert_lbl.config(text="Alert: ACTIVE" if alert else "Alert: NORMAL", fg="#f87171" if alert else "#22c55e")

        pid = read_target_pid(self.pid_entry.get())
        info = inspect_pid(pid)
        if info:
            self.proc_info_lbl.config(
                text=f"Target PID {info['pid']}: name={info['name']} | state={info['state']} | RSS={info['rss_mb']} MB"
            )
            self.last_missing_pid = None
        else:
            self.proc_info_lbl.config(text=f"Target PID: {pid if pid else 'none'} (no live process)")
            if pid and pid != self.last_missing_pid and not self.pid_entry.get().strip():
                self.last_missing_pid = pid
                if PID_FILE.exists():
                    PID_FILE.unlink(missing_ok=True)
                self.log(f"Target PID {pid} exited/not running; cleared stale {PID_FILE}.")

        self.vault_box.delete(0, "end")
        if VAULT_DIR.exists():
            for f in sorted(VAULT_DIR.iterdir(), reverse=True)[:20]:
                if f.is_file():
                    mode = oct(f.stat().st_mode & 0o777)
                    self.vault_box.insert("end", f"{f.name}  |  perms={mode}  |  {f.stat().st_size}B")
        else:
            self.vault_box.insert("end", "(No vault directory yet)")

        self.root.after(1500, self.refresh_ui)

    def trigger_alert(self):
        ALARM_FILE.touch()
        self.log(f"Triggered alert file: {ALARM_FILE}")
        self.refresh_ui()

    def clear_alert(self):
        ALARM_FILE.unlink(missing_ok=True)
        self.log(f"Cleared alert file: {ALARM_FILE}")
        self.refresh_ui()

    def spawn_test_pid(self):
        p = os.fork()
        if p == 0:
            os.execvp("sleep", ["sleep", "600"])
        PID_FILE.write_text(f"{p}\n", encoding="utf-8")
        self.pid_entry.delete(0, "end")
        self.pid_entry.insert(0, str(p))
        self.last_missing_pid = None
        self.log(f"Spawned test process `sleep 600` with PID {p} and saved to {PID_FILE}")
        self.refresh_ui()

    def confirm_kill(self):
        pid = read_target_pid(self.pid_entry.get())
        if not pid_alive(pid):
            messagebox.showwarning("No Live PID", "Select or spawn a live target PID first.")
            return
        if messagebox.askyesno("Confirm SIGKILL", f"Send SIGKILL to PID {pid}? This ends the process immediately."):
            self.send_signal(signal.SIGKILL, "SIGKILL")

    def send_signal(self, sig, label: str):
        pid = read_target_pid(self.pid_entry.get())
        if not pid or pid <= 1:
            self.log("No target PID specified.")
            return
        try:
            os.kill(pid, sig)
            alive_now = pid_alive(pid)
            self.log(f"Sent {label} to PID {pid} | alive_after={alive_now}")
            if not alive_now and PID_FILE.exists() and PID_FILE.read_text(encoding="utf-8").strip() == str(pid):
                PID_FILE.unlink(missing_ok=True)
        except ProcessLookupError:
            self.log(f"PID {pid} not found.")
        except PermissionError:
            self.log(f"Permission denied sending {label} to PID {pid}.")
        self.refresh_ui()


if __name__ == "__main__":
    root = tk.Tk()
    app = SentinelCommandCenter(root)
    root.mainloop()
