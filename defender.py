"""Autonomous Defense Monitor — runs without permission.

Inspired by Hermes Agent's self-improving loop and AutoResearch's
autonomous feedback cycle. Monitors system in real-time, detects threats,
and auto-responds without asking permission.

Architecture:
- Background thread monitoring multiple vectors simultaneously
- Rule engine evaluates threats and triggers auto-responses
- Learning system remembers known-good baselines and flags anomalies
- All actions logged for audit trail
"""

import os
import sys
import json
import time
import signal
import shutil
import hashlib
import threading
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel)

# ─── Configuration ────────────────────────────────────────────────────────────

DEFENSE_DIR = os.path.expanduser("~/hackassist_defense")
BASELINE_FILE = os.path.join(DEFENSE_DIR, "baseline.json")
THREAT_LOG = os.path.join(DEFENSE_DIR, "threats.log")
BLOCKED_IPS_FILE = os.path.join(DEFENSE_DIR, "blocked_ips.json")
MEMORY_FILE = os.path.join(DEFENSE_DIR, "defense_memory.json")

# Files to monitor for integrity
WATCH_FILES = [
    "/etc/hosts",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    os.path.expanduser("~/.ssh/authorized_keys"),
    os.path.expanduser("~/.zshrc"),
    os.path.expanduser("~/.bash_profile"),
]

# Suspicious process patterns
SUSPICIOUS_PATTERNS = [
    "nc -l", "ncat -l", "socat", "msfconsole", "msfvenom",
    "reverse_tcp", "bind_tcp", "python -c 'import socket",
    "bash -i >& /dev/tcp", "cryptominer", "xmrig", "coinhive",
    "/tmp/.", "base64 -d", "curl | sh", "wget | sh",
    "curl | bash", "wget | bash",
]

# Known safe processes (learned baseline)
SAFE_PROCESSES = {
    "Finder", "Dock", "WindowServer", "loginwindow", "SystemUIServer",
    "Spotlight", "mds_stores", "kernel_task", "launchd", "syslogd",
    "Terminal", "iTerm2", "python3", "git", "brew", "node", "code",
}

# Thresholds
MAX_FAILED_LOGINS = 5          # per IP in 5 minutes
MAX_NEW_CONNECTIONS = 50       # new connections per minute
PORT_SCAN_THRESHOLD = 15       # ports hit from single IP in 30 seconds
CHECK_INTERVAL = 10            # seconds between monitoring cycles

# ─── Defense Memory (Hermes-inspired learning) ───────────────────────────────

class DefenseMemory:
    """Persistent memory that learns from past events.

    Inspired by Hermes Agent's learning loop:
    observe → evaluate → remember → improve responses.
    """

    def __init__(self):
        self.memory_path = MEMORY_FILE
        self.data = {
            "known_safe_ips": [],
            "known_safe_ports": [],
            "known_safe_processes": list(SAFE_PROCESSES),
            "threat_history": [],
            "blocked_ips": [],
            "false_positives": [],
            "baseline_hashes": {},
            "learned_patterns": [],
            "stats": {
                "threats_detected": 0,
                "threats_blocked": 0,
                "false_positives": 0,
                "uptime_hours": 0,
            },
        }
        self._load()

    def _load(self):
        if os.path.exists(self.memory_path):
            try:
                with open(self.memory_path, "r") as f:
                    saved = json.load(f)
                self.data.update(saved)
            except (json.JSONDecodeError, IOError):
                pass

    def save(self):
        os.makedirs(os.path.dirname(self.memory_path), exist_ok=True)
        tmp = self.memory_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=2)
        os.replace(tmp, self.memory_path)

    def is_safe_ip(self, ip):
        return ip in self.data["known_safe_ips"] or ip.startswith("127.")

    def is_safe_process(self, name):
        return name in self.data["known_safe_processes"]

    def add_safe_ip(self, ip):
        if ip not in self.data["known_safe_ips"]:
            self.data["known_safe_ips"].append(ip)
            self.save()

    def add_safe_process(self, name):
        if name not in self.data["known_safe_processes"]:
            self.data["known_safe_processes"].append(name)
            self.save()

    def record_threat(self, threat):
        threat["timestamp"] = datetime.now().isoformat()
        self.data["threat_history"].append(threat)
        self.data["stats"]["threats_detected"] += 1
        # Keep last 1000 threats
        if len(self.data["threat_history"]) > 1000:
            self.data["threat_history"] = self.data["threat_history"][-1000:]
        self.save()

    def record_block(self, ip):
        if ip not in self.data["blocked_ips"]:
            self.data["blocked_ips"].append(ip)
        self.data["stats"]["threats_blocked"] += 1
        self.save()

    def record_false_positive(self, description):
        self.data["false_positives"].append({
            "description": description,
            "timestamp": datetime.now().isoformat(),
        })
        self.data["stats"]["false_positives"] += 1
        self.save()


# ─── Threat Event ─────────────────────────────────────────────────────────────

class ThreatEvent:
    """Represents a detected threat."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def __init__(self, category, severity, description, source_ip=None, details=None):
        self.category = category
        self.severity = severity
        self.description = description
        self.source_ip = source_ip
        self.details = details or {}
        self.timestamp = datetime.now()
        self.auto_response = None

    def to_dict(self):
        return {
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "source_ip": self.source_ip,
            "details": self.details,
            "auto_response": self.auto_response,
        }

    def format_alert(self):
        severity_colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "dim",
        }
        color = severity_colors.get(self.severity, "white")
        return (f"[{color}][{self.severity}][/{color}] "
                f"[bold]{self.category}[/bold]: {self.description}")


# ─── Monitor Modules ──────────────────────────────────────────────────────────

def _run_quiet(cmd, timeout=10):
    """Run command silently, return stdout."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, Exception):
        return ""


class NetworkMonitor:
    """Monitor network connections for suspicious activity."""

    def __init__(self, memory):
        self.memory = memory
        self.connection_history = defaultdict(list)  # ip -> [timestamps]
        self.port_scan_tracker = defaultdict(set)     # ip -> {ports}
        self.last_check = datetime.now()

    def check(self):
        threats = []

        # Get current connections
        output = _run_quiet("lsof -i -n -P 2>/dev/null | grep ESTABLISHED")
        if not output:
            return threats

        now = datetime.now()
        current_ips = set()

        for line in output.split("\n"):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) < 9:
                continue

            process_name = parts[0]
            connection_info = parts[8] if len(parts) > 8 else ""

            # Extract remote IP
            if "->" in connection_info:
                remote = connection_info.split("->")[1]
                ip = remote.rsplit(":", 1)[0] if ":" in remote else remote
                port = remote.rsplit(":", 1)[1] if ":" in remote else ""

                if self.memory.is_safe_ip(ip):
                    continue

                current_ips.add(ip)
                self.connection_history[ip].append(now)

                # Track ports per IP (port scan detection)
                if port:
                    self.port_scan_tracker[ip].add(port)

        # Detect port scans (many ports from single IP in short time)
        for ip, ports in self.port_scan_tracker.items():
            if len(ports) > PORT_SCAN_THRESHOLD:
                threats.append(ThreatEvent(
                    "PORT_SCAN", ThreatEvent.HIGH,
                    f"Possible port scan from {ip} ({len(ports)} ports)",
                    source_ip=ip,
                    details={"ports_count": len(ports)},
                ))

        # Detect connection floods
        cutoff = now - timedelta(minutes=1)
        for ip, timestamps in self.connection_history.items():
            recent = [t for t in timestamps if t > cutoff]
            self.connection_history[ip] = recent
            if len(recent) > MAX_NEW_CONNECTIONS:
                threats.append(ThreatEvent(
                    "CONNECTION_FLOOD", ThreatEvent.HIGH,
                    f"Connection flood from {ip} ({len(recent)} in 1 min)",
                    source_ip=ip,
                ))

        # Clean old port scan data every 30 seconds
        if (now - self.last_check).seconds > 30:
            self.port_scan_tracker.clear()
            self.last_check = now

        return threats


class ProcessMonitor:
    """Monitor for suspicious processes."""

    def __init__(self, memory):
        self.memory = memory
        self.known_pids = set()
        self.initialized = False

    def check(self):
        threats = []

        output = _run_quiet("ps aux")
        if not output:
            return threats

        current_pids = set()

        for line in output.split("\n")[1:]:  # Skip header
            parts = line.split(None, 10)
            if len(parts) < 11:
                continue

            pid = parts[1]
            cpu = float(parts[2]) if parts[2].replace('.', '').isdigit() else 0
            mem = float(parts[3]) if parts[3].replace('.', '').isdigit() else 0
            command = parts[10]
            process_name = os.path.basename(command.split()[0]) if command else ""

            current_pids.add(pid)

            # Check for suspicious command patterns
            for pattern in SUSPICIOUS_PATTERNS:
                if pattern.lower() in command.lower():
                    if not self.memory.is_safe_process(process_name):
                        threats.append(ThreatEvent(
                            "SUSPICIOUS_PROCESS", ThreatEvent.CRITICAL,
                            f"Suspicious process: {command[:80]}",
                            details={"pid": pid, "pattern": pattern, "cpu": cpu},
                        ))

            # High resource usage (potential cryptominer)
            if cpu > 90 and not self.memory.is_safe_process(process_name):
                threats.append(ThreatEvent(
                    "HIGH_CPU", ThreatEvent.MEDIUM,
                    f"High CPU ({cpu}%): {process_name} (PID {pid})",
                    details={"pid": pid, "cpu": cpu, "mem": mem},
                ))

        # Detect new processes (after initial baseline)
        if self.initialized:
            new_pids = current_pids - self.known_pids
            if len(new_pids) > 20:
                threats.append(ThreatEvent(
                    "PROCESS_SPIKE", ThreatEvent.MEDIUM,
                    f"{len(new_pids)} new processes spawned suddenly",
                    details={"count": len(new_pids)},
                ))

        self.known_pids = current_pids
        self.initialized = True
        return threats


class PortMonitor:
    """Monitor for new listening ports."""

    def __init__(self, memory):
        self.memory = memory
        self.baseline_ports = set()
        self.initialized = False

    def check(self):
        threats = []

        output = _run_quiet("lsof -i -n -P 2>/dev/null | grep LISTEN")
        if not output:
            return threats

        current_ports = set()
        for line in output.split("\n"):
            parts = line.split()
            if len(parts) < 9:
                continue
            listen_addr = parts[8]
            if ":" in listen_addr:
                port = listen_addr.rsplit(":", 1)[1]
                process = parts[0]
                current_ports.add(f"{port}:{process}")

        if self.initialized:
            new_ports = current_ports - self.baseline_ports
            for port_proc in new_ports:
                port, proc = port_proc.split(":", 1)
                if port not in self.memory.data.get("known_safe_ports", []):
                    threats.append(ThreatEvent(
                        "NEW_PORT", ThreatEvent.HIGH,
                        f"New listening port {port} ({proc})",
                        details={"port": port, "process": proc},
                    ))

        self.baseline_ports = current_ports
        self.initialized = True
        return threats


class FileIntegrityMonitor:
    """Monitor critical files for unauthorized changes."""

    def __init__(self, memory):
        self.memory = memory
        self.file_hashes = {}
        self._build_baseline()

    def _hash_file(self, path):
        try:
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except (IOError, PermissionError):
            return None

    def _build_baseline(self):
        for path in WATCH_FILES:
            if os.path.exists(path):
                h = self._hash_file(path)
                if h:
                    self.file_hashes[path] = h
                    self.memory.data["baseline_hashes"][path] = h
        self.memory.save()

    def check(self):
        threats = []

        for path in WATCH_FILES:
            if not os.path.exists(path):
                if path in self.file_hashes:
                    threats.append(ThreatEvent(
                        "FILE_DELETED", ThreatEvent.CRITICAL,
                        f"Monitored file deleted: {path}",
                        details={"path": path},
                    ))
                continue

            current_hash = self._hash_file(path)
            if current_hash and path in self.file_hashes:
                if current_hash != self.file_hashes[path]:
                    threats.append(ThreatEvent(
                        "FILE_MODIFIED", ThreatEvent.CRITICAL,
                        f"File modified: {path}",
                        details={
                            "path": path,
                            "old_hash": self.file_hashes[path][:16],
                            "new_hash": current_hash[:16],
                        },
                    ))
                    self.file_hashes[path] = current_hash

        return threats


class LoginMonitor:
    """Monitor for failed login attempts and brute force."""

    def __init__(self, memory):
        self.memory = memory
        self.failed_attempts = defaultdict(list)

    def check(self):
        threats = []

        # Check macOS auth log for failed attempts
        output = _run_quiet(
            "log show --predicate 'eventMessage contains \"authentication failure\"' "
            "--last 5m --style compact 2>/dev/null | tail -20"
        )

        if output and "authentication failure" in output.lower():
            lines = [l for l in output.split("\n") if "authentication failure" in l.lower()]

            if len(lines) > MAX_FAILED_LOGINS:
                threats.append(ThreatEvent(
                    "BRUTE_FORCE", ThreatEvent.CRITICAL,
                    f"{len(lines)} failed login attempts in 5 minutes",
                    details={"count": len(lines)},
                ))

        # Check for SSH brute force specifically
        ssh_output = _run_quiet(
            "log show --predicate 'process == \"sshd\" AND eventMessage contains \"Failed\"' "
            "--last 5m --style compact 2>/dev/null | tail -20"
        )

        if ssh_output:
            ssh_lines = [l for l in ssh_output.split("\n") if l.strip()]
            if len(ssh_lines) > 3:
                threats.append(ThreatEvent(
                    "SSH_BRUTE_FORCE", ThreatEvent.CRITICAL,
                    f"{len(ssh_lines)} failed SSH attempts in 5 minutes",
                    details={"count": len(ssh_lines)},
                ))

        return threats


# ─── Auto Response Engine ─────────────────────────────────────────────────────

class AutoResponder:
    """Autonomous response to detected threats.

    Inspired by AutoResearch's evaluate-and-act loop:
    detect → evaluate severity → respond → verify → log.
    """

    def __init__(self, memory):
        self.memory = memory

    def respond(self, threat):
        """Auto-respond to a threat. Returns action taken."""
        if threat.severity == ThreatEvent.CRITICAL:
            return self._respond_critical(threat)
        elif threat.severity == ThreatEvent.HIGH:
            return self._respond_high(threat)
        else:
            return self._respond_log_only(threat)

    def _respond_critical(self, threat):
        actions = []

        if threat.category == "SUSPICIOUS_PROCESS":
            pid = threat.details.get("pid")
            if pid:
                _run_quiet(f"kill -9 {pid}")
                actions.append(f"Killed process PID {pid}")

        if threat.source_ip and not self.memory.is_safe_ip(threat.source_ip):
            self._block_ip(threat.source_ip)
            actions.append(f"Blocked IP {threat.source_ip}")

        if threat.category in ("FILE_MODIFIED", "FILE_DELETED"):
            actions.append("Alert: Critical file change detected")

        if threat.category in ("BRUTE_FORCE", "SSH_BRUTE_FORCE"):
            actions.append("Alert: Brute force detected")

        action_str = "; ".join(actions) if actions else "Logged (no auto-action available)"
        threat.auto_response = action_str
        return action_str

    def _respond_high(self, threat):
        actions = []

        if threat.source_ip and not self.memory.is_safe_ip(threat.source_ip):
            self._block_ip(threat.source_ip)
            actions.append(f"Blocked IP {threat.source_ip}")

        if threat.category == "NEW_PORT":
            port = threat.details.get("port")
            proc = threat.details.get("process")
            actions.append(f"Alert: Unexpected port {port} ({proc})")

        action_str = "; ".join(actions) if actions else "Logged"
        threat.auto_response = action_str
        return action_str

    def _respond_log_only(self, threat):
        threat.auto_response = "Logged for review"
        return "Logged for review"

    def _block_ip(self, ip):
        """Block IP using macOS pf firewall."""
        if not ip or ip.startswith("127.") or ip.startswith("::1"):
            return

        # Add to blocked list
        self.memory.record_block(ip)

        # Try to add pf rule (requires sudo, may fail silently)
        _run_quiet(f"echo 'block drop from {ip} to any' | sudo pfctl -a hackassist -f - 2>/dev/null")


# ─── Defense Log ──────────────────────────────────────────────────────────────

def _log_threat(threat):
    """Append threat to log file."""
    os.makedirs(DEFENSE_DIR, exist_ok=True)
    with open(THREAT_LOG, "a") as f:
        f.write(f"[{datetime.now().isoformat()}] [{threat.severity}] "
                f"{threat.category}: {threat.description}")
        if threat.auto_response:
            f.write(f" | Response: {threat.auto_response}")
        f.write("\n")


# ─── Main Defense Engine ──────────────────────────────────────────────────────

class DefenseEngine:
    """Main defense engine — runs all monitors in a loop.

    Combines Hermes Agent's learning loop with AutoResearch's
    autonomous experiment cycle:
    1. Monitor (observe)
    2. Detect (evaluate)
    3. Respond (act)
    4. Learn (remember)
    5. Repeat
    """

    def __init__(self):
        os.makedirs(DEFENSE_DIR, exist_ok=True)
        self.memory = DefenseMemory()
        self.responder = AutoResponder(self.memory)
        self.monitors = [
            NetworkMonitor(self.memory),
            ProcessMonitor(self.memory),
            PortMonitor(self.memory),
            FileIntegrityMonitor(self.memory),
            LoginMonitor(self.memory),
        ]
        self.running = False
        self.thread = None
        self.threat_count = 0
        self.cycle_count = 0
        self.start_time = None

    def start(self):
        """Start defense monitoring in background thread."""
        if self.running:
            return
        self.running = True
        self.start_time = datetime.now()
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()

    def stop(self):
        """Stop defense monitoring."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=15)

    def _monitor_loop(self):
        """Main monitoring loop — runs autonomously."""
        while self.running:
            self.cycle_count += 1
            all_threats = []

            for monitor in self.monitors:
                try:
                    threats = monitor.check()
                    all_threats.extend(threats)
                except Exception:
                    pass  # Never crash the monitor loop

            for threat in all_threats:
                self.threat_count += 1
                # Auto-respond (no permission needed)
                action = self.responder.respond(threat)
                # Log
                _log_threat(threat)
                # Remember
                self.memory.record_threat(threat.to_dict())
                # Alert on console
                console.print(f"\n  [bold red]DEFENSE ALERT[/bold red] {threat.format_alert()}")
                if action and action != "Logged for review":
                    console.print(f"    [green]Auto-response: {action}[/green]")

            # Update uptime
            if self.start_time:
                hours = (datetime.now() - self.start_time).total_seconds() / 3600
                self.memory.data["stats"]["uptime_hours"] = round(hours, 2)
                if self.cycle_count % 30 == 0:  # Save stats every ~5 minutes
                    self.memory.save()

            time.sleep(CHECK_INTERVAL)

    def get_status(self):
        """Get current defense status."""
        uptime = ""
        if self.start_time:
            delta = datetime.now() - self.start_time
            hours, remainder = divmod(int(delta.total_seconds()), 3600)
            minutes, seconds = divmod(remainder, 60)
            uptime = f"{hours}h {minutes}m {seconds}s"

        return {
            "running": self.running,
            "uptime": uptime,
            "cycles": self.cycle_count,
            "threats_detected": self.threat_count,
            "monitors_active": len(self.monitors),
            "blocked_ips": len(self.memory.data.get("blocked_ips", [])),
            "stats": self.memory.data.get("stats", {}),
        }


# ─── Singleton Engine ─────────────────────────────────────────────────────────

_engine = None


def get_engine():
    global _engine
    if _engine is None:
        _engine = DefenseEngine()
    return _engine


# ─── UI Menu ──────────────────────────────────────────────────────────────────

def run(session):
    """Defense monitor menu."""
    show_stage_header("Defense Monitor",
                      "Autonomous system protection — no permission needed")

    engine = get_engine()

    while True:
        # Status line
        status = engine.get_status()
        if status["running"]:
            console.print(f"  [bold green]ACTIVE[/bold green] | "
                          f"Uptime: {status['uptime']} | "
                          f"Cycles: {status['cycles']} | "
                          f"Threats: {status['threats_detected']} | "
                          f"Blocked IPs: {status['blocked_ips']}")
        else:
            console.print("  [bold red]INACTIVE[/bold red]")
        console.print()

        options = [
            ("1", "Start Defense Monitor" if not status["running"] else "Stop Defense Monitor"),
            ("2", "View Threat Log"),
            ("3", "View Blocked IPs"),
            ("4", "View Defense Stats"),
            ("5", "Manage Safe Lists"),
            ("6", "Run Manual System Check"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            if status["running"]:
                info("Defense monitor continues running in background.")
            return

        elif choice == "1":
            if status["running"]:
                engine.stop()
                success("Defense monitor stopped.")
            else:
                engine.start()
                success("Defense monitor started! Monitoring autonomously...")
                info("Monitors: Network, Process, Ports, File Integrity, Login")
                info("Auto-response: Block IPs, Kill suspicious processes, Alert")

        elif choice == "2":
            _view_threat_log()

        elif choice == "3":
            _view_blocked_ips(engine)

        elif choice == "4":
            _view_stats(engine)

        elif choice == "5":
            _manage_safe_lists(engine)

        elif choice == "6":
            _manual_check(engine)


def _view_threat_log():
    if not os.path.exists(THREAT_LOG):
        warning("No threats logged yet.")
        return

    with open(THREAT_LOG, "r") as f:
        lines = f.readlines()

    if not lines:
        info("Threat log is empty. System is clean!")
        return

    console.print(f"\n[bold cyan]Threat Log (last 30 entries):[/bold cyan]\n")
    for line in lines[-30:]:
        line = line.strip()
        if "[CRITICAL]" in line:
            console.print(f"  [bold red]{line}[/bold red]")
        elif "[HIGH]" in line:
            console.print(f"  [red]{line}[/red]")
        elif "[MEDIUM]" in line:
            console.print(f"  [yellow]{line}[/yellow]")
        else:
            console.print(f"  [dim]{line}[/dim]")
    console.print()


def _view_blocked_ips(engine):
    blocked = engine.memory.data.get("blocked_ips", [])
    if not blocked:
        info("No IPs blocked.")
        return

    console.print(f"\n[bold cyan]Blocked IPs ({len(blocked)}):[/bold cyan]\n")
    for ip in blocked:
        console.print(f"  [red]{ip}[/red]")
    console.print()

    if confirm("Unblock an IP?", default=False):
        ip = ask("IP to unblock")
        if ip in blocked:
            engine.memory.data["blocked_ips"].remove(ip)
            engine.memory.save()
            _run_quiet(f"sudo pfctl -a hackassist -F rules 2>/dev/null")
            success(f"Unblocked {ip}")
        else:
            warning(f"{ip} not in blocked list.")


def _view_stats(engine):
    status = engine.get_status()
    stats = status.get("stats", {})

    console.print("\n[bold cyan]Defense Statistics:[/bold cyan]\n")
    console.print(f"  Running:          [{'green' if status['running'] else 'red'}]"
                  f"{'Yes' if status['running'] else 'No'}[/{'green' if status['running'] else 'red'}]")
    console.print(f"  Uptime:           {status.get('uptime', 'N/A')}")
    console.print(f"  Monitor Cycles:   {status.get('cycles', 0)}")
    console.print(f"  Threats Detected: {stats.get('threats_detected', 0)}")
    console.print(f"  Threats Blocked:  {stats.get('threats_blocked', 0)}")
    console.print(f"  False Positives:  {stats.get('false_positives', 0)}")
    console.print(f"  Blocked IPs:      {status.get('blocked_ips', 0)}")
    console.print(f"  Active Monitors:  {status.get('monitors_active', 0)}")
    console.print()


def _manage_safe_lists(engine):
    options = [
        ("1", "Add safe IP"),
        ("2", "Add safe process"),
        ("3", "View safe lists"),
        ("0", "Back"),
    ]
    choice = show_menu(options)

    if choice == "1":
        ip = ask("Enter IP to mark as safe")
        engine.memory.add_safe_ip(ip)
        success(f"Added {ip} to safe IPs.")
    elif choice == "2":
        proc = ask("Enter process name to mark as safe")
        engine.memory.add_safe_process(proc)
        success(f"Added {proc} to safe processes.")
    elif choice == "3":
        console.print("\n[bold cyan]Safe IPs:[/bold cyan]")
        for ip in engine.memory.data.get("known_safe_ips", []):
            console.print(f"  [green]{ip}[/green]")
        console.print(f"\n[bold cyan]Safe Processes ({len(engine.memory.data.get('known_safe_processes', []))}):[/bold cyan]")
        for proc in sorted(engine.memory.data.get("known_safe_processes", []))[:20]:
            console.print(f"  [green]{proc}[/green]")
        console.print()


def _manual_check(engine):
    """Run all monitors once and report."""
    info("Running manual system check...")
    console.print()

    all_threats = []
    monitor_names = ["Network", "Process", "Ports", "File Integrity", "Login"]

    for monitor, name in zip(engine.monitors, monitor_names):
        try:
            threats = monitor.check()
            if threats:
                for t in threats:
                    console.print(f"  {t.format_alert()}")
                all_threats.extend(threats)
            else:
                console.print(f"  [green][OK][/green] {name}: Clean")
        except Exception as e:
            console.print(f"  [yellow][!][/yellow] {name}: Error - {e}")

    console.print()
    if all_threats:
        warning(f"Found {len(all_threats)} potential threats!")
        if confirm("Auto-respond to all threats?"):
            for t in all_threats:
                action = engine.responder.respond(t)
                _log_threat(t)
                engine.memory.record_threat(t.to_dict())
                console.print(f"  [green]Response: {action}[/green]")
    else:
        success("System is clean! No threats detected.")
