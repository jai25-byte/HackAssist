"""Honeypot Deployer — Spin up decoy services to detect attackers.

Deploy fake SSH, HTTP, FTP, SMB services that log all attacker interactions.
"""

import sys, os, socket, threading, json, time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel)

HONEYPOT_DIR = os.path.expanduser("~/hackassist_defense/honeypots")
os.makedirs(HONEYPOT_DIR, exist_ok=True)

_active_honeypots = {}


def _log_interaction(service, addr, data):
    """Log honeypot interaction."""
    log_file = os.path.join(HONEYPOT_DIR, f"{service}_interactions.log")
    entry = {
        "timestamp": datetime.now().isoformat(),
        "service": service,
        "source_ip": addr[0],
        "source_port": addr[1],
        "data": data[:500],
    }
    with open(log_file, "a") as f:
        f.write(json.dumps(entry) + "\n")

    console.print(f"\n  [bold red]🍯 HONEYPOT HIT[/bold red] [{service}] "
                  f"from {addr[0]}:{addr[1]}")
    if data:
        console.print(f"    [dim]Data: {data[:100]}[/dim]")


class SSHHoneypot:
    """Fake SSH server that captures credentials."""

    BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"

    def __init__(self, port=2222):
        self.port = port
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        success(f"SSH honeypot started on port {self.port}")

    def stop(self):
        self.running = False

    def _serve(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("0.0.0.0", self.port))
            server.listen(5)
            server.settimeout(2)

            while self.running:
                try:
                    conn, addr = server.accept()
                    threading.Thread(target=self._handle,
                                     args=(conn, addr), daemon=True).start()
                except socket.timeout:
                    continue
        except Exception as e:
            error(f"SSH honeypot error: {e}")
        finally:
            server.close()

    def _handle(self, conn, addr):
        try:
            conn.send(self.BANNER)
            data = conn.recv(4096).decode(errors='replace')
            _log_interaction("ssh", addr, data)

            # Send fake auth prompt
            conn.send(b"Password: ")
            password = conn.recv(1024).decode(errors='replace').strip()
            if password:
                _log_interaction("ssh_password", addr, password)

            conn.send(b"Permission denied.\r\n")
            conn.close()
        except Exception:
            pass


class HTTPHoneypot:
    """Fake HTTP server that logs all requests."""

    def __init__(self, port=8888):
        self.port = port
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        success(f"HTTP honeypot started on port {self.port}")

    def stop(self):
        self.running = False

    def _serve(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("0.0.0.0", self.port))
            server.listen(5)
            server.settimeout(2)

            while self.running:
                try:
                    conn, addr = server.accept()
                    threading.Thread(target=self._handle,
                                     args=(conn, addr), daemon=True).start()
                except socket.timeout:
                    continue
        except Exception as e:
            error(f"HTTP honeypot error: {e}")
        finally:
            server.close()

    def _handle(self, conn, addr):
        try:
            request = conn.recv(8192).decode(errors='replace')
            _log_interaction("http", addr, request)

            # Fake login page response
            body = """<html><head><title>Admin Portal</title></head>
<body><h1>Admin Login</h1>
<form method='POST' action='/login'>
<input name='username' placeholder='Username'><br>
<input name='password' type='password' placeholder='Password'><br>
<input type='submit' value='Login'>
</form></body></html>"""

            response = (f"HTTP/1.1 200 OK\r\n"
                        f"Content-Type: text/html\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"Server: Apache/2.4.41\r\n\r\n{body}")
            conn.send(response.encode())
            conn.close()
        except Exception:
            pass


class FTPHoneypot:
    """Fake FTP server that logs connection attempts."""

    def __init__(self, port=2121):
        self.port = port
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        success(f"FTP honeypot started on port {self.port}")

    def stop(self):
        self.running = False

    def _serve(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("0.0.0.0", self.port))
            server.listen(5)
            server.settimeout(2)

            while self.running:
                try:
                    conn, addr = server.accept()
                    threading.Thread(target=self._handle,
                                     args=(conn, addr), daemon=True).start()
                except socket.timeout:
                    continue
        except Exception as e:
            error(f"FTP honeypot error: {e}")
        finally:
            server.close()

    def _handle(self, conn, addr):
        try:
            conn.send(b"220 FTP Server Ready\r\n")
            _log_interaction("ftp", addr, "connection")

            while True:
                data = conn.recv(1024).decode(errors='replace').strip()
                if not data:
                    break

                _log_interaction("ftp_cmd", addr, data)

                if data.upper().startswith("USER"):
                    conn.send(b"331 Password required\r\n")
                elif data.upper().startswith("PASS"):
                    _log_interaction("ftp_password", addr, data)
                    conn.send(b"530 Login incorrect\r\n")
                    break
                elif data.upper().startswith("QUIT"):
                    conn.send(b"221 Goodbye\r\n")
                    break
                else:
                    conn.send(b"500 Unknown command\r\n")
            conn.close()
        except Exception:
            pass


HONEYPOT_TYPES = {
    "ssh": SSHHoneypot,
    "http": HTTPHoneypot,
    "ftp": FTPHoneypot,
}


def _view_logs():
    """View honeypot interaction logs."""
    log_files = [f for f in os.listdir(HONEYPOT_DIR) if f.endswith(".log")]
    if not log_files:
        warning("No honeypot logs found.")
        return

    for log_file in log_files:
        path = os.path.join(HONEYPOT_DIR, log_file)
        console.print(f"\n[bold cyan]{log_file}:[/bold cyan]\n")
        with open(path) as f:
            lines = f.readlines()
        for line in lines[-20:]:
            try:
                entry = json.loads(line)
                timestamp = entry.get("timestamp", "")[:19]
                src = f"{entry.get('source_ip', '?')}:{entry.get('source_port', '?')}"
                data = entry.get("data", "")[:80]
                console.print(f"  [{timestamp}] [yellow]{src}[/yellow] → {data}")
            except json.JSONDecodeError:
                console.print(f"  [dim]{line.strip()[:100]}[/dim]")


def run(session):
    show_stage_header("Honeypot Deployer", "Deploy decoy services to detect attackers")

    while True:
        # Show active honeypots
        if _active_honeypots:
            console.print("[bold green]Active Honeypots:[/bold green]")
            for name, hp in _active_honeypots.items():
                console.print(f"  [green]●[/green] {name} on port {hp.port}")
            console.print()

        options = [
            ("1", "[bold]Deploy SSH Honeypot[/bold] (default port 2222)"),
            ("2", "[bold]Deploy HTTP Honeypot[/bold] (default port 8888)"),
            ("3", "[bold]Deploy FTP Honeypot[/bold] (default port 2121)"),
            ("4", "[bold]Deploy All[/bold] (SSH + HTTP + FTP)"),
            ("5", "View Interaction Logs"),
            ("6", "Stop All Honeypots"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            if _active_honeypots:
                info("Honeypots continue running in background.")
            return
        elif choice in ("1", "2", "3"):
            hp_map = {"1": ("ssh", 2222), "2": ("http", 8888), "3": ("ftp", 2121)}
            name, default_port = hp_map[choice]
            port = int(ask(f"Port", default=str(default_port)))
            hp = HONEYPOT_TYPES[name](port)
            hp.start()
            _active_honeypots[name] = hp
        elif choice == "4":
            for name, (cls, port) in [("ssh", (SSHHoneypot, 2222)),
                                       ("http", (HTTPHoneypot, 8888)),
                                       ("ftp", (FTPHoneypot, 2121))]:
                if name not in _active_honeypots:
                    hp = cls(port)
                    hp.start()
                    _active_honeypots[name] = hp
        elif choice == "5":
            _view_logs()
        elif choice == "6":
            for name, hp in _active_honeypots.items():
                hp.stop()
                info(f"Stopped {name} honeypot")
            _active_honeypots.clear()
            success("All honeypots stopped.")
