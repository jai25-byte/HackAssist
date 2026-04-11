#!/usr/bin/env python3
"""HackAssist - HTTP/HTTPS Proxy Interceptor."""

import socket
import threading
import ssl
import os
from datetime import datetime

from ui import console, show_menu, ask, info, success, warning, error
from executor import run_command, run_with_preview


class ProxyInterceptor:
    """Simple HTTP proxy for intercepting and logging requests."""

    def __init__(self, host='127.0.0.1', port=8080):
        self.host = host
        self.port = port
        self.running = False
        self.log_dir = os.path.expanduser("~/hackassist_proxy_logs")
        self.requests = []
        self._server = None
        self._thread = None

    def start(self):
        os.makedirs(self.log_dir, exist_ok=True)
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._server.bind((self.host, self.port))
            self._server.listen(50)
            self._server.settimeout(1.0)
            self.running = True
            self._thread = threading.Thread(target=self._accept_loop, daemon=True)
            self._thread.start()
            success(f"Proxy listening on {self.host}:{self.port}")
            info(f"Configure browser proxy to {self.host}:{self.port}")
            info(f"Logs saved to {self.log_dir}")
        except OSError as e:
            error(f"Failed to start proxy: {e}")

    def stop(self):
        self.running = False
        if self._server:
            self._server.close()
        success("Proxy stopped.")

    def _accept_loop(self):
        while self.running:
            try:
                client, addr = self._server.accept()
                threading.Thread(target=self._handle_client, args=(client, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break

    def _handle_client(self, client_sock, addr):
        try:
            data = client_sock.recv(8192)
            if not data:
                return

            request_str = data.decode('utf-8', errors='replace')
            lines = request_str.split('\r\n')
            first_line = lines[0] if lines else ''

            entry = {
                'time': datetime.now().isoformat(),
                'from': f"{addr[0]}:{addr[1]}",
                'request': first_line,
                'headers': lines[1:] if len(lines) > 1 else [],
                'size': len(data),
            }
            self.requests.append(entry)
            self._log_request(entry)

            # CONNECT method (HTTPS tunneling)
            if first_line.startswith('CONNECT'):
                self._handle_connect(client_sock, first_line)
            else:
                self._forward_http(client_sock, data, first_line)
        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _handle_connect(self, client_sock, first_line):
        parts = first_line.split()
        if len(parts) < 2:
            return
        host_port = parts[1].split(':')
        host = host_port[0]
        port = int(host_port[1]) if len(host_port) > 1 else 443

        try:
            remote = socket.create_connection((host, port), timeout=10)
            client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self._tunnel(client_sock, remote)
        except Exception:
            client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")

    def _tunnel(self, client, remote):
        """Bidirectional tunnel for CONNECT."""
        client.setblocking(False)
        remote.setblocking(False)
        import select
        while self.running:
            rlist, _, _ = select.select([client, remote], [], [], 1.0)
            for sock in rlist:
                try:
                    data = sock.recv(8192)
                    if not data:
                        return
                    if sock is client:
                        remote.sendall(data)
                    else:
                        client.sendall(data)
                except Exception:
                    return

    def _forward_http(self, client_sock, data, first_line):
        parts = first_line.split()
        if len(parts) < 2:
            return
        # Extract host from headers
        host = None
        port = 80
        for line in data.decode('utf-8', errors='replace').split('\r\n'):
            if line.lower().startswith('host:'):
                host_val = line.split(':', 1)[1].strip()
                if ':' in host_val:
                    host, port = host_val.rsplit(':', 1)
                    port = int(port)
                else:
                    host = host_val
                break
        if not host:
            return

        try:
            remote = socket.create_connection((host, port), timeout=10)
            remote.sendall(data)
            response = b""
            while True:
                try:
                    chunk = remote.recv(8192)
                    if not chunk:
                        break
                    response += chunk
                except Exception:
                    break
            client_sock.sendall(response)
            remote.close()
        except Exception:
            client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")

    def _log_request(self, entry):
        log_file = os.path.join(self.log_dir, f"proxy_{datetime.now().strftime('%Y%m%d')}.log")
        with open(log_file, 'a') as f:
            f.write(f"[{entry['time']}] {entry['from']} -> {entry['request']}\n")

    def show_history(self):
        if not self.requests:
            warning("No requests captured yet.")
            return
        from rich.table import Table
        table = Table(title="Captured Requests", border_style="cyan")
        table.add_column("#", width=4)
        table.add_column("Time", style="dim")
        table.add_column("From", style="cyan")
        table.add_column("Request", style="green")
        table.add_column("Size", style="yellow")

        for i, r in enumerate(self.requests[-50:], 1):
            table.add_row(str(i), r['time'][-8:], r['from'], r['request'][:60], str(r['size']))
        console.print(table)


_proxy = None


def _get_proxy():
    global _proxy
    if _proxy is None:
        _proxy = ProxyInterceptor()
    return _proxy


def _mitmproxy_setup(session):
    info("Setting up mitmproxy (professional intercepting proxy)...")
    run_with_preview("mitmproxy", session=session, stage="proxy")


def _burp_setup():
    info("Burp Suite Integration Tips:")
    tips = [
        "1. Download Burp Suite from portswigger.net",
        "2. Set proxy to 127.0.0.1:8080",
        "3. Install Burp CA certificate in browser",
        "4. Use Intercept tab to modify requests",
        "5. Use Repeater for manual testing",
        "6. Use Intruder for automated fuzzing",
    ]
    for t in tips:
        console.print(f"  [cyan]{t}[/cyan]")


def run(session):
    """Proxy module entry point."""
    proxy = _get_proxy()

    while True:
        status = "[green]RUNNING[/green]" if proxy.running else "[red]STOPPED[/red]"
        console.print(f"\n[bold green]PROXY INTERCEPTOR[/bold green] [{status}]\n")

        options = [
            ("1", "Start Built-in Proxy"),
            ("2", "Stop Built-in Proxy"),
            ("3", "View Captured Requests"),
            ("4", "Launch mitmproxy"),
            ("5", "Burp Suite Tips"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            break
        elif choice == "1":
            if not proxy.running:
                port = ask("Port (default 8080)") or "8080"
                proxy.port = int(port)
                proxy.start()
            else:
                warning("Proxy already running.")
        elif choice == "2":
            proxy.stop()
        elif choice == "3":
            proxy.show_history()
        elif choice == "4":
            _mitmproxy_setup(session)
        elif choice == "5":
            _burp_setup()
