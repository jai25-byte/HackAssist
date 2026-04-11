#!/usr/bin/env python3
"""HackAssist - Live Target Dashboard with Rich TUI."""

import os
import time
import json
import threading
from datetime import datetime

from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.columns import Columns
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

from ui import console, show_menu, ask, info, success, warning, error
from executor import run_command


class TargetDashboard:
    """Live visual dashboard for target intelligence."""

    def __init__(self, session=None):
        self.session = session
        self.target = session['target'] if session else None
        self.data = {
            'ports': [],
            'services': [],
            'vulns': [],
            'subdomains': [],
            'findings': [],
            'commands_run': 0,
            'start_time': datetime.now().isoformat(),
            'status': 'Idle',
        }
        self.running = False
        self._lock = threading.Lock()

    def update_data(self, key, value):
        with self._lock:
            if isinstance(self.data.get(key), list):
                if isinstance(value, list):
                    self.data[key].extend(value)
                else:
                    self.data[key].append(value)
            else:
                self.data[key] = value

    def _build_header(self):
        target = self.target or "No target"
        elapsed = ""
        try:
            start = datetime.fromisoformat(self.data['start_time'])
            delta = datetime.now() - start
            mins = int(delta.total_seconds() // 60)
            secs = int(delta.total_seconds() % 60)
            elapsed = f"{mins}m {secs}s"
        except Exception:
            elapsed = "N/A"

        return Panel(
            f"[bold cyan]Target:[/bold cyan] {target}  |  "
            f"[bold green]Status:[/bold green] {self.data['status']}  |  "
            f"[bold yellow]Elapsed:[/bold yellow] {elapsed}  |  "
            f"[bold magenta]Commands:[/bold magenta] {self.data['commands_run']}",
            title="[bold white]HACKASSIST DASHBOARD[/bold white]",
            border_style="green"
        )

    def _build_ports_table(self):
        table = Table(title="Open Ports", border_style="cyan", expand=True)
        table.add_column("Port", style="bold green", width=8)
        table.add_column("Service", style="cyan")
        table.add_column("Version", style="yellow")
        table.add_column("State", style="green")

        for port in self.data['ports'][-15:]:
            if isinstance(port, dict):
                table.add_row(
                    str(port.get('port', '?')),
                    port.get('service', '?'),
                    port.get('version', ''),
                    port.get('state', 'open')
                )
            else:
                table.add_row(str(port), "?", "", "open")
        return table

    def _build_vulns_table(self):
        table = Table(title="Vulnerabilities", border_style="red", expand=True)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("CVE/Name", style="yellow")
        table.add_column("Description", style="white")

        for vuln in self.data['vulns'][-10:]:
            if isinstance(vuln, dict):
                sev = vuln.get('severity', 'INFO')
                sev_color = {'CRITICAL': 'bold red', 'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'green'}.get(sev, 'white')
                table.add_row(
                    f"[{sev_color}]{sev}[/{sev_color}]",
                    vuln.get('name', '?'),
                    vuln.get('desc', '')[:60]
                )
            else:
                table.add_row("INFO", str(vuln), "")
        return table

    def _build_subdomains_panel(self):
        subs = self.data['subdomains'][-20:]
        if not subs:
            content = "[dim]No subdomains discovered yet[/dim]"
        else:
            content = "\n".join(f"[cyan]{s}[/cyan]" for s in subs)
        return Panel(content, title="Subdomains", border_style="blue")

    def _build_findings_panel(self):
        findings = self.data['findings'][-10:]
        if not findings:
            content = "[dim]No findings yet[/dim]"
        else:
            lines = []
            for f in findings:
                if isinstance(f, dict):
                    sev = f.get('severity', 'info')
                    color = {'critical': 'red', 'high': 'red', 'medium': 'yellow', 'low': 'green'}.get(sev, 'white')
                    lines.append(f"[{color}][{sev.upper()}][/{color}] {f.get('title', '?')}")
                else:
                    lines.append(str(f))
            content = "\n".join(lines)
        return Panel(content, title="Findings", border_style="yellow")

    def _build_layout(self):
        layout = Layout()
        layout.split_column(
            Layout(self._build_header(), size=3, name="header"),
            Layout(name="body"),
            Layout(self._build_findings_panel(), size=14, name="footer"),
        )
        layout["body"].split_row(
            Layout(self._build_ports_table(), name="left"),
            Layout(name="right"),
        )
        layout["right"].split_column(
            Layout(self._build_vulns_table(), name="vulns"),
            Layout(self._build_subdomains_panel(), name="subs"),
        )
        return layout

    def run_live(self):
        """Show live dashboard until user presses Ctrl+C."""
        self.running = True
        self._load_session_data()
        info("Dashboard running. Press Ctrl+C to return to menu.\n")
        try:
            with Live(self._build_layout(), console=console, refresh_per_second=2) as live:
                while self.running:
                    time.sleep(0.5)
                    self._load_session_data()
                    live.update(self._build_layout())
        except KeyboardInterrupt:
            self.running = False
            success("Dashboard closed.")

    def _load_session_data(self):
        """Load data from session files if available."""
        if not self.session:
            return
        session_dir = self.session.get('dir', '')
        if not session_dir or not os.path.exists(session_dir):
            return

        # Load findings
        findings_file = os.path.join(session_dir, 'findings.json')
        if os.path.exists(findings_file):
            try:
                with open(findings_file) as f:
                    data = json.load(f)
                    self.data['findings'] = data if isinstance(data, list) else []
            except Exception:
                pass

        # Load command log for count
        log_file = os.path.join(session_dir, 'commands.log')
        if os.path.exists(log_file):
            try:
                with open(log_file) as f:
                    self.data['commands_run'] = sum(1 for _ in f)
            except Exception:
                pass

    def show_static(self):
        """Show a static snapshot of the dashboard."""
        self._load_session_data()
        console.print(self._build_layout())


def _quick_scan(dashboard):
    """Run a quick nmap scan and populate dashboard."""
    if not dashboard.target:
        error("No target set.")
        return
    dashboard.update_data('status', 'Scanning...')
    output = run_command(f"nmap -sV --top-ports 100 -T4 {dashboard.target}", capture=True, timeout=120)
    if output:
        for line in output.split('\n'):
            line = line.strip()
            if '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0].split('/')
                    dashboard.update_data('ports', {
                        'port': port_proto[0],
                        'service': parts[2] if len(parts) > 2 else '?',
                        'version': ' '.join(parts[3:]) if len(parts) > 3 else '',
                        'state': parts[1]
                    })
    dashboard.update_data('status', 'Scan Complete')
    dashboard.data['commands_run'] += 1


def run(session):
    """Dashboard module entry point."""
    dashboard = TargetDashboard(session)

    while True:
        console.print("\n[bold green]TARGET DASHBOARD[/bold green]\n")
        options = [
            ("1", "Live Dashboard (auto-refresh)"),
            ("2", "Static Snapshot"),
            ("3", "Quick Scan & Visualize"),
            ("4", "Add Port Manually"),
            ("5", "Add Vulnerability Manually"),
            ("6", "Add Subdomain Manually"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            break
        elif choice == "1":
            dashboard.run_live()
        elif choice == "2":
            dashboard.show_static()
        elif choice == "3":
            _quick_scan(dashboard)
            dashboard.show_static()
        elif choice == "4":
            port = ask("Port number")
            svc = ask("Service name")
            ver = ask("Version (optional)") or ""
            dashboard.update_data('ports', {'port': port, 'service': svc, 'version': ver, 'state': 'open'})
            success(f"Added port {port}")
        elif choice == "5":
            name = ask("Vulnerability name/CVE")
            sev = ask("Severity (CRITICAL/HIGH/MEDIUM/LOW)")
            desc = ask("Description")
            dashboard.update_data('vulns', {'name': name, 'severity': sev.upper(), 'desc': desc})
            success(f"Added vulnerability: {name}")
        elif choice == "6":
            sub = ask("Subdomain")
            dashboard.update_data('subdomains', sub)
            success(f"Added: {sub}")
