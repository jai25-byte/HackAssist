#!/usr/bin/env python3
"""HackAssist - Network Mapper Visualization."""

import os
from datetime import datetime
from ui import console, show_menu, ask, info, success, warning, error
from executor import run_with_preview, run_command


def _discover_hosts(session):
    target = session['target'] if session else ask("Target network (e.g. 192.168.1.0/24)")
    if not target:
        return

    info(f"Discovering hosts on {target}...")
    output = run_command(f"nmap -sn {target}", capture=True, timeout=120)
    if not output:
        error("No output from scan.")
        return

    hosts = []
    lines = output.split('\n')
    current_host = {}
    for line in lines:
        if 'Nmap scan report for' in line:
            if current_host:
                hosts.append(current_host)
            parts = line.split('Nmap scan report for ')[-1]
            ip = parts.split('(')[-1].rstrip(')') if '(' in parts else parts
            hostname = parts.split(' (')[0] if '(' in parts else ''
            current_host = {'ip': ip.strip(), 'hostname': hostname.strip(), 'mac': '', 'vendor': ''}
        elif 'MAC Address:' in line:
            mac_parts = line.split('MAC Address: ')[-1]
            mac = mac_parts.split(' ')[0]
            vendor = mac_parts.split('(')[-1].rstrip(')') if '(' in mac_parts else ''
            current_host['mac'] = mac
            current_host['vendor'] = vendor
    if current_host:
        hosts.append(current_host)

    if not hosts:
        warning("No hosts discovered.")
        return

    # Display as visual map
    from rich.table import Table
    from rich.panel import Panel
    from rich.tree import Tree

    # Tree view
    tree = Tree(f"[bold green]Network: {target}[/bold green]")
    for h in hosts:
        label = f"[cyan]{h['ip']}[/cyan]"
        if h['hostname']:
            label += f" ({h['hostname']})"
        node = tree.add(label)
        if h['mac']:
            node.add(f"[dim]MAC: {h['mac']}[/dim]")
        if h['vendor']:
            node.add(f"[dim]Vendor: {h['vendor']}[/dim]")
    console.print(Panel(tree, title="Network Map", border_style="green"))

    # Table view
    table = Table(title=f"Hosts on {target}", border_style="cyan")
    table.add_column("#", width=4)
    table.add_column("IP Address", style="bold green")
    table.add_column("Hostname", style="cyan")
    table.add_column("MAC", style="yellow")
    table.add_column("Vendor", style="dim")

    for i, h in enumerate(hosts, 1):
        table.add_row(str(i), h['ip'], h['hostname'] or '-', h['mac'] or '-', h['vendor'] or '-')
    console.print(table)

    success(f"Found {len(hosts)} hosts")
    return hosts


def _service_map(session):
    target = session['target'] if session else ask("Target (IP or range)")
    if not target:
        return

    info(f"Scanning services on {target}...")
    output = run_command(f"nmap -sV --top-ports 50 -T4 {target}", capture=True, timeout=180)
    if not output:
        return

    from rich.tree import Tree
    from rich.panel import Panel

    tree = Tree(f"[bold green]Service Map: {target}[/bold green]")
    current_host = None
    for line in output.split('\n'):
        if 'Nmap scan report for' in line:
            host = line.split('Nmap scan report for ')[-1]
            current_host = tree.add(f"[bold cyan]{host}[/bold cyan]")
        elif current_host and ('/tcp' in line or '/udp' in line):
            parts = line.split()
            if len(parts) >= 3:
                port = parts[0]
                state = parts[1]
                service = ' '.join(parts[2:])
                color = 'green' if state == 'open' else 'red'
                current_host.add(f"[{color}]{port}[/{color}] {service}")

    console.print(Panel(tree, title="Service Map", border_style="cyan"))


def _topology_ascii(session):
    target = session['target'] if session else ask("Target")
    if not target:
        return

    info(f"Tracing route to {target}...")
    output = run_command(f"traceroute -m 20 {target}", capture=True, timeout=60)
    if not output:
        return

    from rich.panel import Panel
    hops = []
    for line in output.split('\n')[1:]:
        parts = line.strip().split()
        if len(parts) >= 2:
            hop_num = parts[0]
            if parts[1] == '*':
                hops.append(f"  Hop {hop_num}: * * *")
            else:
                host = parts[1]
                hops.append(f"  Hop {hop_num}: [cyan]{host}[/cyan]")

    # ASCII art
    art = "[bold green]YOU[/bold green]\n  |\n"
    for h in hops:
        art += f"{h}\n  |\n"
    art += f"[bold red]{target}[/bold red]"

    console.print(Panel(art, title="Network Topology", border_style="green"))


def _export_map(session):
    target = session['target'] if session else ask("Target network")
    if not target:
        return

    info("Scanning and exporting network map...")
    output_dir = os.path.expanduser("~/hackassist_netmap")
    os.makedirs(output_dir, exist_ok=True)

    # XML output for tools
    xml_file = os.path.join(output_dir, f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml")
    run_with_preview(f"nmap -sV -oX {xml_file} {target}", session=session, stage="netmap")

    if os.path.exists(xml_file):
        success(f"XML export: {xml_file}")
        info("Visualize with: xsltproc to HTML, or import into tools like Zenmap")


def run(session):
    """Network mapper entry point."""
    while True:
        console.print("\n[bold green]NETWORK MAPPER[/bold green]\n")
        options = [
            ("1", "Discover Hosts (Visual Map)"),
            ("2", "Service Map"),
            ("3", "Network Topology (Traceroute)"),
            ("4", "Export Scan (XML)"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            break
        elif choice == "1":
            _discover_hosts(session)
        elif choice == "2":
            _service_map(session)
        elif choice == "3":
            _topology_ascii(session)
        elif choice == "4":
            _export_map(session)
