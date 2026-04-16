"""Reverse Tunnel / Proxy Manager — Auto-setup tunnels through NAT.

Supports: ngrok, chisel, bore, ligolo-ng, SSH reverse tunnels, socat relays.
Auto-detects installed tools, generates configs, manages active tunnels.
"""

import sys
import os
import shutil
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel)
from executor import run_command, run_with_preview
from tool_manager import check_tool

# ─── Tunnel Templates ─────────────────────────────────────────────────────────

TUNNEL_CONFIGS = {
    "ngrok": {
        "check": "ngrok",
        "install": "brew install ngrok",
        "templates": {
            "HTTP Tunnel": "ngrok http {local_port}",
            "TCP Tunnel (reverse shell)": "ngrok tcp {local_port}",
            "TLS Tunnel": "ngrok tls {local_port}",
            "HTTP with Auth": "ngrok http {local_port} --basic-auth='user:pass'",
            "HTTP with Domain": "ngrok http --domain={domain} {local_port}",
        },
    },
    "chisel": {
        "check": "chisel",
        "install": "go install github.com/jpillora/chisel@latest",
        "templates": {
            "Server Mode": "chisel server --reverse --port {server_port}",
            "Client Reverse": "chisel client {server_ip}:{server_port} R:{remote_port}:127.0.0.1:{local_port}",
            "Client SOCKS": "chisel client {server_ip}:{server_port} R:socks",
            "Client Forward": "chisel client {server_ip}:{server_port} {local_port}:{target_ip}:{target_port}",
        },
    },
    "bore": {
        "check": "bore",
        "install": "cargo install bore-cli",
        "templates": {
            "Local Tunnel": "bore local {local_port} --to bore.pub",
            "Local to Custom Server": "bore local {local_port} --to {server_ip} --port {remote_port}",
            "Bore Server": "bore server --min-port 1024",
        },
    },
    "ssh_tunnel": {
        "check": "ssh",
        "install": None,
        "templates": {
            "Local Port Forward": "ssh -L {local_port}:{target_ip}:{target_port} {ssh_user}@{ssh_host}",
            "Remote Port Forward": "ssh -R {remote_port}:127.0.0.1:{local_port} {ssh_user}@{ssh_host}",
            "Dynamic SOCKS Proxy": "ssh -D {local_port} {ssh_user}@{ssh_host}",
            "Reverse SOCKS (double pivot)": "ssh -R {remote_port} -D {local_port} {ssh_user}@{ssh_host}",
            "Background Tunnel": "ssh -f -N -L {local_port}:{target_ip}:{target_port} {ssh_user}@{ssh_host}",
            "Keep-Alive Tunnel": "ssh -o ServerAliveInterval=60 -o ServerAliveCountMax=3 -N -L {local_port}:{target_ip}:{target_port} {ssh_user}@{ssh_host}",
        },
    },
    "socat": {
        "check": "socat",
        "install": "brew install socat",
        "templates": {
            "TCP Relay": "socat TCP-LISTEN:{local_port},reuseaddr,fork TCP:{target_ip}:{target_port}",
            "UDP Relay": "socat UDP-LISTEN:{local_port},reuseaddr,fork UDP:{target_ip}:{target_port}",
            "SSL Relay": "socat OPENSSL-LISTEN:{local_port},cert=server.pem,verify=0,reuseaddr,fork TCP:{target_ip}:{target_port}",
            "File to TCP": "socat TCP-LISTEN:{local_port},reuseaddr OPEN:{filename},creat,append",
        },
    },
    "ligolo": {
        "check": None,
        "install": "go install github.com/nicocha30/ligolo-ng@latest",
        "templates": {
            "Proxy (attacker)": "ligolo-proxy -selfcert -laddr 0.0.0.0:{server_port}",
            "Agent (target)": "ligolo-agent -connect {server_ip}:{server_port} -ignore-cert",
        },
    },
}

# ─── Active Tunnel Tracker ────────────────────────────────────────────────────

_active_tunnels = []


def _detect_tools():
    """Detect which tunneling tools are available."""
    status = {}
    for name, config in TUNNEL_CONFIGS.items():
        check = config.get("check")
        if check:
            status[name] = shutil.which(check) is not None
        else:
            status[name] = False  # Manual check needed
    return status


# ─── Menu ─────────────────────────────────────────────────────────────────────

def run(session):
    show_stage_header("Reverse Tunnel Manager",
                      "Setup tunnels through NAT — ngrok, chisel, bore, SSH, socat, ligolo")

    while True:
        # Show tool availability
        status = _detect_tools()

        options = [
            ("", "[bold white]── TUNNEL TOOLS ──[/bold white]"),
        ]
        idx = 1
        tool_list = list(TUNNEL_CONFIGS.keys())
        for name in tool_list:
            avail = "[green]✓[/green]" if status.get(name) else "[red]✗[/red]"
            options.append((str(idx), f"{avail} [bold]{name}[/bold]"))
            idx += 1

        options.append(("", "[bold white]── HELPERS ──[/bold white]"))
        options.append((str(idx), "Quick Callback Setup (auto-detect best tool)"))
        idx += 1
        options.append((str(idx), "Kill Active Tunnels"))
        idx += 1
        options.append((str(idx), "Tunnel Cheat Sheet"))
        idx += 1
        options.append(("0", "Back to Main Menu"))

        choice = show_menu(options)

        if choice == "0":
            return

        choice_int = int(choice)

        if choice_int <= len(tool_list):
            tool_name = tool_list[choice_int - 1]
            _tunnel_menu(tool_name, session)
        elif choice_int == len(tool_list) + 1:
            _quick_callback(status, session)
        elif choice_int == len(tool_list) + 2:
            _kill_tunnels()
        elif choice_int == len(tool_list) + 3:
            _cheat_sheet()


def _tunnel_menu(tool_name, session):
    config = TUNNEL_CONFIGS[tool_name]
    templates = config["templates"]

    console.print(f"\n[bold cyan]{tool_name.upper()} Tunnels[/bold cyan]\n")

    # Check if installed
    check = config.get("check")
    if check and not shutil.which(check):
        warning(f"{tool_name} is not installed.")
        if config.get("install"):
            console.print(f"  Install: [white]{config['install']}[/white]\n")
            if confirm("Install now?"):
                run_command(config["install"], timeout=300)
        else:
            return

    options = [(str(i + 1), name) for i, name in enumerate(templates.keys())]
    options.append(("0", "Back"))
    choice = show_menu(options)

    if choice == "0":
        return

    idx = int(choice) - 1
    template_name = list(templates.keys())[idx]
    template = templates[template_name]

    # Collect required parameters
    params = {}
    import re
    placeholders = set(re.findall(r'\{(\w+)\}', template))
    for p in sorted(placeholders):
        defaults = {
            "local_port": "4444", "remote_port": "8080", "server_port": "1080",
            "target_port": "80", "ssh_user": "root",
        }
        params[p] = ask(f"{p}", default=defaults.get(p, ""))

    cmd = template.format(**params)
    console.print(f"\n  [bold yellow]Command:[/bold yellow] {cmd}\n")

    if confirm("Run this tunnel?"):
        run_with_preview(cmd, session, "tunnel")


def _quick_callback(status, session):
    """Auto-detect best available tool and setup callback."""
    local_port = ask("Local port for callback", default="4444")

    if status.get("ngrok"):
        cmd = f"ngrok tcp {local_port}"
        info("Using ngrok for callback tunnel")
    elif status.get("chisel"):
        server = ask("Chisel server IP:PORT")
        cmd = f"chisel client {server} R:0.0.0.0:{local_port}:127.0.0.1:{local_port}"
        info("Using chisel for callback tunnel")
    elif status.get("bore"):
        cmd = f"bore local {local_port} --to bore.pub"
        info("Using bore for callback tunnel")
    elif status.get("socat"):
        target = ask("Relay target IP")
        cmd = f"socat TCP-LISTEN:{local_port},reuseaddr,fork TCP:{target}:{local_port}"
        info("Using socat for relay")
    else:
        ssh_host = ask("SSH host for tunnel")
        ssh_user = ask("SSH user", default="root")
        cmd = f"ssh -R {local_port}:127.0.0.1:{local_port} {ssh_user}@{ssh_host}"
        info("Using SSH reverse tunnel (fallback)")

    console.print(f"\n  [bold]{cmd}[/bold]\n")
    if confirm("Start tunnel?"):
        run_with_preview(cmd, session, "tunnel")


def _kill_tunnels():
    """Kill common tunnel processes."""
    tunnels = ["ngrok", "chisel", "bore", "ligolo"]
    for t in tunnels:
        code, out, _ = run_command(f"pkill -f {t} 2>/dev/null || true", timeout=5)
    success("Tunnel processes killed.")


def _cheat_sheet():
    """Quick reference for tunneling."""
    console.print("\n[bold cyan]═══ TUNNEL CHEAT SHEET ═══[/bold cyan]\n")
    sheets = {
        "SSH Local Forward": "ssh -L 8080:internal:80 user@jump  →  localhost:8080 → internal:80",
        "SSH Remote Forward": "ssh -R 9090:localhost:3000 user@vps  →  vps:9090 → your:3000",
        "SSH Dynamic SOCKS": "ssh -D 1080 user@vps  →  SOCKS5 proxy on localhost:1080",
        "Chisel Reverse": "Server: chisel server --reverse --port 8080\n"
                          "    Client: chisel client vps:8080 R:4444:127.0.0.1:4444",
        "Ngrok TCP": "ngrok tcp 4444  →  Get public TCP address for reverse shells",
        "Socat Relay": "socat TCP-LISTEN:80,fork TCP:target:80  →  Port relay",
        "Double Pivot": "ssh -J jump1,jump2 user@internal  →  Multi-hop SSH",
    }
    for name, desc in sheets.items():
        console.print(f"  [bold yellow]{name}:[/bold yellow]")
        for line in desc.split("\n"):
            console.print(f"    [white]{line}[/white]")
        console.print()
