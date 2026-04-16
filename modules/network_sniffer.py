"""Network Sniffer Module - Live packet capture and analysis in terminal (Wireshark-style TUI)."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel, show_knowledge)
from executor import run_with_preview, run_command

STAGE = "sniffer"

# Common capture filters
CAPTURE_FILTERS = {
    "HTTP Traffic": "tcp port 80 or tcp port 8080",
    "HTTPS Traffic": "tcp port 443",
    "DNS Traffic": "udp port 53",
    "SSH Traffic": "tcp port 22",
    "FTP Traffic": "tcp port 21",
    "SMTP Traffic": "tcp port 25 or tcp port 587",
    "ICMP Only": "icmp",
    "ARP Only": "arp",
    "Specific Host": "host {ip}",
    "Specific Subnet": "net {subnet}",
    "SYN Packets": "tcp[tcpflags] & (tcp-syn) != 0",
    "All TCP": "tcp",
    "All UDP": "udp",
}


def _get_interface():
    """Get network interface."""
    info("Available interfaces:")
    run_command("ip link show 2>/dev/null || ifconfig -l 2>/dev/null || networksetup -listallhardwareports 2>/dev/null")
    return ask("Enter network interface (e.g., eth0, en0, wlan0)")


def _tcpdump_live(session):
    """Live packet capture with tcpdump."""
    iface = _get_interface()
    count = ask("Number of packets to capture (0 = unlimited)", default="100")

    # Select filter
    options = [(str(i+1), f"[bold]{name}[/bold] - {filt}") for i, (name, filt) in enumerate(CAPTURE_FILTERS.items())]
    options.append((str(len(CAPTURE_FILTERS)+1), "[bold]Custom filter[/bold]"))
    options.append(("0", "[bold]No filter (capture all)[/bold]"))
    choice = show_menu(options)

    filt = ""
    if choice == "0":
        filt = ""
    elif choice == str(len(CAPTURE_FILTERS)+1):
        filt = ask("Enter custom BPF filter")
    else:
        idx = int(choice) - 1
        filters = list(CAPTURE_FILTERS.values())
        if 0 <= idx < len(filters):
            filt = filters[idx]
            if "{ip}" in filt:
                ip = ask("Enter IP address")
                filt = filt.format(ip=ip)
            elif "{subnet}" in filt:
                subnet = ask("Enter subnet (e.g., 192.168.1.0/24)")
                filt = filt.format(subnet=subnet)

    count_flag = f"-c {count}" if count and count != "0" else ""
    filter_flag = f'"{filt}"' if filt else ""
    cmd = f"tcpdump -i {iface} {count_flag} -nn -v {filter_flag}".strip()
    run_with_preview(cmd, session, STAGE)


def _tcpdump_credentials(session):
    """Capture HTTP credentials and sensitive data."""
    iface = _get_interface()
    warning("[!] Only use on networks you're authorized to monitor!")

    options = [
        ("1", "[bold]HTTP POST data[/bold]    - Capture form submissions"),
        ("2", "[bold]HTTP Auth[/bold]          - Basic/Digest authentication"),
        ("3", "[bold]FTP credentials[/bold]    - FTP USER/PASS"),
        ("4", "[bold]SMTP credentials[/bold]   - Email login capture"),
        ("5", "[bold]All cleartext[/bold]      - Combined credential capture"),
    ]
    choice = show_menu(options)

    cmds = {
        "1": f"tcpdump -i {iface} -A -s0 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' | grep -iE 'user|pass|login|email'",
        "2": f"tcpdump -i {iface} -A -s0 'tcp port 80' | grep -i 'Authorization:'",
        "3": f"tcpdump -i {iface} -A -s0 'tcp port 21' | grep -iE 'USER|PASS'",
        "4": f"tcpdump -i {iface} -A -s0 'tcp port 25 or tcp port 587' | grep -iE 'AUTH|USER|PASS'",
        "5": f"tcpdump -i {iface} -A -s0 'tcp port 80 or tcp port 21 or tcp port 25 or tcp port 110 or tcp port 143' | grep -iE 'user|pass|login|auth'",
    }
    if choice in cmds:
        run_with_preview(cmds[choice], session, STAGE)


def _tshark_live(session):
    """Live capture with tshark (Wireshark CLI)."""
    iface = _get_interface()

    options = [
        ("1", "[bold]Summary mode[/bold]    - One-line per packet"),
        ("2", "[bold]Verbose mode[/bold]    - Full packet details"),
        ("3", "[bold]Protocol stats[/bold]  - Protocol hierarchy"),
        ("4", "[bold]Conversations[/bold]   - Connection summary"),
        ("5", "[bold]HTTP requests[/bold]   - HTTP request URLs"),
        ("6", "[bold]DNS queries[/bold]     - DNS query names"),
    ]
    choice = show_menu(options)

    cmds = {
        "1": f"tshark -i {iface} -c 50",
        "2": f"tshark -i {iface} -c 20 -V",
        "3": f"tshark -i {iface} -c 500 -q -z io,phs",
        "4": f"tshark -i {iface} -c 200 -q -z conv,tcp",
        "5": f"tshark -i {iface} -Y 'http.request' -T fields -e http.host -e http.request.uri -c 50",
        "6": f"tshark -i {iface} -Y 'dns.qry.name' -T fields -e dns.qry.name -c 50",
    }
    if choice in cmds:
        run_with_preview(cmds[choice], session, STAGE)


def _capture_to_pcap(session):
    """Capture traffic to PCAP file for later analysis."""
    iface = _get_interface()
    outfile = ask("Output PCAP file path", default="/tmp/capture.pcap")
    duration = ask("Capture duration in seconds (0 = until Ctrl+C)", default="60")
    filt = ask("BPF filter (or blank for all traffic)")

    filter_flag = f'"{filt}"' if filt else ""
    dur_flag = f"-a duration:{duration}" if duration and duration != "0" else ""

    options = [
        ("1", "[bold]tcpdump[/bold]  - Standard capture"),
        ("2", "[bold]tshark[/bold]   - Wireshark capture"),
    ]
    tool = show_menu(options)

    if tool == "1":
        cmd = f"tcpdump -i {iface} -w {outfile} {filter_flag}".strip()
        if duration and duration != "0":
            cmd = f"timeout {duration} {cmd}"
    elif tool == "2":
        cmd = f"tshark -i {iface} -w {outfile} {dur_flag} {filter_flag}".strip()
    else:
        return

    run_with_preview(cmd, session, STAGE)
    success(f"Capture saved to {outfile}")


def _read_pcap(session):
    """Read and analyze an existing PCAP file."""
    pcap_file = ask("Enter PCAP file path")
    if not pcap_file:
        error("File path required.")
        return

    options = [
        ("1", "[bold]Summary[/bold]       - Packet summary list"),
        ("2", "[bold]Statistics[/bold]     - Protocol hierarchy"),
        ("3", "[bold]Conversations[/bold]  - TCP conversations"),
        ("4", "[bold]HTTP objects[/bold]   - Extract HTTP files"),
        ("5", "[bold]DNS queries[/bold]    - All DNS lookups"),
        ("6", "[bold]Endpoints[/bold]      - IP endpoint stats"),
        ("7", "[bold]Follow stream[/bold]  - Reconstruct TCP stream"),
    ]
    choice = show_menu(options)

    cmds = {
        "1": f"tshark -r {pcap_file} -c 100",
        "2": f"tshark -r {pcap_file} -q -z io,phs",
        "3": f"tshark -r {pcap_file} -q -z conv,tcp",
        "4": f"tshark -r {pcap_file} --export-objects http,/tmp/http_objects/",
        "5": f"tshark -r {pcap_file} -Y dns -T fields -e dns.qry.name -e dns.a",
        "6": f"tshark -r {pcap_file} -q -z endpoints,ip",
        "7": f"tshark -r {pcap_file} -q -z follow,tcp,ascii,0",
    }
    if choice in cmds:
        run_with_preview(cmds[choice], session, STAGE)


def _cheat_sheet():
    """Network sniffing cheat sheet."""
    content = """# Network Sniffing Cheat Sheet

## tcpdump
```
tcpdump -i eth0                    # Capture all on interface
tcpdump -i eth0 -c 100            # Capture 100 packets
tcpdump -i eth0 -w file.pcap      # Write to file
tcpdump -r file.pcap              # Read from file
tcpdump -i eth0 -nn -v 'tcp port 80'  # HTTP traffic verbose
tcpdump -i eth0 -A 'tcp port 80'  # ASCII output (see content)
tcpdump -i eth0 -X               # Hex + ASCII
```

## tshark
```
tshark -i eth0                    # Capture
tshark -i eth0 -c 50             # 50 packets
tshark -r file.pcap              # Read PCAP
tshark -r file.pcap -q -z io,phs  # Protocol stats
tshark -r file.pcap -q -z conv,tcp  # Conversations
tshark -Y 'http.request' -T fields -e http.host  # HTTP hosts
```

## Common BPF Filters
```
host 10.0.0.1                    # Specific host
net 192.168.1.0/24               # Subnet
tcp port 80                      # HTTP
udp port 53                      # DNS
tcp[tcpflags] & (tcp-syn) != 0   # SYN packets
not port 22                      # Exclude SSH
```

## Tools: tcpdump, tshark, wireshark, ngrep, tcpflow
"""
    show_knowledge(content)


def run(session):
    """Network Sniffer module entry point."""
    show_stage_header("Network Sniffer", "Live packet capture & analysis — Wireshark in your terminal")

    while True:
        options = [
            ("1", "[bold]tcpdump Live[/bold]     - Capture with filters"),
            ("2", "[bold]Credential Sniff[/bold] - Capture cleartext creds"),
            ("3", "[bold]tshark Live[/bold]      - Wireshark CLI capture"),
            ("4", "[bold]Capture to PCAP[/bold]  - Save to file"),
            ("5", "[bold]Read PCAP[/bold]        - Analyze existing capture"),
            ("6", "[bold]Cheat Sheet[/bold]      - Sniffing reference"),
            ("0", "[bold]Back to Main Menu[/bold]"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _tcpdump_live(session)
        elif choice == "2":
            _tcpdump_credentials(session)
        elif choice == "3":
            _tshark_live(session)
        elif choice == "4":
            _capture_to_pcap(session)
        elif choice == "5":
            _read_pcap(session)
        elif choice == "6":
            _cheat_sheet()
