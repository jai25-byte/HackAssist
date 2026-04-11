#!/usr/bin/env python3
"""HackAssist - OSINT Framework Module."""

from ui import console, show_menu, ask, info, success, warning, error
from executor import run_with_preview, run_command


PERSON_OSINT = {
    'Username Search (sherlock)': 'sherlock {username}',
    'Email Lookup (holehe)': 'holehe {email}',
    'Email to Domains (theHarvester)': 'theHarvester -d {domain} -b all -l 100',
    'Phone Lookup (phoneinfoga)': 'phoneinfoga scan -n {phone}',
    'Social Media': 'sherlock {username} --print-found',
}

DOMAIN_OSINT = {
    'WHOIS': 'whois {target}',
    'DNS Records': 'dig ANY {target}',
    'Subdomains (subfinder)': 'subfinder -d {target} -silent',
    'Subdomains (amass)': 'amass enum -passive -d {target}',
    'Certificate Transparency': 'curl -s "https://crt.sh/?q=%25.{target}&output=json" | python3 -c "import sys,json;[print(x[\'name_value\']) for x in json.load(sys.stdin)]" 2>/dev/null | sort -u',
    'Wayback URLs': 'curl -s "https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=text&fl=original&collapse=urlkey" | head -50',
    'Technology Stack': 'whatweb {target}',
    'Robots.txt': 'curl -s http://{target}/robots.txt',
    'Sitemap': 'curl -s http://{target}/sitemap.xml | head -50',
    'Security Headers': 'curl -sI http://{target} | grep -iE "(x-frame|x-xss|x-content|strict-transport|content-security)"',
}

IP_OSINT = {
    'IP Info': 'curl -s ipinfo.io/{target}',
    'Reverse DNS': 'dig -x {target}',
    'ASN Lookup': 'whois -h whois.cymru.com " -v {target}"',
    'Shodan (CLI)': 'shodan host {target}',
    'Traceroute': 'traceroute {target}',
    'GeoIP': 'curl -s "http://ip-api.com/json/{target}"',
}

GOOGLE_DORKS = {
    'Find login pages': 'site:{target} inurl:login OR inurl:admin OR inurl:signin',
    'Exposed files': 'site:{target} ext:pdf OR ext:doc OR ext:xls OR ext:sql OR ext:log',
    'Config files': 'site:{target} ext:conf OR ext:cfg OR ext:env OR ext:ini',
    'Error pages': 'site:{target} "error" OR "warning" OR "mysql" OR "syntax"',
    'Directories': 'site:{target} intitle:"index of"',
    'Subdomains': 'site:*.{target}',
    'Sensitive paths': 'site:{target} inurl:wp-admin OR inurl:phpmyadmin OR inurl:.git',
    'Leaked passwords': 'site:{target} inurl:password OR inurl:passwd filetype:txt',
    'API endpoints': 'site:{target} inurl:api OR inurl:v1 OR inurl:v2',
    'Backup files': 'site:{target} ext:bak OR ext:old OR ext:backup',
}


def _run_category(title, commands, session, target_key='target'):
    console.print(f"\n[bold cyan]{title}[/bold cyan]\n")
    options = [(str(i), name) for i, name in enumerate(commands.keys(), 1)]
    options.append(("0", "Back"))
    choice = show_menu(options)
    if choice == "0":
        return
    try:
        idx = int(choice) - 1
        name = list(commands.keys())[idx]
        cmd = commands[name]
        if '{target}' in cmd:
            target = session['target'] if session else ask("Target")
            cmd = cmd.replace('{target}', target)
        if '{username}' in cmd:
            cmd = cmd.replace('{username}', ask("Username"))
        if '{email}' in cmd:
            cmd = cmd.replace('{email}', ask("Email"))
        if '{domain}' in cmd:
            cmd = cmd.replace('{domain}', ask("Domain"))
        if '{phone}' in cmd:
            cmd = cmd.replace('{phone}', ask("Phone number"))
        run_with_preview(cmd, session=session, stage="osint")
    except (ValueError, IndexError):
        pass


def _google_dorks(session):
    target = session['target'] if session else ask("Target domain")
    console.print("\n[bold cyan]Google Dorks[/bold cyan]\n")

    from rich.table import Table
    table = Table(border_style="cyan")
    table.add_column("#", width=4)
    table.add_column("Purpose", style="cyan")
    table.add_column("Dork", style="yellow")

    for i, (purpose, dork) in enumerate(GOOGLE_DORKS.items(), 1):
        table.add_row(str(i), purpose, dork.replace('{target}', target))
    console.print(table)
    info("Copy and paste these into Google search.")


def _data_breach_check():
    info("Data Breach Checking Resources:")
    resources = [
        ("Have I Been Pwned", "https://haveibeenpwned.com"),
        ("DeHashed", "https://dehashed.com"),
        ("LeakCheck", "https://leakcheck.io"),
        ("IntelX", "https://intelx.io"),
        ("Snusbase", "https://snusbase.com"),
    ]
    from rich.table import Table
    table = Table(border_style="cyan")
    table.add_column("Service", style="cyan")
    table.add_column("URL", style="green")
    for name, url in resources:
        table.add_row(name, url)
    console.print(table)


def run(session):
    """OSINT framework entry point."""
    while True:
        console.print("\n[bold green]OSINT FRAMEWORK[/bold green]\n")
        options = [
            ("1", "Person OSINT"),
            ("2", "Domain OSINT"),
            ("3", "IP OSINT"),
            ("4", "Google Dorks"),
            ("5", "Data Breach Check"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            break
        elif choice == "1":
            _run_category("Person OSINT", PERSON_OSINT, session)
        elif choice == "2":
            _run_category("Domain OSINT", DOMAIN_OSINT, session)
        elif choice == "3":
            _run_category("IP OSINT", IP_OSINT, session)
        elif choice == "4":
            _google_dorks(session)
        elif choice == "5":
            _data_breach_check()
