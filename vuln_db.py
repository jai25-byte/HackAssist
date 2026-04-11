"""Vulnerability Database — offline CVE lookup and service-to-CVE matching."""

import sys
import os
import json
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel)
from executor import run_command

STAGE = "vuln_db"
DB_DIR = os.path.expanduser("~/hackassist_vulndb")

# ─── Built-in Vulnerability Mappings ──────────────────────────────────────────
# Common services → known CVEs (curated high-impact vulns)

VULN_MAP = {
    "apache/2.4.49": [
        {"cve": "CVE-2021-41773", "severity": "CRITICAL", "title": "Path Traversal & RCE",
         "description": "Path traversal via URL-encoded dots allows reading files and executing CGI scripts."},
    ],
    "apache/2.4.50": [
        {"cve": "CVE-2021-42013", "severity": "CRITICAL", "title": "Path Traversal bypass of CVE-2021-41773",
         "description": "Incomplete fix for CVE-2021-41773 allows RCE."},
    ],
    "openssh/7.": [
        {"cve": "CVE-2018-15473", "severity": "MEDIUM", "title": "Username Enumeration",
         "description": "OpenSSH through 7.7 allows user enumeration via malformed packets."},
    ],
    "openssh/8.": [
        {"cve": "CVE-2020-15778", "severity": "MEDIUM", "title": "Command Injection via scp",
         "description": "scp allows command injection via backtick characters in filenames."},
    ],
    "vsftpd/2.3.4": [
        {"cve": "CVE-2011-2523", "severity": "CRITICAL", "title": "Backdoor Command Execution",
         "description": "vsftpd 2.3.4 contains a backdoor allowing shell on port 6200."},
    ],
    "proftpd/1.3.5": [
        {"cve": "CVE-2015-3306", "severity": "CRITICAL", "title": "Remote Code Execution via mod_copy",
         "description": "mod_copy allows unauthenticated file copy leading to RCE."},
    ],
    "samba/3.": [
        {"cve": "CVE-2017-7494", "severity": "CRITICAL", "title": "SambaCry RCE",
         "description": "Samba 3.5+ allows remote code execution via writable share."},
    ],
    "samba/4.": [
        {"cve": "CVE-2017-7494", "severity": "CRITICAL", "title": "SambaCry RCE",
         "description": "Samba 3.5-4.5 allows remote code execution via writable share."},
    ],
    "nginx/1.": [
        {"cve": "CVE-2021-23017", "severity": "HIGH", "title": "DNS Resolver Off-by-One",
         "description": "1-byte memory overwrite in DNS resolver may allow RCE."},
    ],
    "iis/7.5": [
        {"cve": "CVE-2017-7269", "severity": "CRITICAL", "title": "WebDAV Buffer Overflow RCE",
         "description": "Buffer overflow in ScStoragePathFromUrl allows RCE."},
    ],
    "tomcat/8.": [
        {"cve": "CVE-2017-12617", "severity": "HIGH", "title": "JSP Upload via PUT",
         "description": "PUT method with JSP extension allows code execution."},
    ],
    "tomcat/9.": [
        {"cve": "CVE-2020-1938", "severity": "CRITICAL", "title": "Ghostcat AJP File Read/Inclusion",
         "description": "AJP connector allows file read and potential RCE."},
    ],
    "mysql/5.": [
        {"cve": "CVE-2012-2122", "severity": "HIGH", "title": "Authentication Bypass",
         "description": "Repeated login attempts may bypass password (1/256 chance per try)."},
    ],
    "wordpress": [
        {"cve": "CVE-2022-21661", "severity": "HIGH", "title": "SQL Injection via WP_Query",
         "description": "SQL injection in WP_Query via crafted post arguments."},
    ],
    "phpmyadmin": [
        {"cve": "CVE-2018-12613", "severity": "HIGH", "title": "Local File Inclusion",
         "description": "File inclusion via ?target= parameter in index.php."},
    ],
    "drupal/7": [
        {"cve": "CVE-2018-7600", "severity": "CRITICAL", "title": "Drupalgeddon2 RCE",
         "description": "Remote code execution via Form API."},
    ],
    "drupal/8": [
        {"cve": "CVE-2019-6340", "severity": "CRITICAL", "title": "REST RCE",
         "description": "RCE via crafted REST requests when RESTful Web Services enabled."},
    ],
    "elasticsearch": [
        {"cve": "CVE-2015-1427", "severity": "CRITICAL", "title": "Groovy Sandbox Bypass RCE",
         "description": "Dynamic scripting allows arbitrary command execution."},
    ],
    "redis": [
        {"cve": "CVE-2022-0543", "severity": "CRITICAL", "title": "Lua Sandbox Escape",
         "description": "Lua sandbox escape allows OS command execution."},
    ],
    "log4j": [
        {"cve": "CVE-2021-44228", "severity": "CRITICAL", "title": "Log4Shell RCE",
         "description": "JNDI injection via log message allows remote code execution."},
    ],
    "spring": [
        {"cve": "CVE-2022-22965", "severity": "CRITICAL", "title": "Spring4Shell RCE",
         "description": "Spring Framework RCE via data binding on JDK 9+."},
    ],
    "shellshock": [
        {"cve": "CVE-2014-6271", "severity": "CRITICAL", "title": "Shellshock Bash RCE",
         "description": "GNU Bash allows arbitrary command execution via environment variables."},
    ],
    "heartbleed": [
        {"cve": "CVE-2014-0160", "severity": "HIGH", "title": "OpenSSL Heartbleed",
         "description": "TLS heartbeat extension allows reading server memory."},
    ],
    "eternalblue": [
        {"cve": "CVE-2017-0144", "severity": "CRITICAL", "title": "EternalBlue SMBv1 RCE",
         "description": "SMBv1 buffer overflow allows remote code execution (WannaCry)."},
    ],
    "bluekeep": [
        {"cve": "CVE-2019-0708", "severity": "CRITICAL", "title": "BlueKeep RDP RCE",
         "description": "Remote Desktop Services RCE - wormable, pre-auth."},
    ],
}


def _search_vulns(query):
    """Search vulnerability database for a query."""
    query = query.lower().strip()
    results = []

    for key, vulns in VULN_MAP.items():
        if query in key.lower():
            results.extend(vulns)

    # Also search within CVE descriptions
    for key, vulns in VULN_MAP.items():
        for vuln in vulns:
            if (query in vuln["title"].lower() or
                query in vuln["description"].lower() or
                query in vuln["cve"].lower()):
                if vuln not in results:
                    results.append(vuln)

    return results


def _match_service(service, version=""):
    """Match a service/version string to known vulnerabilities."""
    results = []
    search = f"{service}/{version}".lower() if version else service.lower()

    for key, vulns in VULN_MAP.items():
        if key in search or search in key:
            results.extend(vulns)

    # Broader match: just service name
    if not results:
        for key, vulns in VULN_MAP.items():
            if service.lower() in key:
                results.extend(vulns)

    return results


def _auto_match_nmap(nmap_output):
    """Parse nmap output and auto-match to CVEs."""
    results = []
    for line in nmap_output.split("\n"):
        match = re.match(r'(\d+)/\w+\s+open\s+(\S+)\s*(.*)', line)
        if match:
            port = match.group(1)
            service = match.group(2)
            version = match.group(3).strip()
            vulns = _match_service(service, version)
            if vulns:
                results.append({"port": port, "service": service, "version": version, "vulns": vulns})
    return results


# ─── Menu ─────────────────────────────────────────────────────────────────────

def run(session):
    show_stage_header("Vulnerability Database", "Offline CVE lookup & service-to-exploit matching")

    while True:
        options = [
            ("1", "Search by CVE ID"),
            ("2", "Search by Service/Software"),
            ("3", "Auto-Match from Nmap Output"),
            ("4", "Browse All Known Vulnerabilities"),
            ("5", "Search by Keyword"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _search_cve()
        elif choice == "2":
            _search_service()
        elif choice == "3":
            _auto_match(session)
        elif choice == "4":
            _browse_all()
        elif choice == "5":
            _keyword_search()


def _display_vulns(vulns, context=""):
    sev_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue"}
    for v in vulns:
        color = sev_colors.get(v["severity"], "white")
        console.print(f"  [{color}][{v['severity']}] {v['cve']}[/{color}]")
        console.print(f"    [bold]{v['title']}[/bold]")
        console.print(f"    [dim]{v['description']}[/dim]")
        if context:
            console.print(f"    [cyan]Context: {context}[/cyan]")
        console.print()


def _search_cve():
    cve_id = ask("Enter CVE ID (e.g. CVE-2021-44228)")
    results = _search_vulns(cve_id)
    if results:
        console.print(f"\n[bold]Found {len(results)} results:[/bold]\n")
        _display_vulns(results)
    else:
        warning(f"'{cve_id}' not found in local database.")
        info("Try: searchsploit or https://cve.mitre.org for online lookup.")


def _search_service():
    service = ask("Service name (e.g. apache, openssh, mysql)")
    version = ask("Version (optional, e.g. 2.4.49)", default="")
    results = _match_service(service, version)
    if results:
        console.print(f"\n[bold]Found {len(results)} vulnerabilities for {service} {version}:[/bold]\n")
        _display_vulns(results)
    else:
        warning(f"No known vulnerabilities for '{service} {version}' in local database.")


def _auto_match(session):
    console.print("\n[bold]Paste nmap output (blank line to finish):[/bold]\n")
    lines = []
    while True:
        try:
            line = input()
            if line == "":
                break
            lines.append(line)
        except EOFError:
            break

    if not lines:
        warning("No input provided.")
        return

    nmap_output = "\n".join(lines)
    matches = _auto_match_nmap(nmap_output)

    if not matches:
        info("No known vulnerabilities matched for discovered services.")
        return

    console.print(f"\n[bold red]Found vulnerabilities for {len(matches)} services:[/bold red]\n")
    for m in matches:
        console.print(f"[bold cyan]Port {m['port']} — {m['service']} {m['version']}[/bold cyan]")
        _display_vulns(m["vulns"])

        if session:
            from session import save_finding
            for v in m["vulns"]:
                save_finding(session, "vuln_db", f"{v['cve']}: {v['title']}", v["severity"].lower(),
                             f"Port {m['port']}, {m['service']} {m['version']}: {v['description']}")


def _browse_all():
    console.print(f"\n[bold cyan]All Known Vulnerabilities ({sum(len(v) for v in VULN_MAP.values())}):[/bold cyan]\n")
    for key, vulns in sorted(VULN_MAP.items()):
        console.print(f"[bold white]{key}:[/bold white]")
        _display_vulns(vulns)


def _keyword_search():
    keyword = ask("Search keyword (e.g. rce, injection, overflow)")
    results = _search_vulns(keyword)
    if results:
        console.print(f"\n[bold]Found {len(results)} results for '{keyword}':[/bold]\n")
        _display_vulns(results)
    else:
        warning(f"No results for '{keyword}'.")
