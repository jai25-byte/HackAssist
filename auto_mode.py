"""AI Auto Mode - Autonomous hacking pipeline that chains stages automatically.

Runs full attack chains without manual intervention:
  Auto Recon → Auto Scan → Auto Enumerate → Auto Exploit suggestions
Makes intelligent decisions based on discovered data.
"""

import re
import sys
import os
import time
import subprocess
import shutil
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ui import (console, show_stage_header, info, success, warning, error,
                confirm, ask, show_results_panel)
from executor import run_command
from session import log_command, save_finding
from tool_manager import check_tool, ensure_tool


# ── Result containers ────────────────────────────────────────────────────────

class ScanResult:
    """Holds parsed scan data that flows between stages."""
    def __init__(self, target):
        self.target = target
        self.subdomains = []
        self.open_ports = []        # list of (port, protocol, service, version)
        self.os_guess = ""
        self.web_ports = []         # ports running HTTP/HTTPS
        self.directories = []       # discovered web paths
        self.vulnerabilities = []   # (title, severity, details)
        self.emails = []
        self.dns_records = []
        self.whois_info = ""
        self.raw_outputs = {}       # stage -> raw output text


# ── Autonomous Pipeline ──────────────────────────────────────────────────────

def run_auto_mode(session):
    """Main entry: fully autonomous attack pipeline."""
    show_stage_header(
        "AI AUTO MODE",
        "Autonomous reconnaissance, scanning, enumeration & analysis.\n"
        "  The AI will chain tools together and make decisions based on results."
    )

    warning("This will automatically run multiple tools against the target.")
    warning("Ensure you have EXPLICIT AUTHORIZATION before proceeding.\n")

    target = ask("Enter target IP or domain")

    depth_options = [
        ("1", "Quick    — Fast recon + top-port scan (2-5 min)"),
        ("2", "Standard — Full recon + service scan + enum (10-20 min)"),
        ("3", "Deep     — Everything including vuln scan + dir brute (30+ min)"),
    ]
    console.print("\n[bold]Scan depth:[/bold]")
    from ui import show_menu
    depth = show_menu(depth_options)

    if not confirm(f"\nLaunch autonomous scan against [bold]{target}[/bold]?"):
        warning("Aborted.")
        return

    result = ScanResult(target)
    start_time = time.time()

    console.print("\n")
    _print_phase("PHASE 1: RECONNAISSANCE")
    _auto_recon(target, result, session, depth)

    _print_phase("PHASE 2: PORT SCANNING")
    _auto_scan(target, result, session, depth)

    _print_phase("PHASE 3: SERVICE ENUMERATION")
    _auto_enumerate(target, result, session, depth)

    _print_phase("PHASE 4: VULNERABILITY ANALYSIS")
    _auto_vuln_analysis(target, result, session, depth)

    _print_phase("PHASE 5: AI ANALYSIS & RECOMMENDATIONS")
    _auto_report(target, result, session, start_time)

    elapsed = time.time() - start_time
    success(f"\nAutonomous scan completed in {elapsed:.0f} seconds.")
    console.print()


# ── Phase 1: Auto Recon ──────────────────────────────────────────────────────

def _auto_recon(target, result, session, depth):
    # WHOIS
    if shutil.which("whois"):
        info("[Recon] Running WHOIS lookup...")
        code, out, _ = run_command(f"whois {target}")
        result.whois_info = out
        result.raw_outputs["whois"] = out
        if session:
            log_command(session, "recon", f"whois {target}", out)
        _parse_whois(out, result)

    # DNS records
    if shutil.which("dig"):
        info("[Recon] Querying DNS records...")
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            code, out, _ = run_command(f"dig {target} {rtype} +short", capture=True)
            if out.strip():
                for line in out.strip().split("\n"):
                    result.dns_records.append((rtype, line.strip()))
        if result.dns_records:
            success(f"  Found {len(result.dns_records)} DNS records")
            if session:
                dns_text = "\n".join(f"{r[0]}: {r[1]}" for r in result.dns_records)
                log_command(session, "recon", "DNS enumeration", dns_text)

    # Subdomain discovery (standard+ depth)
    if depth in ("2", "3") and check_tool("subfinder"):
        info("[Recon] Discovering subdomains with subfinder...")
        code, out, _ = run_command(f"subfinder -d {target} -silent -timeout 30")
        if out.strip():
            result.subdomains = [s.strip() for s in out.strip().split("\n") if s.strip()]
            success(f"  Found {len(result.subdomains)} subdomains")
            if session:
                log_command(session, "recon", f"subfinder -d {target}", out)


def _parse_whois(raw, result):
    """Extract key WHOIS fields."""
    interesting = []
    for line in raw.split("\n"):
        lower = line.lower()
        if any(k in lower for k in ["registrar:", "creation", "expir", "name server", "org:"]):
            interesting.append(line.strip())
    if interesting:
        success(f"  Extracted {len(interesting)} WHOIS fields")


# ── Phase 2: Auto Port Scan ──────────────────────────────────────────────────

def _auto_scan(target, result, session, depth):
    if not check_tool("nmap"):
        if not ensure_tool("nmap"):
            warning("nmap not available — skipping scan phase")
            return

    # Choose scan intensity based on depth
    if depth == "1":
        cmd = f"nmap -T4 -sV --top-ports 100 -oN /tmp/hackassist_scan.txt {target}"
    elif depth == "2":
        cmd = f"nmap -T4 -sV -sC -oN /tmp/hackassist_scan.txt {target}"
    else:
        cmd = f"nmap -T4 -sV -sC -p- -oN /tmp/hackassist_scan.txt {target}"

    info(f"[Scan] Running: {cmd}")
    code, out, _ = run_command(cmd, timeout=600)
    result.raw_outputs["nmap"] = out
    if session:
        log_command(session, "scanning", cmd, out)

    _parse_nmap(out, result)

    if result.open_ports:
        success(f"  Found {len(result.open_ports)} open ports")
        console.print()
        for port, proto, service, version in result.open_ports:
            svc_str = f"{service} {version}".strip()
            console.print(f"    [yellow]{port}/{proto}[/yellow]  {svc_str}")
        console.print()
    else:
        warning("  No open ports found")

    # Auto-detect web ports
    for port, proto, service, version in result.open_ports:
        svc_lower = service.lower()
        if any(w in svc_lower for w in ["http", "web", "apache", "nginx", "iis", "tomcat"]):
            result.web_ports.append(port)
    if result.web_ports:
        info(f"  Detected web services on ports: {result.web_ports}")


def _parse_nmap(raw, result):
    """Parse nmap output to extract open ports and services."""
    for line in raw.split("\n"):
        # Match lines like: 80/tcp  open  http  Apache httpd 2.4.49
        match = re.match(
            r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)',
            line.strip()
        )
        if match:
            port = int(match.group(1))
            proto = match.group(2)
            service = match.group(3)
            version = match.group(4).strip()
            result.open_ports.append((port, proto, service, version))

    # Try to grab OS
    for line in raw.split("\n"):
        if "OS details:" in line or "Running:" in line:
            result.os_guess = line.split(":", 1)[1].strip()
            break


# ── Phase 3: Auto Enumerate ──────────────────────────────────────────────────

def _auto_enumerate(target, result, session, depth):
    if not result.open_ports:
        warning("[Enum] No open ports to enumerate")
        return

    # Web enumeration
    if result.web_ports and depth in ("2", "3"):
        for port in result.web_ports[:3]:  # limit to first 3 web ports
            scheme = "https" if port == 443 else "http"
            base_url = f"{scheme}://{target}:{port}"

            # Gobuster directory scan
            if check_tool("gobuster"):
                # Find a wordlist
                wordlist = _find_wordlist()
                if wordlist:
                    info(f"[Enum] Directory brute-force on {base_url}...")
                    cmd = f"gobuster dir -u {base_url} -w {wordlist} -q -t 20 --timeout 10s -o /tmp/hackassist_dirs.txt"
                    code, out, _ = run_command(cmd, timeout=300)
                    if out.strip():
                        dirs = [l.strip() for l in out.strip().split("\n") if l.strip()]
                        result.directories.extend(dirs)
                        success(f"  Found {len(dirs)} directories/files on port {port}")
                    if session:
                        log_command(session, "enumeration", cmd, out)

            # Nikto scan (deep only)
            if depth == "3" and check_tool("nikto"):
                info(f"[Enum] Nikto vulnerability scan on {base_url}...")
                cmd = f"nikto -h {base_url} -maxtime 120"
                code, out, _ = run_command(cmd, timeout=180)
                if session:
                    log_command(session, "enumeration", cmd, out)
                _parse_nikto(out, result)

    # SMB enumeration (port 445)
    smb_ports = [p for p, _, s, _ in result.open_ports if p in (139, 445) or "smb" in s.lower()]
    if smb_ports and check_tool("nmap"):
        info("[Enum] SMB enumeration detected — running scripts...")
        cmd = f"nmap --script smb-enum-shares,smb-enum-users,smb-os-discovery -p {smb_ports[0]} {target}"
        code, out, _ = run_command(cmd, timeout=120)
        if session:
            log_command(session, "enumeration", cmd, out)

    # FTP check (port 21)
    ftp_ports = [p for p, _, s, _ in result.open_ports if p == 21 or "ftp" in s.lower()]
    if ftp_ports and check_tool("nmap"):
        info("[Enum] FTP detected — checking anonymous access...")
        cmd = f"nmap --script ftp-anon -p {ftp_ports[0]} {target}"
        code, out, _ = run_command(cmd, timeout=60)
        if "Anonymous FTP login allowed" in out:
            result.vulnerabilities.append((
                "Anonymous FTP Access",
                "high",
                f"FTP on port {ftp_ports[0]} allows anonymous login"
            ))
            success("  [!] Anonymous FTP access detected!")
        if session:
            log_command(session, "enumeration", cmd, out)

    # SSH version check
    ssh_ports = [p for p, _, s, _ in result.open_ports if "ssh" in s.lower()]
    if ssh_ports:
        for port, _, _, version in result.open_ports:
            if "ssh" in _.lower() if isinstance(_, str) else False:
                pass
        info(f"  SSH detected on port(s): {ssh_ports}")


def _parse_nikto(raw, result):
    """Extract nikto findings."""
    for line in raw.split("\n"):
        if "+ " in line and "OSVDB" in line:
            result.vulnerabilities.append((
                line.strip(),
                "medium",
                "Detected by Nikto"
            ))


def _find_wordlist():
    """Find an available wordlist on the system."""
    candidates = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "/opt/homebrew/share/dirb/wordlists/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        os.path.expanduser("~/wordlists/common.txt"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path

    # Create a minimal wordlist if none found
    minimal = os.path.expanduser("~/tools/minimal_wordlist.txt")
    if not os.path.exists(minimal):
        os.makedirs(os.path.dirname(minimal), exist_ok=True)
        common_dirs = [
            "admin", "login", "wp-admin", "wp-login.php", "administrator",
            "dashboard", "api", "v1", "v2", "console", "phpmyadmin",
            "robots.txt", "sitemap.xml", ".git", ".env", "config",
            "backup", "test", "dev", "staging", "uploads", "images",
            "css", "js", "assets", "static", "media", "files",
            "cgi-bin", "server-status", "server-info", ".htaccess",
            ".htpasswd", "wp-content", "wp-includes", "xmlrpc.php",
            "readme.html", "license.txt", "changelog.txt",
        ]
        with open(minimal, "w") as f:
            f.write("\n".join(common_dirs) + "\n")
        info(f"  Created minimal wordlist at {minimal}")
    return minimal


# ── Phase 4: Vulnerability Analysis ──────────────────────────────────────────

def _auto_vuln_analysis(target, result, session, depth):
    """Analyze collected data for vulnerabilities and misconfigurations."""

    info("[Analysis] Analyzing collected data for vulnerabilities...\n")

    # Check for known vulnerable service versions
    _check_service_vulns(result)

    # Nmap vuln scripts (deep mode only)
    if depth == "3" and result.open_ports and check_tool("nmap"):
        ports_str = ",".join(str(p) for p, _, _, _ in result.open_ports)
        info("[Analysis] Running nmap vulnerability scripts...")
        cmd = f"nmap --script vuln -p {ports_str} {target}"
        code, out, _ = run_command(cmd, timeout=300)
        if session:
            log_command(session, "scanning", cmd, out)

        # Parse vuln script output
        if "VULNERABLE" in out:
            for line in out.split("\n"):
                if "VULNERABLE" in line or "CVE-" in line:
                    result.vulnerabilities.append((
                        line.strip(),
                        "high",
                        "Detected by nmap vuln scripts"
                    ))

    # Save findings to session
    if session:
        for title, severity, details in result.vulnerabilities:
            save_finding(session, "auto_scan", title, severity, details)


def _check_service_vulns(result):
    """Check service versions against known vulnerable versions."""
    vuln_signatures = {
        "vsftpd 2.3.4": ("vsftpd 2.3.4 Backdoor", "critical",
                          "This version contains a backdoor. Exploit: CVE-2011-2523"),
        "openssh 7.2": ("OpenSSH 7.2 User Enumeration", "medium",
                        "Vulnerable to username enumeration. CVE-2016-6210"),
        "apache 2.4.49": ("Apache 2.4.49 Path Traversal", "critical",
                          "RCE via path traversal. CVE-2021-41773"),
        "apache 2.4.50": ("Apache 2.4.50 Path Traversal Bypass", "critical",
                          "Bypass of CVE-2021-41773 fix. CVE-2021-42013"),
        "proftpd 1.3.5": ("ProFTPd 1.3.5 RCE", "critical",
                          "Remote code execution. CVE-2015-3306"),
        "samba 3.": ("Samba 3.x Potential Vulnerabilities", "high",
                     "Samba 3.x has multiple known CVEs including CVE-2017-7494"),
        "iis 6.0": ("IIS 6.0 WebDAV RCE", "critical",
                    "Buffer overflow in WebDAV. CVE-2017-7269"),
        "tomcat": ("Apache Tomcat Detected", "info",
                   "Check for /manager/html with default creds tomcat:tomcat"),
        "wordpress": ("WordPress Detected", "info",
                      "Run wpscan for detailed WordPress vulnerability analysis"),
        "phpmyadmin": ("phpMyAdmin Detected", "medium",
                       "Check version for known CVEs and try default credentials"),
    }

    for port, proto, service, version in result.open_ports:
        full_svc = f"{service} {version}".lower()
        for sig, (title, severity, details) in vuln_signatures.items():
            if sig in full_svc:
                result.vulnerabilities.append((
                    f"[Port {port}] {title}",
                    severity,
                    details
                ))
                severity_color = {"critical": "red", "high": "red", "medium": "yellow"}.get(severity, "blue")
                console.print(f"  [{severity_color}][!] {title} on port {port}[/{severity_color}]")


# ── Phase 5: Report ──────────────────────────────────────────────────────────

def _auto_report(target, result, session, start_time):
    """Generate AI analysis and attack recommendations."""
    elapsed = time.time() - start_time

    console.print()
    console.print("[bold green]" + "=" * 60 + "[/bold green]")
    console.print("[bold green]  AUTONOMOUS SCAN RESULTS[/bold green]")
    console.print("[bold green]" + "=" * 60 + "[/bold green]\n")

    # Summary table
    console.print(f"  [bold]Target:[/bold]          {target}")
    console.print(f"  [bold]Scan Time:[/bold]       {elapsed:.0f} seconds")
    console.print(f"  [bold]Open Ports:[/bold]      {len(result.open_ports)}")
    console.print(f"  [bold]Subdomains:[/bold]      {len(result.subdomains)}")
    console.print(f"  [bold]Directories:[/bold]     {len(result.directories)}")
    console.print(f"  [bold]Vulnerabilities:[/bold] {len(result.vulnerabilities)}")
    if result.os_guess:
        console.print(f"  [bold]OS Guess:[/bold]        {result.os_guess}")
    console.print()

    # Open ports detail
    if result.open_ports:
        console.print("[bold cyan]Open Ports:[/bold cyan]")
        for port, proto, service, version in result.open_ports:
            svc = f"{service} {version}".strip()
            console.print(f"  [yellow]{port:>5}/{proto}[/yellow]  {svc}")
        console.print()

    # Vulnerabilities
    if result.vulnerabilities:
        console.print("[bold red]Vulnerabilities Found:[/bold red]")
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_vulns = sorted(result.vulnerabilities, key=lambda v: severity_order.get(v[1], 5))
        for title, severity, details in sorted_vulns:
            sev_color = {"critical": "bold red", "high": "red", "medium": "yellow",
                         "low": "blue", "info": "dim"}.get(severity, "white")
            console.print(f"  [{sev_color}][{severity.upper()}][/{sev_color}] {title}")
            console.print(f"    [dim]{details}[/dim]")
        console.print()

    # Subdomains
    if result.subdomains:
        console.print(f"[bold cyan]Subdomains ({len(result.subdomains)}):[/bold cyan]")
        for sub in result.subdomains[:20]:
            console.print(f"  [dim]{sub}[/dim]")
        if len(result.subdomains) > 20:
            console.print(f"  [dim]... and {len(result.subdomains) - 20} more[/dim]")
        console.print()

    # Discovered directories
    if result.directories:
        console.print(f"[bold cyan]Discovered Paths ({len(result.directories)}):[/bold cyan]")
        for d in result.directories[:20]:
            console.print(f"  [dim]{d}[/dim]")
        console.print()

    # AI Recommendations
    _generate_recommendations(result)

    # Save auto-report if session active
    if session:
        report_path = os.path.join(session["path"], "auto_scan_report.md")
        _save_auto_report(report_path, target, result, elapsed)
        success(f"Full report saved: {report_path}")


def _generate_recommendations(result):
    """AI-driven attack path recommendations based on findings."""
    console.print("[bold green]AI RECOMMENDED NEXT STEPS:[/bold green]\n")

    recommendations = []
    priority = 1

    # Critical vulns first
    critical = [v for v in result.vulnerabilities if v[1] == "critical"]
    if critical:
        for title, _, details in critical:
            recommendations.append((priority, f"EXPLOIT: {title}", details))
            priority += 1

    # Web attack surface
    if result.web_ports:
        ports_str = ", ".join(str(p) for p in result.web_ports)
        recommendations.append((priority, f"Web services on ports {ports_str}",
                                "Run deeper web enumeration: gobuster with larger wordlists, "
                                "nikto, check for SQLi/XSS, test authentication"))
        priority += 1

    # Check for common exploitable services
    for port, _, service, version in result.open_ports:
        svc = service.lower()
        if "ftp" in svc:
            recommendations.append((priority, f"FTP on port {port}",
                                    "Try anonymous login, check version for known exploits"))
            priority += 1
        elif "ssh" in svc:
            recommendations.append((priority, f"SSH on port {port}",
                                    "Try common credentials, check for key-based auth misconfigs"))
            priority += 1
        elif "smb" in svc or port in (139, 445):
            recommendations.append((priority, f"SMB on port {port}",
                                    "Enumerate shares (smbclient), check for EternalBlue, try null session"))
            priority += 1
        elif "mysql" in svc or "postgres" in svc or "mssql" in svc:
            recommendations.append((priority, f"Database ({service}) on port {port}",
                                    "Try default credentials, check for remote access misconfig"))
            priority += 1
        elif "redis" in svc:
            recommendations.append((priority, f"Redis on port {port}",
                                    "Check for unauthenticated access — redis-cli -h target"))
            priority += 1
        elif "vnc" in svc:
            recommendations.append((priority, f"VNC on port {port}",
                                    "Try unauthenticated access, brute-force with hydra"))
            priority += 1

    # Subdomain recommendations
    if result.subdomains:
        recommendations.append((priority, f"{len(result.subdomains)} subdomains found",
                                "Scan top subdomains for additional attack surface"))
        priority += 1

    if not recommendations:
        recommendations.append((1, "No obvious attack vectors found",
                                "Try deeper scanning, different wordlists, or manual investigation"))

    for num, title, details in recommendations:
        console.print(f"  [bold yellow]{num}.[/bold yellow] [bold]{title}[/bold]")
        console.print(f"     [dim]{details}[/dim]")
    console.print()


def _save_auto_report(path, target, result, elapsed):
    """Save autonomous scan results to markdown."""
    with open(path, "w") as f:
        f.write(f"# Autonomous Scan Report: {target}\n\n")
        f.write(f"- **Scan Time:** {elapsed:.0f} seconds\n")
        f.write(f"- **Generated:** {datetime.now().isoformat()[:19]}\n\n")

        f.write("## Open Ports\n\n")
        f.write("| Port | Protocol | Service | Version |\n")
        f.write("|------|----------|---------|----------|\n")
        for port, proto, service, version in result.open_ports:
            f.write(f"| {port} | {proto} | {service} | {version} |\n")
        f.write("\n")

        if result.vulnerabilities:
            f.write("## Vulnerabilities\n\n")
            for title, severity, details in result.vulnerabilities:
                f.write(f"### [{severity.upper()}] {title}\n\n{details}\n\n")

        if result.subdomains:
            f.write("## Subdomains\n\n")
            for sub in result.subdomains:
                f.write(f"- {sub}\n")
            f.write("\n")

        if result.directories:
            f.write("## Discovered Paths\n\n")
            for d in result.directories:
                f.write(f"- {d}\n")
            f.write("\n")


# ── Utility ──────────────────────────────────────────────────────────────────

def _print_phase(text):
    console.print(f"\n[bold magenta]{'─' * 60}[/bold magenta]")
    console.print(f"[bold magenta]  {text}[/bold magenta]")
    console.print(f"[bold magenta]{'─' * 60}[/bold magenta]\n")
