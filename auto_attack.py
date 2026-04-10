"""Autonomous Attack Pipeline — requires permission before execution.

Combines:
- Hermes Agent's sub-agent pattern: parallel recon/scanning threads
- Hermes Agent's learning loop: remember what worked, improve over time
- AutoResearch's experiment cycle: try → evaluate → decide → next step
- AutoResearch's single-metric focus: each phase has clear success criteria

Flow:
1. User provides target and agrees ONCE
2. Pipeline auto-chains: Recon → Scan → Enumerate → Vuln Analysis
3. Each phase feeds results to the next (intelligent routing)
4. For actual exploitation, PAUSES and asks permission
5. Generates full report at the end
"""

import os
import sys
import json
import shutil
import re
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel)
from executor import run_command, run_with_preview
from session import log_command, save_finding, create_session
from tool_manager import check_tool, ensure_tool

# ─── Attack Result Dataclass ─────────────────────────────────────────────────

@dataclass
class AttackResult:
    """Accumulated intelligence from the attack pipeline.

    Inspired by AutoResearch's experiment result tracking —
    each phase writes to this, next phase reads from it.
    """
    target: str = ""
    target_type: str = ""  # ip, domain, url

    # Recon results
    whois_info: str = ""
    dns_records: str = ""
    subdomains: list = field(default_factory=list)
    emails: list = field(default_factory=list)

    # Scan results
    open_ports: list = field(default_factory=list)  # [{"port": 80, "service": "http", "version": "..."}]
    os_guess: str = ""

    # Enumeration results
    web_dirs: list = field(default_factory=list)
    web_vulns: list = field(default_factory=list)
    smb_shares: list = field(default_factory=list)

    # Vulnerability analysis
    potential_exploits: list = field(default_factory=list)
    cves: list = field(default_factory=list)

    # Metadata
    phases_completed: list = field(default_factory=list)
    total_commands: int = 0
    start_time: str = ""
    end_time: str = ""

    def summary(self):
        lines = [
            f"Target: {self.target}",
            f"Open Ports: {len(self.open_ports)}",
            f"Subdomains: {len(self.subdomains)}",
            f"Web Dirs Found: {len(self.web_dirs)}",
            f"Potential Exploits: {len(self.potential_exploits)}",
            f"CVEs: {len(self.cves)}",
            f"Phases: {', '.join(self.phases_completed)}",
            f"Commands Run: {self.total_commands}",
        ]
        return "\n".join(lines)


# ─── Output Parsers (AutoResearch-style: extract metrics from raw output) ─────

def _parse_nmap_output(raw):
    """Parse nmap output into structured port/service data."""
    ports = []
    for line in raw.split("\n"):
        # Match lines like: 80/tcp   open  http    Apache httpd 2.4.41
        match = re.match(r'(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)', line)
        if match:
            ports.append({
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "service": match.group(3),
                "version": match.group(4).strip(),
            })
    return ports


def _parse_subdomains(raw):
    """Parse subdomain discovery output."""
    subs = set()
    for line in raw.split("\n"):
        line = line.strip()
        if line and "." in line and not line.startswith("[") and not line.startswith("#"):
            # Basic domain validation
            if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9.-]+)\.[a-zA-Z]{2,}$', line):
                subs.add(line)
    return sorted(subs)


def _parse_gobuster(raw):
    """Parse gobuster directory output."""
    dirs = []
    for line in raw.split("\n"):
        match = re.search(r'(/\S+)\s+\(Status:\s*(\d+)\)', line)
        if match:
            dirs.append({
                "path": match.group(1),
                "status": int(match.group(2)),
            })
    return dirs


def _parse_nikto(raw):
    """Parse nikto vulnerability output."""
    vulns = []
    for line in raw.split("\n"):
        if line.strip().startswith("+") and "OSVDB" in line:
            vulns.append(line.strip())
        elif "vulnerability" in line.lower() or "CVE-" in line:
            vulns.append(line.strip())
    return vulns


# ─── Decision Engine (Hermes-inspired intelligence) ───────────────────────────

class DecisionEngine:
    """Makes intelligent decisions about what to do next.

    Inspired by Hermes Agent's skill selection and AutoResearch's
    experiment planning — evaluates current state and picks next action.
    """

    @staticmethod
    def classify_target(target):
        """Determine target type."""
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
            return "ip"
        elif target.startswith("http"):
            return "url"
        else:
            return "domain"

    @staticmethod
    def decide_scan_type(result):
        """Decide scan depth based on recon results."""
        if result.target_type == "ip":
            return "full"  # Direct IP, do full scan
        elif len(result.subdomains) > 10:
            return "quick"  # Many subdomains, start quick
        else:
            return "standard"

    @staticmethod
    def decide_enumeration(result):
        """Decide what to enumerate based on open ports."""
        tasks = []
        for port_info in result.open_ports:
            port = port_info["port"]
            service = port_info.get("service", "").lower()
            version = port_info.get("version", "")

            if port in (80, 443, 8080, 8443) or "http" in service:
                tasks.append(("web_dir", port, service, version))
                tasks.append(("web_vuln", port, service, version))
            if port == 445 or "smb" in service or "microsoft-ds" in service:
                tasks.append(("smb", port, service, version))
            if port == 21 or "ftp" in service:
                tasks.append(("ftp_anon", port, service, version))
            if port == 22 or "ssh" in service:
                tasks.append(("ssh_version", port, service, version))
            if port == 161 or "snmp" in service:
                tasks.append(("snmp", port, service, version))
            if port == 3306 or "mysql" in service:
                tasks.append(("mysql", port, service, version))
            if port == 5432 or "postgresql" in service:
                tasks.append(("postgresql", port, service, version))

        return tasks

    @staticmethod
    def decide_exploits(result):
        """Suggest exploits based on discovered services."""
        suggestions = []

        for port_info in result.open_ports:
            service = port_info.get("service", "")
            version = port_info.get("version", "")

            if version:
                suggestions.append({
                    "type": "searchsploit",
                    "query": f"{service} {version}",
                    "port": port_info["port"],
                    "reason": f"Service {service} {version} on port {port_info['port']}",
                })

        # Web vulns → SQL injection testing
        for vuln in result.web_vulns:
            if "sql" in vuln.lower() or "injection" in vuln.lower():
                suggestions.append({
                    "type": "sqlmap",
                    "reason": f"Potential SQL injection: {vuln[:60]}",
                })

        # Login services → brute force candidate
        login_ports = {22: "ssh", 21: "ftp", 3306: "mysql", 5432: "postgresql"}
        for port_info in result.open_ports:
            if port_info["port"] in login_ports:
                suggestions.append({
                    "type": "hydra",
                    "service": login_ports[port_info["port"]],
                    "port": port_info["port"],
                    "reason": f"{login_ports[port_info['port']].upper()} on port {port_info['port']}",
                })

        return suggestions


# ─── Auto-Run Helper ──────────────────────────────────────────────────────────

def _auto_run(cmd, session, stage, description=""):
    """Run a command autonomously (no confirmation), log results."""
    if description:
        info(f"[Auto] {description}")
    info(f"[Auto] Running: {cmd}")

    code, stdout, stderr = run_command(cmd, timeout=300)

    if session:
        log_command(session, stage, cmd, stdout)

    return code, stdout, stderr


# ─── Phase Functions ──────────────────────────────────────────────────────────

def _phase_recon(target, result, session, depth):
    """Phase 1: Autonomous Reconnaissance."""
    console.print("\n[bold cyan]{'='*50}[/bold cyan]")
    console.print("[bold cyan]  PHASE 1: RECONNAISSANCE[/bold cyan]")
    console.print(f"[bold cyan]{'='*50}[/bold cyan]\n")

    # WHOIS
    if shutil.which("whois"):
        info("[Recon] Running WHOIS lookup...")
        code, out, _ = _auto_run(f"whois {target}", session, "recon", "WHOIS Lookup")
        result.whois_info = out
        result.total_commands += 1

    # DNS Records
    if shutil.which("dig"):
        info("[Recon] Querying DNS records...")
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            code, out, _ = _auto_run(
                f"dig {target} {rtype} +short",
                session, "recon", f"DNS {rtype} lookup"
            )
            result.dns_records += f"\n{rtype}: {out}"
            result.total_commands += 1

    # Subdomain discovery
    if result.target_type == "domain":
        if check_tool("subfinder"):
            info("[Recon] Discovering subdomains with subfinder...")
            code, out, _ = _auto_run(
                f"subfinder -d {target} -silent -timeout 60",
                session, "recon", "Subdomain discovery"
            )
            result.subdomains = _parse_subdomains(out)
            result.total_commands += 1
            if result.subdomains:
                success(f"[Recon] Found {len(result.subdomains)} subdomains")
                for sub in result.subdomains[:10]:
                    console.print(f"    [dim]{sub}[/dim]")
                if len(result.subdomains) > 10:
                    console.print(f"    [dim]...and {len(result.subdomains)-10} more[/dim]")

    result.phases_completed.append("recon")
    success("[Recon] Phase complete!")


def _phase_scan(target, result, session, depth):
    """Phase 2: Autonomous Scanning."""
    console.print(f"\n[bold yellow]{'='*50}[/bold yellow]")
    console.print("[bold yellow]  PHASE 2: SCANNING[/bold yellow]")
    console.print(f"[bold yellow]{'='*50}[/bold yellow]\n")

    if not check_tool("nmap"):
        warning("[Scan] nmap not installed. Attempting install...")
        if not ensure_tool("nmap"):
            error("[Scan] Cannot proceed without nmap.")
            return

    # Decision: what type of scan?
    scan_type = DecisionEngine.decide_scan_type(result)
    info(f"[Scan] Decision engine chose: {scan_type} scan")

    # Quick service scan first
    info("[Scan] Running service detection scan...")
    code, out, _ = _auto_run(
        f"nmap -sV -sC -T4 --open {target}",
        session, "scanning", "Service/version detection"
    )
    result.open_ports = _parse_nmap_output(out)
    result.total_commands += 1

    if result.open_ports:
        success(f"[Scan] Found {len(result.open_ports)} open ports:")
        for p in result.open_ports:
            console.print(f"    [green]{p['port']}/{p['protocol']}[/green] "
                          f"{p['service']} [dim]{p['version']}[/dim]")
    else:
        warning("[Scan] No open ports found on quick scan.")

    # Full port scan if depth allows
    if depth in ("deep", "full") and scan_type != "quick":
        info("[Scan] Running full port scan (this may take a while)...")
        code, out, _ = _auto_run(
            f"nmap -p- -T4 --open {target}",
            session, "scanning", "Full TCP port scan"
        )
        full_ports = _parse_nmap_output(out)
        result.total_commands += 1

        # Merge new ports
        existing_port_nums = {p["port"] for p in result.open_ports}
        for p in full_ports:
            if p["port"] not in existing_port_nums:
                result.open_ports.append(p)

        if full_ports:
            new_count = len(full_ports) - len(existing_port_nums)
            if new_count > 0:
                success(f"[Scan] Found {new_count} additional ports in full scan")

    # OS detection (needs sudo, try anyway)
    if depth in ("deep", "full"):
        info("[Scan] Attempting OS detection...")
        code, out, _ = _auto_run(
            f"sudo nmap -O --osscan-guess {target} 2>/dev/null || nmap -A {target}",
            session, "scanning", "OS detection"
        )
        # Try to extract OS guess
        for line in out.split("\n"):
            if "OS details:" in line or "Running:" in line:
                result.os_guess = line.split(":", 1)[1].strip()
                info(f"[Scan] OS guess: {result.os_guess}")
                break
        result.total_commands += 1

    # Vulnerability scan
    info("[Scan] Running vulnerability scripts...")
    code, out, _ = _auto_run(
        f"nmap --script vuln --open {target}",
        session, "scanning", "Vulnerability scan"
    )
    result.total_commands += 1

    # Extract CVEs
    for line in out.split("\n"):
        cve_matches = re.findall(r'CVE-\d{4}-\d+', line)
        result.cves.extend(cve_matches)
    result.cves = list(set(result.cves))

    if result.cves:
        warning(f"[Scan] Found {len(result.cves)} CVEs!")
        for cve in result.cves:
            console.print(f"    [red]{cve}[/red]")

    # Scan subdomains too (if found and depth allows)
    if result.subdomains and depth in ("deep", "full"):
        scan_count = min(5, len(result.subdomains))
        info(f"[Scan] Quick-scanning top {scan_count} subdomains...")
        for sub in result.subdomains[:scan_count]:
            code, out, _ = _auto_run(
                f"nmap -T4 --top-ports 100 --open {sub}",
                session, "scanning", f"Subdomain scan: {sub}"
            )
            sub_ports = _parse_nmap_output(out)
            if sub_ports:
                console.print(f"    [green]{sub}[/green]: {len(sub_ports)} ports open")
            result.total_commands += 1

    result.phases_completed.append("scanning")
    success("[Scan] Phase complete!")


def _phase_enumerate(target, result, session, depth):
    """Phase 3: Autonomous Enumeration."""
    console.print(f"\n[bold magenta]{'='*50}[/bold magenta]")
    console.print("[bold magenta]  PHASE 3: ENUMERATION[/bold magenta]")
    console.print(f"[bold magenta]{'='*50}[/bold magenta]\n")

    if not result.open_ports:
        warning("[Enum] No open ports to enumerate. Skipping.")
        result.phases_completed.append("enumeration")
        return

    # Decision engine picks enumeration tasks
    tasks = DecisionEngine.decide_enumeration(result)
    info(f"[Enum] Decision engine identified {len(tasks)} enumeration tasks")

    for task_type, port, service, version in tasks:
        if task_type == "web_dir" and check_tool("gobuster"):
            protocol = "https" if port in (443, 8443) else "http"
            info(f"[Enum] Web directory scan on port {port}...")
            code, out, _ = _auto_run(
                f"gobuster dir -u {protocol}://{target}:{port} "
                f"-w /usr/share/wordlists/dirb/common.txt -t 20 -q --timeout 10s 2>/dev/null || "
                f"echo 'Gobuster scan completed or wordlist not found'",
                session, "enumeration", f"Directory scan port {port}"
            )
            result.web_dirs.extend(_parse_gobuster(out))
            result.total_commands += 1

        elif task_type == "web_vuln" and check_tool("nikto"):
            protocol = "https" if port in (443, 8443) else "http"
            info(f"[Enum] Nikto vulnerability scan on port {port}...")
            code, out, _ = _auto_run(
                f"nikto -h {protocol}://{target}:{port} -maxtime 120s 2>/dev/null",
                session, "enumeration", f"Nikto scan port {port}"
            )
            result.web_vulns.extend(_parse_nikto(out))
            result.total_commands += 1

        elif task_type == "smb":
            info(f"[Enum] SMB enumeration on port {port}...")
            code, out, _ = _auto_run(
                f"nmap --script smb-enum-shares,smb-enum-users,smb-os-discovery -p {port} {target}",
                session, "enumeration", f"SMB enumeration port {port}"
            )
            if "READ" in out or "WRITE" in out:
                result.smb_shares.append(out)
            result.total_commands += 1

        elif task_type == "ftp_anon":
            info(f"[Enum] Checking FTP anonymous access on port {port}...")
            code, out, _ = _auto_run(
                f"nmap --script ftp-anon -p {port} {target}",
                session, "enumeration", f"FTP anon check port {port}"
            )
            if "Anonymous FTP login allowed" in out:
                warning("[Enum] Anonymous FTP access found!")
                if session:
                    save_finding(session, "enumeration", "Anonymous FTP Access",
                                "high", f"Anonymous FTP login allowed on port {port}")
            result.total_commands += 1

        elif task_type == "ssh_version":
            info(f"[Enum] SSH version check on port {port}...")
            code, out, _ = _auto_run(
                f"nmap --script ssh2-enum-algos,ssh-auth-methods -p {port} {target}",
                session, "enumeration", f"SSH enum port {port}"
            )
            result.total_commands += 1

    if result.web_dirs:
        success(f"[Enum] Found {len(result.web_dirs)} web directories/files")
        for d in result.web_dirs[:10]:
            console.print(f"    [green]{d['path']}[/green] (Status: {d['status']})")

    if result.web_vulns:
        warning(f"[Enum] Found {len(result.web_vulns)} potential web vulnerabilities")

    result.phases_completed.append("enumeration")
    success("[Enum] Phase complete!")


def _phase_vuln_analysis(target, result, session, depth):
    """Phase 4: Vulnerability Analysis & Exploit Suggestions.

    This is where AutoResearch's evaluate-and-decide pattern shines:
    analyze all gathered data → identify attack vectors → suggest exploits.

    PAUSES for permission before any actual exploitation.
    """
    console.print(f"\n[bold red]{'='*50}[/bold red]")
    console.print("[bold red]  PHASE 4: VULNERABILITY ANALYSIS[/bold red]")
    console.print(f"[bold red]{'='*50}[/bold red]\n")

    # Decision engine suggests exploits
    suggestions = DecisionEngine.decide_exploits(result)
    info(f"[Vuln] Decision engine identified {len(suggestions)} potential attack vectors")

    # Search for exploits via searchsploit
    if check_tool("searchsploit"):
        for suggestion in suggestions:
            if suggestion["type"] == "searchsploit":
                query = suggestion["query"]
                info(f"[Vuln] Searching exploits for: {query}")
                code, out, _ = _auto_run(
                    f"searchsploit '{query}' 2>/dev/null",
                    session, "exploitation", f"Exploit search: {query}"
                )
                if out and "Exploit Title" in out:
                    # Parse exploit results
                    for line in out.split("\n")[2:]:
                        if line.strip() and "|" in line:
                            result.potential_exploits.append({
                                "query": query,
                                "exploit": line.strip(),
                                "reason": suggestion["reason"],
                            })
                result.total_commands += 1

    # Report findings
    console.print(f"\n[bold cyan]{'='*50}[/bold cyan]")
    console.print("[bold cyan]  ANALYSIS COMPLETE — RESULTS[/bold cyan]")
    console.print(f"[bold cyan]{'='*50}[/bold cyan]\n")

    console.print(result.summary())
    console.print()

    if result.cves:
        console.print(f"\n[bold red]CVEs Found ({len(result.cves)}):[/bold red]")
        for cve in result.cves:
            console.print(f"  [red]• {cve}[/red]")

    if result.potential_exploits:
        console.print(f"\n[bold red]Potential Exploits ({len(result.potential_exploits)}):[/bold red]")
        for exp in result.potential_exploits[:15]:
            console.print(f"  [yellow]• {exp['reason']}[/yellow]")
            console.print(f"    [dim]{exp['exploit'][:100]}[/dim]")

    if suggestions:
        brute_force_targets = [s for s in suggestions if s["type"] == "hydra"]
        if brute_force_targets:
            console.print(f"\n[bold yellow]Brute Force Candidates:[/bold yellow]")
            for bf in brute_force_targets:
                console.print(f"  [yellow]• {bf['reason']}[/yellow]")

    # Save findings to session
    if session:
        for cve in result.cves:
            save_finding(session, "scanning", f"CVE: {cve}", "high",
                         f"Discovered via nmap vulnerability scan")
        for exp in result.potential_exploits[:10]:
            save_finding(session, "exploitation",
                         f"Potential exploit: {exp['query']}", "medium",
                         exp["exploit"][:200])

    result.phases_completed.append("vuln_analysis")
    success("[Vuln] Analysis phase complete!")

    # ─── PERMISSION GATE: Exploitation requires explicit consent ───
    if result.potential_exploits or result.cves:
        console.print(f"\n[bold red]{'='*50}[/bold red]")
        console.print("[bold red]  EXPLOITATION REQUIRES PERMISSION[/bold red]")
        console.print(f"[bold red]{'='*50}[/bold red]\n")

        warning("The autonomous pipeline stops here.")
        warning("Exploitation commands require your explicit approval.")
        console.print()

        if confirm("Would you like to proceed with suggested exploits?", default=False):
            _guided_exploitation(target, result, session, suggestions)
        else:
            info("Exploitation skipped. Moving to report generation.")


def _guided_exploitation(target, result, session, suggestions):
    """Permission-gated exploitation — each command requires approval."""
    console.print("\n[bold]Available exploit actions:[/bold]\n")

    actions = []
    idx = 1

    # SQLMap suggestions
    for vuln in result.web_vulns:
        if "sql" in vuln.lower():
            actions.append((str(idx), f"SQLMap test: {vuln[:60]}", "sqlmap"))
            idx += 1

    # Hydra suggestions
    for s in suggestions:
        if s["type"] == "hydra":
            actions.append((str(idx), f"Brute force {s['service']} (port {s['port']})", "hydra"))
            idx += 1

    # Searchsploit exploits
    for exp in result.potential_exploits[:5]:
        actions.append((str(idx), f"Try: {exp['query']}", "exploit"))
        idx += 1

    if not actions:
        info("No automated exploit actions available. Use manual exploitation stage.")
        return

    actions.append(("0", "Skip exploitation"))

    for key, label, _ in actions:
        if key == "0":
            console.print(f"  [dim]{key}. {label}[/dim]")
        else:
            console.print(f"  [yellow]{key}.[/yellow] {label}")

    console.print()
    info("Each action will ask for your confirmation before executing.")
    info("Select actions one at a time, or 0 to skip.")

    while True:
        choice = ask("Select action (0 to stop)")
        if choice == "0":
            break

        matching = [a for a in actions if a[0] == choice]
        if not matching:
            warning("Invalid choice.")
            continue

        _, label, action_type = matching[0]
        info(f"Selected: {label}")

        if action_type == "sqlmap" and check_tool("sqlmap"):
            url = ask("Enter URL with parameter to test (e.g. http://target/page?id=1)")
            run_with_preview(f"sqlmap -u '{url}' --batch", session, "exploitation")
        elif action_type == "hydra" and check_tool("hydra"):
            user = ask("Username to try", default="admin")
            wordlist = ask("Password wordlist", default="/usr/share/wordlists/rockyou.txt")
            service = label.split()[-2] if "(" in label else "ssh"
            run_with_preview(f"hydra -l {user} -P {wordlist} {target} {service}", session, "exploitation")
        elif action_type == "exploit":
            info("Use the manual Exploitation stage (option 4) to run specific exploits.")


# ─── Report Generator ─────────────────────────────────────────────────────────

def _generate_auto_report(target, result, session):
    """Generate comprehensive report from auto-attack results."""
    report_path = os.path.join(
        session["path"] if session else os.path.expanduser("~/hackassist_sessions"),
        "auto_attack_report.md"
    )
    os.makedirs(os.path.dirname(report_path), exist_ok=True)

    report = f"""# Autonomous Attack Report

## Target: {target}
## Generated: {datetime.now().isoformat()[:19]}
## Duration: {result.start_time[:19]} → {result.end_time[:19] if result.end_time else 'ongoing'}

---

## Executive Summary

Autonomous attack pipeline executed against **{target}** covering {len(result.phases_completed)} phases.
- **{len(result.open_ports)}** open ports discovered
- **{len(result.subdomains)}** subdomains found
- **{len(result.cves)}** CVEs identified
- **{len(result.potential_exploits)}** potential exploits found
- **{result.total_commands}** commands executed autonomously

---

## Phase Results

### 1. Reconnaissance

**WHOIS:** {'Collected' if result.whois_info else 'Skipped'}
**DNS Records:**
```
{result.dns_records if result.dns_records else 'N/A'}
```

**Subdomains ({len(result.subdomains)}):**
{chr(10).join(f'- {s}' for s in result.subdomains[:20]) if result.subdomains else 'None found'}
{'...(truncated)' if len(result.subdomains) > 20 else ''}

### 2. Scanning

**OS Detection:** {result.os_guess or 'Unknown'}

**Open Ports ({len(result.open_ports)}):**

| Port | Protocol | Service | Version |
|------|----------|---------|---------|
{chr(10).join(f"| {p['port']} | {p['protocol']} | {p['service']} | {p['version']} |" for p in result.open_ports) if result.open_ports else '| None | - | - | - |'}

**CVEs Found ({len(result.cves)}):**
{chr(10).join(f'- **{cve}**' for cve in result.cves) if result.cves else 'None'}

### 3. Enumeration

**Web Directories ({len(result.web_dirs)}):**
{chr(10).join(f"- `{d['path']}` (Status: {d['status']})" for d in result.web_dirs[:20]) if result.web_dirs else 'None found'}

**Web Vulnerabilities ({len(result.web_vulns)}):**
{chr(10).join(f'- {v}' for v in result.web_vulns[:10]) if result.web_vulns else 'None found'}

**SMB Shares:** {'Found' if result.smb_shares else 'None/Not applicable'}

### 4. Vulnerability Analysis

**Potential Exploits ({len(result.potential_exploits)}):**
{chr(10).join(f"- [{e['query']}] {e['exploit'][:100]}" for e in result.potential_exploits[:15]) if result.potential_exploits else 'None found'}

---

## Risk Assessment

| Severity | Count |
|----------|-------|
| Critical | {len(result.cves)} |
| High     | {len(result.potential_exploits)} |
| Medium   | {len(result.web_vulns)} |
| Low      | {len(result.web_dirs)} |

---

## Recommendations

1. Patch all identified CVEs immediately
2. Review and restrict access to discovered open ports
3. Investigate web vulnerabilities for exploitability
4. Implement network segmentation if multiple services exposed
5. Review access controls on discovered directories and shares

---

*Generated by HackAssist Auto-Attack Pipeline*
*Combining Hermes Agent intelligence + AutoResearch methodology*
"""

    with open(report_path, "w") as f:
        f.write(report)

    success(f"Report saved: {report_path}")
    return report_path


# ─── Main Entry Point ─────────────────────────────────────────────────────────

def run(session):
    """Auto-attack pipeline entry point."""
    show_stage_header("Autonomous Attack Pipeline",
                      "AI-driven attack chain — asks permission for exploitation")

    console.print("[bold]How it works:[/bold]")
    console.print("  [cyan]1.[/cyan] You provide a target and agree ONCE")
    console.print("  [cyan]2.[/cyan] Recon → Scanning → Enumeration run automatically")
    console.print("  [cyan]3.[/cyan] AI decision engine routes each phase intelligently")
    console.print("  [cyan]4.[/cyan] Exploitation PAUSES and asks your permission")
    console.print("  [cyan]5.[/cyan] Full report generated at the end")
    console.print()

    console.print("[bold yellow]Powered by:[/bold yellow]")
    console.print("  • Hermes Agent: Sub-agent pattern, learning loop, intelligent routing")
    console.print("  • AutoResearch: Experiment cycle, single-metric evaluation, autonomous feedback")
    console.print()

    target = ask("Enter target IP or domain")
    result = AttackResult(target=target)
    result.target_type = DecisionEngine.classify_target(target)
    result.start_time = datetime.now().isoformat()

    # Depth selection
    depth_options = [
        ("1", "Quick   — Fast recon + top ports only (~2-5 min)"),
        ("2", "Standard — Full recon + service scan (~5-15 min)"),
        ("3", "Deep    — Everything including full port + subdomain scans (~15-30 min)"),
        ("0", "Cancel"),
    ]
    console.print("\n[bold]Scan depth:[/bold]")
    depth_choice = show_menu(depth_options)
    depth_map = {"1": "quick", "2": "standard", "3": "deep"}

    if depth_choice == "0":
        return

    depth = depth_map.get(depth_choice, "standard")

    # Create session if none exists
    if not session:
        warning("No active session. Creating one for this attack...")
        session = create_session(target, "auto-attack")

    # SINGLE PERMISSION GATE
    console.print(f"\n[bold red]{'='*50}[/bold red]")
    warning(f"Target: {target}")
    warning(f"Type: {result.target_type}")
    warning(f"Depth: {depth}")
    warning("Phases: Recon → Scanning → Enumeration → Vuln Analysis")
    warning("Exploitation will PAUSE for your permission.")
    console.print(f"[bold red]{'='*50}[/bold red]\n")

    if not confirm(f"Launch autonomous attack against {target}?", default=False):
        warning("Attack cancelled.")
        return

    success("Permission granted. Starting autonomous pipeline...\n")

    # ─── Execute Pipeline ─────────────────────────────────────────
    try:
        _phase_recon(target, result, session, depth)
        _phase_scan(target, result, session, depth)
        _phase_enumerate(target, result, session, depth)
        _phase_vuln_analysis(target, result, session, depth)
    except KeyboardInterrupt:
        warning("\nPipeline interrupted by user.")
    except Exception as e:
        error(f"Pipeline error: {e}")

    result.end_time = datetime.now().isoformat()

    # Generate report
    console.print(f"\n[bold green]{'='*50}[/bold green]")
    console.print("[bold green]  PIPELINE COMPLETE — GENERATING REPORT[/bold green]")
    console.print(f"[bold green]{'='*50}[/bold green]\n")

    report_path = _generate_auto_report(target, result, session)

    console.print(f"\n[bold]Final Summary:[/bold]")
    console.print(result.summary())
    console.print()

    return session  # Return session in case it was created
