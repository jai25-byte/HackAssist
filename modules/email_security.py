"""Email Security Checker — SPF/DKIM/DMARC analysis, header forensics.

Validate email security configurations, analyze headers for spoofing indicators.
"""

import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel)
from executor import run_command, run_with_preview
from session import save_finding


def _check_spf(domain, session):
    info(f"Checking SPF record for {domain}...")
    code, out, _ = run_command(f"dig {domain} TXT +short | grep -i spf", timeout=15)
    if "v=spf" in out.lower():
        success(f"SPF Record found:")
        console.print(f"  [green]{out.strip()}[/green]\n")
        # Analyze SPF
        if "-all" in out:
            success("  SPF policy: HARD FAIL (-all) — Good, strict policy")
        elif "~all" in out:
            warning("  SPF policy: SOFT FAIL (~all) — Moderate, allows through")
        elif "?all" in out:
            warning("  SPF policy: NEUTRAL (?all) — Weak, doesn't enforce")
        elif "+all" in out:
            error("  SPF policy: PASS ALL (+all) — DANGEROUS! Anyone can spoof!")
            if session:
                save_finding(session, "email", f"SPF +all on {domain}", "critical",
                             "SPF record allows anyone to send as this domain")
    else:
        error(f"No SPF record found for {domain}")
        if session:
            save_finding(session, "email", f"Missing SPF on {domain}", "high",
                         "No SPF record — domain can be spoofed")


def _check_dkim(domain, session):
    info(f"Checking DKIM for {domain}...")
    selectors = ["default", "google", "selector1", "selector2", "k1", "mail",
                 "s1", "s2", "dkim", "mandrill", "amazonses", "everlytickey1"]
    found = False
    for sel in selectors:
        code, out, _ = run_command(f"dig {sel}._domainkey.{domain} TXT +short", timeout=10)
        if out.strip() and "NXDOMAIN" not in out and "v=DKIM" in out:
            success(f"DKIM found (selector: {sel}):")
            console.print(f"  [green]{out.strip()[:200]}[/green]")
            found = True
            break
    if not found:
        warning(f"No DKIM records found with common selectors")
        console.print("  [dim]Try: dig <selector>._domainkey." + domain + " TXT[/dim]")


def _check_dmarc(domain, session):
    info(f"Checking DMARC for {domain}...")
    code, out, _ = run_command(f"dig _dmarc.{domain} TXT +short", timeout=15)
    if "v=DMARC" in out.upper() or "v=dmarc" in out.lower():
        success(f"DMARC Record found:")
        console.print(f"  [green]{out.strip()}[/green]\n")
        # Analyze policy
        if "p=reject" in out.lower():
            success("  DMARC policy: REJECT — Strongest protection")
        elif "p=quarantine" in out.lower():
            info("  DMARC policy: QUARANTINE — Good, suspicious mail goes to spam")
        elif "p=none" in out.lower():
            warning("  DMARC policy: NONE — Monitoring only, no enforcement")
            if session:
                save_finding(session, "email", f"DMARC p=none on {domain}", "medium",
                             "DMARC in monitoring mode — doesn't prevent spoofing")
        # Check reporting
        if "rua=" in out.lower():
            info("  Aggregate reporting: Enabled")
        if "ruf=" in out.lower():
            info("  Forensic reporting: Enabled")
    else:
        error(f"No DMARC record found for {domain}")
        if session:
            save_finding(session, "email", f"Missing DMARC on {domain}", "high",
                         "No DMARC record — email spoofing possible")


def _check_mx(domain, session):
    info(f"Checking MX records for {domain}...")
    run_command(f"dig {domain} MX +short | sort -n", timeout=15)


def _full_check(domain, session):
    console.print(f"\n[bold cyan]═══ FULL EMAIL SECURITY AUDIT: {domain} ═══[/bold cyan]\n")
    _check_mx(domain, session)
    console.print()
    _check_spf(domain, session)
    console.print()
    _check_dkim(domain, session)
    console.print()
    _check_dmarc(domain, session)
    console.print()
    # Additional checks
    info("Checking for DANE/TLSA...")
    run_command(f"dig _25._tcp.{domain} TLSA +short", timeout=10)
    info("Checking for MTA-STS...")
    run_command(f"dig _mta-sts.{domain} TXT +short", timeout=10)


def _header_analyzer():
    """Analyze email headers for spoofing indicators."""
    console.print("\n[bold cyan]Email Header Analyzer[/bold cyan]")
    console.print("[dim]Paste email headers (blank line to finish):[/dim]\n")

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
        warning("No headers provided.")
        return

    headers = "\n".join(lines)
    console.print(f"\n[bold green]Analysis:[/bold green]\n")

    # Extract key headers
    patterns = {
        "From": r'From:\s*(.+)', "To": r'To:\s*(.+)',
        "Reply-To": r'Reply-To:\s*(.+)', "Return-Path": r'Return-Path:\s*(.+)',
        "Message-ID": r'Message-ID:\s*(.+)', "X-Originating-IP": r'X-Originating-IP:\s*(.+)',
        "Received-SPF": r'Received-SPF:\s*(.+)', "DKIM-Signature": r'DKIM-Signature:\s*(.+)',
        "Authentication-Results": r'Authentication-Results:\s*(.+)',
    }

    for name, pattern in patterns.items():
        matches = re.findall(pattern, headers, re.IGNORECASE)
        if matches:
            console.print(f"  [bold]{name}:[/bold] {matches[0][:100]}")

    # Check for spoofing indicators
    console.print(f"\n[bold yellow]Spoofing Indicators:[/bold yellow]\n")

    from_match = re.search(r'From:\s*.*<(.+?)>', headers, re.IGNORECASE)
    return_match = re.search(r'Return-Path:\s*<(.+?)>', headers, re.IGNORECASE)
    if from_match and return_match:
        if from_match.group(1).split("@")[1] != return_match.group(1).split("@")[1]:
            error("  ⚠ FROM and RETURN-PATH domains don't match — possible spoofing!")
        else:
            success("  ✓ FROM and RETURN-PATH domains match")

    if "spf=fail" in headers.lower():
        error("  ⚠ SPF check FAILED — sender not authorized")
    elif "spf=pass" in headers.lower():
        success("  ✓ SPF check PASSED")

    if "dkim=fail" in headers.lower():
        error("  ⚠ DKIM check FAILED — message may be tampered")
    elif "dkim=pass" in headers.lower():
        success("  ✓ DKIM check PASSED")

    if "dmarc=fail" in headers.lower():
        error("  ⚠ DMARC check FAILED")
    elif "dmarc=pass" in headers.lower():
        success("  ✓ DMARC check PASSED")

    # Trace route through Received headers
    received = re.findall(r'Received:\s*(.+?)(?=Received:|$)', headers, re.DOTALL | re.IGNORECASE)
    if received:
        console.print(f"\n[bold cyan]Mail Path ({len(received)} hops):[/bold cyan]")
        for i, hop in enumerate(reversed(received)):
            hop_clean = " ".join(hop.split())[:120]
            console.print(f"  [dim]{i+1}.[/dim] {hop_clean}")


def run(session):
    show_stage_header("Email Security Checker", "SPF/DKIM/DMARC validation & header forensics")

    while True:
        options = [
            ("1", "[bold]Full Email Security Audit[/bold] (SPF + DKIM + DMARC + MX)"),
            ("2", "Check SPF Record"),
            ("3", "Check DKIM Record"),
            ("4", "Check DMARC Record"),
            ("5", "Check MX Records"),
            ("6", "[bold]Email Header Analyzer[/bold] (spoofing detection)"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return

        if choice == "6":
            _header_analyzer()
        else:
            domain = ask("Enter domain")
            if choice == "1":
                _full_check(domain, session)
            elif choice == "2":
                _check_spf(domain, session)
            elif choice == "3":
                _check_dkim(domain, session)
            elif choice == "4":
                _check_dmarc(domain, session)
            elif choice == "5":
                _check_mx(domain, session)
