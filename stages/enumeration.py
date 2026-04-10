"""Enumeration stage - deep-dive into discovered services."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui import (show_stage_header, show_menu, ask, info, warning,
                show_knowledge, console, confirm)
from tool_manager import ensure_tool
from executor import run_with_preview
from knowledge import STAGES, CHEATSHEETS

STAGE = "enumeration"


def run(session):
    stage_info = STAGES["enumeration"]
    show_stage_header(stage_info["name"], "Deep-dive into discovered services")

    while True:
        options = [
            ("1", "Web Directory Bruteforce (gobuster)"),
            ("2", "Web Directory Fuzz (ffuf)"),
            ("3", "Web Vulnerability Scan (nikto)"),
            ("4", "SMB Enumeration"),
            ("5", "SNMP Enumeration"),
            ("6", "DNS Zone Transfer"),
            ("7", "Banner Grabbing (netcat)"),
            ("8", "SSL/TLS Analysis"),
            ("9", "Cheat Sheets"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _gobuster(session)
        elif choice == "2":
            _ffuf(session)
        elif choice == "3":
            _nikto(session)
        elif choice == "4":
            _smb_enum(session)
        elif choice == "5":
            _snmp_enum(session)
        elif choice == "6":
            _dns_zone_transfer(session)
        elif choice == "7":
            _banner_grab(session)
        elif choice == "8":
            _ssl_analysis(session)
        elif choice == "9":
            _show_cheatsheets()


def _gobuster(session):
    if not ensure_tool("gobuster"):
        return
    target = ask("Enter target URL (e.g. http://10.10.10.1)")
    wordlist = ask("Wordlist path", default="/usr/share/wordlists/dirb/common.txt")
    extensions = ask("File extensions to search (leave empty for none)", default="")

    cmd = f"gobuster dir -u {target} -w {wordlist}"
    if extensions:
        cmd += f" -x {extensions}"
    run_with_preview(cmd, session, STAGE)


def _ffuf(session):
    if not ensure_tool("ffuf"):
        return
    target = ask("Enter target URL with FUZZ keyword (e.g. http://target/FUZZ)")
    if "FUZZ" not in target:
        warning("URL should contain FUZZ keyword for fuzzing position")
        target = ask("Re-enter URL with FUZZ", default=f"{target}/FUZZ")
    wordlist = ask("Wordlist path", default="/usr/share/wordlists/dirb/common.txt")
    cmd = f"ffuf -u {target} -w {wordlist}"

    if confirm("Filter by response size?", default=False):
        size = ask("Filter out size (e.g. 0, 1234)")
        cmd += f" -fs {size}"

    run_with_preview(cmd, session, STAGE)


def _nikto(session):
    if not ensure_tool("nikto"):
        return
    target = ask("Enter target URL or IP")
    ssl = confirm("Use SSL/HTTPS?", default=False)
    cmd = f"nikto -h {target}"
    if ssl:
        cmd += " -ssl"
    run_with_preview(cmd, session, STAGE)


def _smb_enum(session):
    if not ensure_tool("nmap"):
        return
    target = ask("Enter target IP")
    options = [
        ("1", "List shares"),
        ("2", "Enumerate users"),
        ("3", "Full SMB enumeration"),
        ("0", "Back"),
    ]
    choice = show_menu(options)
    if choice == "0":
        return
    elif choice == "1":
        run_with_preview(f"nmap --script smb-enum-shares -p 445 {target}", session, STAGE)
    elif choice == "2":
        run_with_preview(f"nmap --script smb-enum-users -p 445 {target}", session, STAGE)
    elif choice == "3":
        run_with_preview(
            f"nmap --script smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode -p 445 {target}",
            session, STAGE
        )


def _snmp_enum(session):
    if not ensure_tool("nmap"):
        return
    target = ask("Enter target IP")
    community = ask("Community string", default="public")
    run_with_preview(
        f"nmap -sU -p 161 --script snmp-brute,snmp-info,snmp-interfaces,snmp-processes {target}",
        session, STAGE
    )


def _dns_zone_transfer(session):
    target = ask("Enter domain")
    ns = ask("Name server (leave empty to auto-detect)", default="")
    if ns:
        run_with_preview(f"dig axfr {target} @{ns}", session, STAGE)
    else:
        info("Detecting name servers first...")
        run_with_preview(f"dig ns {target} +short", session, STAGE)
        ns = ask("Enter a name server from above")
        run_with_preview(f"dig axfr {target} @{ns}", session, STAGE)


def _banner_grab(session):
    target = ask("Enter target IP")
    port = ask("Enter port", default="80")
    info("Sending empty request to grab banner (timeout 5s)...")
    run_with_preview(f"echo '' | nc -w 5 {target} {port}", session, STAGE)


def _ssl_analysis(session):
    target = ask("Enter target hostname")
    port = ask("Enter port", default="443")
    options = [
        ("1", "Show certificate details"),
        ("2", "Check supported ciphers (nmap)"),
        ("3", "Test SSL/TLS vulnerabilities (nmap)"),
        ("0", "Back"),
    ]
    choice = show_menu(options)
    if choice == "0":
        return
    elif choice == "1":
        run_with_preview(
            f"echo | openssl s_client -connect {target}:{port} -servername {target} 2>/dev/null | openssl x509 -noout -text",
            session, STAGE
        )
    elif choice == "2":
        if ensure_tool("nmap"):
            run_with_preview(f"nmap --script ssl-enum-ciphers -p {port} {target}", session, STAGE)
    elif choice == "3":
        if ensure_tool("nmap"):
            run_with_preview(
                f"nmap --script ssl-heartbleed,ssl-poodle,ssl-ccs-injection -p {port} {target}",
                session, STAGE
            )


def _show_cheatsheets():
    for tool in ["gobuster", "ffuf", "nikto"]:
        if tool in CHEATSHEETS:
            console.print(f"\n[bold cyan]{tool} Cheat Sheet:[/bold cyan]\n")
            for name, cmd in CHEATSHEETS[tool].items():
                console.print(f"  [yellow]{name}:[/yellow]")
                console.print(f"    [bold white]{cmd}[/bold white]\n")
