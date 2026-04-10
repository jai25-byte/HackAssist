"""Reconnaissance stage - information gathering."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui import (show_stage_header, show_menu, ask, info, warning,
                show_knowledge, show_results_panel, console)
from tool_manager import ensure_tool, check_tool
from executor import run_with_preview
from knowledge import STAGES, CHEATSHEETS, GOOGLE_DORKS

STAGE = "recon"


def run(session):
    stage_info = STAGES["recon"]
    show_stage_header(stage_info["name"], "Passive & active information gathering")

    while True:
        options = [
            ("1", "WHOIS Lookup"),
            ("2", "DNS Enumeration"),
            ("3", "Subdomain Discovery (subfinder/amass)"),
            ("4", "Email/Domain Harvesting (theHarvester)"),
            ("5", "Shodan Search"),
            ("6", "Google Dork Generator"),
            ("7", "OSINT Knowledge Base"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return

        elif choice == "1":
            _whois_lookup(session)
        elif choice == "2":
            _dns_enum(session)
        elif choice == "3":
            _subdomain_discovery(session)
        elif choice == "4":
            _email_harvest(session)
        elif choice == "5":
            _shodan_search(session)
        elif choice == "6":
            _google_dorks()
        elif choice == "7":
            show_knowledge("Reconnaissance Guide", stage_info["description"])
            console.print("\n[bold cyan]Tips:[/bold cyan]")
            for tip in stage_info["tips"]:
                console.print(f"  [yellow]>[/yellow] {tip}")
            console.print()


def _whois_lookup(session):
    target = ask("Enter domain or IP")
    run_with_preview(f"whois {target}", session, STAGE)


def _dns_enum(session):
    target = ask("Enter domain")
    options = [
        ("1", "All Records (ANY)"),
        ("2", "A Records"),
        ("3", "MX Records"),
        ("4", "NS Records"),
        ("5", "TXT Records"),
        ("6", "CNAME Records"),
        ("7", "SOA Record"),
        ("0", "Back"),
    ]
    choice = show_menu(options)
    record_map = {"1": "ANY", "2": "A", "3": "MX", "4": "NS", "5": "TXT", "6": "CNAME", "7": "SOA"}
    if choice == "0":
        return
    rtype = record_map.get(choice, "ANY")
    run_with_preview(f"dig {target} {rtype} +noall +answer", session, STAGE)


def _subdomain_discovery(session):
    target = ask("Enter root domain (e.g. example.com)")

    options = [
        ("1", "subfinder (fast, passive)"),
        ("2", "amass (comprehensive, slower)"),
        ("0", "Back"),
    ]
    choice = show_menu(options)

    if choice == "0":
        return
    elif choice == "1":
        if not ensure_tool("subfinder"):
            return
        run_with_preview(f"subfinder -d {target} -silent", session, STAGE)
    elif choice == "2":
        if not ensure_tool("amass"):
            return
        run_with_preview(f"amass enum -passive -d {target}", session, STAGE)


def _email_harvest(session):
    if not ensure_tool("theHarvester"):
        return
    target = ask("Enter domain")
    source = ask("Search source", default="all")
    run_with_preview(f"theHarvester -d {target} -b {source}", session, STAGE)


def _shodan_search(session):
    if not ensure_tool("shodan"):
        return
    target = ask("Enter IP, domain, or search query")
    options = [
        ("1", "Host lookup (IP)"),
        ("2", "Search query"),
        ("3", "Domain info"),
        ("0", "Back"),
    ]
    choice = show_menu(options)
    if choice == "0":
        return
    elif choice == "1":
        run_with_preview(f"shodan host {target}", session, STAGE)
    elif choice == "2":
        run_with_preview(f"shodan search '{target}'", session, STAGE)
    elif choice == "3":
        run_with_preview(f"shodan domain {target}", session, STAGE)


def _google_dorks():
    target = ask("Enter target domain")
    console.print(f"\n[bold cyan]Google Dorks for {target}:[/bold cyan]\n")
    for name, dork in GOOGLE_DORKS.items():
        formatted = dork.format(target=target)
        console.print(f"  [yellow]{name}:[/yellow]")
        console.print(f"    [bold white]{formatted}[/bold white]\n")
    info("Copy these dorks and paste them into Google search.")
