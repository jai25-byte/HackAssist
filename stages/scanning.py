"""Scanning stage - port scanning and service detection."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui import (show_stage_header, show_menu, ask, info, warning,
                show_knowledge, console, confirm)
from tool_manager import ensure_tool
from executor import run_with_preview
from knowledge import STAGES, CHEATSHEETS

STAGE = "scanning"


def run(session):
    stage_info = STAGES["scanning"]
    show_stage_header(stage_info["name"], "Port scanning & service detection")

    while True:
        options = [
            ("1", "Quick Port Scan (Top 1000)"),
            ("2", "Full TCP Scan (All 65535 ports)"),
            ("3", "UDP Scan (Top 100)"),
            ("4", "Service & Version Detection"),
            ("5", "OS Detection"),
            ("6", "Vulnerability Scan (NSE scripts)"),
            ("7", "Aggressive Scan (All-in-one)"),
            ("8", "Fast Scan (RustScan -> nmap)"),
            ("9", "Custom nmap Command"),
            ("10", "Nmap Cheat Sheet"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return

        if choice == "10":
            _show_cheatsheet()
            continue

        if choice == "8":
            _rustscan(session)
            continue

        if choice == "9":
            _custom_nmap(session)
            continue

        if not ensure_tool("nmap"):
            continue

        target = ask("Enter target IP or hostname")

        if choice == "1":
            run_with_preview(f"nmap -T4 {target}", session, STAGE)
        elif choice == "2":
            warning("Full port scan may take several minutes.")
            run_with_preview(f"nmap -p- -T4 {target}", session, STAGE)
        elif choice == "3":
            warning("UDP scan requires sudo and is slow.")
            run_with_preview(f"sudo nmap -sU --top-ports 100 {target}", session, STAGE)
        elif choice == "4":
            run_with_preview(f"nmap -sV -sC -T4 {target}", session, STAGE)
        elif choice == "5":
            run_with_preview(f"sudo nmap -O {target}", session, STAGE)
        elif choice == "6":
            run_with_preview(f"nmap --script vuln {target}", session, STAGE)
        elif choice == "7":
            save = confirm("Save output to files?", default=True)
            if save:
                run_with_preview(f"nmap -A -T4 -oA nmap_aggressive_{target} {target}", session, STAGE)
            else:
                run_with_preview(f"nmap -A -T4 {target}", session, STAGE)


def _rustscan(session):
    if not ensure_tool("rustscan"):
        return
    target = ask("Enter target IP or hostname")
    run_with_preview(f"rustscan -a {target} -- -sV -sC", session, STAGE)


def _custom_nmap(session):
    if not ensure_tool("nmap"):
        return
    cmd = ask("Enter full nmap command (e.g. nmap -sV -p 80,443 target)")
    if not cmd.startswith("nmap"):
        warning("Command should start with 'nmap'")
        return
    run_with_preview(cmd, session, STAGE)


def _show_cheatsheet():
    console.print("\n[bold cyan]Nmap Cheat Sheet:[/bold cyan]\n")
    for name, cmd in CHEATSHEETS["nmap"].items():
        console.print(f"  [yellow]{name}:[/yellow]")
        console.print(f"    [bold white]{cmd}[/bold white]\n")
