#!/usr/bin/env python3
"""HackAssist - Terminal AI Hacking Assistant.

A standalone, menu-driven hacking assistant for authorized security testing.
Covers all pentesting stages: Recon, Scanning, Enumeration, Exploitation,
Post-Exploitation, and Reporting.

Usage:
    python3 hackassist.py
"""

import sys
import os

# Ensure imports work from project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ui import (console, show_banner, show_disclaimer, show_menu,
                show_stage_header, info, success, warning, error)
from session import get_session_menu
from tool_manager import show_manager_menu
from stages import recon, scanning, enumeration, exploitation, post_exploit, reporting


def main():
    try:
        console.clear()
        show_banner()
        show_disclaimer()

        # Session setup
        session = None
        info("Setting up your engagement session...\n")
        session = get_session_menu(session)

        if session:
            success(f"Active session: {session['target']} ({session['type']})")
        else:
            warning("Running without a session. Results won't be saved.")
        console.print()

        # Main menu loop
        while True:
            console.print("[bold green]=" * 50 + "[/bold green]")
            target_display = f" | Target: [cyan]{session['target']}[/cyan]" if session else ""
            console.print(f"[bold green]  HACKASSIST MAIN MENU{target_display}[/bold green]")
            console.print("[bold green]=" * 50 + "[/bold green]\n")

            options = [
                ("1", "[bold]Recon[/bold]           - Passive & active information gathering"),
                ("2", "[bold]Scanning[/bold]        - Port scanning & service detection"),
                ("3", "[bold]Enumeration[/bold]     - Deep-dive into discovered services"),
                ("4", "[bold]Exploitation[/bold]    - Vulnerability exploitation & access"),
                ("5", "[bold]Post-Exploit[/bold]    - Privilege escalation & persistence"),
                ("6", "[bold]Reporting[/bold]       - Generate engagement report"),
                ("7", "[bold]Tool Manager[/bold]    - Check & install hacking tools"),
                ("8", "[bold]Session[/bold]         - Manage engagement sessions"),
                ("0", "Exit"),
            ]
            choice = show_menu(options)

            if choice == "0":
                console.print("\n[bold green]Thanks for using HackAssist. Happy hacking![/bold green]\n")
                sys.exit(0)
            elif choice == "1":
                recon.run(session)
            elif choice == "2":
                scanning.run(session)
            elif choice == "3":
                enumeration.run(session)
            elif choice == "4":
                exploitation.run(session)
            elif choice == "5":
                post_exploit.run(session)
            elif choice == "6":
                reporting.run(session)
            elif choice == "7":
                show_manager_menu()
            elif choice == "8":
                session = get_session_menu(session)
                if session:
                    success(f"Active session: {session['target']} ({session['type']})")
                else:
                    warning("Running without a session.")
                console.print()

    except KeyboardInterrupt:
        console.print("\n\n[bold yellow]Interrupted. Exiting HackAssist...[/bold yellow]\n")
        sys.exit(0)
    except Exception as e:
        error(f"Unexpected error: {e}")
        console.print_exception()
        sys.exit(1)


if __name__ == "__main__":
    main()
