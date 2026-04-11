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
from stages import recon, scanning, enumeration, exploitation, post_exploit, reporting, footprint_erasure
import auto_attack
import defender
import ai_brain
import payload_generator
import c2_server
import wifi_attack
import phishing
import api_pentest
import vuln_db
import dashboard
import plugin_loader
import proxy
import cred_manager
import cloud_pentest
import container_escape
import active_directory
import playbooks
import scheduled_recon
import exploit_compiler
import multi_target
import stego
import osint
import malware_analysis
import network_map
import privesc_auto


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

            # Show defense status if running
            defense_engine = defender.get_engine()
            if defense_engine.running:
                ds = defense_engine.get_status()
                console.print(f"  [bold green]SHIELD ACTIVE[/bold green] [dim]| "
                              f"Uptime: {ds['uptime']} | Threats: {ds['threats_detected']}[/dim]\n")

            options = [
                ("", "[bold white]── CORE STAGES ──[/bold white]"),
                ("1", "[bold]Recon[/bold]             - Passive & active information gathering"),
                ("2", "[bold]Scanning[/bold]          - Port scanning & service detection"),
                ("3", "[bold]Enumeration[/bold]       - Deep-dive into discovered services"),
                ("4", "[bold]Exploitation[/bold]      - Vulnerability exploitation & access"),
                ("5", "[bold]Post-Exploit[/bold]      - Privilege escalation & persistence"),
                ("6", "[bold]Reporting[/bold]         - Generate engagement report"),
                ("", "[bold white]── AI & AUTOMATION ──[/bold white]"),
                ("7", "[bold cyan]AI Brain[/bold cyan]         - Venice.ai/CAI-style AI chat with personas"),
                ("8", "[bold red]Auto Attack[/bold red]      - AI autonomous attack pipeline"),
                ("9", "[bold green]Defense Monitor[/bold green]  - Autonomous system protection"),
                ("10", "[bold]Dashboard[/bold]         - Live visual target dashboard"),
                ("", "[bold white]── ARSENAL ──[/bold white]"),
                ("11", "[bold]Payload Generator[/bold] - Shells, web shells, encoders"),
                ("12", "[bold]C2 Server[/bold]         - Command & control server"),
                ("13", "[bold]Exploit Compiler[/bold]  - Auto-compile & shellcode gen"),
                ("14", "[bold]Vuln Database[/bold]     - Built-in CVE lookup"),
                ("15", "[bold]Credential Manager[/bold]- Creds, hashes, wordlists"),
                ("", "[bold white]── SPECIALIZED ──[/bold white]"),
                ("16", "[bold]WiFi Attacks[/bold]      - Wireless pentesting suite"),
                ("17", "[bold]Phishing[/bold]          - Email & credential harvesting"),
                ("18", "[bold]API Pentesting[/bold]    - REST/GraphQL/JWT testing"),
                ("19", "[bold]Active Directory[/bold]  - AD/Kerberos attacks"),
                ("20", "[bold]Cloud Pentesting[/bold]  - AWS/Azure/GCP security"),
                ("21", "[bold]Container Escape[/bold]  - Docker/K8s breakout"),
                ("22", "[bold]PrivEsc Auto[/bold]      - Privilege escalation exploiter"),
                ("", "[bold white]── INTEL & RECON ──[/bold white]"),
                ("23", "[bold]OSINT Framework[/bold]   - Person/domain/IP intelligence"),
                ("24", "[bold]Network Mapper[/bold]    - Visual network mapping"),
                ("25", "[bold]Scheduled Recon[/bold]   - Automated recurring scans"),
                ("26", "[bold]Multi-Target[/bold]      - Parallel multi-target ops"),
                ("", "[bold white]── TOOLS & EXTRAS ──[/bold white]"),
                ("27", "[bold]Steganography[/bold]     - Hide/extract hidden data"),
                ("28", "[bold]Malware Analysis[/bold]  - Static analysis & YARA"),
                ("29", "[bold]Attack Playbooks[/bold]  - Pre-built attack workflows"),
                ("30", "[bold]Proxy Interceptor[/bold] - HTTP/HTTPS interception"),
                ("31", "[bold]Plugin System[/bold]     - Extend with custom modules"),
                ("", "[bold white]── SYSTEM ──[/bold white]"),
                ("32", "[bold]Tool Manager[/bold]      - Check & install hacking tools"),
                ("33", "[bold]Session Manager[/bold]   - Manage engagement sessions"),
                ("34", "[bold red]Footprint Erasure[/bold red] - Cover tracks & self-destruct"),
                ("0", "[bold]Exit[/bold]"),
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
                ai_brain.run(session)
            elif choice == "8":
                result_session = auto_attack.run(session)
                if result_session and not session:
                    session = result_session
            elif choice == "9":
                defender.run(session)
            elif choice == "10":
                dashboard.run(session)
            elif choice == "11":
                payload_generator.run(session)
            elif choice == "12":
                c2_server.run(session)
            elif choice == "13":
                exploit_compiler.run(session)
            elif choice == "14":
                vuln_db.run(session)
            elif choice == "15":
                cred_manager.run(session)
            elif choice == "16":
                wifi_attack.run(session)
            elif choice == "17":
                phishing.run(session)
            elif choice == "18":
                api_pentest.run(session)
            elif choice == "19":
                active_directory.run(session)
            elif choice == "20":
                cloud_pentest.run(session)
            elif choice == "21":
                container_escape.run(session)
            elif choice == "22":
                privesc_auto.run(session)
            elif choice == "23":
                osint.run(session)
            elif choice == "24":
                network_map.run(session)
            elif choice == "25":
                scheduled_recon.run(session)
            elif choice == "26":
                multi_target.run(session)
            elif choice == "27":
                stego.run(session)
            elif choice == "28":
                malware_analysis.run(session)
            elif choice == "29":
                playbooks.run(session)
            elif choice == "30":
                proxy.run(session)
            elif choice == "31":
                plugin_loader.run(session)
            elif choice == "32":
                show_manager_menu()
            elif choice == "33":
                session = get_session_menu(session)
                if session:
                    success(f"Active session: {session['target']} ({session['type']})")
                else:
                    warning("Running without a session.")
                console.print()
            elif choice == "34":
                footprint_erasure.run(session)

    except KeyboardInterrupt:
        console.print("\n\n[bold yellow]Interrupted. Exiting HackAssist...[/bold yellow]\n")
        sys.exit(0)
    except Exception as e:
        error(f"Unexpected error: {e}")
        console.print_exception()
        sys.exit(1)


if __name__ == "__main__":
    main()
