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
import auto_mode
from modules import arp_spoofer, dns_spoofer, packet_crafter, network_sniffer
from modules import vlan_hopper, ipv6_attack, amsi_bypass, traffic_blender
from modules import lolbins, pivoting, responder_suite, persistence
from modules import process_hollow, vpn_pentest, snmp_exploit, password_cracker
from modules import rubber_ducky, waf_bypass
# ── New Batch 1-4 modules ──
from modules import reverse_tunnel, exploit_chain, ctf_mode, fuzzer_engine
from modules import dns_tunnel, mobile_pentest, email_security, web_vulns
from modules import ai_code_auditor, honeypot, notification, technique_wiki
from modules import infra_pentest, skill_tree, elite_arsenal


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
            console.print("[bold green]=" * 60 + "[/bold green]")
            target_display = f" | Target: [cyan]{session['target']}[/cyan]" if session else ""
            console.print(f"[bold green]  HACKASSIST MAIN MENU{target_display}[/bold green]")
            console.print("[bold green]=" * 60 + "[/bold green]\n")

            # Show defense status if running
            defense_engine = defender.get_engine()
            if defense_engine.running:
                ds = defense_engine.get_status()
                console.print(f"  [bold green]🛡 SHIELD ACTIVE[/bold green] [dim]| "
                              f"Uptime: {ds['uptime']} | Threats: {ds['threats_detected']}[/dim]\n")

            options = [
                # ── CORE STAGES ──
                ("", "[bold white]── CORE STAGES ──[/bold white]"),
                ("1",  "[bold]Recon[/bold]              — Passive & active information gathering"),
                ("2",  "[bold]Scanning[/bold]           — Port scanning & service detection"),
                ("3",  "[bold]Enumeration[/bold]        — Deep-dive into discovered services"),
                ("4",  "[bold]Exploitation[/bold]       — Vulnerability exploitation & access"),
                ("5",  "[bold]Post-Exploit[/bold]       — Privilege escalation & persistence"),
                ("6",  "[bold]Reporting[/bold]          — Generate engagement report"),

                # ── AI & AUTOMATION ──
                ("", "[bold white]── AI & AUTOMATION ──[/bold white]"),
                ("7",  "[bold cyan]AI Brain[/bold cyan]          — LLM chat with security personas"),
                ("8",  "[bold red]Auto Attack[/bold red]       — AI autonomous attack pipeline"),
                ("9",  "[bold yellow]AI Auto Mode[/bold yellow]     — Full autonomous scan chain"),
                ("10", "[bold green]Defense Monitor[/bold green]   — Autonomous system protection"),
                ("11", "[bold magenta]AI Code Auditor[/bold magenta]  — AI-powered source code review"),

                # ── DASHBOARD & INTEL ──
                ("", "[bold white]── DASHBOARD & INTEL ──[/bold white]"),
                ("12", "[bold]Dashboard[/bold]          — Live visual target dashboard"),
                ("13", "[bold]MITRE ATT&CK Wiki[/bold] — Technique browser with examples"),
                ("14", "[bold]Threat Intel[/bold]       — IOC lookup, log analysis, elite tools"),

                # ── ARSENAL ──
                ("", "[bold white]── ARSENAL ──[/bold white]"),
                ("15", "[bold]Payload Generator[/bold]  — Shells, web shells, encoders"),
                ("16", "[bold]C2 Server[/bold]          — Multi-session shell manager"),
                ("17", "[bold]Exploit Compiler[/bold]   — Auto-compile & shellcode gen"),
                ("18", "[bold]Exploit Chain[/bold]      — Chain vulns into attack paths"),
                ("19", "[bold]Vuln Database[/bold]      — Built-in CVE lookup"),
                ("20", "[bold]Credential Manager[/bold] — Creds, hashes, wordlists"),

                # ── WEB ATTACKS ──
                ("", "[bold white]── WEB ATTACKS ──[/bold white]"),
                ("21", "[bold]Web Vuln Scanners[/bold]  — SSRF/CORS/SSTI/XXE/GraphQL/Race"),
                ("22", "[bold]Fuzzer Engine[/bold]      — HTTP/TCP mutation fuzzing"),
                ("23", "[bold]API Pentesting[/bold]     — REST/GraphQL/JWT testing"),

                # ── SPECIALIZED ──
                ("", "[bold white]── SPECIALIZED ──[/bold white]"),
                ("24", "[bold]WiFi Attacks[/bold]       — Wireless pentesting suite"),
                ("25", "[bold]Phishing[/bold]           — Email & credential harvesting"),
                ("26", "[bold]Active Directory[/bold]   — AD/Kerberos attacks"),
                ("27", "[bold]Cloud Pentesting[/bold]   — AWS/Azure/GCP security"),
                ("28", "[bold]Container Escape[/bold]   — Docker/K8s breakout"),
                ("29", "[bold]Mobile Pentesting[/bold]  — Android APK/iOS/Frida hooks"),
                ("30", "[bold]Infra Pentesting[/bold]   — DB/LDAP/SMTP/CI-CD/K8s/IaC"),
                ("31", "[bold]Email Security[/bold]     — SPF/DKIM/DMARC & header forensics"),
                ("32", "[bold]PrivEsc Auto[/bold]       — Privilege escalation exploiter"),

                # ── INTEL & RECON ──
                ("", "[bold white]── INTEL & RECON ──[/bold white]"),
                ("33", "[bold]OSINT Framework[/bold]    — Person/domain/IP intelligence"),
                ("34", "[bold]Network Mapper[/bold]     — Visual network mapping"),
                ("35", "[bold]Scheduled Recon[/bold]    — Automated recurring scans"),
                ("36", "[bold]Multi-Target[/bold]       — Parallel multi-target ops"),
                ("37", "[bold]DNS Tunneling[/bold]      — Data exfil & C2 over DNS"),
                ("38", "[bold]Reverse Tunnels[/bold]    — ngrok/chisel/bore/SSH/ligolo"),

                # ── TOOLS & EXTRAS ──
                ("", "[bold white]── TOOLS & EXTRAS ──[/bold white]"),
                ("39", "[bold]Steganography[/bold]      — Hide/extract hidden data"),
                ("40", "[bold]Malware Analysis[/bold]   — Static analysis & YARA"),
                ("41", "[bold]Attack Playbooks[/bold]   — Pre-built attack workflows"),
                ("42", "[bold]CTF Mode[/bold]           — Challenge solver & decoder"),
                ("43", "[bold]Proxy Interceptor[/bold]  — HTTP/HTTPS interception"),
                ("44", "[bold]Plugin System[/bold]      — Extend with custom modules"),
                ("45", "[bold]Honeypot Deployer[/bold]  — Decoy services for detection"),

                # ── NETWORK WARFARE ──
                ("", "[bold white]── NETWORK WARFARE ──[/bold white]"),
                ("46", "[bold]ARP Spoofer[/bold]        — ARP poisoning & MITM"),
                ("47", "[bold]DNS Spoofer[/bold]        — DNS poisoning & hijack"),
                ("48", "[bold]Packet Crafter[/bold]     — Custom packets (Scapy)"),
                ("49", "[bold]Network Sniffer[/bold]    — Wireshark in terminal"),
                ("50", "[bold]VLAN Hopper[/bold]        — VLAN escape attacks"),
                ("51", "[bold]IPv6 Attacks[/bold]       — IPv6-specific exploitation"),
                ("52", "[bold]Responder Suite[/bold]    — LLMNR/NBT-NS & NTLM relay"),
                ("53", "[bold]SNMP Exploiter[/bold]     — SNMP enum & exploitation"),
                ("54", "[bold]VPN Pentester[/bold]      — IPSec/SSL VPN attacks"),

                # ── EVASION & PERSISTENCE ──
                ("", "[bold white]── EVASION & PERSISTENCE ──[/bold white]"),
                ("55", "[bold]AMSI/ETW Bypass[/bold]    — Windows defense evasion"),
                ("56", "[bold]Traffic Blender[/bold]    — C2 traffic disguise & tunnels"),
                ("57", "[bold]LOLBins[/bold]            — Living off the Land database"),
                ("58", "[bold]WAF Bypass[/bold]         — WAF fingerprint & bypass payloads"),
                ("59", "[bold]Persistence[/bold]        — Linux/Windows persistence methods"),
                ("60", "[bold]Process Injection[/bold]  — Hollowing, DLL inject, APC"),
                ("61", "[bold]Pivoting[/bold]           — SSH tunnels, chisel, ligolo"),
                ("62", "[bold]Password Cracker[/bold]   — Hashcat/John unified wrapper"),
                ("63", "[bold]Rubber Ducky[/bold]       — USB HID payload generator"),
                ("64", "[bold]Elite Arsenal[/bold]      — Polymorphic, timestomp, callbacks"),

                # ── GAMIFICATION ──
                ("", "[bold white]── GAMIFICATION ──[/bold white]"),
                ("65", "[bold]Skill Tree[/bold]         — XP progression & challenges"),

                # ── SYSTEM ──
                ("", "[bold white]── SYSTEM ──[/bold white]"),
                ("66", "[bold]Notifications[/bold]      — Desktop/Telegram/Discord alerts"),
                ("67", "[bold]Tool Manager[/bold]       — Check & install hacking tools"),
                ("68", "[bold]Session Manager[/bold]    — Manage engagement sessions"),
                ("69", "[bold red]Footprint Erasure[/bold red] — Cover tracks & self-destruct"),
                ("0",  "[bold]Exit[/bold]"),
            ]
            choice = show_menu(options)

            # ── Core Stages ──
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

            # ── AI & Automation ──
            elif choice == "7":
                ai_brain.run(session)
            elif choice == "8":
                result_session = auto_attack.run(session)
                if result_session and not session:
                    session = result_session
            elif choice == "9":
                auto_mode.run_auto_mode(session)
            elif choice == "10":
                defender.run(session)
            elif choice == "11":
                ai_code_auditor.run(session)

            # ── Dashboard & Intel ──
            elif choice == "12":
                dashboard.run(session)
            elif choice == "13":
                technique_wiki.run(session)
            elif choice == "14":
                elite_arsenal.run(session)

            # ── Arsenal ──
            elif choice == "15":
                payload_generator.run(session)
            elif choice == "16":
                c2_server.run(session)
            elif choice == "17":
                exploit_compiler.run(session)
            elif choice == "18":
                exploit_chain.run(session)
            elif choice == "19":
                vuln_db.run(session)
            elif choice == "20":
                cred_manager.run(session)

            # ── Web Attacks ──
            elif choice == "21":
                web_vulns.run(session)
            elif choice == "22":
                fuzzer_engine.run(session)
            elif choice == "23":
                api_pentest.run(session)

            # ── Specialized ──
            elif choice == "24":
                wifi_attack.run(session)
            elif choice == "25":
                phishing.run(session)
            elif choice == "26":
                active_directory.run(session)
            elif choice == "27":
                cloud_pentest.run(session)
            elif choice == "28":
                container_escape.run(session)
            elif choice == "29":
                mobile_pentest.run(session)
            elif choice == "30":
                infra_pentest.run(session)
            elif choice == "31":
                email_security.run(session)
            elif choice == "32":
                privesc_auto.run(session)

            # ── Intel & Recon ──
            elif choice == "33":
                osint.run(session)
            elif choice == "34":
                network_map.run(session)
            elif choice == "35":
                scheduled_recon.run(session)
            elif choice == "36":
                multi_target.run(session)
            elif choice == "37":
                dns_tunnel.run(session)
            elif choice == "38":
                reverse_tunnel.run(session)

            # ── Tools & Extras ──
            elif choice == "39":
                stego.run(session)
            elif choice == "40":
                malware_analysis.run(session)
            elif choice == "41":
                playbooks.run(session)
            elif choice == "42":
                ctf_mode.run(session)
            elif choice == "43":
                proxy.run(session)
            elif choice == "44":
                plugin_loader.run(session)
            elif choice == "45":
                honeypot.run(session)

            # ── Network Warfare ──
            elif choice == "46":
                arp_spoofer.run(session)
            elif choice == "47":
                dns_spoofer.run(session)
            elif choice == "48":
                packet_crafter.run(session)
            elif choice == "49":
                network_sniffer.run(session)
            elif choice == "50":
                vlan_hopper.run(session)
            elif choice == "51":
                ipv6_attack.run(session)
            elif choice == "52":
                responder_suite.run(session)
            elif choice == "53":
                snmp_exploit.run(session)
            elif choice == "54":
                vpn_pentest.run(session)

            # ── Evasion & Persistence ──
            elif choice == "55":
                amsi_bypass.run(session)
            elif choice == "56":
                traffic_blender.run(session)
            elif choice == "57":
                lolbins.run(session)
            elif choice == "58":
                waf_bypass.run(session)
            elif choice == "59":
                persistence.run(session)
            elif choice == "60":
                process_hollow.run(session)
            elif choice == "61":
                pivoting.run(session)
            elif choice == "62":
                password_cracker.run(session)
            elif choice == "63":
                rubber_ducky.run(session)
            elif choice == "64":
                elite_arsenal.run(session)

            # ── Gamification ──
            elif choice == "65":
                skill_tree.run(session)

            # ── System ──
            elif choice == "66":
                notification.run(session)
            elif choice == "67":
                show_manager_menu()
            elif choice == "68":
                session = get_session_menu(session)
                if session:
                    success(f"Active session: {session['target']} ({session['type']})")
                else:
                    warning("Running without a session.")
                console.print()
            elif choice == "69":
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
