#!/usr/bin/env python3
"""HackAssist - Credential Manager for pentesting engagements."""

import os
import json
import hashlib
import base64
from datetime import datetime

from ui import console, show_menu, ask, info, success, warning, error


CRED_DIR = os.path.expanduser("~/hackassist_creds")
CRED_FILE = os.path.join(CRED_DIR, "credentials.json")

# Common default credential pairs
DEFAULT_CREDS = {
    'SSH': [('root', 'root'), ('root', 'toor'), ('admin', 'admin'), ('admin', 'password')],
    'FTP': [('anonymous', ''), ('ftp', 'ftp'), ('admin', 'admin')],
    'MySQL': [('root', ''), ('root', 'root'), ('root', 'mysql')],
    'PostgreSQL': [('postgres', 'postgres'), ('postgres', '')],
    'MongoDB': [('admin', 'admin'), ('root', 'root')],
    'Redis': [('', ''), ('default', 'redis')],
    'Tomcat': [('tomcat', 'tomcat'), ('admin', 'admin'), ('manager', 'manager')],
    'Jenkins': [('admin', 'admin'), ('jenkins', 'jenkins')],
    'WordPress': [('admin', 'admin'), ('admin', 'password')],
    'Router': [('admin', 'admin'), ('admin', 'password'), ('admin', '1234')],
    'SNMP': [('public', ''), ('private', ''), ('community', '')],
    'VNC': [('', 'password'), ('', '1234')],
}

# Common wordlists
WORDLISTS = {
    'rockyou': '/usr/share/wordlists/rockyou.txt',
    'dirb_common': '/usr/share/dirb/wordlists/common.txt',
    'seclists_passwords': '/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt',
    'seclists_usernames': '/usr/share/seclists/Usernames/top-usernames-shortlist.txt',
    'custom': '',
}


def _ensure_dir():
    os.makedirs(CRED_DIR, exist_ok=True)
    if not os.path.exists(CRED_FILE):
        with open(CRED_FILE, 'w') as f:
            json.dump([], f)


def _load_creds():
    _ensure_dir()
    try:
        with open(CRED_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def _save_creds(creds):
    _ensure_dir()
    with open(CRED_FILE, 'w') as f:
        json.dump(creds, f, indent=2)


def _add_credential():
    host = ask("Host/Target")
    service = ask("Service (SSH/FTP/HTTP/etc)")
    username = ask("Username")
    password = ask("Password")
    source = ask("Source (manual/brute/dump)") or "manual"
    notes = ask("Notes (optional)") or ""

    cred = {
        'host': host,
        'service': service,
        'username': username,
        'password': password,
        'source': source,
        'notes': notes,
        'added': datetime.now().isoformat(),
    }

    creds = _load_creds()
    creds.append(cred)
    _save_creds(creds)
    success(f"Credential saved: {username}@{host} ({service})")


def _list_credentials():
    creds = _load_creds()
    if not creds:
        warning("No credentials stored.")
        return

    from rich.table import Table
    table = Table(title="Stored Credentials", border_style="green")
    table.add_column("#", width=4)
    table.add_column("Host", style="cyan")
    table.add_column("Service", style="yellow")
    table.add_column("Username", style="green")
    table.add_column("Password", style="red")
    table.add_column("Source", style="dim")

    for i, c in enumerate(creds, 1):
        table.add_row(str(i), c['host'], c['service'], c['username'], c['password'], c['source'])
    console.print(table)


def _search_credentials():
    query = ask("Search (host/service/username)")
    if not query:
        return

    creds = _load_creds()
    matches = [c for c in creds if query.lower() in json.dumps(c).lower()]

    if not matches:
        warning("No matching credentials found.")
        return

    from rich.table import Table
    table = Table(title=f"Search: '{query}'", border_style="green")
    table.add_column("Host", style="cyan")
    table.add_column("Service", style="yellow")
    table.add_column("Username", style="green")
    table.add_column("Password", style="red")

    for c in matches:
        table.add_row(c['host'], c['service'], c['username'], c['password'])
    console.print(table)


def _show_defaults():
    from rich.table import Table
    table = Table(title="Default Credentials Database", border_style="yellow")
    table.add_column("Service", style="cyan")
    table.add_column("Username", style="green")
    table.add_column("Password", style="red")

    for service, pairs in DEFAULT_CREDS.items():
        for user, passwd in pairs:
            table.add_row(service, user or "(empty)", passwd or "(empty)")
    console.print(table)


def _hash_identifier():
    hash_val = ask("Enter hash value")
    if not hash_val:
        return

    length = len(hash_val)
    candidates = []
    if length == 32:
        candidates = ["MD5", "NTLM", "MD4"]
    elif length == 40:
        candidates = ["SHA-1", "MySQL5"]
    elif length == 56:
        candidates = ["SHA-224"]
    elif length == 64:
        candidates = ["SHA-256", "SHA3-256"]
    elif length == 96:
        candidates = ["SHA-384"]
    elif length == 128:
        candidates = ["SHA-512", "SHA3-512"]
    elif hash_val.startswith('$1$'):
        candidates = ["MD5crypt"]
    elif hash_val.startswith('$2'):
        candidates = ["bcrypt"]
    elif hash_val.startswith('$5$'):
        candidates = ["SHA-256crypt"]
    elif hash_val.startswith('$6$'):
        candidates = ["SHA-512crypt"]
    elif hash_val.startswith('$apr1$'):
        candidates = ["Apache APR1"]
    elif ':' in hash_val:
        candidates = ["NTLM (with salt)", "NetNTLMv2", "LM:NT"]

    if candidates:
        info(f"Hash length: {length}")
        info(f"Possible types: [bold]{', '.join(candidates)}[/bold]")

        hashcat_modes = {
            'MD5': '0', 'SHA-1': '100', 'SHA-256': '1400', 'SHA-512': '1700',
            'NTLM': '1000', 'bcrypt': '3200', 'MD5crypt': '500',
            'SHA-256crypt': '7400', 'SHA-512crypt': '1800', 'NetNTLMv2': '5600',
        }
        for c in candidates:
            if c in hashcat_modes:
                console.print(f"  [dim]Hashcat mode for {c}: -m {hashcat_modes[c]}[/dim]")
    else:
        warning(f"Unknown hash format (length: {length})")


def _wordlist_manager():
    from rich.table import Table
    table = Table(title="Wordlist Locations", border_style="cyan")
    table.add_column("Name", style="cyan")
    table.add_column("Path", style="green")
    table.add_column("Exists", style="bold")

    for name, path in WORDLISTS.items():
        if path:
            exists = "[green]Yes[/green]" if os.path.exists(path) else "[red]No[/red]"
            table.add_row(name, path, exists)
        else:
            table.add_row(name, "(user-defined)", "[dim]N/A[/dim]")
    console.print(table)

    info("Install SecLists: git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists")


def _export_creds():
    creds = _load_creds()
    if not creds:
        warning("No credentials to export.")
        return

    export_file = os.path.join(CRED_DIR, f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    with open(export_file, 'w') as f:
        f.write("host,service,username,password,source,notes\n")
        for c in creds:
            f.write(f"{c['host']},{c['service']},{c['username']},{c['password']},{c['source']},{c.get('notes', '')}\n")
    success(f"Exported to {export_file}")


def run(session):
    """Credential manager entry point."""
    while True:
        console.print("\n[bold green]CREDENTIAL MANAGER[/bold green]\n")
        options = [
            ("1", "Add Credential"),
            ("2", "List All Credentials"),
            ("3", "Search Credentials"),
            ("4", "Default Credentials Database"),
            ("5", "Hash Identifier"),
            ("6", "Wordlist Manager"),
            ("7", "Export Credentials (CSV)"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            break
        elif choice == "1":
            _add_credential()
        elif choice == "2":
            _list_credentials()
        elif choice == "3":
            _search_credentials()
        elif choice == "4":
            _show_defaults()
        elif choice == "5":
            _hash_identifier()
        elif choice == "6":
            _wordlist_manager()
        elif choice == "7":
            _export_creds()
