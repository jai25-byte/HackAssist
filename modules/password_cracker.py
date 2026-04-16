"""Password Cracker Module - Unified hashcat/john wrapper with hash identification and wordlist generation."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel, show_knowledge)
from executor import run_with_preview, run_command

STAGE = "crack"

HASH_MODES = {
    "MD5": {"hashcat": 0, "john": "raw-md5", "example": "5d41402abc4b2a76b9719d911017c592"},
    "SHA1": {"hashcat": 100, "john": "raw-sha1", "example": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"},
    "SHA256": {"hashcat": 1400, "john": "raw-sha256", "example": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
    "SHA512": {"hashcat": 1700, "john": "raw-sha512", "example": ""},
    "NTLM": {"hashcat": 1000, "john": "nt", "example": "32ed87bdb5fdc5e9cba88547376818d4"},
    "NTLMv2": {"hashcat": 5600, "john": "netntlmv2", "example": ""},
    "NTLMv1": {"hashcat": 5500, "john": "netntlm", "example": ""},
    "MySQL": {"hashcat": 300, "john": "mysql-sha1", "example": ""},
    "bcrypt": {"hashcat": 3200, "john": "bcrypt", "example": "$2a$05$..."},
    "WPA/WPA2": {"hashcat": 22000, "john": "wpapsk", "example": ""},
    "Kerberos TGS (Kerberoast)": {"hashcat": 13100, "john": "krb5tgs", "example": "$krb5tgs$23$..."},
    "Kerberos AS-REP": {"hashcat": 18200, "john": "krb5asrep", "example": "$krb5asrep$23$..."},
    "SHA512crypt ($6$)": {"hashcat": 1800, "john": "sha512crypt", "example": "$6$rounds=5000$..."},
    "MD5crypt ($1$)": {"hashcat": 500, "john": "md5crypt", "example": "$1$..."},
    "LM": {"hashcat": 3000, "john": "lm", "example": ""},
    "MSSQL": {"hashcat": 1731, "john": "mssql12", "example": ""},
    "PostgreSQL": {"hashcat": 12, "john": "dynamic_1034", "example": ""},
    "Cisco Type 5": {"hashcat": 500, "john": "md5crypt", "example": "$1$..."},
    "Cisco Type 7": {"hashcat": -1, "john": "cisco", "example": ""},
}


def _identify_hash(session):
    """Identify hash type."""
    hash_val = ask("Enter hash to identify")
    if not hash_val:
        error("Hash required.")
        return

    # Try hashid first
    cmd = f"hashid '{hash_val}' 2>/dev/null || hash-identifier <<< '{hash_val}' 2>/dev/null"
    run_with_preview(cmd, session, STAGE)

    # Manual identification hints
    length = len(hash_val)
    console.print(f"\n[bold cyan]Hash Analysis:[/bold cyan]")
    console.print(f"  Length: {length} characters")

    guesses = []
    if length == 32:
        guesses = ["MD5", "NTLM", "LM"]
    elif length == 40:
        guesses = ["SHA1", "MySQL"]
    elif length == 64:
        guesses = ["SHA256"]
    elif length == 128:
        guesses = ["SHA512"]
    elif hash_val.startswith("$2"):
        guesses = ["bcrypt"]
    elif hash_val.startswith("$6$"):
        guesses = ["SHA512crypt ($6$)"]
    elif hash_val.startswith("$1$"):
        guesses = ["MD5crypt ($1$)"]
    elif hash_val.startswith("$krb5tgs$"):
        guesses = ["Kerberos TGS (Kerberoast)"]
    elif hash_val.startswith("$krb5asrep$"):
        guesses = ["Kerberos AS-REP"]

    if guesses:
        console.print(f"  Likely: [green]{', '.join(guesses)}[/green]")
        for g in guesses:
            if g in HASH_MODES:
                m = HASH_MODES[g]
                console.print(f"    Hashcat: -m {m['hashcat']}  |  John: --format={m['john']}")


def _hashcat_attack(session):
    """Run hashcat cracking attack."""
    hashfile = ask("Enter hash file path")
    if not hashfile:
        error("Hash file required.")
        return

    # Select hash type
    info("Select hash type:")
    modes = list(HASH_MODES.items())
    options = [(str(i+1), f"[bold]{name}[/bold] (hashcat -m {m['hashcat']})") for i, (name, m) in enumerate(modes)]
    options.append(("0", "[bold]Enter mode manually[/bold]"))
    choice = show_menu(options)

    if choice == "0":
        mode = ask("Enter hashcat mode number")
    else:
        idx = int(choice) - 1
        if 0 <= idx < len(modes):
            mode = str(modes[idx][1]["hashcat"])
        else:
            return

    # Attack type
    options2 = [
        ("1", "[bold]Dictionary[/bold]     - Wordlist attack (-a 0)"),
        ("2", "[bold]Dictionary+Rules[/bold]- Wordlist with rules (-a 0 -r)"),
        ("3", "[bold]Brute force[/bold]    - Mask attack (-a 3)"),
        ("4", "[bold]Combinator[/bold]     - Combine two wordlists (-a 1)"),
    ]
    attack = show_menu(options2)

    if attack == "1":
        wordlist = ask("Wordlist path", default="/usr/share/wordlists/rockyou.txt")
        cmd = f"hashcat -m {mode} -a 0 {hashfile} {wordlist} --force"
    elif attack == "2":
        wordlist = ask("Wordlist path", default="/usr/share/wordlists/rockyou.txt")
        rule = ask("Rule file", default="best64.rule")
        cmd = f"hashcat -m {mode} -a 0 {hashfile} {wordlist} -r {rule} --force"
    elif attack == "3":
        mask = ask("Mask (e.g., ?a?a?a?a?a?a for 6-char all)", default="?a?a?a?a?a?a")
        cmd = f"hashcat -m {mode} -a 3 {hashfile} '{mask}' --force"
        info("Mask chars: ?l=lower ?u=upper ?d=digit ?s=special ?a=all")
    elif attack == "4":
        wl1 = ask("Wordlist 1")
        wl2 = ask("Wordlist 2")
        cmd = f"hashcat -m {mode} -a 1 {hashfile} {wl1} {wl2} --force"
    else:
        return

    run_with_preview(cmd, session, STAGE)


def _john_attack(session):
    """Run John the Ripper cracking attack."""
    hashfile = ask("Enter hash file path")
    if not hashfile:
        error("Hash file required.")
        return

    options = [
        ("1", "[bold]Auto-detect[/bold]   - Let John guess format"),
        ("2", "[bold]Specify format[/bold] - Choose hash format"),
        ("3", "[bold]Show cracked[/bold]   - Display previously cracked"),
    ]
    choice = show_menu(options)

    if choice == "1":
        wordlist = ask("Wordlist path", default="/usr/share/wordlists/rockyou.txt")
        cmd = f"john --wordlist={wordlist} {hashfile}"
        run_with_preview(cmd, session, STAGE)
    elif choice == "2":
        fmt = ask("John format (e.g., raw-md5, nt, bcrypt)")
        wordlist = ask("Wordlist path", default="/usr/share/wordlists/rockyou.txt")
        cmd = f"john --format={fmt} --wordlist={wordlist} {hashfile}"
        run_with_preview(cmd, session, STAGE)
    elif choice == "3":
        cmd = f"john --show {hashfile}"
        run_with_preview(cmd, session, STAGE)


def _generate_wordlist(session):
    """Generate custom wordlists."""
    options = [
        ("1", "[bold]CeWL[/bold]          - Spider website for words"),
        ("2", "[bold]Crunch[/bold]         - Pattern-based generation"),
        ("3", "[bold]CUPP[/bold]           - Profile-based (social eng)"),
        ("4", "[bold]Combine lists[/bold]  - Merge wordlists"),
    ]
    choice = show_menu(options)

    if choice == "1":
        url = ask("Enter target URL to spider")
        depth = ask("Spider depth", default="3")
        minlen = ask("Minimum word length", default="6")
        output = ask("Output file", default="/tmp/cewl_wordlist.txt")
        cmd = f"cewl {url} -d {depth} -m {minlen} -w {output}"
        run_with_preview(cmd, session, STAGE)

    elif choice == "2":
        minlen = ask("Minimum length", default="6")
        maxlen = ask("Maximum length", default="8")
        charset = ask("Characters (e.g., abcdef0123456789)", default="abcdefghijklmnopqrstuvwxyz0123456789")
        output = ask("Output file", default="/tmp/crunch_wordlist.txt")
        cmd = f"crunch {minlen} {maxlen} {charset} -o {output}"
        run_with_preview(cmd, session, STAGE)

    elif choice == "3":
        cmd = "cupp -i"
        info("CUPP will ask personal questions to build a targeted wordlist.")
        run_with_preview(cmd, session, STAGE)

    elif choice == "4":
        files = ask("Enter wordlist files (space-separated)")
        output = ask("Output file", default="/tmp/combined_wordlist.txt")
        cmd = f"cat {files} | sort -u > {output} && wc -l {output}"
        run_with_preview(cmd, session, STAGE)


def _hash_modes_reference(session):
    """Display hash modes reference table."""
    from rich.table import Table
    table = Table(title="Hash Modes Reference", show_header=True)
    table.add_column("Hash Type", style="cyan bold")
    table.add_column("Hashcat -m", style="yellow")
    table.add_column("John --format", style="green")

    for name, m in HASH_MODES.items():
        hc = str(m["hashcat"]) if m["hashcat"] >= 0 else "N/A"
        table.add_row(name, hc, m["john"])

    console.print(table)


def _cheat_sheet():
    content = """# Password Cracking Cheat Sheet

## Hashcat
```
hashcat -m 0 hashes.txt rockyou.txt          # MD5 + wordlist
hashcat -m 1000 hashes.txt rockyou.txt       # NTLM
hashcat -m 5600 hashes.txt rockyou.txt       # NTLMv2
hashcat -m 13100 hashes.txt rockyou.txt      # Kerberoast
hashcat -m 22000 capture.hc22000 rockyou.txt # WPA
hashcat -m 0 -a 3 hashes.txt '?a?a?a?a?a?a' # Brute 6-char
hashcat -m 0 -a 0 -r best64.rule hashes.txt rockyou.txt  # Rules
```

## John the Ripper
```
john --wordlist=rockyou.txt hashes.txt       # Auto-detect
john --format=raw-md5 --wordlist=rockyou.txt hashes.txt
john --show hashes.txt                        # Show cracked
john --rules --wordlist=rockyou.txt hashes.txt  # With rules
```

## Wordlist Generation
```
cewl http://target -d 3 -m 6 -w wordlist.txt  # Spider site
crunch 6 8 abc123 -o wordlist.txt              # Pattern gen
cupp -i                                         # Profile-based
```

## Mask Characters (hashcat)
?l = lowercase, ?u = uppercase, ?d = digit
?s = special, ?a = all, ?b = binary
"""
    show_knowledge(content)


def run(session):
    """Password Cracker module entry point."""
    show_stage_header("Password Cracker", "Unified hashcat/john wrapper — identify, crack, generate")

    while True:
        options = [
            ("1", "[bold]Identify Hash[/bold]    - Detect hash type"),
            ("2", "[bold]Hashcat Attack[/bold]   - GPU-accelerated cracking"),
            ("3", "[bold]John Attack[/bold]      - CPU cracking"),
            ("4", "[bold]Generate Wordlist[/bold]- CeWL, crunch, CUPP"),
            ("5", "[bold]Hash Modes[/bold]       - Reference table"),
            ("6", "[bold]Cheat Sheet[/bold]      - Cracking reference"),
            ("0", "[bold]Back to Main Menu[/bold]"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _identify_hash(session)
        elif choice == "2":
            _hashcat_attack(session)
        elif choice == "3":
            _john_attack(session)
        elif choice == "4":
            _generate_wordlist(session)
        elif choice == "5":
            _hash_modes_reference(session)
        elif choice == "6":
            _cheat_sheet()
