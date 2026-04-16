"""Skill Tree & Challenge Mode — Gamified learning with progression.

Track pentest skills, built-in practice challenges, and XP system.
"""

import sys, os, json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel)

SKILL_FILE = os.path.expanduser("~/hackassist_sessions/skill_tree.json")

SKILL_TREE = {
    "Recon": {
        "icon": "🔍", "xp_required": [0, 50, 150, 300, 500],
        "skills": [
            ("WHOIS Lookup", 10), ("DNS Enumeration", 15),
            ("Subdomain Discovery", 20), ("OSINT Master", 50),
        ],
    },
    "Scanning": {
        "icon": "📡", "xp_required": [0, 75, 200, 400, 700],
        "skills": [
            ("Port Scanner", 15), ("Service Fingerprinting", 20),
            ("Vulnerability Scanner", 30), ("Stealth Scanning", 50),
        ],
    },
    "Web Hacking": {
        "icon": "🌐", "xp_required": [0, 100, 250, 500, 1000],
        "skills": [
            ("SQL Injection", 25), ("XSS Hunter", 25),
            ("SSRF Expert", 40), ("Auth Bypass", 50),
            ("Deserialization", 60), ("SSTI Master", 60),
        ],
    },
    "Exploitation": {
        "icon": "💥", "xp_required": [0, 100, 300, 600, 1200],
        "skills": [
            ("Searchsploit", 20), ("Metasploit", 30),
            ("Custom Exploit Writing", 60), ("Buffer Overflow", 80),
        ],
    },
    "Post-Exploitation": {
        "icon": "🔑", "xp_required": [0, 75, 200, 400, 800],
        "skills": [
            ("PrivEsc Linux", 25), ("PrivEsc Windows", 25),
            ("Lateral Movement", 40), ("Data Exfiltration", 50),
            ("Persistence", 60),
        ],
    },
    "Cryptography": {
        "icon": "🔐", "xp_required": [0, 50, 150, 350, 600],
        "skills": [
            ("Hash Cracking", 15), ("Cipher Analysis", 25),
            ("RSA Attacks", 40), ("Crypto Implementation Bugs", 60),
        ],
    },
    "Defense": {
        "icon": "🛡️", "xp_required": [0, 50, 150, 300, 500],
        "skills": [
            ("Log Analysis", 15), ("Firewall Config", 20),
            ("Threat Hunting", 35), ("Incident Response", 50),
        ],
    },
}

CHALLENGES = [
    {
        "name": "First Scan", "category": "Scanning", "xp": 15,
        "description": "Run your first nmap scan against a target",
        "hint": "Use: nmap -sV target_ip",
        "check_type": "manual",
    },
    {
        "name": "Find the Flag (Base64)", "category": "Cryptography", "xp": 10,
        "description": "Decode this: ZmxhZ3tkZWNvZGVkX2l0IX0=",
        "hint": "Try base64 decoding",
        "check_type": "answer", "answer": "flag{decoded_it!}",
    },
    {
        "name": "Hidden Header", "category": "Web Hacking", "xp": 20,
        "description": "Use curl to find the custom header on httpbin.org/headers",
        "hint": "curl -v http://httpbin.org/headers",
        "check_type": "manual",
    },
    {
        "name": "ROT13 Challenge", "category": "Cryptography", "xp": 10,
        "description": "Decode: synt{ebg13_vf_rnfl}",
        "hint": "ROT13 is a Caesar cipher with shift 13",
        "check_type": "answer", "answer": "flag{rot13_is_easy}",
    },
    {
        "name": "Hash Cracker", "category": "Cryptography", "xp": 25,
        "description": "Crack this MD5: 5f4dcc3b5aa765d61d8327deb882cf99",
        "hint": "It's a very common password",
        "check_type": "answer", "answer": "password",
    },
    {
        "name": "Subdomain Hunter", "category": "Recon", "xp": 20,
        "description": "Find at least 5 subdomains of example.com using dig or subfinder",
        "hint": "subfinder -d example.com -silent",
        "check_type": "manual",
    },
    {
        "name": "Service Fingerprint", "category": "Scanning", "xp": 20,
        "description": "Identify the SSH version on scanme.nmap.org",
        "hint": "nmap -sV -p 22 scanme.nmap.org",
        "check_type": "manual",
    },
    {
        "name": "Caesar Brute Force", "category": "Cryptography", "xp": 15,
        "description": "Decode: msyn{jhblhy_byvael}  (hint: it's not ROT13)",
        "hint": "Try all 25 rotations. Use CTF Mode auto-decode.",
        "check_type": "answer", "answer": "flag{caesar_cipher}",
    },
    {
        "name": "SQL Injection Basics", "category": "Web Hacking", "xp": 30,
        "description": "What SQL injection payload bypasses 'SELECT * FROM users WHERE user='' AND pass=''?",
        "hint": "Think about how to make the WHERE clause always true",
        "check_type": "answer", "answer": "' OR 1=1 --",
    },
    {
        "name": "SUID Discovery", "category": "Post-Exploitation", "xp": 20,
        "description": "What command finds SUID binaries on Linux?",
        "hint": "Use find with -perm flag",
        "check_type": "answer", "answer": "find / -perm -4000",
    },
]


def _load_progress():
    if os.path.exists(SKILL_FILE):
        with open(SKILL_FILE) as f:
            return json.load(f)
    return {"xp": {cat: 0 for cat in SKILL_TREE}, "completed": [], "total_xp": 0}


def _save_progress(progress):
    os.makedirs(os.path.dirname(SKILL_FILE), exist_ok=True)
    with open(SKILL_FILE, "w") as f:
        json.dump(progress, f, indent=2)


def _get_level(category, xp):
    levels = SKILL_TREE[category]["xp_required"]
    level = 0
    for i, req in enumerate(levels):
        if xp >= req:
            level = i
    return level


def _show_skill_tree():
    progress = _load_progress()
    console.print("\n[bold cyan]═══ SKILL TREE ═══[/bold cyan]\n")

    total_xp = sum(progress["xp"].values())
    rank = "Newbie"
    if total_xp > 100: rank = "Script Kiddie"
    if total_xp > 300: rank = "Hacker"
    if total_xp > 700: rank = "Elite Hacker"
    if total_xp > 1500: rank = "Cyber Ninja"
    if total_xp > 3000: rank = "Legendary"

    console.print(f"  [bold]Rank:[/bold] [bold yellow]{rank}[/bold yellow]  |  "
                  f"[bold]Total XP:[/bold] [green]{total_xp}[/green]\n")

    for category, config in SKILL_TREE.items():
        xp = progress["xp"].get(category, 0)
        level = _get_level(category, xp)
        max_level = len(config["xp_required"]) - 1
        next_xp = config["xp_required"][min(level + 1, max_level)]

        bar_width = 20
        fill = int((xp / max(next_xp, 1)) * bar_width) if level < max_level else bar_width
        bar = "█" * fill + "░" * (bar_width - fill)

        console.print(f"  {config['icon']} [bold]{category}[/bold]  Lv.{level}/{max_level}")
        console.print(f"     [{bar}] {xp}/{next_xp} XP")
        console.print()


def _challenge_mode(session):
    progress = _load_progress()

    console.print("\n[bold cyan]═══ CHALLENGES ═══[/bold cyan]\n")

    for i, challenge in enumerate(CHALLENGES):
        completed = challenge["name"] in progress["completed"]
        status = "[green]✓[/green]" if completed else "[dim]○[/dim]"
        xp = f"[green]+{challenge['xp']} XP[/green]" if not completed else "[dim]done[/dim]"
        console.print(f"  {status} [{i+1}] [bold]{challenge['name']}[/bold] "
                      f"({challenge['category']}) {xp}")

    console.print()
    choice = ask("Challenge number (0 to go back)")
    if choice == "0":
        return

    idx = int(choice) - 1
    if idx < 0 or idx >= len(CHALLENGES):
        error("Invalid challenge")
        return

    challenge = CHALLENGES[idx]
    if challenge["name"] in progress["completed"]:
        info("Already completed!")
        return

    console.print(f"\n[bold yellow]Challenge: {challenge['name']}[/bold yellow]")
    console.print(f"  [dim]{challenge['description']}[/dim]")
    console.print(f"  [cyan]Category:[/cyan] {challenge['category']}")
    console.print(f"  [green]Reward:[/green] +{challenge['xp']} XP\n")

    if confirm("Show hint?", default=False):
        console.print(f"  [yellow]Hint:[/yellow] {challenge['hint']}\n")

    if challenge["check_type"] == "answer":
        answer = ask("Your answer")
        if answer.strip().lower() == challenge["answer"].lower():
            success("🎉 Correct!")
            progress["completed"].append(challenge["name"])
            cat = challenge["category"]
            progress["xp"][cat] = progress["xp"].get(cat, 0) + challenge["xp"]
            progress["total_xp"] = sum(progress["xp"].values())
            _save_progress(progress)
            success(f"+{challenge['xp']} XP in {cat}!")
        else:
            error("❌ Wrong answer. Try again!")
    elif challenge["check_type"] == "manual":
        if confirm("Did you complete this challenge?"):
            progress["completed"].append(challenge["name"])
            cat = challenge["category"]
            progress["xp"][cat] = progress["xp"].get(cat, 0) + challenge["xp"]
            progress["total_xp"] = sum(progress["xp"].values())
            _save_progress(progress)
            success(f"+{challenge['xp']} XP in {cat}!")


def run(session):
    show_stage_header("Skill Tree & Challenges", "Gamified pentesting progression")

    while True:
        options = [
            ("1", "[bold]View Skill Tree[/bold] — Your pentesting progression"),
            ("2", "[bold]Challenge Mode[/bold] — Practice challenges with XP rewards"),
            ("3", "Reset Progress"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _show_skill_tree()
        elif choice == "2":
            _challenge_mode(session)
        elif choice == "3":
            if confirm("Reset ALL progress?", default=False):
                if os.path.exists(SKILL_FILE):
                    os.remove(SKILL_FILE)
                success("Progress reset.")
