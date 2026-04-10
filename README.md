# HackAssist

**AI-powered terminal hacking assistant for authorized security testing.**

A standalone, menu-driven penetration testing toolkit that guides you through every stage of an engagement — from reconnaissance to footprint erasure. No API keys needed. Runs entirely in your terminal.

![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-macOS%20|%20Linux-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Tools](https://img.shields.io/badge/Tools-30+-orange)

---

## Features

### 11-Stage Attack Framework

| # | Stage | Description |
|---|-------|-------------|
| 1 | **Recon** | WHOIS, DNS, subdomain discovery, theHarvester, Shodan, Google dork generator |
| 2 | **Scanning** | 9 nmap scan types, RustScan, masscan, custom commands |
| 3 | **Enumeration** | gobuster, ffuf, nikto, SMB/SNMP enum, DNS zone transfer, SSL analysis |
| 4 | **Exploitation** | searchsploit, sqlmap, hydra, john/hashcat, reverse shell generator (11 languages) |
| 5 | **Post-Exploit** | LinPEAS/WinPEAS, SUID finder, priv-esc checklists, file transfer helpers |
| 6 | **Reporting** | Auto-generate markdown reports from session data |
| 7 | **Tool Manager** | Auto-detect 30+ tools, install missing ones via brew/pip/git |
| 8 | **Session** | Track engagements, log all commands & outputs |
| 9 | **Auto Attack** | AI-driven autonomous pipeline: Recon -> Scan -> Enum -> Vuln Analysis |
| 10 | **Defense Monitor** | Real-time autonomous system protection (5 monitors, auto-response) |
| 11 | **Footprint Erasure** | Cover tracks, clean logs, self-destruct |

### Autonomous Defense Monitor (no permission needed)

Runs in a background thread while you work. Monitors and auto-responds:

- **Network** — Detects port scans, connection floods. Auto-blocks IPs via pf firewall.
- **Process** — Detects reverse shells, cryptominers, suspicious commands. Auto-kills processes.
- **Ports** — Alerts on new unexpected listening ports.
- **File Integrity** — Watches `/etc/passwd`, `sudoers`, SSH keys, shell configs for changes.
- **Login** — Detects SSH/login brute force attempts.
- **Learning Memory** — Remembers baselines, safe IPs/processes, improves over time (inspired by [Hermes Agent](https://github.com/NousResearch/hermes-agent)).

### AI Auto-Attack Pipeline (permission-gated)

Autonomous attack chain inspired by [Hermes Agent](https://github.com/NousResearch/hermes-agent) + [AutoResearch](https://github.com/karpathy/autoresearch):

1. You provide a target and agree **once**
2. **Recon -> Scanning -> Enumeration -> Vuln Analysis** runs autonomously
3. AI decision engine parses output and routes each phase intelligently
4. **Pauses at exploitation** — asks your permission before any exploit
5. Generates a full markdown report

### Footprint Erasure & Self-Destruct

- Linux/Windows log cleanup (targeted IP removal or full wipe)
- Shell history wipe (bash, zsh, python, mysql, vim, less, node)
- Web server log cleanup (Apache/Nginx)
- SSH trace cleanup, timestomping, secure file deletion
- Network trace cleanup (ARP, DNS, firewall rules)
- **Self-Destruct**: Triple-confirmed destruction of all HackAssist data, sessions, defense logs, source code, and shell history references

### Built-in Knowledge Base

- Stage-by-stage explanations and tips
- Cheat sheets for 11 tools (nmap, sqlmap, hydra, john, hashcat, gobuster, ffuf, nikto, etc.)
- Reverse shell generator (11 languages: bash, python, php, perl, ruby, netcat, PowerShell, socat)
- Google dork generator (14 dork categories)
- Linux & Windows privilege escalation checklists
- 55-command anti-forensics reference

---

## Installation

```bash
# Clone the repo
git clone https://github.com/jai25-byte/HackAssist.git
cd HackAssist

# Install the only dependency
pip3 install rich

# Run
python3 hackassist.py
```

### Requirements

- **Python 3.9+**
- **macOS or Linux** (macOS optimized, Linux compatible)
- **Homebrew** (for installing security tools on macOS)
- Only Python dependency: `rich`

---

## Usage

```bash
python3 hackassist.py
```

You'll see:

```
    __  __           __   ___              _      __
   / / / /___ ______/ /__/   |  __________(_)____/ /_
  / /_/ / __ `/ ___/ //_/ /| | / ___/ ___/ / ___/ __/
 / __  / /_/ / /__/ ,< / ___ |(__  |__  ) (__  ) /_
/_/ /_/\__,_/\___/_/|_/_/  |_/____/____/_/____/\__/

  1. Recon           - Passive & active information gathering
  2. Scanning        - Port scanning & service detection
  3. Enumeration     - Deep-dive into discovered services
  4. Exploitation    - Vulnerability exploitation & access
  5. Post-Exploit    - Privilege escalation & persistence
  6. Reporting       - Generate engagement report
  7. Tool Manager    - Check & install hacking tools
  8. Session         - Manage engagement sessions
  9. Auto Attack     - AI autonomous attack pipeline
 10. Defense         - Autonomous system protection
 11. Footprint Erasure - Cover tracks & self-destruct
  0. Exit
```

### Quick Start

1. **Agree to the disclaimer** (type `I AGREE`)
2. **Create a session** (tracks all your commands and findings)
3. **Go to Tool Manager** (option 7) to install any missing tools
4. **Start with Recon** (option 1) and work your way down
5. **Or use Auto Attack** (option 9) for an AI-driven autonomous pipeline

---

## Supported Tools (30+)

HackAssist auto-detects installed tools and offers to install missing ones.

| Category | Tools |
|----------|-------|
| Recon | whois, subfinder, amass, theHarvester, shodan |
| Scanning | nmap, masscan, rustscan |
| Web | nikto, gobuster, ffuf, sqlmap, wfuzz |
| Exploitation | metasploit, searchsploit, hydra, john, hashcat |
| Network | wireshark, tcpdump, netcat, aircrack-ng |
| Post-Exploit | linpeas, winpeas, pspy |
| Utilities | curl, wget, jq, git |

---

## Project Structure

```
HackAssist/
├── hackassist.py          # Entry point & main menu
├── ui.py                  # Rich TUI components
├── executor.py            # Command runner with real-time streaming
├── tool_manager.py        # 30+ tool registry & installer
├── session.py             # Engagement session tracking
├── knowledge.py           # Knowledge base & cheat sheets
├── defender.py            # Autonomous defense monitor
├── auto_attack.py         # AI auto-attack pipeline
├── auto_mode.py           # Legacy auto mode
├── stages/
│   ├── recon.py           # Reconnaissance
│   ├── scanning.py        # Port scanning
│   ├── enumeration.py     # Service enumeration
│   ├── exploitation.py    # Exploitation & access
│   ├── post_exploit.py    # Privilege escalation
│   ├── reporting.py       # Report generation
│   └── footprint_erasure.py  # Anti-forensics & self-destruct
└── requirements.txt       # rich
```

---

## Inspired By

- **[Hermes Agent](https://github.com/NousResearch/hermes-agent)** — Self-improving learning loop, sub-agent spawning, persistent memory
- **[AutoResearch](https://github.com/karpathy/autoresearch)** — Autonomous experiment cycle (try -> evaluate -> decide -> act), single-metric focus

---

## Disclaimer

> **WARNING:** This tool is intended for **authorized security testing only**.
> Unauthorized access to computer systems is **illegal** and punishable by law.
> By using this tool, you confirm that you have explicit written authorization
> to test the target systems, or you are using this in a controlled lab/CTF environment.
> The developer assumes **no liability** for misuse.

---

## License

MIT License. Use responsibly.
