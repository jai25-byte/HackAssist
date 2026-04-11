#!/usr/bin/env python3
"""HackAssist - Multi-Target Mode for parallel operations."""

import os
import threading
import time
from datetime import datetime

from ui import console, show_menu, ask, info, success, warning, error
from executor import run_command

TARGETS_DIR = os.path.expanduser("~/hackassist_multitarget")


def _ensure_dir():
    os.makedirs(TARGETS_DIR, exist_ok=True)


def _load_targets():
    filepath = os.path.join(TARGETS_DIR, "targets.txt")
    if not os.path.exists(filepath):
        return []
    with open(filepath) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]


def _save_targets(targets):
    _ensure_dir()
    filepath = os.path.join(TARGETS_DIR, "targets.txt")
    with open(filepath, 'w') as f:
        f.write('\n'.join(targets) + '\n')


def _manage_targets():
    targets = _load_targets()
    while True:
        console.print(f"\n[bold cyan]Targets ({len(targets)}):[/bold cyan]")
        for i, t in enumerate(targets, 1):
            console.print(f"  {i}. [cyan]{t}[/cyan]")
        if not targets:
            console.print("  [dim]No targets loaded[/dim]")

        options = [
            ("a", "Add target"),
            ("f", "Load from file"),
            ("r", "Remove target"),
            ("c", "Clear all"),
            ("0", "Back"),
        ]
        choice = show_menu(options)

        if choice == "0":
            break
        elif choice == "a":
            target = ask("Target (IP/hostname)")
            if target:
                targets.append(target)
                _save_targets(targets)
                success(f"Added: {target}")
        elif choice == "f":
            filepath = ask("File path (one target per line)")
            if filepath and os.path.exists(filepath):
                with open(filepath) as f:
                    new = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                targets.extend(new)
                _save_targets(targets)
                success(f"Loaded {len(new)} targets")
            else:
                error("File not found.")
        elif choice == "r":
            num = ask("Target number to remove")
            try:
                idx = int(num) - 1
                removed = targets.pop(idx)
                _save_targets(targets)
                success(f"Removed: {removed}")
            except (ValueError, IndexError):
                error("Invalid number.")
        elif choice == "c":
            targets = []
            _save_targets(targets)
            success("All targets cleared.")


def _parallel_scan():
    targets = _load_targets()
    if not targets:
        error("No targets loaded. Add targets first.")
        return

    cmd_template = ask("Command template (use {target} placeholder)") or "nmap -sV --top-ports 20 -T4 {target}"
    max_threads = int(ask("Max concurrent threads (default 5)") or "5")

    results = {}
    lock = threading.Lock()
    semaphore = threading.Semaphore(max_threads)

    def scan_target(target):
        with semaphore:
            cmd = cmd_template.replace('{target}', target)
            output = run_command(cmd, capture=True, timeout=300)
            with lock:
                results[target] = output or "(no output)"

    console.print(f"\n[bold]Scanning {len(targets)} targets with {max_threads} threads...[/bold]\n")
    threads = []
    for t in targets:
        thread = threading.Thread(target=scan_target, args=(t,))
        threads.append(thread)
        thread.start()

    # Wait with progress
    from rich.progress import Progress
    with Progress(console=console) as progress:
        task = progress.add_task("Scanning...", total=len(targets))
        while any(t.is_alive() for t in threads):
            done = len(results)
            progress.update(task, completed=done)
            time.sleep(0.5)
        progress.update(task, completed=len(targets))

    # Display results
    for target, output in results.items():
        console.print(f"\n[bold cyan]{'='*50}[/bold cyan]")
        console.print(f"[bold green]Target: {target}[/bold green]")
        console.print(f"[bold cyan]{'='*50}[/bold cyan]")
        console.print(output[:2000])

    # Save results
    _ensure_dir()
    result_file = os.path.join(TARGETS_DIR, f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    with open(result_file, 'w') as f:
        for target, output in results.items():
            f.write(f"\n{'='*50}\nTarget: {target}\n{'='*50}\n{output}\n")
    success(f"Results saved: {result_file}")


def _compare_results():
    targets = _load_targets()
    if not targets:
        error("No targets loaded.")
        return

    from rich.table import Table
    table = Table(title="Multi-Target Comparison", border_style="cyan")
    table.add_column("Target", style="cyan")
    table.add_column("Ping", style="green")
    table.add_column("Open Ports", style="yellow")

    for target in targets:
        # Quick ping
        ping = run_command(f"ping -c 1 -W 2 {target}", capture=True, timeout=5)
        ping_status = "[green]Up[/green]" if ping and "1 packets received" in ping else "[red]Down[/red]"

        # Quick port check
        ports_out = run_command(f"nmap -sT --top-ports 10 -T4 {target} 2>/dev/null | grep open", capture=True, timeout=30)
        port_count = len(ports_out.strip().split('\n')) if ports_out and ports_out.strip() else 0

        table.add_row(target, ping_status, str(port_count))

    console.print(table)


def run(session):
    """Multi-target mode entry point."""
    while True:
        targets = _load_targets()
        console.print(f"\n[bold green]MULTI-TARGET MODE[/bold green] ({len(targets)} targets)\n")
        options = [
            ("1", "Manage Targets"),
            ("2", "Parallel Scan"),
            ("3", "Quick Compare"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            break
        elif choice == "1":
            _manage_targets()
        elif choice == "2":
            _parallel_scan()
        elif choice == "3":
            _compare_results()
