#!/usr/bin/env python3
"""HackAssist - Scheduled Reconnaissance Module."""

import os
import json
import time
import threading
from datetime import datetime

from ui import console, show_menu, ask, info, success, warning, error
from executor import run_command

SCHED_DIR = os.path.expanduser("~/hackassist_scheduled")
SCHED_FILE = os.path.join(SCHED_DIR, "jobs.json")

RECON_TEMPLATES = {
    'Port Monitor': {'cmd': 'nmap -sV --top-ports 100 -T4 {target}', 'desc': 'Monitor for new open ports'},
    'Subdomain Monitor': {'cmd': 'subfinder -d {target} -silent', 'desc': 'Discover new subdomains'},
    'Certificate Transparency': {'cmd': 'curl -s "https://crt.sh/?q=%25.{target}&output=json" | python3 -m json.tool', 'desc': 'Monitor new SSL certs'},
    'DNS Changes': {'cmd': 'dig ANY {target}', 'desc': 'Monitor DNS record changes'},
    'HTTP Status': {'cmd': 'curl -sI http://{target} -o /dev/null -w "%{{http_code}}"', 'desc': 'Monitor HTTP availability'},
    'Technology Changes': {'cmd': 'whatweb {target} -q', 'desc': 'Detect technology stack changes'},
    'Whois Changes': {'cmd': 'whois {target}', 'desc': 'Monitor WHOIS record changes'},
    'Custom Command': {'cmd': '', 'desc': 'Run any custom command on schedule'},
}

_scheduler_thread = None
_scheduler_running = False


def _ensure_dir():
    os.makedirs(SCHED_DIR, exist_ok=True)
    if not os.path.exists(SCHED_FILE):
        with open(SCHED_FILE, 'w') as f:
            json.dump([], f)


def _load_jobs():
    _ensure_dir()
    try:
        with open(SCHED_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def _save_jobs(jobs):
    _ensure_dir()
    with open(SCHED_FILE, 'w') as f:
        json.dump(jobs, f, indent=2)


def _create_job(session):
    console.print("\n[bold cyan]Recon Templates[/bold cyan]\n")
    options = [(str(i), f"{name} - {t['desc']}") for i, (name, t) in enumerate(RECON_TEMPLATES.items(), 1)]
    options.append(("0", "Cancel"))
    choice = show_menu(options)
    if choice == "0":
        return

    try:
        idx = int(choice) - 1
        name = list(RECON_TEMPLATES.keys())[idx]
        template = RECON_TEMPLATES[name]
    except (ValueError, IndexError):
        return

    target = session['target'] if session else ask("Target")
    cmd = template['cmd']
    if name == 'Custom Command':
        cmd = ask("Command to run")
    else:
        cmd = cmd.replace('{target}', target)

    interval = ask("Interval in minutes (default 60)") or "60"

    job = {
        'id': int(time.time()),
        'name': f"{name} - {target}",
        'command': cmd,
        'interval_min': int(interval),
        'target': target,
        'created': datetime.now().isoformat(),
        'last_run': None,
        'run_count': 0,
        'active': True,
        'results_file': os.path.join(SCHED_DIR, f"results_{int(time.time())}.log"),
    }

    jobs = _load_jobs()
    jobs.append(job)
    _save_jobs(jobs)
    success(f"Job created: {job['name']} (every {interval} min)")


def _list_jobs():
    jobs = _load_jobs()
    if not jobs:
        warning("No scheduled jobs.")
        return

    from rich.table import Table
    table = Table(title="Scheduled Recon Jobs", border_style="cyan")
    table.add_column("ID", width=12)
    table.add_column("Name", style="cyan")
    table.add_column("Interval", style="yellow")
    table.add_column("Runs", style="green")
    table.add_column("Last Run", style="dim")
    table.add_column("Status", style="bold")

    for j in jobs:
        status = "[green]Active[/green]" if j['active'] else "[red]Paused[/red]"
        last = j['last_run'][-19:] if j['last_run'] else "Never"
        table.add_row(str(j['id']), j['name'], f"{j['interval_min']}m", str(j['run_count']), last, status)
    console.print(table)


def _run_scheduler():
    global _scheduler_running
    _scheduler_running = True
    info("Scheduler started in background.")

    while _scheduler_running:
        jobs = _load_jobs()
        now = time.time()
        updated = False

        for job in jobs:
            if not job['active']:
                continue
            last = 0
            if job['last_run']:
                try:
                    last = datetime.fromisoformat(job['last_run']).timestamp()
                except Exception:
                    pass
            if now - last >= job['interval_min'] * 60:
                output = run_command(job['command'], capture=True, timeout=300)
                job['last_run'] = datetime.now().isoformat()
                job['run_count'] += 1
                updated = True

                # Save results
                try:
                    with open(job['results_file'], 'a') as f:
                        f.write(f"\n=== Run #{job['run_count']} at {job['last_run']} ===\n")
                        f.write(output or "(no output)")
                        f.write("\n")
                except Exception:
                    pass

        if updated:
            _save_jobs(jobs)
        time.sleep(30)


def _start_scheduler():
    global _scheduler_thread, _scheduler_running
    if _scheduler_running:
        warning("Scheduler already running.")
        return
    _scheduler_thread = threading.Thread(target=_run_scheduler, daemon=True)
    _scheduler_thread.start()
    success("Background scheduler started.")


def _stop_scheduler():
    global _scheduler_running
    _scheduler_running = False
    success("Scheduler stopped.")


def _view_results():
    jobs = _load_jobs()
    if not jobs:
        warning("No jobs.")
        return

    options = [(str(i), j['name']) for i, j in enumerate(jobs, 1)]
    options.append(("0", "Back"))
    choice = show_menu(options)
    if choice == "0":
        return

    try:
        idx = int(choice) - 1
        job = jobs[idx]
        if os.path.exists(job['results_file']):
            with open(job['results_file']) as f:
                content = f.read()[-5000:]  # Last 5000 chars
            console.print(content)
        else:
            warning("No results yet.")
    except (ValueError, IndexError):
        pass


def run(session):
    """Scheduled recon entry point."""
    while True:
        status = "[green]RUNNING[/green]" if _scheduler_running else "[red]STOPPED[/red]"
        console.print(f"\n[bold green]SCHEDULED RECON[/bold green] [{status}]\n")
        options = [
            ("1", "Create Recon Job"),
            ("2", "List Jobs"),
            ("3", "Start Scheduler"),
            ("4", "Stop Scheduler"),
            ("5", "View Results"),
            ("6", "Run Job Now"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            break
        elif choice == "1":
            _create_job(session)
        elif choice == "2":
            _list_jobs()
        elif choice == "3":
            _start_scheduler()
        elif choice == "4":
            _stop_scheduler()
        elif choice == "5":
            _view_results()
        elif choice == "6":
            jobs = _load_jobs()
            if jobs:
                options = [(str(i), j['name']) for i, j in enumerate(jobs, 1)]
                options.append(("0", "Back"))
                c = show_menu(options)
                if c != "0":
                    try:
                        j = jobs[int(c) - 1]
                        output = run_command(j['command'], capture=True, timeout=300)
                        console.print(output or "(no output)")
                    except (ValueError, IndexError):
                        pass
