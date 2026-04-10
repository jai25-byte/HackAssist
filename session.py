"""Session/engagement tracking and logging."""

import os
import json
import re
from datetime import datetime
from ui import (console, show_menu, show_stage_header, info, success,
                error, warning, ask, confirm, show_results_panel)

SESSIONS_DIR = os.path.expanduser("~/hackassist_sessions")
STAGE_DIRS = ["recon", "scanning", "enumeration", "exploitation", "post_exploitation"]


def _sanitize(name):
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', name)


def create_session(target, engagement_type):
    """Create a new engagement session with directory structure."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    safe_target = _sanitize(target)
    session_name = f"{timestamp}_{safe_target}"
    session_path = os.path.join(SESSIONS_DIR, session_name)

    os.makedirs(session_path, exist_ok=True)
    for stage_dir in STAGE_DIRS:
        os.makedirs(os.path.join(session_path, stage_dir), exist_ok=True)

    session = {
        "target": target,
        "type": engagement_type,
        "started": datetime.now().isoformat(),
        "path": session_path,
        "findings": [],
        "commands": [],
    }

    _save_session(session)

    # Create empty commands log
    with open(os.path.join(session_path, "commands.log"), "w") as f:
        f.write(f"# HackAssist Session Log\n# Target: {target}\n# Type: {engagement_type}\n# Started: {session['started']}\n\n")

    success(f"Session created: {session_path}")
    return session


def _save_session(session):
    """Save session metadata to JSON."""
    path = os.path.join(session["path"], "session.json")
    # Atomic write
    tmp_path = path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(session, f, indent=2)
    os.replace(tmp_path, path)


def load_session(session_path):
    """Load an existing session."""
    json_path = os.path.join(session_path, "session.json")
    if not os.path.exists(json_path):
        error(f"No session.json found in {session_path}")
        return None
    with open(json_path, "r") as f:
        return json.load(f)


def list_sessions():
    """List all existing sessions."""
    if not os.path.exists(SESSIONS_DIR):
        return []

    sessions = []
    for name in sorted(os.listdir(SESSIONS_DIR), reverse=True):
        path = os.path.join(SESSIONS_DIR, name)
        if os.path.isdir(path):
            session = load_session(path)
            if session:
                sessions.append(session)
    return sessions


def log_command(session, stage, command, output):
    """Log a command and its output to the session."""
    if not session:
        return

    timestamp = datetime.now().isoformat()

    # Append to commands.log
    log_path = os.path.join(session["path"], "commands.log")
    with open(log_path, "a") as f:
        f.write(f"\n[{timestamp}] [{stage}]\n")
        f.write(f"$ {command}\n")
        if output:
            f.write(output)
            if not output.endswith("\n"):
                f.write("\n")
        f.write("-" * 60 + "\n")

    # Save output to stage directory
    stage_dir = os.path.join(session["path"], stage.replace("-", "_"))
    if os.path.isdir(stage_dir):
        safe_cmd = _sanitize(command[:50])
        ts = datetime.now().strftime("%H%M%S")
        output_file = os.path.join(stage_dir, f"{ts}_{safe_cmd}.txt")
        with open(output_file, "w") as f:
            f.write(f"Command: {command}\nTimestamp: {timestamp}\n\n{output or ''}")

    # Track in session
    session["commands"].append({
        "stage": stage,
        "command": command,
        "timestamp": timestamp,
    })
    _save_session(session)


def save_finding(session, stage, title, severity, details):
    """Add a finding to the session."""
    if not session:
        return

    finding = {
        "stage": stage,
        "title": title,
        "severity": severity,
        "details": details,
        "timestamp": datetime.now().isoformat(),
    }
    session["findings"].append(finding)
    _save_session(session)
    success(f"Finding saved: {title}")


def get_session_menu(current_session):
    """Interactive session management menu. Returns session dict or None."""
    show_stage_header("Session Manager", "Create or load engagement sessions")

    while True:
        status = f"Current: [green]{current_session['target']}[/green]" if current_session else "No active session"
        console.print(f"  [dim]{status}[/dim]\n")

        options = [
            ("1", "Create New Session"),
            ("2", "Load Existing Session"),
            ("3", "Continue Without Session"),
        ]
        if current_session:
            options.insert(0, ("4", f"Keep Current ({current_session.get('target', 'unknown')})"))
        options.append(("0", "Back"))

        choice = show_menu(options)

        if choice == "0" or choice == "4":
            return current_session
        elif choice == "1":
            target = ask("Enter target (IP, domain, or CTF name)")
            type_options = [
                ("1", "CTF Competition"),
                ("2", "Authorized Pentest"),
                ("3", "Bug Bounty"),
                ("4", "Lab/Learning"),
            ]
            console.print("\n[bold]Engagement type:[/bold]")
            type_choice = show_menu(type_options)
            type_map = {"1": "ctf", "2": "pentest", "3": "bugbounty", "4": "lab"}
            return create_session(target, type_map.get(type_choice, "lab"))
        elif choice == "2":
            sessions = list_sessions()
            if not sessions:
                warning("No existing sessions found.")
                continue
            console.print("\n[bold]Existing sessions:[/bold]")
            sess_options = []
            for i, s in enumerate(sessions[:10]):
                label = f"{s['target']} ({s['type']}) - {s['started'][:10]}"
                sess_options.append((str(i+1), label))
            sess_options.append(("0", "Back"))
            sess_choice = show_menu(sess_options)
            if sess_choice != "0":
                return sessions[int(sess_choice) - 1]
        elif choice == "3":
            return None
