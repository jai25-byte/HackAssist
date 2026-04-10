"""Reporting stage - generate engagement reports."""

import sys
import os
import subprocess
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui import (show_stage_header, show_menu, ask, info, success, warning,
                error, console, confirm)

STAGE = "reporting"


def run(session):
    show_stage_header("Reporting", "Document and export your findings")

    if not session:
        warning("No active session. Create a session first to use reporting.")
        warning("You can still add findings manually.")
        return

    while True:
        finding_count = len(session.get("findings", []))
        cmd_count = len(session.get("commands", []))
        console.print(f"  [dim]Session: {session.get('target', 'N/A')} | "
                      f"Findings: {finding_count} | Commands logged: {cmd_count}[/dim]\n")

        options = [
            ("1", "View Current Findings"),
            ("2", "Add Manual Finding"),
            ("3", "Generate Markdown Report"),
            ("4", "View Commands Log"),
            ("5", "Open Session Folder"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _view_findings(session)
        elif choice == "2":
            _add_finding(session)
        elif choice == "3":
            _generate_report(session)
        elif choice == "4":
            _view_commands(session)
        elif choice == "5":
            _open_folder(session)


def _view_findings(session):
    findings = session.get("findings", [])
    if not findings:
        warning("No findings recorded yet.")
        return

    severity_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    console.print(f"\n[bold cyan]Findings ({len(findings)}):[/bold cyan]\n")
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "info").lower()
        color = severity_colors.get(sev, "white")
        console.print(f"  [{color}]{i}. [{sev.upper()}] {f['title']}[/{color}]")
        console.print(f"     [dim]Stage: {f.get('stage', 'N/A')} | {f.get('timestamp', '')[:19]}[/dim]")
        if f.get("details"):
            console.print(f"     {f['details'][:100]}")
        console.print()


def _add_finding(session):
    from session import save_finding

    title = ask("Finding title")
    stage_options = [
        ("1", "Recon"), ("2", "Scanning"), ("3", "Enumeration"),
        ("4", "Exploitation"), ("5", "Post-Exploitation"),
    ]
    console.print("\n[bold]Stage:[/bold]")
    stage_choice = show_menu(stage_options)
    stage_map = {"1": "recon", "2": "scanning", "3": "enumeration",
                 "4": "exploitation", "5": "post_exploitation"}
    stage = stage_map.get(stage_choice, "recon")

    sev_options = [
        ("1", "Critical"), ("2", "High"), ("3", "Medium"),
        ("4", "Low"), ("5", "Informational"),
    ]
    console.print("\n[bold]Severity:[/bold]")
    sev_choice = show_menu(sev_options)
    sev_map = {"1": "critical", "2": "high", "3": "medium", "4": "low", "5": "info"}
    severity = sev_map.get(sev_choice, "info")

    details = ask("Details / description")

    save_finding(session, stage, title, severity, details)


def _generate_report(session):
    report_path = os.path.join(session["path"], "report.md")

    findings = session.get("findings", [])
    commands = session.get("commands", [])

    # Count findings by severity
    sev_counts = {}
    for f in findings:
        s = f.get("severity", "info")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    report = f"""# Penetration Test Report

## Engagement Summary

| Field | Value |
|-------|-------|
| Target | {session.get('target', 'N/A')} |
| Type | {session.get('type', 'N/A')} |
| Started | {session.get('started', 'N/A')} |
| Report Generated | {datetime.now().isoformat()[:19]} |
| Total Findings | {len(findings)} |
| Commands Executed | {len(commands)} |

## Finding Summary

| Severity | Count |
|----------|-------|
| Critical | {sev_counts.get('critical', 0)} |
| High | {sev_counts.get('high', 0)} |
| Medium | {sev_counts.get('medium', 0)} |
| Low | {sev_counts.get('low', 0)} |
| Info | {sev_counts.get('info', 0)} |

## Detailed Findings

"""
    if not findings:
        report += "_No findings recorded._\n\n"
    else:
        for i, f in enumerate(findings, 1):
            report += f"""### {i}. {f.get('title', 'Untitled')}

- **Severity:** {f.get('severity', 'N/A').upper()}
- **Stage:** {f.get('stage', 'N/A')}
- **Discovered:** {f.get('timestamp', 'N/A')[:19]}

**Details:**

{f.get('details', 'No details provided.')}

---

"""

    report += """## Methodology

The following stages were covered during this engagement:

1. **Reconnaissance** - Passive and active information gathering
2. **Scanning** - Port scanning and service detection
3. **Enumeration** - Deep-dive into discovered services
4. **Exploitation** - Vulnerability exploitation
5. **Post-Exploitation** - Privilege escalation and lateral movement

## Commands Executed

"""
    if commands:
        # Group commands by stage
        stages_seen = {}
        for c in commands:
            stage = c.get("stage", "unknown")
            if stage not in stages_seen:
                stages_seen[stage] = []
            stages_seen[stage].append(c)

        for stage, cmds in stages_seen.items():
            report += f"### {stage.replace('_', ' ').title()}\n\n"
            for c in cmds:
                report += f"- `{c.get('command', 'N/A')}` ({c.get('timestamp', '')[:19]})\n"
            report += "\n"
    else:
        report += "_No commands logged._\n\n"

    report += """## Recommendations

_Add specific remediation recommendations for each finding._

## Disclaimer

This report is provided for authorized security testing purposes only.
The findings and recommendations are based on the conditions at the time of testing.

---

*Generated by HackAssist*
"""

    with open(report_path, "w") as f:
        f.write(report)

    success(f"Report generated: {report_path}")
    console.print(f"  [dim]{report_path}[/dim]\n")


def _view_commands(session):
    log_path = os.path.join(session["path"], "commands.log")
    if not os.path.exists(log_path):
        warning("No commands log found.")
        return

    with open(log_path, "r") as f:
        content = f.read()

    if not content.strip():
        warning("Commands log is empty.")
        return

    console.print(f"\n[bold cyan]Commands Log:[/bold cyan]\n")
    for line in content.split("\n")[-50:]:  # Last 50 lines
        console.print(f"  [dim]{line}[/dim]")
    console.print()


def _open_folder(session):
    path = session.get("path", "")
    if not path or not os.path.exists(path):
        error("Session path not found.")
        return
    info(f"Opening: {path}")
    subprocess.run(["open", path])
