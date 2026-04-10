"""Command executor with real-time output streaming."""

import subprocess
import signal
import sys
from datetime import datetime
from ui import console, show_command_preview, info, error, success, warning


def run_command(cmd, capture=True, timeout=600):
    """Run a shell command with real-time output streaming.

    Returns:
        tuple: (returncode, stdout_text, stderr_text)
    """
    info(f"Running: {cmd}")
    console.print()

    stdout_lines = []
    try:
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        for line in iter(process.stdout.readline, ''):
            console.print(f"  [dim]{line.rstrip()}[/dim]")
            if capture:
                stdout_lines.append(line)

        process.wait(timeout=timeout)
        console.print()

        output = ''.join(stdout_lines)

        if process.returncode == 0:
            success("Command completed successfully.")
        else:
            warning(f"Command exited with code {process.returncode}")

        return process.returncode, output, ""

    except subprocess.TimeoutExpired:
        process.kill()
        error(f"Command timed out after {timeout}s")
        return -1, ''.join(stdout_lines), "Timeout"
    except KeyboardInterrupt:
        process.kill()
        process.wait()
        warning("Command interrupted by user.")
        return -2, ''.join(stdout_lines), "Interrupted"


def run_with_preview(cmd, session=None, stage=None):
    """Show command preview, ask confirmation, run, and optionally log to session.

    Returns:
        tuple: (returncode, stdout, stderr) or None if user declined.
    """
    confirmed = show_command_preview(cmd)
    if not confirmed:
        warning("Command skipped.")
        return None

    result = run_command(cmd)

    if session and stage:
        from session import log_command
        log_command(session, stage, cmd, result[1])

    return result
