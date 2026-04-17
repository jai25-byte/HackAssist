"""Shared Rich UI components for HackAssist."""

import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich.syntax import Syntax
from rich.markdown import Markdown

console = Console()

BANNER_IDLE = r"""
    __  __           __   ___              _      __
   / / / /___ ______/ /__/   |  __________(_)____/ /_
  / /_/ / __ `/ ___/ //_/ /| | / ___/ ___/ / ___/ __/
 / __  / /_/ / /__/ ,< / ___ |(__  |__  ) (__  ) /_
/_/ /_/\__,_/\___/_/|_/_/  |_/____/____/_/____/\__/
"""

BANNER_ACTIVE = r"""
🔥 __  __           __   ___              _      __ 🔥
🔥/ / / /___ ______/ /__/   |  __________(_)____/ /_🔥
🔥/ /_/ / __ `/ ___/ //_/ /| | / ___/ ___/ / ___/ __/🔥
🔥/ __  / /_/ / /__/ ,< / ___ |(__  |__  ) (__  ) /_ 🔥
🔥/_/ /_/\__,_/\___/_/|_/_/  |_/____/____/_/____/\__/🔥
"""

VERSION = "v1.5.0-Mega"

# Theme definitions
THEMES = {
    "default": {"primary": "green", "secondary": "cyan", "alert": "red", "warn": "yellow", "info": "blue"},
    "matrix": {"primary": "green", "secondary": "green", "alert": "bright_green", "warn": "green", "info": "green"},
    "cyberpunk": {"primary": "magenta", "secondary": "cyan", "alert": "bright_red", "warn": "yellow", "info": "bright_blue"},
    "dracula": {"primary": "magenta", "secondary": "cyan", "alert": "red", "warn": "yellow", "info": "green"}
}
CURRENT_THEME = "default"

def set_theme(theme_name):
    global CURRENT_THEME
    if theme_name in THEMES:
        CURRENT_THEME = theme_name

def get_color(color_type):
    return THEMES[CURRENT_THEME][color_type]

def show_banner(threat_level="low"):
    banner = BANNER_ACTIVE if threat_level == "high" else BANNER_IDLE
    banner_text = Text(banner, style=f"bold {get_color('primary')}")
    console.print(Panel(
        banner_text,
        subtitle=f"[{get_color('secondary')}]{VERSION}[/{get_color('secondary')}] | Terminal Hacking Assistant",
        border_style=get_color('primary'),
    ))



def show_disclaimer():
    disclaimer = """
[bold red]WARNING: LEGAL DISCLAIMER[/bold red]

This tool is intended for [bold]authorized security testing only[/bold].

Unauthorized access to computer systems is [bold red]ILLEGAL[/bold red] and punishable
by law under the Computer Fraud and Abuse Act (CFAA) and similar
legislation worldwide.

By using this tool, you confirm that:
  [yellow]1.[/yellow] You have explicit written authorization to test the target systems, OR
  [yellow]2.[/yellow] You are using this in a controlled lab/CTF environment.

[bold]The developer assumes NO liability for misuse of this tool.[/bold]
"""
    console.print(Panel(disclaimer, border_style="red", title="[bold red]DISCLAIMER[/bold red]"))
    response = Prompt.ask("[bold yellow]Type 'I AGREE' to continue[/bold yellow]")
    if response.strip().upper() != "I AGREE":
        console.print("[red]You must agree to the disclaimer to use this tool. Exiting.[/red]")
        sys.exit(0)
    console.print("[green]Disclaimer accepted. Proceeding...[/green]\n")
    return True


def show_stage_header(title, description):
    console.print()
    console.print(Panel(
        f"[bold white]{description}[/bold white]",
        title=f"[bold {get_color('secondary')}]{title}[/bold {get_color('secondary')}]",
        border_style=get_color('secondary'),
    ))
    console.print()


def show_menu(options):
    """Display a numbered menu and return the selected key.

    Args:
        options: list of (key, label) tuples, e.g. [("1", "Quick Scan"), ("0", "Back")]
    Returns:
        The key string of the selected option.
    """
    for key, label in options:
        if key == "":
            console.print(f"\n  {label}")
        elif key == "0":
            console.print(f"  [dim]{key}.[/dim] [dim]{label}[/dim]")
        else:
            console.print(f"  [bold yellow]{key}.[/bold yellow] {label}")
    console.print()

    valid_keys = [k for k, _ in options if k != ""]
    while True:
        choice = Prompt.ask("[bold green]Select option[/bold green]")
        if choice in valid_keys:
            return choice
        console.print(f"[red]Invalid choice. Valid options: {', '.join(valid_keys)}[/red]")


def show_tool_status(tools_status):
    """Show a table of tool install status.

    Args:
        tools_status: dict of {tool_name: (installed: bool, description: str)}
    """
    table = Table(title="Tool Status", border_style="cyan")
    table.add_column("Tool", style="bold white")
    table.add_column("Status", justify="center")
    table.add_column("Description", style="dim")

    for name, (installed, desc) in tools_status.items():
        status = "[bold green]Installed[/bold green]" if installed else "[bold red]Missing[/bold red]"
        table.add_row(name, status, desc)

    console.print(table)
    console.print()


def show_command_preview(cmd):
    """Show command preview and ask for confirmation. Returns True if confirmed."""
    console.print(Panel(
        f"[bold yellow]{cmd}[/bold yellow]",
        title="[bold]Command to execute[/bold]",
        border_style="yellow",
    ))
    return Confirm.ask("[bold]Run this command?[/bold]", default=True)


def success(msg):
    console.print(f"[bold {get_color('primary')}][+][/bold {get_color('primary')}] {msg}")

def error(msg):
    console.print(f"[bold {get_color('alert')}][-][/bold {get_color('alert')}] {msg}")

def warning(msg):
    console.print(f"[bold {get_color('warn')}][!][/bold {get_color('warn')}] {msg}")

def info(msg):
    console.print(f"[bold {get_color('info')}][*][/bold {get_color('info')}] {msg}")

def ask(prompt, default=None):
    if default:
        return Prompt.ask(f"[bold {get_color('primary')}]{prompt}[/bold {get_color('primary')}]", default=default)
    return Prompt.ask(f"[bold {get_color('primary')}]{prompt}[/bold {get_color('primary')}]")


def confirm(prompt, default=True):
    return Confirm.ask(f"[bold]{prompt}[/bold]", default=default)


def show_results_panel(title, content):
    console.print(Panel(content, title=f"[bold green]{title}[/bold green]", border_style="green"))


def show_knowledge(title, text):
    console.print(Panel(
        Markdown(text),
        title=f"[bold cyan]{title}[/bold cyan]",
        border_style="cyan",
    ))
