#!/usr/bin/env python3
"""HackAssist - Plugin System for extensible modules."""

import os
import sys
import importlib
import json

from ui import console, show_menu, ask, info, success, warning, error

PLUGIN_DIR = os.path.expanduser("~/hackassist_plugins")
PLUGIN_REGISTRY = os.path.join(PLUGIN_DIR, "registry.json")

PLUGIN_TEMPLATE = '''#!/usr/bin/env python3
"""HackAssist Plugin: {name}
Description: {description}
Author: {author}
"""

from ui import console, show_menu, ask, info, success, error

PLUGIN_INFO = {{
    "name": "{name}",
    "description": "{description}",
    "author": "{author}",
    "version": "1.0.0",
}}

def run(session):
    """Plugin entry point."""
    console.print(f"\\n[bold green]{{PLUGIN_INFO['name']}}[/bold green]")
    console.print(f"[dim]{{PLUGIN_INFO['description']}}[/dim]\\n")

    # Add your plugin logic here
    info("This is a template plugin. Edit to add functionality.")
'''


def _ensure_plugin_dir():
    os.makedirs(PLUGIN_DIR, exist_ok=True)
    if not os.path.exists(PLUGIN_REGISTRY):
        with open(PLUGIN_REGISTRY, 'w') as f:
            json.dump([], f)


def _load_registry():
    _ensure_plugin_dir()
    try:
        with open(PLUGIN_REGISTRY) as f:
            return json.load(f)
    except Exception:
        return []


def _save_registry(registry):
    _ensure_plugin_dir()
    with open(PLUGIN_REGISTRY, 'w') as f:
        json.dump(registry, f, indent=2)


def _list_plugins():
    registry = _load_registry()
    if not registry:
        warning("No plugins installed.")
        return

    from rich.table import Table
    table = Table(title="Installed Plugins", border_style="green")
    table.add_column("#", style="bold", width=4)
    table.add_column("Name", style="cyan")
    table.add_column("Version", style="yellow")
    table.add_column("Author", style="green")
    table.add_column("Status", style="bold")

    for i, p in enumerate(registry, 1):
        status = "[green]Active[/green]" if p.get('active', True) else "[red]Disabled[/red]"
        table.add_row(str(i), p['name'], p.get('version', '?'), p.get('author', '?'), status)
    console.print(table)


def _create_plugin():
    name = ask("Plugin name")
    if not name:
        return
    desc = ask("Description") or "Custom plugin"
    author = ask("Author") or "Unknown"

    filename = name.lower().replace(' ', '_').replace('-', '_') + ".py"
    filepath = os.path.join(PLUGIN_DIR, filename)

    if os.path.exists(filepath):
        error(f"Plugin file already exists: {filepath}")
        return

    with open(filepath, 'w') as f:
        f.write(PLUGIN_TEMPLATE.format(name=name, description=desc, author=author))

    registry = _load_registry()
    registry.append({
        'name': name,
        'file': filename,
        'description': desc,
        'author': author,
        'version': '1.0.0',
        'active': True,
    })
    _save_registry(registry)
    success(f"Plugin created: {filepath}")
    info("Edit the file to add your custom functionality.")


def _run_plugin(session):
    registry = _load_registry()
    active = [p for p in registry if p.get('active', True)]
    if not active:
        warning("No active plugins.")
        return

    options = [(str(i), f"{p['name']} - {p.get('description', '')}") for i, p in enumerate(active, 1)]
    options.append(("0", "Back"))
    choice = show_menu(options)

    if choice == "0":
        return

    try:
        idx = int(choice) - 1
        plugin = active[idx]
    except (ValueError, IndexError):
        return

    filepath = os.path.join(PLUGIN_DIR, plugin['file'])
    if not os.path.exists(filepath):
        error(f"Plugin file not found: {filepath}")
        return

    try:
        spec = importlib.util.spec_from_file_location(plugin['name'], filepath)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if hasattr(mod, 'run'):
            mod.run(session)
        else:
            error("Plugin has no run() function.")
    except Exception as e:
        error(f"Plugin error: {e}")


def _install_from_file():
    filepath = ask("Path to plugin .py file")
    if not filepath or not os.path.exists(filepath):
        error("File not found.")
        return

    _ensure_plugin_dir()
    filename = os.path.basename(filepath)
    dest = os.path.join(PLUGIN_DIR, filename)

    try:
        spec = importlib.util.spec_from_file_location("test_plugin", filepath)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        plugin_info = getattr(mod, 'PLUGIN_INFO', {})
        name = plugin_info.get('name', filename.replace('.py', ''))

        import shutil
        shutil.copy2(filepath, dest)

        registry = _load_registry()
        registry.append({
            'name': name,
            'file': filename,
            'description': plugin_info.get('description', ''),
            'author': plugin_info.get('author', 'Unknown'),
            'version': plugin_info.get('version', '1.0.0'),
            'active': True,
        })
        _save_registry(registry)
        success(f"Plugin installed: {name}")
    except Exception as e:
        error(f"Failed to install plugin: {e}")


def run(session):
    """Plugin system entry point."""
    while True:
        console.print("\n[bold green]PLUGIN SYSTEM[/bold green]\n")
        options = [
            ("1", "List Installed Plugins"),
            ("2", "Run a Plugin"),
            ("3", "Create New Plugin"),
            ("4", "Install Plugin from File"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            break
        elif choice == "1":
            _list_plugins()
        elif choice == "2":
            _run_plugin(session)
        elif choice == "3":
            _create_plugin()
        elif choice == "4":
            _install_from_file()
