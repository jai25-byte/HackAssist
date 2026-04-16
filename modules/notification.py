"""Notification System — Desktop/Telegram/Discord alerts.

Send alerts when scans finish, threats detected, or findings discovered.
"""

import sys, os, json, subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm)

CONFIG_FILE = os.path.expanduser("~/hackassist_defense/notification_config.json")


def _load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {"desktop": True, "telegram": {"enabled": False}, "discord": {"enabled": False}}


def _save_config(config):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def notify(title, message, severity="info"):
    """Send notification through all configured channels."""
    config = _load_config()

    # Desktop notification (macOS)
    if config.get("desktop", True):
        try:
            subprocess.run([
                "osascript", "-e",
                f'display notification "{message}" with title "HackAssist: {title}"'
            ], capture_output=True, timeout=5)
        except Exception:
            pass

    # Telegram
    tg = config.get("telegram", {})
    if tg.get("enabled") and tg.get("bot_token") and tg.get("chat_id"):
        try:
            import urllib.request
            url = f"https://api.telegram.org/bot{tg['bot_token']}/sendMessage"
            data = json.dumps({"chat_id": tg["chat_id"],
                               "text": f"🔐 *HackAssist*\n*{title}*\n{message}",
                               "parse_mode": "Markdown"}).encode()
            req = urllib.request.Request(url, data=data,
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10)
        except Exception:
            pass

    # Discord
    dc = config.get("discord", {})
    if dc.get("enabled") and dc.get("webhook_url"):
        try:
            import urllib.request
            colors = {"critical": 16711680, "high": 16744448, "medium": 16776960,
                       "low": 65280, "info": 3447003}
            data = json.dumps({"embeds": [{
                "title": f"HackAssist: {title}",
                "description": message,
                "color": colors.get(severity, 3447003),
            }]}).encode()
            req = urllib.request.Request(dc["webhook_url"], data=data,
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10)
        except Exception:
            pass


def run(session):
    show_stage_header("Notification System", "Desktop, Telegram, and Discord alerts")
    config = _load_config()

    while True:
        desktop = "[green]ON[/green]" if config.get("desktop") else "[red]OFF[/red]"
        tg = "[green]ON[/green]" if config.get("telegram", {}).get("enabled") else "[red]OFF[/red]"
        dc = "[green]ON[/green]" if config.get("discord", {}).get("enabled") else "[red]OFF[/red]"

        console.print(f"  Desktop: {desktop} | Telegram: {tg} | Discord: {dc}\n")

        options = [
            ("1", "Toggle Desktop Notifications"),
            ("2", "Configure Telegram Bot"),
            ("3", "Configure Discord Webhook"),
            ("4", "Send Test Notification"),
            ("0", "Back"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            config["desktop"] = not config.get("desktop", True)
            _save_config(config)
            success(f"Desktop notifications: {'ON' if config['desktop'] else 'OFF'}")
        elif choice == "2":
            token = ask("Telegram bot token (from @BotFather)")
            chat_id = ask("Chat ID (send /start to @userinfobot)")
            config["telegram"] = {"enabled": True, "bot_token": token, "chat_id": chat_id}
            _save_config(config)
            success("Telegram configured")
        elif choice == "3":
            url = ask("Discord webhook URL")
            config["discord"] = {"enabled": True, "webhook_url": url}
            _save_config(config)
            success("Discord configured")
        elif choice == "4":
            notify("Test Alert", "This is a test notification from HackAssist!", "info")
            success("Test notification sent!")
