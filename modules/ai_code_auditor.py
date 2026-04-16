"""AI Code Auditor — Feed source code to local LLM for vulnerability analysis.

Uses Ollama to analyze code for SQLi, XSS, buffer overflows, auth bypass, etc.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel)
from executor import run_command

AUDIT_PROMPTS = {
    "general": """You are a senior application security auditor. Analyze this source code for security vulnerabilities.

For each vulnerability found, report:
1. Type (e.g., SQLi, XSS, IDOR, Buffer Overflow, Auth Bypass)
2. Severity (Critical/High/Medium/Low)
3. Location (function name, line description)
4. Description of the vulnerability
5. Exploitation scenario
6. Remediation recommendation
7. CWE ID if applicable

Be thorough. Check for: SQL injection, XSS, CSRF, SSRF, path traversal, command injection,
insecure deserialization, hardcoded secrets, weak crypto, race conditions, integer overflow,
buffer overflow, use-after-free, null pointer dereference, auth bypass, IDOR.

SOURCE CODE:
""",
    "web": """You are a web application security expert. Analyze this code for OWASP Top 10 vulnerabilities.
Focus on: SQL injection, XSS (reflected/stored/DOM), CSRF, insecure direct object references,
security misconfigurations, sensitive data exposure, broken authentication, broken access control,
insecure deserialization, insufficient logging.

SOURCE CODE:
""",
    "binary": """You are a binary exploitation expert. Analyze this C/C++ code for memory safety vulnerabilities.
Focus on: buffer overflows, use-after-free, double free, integer overflow/underflow, format string bugs,
null pointer dereference, heap corruption, stack smashing, race conditions, uninitialized variables.

SOURCE CODE:
""",
    "api": """You are an API security expert. Analyze this code for API-specific vulnerabilities.
Focus on: broken authentication, broken authorization, excessive data exposure, lack of rate limiting,
BOLA/IDOR, mass assignment, SSRF, injection, improper asset management, insufficient logging.

SOURCE CODE:
""",
}


def _ollama_analyze(code, prompt_type="general", model="llama3.2"):
    """Send code to Ollama for analysis."""
    import subprocess, shutil
    if not shutil.which("ollama"):
        error("Ollama not installed. Install: curl -fsSL https://ollama.ai/install.sh | sh")
        return None

    prompt = AUDIT_PROMPTS.get(prompt_type, AUDIT_PROMPTS["general"]) + code

    try:
        process = subprocess.Popen(
            ["ollama", "run", model],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        stdout, stderr = process.communicate(input=prompt, timeout=180)
        return stdout.strip() if stdout else "No response from model."
    except subprocess.TimeoutExpired:
        process.kill()
        return "Analysis timed out. Try with less code or a faster model."
    except Exception as e:
        return f"Error: {e}"


def _scan_file(filepath, session, audit_type="general"):
    """Scan a single file."""
    if not os.path.exists(filepath):
        error(f"File not found: {filepath}")
        return

    with open(filepath, 'r', errors='replace') as f:
        code = f.read()

    if len(code) > 10000:
        warning(f"File is large ({len(code)} chars). Truncating to 10000 chars.")
        code = code[:10000]

    info(f"Analyzing {filepath} ({len(code)} chars)...")
    result = _ollama_analyze(code, audit_type)

    if result:
        console.print(f"\n[bold green]AI Security Audit — {os.path.basename(filepath)}:[/bold green]\n")
        console.print(result)

        if session and confirm("\nSave this audit as a finding?", default=False):
            from session import save_finding
            save_finding(session, "code_audit", f"Code audit: {os.path.basename(filepath)}",
                         "medium", result[:2000])


def _scan_directory(dirpath, session, audit_type="general"):
    """Scan all source files in directory."""
    extensions = {'.py', '.js', '.ts', '.php', '.rb', '.go', '.java', '.c', '.cpp',
                  '.cs', '.rs', '.swift', '.kt', '.scala', '.sh', '.pl'}

    files = []
    for root, dirs, filenames in os.walk(dirpath):
        dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', 'vendor', '.venv', 'venv'}]
        for f in filenames:
            if any(f.endswith(ext) for ext in extensions):
                files.append(os.path.join(root, f))

    if not files:
        warning("No source files found.")
        return

    console.print(f"\n[bold]Found {len(files)} source files[/bold]\n")
    max_files = int(ask("Max files to scan", default="5"))

    for filepath in files[:max_files]:
        _scan_file(filepath, session, audit_type)
        console.print("\n" + "─" * 60 + "\n")


def _paste_and_audit(session, audit_type="general"):
    """Paste code and get AI audit."""
    console.print("\n[bold cyan]Paste Code to Audit[/bold cyan]")
    console.print("[dim]Paste your code, then enter a blank line to finish:[/dim]\n")

    lines = []
    while True:
        try:
            line = input()
            if line == "":
                break
            lines.append(line)
        except EOFError:
            break

    if not lines:
        warning("No code provided.")
        return

    code = "\n".join(lines)
    info(f"Analyzing {len(lines)} lines of code...")
    result = _ollama_analyze(code, audit_type)
    if result:
        console.print(f"\n[bold green]AI Security Audit:[/bold green]\n")
        console.print(result)


# ─── Quick Pattern Scanner (No AI needed) ────────────────────────────────────

VULN_PATTERNS = {
    "SQL Injection": [
        r'execute\s*\(.*%s', r'cursor\.execute\s*\(.*\+', r'cursor\.execute\s*\(.*format',
        r'query\s*=.*\+.*request', r'\$_GET\[.*\]\s*\.', r'\"SELECT.*\"\s*\+',
    ],
    "Command Injection": [
        r'os\.system\s*\(', r'subprocess\.call\s*\(.*shell\s*=\s*True',
        r'eval\s*\(', r'exec\s*\(', r'popen\s*\(',
        r'Runtime\.getRuntime\(\)\.exec', r'child_process\.exec',
    ],
    "XSS": [
        r'innerHTML\s*=', r'document\.write\s*\(', r'\.html\s*\(',
        r'v-html\s*=', r'dangerouslySetInnerHTML',
    ],
    "Hardcoded Secrets": [
        r'password\s*=\s*["\'][^"\']+["\']', r'secret\s*=\s*["\'][^"\']+["\']',
        r'api_key\s*=\s*["\'][^"\']+["\']', r'token\s*=\s*["\'][^"\']+["\']',
        r'AKIA[0-9A-Z]{16}',
    ],
    "Path Traversal": [
        r'open\s*\(.*request', r'readFile\s*\(.*req\.',
        r'include\s*\(\s*\$_', r'file_get_contents\s*\(\s*\$_',
    ],
    "Weak Crypto": [
        r'md5\s*\(', r'sha1\s*\(', r'DES\b', r'RC4\b',
        r'random\.random\s*\(', r'Math\.random\s*\(',
    ],
}


def _quick_scan(filepath, session):
    """Quick regex-based vulnerability scan without AI."""
    if not os.path.exists(filepath):
        error(f"File not found: {filepath}")
        return

    with open(filepath, 'r', errors='replace') as f:
        lines = f.readlines()

    console.print(f"\n[bold cyan]Quick Pattern Scan: {filepath}[/bold cyan]\n")
    findings = 0

    for vuln_type, patterns in VULN_PATTERNS.items():
        for pattern in patterns:
            import re
            for i, line in enumerate(lines):
                if re.search(pattern, line, re.IGNORECASE):
                    console.print(f"  [red][{vuln_type}][/red] Line {i+1}: {line.strip()[:100]}")
                    findings += 1

    if findings == 0:
        success("No obvious patterns found (AI analysis may find more)")
    else:
        warning(f"Found {findings} potential issues")


def run(session):
    show_stage_header("AI Code Auditor", "AI-powered source code security analysis")

    while True:
        options = [
            ("", "[bold white]── AI AUDIT (Ollama) ──[/bold white]"),
            ("1", "[bold]Audit File[/bold] — AI analyzes a source file"),
            ("2", "[bold]Audit Directory[/bold] — AI scans all source files"),
            ("3", "[bold]Paste & Audit[/bold] — Paste code for AI review"),
            ("", "[bold white]── QUICK SCAN (No AI) ──[/bold white]"),
            ("4", "[bold]Pattern Scan[/bold] — Regex-based vuln detection"),
            ("", "[bold white]── AUDIT TYPE ──[/bold white]"),
            ("5", "Web App Audit"),
            ("6", "Binary/C/C++ Audit"),
            ("7", "API Security Audit"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            filepath = ask("File path")
            _scan_file(filepath, session)
        elif choice == "2":
            dirpath = ask("Directory path")
            _scan_directory(dirpath, session)
        elif choice == "3":
            _paste_and_audit(session)
        elif choice == "4":
            filepath = ask("File path")
            _quick_scan(filepath, session)
        elif choice == "5":
            filepath = ask("File path")
            _scan_file(filepath, session, "web")
        elif choice == "6":
            filepath = ask("File path")
            _scan_file(filepath, session, "binary")
        elif choice == "7":
            filepath = ask("File path")
            _scan_file(filepath, session, "api")
