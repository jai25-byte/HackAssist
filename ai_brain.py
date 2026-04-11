"""AI Brain — Local LLM integration via Ollama for intelligent decision-making.

Uses Ollama (local LLM) to analyze scan results, suggest next steps,
interpret output, and provide context-aware guidance. Fully offline, no API keys.
"""

import sys
import os
import json
import shutil
import subprocess
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel)
from executor import run_command, run_with_preview

# ─── Ollama Interface ─────────────────────────────────────────────────────────

OLLAMA_MODELS = [
    ("llama3.2", "Fast, 3B params — good for quick analysis"),
    ("llama3.1", "Strong 8B model — great balance of speed and quality"),
    ("mistral", "7B model — excellent at code and security analysis"),
    ("codellama", "Specialized for code — great for exploit analysis"),
    ("phi3", "Microsoft's 3.8B — fast and capable"),
]

SYSTEM_PROMPT = """You are HackAssist AI — an expert penetration testing assistant.
You analyze scan results, suggest attack vectors, explain vulnerabilities,
and guide the user through exploitation steps. You are direct, technical,
and provide actionable commands. Always note when actions require authorization.
Format your responses with clear sections and bullet points."""

# Venice.ai / CAI style - unrestricted security research personas
AI_PERSONAS = {
    'HackAssist': {
        'name': 'HackAssist AI',
        'desc': 'Default pentesting assistant — technical, direct, actionable',
        'system': SYSTEM_PROMPT,
    },
    'RedTeam': {
        'name': 'RedTeam Operator',
        'desc': 'Offensive security specialist — thinks like an attacker',
        'system': """You are an elite Red Team operator. You think like an advanced adversary.
You provide detailed attack chains, evasion techniques, and creative exploitation paths.
You explain TTPs (Tactics, Techniques, Procedures) mapped to MITRE ATT&CK.
Be specific with commands, payloads, and tooling. This is for authorized security testing only.""",
    },
    'BugHunter': {
        'name': 'Bug Bounty Hunter',
        'desc': 'Bug bounty specialist — finds vulns in web apps',
        'system': """You are a top-ranked bug bounty hunter. You specialize in finding
vulnerabilities in web applications, APIs, and mobile apps. You know every OWASP category,
creative bypass techniques, and how to chain low-severity bugs into critical findings.
Provide specific payloads, test cases, and PoC steps. Focus on impact and reproducibility.""",
    },
    'Forensics': {
        'name': 'Digital Forensics Expert',
        'desc': 'DFIR specialist — incident response & forensics',
        'system': """You are a senior digital forensics and incident response (DFIR) expert.
You analyze artifacts, identify indicators of compromise, reconstruct attack timelines,
and preserve evidence chain of custody. Provide specific forensic commands and tool usage.
Think methodically and document everything.""",
    },
    'Malware': {
        'name': 'Malware Researcher',
        'desc': 'Malware reverse engineering specialist',
        'system': """You are a malware researcher and reverse engineer. You analyze binaries,
identify malware families, explain obfuscation techniques, and provide decompilation guidance.
You know common malware TTPs, C2 protocols, and evasion techniques. Provide specific
analysis steps using tools like Ghidra, IDA, radare2, and dynamic analysis sandboxes.""",
    },
    'Social': {
        'name': 'Social Engineer',
        'desc': 'Social engineering & phishing specialist',
        'system': """You are a social engineering expert for authorized red team engagements.
You design phishing campaigns, pretexting scenarios, and physical security tests.
You understand human psychology, persuasion techniques, and OSINT for target profiling.
All advice is for authorized security assessments only.""",
    },
    'Cloud': {
        'name': 'Cloud Security Architect',
        'desc': 'AWS/Azure/GCP security specialist',
        'system': """You are a cloud security architect specializing in AWS, Azure, and GCP.
You identify cloud misconfigurations, IAM weaknesses, and cloud-native attack paths.
You know serverless exploitation, container escapes, and cloud privilege escalation.
Provide specific CLI commands and API calls for each cloud provider.""",
    },
    'Custom': {
        'name': 'Custom Persona',
        'desc': 'Define your own AI personality',
        'system': None,  # User provides
    },
}


def _ollama_available():
    """Check if Ollama is installed and running."""
    return shutil.which("ollama") is not None


def _ollama_running():
    """Check if Ollama server is running."""
    try:
        result = subprocess.run(
            ["curl", "-s", "http://localhost:11434/api/tags"],
            capture_output=True, text=True, timeout=3
        )
        return result.returncode == 0
    except Exception:
        return False


def _get_installed_models():
    """Get list of installed Ollama models."""
    try:
        result = subprocess.run(
            ["ollama", "list"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            models = []
            for line in result.stdout.strip().split("\n")[1:]:
                if line.strip():
                    name = line.split()[0]
                    models.append(name)
            return models
    except Exception:
        pass
    return []


def _ask_ollama(prompt, model="llama3.2", context=None):
    """Send a prompt to Ollama and stream the response."""
    full_prompt = prompt
    if context:
        full_prompt = f"Context:\n{context}\n\nQuestion: {prompt}"

    try:
        process = subprocess.Popen(
            ["ollama", "run", model],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Send the prompt with system context
        input_text = f"{SYSTEM_PROMPT}\n\n{full_prompt}"
        stdout, stderr = process.communicate(input=input_text, timeout=120)

        return stdout.strip() if stdout else "No response from model."

    except subprocess.TimeoutExpired:
        process.kill()
        return "Model timed out. Try a smaller model or simpler query."
    except Exception as e:
        return f"Error communicating with Ollama: {e}"


# ─── Analysis Functions ──────────────────────────────────────────────────────

def analyze_nmap_output(nmap_output, model="llama3.2"):
    """AI analysis of nmap scan results."""
    prompt = """Analyze this nmap scan output. For each open port:
1. Identify the service and version
2. List known vulnerabilities for that version
3. Suggest specific exploitation techniques
4. Recommend next enumeration steps
5. Rate the overall attack surface (Low/Medium/High/Critical)

Provide specific commands to run next."""

    return _ask_ollama(prompt, model, context=nmap_output)


def analyze_web_response(response_data, model="llama3.2"):
    """AI analysis of web application responses."""
    prompt = """Analyze this web application data:
1. Identify potential vulnerabilities (OWASP Top 10)
2. Look for information disclosure
3. Suggest injection points
4. Recommend specific tools and payloads to test
5. Identify the technology stack"""

    return _ask_ollama(prompt, model, context=response_data)


def suggest_next_steps(findings, model="llama3.2"):
    """AI suggests next steps based on current findings."""
    prompt = """Based on these penetration test findings, suggest the next steps:
1. What are the highest-priority attack vectors?
2. What tools should be used?
3. Provide specific commands to run
4. What quick wins should be tried first?
5. Any lateral movement opportunities?"""

    return _ask_ollama(prompt, model, context=json.dumps(findings, indent=2))


def explain_exploit(exploit_info, model="llama3.2"):
    """AI explains how an exploit works and how to use it."""
    prompt = """Explain this exploit in detail:
1. What vulnerability does it target?
2. What are the prerequisites?
3. Step-by-step exploitation guide
4. How to verify successful exploitation
5. Post-exploitation recommendations"""

    return _ask_ollama(prompt, model, context=exploit_info)


def generate_report_summary(session_data, model="llama3.2"):
    """AI generates an executive summary from session data."""
    prompt = """Generate a professional penetration test executive summary:
1. Overall security posture assessment
2. Critical findings summary
3. Risk ratings with business impact
4. Top 5 remediation priorities
5. Strategic recommendations

Write in a professional tone suitable for C-level executives."""

    return _ask_ollama(prompt, model, context=json.dumps(session_data, indent=2))


# ─── Interactive Chat ────────────────────────────────────────────────────────

def _select_persona():
    """Venice.ai/CAI-style persona selection."""
    console.print("\n[bold cyan]═══ SELECT AI PERSONA ═══[/bold cyan]\n")
    from rich.table import Table
    table = Table(border_style="cyan", show_header=True)
    table.add_column("#", width=4, style="bold")
    table.add_column("Persona", style="bold cyan")
    table.add_column("Specialty", style="yellow")

    keys = list(AI_PERSONAS.keys())
    for i, key in enumerate(keys, 1):
        p = AI_PERSONAS[key]
        table.add_row(str(i), p['name'], p['desc'])
    console.print(table)

    choice = ask("Select persona #")
    try:
        idx = int(choice) - 1
        key = keys[idx]
        persona = AI_PERSONAS[key]
        if key == 'Custom':
            persona = dict(persona)
            persona['name'] = ask("Persona name") or "Custom AI"
            persona['system'] = ask("System prompt (describe personality)") or SYSTEM_PROMPT
        success(f"Persona: {persona['name']}")
        return persona
    except (ValueError, IndexError):
        return AI_PERSONAS['HackAssist']


def _interactive_chat(model, session, persona=None):
    """Venice.ai/CAI-style free-form chat with AI personas."""
    if not persona:
        persona = AI_PERSONAS['HackAssist']

    console.print(f"\n[bold cyan]═══ {persona['name']} ═══[/bold cyan]")
    console.print(f"[dim]{persona['desc']}[/dim]")
    console.print("[dim]Commands: 'exit' quit | '/persona' switch | '/clear' reset[/dim]")

    # Build context from session
    context = ""
    if session:
        context = f"Target: {session.get('target', 'unknown')}\n"
        context += f"Type: {session.get('type', 'unknown')}\n"
        findings = session.get("findings", [])
        if findings:
            context += f"Findings so far: {json.dumps(findings[:5], indent=2)}\n"
        commands = session.get("commands", [])
        if commands:
            context += f"Recent commands: {json.dumps(commands[-5:], indent=2)}\n"

    if context:
        info(f"Session context loaded ({len(context)} chars)")

    # Override system prompt with persona
    original_prompt = globals().get('SYSTEM_PROMPT')
    chat_system = persona.get('system') or SYSTEM_PROMPT

    while True:
        console.print()
        user_input = ask(f"[bold white]You[/bold white]")
        if not user_input or user_input.lower() in ("exit", "quit", "back", "q"):
            return

        if user_input == '/persona':
            persona = _select_persona()
            chat_system = persona.get('system') or SYSTEM_PROMPT
            console.print(f"[bold cyan]Switched to: {persona['name']}[/bold cyan]")
            continue
        if user_input == '/clear':
            context = ""
            console.print("[dim]Context cleared.[/dim]")
            continue

        info("Thinking...")
        # Use persona system prompt
        full_prompt = f"{chat_system}\n\n"
        if context:
            full_prompt += f"Context:\n{context}\n\n"
        full_prompt += f"User: {user_input}"

        try:
            process = subprocess.Popen(
                ["ollama", "run", model],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, _ = process.communicate(input=full_prompt, timeout=120)
            response = stdout.strip() if stdout else "No response."
        except subprocess.TimeoutExpired:
            process.kill()
            response = "Timed out."
        except Exception as e:
            response = f"Error: {e}"

        console.print(f"\n[bold green]{persona['name']}:[/bold green] {response}")
        context += f"\nUser: {user_input}\n{persona['name']}: {response}\n"


# ─── Paste & Analyze ─────────────────────────────────────────────────────────

def _paste_and_analyze(model, session):
    """Paste tool output and get AI analysis."""
    console.print("\n[bold cyan]Paste & Analyze[/bold cyan]")
    console.print("[dim]Paste output from any tool and get AI analysis.[/dim]")
    console.print("[dim]Enter a blank line to finish pasting.[/dim]\n")

    lines = []
    info("Paste your output (blank line to finish):")
    while True:
        try:
            line = input()
            if line == "":
                break
            lines.append(line)
        except EOFError:
            break

    if not lines:
        warning("No input provided.")
        return

    output = "\n".join(lines)
    info(f"Analyzing {len(lines)} lines of output...")

    # Auto-detect tool type
    tool_type = "unknown"
    if "Nmap scan report" in output or "/tcp" in output:
        tool_type = "nmap"
    elif "OSVDB" in output or "nikto" in output.lower():
        tool_type = "nikto"
    elif "Status:" in output and ("/" in output):
        tool_type = "gobuster/ffuf"
    elif "sqlmap" in output.lower() or "injection" in output.lower():
        tool_type = "sqlmap"

    info(f"Detected tool: {tool_type}")

    prompt = f"""Analyze this {tool_type} output from a penetration test.
Provide:
1. Summary of key findings
2. Vulnerabilities identified
3. Severity assessment
4. Recommended next steps with specific commands
5. Any interesting patterns or anomalies"""

    response = _ask_ollama(prompt, model, context=output)
    console.print(f"\n[bold green]AI Analysis:[/bold green]\n{response}")

    # Offer to save finding
    if session and confirm("\nSave this analysis as a finding?", default=False):
        from session import save_finding
        title = ask("Finding title")
        save_finding(session, "ai_analysis", title, "medium", response[:500])


# ─── Main Menu ────────────────────────────────────────────────────────────────

def run(session):
    """AI Brain entry point."""
    show_stage_header("AI Brain", "Local LLM-powered intelligent analysis")

    if not _ollama_available():
        error("Ollama is not installed.")
        console.print("\n[bold]Install Ollama:[/bold]")
        console.print("  [white]curl -fsSL https://ollama.ai/install.sh | sh[/white]")
        console.print("  [dim]Or visit: https://ollama.ai[/dim]\n")

        if confirm("Install Ollama now?"):
            run_with_preview("curl -fsSL https://ollama.ai/install.sh | sh", session, "ai")
        else:
            return

    if not _ollama_running():
        warning("Ollama server is not running.")
        if confirm("Start Ollama?"):
            run_command("ollama serve &", timeout=5)
            import time
            time.sleep(2)

    # Check/select model
    installed = _get_installed_models()
    if not installed:
        info("No models installed. Let's pull one.")
        console.print("\n[bold]Available models:[/bold]")
        for name, desc in OLLAMA_MODELS:
            console.print(f"  [yellow]{name}[/yellow] — {desc}")
        model_name = ask("Model to pull", default="llama3.2")
        info(f"Pulling {model_name}... (this may take a few minutes)")
        run_command(f"ollama pull {model_name}", timeout=600)
        installed = [model_name]

    # Select model
    if len(installed) == 1:
        model = installed[0]
    else:
        console.print("\n[bold]Installed models:[/bold]")
        model_options = [(str(i+1), m) for i, m in enumerate(installed)]
        model_options.append(("0", "Back"))
        choice = show_menu(model_options)
        if choice == "0":
            return
        model = installed[int(choice) - 1]

    success(f"Using model: {model}")

    active_persona = AI_PERSONAS['HackAssist']

    while True:
        console.print()
        console.print(f"[dim]Model: {model} | Persona: {active_persona['name']}[/dim]")
        options = [
            ("1", "[bold cyan]AI Chat[/bold cyan] (Venice.ai/CAI-style with personas)"),
            ("2", "Paste & Analyze (paste tool output for AI analysis)"),
            ("3", "Analyze Session Findings"),
            ("4", "Generate AI Report Summary"),
            ("5", "Suggest Next Steps"),
            ("6", "Explain an Exploit"),
            ("7", "[bold]Switch Persona[/bold] (RedTeam/BugHunter/Forensics/...)"),
            ("8", "Switch Model"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _interactive_chat(model, session, active_persona)
        elif choice == "2":
            _paste_and_analyze(model, session)
        elif choice == "3":
            if session and session.get("findings"):
                info("Analyzing session findings...")
                response = suggest_next_steps(session["findings"], model)
                console.print(f"\n[bold green]AI Analysis:[/bold green]\n{response}")
            else:
                warning("No findings in current session.")
        elif choice == "4":
            if session:
                info("Generating executive summary...")
                response = generate_report_summary(session, model)
                console.print(f"\n[bold green]Executive Summary:[/bold green]\n{response}")
            else:
                warning("No active session.")
        elif choice == "5":
            question = ask("Describe your current situation")
            response = _ask_ollama(
                f"I'm doing a pentest. {question}. What should I do next? Give specific commands.",
                model
            )
            console.print(f"\n[bold green]AI:[/bold green]\n{response}")
        elif choice == "6":
            exploit = ask("Describe the exploit or paste exploit info")
            info("Analyzing exploit...")
            response = explain_exploit(exploit, model)
            console.print(f"\n[bold green]AI:[/bold green]\n{response}")
        elif choice == "7":
            active_persona = _select_persona()
        elif choice == "8":
            installed = _get_installed_models()
            if installed:
                model_options = [(str(i+1), m) for i, m in enumerate(installed)]
                choice = show_menu(model_options)
                model = installed[int(choice) - 1]
                success(f"Switched to: {model}")
