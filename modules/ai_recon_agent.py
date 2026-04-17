"""AI Recon Agent - Autonomous OSINT & network recon agent.

Uses local LLM to reason about targets, suggest recon steps, and interpret findings.
"""

import sys, os, subprocess
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm)
from executor import run_command
from session import save_finding

RECON_SYSTEM_PROMPT = """You are an elite, autonomous Reconnaissance Agent.
You are helping a penetration tester map a target's external footprint and network.
When given a target (domain, IP, or organization), generate a structured plan
to gather intelligence. When given raw data (whois, nmap, subdomains), analyze
it and suggest the most critical weak points or next steps.

Output formats:
If planning: Provide a 3-step prioritized plan.
If analyzing data: Highlight interesting ports, names, or misconfigurations,
and suggest an exact command to run next.
"""

def _ask_agent(prompt, model="llama3.2"):
    """Consult the local LLM for recon advice."""
    if not __import__("shutil").which("ollama"):
        return "Ollama not installed. Please install it first."
    
    full_prompt = f"{RECON_SYSTEM_PROMPT}\n\nUser Input: {prompt}"
    
    try:
        console.print("[dim]Agent is thinking...[/dim]")
        process = subprocess.Popen(
            ["ollama", "run", model],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        stdout, _ = process.communicate(input=full_prompt, timeout=120)
        return stdout.strip() if stdout else "No response from agent."
    except subprocess.TimeoutExpired:
        process.kill()
        return "Agent timed out."
    except Exception as e:
        return f"Agent error: {e}"

def _interactive_recon_session(session):
    console.print("\n[bold cyan]AI Recon Agent - Interactive Shell[/bold cyan]")
    console.print("Type your target or raw data. The agent will analyze it. Type 'exit' to quit.\n")
    
    while True:
        try:
            user_input = input("\n[ReconAgent]> ").strip()
            if not user_input:
                continue
            if user_input.lower() in ('exit', 'quit'):
                break
            
            response = _ask_agent(user_input)
            console.print(f"\n[bold green]Agent Response:[/bold green]\n{response}\n")
            
            if session and confirm("Save this analysis to session?", default=False):
                save_finding(session, "recon_agent", f"Analysis: {user_input[:50]}...", "info", response)
        except EOFError:
            break

def _autonomous_recon(session):
    target = ask("Enter target domain/IP for autonomous recon")
    if not target:
        return
        
    console.print(f"\n[bold cyan]Initiating Autonomous Recon on {target}...[/bold cyan]")
    
    plan = _ask_agent(f"Create a recon plan for {target}.")
    console.print(f"\n[bold green]Initial Plan:[/bold green]\n{plan}\n")
    
    if confirm("Run Nmap and Subdomain discovery, and feed back to agent?"):
        info("Running basic nmap...")
        code, nmap_out, _ = run_command(f"nmap -F {target}", timeout=30)
        info("Running basic whois...")
        code, whois_out, _ = run_command(f"whois {target} | head -20", timeout=15)
        
        combined_data = f"Nmap results:\n{nmap_out}\n\nWhois results:\n{whois_out}"
        console.print(f"\n[bold cyan]Feeding data to agent...[/bold cyan]")
        
        analysis = _ask_agent(f"Analyze this recon data for {target}:\n\n{combined_data}")
        console.print(f"\n[bold green]Agent Analysis:[/bold green]\n{analysis}\n")
        
        if session:
             save_finding(session, "recon_agent", f"Auto Recon Analysis: {target}", "medium", analysis)

def run(session):
    show_stage_header("AI Recon Agent", "Autonomous LLM-driven intelligence gathering")
    
    while True:
        options = [
            ("1", "Interactive Recon Agent (Chat)"),
            ("2", "Autonomous Target Recon (Auto-gather & Analyze)"),
            ("0", "Back"),
        ]
        choice = show_menu(options)
        
        if choice == "0":
            return
        elif choice == "1":
            _interactive_recon_session(session)
        elif choice == "2":
            _autonomous_recon(session)
