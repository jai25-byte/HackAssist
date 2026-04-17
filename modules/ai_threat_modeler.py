"""AI Threat Modeler - Generate STRIDE threat models and attack trees.

Given system architecture, outputs a detailed security analysis.
"""

import sys, os, subprocess
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui import (console, show_stage_header, show_menu, ask, info, success)
from session import save_finding

THREAT_MODEL_PROMPT = """You are a senior Application Security Architect.
Perform a threat model using the STRIDE methodology for the provided system architecture.
Output format:
1. System Overview
2. STRIDE Threat Analysis (Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation of Privilege)
3. Attack Tree for the most critical component
4. Key Mitigations
Be highly technical and specific to cloud and modern stack environments.
"""

def _model_threat(arch_desc, model="llama3.2"):
    if not __import__("shutil").which("ollama"):
        return "Ollama not installed."
        
    full_prompt = f"{THREAT_MODEL_PROMPT}\n\nSystem Architecture:\n{arch_desc}"
    
    try:
        console.print("[dim]Analyzing architecture and building threat model...[/dim]")
        process = subprocess.Popen(
            ["ollama", "run", model],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        stdout, _ = process.communicate(input=full_prompt, timeout=120)
        return stdout.strip() if stdout else "No response."
    except Exception as e:
        return f"Error: {e}"

def run(session):
    show_stage_header("AI Threat Modeler", "Generate STRIDE models and attack trees")
    
    console.print("Describe the system architecture (e.g., 'React frontend talking to Spring Boot API, Postgres DB, Redis cache on AWS'):")
    arch = ask("Architecture description")
    
    if arch:
        model_out = _model_threat(arch)
        console.print(f"\n[bold green]Threat Model:[/bold green]\n\n{model_out}\n")
        
        if session and confirm("Save threat model to session?"):
           save_finding(session, "threat_model", "System Threat Model", "info", model_out)
