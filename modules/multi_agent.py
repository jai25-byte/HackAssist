"""Multi-Agent System - Multiple specialized personas cooperating.

Combines Recon Analyst, Exploit Dev, and Defense Analyst.
"""

import sys, os, subprocess, threading, queue
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui import (console, show_stage_header, show_menu, ask, info, success, warning)

AGENT_PROMPTS = {
    "Recon Specialist": "You are the Recon Specialist. Find external attack surface, subdomains, open ports, and gather OSINT. Provide targets for the Exploit Dev.",
    "Exploit Developer": "You are the Exploit Developer. Read the Recon Specialist's targets and suggest CVEs, misconfigurations, and exploit scripts to gain access.",
    "Defense Analyst": "You are the Defense Analyst. Look at what the Exploit Developer is doing and suggest how Blue Teams would detect it, or how to evade detection.",
}

class AQueueThread(threading.Thread):
    def __init__(self, name, model, prompt, input_queue, out_queue):
        threading.Thread.__init__(self)
        self.name = name
        self.model = model
        self.prompt = prompt
        self.input_queue = input_queue
        self.out_queue = out_queue
        self.running = True

    def run(self):
        while self.running:
            try:
                task = self.input_queue.get(timeout=1)
                if task == "STOP":
                    break
                    
                full_prompt = f"{self.prompt}\n\nCurrent Context/Task:\n{task}"
                proc = subprocess.Popen(
                    ["ollama", "run", self.model],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True,
                )
                stdout, _ = proc.communicate(input=full_prompt, timeout=120)
                self.out_queue.put((self.name, stdout.strip() if stdout else "No thoughts."))
                self.input_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                self.out_queue.put((self.name, f"Error: {e}"))

def _run_multi_agent_session(target):
    console.print(f"\n[bold cyan]Starting Multi-Agent Swarm against {target}[/bold cyan]\n")
    
    queues = {name: queue.Queue() for name in AGENT_PROMPTS}
    out_queue = queue.Queue()
    threads = []
    
    # Start agents
    for name, prompt in AGENT_PROMPTS.items():
        t = AQueueThread(name, "llama3.2", prompt, queues[name], out_queue)
        t.start()
        threads.append((name, t))
        
    info("Swarm initialized. Give the initial Recon Specialist order...")
    
    # Kickoff
    queues["Recon Specialist"].put(f"Target is {target}. Do a theoretical recon pass.")
    
    try:
        # Phase 1: Recon thoughts
        name, recon_result = out_queue.get(timeout=120)
        console.print(f"\n[bold magenta][{name}][/bold magenta]:\n{recon_result}\n")
        
        # Phase 2: Feed recon to exploit dev
        info("Passing intel to Exploit Developer...")
        queues["Exploit Developer"].put(f"Recon data:\n{recon_result}\nPlan the attack.")
        name, exploit_result = out_queue.get(timeout=120)
        console.print(f"\n[bold red][{name}][/bold red]:\n{exploit_result}\n")
        
        # Phase 3: Feed exploit plan to defense analyst
        info("Passing attack plan to Defense Analyst for evasion review...")
        queues["Defense Analyst"].put(f"Attack Plan:\n{exploit_result}\nHow do we evade detection?")
        name, defense_result = out_queue.get(timeout=120)
        console.print(f"\n[bold blue][{name}][/bold blue]:\n{defense_result}\n")
        
    except Exception as e:
        warning(f"Swarm halted: {e}")
    finally:
        for name, t in threads:
            queues[name].put("STOP")
            if t.is_alive():
                queues[name].put("STOP")
        success("Swarm operation completed.")

def run(session):
    show_stage_header("Multi-Agent AI Swarm", "Cooperative AI personas (Recon, Exploit, Defense)")
    
    if not __import__("shutil").which("ollama"):
        error("Ollama is required for multi-agent swarm.")
        return
        
    target = ask("Target domain/IP for Swarm simulation")
    if target:
        _run_multi_agent_session(target)
