"""Tool registry, installation checker, and installer."""

import shutil
import os
from ui import (console, show_menu, show_tool_status, show_stage_header,
                info, success, error, warning, confirm)
from executor import run_command

TOOLS = {
    # === Recon ===
    "whois": {
        "check": "whois",
        "install": None,
        "category": "recon",
        "description": "Domain/IP registration lookup (built-in)",
    },
    "subfinder": {
        "check": "subfinder",
        "install": "brew install subfinder",
        "category": "recon",
        "description": "Fast subdomain discovery tool",
    },
    "amass": {
        "check": "amass",
        "install": "brew install amass",
        "category": "recon",
        "description": "In-depth attack surface mapping",
    },
    "theHarvester": {
        "check": "theHarvester",
        "install": "pip3 install theHarvester",
        "category": "recon",
        "description": "Email, subdomain & name harvester",
    },
    "shodan": {
        "check": "shodan",
        "install": "pip3 install shodan",
        "category": "recon",
        "description": "Shodan CLI for internet device search",
    },
    # === Scanning ===
    "nmap": {
        "check": "nmap",
        "install": "brew install nmap",
        "category": "scanning",
        "description": "Network port scanner & service detector",
    },
    "masscan": {
        "check": "masscan",
        "install": "brew install masscan",
        "category": "scanning",
        "description": "Fastest Internet port scanner",
    },
    "rustscan": {
        "check": "rustscan",
        "install": "brew install rustscan",
        "category": "scanning",
        "description": "Fast port scanner that feeds into nmap",
    },
    # === Web ===
    "nikto": {
        "check": "nikto",
        "install": "brew install nikto",
        "category": "web",
        "description": "Web server vulnerability scanner",
    },
    "gobuster": {
        "check": "gobuster",
        "install": "brew install gobuster",
        "category": "web",
        "description": "Directory/file & DNS busting tool",
    },
    "ffuf": {
        "check": "ffuf",
        "install": "brew install ffuf",
        "category": "web",
        "description": "Fast web fuzzer",
    },
    "sqlmap": {
        "check": "sqlmap",
        "install": "brew install sqlmap",
        "category": "web",
        "description": "Automatic SQL injection tool",
    },
    "wfuzz": {
        "check": "wfuzz",
        "install": "pip3 install wfuzz",
        "category": "web",
        "description": "Web application fuzzer",
    },
    # === Exploitation ===
    "msfconsole": {
        "check": "msfconsole",
        "install": "brew install metasploit",
        "category": "exploitation",
        "description": "Metasploit Framework console",
    },
    "searchsploit": {
        "check": "searchsploit",
        "install": "brew install exploitdb",
        "category": "exploitation",
        "description": "Exploit-DB offline search tool",
    },
    "hydra": {
        "check": "hydra",
        "install": "brew install hydra",
        "category": "exploitation",
        "description": "Online password brute-force tool",
    },
    "john": {
        "check": "john",
        "install": "brew install john",
        "category": "exploitation",
        "description": "John the Ripper password cracker",
    },
    "hashcat": {
        "check": "hashcat",
        "install": "brew install hashcat",
        "category": "exploitation",
        "description": "Advanced GPU password cracker",
    },
    # === Network ===
    "wireshark": {
        "check": "wireshark",
        "install": "brew install --cask wireshark",
        "category": "network",
        "description": "Network protocol analyzer (GUI)",
    },
    "tcpdump": {
        "check": "tcpdump",
        "install": None,
        "category": "network",
        "description": "Command-line packet analyzer (built-in)",
    },
    "netcat": {
        "check": "nc",
        "install": "brew install netcat",
        "category": "network",
        "description": "TCP/UDP networking utility",
    },
    "aircrack-ng": {
        "check": "aircrack-ng",
        "install": "brew install aircrack-ng",
        "category": "network",
        "description": "Wi-Fi security auditing tools",
    },
    # === Post-Exploitation ===
    "linpeas": {
        "check": None,
        "path": os.path.expanduser("~/tools/PEASS-ng/linPEAS/linpeas.sh"),
        "install": "git clone https://github.com/peass-ng/PEASS-ng.git " + os.path.expanduser("~/tools/PEASS-ng"),
        "category": "post-exploitation",
        "description": "Linux privilege escalation checker",
    },
    "winpeas": {
        "check": None,
        "path": os.path.expanduser("~/tools/PEASS-ng/winPEAS"),
        "install": "git clone https://github.com/peass-ng/PEASS-ng.git " + os.path.expanduser("~/tools/PEASS-ng"),
        "category": "post-exploitation",
        "description": "Windows privilege escalation checker",
    },
    "pspy": {
        "check": None,
        "path": os.path.expanduser("~/tools/pspy"),
        "install": "git clone https://github.com/DominicBreuker/pspy.git " + os.path.expanduser("~/tools/pspy"),
        "category": "post-exploitation",
        "description": "Unprivileged Linux process snooping",
    },
    # === Utilities ===
    "curl": {
        "check": "curl",
        "install": None,
        "category": "utilities",
        "description": "URL transfer tool (built-in)",
    },
    "wget": {
        "check": "wget",
        "install": "brew install wget",
        "category": "utilities",
        "description": "Non-interactive network downloader",
    },
    "jq": {
        "check": "jq",
        "install": "brew install jq",
        "category": "utilities",
        "description": "Command-line JSON processor",
    },
    "git": {
        "check": "git",
        "install": None,
        "category": "utilities",
        "description": "Version control system (built-in)",
    },
}


def check_tool(name):
    """Check if a tool is installed."""
    tool = TOOLS.get(name)
    if not tool:
        return False

    if tool.get("check"):
        return shutil.which(tool["check"]) is not None
    elif tool.get("path"):
        return os.path.exists(tool["path"])
    return False


def check_all():
    """Check all tools, returns dict of {name: bool}."""
    return {name: check_tool(name) for name in TOOLS}


def check_category(category):
    """Check tools in a specific category."""
    return {
        name: check_tool(name)
        for name, info in TOOLS.items()
        if info["category"] == category
    }


def get_tool_status_display(tools_filter=None):
    """Get tool status for display. Returns dict for show_tool_status()."""
    if tools_filter:
        names = tools_filter
    else:
        names = TOOLS.keys()

    return {
        name: (check_tool(name), TOOLS[name]["description"])
        for name in names
        if name in TOOLS
    }


def install_tool(name):
    """Install a single tool with user confirmation."""
    tool = TOOLS.get(name)
    if not tool:
        error(f"Unknown tool: {name}")
        return False

    if not tool.get("install"):
        info(f"{name} is a built-in tool, no installation needed.")
        return True

    if check_tool(name):
        info(f"{name} is already installed.")
        return True

    info(f"Installing {name}: {tool['description']}")
    if confirm(f"Run: {tool['install']}?"):
        code, stdout, stderr = run_command(tool["install"], timeout=600)
        if code == 0:
            success(f"{name} installed successfully!")
            return True
        else:
            error(f"Failed to install {name}. Check output above.")
            return False
    else:
        warning("Installation skipped.")
        return False


def install_missing_category(category):
    """Install all missing tools in a category."""
    status = check_category(category)
    missing = [name for name, installed in status.items() if not installed]

    if not missing:
        success(f"All {category} tools are already installed!")
        return

    info(f"Missing {category} tools: {', '.join(missing)}")
    if confirm(f"Install all {len(missing)} missing tools?"):
        for name in missing:
            install_tool(name)


def ensure_tool(name):
    """Check if tool is installed, offer to install if not. Returns True if available."""
    if check_tool(name):
        return True

    warning(f"{name} is not installed.")
    tool = TOOLS.get(name)
    if tool and tool.get("install"):
        return install_tool(name)
    return False


def show_manager_menu():
    """Interactive tool manager menu."""
    show_stage_header("Tool Manager", "Check installed tools and install missing ones")

    categories = sorted(set(t["category"] for t in TOOLS.values()))

    while True:
        options = [
            ("1", "View All Tools"),
            ("2", "View by Category"),
            ("3", "Install All Missing Tools"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            show_tool_status(get_tool_status_display())
        elif choice == "2":
            cat_options = [(str(i+1), cat) for i, cat in enumerate(categories)]
            cat_options.append(("0", "Back"))
            console.print("\n[bold]Categories:[/bold]")
            cat_choice = show_menu(cat_options)
            if cat_choice != "0":
                cat = categories[int(cat_choice) - 1]
                tools_in_cat = [n for n, t in TOOLS.items() if t["category"] == cat]
                show_tool_status(get_tool_status_display(tools_in_cat))
                install_missing_category(cat)
        elif choice == "3":
            status = check_all()
            missing = [n for n, installed in status.items() if not installed and TOOLS[n].get("install")]
            if not missing:
                success("All tools are installed!")
            else:
                info(f"Missing tools: {', '.join(missing)}")
                if confirm(f"Install all {len(missing)} missing tools? (This may take a while)"):
                    for name in missing:
                        install_tool(name)
