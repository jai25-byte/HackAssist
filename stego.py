#!/usr/bin/env python3
"""HackAssist - Steganography Module."""

from ui import console, show_menu, ask, info, success, warning, error
from executor import run_with_preview, run_command


STEGO_TOOLS = {
    'steghide': {
        'embed': 'steghide embed -cf {cover} -ef {secret} -sf {output} -p {password}',
        'extract': 'steghide extract -sf {file} -p {password}',
        'info': 'steghide info {file}',
    },
    'exiftool': {
        'read': 'exiftool {file}',
        'comment': 'exiftool -Comment="{message}" {file}',
        'strip': 'exiftool -all= {file}',
    },
    'binwalk': {
        'analyze': 'binwalk {file}',
        'extract': 'binwalk -e {file}',
        'entropy': 'binwalk -E {file}',
    },
    'strings': {
        'extract': 'strings {file}',
        'unicode': 'strings -el {file}',
        'min_length': 'strings -n {length} {file}',
    },
    'zsteg': {
        'analyze': 'zsteg {file}',
        'all': 'zsteg -a {file}',
    },
    'foremost': {
        'carve': 'foremost -i {file} -o {output_dir}',
    },
}

CTF_CHECKLIST = [
    "1. Check file type: file <image>",
    "2. Check metadata: exiftool <image>",
    "3. Check strings: strings <image>",
    "4. Check hex: xxd <image> | head -50",
    "5. Binwalk analysis: binwalk <image>",
    "6. Binwalk extract: binwalk -e <image>",
    "7. Steghide extract: steghide extract -sf <image>",
    "8. zsteg (PNG/BMP): zsteg <image>",
    "9. Check LSB: stegsolve or zsteg",
    "10. Foremost carve: foremost -i <image>",
    "11. Check for ZIP in image: unzip <image>",
    "12. Check entropy: binwalk -E <image>",
    "13. Pngcheck: pngcheck -v <image>",
    "14. Audio stego: sonic-visualiser, audacity spectogram",
]


def _steghide_menu(session):
    options = [
        ("1", "Embed secret in image"),
        ("2", "Extract hidden data"),
        ("3", "File info"),
        ("0", "Back"),
    ]
    choice = show_menu(options)
    if choice == "0":
        return

    if choice == "1":
        cover = ask("Cover file (image)")
        secret = ask("Secret file to hide")
        output = ask("Output file") or cover
        password = ask("Password") or ""
        cmd = STEGO_TOOLS['steghide']['embed'].format(cover=cover, secret=secret, output=output, password=password)
        run_with_preview(cmd, session=session, stage="stego")
    elif choice == "2":
        file = ask("Stego file")
        password = ask("Password (empty for none)") or ""
        cmd = STEGO_TOOLS['steghide']['extract'].format(file=file, password=password)
        run_with_preview(cmd, session=session, stage="stego")
    elif choice == "3":
        file = ask("File to analyze")
        cmd = STEGO_TOOLS['steghide']['info'].format(file=file)
        run_with_preview(cmd, session=session, stage="stego")


def _analyze_file(session):
    file = ask("File to analyze")
    if not file:
        return

    console.print("\n[bold cyan]Running analysis tools...[/bold cyan]\n")
    cmds = [
        ('File type', f'file {file}'),
        ('Exiftool', f'exiftool {file}'),
        ('Strings (first 50)', f'strings {file} | head -50'),
        ('Binwalk', f'binwalk {file}'),
        ('Hex dump (first 100 bytes)', f'xxd {file} | head -10'),
    ]
    for name, cmd in cmds:
        console.print(f"\n[bold]{name}:[/bold]")
        output = run_command(cmd, capture=True, timeout=30)
        if output:
            console.print(output[:1000])


def _ctf_checklist():
    from rich.panel import Panel
    content = "\n".join(f"[cyan]{item}[/cyan]" for item in CTF_CHECKLIST)
    console.print(Panel(content, title="Stego CTF Checklist", border_style="green"))


def _lsb_encode():
    info("LSB (Least Significant Bit) Encoding")
    info("For Python-based LSB steganography, install: pip3 install stegano")
    console.print("""
[cyan]# Hide message in image:
from stegano import lsb
secret = lsb.hide("input.png", "secret message")
secret.save("output.png")

# Reveal message:
from stegano import lsb
message = lsb.reveal("output.png")
print(message)[/cyan]
""")


def run(session):
    """Steganography module entry point."""
    while True:
        console.print("\n[bold green]STEGANOGRAPHY[/bold green]\n")
        options = [
            ("1", "Steghide (Embed/Extract)"),
            ("2", "Analyze File (Multi-tool)"),
            ("3", "CTF Stego Checklist"),
            ("4", "LSB Encoding Guide"),
            ("0", "Back to Main Menu"),
        ]
        choice = show_menu(options)

        if choice == "0":
            break
        elif choice == "1":
            _steghide_menu(session)
        elif choice == "2":
            _analyze_file(session)
        elif choice == "3":
            _ctf_checklist()
        elif choice == "4":
            _lsb_encode()
