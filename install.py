#!/usr/bin/env python3
"""Cross-platform installer for PingMe."""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import stat
import subprocess
import sys
import sysconfig
from pathlib import Path
from typing import NoReturn

APP = "pingme"
SCRIPT = "pingme.py"
MARKER_START = "# >>> pingme completion >>>"
MARKER_END = "# <<< pingme completion <<<"

PING_TOOLS = ["auto", "fping", "ping"]
OUTPUT_FORMATS = ["txt", "csv", "json"]

OPTIONS = [
    "-h", "--help", "--version", "help", "--help-topic", "--help-all",
    "-s", "--sub", "-f", "--file", "--host", "--exclude", "--max-hosts",
    "--scan", "--dns", "--tcp-ports", "--tcp-timeout", "--ipinfo",
    "-t", "--threads", "--timeout", "--count", "--retry", "--rate",
    "--ping-tool", "--fast", "--resume", "--alive-out", "--dead-out", "--error-out",
    "--hostnames-out", "--changes-out", "--out-format", "--label", "--quiet",
    "--no-banner", "--history", "--changes", "--compare", "--diff",
    "--clear-history", "--no-history",
]
HELP_TOPICS = ["targets", "scan", "discovery", "output", "history", "advanced", "examples"]


def color(code: str, text: str) -> str:
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text
    return f"\033[{code}m{text}\033[0m"


def info(message: str) -> None:
    print(f"{color('96', '[*]')} {message}")


def success(message: str) -> None:
    print(f"{color('92', '[+]')} {message}")


def warn(message: str) -> None:
    print(f"{color('93', '[!]')} {message}")


def fail(message: str) -> NoReturn:
    print(f"{color('91', '[x]')} {message}", file=sys.stderr)
    raise SystemExit(1)


def project_script() -> Path:
    path = Path(__file__).resolve().parent / SCRIPT
    if not path.is_file():
        fail(f"{SCRIPT} was not found beside install.py")
    return path


def detect_os() -> str:
    name = platform.system().lower()
    if name == "darwin":
        return "macos"
    if name == "windows":
        return "windows"
    if name == "linux":
        return "linux"
    return name


def detect_shell(system: str, requested: str) -> str:
    if requested != "auto":
        return requested
    if system == "windows":
        return "powershell"
    shell = Path(os.environ.get("SHELL", "")).name.lower()
    if shell in {"zsh", "bash", "fish"}:
        return shell
    return "zsh" if system == "macos" else "bash"


def run(command: list[str]) -> None:
    try:
        subprocess.run(command, check=True)
    except FileNotFoundError:
        fail(f"Required command not found: {command[0]}")
    except subprocess.CalledProcessError as error:
        fail(f"Command failed with exit code {error.returncode}: {' '.join(command)}")


def make_executable(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def install_unix_launcher(source: Path, user_install: bool) -> Path:
    make_executable(source)
    destination = (
        Path.home() / ".local/bin/pingme"
        if user_install
        else Path("/usr/local/bin/pingme")
    )

    if user_install:
        destination.parent.mkdir(parents=True, exist_ok=True)

    absolute_source = source.resolve()

    if destination.exists() or destination.is_symlink():
        try:
            if destination.is_symlink() and destination.resolve() == absolute_source:
                success(f"Launcher already installed: {destination}")
                return destination
        except OSError:
            pass

    if os.access(destination.parent, os.W_OK):
        destination.unlink(missing_ok=True)
        destination.symlink_to(absolute_source)
    else:
        info(f"Administrator permission is required to write {destination}")
        run(["sudo", "ln", "-sfn", str(absolute_source), str(destination)])

    success(f"Installed launcher: {destination} -> {absolute_source}")
    return destination


def windows_scripts_dir() -> Path:
    value = sysconfig.get_path("scripts", scheme="nt_user")
    if value:
        return Path(value)
    return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Programs" / "Python" / "Scripts"


def add_windows_user_path(directory: Path) -> None:
    """Prepend the Python user Scripts directory to the Windows user PATH."""
    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            "Environment",
            0,
            winreg.KEY_READ | winreg.KEY_WRITE,
        )
        try:
            current, value_type = winreg.QueryValueEx(key, "Path")
        except FileNotFoundError:
            current, value_type = "", winreg.REG_EXPAND_SZ

        entries = [entry for entry in current.split(";") if entry]
        target_norm = os.path.normcase(os.path.normpath(str(directory)))
        filtered = [
            entry for entry in entries
            if os.path.normcase(os.path.normpath(os.path.expandvars(entry))) != target_norm
        ]
        updated = ";".join([str(directory), *filtered])
        winreg.SetValueEx(key, "Path", 0, value_type, updated)
        winreg.CloseKey(key)

        os.environ["PATH"] = str(directory) + os.pathsep + os.environ.get("PATH", "")
        success(f"Windows user PATH updated: {directory}")
    except Exception as error:
        warn(f"Could not update Windows PATH automatically: {error}")
        warn(f"Add this directory to PATH manually: {directory}")


def _source_version(source: Path) -> str:
    text = source.read_text(encoding="utf-8", errors="replace")
    match = __import__("re").search(r'^VERSION\s*=\s*["\']([^"\']+)', text, __import__("re").MULTILINE)
    return match.group(1) if match else "unknown"


def install_windows_launcher(source: Path) -> Path:
    """Force-install the exact local PingMe script and verify the installed build."""
    existing_command = shutil.which("pingme.cmd") or shutil.which("pingme")
    destination_dir = windows_scripts_dir()
    destination_dir.mkdir(parents=True, exist_ok=True)

    installed_script = destination_dir / SCRIPT
    launcher = destination_dir / "pingme.cmd"

    # Remove stale wrappers in the destination before replacing them.
    for stale in (destination_dir / "pingme.bat", destination_dir / "pingme.exe"):
        try:
            stale.unlink(missing_ok=True)
        except OSError:
            pass

    shutil.copyfile(source, installed_script)
    launcher.write_text(
        f'@echo off\r\n"{sys.executable}" "{installed_script}" %*\r\n',
        encoding="utf-8",
    )

    # Existing terminals retain their old PATH. Refresh a previously installed
    # PingMe wrapper only after verifying its adjacent script is really ours.
    if existing_command:
        existing_launcher = Path(existing_command)
        existing_script = existing_launcher.with_name(SCRIPT)
        try:
            is_pingme = (
                existing_launcher.resolve() != launcher.resolve()
                and existing_script.is_file()
                and 'APP_NAME = "PingMe"' in existing_script.read_text(encoding="utf-8", errors="replace")
            )
            if is_pingme:
                shutil.copyfile(source, existing_script)
                existing_launcher.write_text(
                    f'@echo off\r\n"{sys.executable}" "{existing_script}" %*\r\n',
                    encoding="utf-8",
                )
                success(f"Refreshed existing launcher: {existing_launcher}")
        except OSError as error:
            warn(f"Could not refresh existing PingMe launcher: {error}")

    add_windows_user_path(destination_dir)

    expected = _source_version(source)
    check = subprocess.run(
        [sys.executable, str(installed_script), "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=20,
        check=False,
    )
    output = check.stdout.strip()
    if check.returncode != 0 or expected not in output:
        fail(f"Installed PingMe verification failed: {output or 'no output'}")

    marker = "FILE SCAN STATUS"
    installed_text = installed_script.read_text(encoding="utf-8", errors="replace")
    if marker not in installed_text:
        fail("Installed script is missing the file hostname/status table feature")

    success(f"Installed launcher: {launcher}")
    success(f"Verified installed build: {output}")
    return launcher


def zsh_completion() -> str:
    ping_tools = " ".join(PING_TOOLS)
    formats = " ".join(OUTPUT_FORMATS)

    return f'''#compdef pingme

_pingme() {{
  _arguments -C \\
    '(-s --sub)'{{-s,--sub}}'[show subnet information]:CIDR:' \\
    '(-f --file)'{{-f,--file}}'[scan targets from file]:target file:_files' \\
    '--host[scan one or more IPs or hostnames]:host or IP: ' \\
    '--diff[compare two snapshot files]:first file:_files:second file:_files' \\
    '--history[list stored scan history]' \\
    '--clear-history[delete history for a label]:label:' \\
    '--ipinfo[classify one or more IP addresses]:IP address: ' \\
    '--scan[run host discovery scan]' \\
    '(-t --threads)'{{-t,--threads}}'[concurrent threads]:threads:' \\
    '--timeout[per-packet timeout in seconds]:seconds:' \\
    '--count[packets per host]:count:' \\
    '--tcp-ports[TCP ports or ranges]:ports:' \\
    '--tcp-timeout[TCP connect timeout]:seconds:' \\
    '--max-hosts[maximum expanded CIDR hosts]:count:' \\
    '--retry[retry attempts for dead hosts]:count:' \\
    '--rate[maximum packets per second]:packets per second:' \\
    '--exclude[exclude IPs or CIDRs]:IP or CIDR: ' \\
    '--dns[perform reverse DNS lookup]' \\
    '--resume[resume interrupted scan]' \\
    '--ping-tool[select ping backend]:backend:({ping_tools})' \\
    '--fast[use fast scan settings]' \\
    '--no-history[do not save scan history]' \\
    '--changes[show simple hostname-aware changes]' \\
    '--compare[legacy IP-only comparison]' \\
    '--quiet[suppress per-host output]' \\
    '--alive-out[alive hosts output file]:file:_files' \\
    '--dead-out[no-response hosts output file]:file:_files' \\
    '--error-out[probe errors output file]:file:_files' \\
    '--hostnames-out[complete hostname status report]:file:_files' \\
    '--changes-out[changes report file]:file:_files' \\
    '--out-format[output format]:format:({formats})' \\
    '--label[custom scan history label]:label:' \\
    '--no-banner[hide ASCII banner]' \\
    '(-h --help)'{{-h,--help}}'[show help]'
}}

_pingme "$@"
'''


def bash_completion() -> str:
    options = " ".join(OPTIONS)
    ping_tools = " ".join(PING_TOOLS)
    formats = " ".join(OUTPUT_FORMATS)

    return f'''_pingme_completion() {{
    local cur prev
    COMPREPLY=()
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"

    case "$prev" in
        --ping-tool)
            COMPREPLY=( $(compgen -W "{ping_tools}" -- "$cur") )
            return
            ;;
        --out-format)
            COMPREPLY=( $(compgen -W "{formats}" -- "$cur") )
            return
            ;;
        -f|--file|--alive-out|--dead-out|--error-out|--hostnames-out|--changes-out)
            COMPREPLY=( $(compgen -f -- "$cur") )
            return
            ;;
        --diff)
            COMPREPLY=( $(compgen -f -- "$cur") )
            return
            ;;
    esac

    COMPREPLY=( $(compgen -W "{options}" -- "$cur") )
}}
complete -F _pingme_completion pingme
'''


def fish_completion() -> str:
    descriptions = {
        "help": "Show help",
        "sub": "Show subnet information",
        "file": "Scan targets from a file",
        "host": "Scan IPs or hostnames",
        "diff": "Compare two snapshot files",
        "history": "List stored scan history",
        "clear-history": "Delete history for a label",
        "ipinfo": "Classify IP addresses",
        "scan": "Run host discovery scan",
        "threads": "Concurrent threads",
        "timeout": "Per-packet timeout",
        "count": "Packets per host",
        "tcp-ports": "TCP ports or ranges",
        "tcp-timeout": "TCP connect timeout",
        "max-hosts": "Maximum CIDR targets",
        "retry": "Retry dead hosts",
        "rate": "Maximum packets per second",
        "exclude": "Exclude IPs or CIDRs",
        "dns": "Reverse DNS lookup",
        "resume": "Resume interrupted scan",
        "ping-tool": "Select ping backend",
        "fast": "Fast scan settings",
        "no-history": "Do not save history",
        "compare": "Compare with previous scan",
        "quiet": "Suppress per-host output",
        "alive-out": "Alive output file",
        "dead-out": "No-response output file",
        "error-out": "Probe error output file",
        "out-format": "Output format",
        "label": "Custom history label",
        "no-banner": "Hide ASCII banner",
    }

    lines = ["complete -c pingme -f"]
    for option in OPTIONS:
        if option.startswith("--"):
            long_name = option[2:]
            description = descriptions.get(long_name, "PingMe option")
            lines.append(f"complete -c pingme -l {long_name} -d '{description}'")
        elif option.startswith("-") and len(option) == 2:
            lines.append(f"complete -c pingme -s {option[1:]}")

    lines.extend(
        [
            f"complete -c pingme -n '__fish_seen_argument -l ping-tool' -a '{' '.join(PING_TOOLS)}'",
            f"complete -c pingme -n '__fish_seen_argument -l out-format' -a '{' '.join(OUTPUT_FORMATS)}'",
            "complete -c pingme -n '__fish_seen_argument -s f -l file -l alive-out -l dead-out -l error-out -l diff' -a '(__fish_complete_path)'",
        ]
    )

    return "\n".join(lines) + "\n"


def powershell_completion() -> str:
    all_words = OPTIONS + PING_TOOLS + OUTPUT_FORMATS + HELP_TOPICS
    words = ",".join(repr(item) for item in all_words)

    return (
        "Register-ArgumentCompleter -Native -CommandName pingme -ScriptBlock {\n"
        "  param($wordToComplete, $commandAst, $cursorPosition)\n"
        f"  @({words}) | Where-Object {{ $_ -like \"$wordToComplete*\" }} | "
        "ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }\n"
        "}\n"
    )


def replace_managed_block(path: Path, content: str) -> None:
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    block = f"{MARKER_START}\n{content.rstrip()}\n{MARKER_END}"

    if MARKER_START in existing and MARKER_END in existing:
        before = existing.split(MARKER_START, 1)[0].rstrip()
        after = existing.split(MARKER_END, 1)[1].lstrip()
        updated = f"{before}\n\n{block}\n"
        if after:
            updated += f"\n{after}"
    else:
        separator = "\n\n" if existing.strip() else ""
        updated = existing.rstrip() + separator + block + "\n"

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(updated, encoding="utf-8")


def install_completion(shell: str, system: str) -> None:
    home = Path.home()

    if shell == "zsh":
        completion_dir = home / ".zsh/completions"
        completion_dir.mkdir(parents=True, exist_ok=True)
        completion_file = completion_dir / "_pingme"
        completion_file.write_text(zsh_completion(), encoding="utf-8")

        replace_managed_block(
            home / ".zshrc",
            "fpath=(~/.zsh/completions $fpath)\nautoload -Uz compinit && compinit",
        )
        success(f"Installed Zsh completion: {completion_file}")

    elif shell == "bash":
        completion_dir = home / ".local/share/bash-completion/completions"
        completion_dir.mkdir(parents=True, exist_ok=True)
        completion_file = completion_dir / "pingme"
        completion_file.write_text(bash_completion(), encoding="utf-8")
        success(f"Installed Bash completion: {completion_file}")

        if system == "macos":
            replace_managed_block(home / ".bash_profile", f"source {completion_file}")

    elif shell == "fish":
        completion_file = home / ".config/fish/completions/pingme.fish"
        completion_file.parent.mkdir(parents=True, exist_ok=True)
        completion_file.write_text(fish_completion(), encoding="utf-8")
        success(f"Installed Fish completion: {completion_file}")

    elif shell == "powershell":
        completion_file = home / "Documents/PowerShell/pingme-completion.ps1"
        completion_file.parent.mkdir(parents=True, exist_ok=True)
        completion_file.write_text(powershell_completion(), encoding="utf-8")

        profile = home / "Documents/PowerShell/Microsoft.PowerShell_profile.ps1"
        replace_managed_block(profile, f'. "{completion_file}"')
        success(f"Installed PowerShell completion: {completion_file}")

    else:
        warn(f"Automatic completion is not available for shell: {shell}")


def dependency_report(system: str) -> None:
    if shutil.which("ping") or shutil.which("ping6"):
        success("System ping detected")
    else:
        warn("System ping was not found in PATH")

    if shutil.which("fping"):
        success("fping detected — PingMe will use it for faster scans")
    else:
        warn("fping was not found. It is optional but recommended for faster scanning.")
        if system == "linux":
            print("    Debian/Kali/Ubuntu: sudo apt install fping")
            print("    Fedora/RHEL:        sudo dnf install fping")
        elif system == "macos":
            print("    Homebrew:           brew install fping")
        elif system == "windows":
            print("    PingMe will use the built-in Windows ping command.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install PingMe, a global launcher, and shell tab completion"
    )

    location = parser.add_mutually_exclusive_group()
    location.add_argument(
        "--user",
        action="store_true",
        help="install launcher under ~/.local/bin instead of /usr/local/bin",
    )
    location.add_argument(
        "--system",
        action="store_true",
        help="install launcher system-wide (Unix default)",
    )

    parser.add_argument(
        "--shell",
        choices=("auto", "zsh", "bash", "fish", "powershell", "none"),
        default="auto",
        help="shell completion target (default: auto-detect)",
    )
    parser.add_argument(
        "--no-completion",
        action="store_true",
        help="do not install shell tab completion",
    )

    return parser.parse_args()


def main() -> None:
    if os.name == "nt":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
            sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        except (AttributeError, ValueError):
            pass
    args = parse_args()
    source = project_script()
    system = detect_os()
    shell = detect_shell(system, args.shell)

    print()
    print(color("95;1", "  PingMe Installer"))
    print(color("90", "  ─────────────────────────────────────────"))
    info(f"Operating system: {platform.system()} {platform.release()} ({platform.machine()})")
    info(f"Python: {platform.python_version()}")
    info(f"Shell: {shell}")
    print()

    if system in {"linux", "macos"}:
        user_install = args.user
        launcher = install_unix_launcher(source, user_install)

        if user_install and str(launcher.parent) not in os.environ.get("PATH", "").split(os.pathsep):
            warn(f"{launcher.parent} is not currently in PATH")
            if shell == "zsh":
                print('    Add this to ~/.zshrc: export PATH="$HOME/.local/bin:$PATH"')
            elif shell == "bash":
                print('    Add this to ~/.bashrc: export PATH="$HOME/.local/bin:$PATH"')
            elif shell == "fish":
                print("    Run: fish_add_path ~/.local/bin")

    elif system == "windows":
        if args.system:
            warn("Windows uses a per-user launcher; --system is ignored")
        install_windows_launcher(source)

    else:
        fail(f"Unsupported operating system: {platform.system()}")

    if not args.no_completion and shell != "none":
        install_completion(shell, system)

    print()
    dependency_report(system)
    print()
    success("PingMe installation completed")

    if shell in {"zsh", "bash", "fish"}:
        print(f"    Reload your shell: exec {shell}")
    elif shell == "powershell":
        print("    Open a new PowerShell window")

    print("    Verify installation: pingme --help")
    print("    Test completion: type 'pingme --' and press TAB")
    print()


if __name__ == "__main__":
    main()
