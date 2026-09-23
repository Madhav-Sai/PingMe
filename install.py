#!/usr/bin/env python3
"""Cross-platform installer for PingMe."""

from __future__ import annotations

import argparse
import os
import platform
import shlex
import shutil
import stat
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path
from typing import NoReturn

APP = "pingme"
SCRIPT = "pingme.py"
MARKER_START = "# >>> pingme completion >>>"
MARKER_END = "# <<< pingme completion <<<"

# Completion is generated from pingme.py's own argument parser, so every option
# is always covered. VALUE_HINTS adds what argparse cannot know: what to suggest
# for a value. Kinds: file, dir, iface, subnet, text (free text; the hint is shown).
VALUE_HINTS: dict[str, tuple[str, list[tuple[str, str]]]] = {
    "sub": ("subnet", []),
    "file": ("file", []),
    "host": ("text", [("<IP or hostname>", "")]),
    "exclude": ("text", [("<IP or CIDR>", "")]),
    "max_hosts": ("text", [("256", ""), ("1024", ""), ("65536", "default")]),
    "tag": ("text", [("<tag>", "lines marked @tag in the target file")]),
    "column": ("text", [("<column>", "CSV header name holding the targets")]),
    "discover6": ("iface", []),
    "reverse": ("text", [("<IP or CIDR>", "")]),
    "tcp_ports": ("text", []),  # filled from pingme.TCP_PORT_PRESETS
    "tcp_timeout": ("text", [("0.5", "seconds"), ("1", "seconds"), ("2", "default")]),
    "ipinfo": ("text", [("<IP>", "")]),
    "threads": ("text", [("10", ""), ("20", "default"), ("50", ""), ("100", "")]),
    "timeout": ("text", [("0.5", "seconds"), ("1", "seconds"), ("2", "default"), ("auto", "adapt to measured RTT")]),
    "count": ("text", [("1", ""), ("2", ""), ("3", "default"), ("5", "")]),
    "min_replies": ("text", [("1", ""), ("2", "default"), ("3", "")]),
    "retry": ("text", [("0", "default"), ("1", ""), ("2", "")]),
    "rate": ("text", [("0", "unlimited (default)"), ("50", "packets/s"), ("200", "packets/s")]),
    "interface": ("iface", []),
    "watch": ("text", [("30", "seconds"), ("60", "seconds"), ("300", "seconds")]),
    "alive_out": ("file", [("alive.txt", "default")]),
    "dead_out": ("file", [("dead.txt", "default")]),
    "error_out": ("file", [("errors.txt", "default")]),
    "hostnames_out": ("file", [("hostnames.txt", "live-host report"), ("hostnames.csv", "CSV rows"),
                               ("hostnames.json", "JSON rows")]),
    "changes_out": ("file", [("changes.txt", "default")]),
    "html": ("file", [("report.html", "HTML report")]),
    "nmap_xml": ("file", [("scan.xml", "nmap XML")]),
    "label": ("text", [("<name>", "history label")]),
    "diff": ("file", []),
    "clear_history": ("file", []),
    "uptime": ("file", []),
    "keep": ("text", [("10", ""), ("50", "default"), ("0", "keep everything")]),
    "data_dir": ("dir", []),
    "notify": ("text", [("https://", "Slack/Teams/Discord/any webhook"), ("mailto:", "e-mail"),
                        ("telegram://", "TOKEN@CHAT")]),
    "serve": ("text", [("9109", "port"), ("127.0.0.1:9109", "local only"), ("0.0.0.0:9109", "all adapters")]),
    "wol": ("text", [("<MAC>", "aa:bb:cc:dd:ee:ff")]),
    "wol_broadcast": ("text", [("255.255.255.255", "default")]),
    "config": ("file", []),
}
CHOICE_HELP: dict[str, dict[str, str]] = {
    "ping_tool": {"auto": "pick the best available", "native": "built-in ICMP engine", "fping": "fping sweep",
                  "ping": "system ping", "ask": "choose interactively"},
    "out_format": {"txt": "one IP per line", "csv": "spreadsheet rows", "json": "full detail"},
    "color": {"auto": "only on a terminal", "always": "force colors", "never": "plain text"},
    "notify_on": {"changes": "when something changes", "down": "whenever a host is down",
                  "always": "after every scan"},
}


def _load_pingme():
    import importlib.util
    spec = importlib.util.spec_from_file_location("pingme_completion_source", project_script())
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def completion_spec() -> list[dict]:
    """Every option from pingme's parser with what its value completes to."""
    pingme = _load_pingme()
    presets = [(name, ports) for name, ports in pingme.TCP_PORT_PRESETS.items()]
    options = []
    for action in pingme.build_parser()._actions:
        if not action.option_strings:
            continue
        takes_value = action.nargs != 0
        kind, values = VALUE_HINTS.get(action.dest, ("text", []))
        if action.choices:
            kind, values = "choice", [(str(c), CHOICE_HELP.get(action.dest, {}).get(str(c), ""))
                                      for c in action.choices]
        if action.dest == "tcp_ports":
            values = presets + [("22,80,443", "explicit list"), ("8000-8010", "range")]
        options.append({
            "names": list(action.option_strings),
            "dest": action.dest,
            "help": " ".join((action.help or "").split()).replace("%%", "%"),
            "takes_value": takes_value,
            "nargs": action.nargs,
            "kind": kind if takes_value else None,
            "values": values if takes_value else [],
            "metavar": action.metavar if isinstance(action.metavar, str) else action.dest.upper(),
        })
    return options


def all_options() -> list[str]:
    return [name for option in completion_spec() for name in option["names"]]


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
    destination = (
        Path.home() / ".local/bin/pingme"
        if user_install
        else Path("/usr/local/bin/pingme")
    )

    if user_install:
        destination.parent.mkdir(parents=True, exist_ok=True)

    absolute_source = source.resolve()
    launcher = (
        "#!/bin/sh\n"
        f"exec /usr/bin/env python3 {shlex.quote(str(absolute_source))} \"$@\"\n"
    ).encode("utf-8")

    if os.access(destination.parent, os.W_OK):
        destination.unlink(missing_ok=True)
        destination.write_bytes(launcher)
        make_executable(destination)
    else:
        info(f"Administrator permission is required to write {destination}")
        temporary_name = ""
        try:
            with tempfile.NamedTemporaryFile(prefix="pingme-launcher-", delete=False) as temporary:
                temporary.write(launcher)
                temporary_name = temporary.name
            run(["sudo", "install", "-m", "755", temporary_name, str(destination)])
        finally:
            if temporary_name:
                Path(temporary_name).unlink(missing_ok=True)

    success(f"Installed launcher: {destination} -> python3 {absolute_source}")
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


IFACE_ADDRESSES_SH = "ip -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1"
# "10.10.11.30:wlan0" pairs for zsh's described list (IPv4; IPv6 colons would split the description).
IFACE_V4_DESCRIBED_SH = "ip -o -4 addr show 2>/dev/null | awk '{print $4, $2}' | sed 's|/[0-9]* |:|'"
LOCAL_SUBNETS_SH = "ip -o -4 route show scope link 2>/dev/null | awk '{print $1}'"


def _zsh_quote(text: str) -> str:
    return text.replace("\\", "\\\\").replace("'", "'\\''").replace(":", "\\:").replace("[", "\\[").replace("]", "\\]")


def _zsh_value_function(option: dict) -> str:
    """Completion function for one option's value; the option's help is the list heading."""
    heading = option["help"].replace("'", "")
    real = [(v, d) for v, d in option["values"] if not v.startswith("<")]
    placeholder = next((f"{v}{': ' + d if d else ''}" for v, d in option["values"] if v.startswith("<")), "")
    kind = option["kind"]
    body = []
    if kind == "file":
        body.append("_files")
    elif kind == "dir":
        body.append("_files -/")
    elif kind == "iface":
        body.append("_net_interfaces")
        body.append(f'local -a addrs; addrs=(${{(f)"$({IFACE_V4_DESCRIBED_SH})"}})')
        body.append("(( ${#addrs} )) && _describe -t addresses 'adapter IP address' addrs")
    elif kind == "subnet":
        body.append(f'local -a nets; nets=(${{(f)"$({LOCAL_SUBNETS_SH})"}})')
        body.append("(( ${#nets} )) && _describe -t networks 'networks on this machine' nets")
    if real:
        items = " ".join("'" + (v.replace(":", "\\:") + (":" + d if d else "")).replace("'", "'\\''") + "'"
                         for v, d in real)
        body.append(f"local -a vals; vals=({items})")
        body.append(f"_describe -t values '{heading}' vals")
    elif kind == "text":
        body.append(f"_message -r '{heading}{' — ' + placeholder if placeholder else ''}'")
    return f"_pingme_value_{option['dest']}() {{\n  " + "\n  ".join(body) + "\n}\n"


def zsh_completion() -> str:
    spec = completion_spec()
    functions = "\n".join(_zsh_value_function(option) for option in spec if option["takes_value"])
    lines = []
    for option in spec:
        names = option["names"]
        exclude = f"'({' '.join(names)})'" if len(names) > 1 else ""
        name_part = ("{" + ",".join(names) + "}") if len(names) > 1 else names[0]
        repeat = "*" if option["nargs"] in ("+", "*") or option["dest"] in {"tag", "notify"} else ""
        desc = f"'[{_zsh_quote(option['help'])}]"
        if option["takes_value"]:
            value = f":{_zsh_quote(option['metavar'].lower())}:_pingme_value_{option['dest']}"
            if option["nargs"] == 2:
                value += value  # --diff takes two files
            desc += value
        desc += "'"
        if len(names) > 1:
            lines.append(f"    {exclude[:-1]}{repeat}'{name_part}{desc}")
        else:
            lines.append(f"    '{repeat}{names[0]}{desc[1:]}")
    arguments = " \\\n".join(lines + ["    '*:target:_pingme_targets'"])
    return f"""#compdef pingme
# Generated by install.py from pingme.py's option list.

{functions}
_pingme_targets() {{
  _files
  local -a nets; nets=(${{(f)"$({LOCAL_SUBNETS_SH})"}})
  (( ${{#nets}} )) && _describe -t networks 'networks on this machine' nets
  local -a words; words=('help:show help topics')
  _describe -t commands 'command' words
}}

_pingme() {{
  _arguments -s -S \\
{arguments}
}}

_pingme "$@"
"""


def bash_completion() -> str:
    spec = completion_spec()
    options = " ".join(all_options())
    cases = []
    for option in spec:
        if not option["takes_value"]:
            continue
        pattern = "|".join(option["names"])
        words = " ".join(v for v, _d in option["values"] if not v.startswith("<"))
        kind = option["kind"]
        if kind == "file":
            action = f'COMPREPLY=( $(compgen -f -- "$cur") $(compgen -W "{words}" -- "$cur") ); compopt -o filenames 2>/dev/null'
        elif kind == "dir":
            action = 'COMPREPLY=( $(compgen -d -- "$cur") ); compopt -o filenames 2>/dev/null'
        elif kind == "iface":
            action = f'COMPREPLY=( $(compgen -W "$(ls /sys/class/net 2>/dev/null) $({IFACE_ADDRESSES_SH})" -- "$cur") )'
        elif kind == "subnet":
            action = f'COMPREPLY=( $(compgen -W "$({LOCAL_SUBNETS_SH})" -- "$cur") )'
        else:
            action = f'COMPREPLY=( $(compgen -W "{words}" -- "$cur") )'
        cases.append(f"        {pattern})\n            {action}\n            return\n            ;;")
    diff = "|".join(next(o["names"] for o in spec if o["dest"] == "diff"))
    return f"""# Generated by install.py from pingme.py's option list.
_pingme_completion() {{
    local cur prev prev2
    COMPREPLY=()
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"
    prev2="${{COMP_WORDS[COMP_CWORD-2]}}"

    case "$prev2" in
        {diff})
            COMPREPLY=( $(compgen -f -- "$cur") ); compopt -o filenames 2>/dev/null
            return
            ;;
    esac
    case "$prev" in
{chr(10).join(cases)}
        help)
            COMPREPLY=( $(compgen -W "{' '.join(v for v, _d in next(o['values'] for o in spec if o['dest'] == 'help_topic'))}" -- "$cur") )
            return
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "{options}" -- "$cur") )
    else
        COMPREPLY=( $(compgen -f -- "$cur") $(compgen -W "help $({LOCAL_SUBNETS_SH})" -- "$cur") )
        compopt -o filenames 2>/dev/null
    fi
}}
complete -F _pingme_completion pingme
"""


def _fish_quote(text: str) -> str:
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"


def fish_completion() -> str:
    lines = ["# Generated by install.py from pingme.py's option list.", "complete -c pingme -f",
             "complete -c pingme -n '__fish_is_first_arg' -a help -d 'Show help topics'",
             "complete -c pingme -a '(__fish_complete_path)'",
             "complete -c pingme -a '(ip -o -4 route show scope link 2>/dev/null | string split -f1 \" \")' -d 'local network'"]
    for option in completion_spec():
        flags = " ".join(f"-l {n[2:]}" if n.startswith("--") else f"-s {n[1:]}" for n in option["names"])
        base = f"complete -c pingme {flags} -d {_fish_quote(option['help'])}"
        if not option["takes_value"]:
            lines.append(base)
            continue
        kind = option["kind"]
        values = [(v, d) for v, d in option["values"] if not v.startswith("<")]
        if values:
            printf = " ".join(f"{_fish_quote(v)} {_fish_quote(d)}" for v, d in values)
            source = f"(printf '%s\\t%s\\n' {printf})"
        else:
            source = ""
        if kind == "file":
            lines.append(f"{base} -r -F" + (f" -a {_fish_quote(source)}" if source else ""))
        elif kind == "dir":
            lines.append(f"{base} -x -a '(__fish_complete_directories)'")
        elif kind == "iface":
            lines.append(f"{base} -x -a '(__fish_print_interfaces)'")
        elif kind == "subnet":
            lines.append(f"{base} -x -a '(ip -o -4 route show scope link 2>/dev/null | string split -f1 \" \")'")
        else:
            lines.append(f"{base} -x" + (f" -a {_fish_quote(source)}" if source else ""))
    return "\n".join(lines) + "\n"


def _ps_quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def powershell_completion() -> str:
    spec = completion_spec()
    option_rows = ",\n".join(
        f"    @({_ps_quote(name)}, {_ps_quote(option['help'] or name)})"
        for option in spec for name in option["names"])
    value_rows = []
    for option in spec:
        if not option["takes_value"]:
            continue
        values = ", ".join(f"@({_ps_quote(v)}, {_ps_quote(d or v)})"
                           for v, d in option["values"] if not v.startswith("<"))
        for name in option["names"]:
            value_rows.append(f"    {_ps_quote(name)} = @{{ kind = {_ps_quote(option['kind'])}; values = @({values}) }}")
    return f"""# Generated by install.py from pingme.py's option list.
$PingMeOptions = @(
{option_rows}
)
$PingMeValues = @{{
{chr(10).join(value_rows)}
}}
Register-ArgumentCompleter -Native -CommandName pingme, pingme.py, pingme.cmd -ScriptBlock {{
  param($wordToComplete, $commandAst, $cursorPosition)
  $words = @($commandAst.CommandElements | Where-Object {{ $_.Extent.EndOffset -lt $cursorPosition -or $_.Extent.Text -ne $wordToComplete }} | ForEach-Object {{ $_.Extent.Text }})
  $previous = if ($words.Count -ge 2) {{ $words[-1] }} else {{ '' }}
  if ($wordToComplete -and $words.Count -ge 1 -and $words[-1] -eq $wordToComplete) {{
    $previous = if ($words.Count -ge 2) {{ $words[-2] }} else {{ '' }}
  }}
  $spec = $PingMeValues[$previous]
  if ($spec) {{
    foreach ($item in $spec.values) {{
      if ($item[0] -like "$wordToComplete*") {{
        [System.Management.Automation.CompletionResult]::new($item[0], $item[0], 'ParameterValue', $item[1])
      }}
    }}
    if ($spec.kind -eq 'iface') {{
      [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | ForEach-Object {{
        $name = $_.Name
        $_.GetIPProperties().UnicastAddresses | ForEach-Object {{
          $ip = $_.Address.ToString()
          if ($ip -like "$wordToComplete*") {{ [System.Management.Automation.CompletionResult]::new($ip, $ip, 'ParameterValue', $name) }}
        }}
      }}
    }}
    if ($spec.kind -in @('file', 'dir')) {{
      Get-ChildItem -Path "$wordToComplete*" -ErrorAction SilentlyContinue | Where-Object {{ $spec.kind -eq 'file' -or $_.PSIsContainer }} | ForEach-Object {{
        [System.Management.Automation.CompletionResult]::new($_.Name, $_.Name, 'ProviderItem', $_.FullName)
      }}
    }}
    return
  }}
  if ($wordToComplete -like '-*' -or -not $wordToComplete) {{
    foreach ($item in $PingMeOptions) {{
      if ($item[0] -like "$wordToComplete*") {{
        [System.Management.Automation.CompletionResult]::new($item[0], $item[0], 'ParameterName', $item[1])
      }}
    }}
  }}
  if ($wordToComplete -notlike '-*') {{
    Get-ChildItem -Path "$wordToComplete*" -ErrorAction SilentlyContinue | ForEach-Object {{
      [System.Management.Automation.CompletionResult]::new($_.Name, $_.Name, 'ProviderItem', $_.FullName)
    }}
  }}
}}
"""


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
