#!/usr/bin/env python3
"""Cross-platform smoke tests for PingMe."""

from __future__ import annotations

import http.server
import os
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PINGME = ROOT / "pingme.py"


STATE_DIR = tempfile.TemporaryDirectory(prefix="pingme-state-")


def run(*args: str, cwd: Path | None = None, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    # Isolate history/config so the smoke test never touches the user's own state.
    env = {**os.environ, "PINGME_DATA_DIR": STATE_DIR.name, "PINGME_CONFIG": os.devnull + ".missing"}
    return subprocess.run(
        [sys.executable, str(PINGME), *args],
        env=env,
        cwd=str(cwd or ROOT),
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


def require(condition: bool, message: str, output: str = "") -> None:
    if not condition:
        if output:
            print(output)
        raise AssertionError(message)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    subprocess.run([sys.executable, "-m", "py_compile", str(PINGME)], check=True)

    version = run("--version")
    require(version.returncode == 0, "--version failed", version.stdout)
    require("3.3.0" in version.stdout, "unexpected version", version.stdout)

    help_result = run("help", "examples")
    require(help_result.returncode == 0, "nested help failed", help_result.stdout)
    require("Examples" in help_result.stdout or "examples" in help_result.stdout.lower(), "examples help missing", help_result.stdout)

    quick_help = run("-h")
    require(quick_help.returncode == 0 and "EVERYDAY EXAMPLES" in quick_help.stdout, "quick help failed", quick_help.stdout)

    typo = run("--tpc-ports", "22", "127.0.0.1")
    require(typo.returncode == 2 and "--tcp-ports" in typo.stdout, "option suggestion missing", typo.stdout)

    reverse = run("--reverse", "127.0.0.1", "--no-banner")
    require(reverse.returncode == 0 and "REVERSE LOOKUP" in reverse.stdout, "reverse lookup failed", reverse.stdout)

    subnet = run("--sub", "192.168.1.0/30", "--no-banner")
    require(subnet.returncode == 0, "subnet mode failed", subnet.stdout)
    require("SUBNET INFORMATION" in subnet.stdout, "subnet table missing", subnet.stdout)

    ipinfo = run("--ipinfo", "127.0.0.1", "8.8.8.8", "--no-banner")
    require(ipinfo.returncode == 0, "IP classification failed", ipinfo.stdout)
    require("IP CLASSIFICATION" in ipinfo.stdout, "IP classification table missing", ipinfo.stdout)

    with tempfile.TemporaryDirectory(prefix="pingme-smoke-") as directory:
        work = Path(directory)
        targets = work / "targets.txt"
        targets.write_text("localhost\n127.0.0.1\ninvalid-pingme-smoke.invalid\n", encoding="utf-8")

        port = free_port()
        handler = http.server.SimpleHTTPRequestHandler
        server = socketserver.TCPServer(("127.0.0.1", port), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = run(
                "-f", str(targets),
                "--tcp-ports", str(port),
                "--tcp-timeout", "1",
                "--count", "1",
                "--timeout", "1",
                "--threads", "4",
                "--verbose",
                "--no-banner",
                "--no-history",
                cwd=work,
                timeout=90,
            )
        finally:
            server.shutdown()
            server.server_close()

        # One target cannot be resolved, so the documented exit status is 1.
        require(result.returncode == 1, "file scan exit status", result.stdout)
        for marker in ("HOST RESOLUTION", "FILE SCAN STATUS", "REACHABLE", "UNRESOLVED", "127.0.0.1"):
            require(marker in result.stdout, f"missing output marker: {marker}", result.stdout)

        positional = run(
            "127.0.0.1", "--tcp-ports", "1", "--tcp-timeout", "0.5", "--timeout", "1",
            "--no-banner", "--no-history", "--compact", cwd=work,
        )
        require(positional.returncode == 0, "positional host scan failed", positional.stdout)
        require("reachable=1" in positional.stdout, "positional host not reachable", positional.stdout)

    print("[+] PingMe smoke tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
