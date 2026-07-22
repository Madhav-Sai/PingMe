#!/usr/bin/env python3
"""Cross-platform smoke tests for PingMe."""

from __future__ import annotations

import http.server
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PINGME = ROOT / "pingme.py"


def run(*args: str, cwd: Path | None = None, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(PINGME), *args],
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
    require("3.1.3" in version.stdout, "unexpected version", version.stdout)

    help_result = run("help", "examples")
    require(help_result.returncode == 0, "nested help failed", help_result.stdout)
    require("Examples" in help_result.stdout or "examples" in help_result.stdout.lower(), "examples help missing", help_result.stdout)

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
                "--quiet",
                "--no-banner",
                "--no-history",
                cwd=work,
                timeout=90,
            )
        finally:
            server.shutdown()
            server.server_close()

        require(result.returncode == 0, "file scan failed", result.stdout)
        for marker in ("HOST RESOLUTION", "FILE SCAN STATUS", "REACHABLE", "UNRESOLVED", "127.0.0.1"):
            require(marker in result.stdout, f"missing output marker: {marker}", result.stdout)

    print("[+] PingMe smoke tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
