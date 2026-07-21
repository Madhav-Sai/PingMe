#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║              PingMe — Advanced Ping Scanner v3.1.0 by Madhav       ║
║   Subnet Info · Ping Scan · TTL Fingerprint · Reverse DNS        ║
║   History · Diff · IP Classify · Retry · Resume · Rate-Limit     ║
╚══════════════════════════════════════════════════════════════════╝
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional, Union


APP_NAME = "PingMe"
VERSION = "3.1.0"
BUILD = "hostnames-changes-report"


# ─────────────────────────────────────────────────────────────────
# ANSI COLOR PALETTE
# ─────────────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    ORANGE  = "\033[38;5;208m"
    LIME    = "\033[38;5;118m"
    PURPLE  = "\033[38;5;135m"
    TEAL    = "\033[38;5;51m"
    PINK    = "\033[38;5;213m"
    BG_RED   = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_BLUE  = "\033[44m"
    BG_DARK  = "\033[40m"

    @staticmethod
    def b(text):    return f"{C.BOLD}{text}{C.RESET}"
    @staticmethod
    def ok(text):   return f"{C.GREEN}{text}{C.RESET}"
    @staticmethod
    def err(text):  return f"{C.RED}{text}{C.RESET}"
    @staticmethod
    def warn(text): return f"{C.YELLOW}{text}{C.RESET}"
    @staticmethod
    def info(text): return f"{C.CYAN}{text}{C.RESET}"
    @staticmethod
    def hi(text):   return f"{C.MAGENTA}{C.BOLD}{text}{C.RESET}"


# ─────────────────────────────────────────────────────────────────
# HISTORY / PERSISTENCE
# ─────────────────────────────────────────────────────────────────
def _data_dir() -> Path:
    """Always resolves to ./data relative to the CURRENT working directory."""
    return Path(os.getcwd()) / "data"


def history_file(label: str) -> Path:
    d = _data_dir()
    d.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.\-]", "_", label)
    return d / f"{safe}.json"


def save_scan(label: str, results: list[dict]):
    """Save a scan. results = list of {ip, alive, ttl, os_guess, hostname, scope}"""
    alive = sorted(r["ip"] for r in results if r["alive"])
    dead  = sorted(r["ip"] for r in results if not r["alive"])
    data  = {
        "label":     label,
        "timestamp": datetime.now().isoformat(),
        "alive":     alive,
        "dead":      dead,
        "results":   results,
    }
    hf = history_file(label)
    existing: list = []
    if hf.exists():
        try:
            existing = json.loads(hf.read_text())
        except Exception:
            existing = []
    if not isinstance(existing, list):
        existing = []
    existing.append(data)
    hf.write_text(json.dumps(existing, indent=2))
    print(f"  {C.DIM}[data] saved → {hf}{C.RESET}")


def load_history(label: str) -> list[dict]:
    hf = history_file(label)
    if not hf.exists():
        return []
    try:
        data = json.loads(hf.read_text())
        return data if isinstance(data, list) else []
    except Exception:
        return []


# ─────────────────────────────────────────────────────────────────
# RESUME / PARTIAL SAVE
# ─────────────────────────────────────────────────────────────────
def _resume_file(label: str) -> Path:
    d = _data_dir()
    d.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.\-]", "_", label)
    return d / f".resume_{safe}.json"


def save_partial(label: str, done_results: list[dict], remaining: list[str]):
    rf = _resume_file(label)
    rf.write_text(json.dumps({
        "label":     label,
        "timestamp": datetime.now().isoformat(),
        "done":      done_results,
        "remaining": remaining,
    }, indent=2))


def load_partial(label: str) -> Optional[dict]:
    rf = _resume_file(label)
    if not rf.exists():
        return None
    try:
        return json.loads(rf.read_text())
    except Exception:
        return None


def clear_partial(label: str):
    rf = _resume_file(label)
    if rf.exists():
        rf.unlink()


# ─────────────────────────────────────────────────────────────────
# TTL FINGERPRINTING
# ─────────────────────────────────────────────────────────────────
def ttl_to_os(ttl: Optional[int]) -> str:
    """
    Guess OS from TTL value.
    Each OS sets an initial TTL; we bucket by common ranges to absorb hops.
      ≥ 240        → Cisco / Network Device  (initial 255)
      128–239      → Windows                 (initial 128)
      64–127       → Linux / Unix / macOS    (initial 64)
      1–63         → Linux (many hops away)
      None / 0     → Unknown
    """
    if ttl is None or ttl <= 0:
        return "Unknown"
    if ttl >= 240:
        return "Cisco/Network"
    if ttl >= 128:
        return "Windows"
    if ttl >= 64:
        return "Linux/Unix"
    return "Linux (far)"


def ttl_color(os_guess: str) -> str:
    return {
        "Windows":       C.BLUE,
        "Linux/Unix":    C.LIME,
        "Cisco/Network": C.ORANGE,
        "Linux (far)":   C.TEAL,
        "Unknown":       C.DIM,
    }.get(os_guess, C.DIM)


# ─────────────────────────────────────────────────────────────────
# REVERSE DNS
# ─────────────────────────────────────────────────────────────────
_dns_cache: dict[str, str] = {}
_dns_lock  = threading.Lock()


def reverse_dns(ip: str, timeout: float = 1.5) -> str:
    """Non-blocking reverse DNS with per-IP cache and timeout."""
    with _dns_lock:
        if ip in _dns_cache:
            return _dns_cache[ip]

    result = ""
    def _lookup():
        nonlocal result
        try:
            result = socket.gethostbyaddr(ip)[0]
        except Exception:
            result = ""

    t = threading.Thread(target=_lookup, daemon=True)
    t.start()
    t.join(timeout)
    hostname = result if result and result != ip else ""

    with _dns_lock:
        _dns_cache[ip] = hostname
    return hostname


# ─────────────────────────────────────────────────────────────────
# IP CLASSIFIER
# ─────────────────────────────────────────────────────────────────
def ip_classify(ip_str: str) -> dict:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return {"scope": "Invalid", "color": C.RED, "rfc": "", "description": "Not a valid IP"}

    if ip.is_loopback:
        if ip.version == 6:
            return {"scope": "Loopback", "color": C.DIM, "rfc": "RFC 4291", "description": "IPv6 loopback (::1/128)"}
        return {"scope": "Loopback", "color": C.DIM, "rfc": "RFC 5735", "description": "Loopback (127.0.0.0/8)"}
    if ip.is_link_local:
        if ip.version == 6:
            return {"scope": "Link-Local", "color": C.YELLOW, "rfc": "RFC 4291", "description": "IPv6 link-local (fe80::/10)"}
        return {"scope": "Link-Local",     "color": C.YELLOW, "rfc": "RFC 3927", "description": "Link-local (169.254.0.0/16) — APIPA"}
    if ip.is_multicast:
        if ip.version == 6:
            return {"scope": "Multicast", "color": C.ORANGE, "rfc": "RFC 4291", "description": "IPv6 multicast (ff00::/8)"}
        return {"scope": "Multicast",      "color": C.ORANGE, "rfc": "RFC 5771", "description": "Multicast (224.0.0.0/4)"}
    if ip.is_reserved:
        return {"scope": "Reserved",       "color": C.PURPLE, "rfc": "RFC 1112", "description": "Reserved / future use"}

    for doc in [ipaddress.ip_network("192.0.2.0/24"),
                ipaddress.ip_network("198.51.100.0/24"),
                ipaddress.ip_network("203.0.113.0/24")]:
        if ip in doc:
            return {"scope": "Documentation", "color": C.DIM, "rfc": "RFC 5737",
                    "description": f"Documentation/example ({doc})"}

    if ip in ipaddress.ip_network("100.64.0.0/10"):
        return {"scope": "Private", "color": C.CYAN, "rfc": "RFC 6598",
                "description": "Shared address space / CGNAT (100.64.0.0/10)"}

    if ip.is_private:
        if ip.version == 6:
            if ip in ipaddress.ip_network("fc00::/7"):
                return {"scope": "Private", "color": C.CYAN, "rfc": "RFC 4193", "description": "IPv6 unique local address (fc00::/7)"}
            return {"scope": "Private", "color": C.CYAN, "rfc": "IANA", "description": "IPv6 special-purpose address"}
        for net, rfc, desc in [
            (ipaddress.ip_network("10.0.0.0/8"),     "RFC 1918", "Class A private (10.0.0.0/8)"),
            (ipaddress.ip_network("172.16.0.0/12"),  "RFC 1918", "Class B private (172.16.0.0/12)"),
            (ipaddress.ip_network("192.168.0.0/16"), "RFC 1918", "Class C private (192.168.0.0/16)"),
        ]:
            if ip in net:
                return {"scope": "Private", "color": C.CYAN, "rfc": rfc, "description": desc}
        return {"scope": "Private", "color": C.CYAN, "rfc": "RFC 1918", "description": "Private address"}

    return {"scope": "Public", "color": C.LIME, "rfc": "IANA", "description": "Publicly routable address"}


def show_ipinfo(targets: list[str]):
    LABEL_W, VALUE_W = 18, 36
    BW = LABEL_W + VALUE_W + 3

    def _border(l, r):
        return f"  {C.MAGENTA}{C.BOLD}{l}{'─' * BW}{r}{C.RESET}"

    def row(label, value, vcol=C.WHITE):
        return (
            f"  {C.MAGENTA}{C.BOLD}│{C.RESET}"
            f" {C.CYAN}{C.BOLD}{label:<{LABEL_W}}{C.RESET}"
            f" {vcol}{str(value)[:VALUE_W]:<{VALUE_W}}{C.RESET}"
            f"{C.MAGENTA}{C.BOLD}│{C.RESET}"
        )

    print(f"\n  {C.BOLD}{C.MAGENTA}┌{'─' * BW}┐")
    print(f"  │{'  🔍  IP CLASSIFICATION':^{BW}}│")
    print(f"  └{'─' * BW}┘{C.RESET}")

    for ip_str in targets:
        info = ip_classify(ip_str)
        print(_border("├", "┤"))
        print(row("IP Address",   ip_str,               C.WHITE))
        print(row("Scope",        info["scope"],         info["color"] + C.BOLD))
        print(row("RFC / Auth",   info["rfc"],           C.DIM + C.WHITE))
        print(row("Description",  info["description"],   C.WHITE))

    print(_border("└", "┘"))
    print()


# ─────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────
def banner(no_banner: bool = False):
    if no_banner:
        return
    ts = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    lines = [
        f"{C.RED}{C.BOLD}",
        "  ██████╗ ██╗███╗   ██╗ ██████╗ ███╗   ███╗███████╗",
        "  ██╔══██╗██║████╗  ██║██╔════╝ ████╗ ████║██╔════╝",
        "  ██████╔╝██║██╔██╗ ██║██║  ███╗██╔████╔██║█████╗  ",
        "  ██╔═══╝ ██║██║╚██╗██║██║   ██║██║╚██╔╝██║██╔══╝  ",
        "  ██║     ██║██║ ╚████║╚██████╔╝██║ ╚═╝ ██║███████╗",
        "  ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝",
        f"{C.RESET}",
        f"  {C.PURPLE}Advanced Ping Scanner v{VERSION} By Madhav {C.RESET}  {C.DIM}│{C.RESET}  {C.DIM}{ts}{C.RESET}",
        f"  {C.DIM}Build: {BUILD} · file hostname/IP/status table enabled{C.RESET}",
        f"  {C.DIM}{'─' * 70}{C.RESET}",
    ]
    print("\n".join(lines))


# ─────────────────────────────────────────────────────────────────
# SUBNET INFO
# ─────────────────────────────────────────────────────────────────
def show_subnet_info(cidr: str) -> Union[ipaddress.IPv4Network, ipaddress.IPv6Network]:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        print(C.err(f"\n  ✗ Invalid CIDR: {e}"))
        sys.exit(1)

    is_ipv4 = net.version == 4
    total = max(net.num_addresses - 2, 0) if is_ipv4 and net.prefixlen <= 30 else net.num_addresses
    first_host = next(net.hosts(), None) if is_ipv4 else net.network_address
    last_host = (
        ipaddress.ip_address(int(net.broadcast_address) - 1)
        if is_ipv4 and net.prefixlen <= 30 and total > 0
        else net[-1]
    )
    prefix = net.prefixlen
    LABEL_W, VALUE_W = 24, 26
    BW = LABEL_W + VALUE_W + 3

    def _border(l, r): return f"  {C.MAGENTA}{C.BOLD}{l}{'─' * BW}{r}{C.RESET}"
    top = _border("┌", "┐"); bot = _border("└", "┘"); sep = _border("├", "┤")

    def hdr(title):
        vis_len = len(title) + 1
        pad = BW - vis_len - 2
        return (f"  {C.MAGENTA}{C.BOLD}│{C.RESET}"
                f"  {C.BOLD}{C.WHITE}{title}{' ' * max(pad,0)}{C.RESET}"
                f"{C.MAGENTA}{C.BOLD}│{C.RESET}")

    def row(label, value, vcol=C.WHITE):
        return (f"  {C.MAGENTA}{C.BOLD}│{C.RESET}"
                f" {C.CYAN}{C.BOLD}{label:<{LABEL_W}}{C.RESET}"
                f" {vcol}{str(value)[:VALUE_W]:<{VALUE_W}}{C.RESET}"
                f"{C.MAGENTA}{C.BOLD}│{C.RESET}")

    print(); print(top); print(hdr("🌐  SUBNET INFORMATION")); print(sep)
    print(row("CIDR",              cidr,                       C.LIME))
    print(row("Network Address",   str(net.network_address),   C.YELLOW))
    if is_ipv4:
        print(row("Broadcast Address", str(net.broadcast_address), C.YELLOW))
    print(row("Subnet Mask",       str(net.netmask),           C.WHITE))
    print(row("Wildcard Mask",     str(net.hostmask),          C.WHITE))
    print(row("Prefix Length",     f"/{prefix}",               C.ORANGE))
    print(row("IP Version",        f"IPv{net.version}",        C.CYAN))
    if total > 0:
        print(sep)
        print(row("First Host",       str(first_host),         C.GREEN))
        print(row("Last Host",        str(last_host),          C.GREEN))
        print(row("Total Usable IPs" if is_ipv4 else "Total Addresses", f"{total:,}", C.BOLD + C.LIME))
    print(bot)

    bar_w = 32
    address_bits = net.max_prefixlen
    pct   = (total / (2 ** (address_bits - prefix))) * 100 if prefix < address_bits else 100
    fill  = max(1, int((prefix / address_bits) * bar_w))
    bar   = f"{C.TEAL}{'█' * fill}{C.DIM}{'░' * (bar_w - fill)}{C.RESET}"
    print(f"\n  {C.DIM}Prefix /{prefix} usage:{C.RESET}  {bar}  {C.DIM}/{prefix} of /{address_bits}  ({pct:.1f}% host space){C.RESET}")

    print(f"\n  {C.BOLD}{C.MAGENTA}┌{'─' * BW}┐{C.RESET}")
    print(hdr("📐  SUBNET BREAKDOWN"))
    print(f"  {C.MAGENTA}{C.BOLD}├{'─' * BW}┤{C.RESET}")
    sub_prefixes = [24, 25, 26, 27, 28, 29, 30] if is_ipv4 else [64, 96, 112, 120, 124, 126]
    for sub_prefix in sub_prefixes:
        if sub_prefix <= prefix:
            continue
        n_subnets  = 2 ** (sub_prefix - prefix)
        hosts_each = max(2 ** (address_bits - sub_prefix) - 2, 0) if is_ipv4 else 2 ** (address_bits - sub_prefix)
        print(row(f"/{sub_prefix} subnets", f"{n_subnets:>5,}  ×  {hosts_each} hosts each", C.WHITE))
    print(f"  {C.MAGENTA}{C.BOLD}├{'─' * BW}┤{C.RESET}")
    class_label = ("Class A (/8)" if prefix <= 8 else
                   "Class B (/16)" if prefix <= 16 else
                   "Class C (/24)" if prefix <= 24 else "Subnetted") if is_ipv4 else "IPv6 subnet"
    scope = f"{'Private' if net.is_private else 'Public'} · {class_label}"
    print(row("Address Scope",           scope,                   C.PINK))
    print(row("Total IPs (incl. net+bc)" if is_ipv4 else "Total Addresses", f"{net.num_addresses:,}", C.DIM + C.WHITE))
    print(f"  {C.MAGENTA}{C.BOLD}└{'─' * BW}┘{C.RESET}\n")
    return net


# ─────────────────────────────────────────────────────────────────
# EXCLUDE FILTER
# ─────────────────────────────────────────────────────────────────
def build_exclude_filter(
    exclude_args: list[str],
) -> tuple[set[str], list[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]]:
    """Parse --exclude values without expanding potentially huge CIDRs in memory."""
    excluded_ips: set[str] = set()
    excluded_nets: list[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
    for item in (exclude_args or []):
        item = item.strip()
        try:
            net = ipaddress.ip_network(item, strict=False)
            excluded_nets.append(net)
        except ValueError:
            try:
                excluded_ips.add(str(ipaddress.ip_address(item)))
            except ValueError:
                print(C.warn(f"  ⚠  Invalid --exclude value ignored: {item}"))
    return excluded_ips, excluded_nets


def is_excluded(
    ip: str,
    excluded_ips: set[str],
    excluded_nets: list[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]],
) -> bool:
    if ip in excluded_ips:
        return True
    address = ipaddress.ip_address(ip)
    return any(address in network for network in excluded_nets)


# ─────────────────────────────────────────────────────────────────
# RATE LIMITER
# ─────────────────────────────────────────────────────────────────
class RateLimiter:
    """Token-bucket rate limiter — caps packets/sec across all threads."""
    def __init__(self, rate: int):
        self.rate      = rate          # max tokens (packets) per second
        self.tokens    = float(rate)
        self.last_time = time.monotonic()
        self._lock     = threading.Lock()

    def acquire(self, n: int = 1):
        """Block until n tokens are available."""
        if self.rate <= 0:
            return
        while True:
            with self._lock:
                now    = time.monotonic()
                delta  = now - self.last_time
                self.tokens    = min(self.rate, self.tokens + delta * self.rate)
                self.last_time = now
                if self.tokens >= n:
                    self.tokens -= n
                    return
            time.sleep(0.01)


# ─────────────────────────────────────────────────────────────────
# TOOL SELECTION  (cached at module level — FIX 4)
# ─────────────────────────────────────────────────────────────────
_FPING_PATH: Optional[str] = shutil.which("fping")
_PING_PATH:  Optional[str] = shutil.which("ping")
_PING6_PATH: Optional[str] = shutil.which("ping6")

# User-selected tool: "auto" | "fping" | "ping"
_PING_TOOL: str = "auto"


def _use_fping() -> bool:
    """Return True if fping should be used for this scan."""
    if _PING_TOOL == "fping":
        return _FPING_PATH is not None
    if _PING_TOOL == "ping":
        return False
    # auto: prefer fping if available
    return _FPING_PATH is not None


def _is_ipv6(ip: str) -> bool:
    return ipaddress.ip_address(ip).version == 6


def _ping_via_fping(ip: str, timeout: int, count: int) -> tuple[bool, Optional[int]]:
    """
    fping 5.1 on Kali confirmed behaviour (from debug output):
      - Per-packet lines (including TTL) → STDOUT
      - Summary "xmt/rcv/%loss = N/M/P%" → STDERR
      - Dead host: exit=1, stdout has timed-out lines, stderr has rcv=0
      - Alive host: exit=0, stdout has reply lines with TTL, stderr has rcv>0

    Rules:
      - NO -p flag (causes subprocess timeout to fire before fping finishes)
      - Capture BOTH stdout AND stderr
      - Parse rcv count from stderr summary ONLY
      - Parse TTL from stdout per-packet lines
      - Never use exit code to determine alive/dead
    """
    if not _FPING_PATH:
        return False, None

    # Generous timeout — no -p flag so fping finishes in count*timeout seconds
    proc_timeout = (count * timeout) + 10

    try:
        command = [_FPING_PATH]
        if _is_ipv6(ip):
            command.append("-6")
        command.extend(["-c", str(count), "-t", str(timeout * 1000), ip])
        r = subprocess.run(
            command,
            stdout=subprocess.PIPE,   # per-packet lines + TTL
            stderr=subprocess.PIPE,   # xmt/rcv/%loss summary
            timeout=proc_timeout,
        )
    except subprocess.TimeoutExpired:
        return False, None
    except Exception:
        raise   # let _ping_one fall through to ping

    stdout_text = r.stdout.decode(errors="ignore")
    stderr_text = r.stderr.decode(errors="ignore")

    # ── Step 1: determine alive from stderr summary ──────────────
    # Line format: "ip : xmt/rcv/%loss = 3/0/100%[, min/avg/max = ...]"
    alive = False
    for line in stderr_text.splitlines():
        if "xmt/rcv/%loss =" not in line:
            continue
        try:
            after  = line.split("xmt/rcv/%loss =", 1)[1].strip()
            counts = after.split(",")[0].strip()   # "3/0/100%"
            rcv    = int(counts.split("/")[1].strip())
            alive  = rcv > 0
        except (IndexError, ValueError):
            alive = False
        break   # only one summary line per IP

    if not alive and re.search(r"\b\d+\s+bytes\b", stdout_text, re.IGNORECASE):
        alive = True

    # ── Step 2: parse TTL from stdout per-packet lines ──────────
    # Line format: "ip : [N], 64 bytes, X ms (Y avg, Z% loss)"
    # TTL not shown in fping stdout by default — check anyway
    ttl = None
    for line in stdout_text.splitlines():
        m = re.search(r"ttl[=:](\d+)", line, re.IGNORECASE)
        if m:
            ttl = int(m.group(1))
            break

    return alive, ttl


def _ping_via_system(ip: str, timeout: int, count: int) -> tuple[bool, Optional[int]]:
    """
    OS ping confirmed behaviour on Kali (from debug output):
      - Everything goes to STDOUT
      - Dead:  "3 packets transmitted, 0 received, 100% packet loss"
      - Alive: "3 packets transmitted, 3 received, 0% packet loss"
      - TTL in per-packet lines: "64 bytes from ip: icmp_seq=1 ttl=128 time=22ms"

    Rules:
      - Parse "X received" from stdout — only signal we trust
      - Parse TTL from per-packet lines in stdout
      - Try with -i 0.5 first, fall back without it
      - Never use exit code
    """
    if sys.platform == "win32":
        cmds         = [[_PING_PATH or "ping", "-n", str(count), "-w", str(timeout * 1000), ip]]
        proc_timeout = (count * timeout) + 5
    else:
        if _is_ipv6(ip):
            ping_binary = _PING6_PATH or _PING_PATH or "ping"
            ipv6_flag = [] if _PING6_PATH else ["-6"]
            cmds = [
                [ping_binary, *ipv6_flag, "-c", str(count), "-W", str(timeout), "-i", "0.5", ip],
                [ping_binary, *ipv6_flag, "-c", str(count), "-W", str(timeout), ip],
            ]
            proc_timeout = (count * timeout) + 10
        else:
            cmds = [
                [_PING_PATH or "ping", "-c", str(count), "-W", str(timeout), "-i", "0.5", ip],
                [_PING_PATH or "ping", "-c", str(count), "-W", str(timeout), ip],
            ]
            proc_timeout = (count * timeout) + 10

    stdout_text = ""
    for cmd in cmds:
        try:
            r = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=proc_timeout,
            )
            stdout_text = r.stdout.decode(errors="ignore")
            break
        except subprocess.TimeoutExpired:
            return False, None
        except Exception:
            continue   # try next variant

    if not stdout_text:
        return False, None

    m = re.search(
        r'(?:Received\s*=\s*(\d+)|(\d+)\s+(?:packets?\s+)?received)',
        stdout_text,
        re.IGNORECASE,
    )
    if not m:
        alive = bool(re.search(r'^\s*\d+\s+bytes\s+from\s+', stdout_text, re.IGNORECASE | re.MULTILINE))
    else:
        alive = int(m.group(1) or m.group(2)) > 0

    # Parse TTL from per-packet lines
    ttl = None
    if alive:
        t = re.search(r'ttl[=:](\d+)', stdout_text, re.IGNORECASE)
        if t:
            ttl = int(t.group(1))

    return alive, ttl


def parse_tcp_ports(value: str) -> list[int]:
    ports: list[int] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        bounds = item.split("-", 1)
        try:
            start = int(bounds[0])
            end = int(bounds[-1])
        except ValueError as exc:
            raise ValueError(f"invalid TCP port: {item}") from exc
        if not 1 <= start <= end <= 65535:
            raise ValueError(f"TCP port out of range: {item}")
        if end - start >= 1024:
            raise ValueError(f"TCP port range is too large: {item}")
        ports.extend(range(start, end + 1))
    ports = list(dict.fromkeys(ports))
    if not ports:
        raise ValueError("at least one TCP port is required")
    return ports


def tcp_open_ports(ip: str, ports: list[int], timeout: int) -> list[int]:
    open_ports: list[int] = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                open_ports.append(port)
        except OSError:
            continue
    return open_ports


# ─────────────────────────────────────────────────────────────────
# SINGLE-IP PING  — returns rich result dict
# ─────────────────────────────────────────────────────────────────
def _ping_one(
    ip:           str,
    timeout:      int              = 2,
    count:        int              = 3,
    rate_limiter: Optional[RateLimiter] = None,
    do_dns:       bool             = False,
    tcp_ports:    Optional[list[int]] = None,
    tcp_timeout:  int              = 2,
) -> dict:
    """
    Ping one IP. Cleanly separated fping / OS-ping backends.
    Returns: { ip, alive, ttl, os_guess, hostname, scope, rfc }

    FIX 1: fping and OS ping are mutually exclusive — never both run.
    FIX 2: fping result parsed from stderr, fail-safe to False.
    FIX 3: OS ping falls back without -i flag if rejected by kernel.
    FIX 4: _use_fping() uses cached path, no per-call filesystem search.
    FIX 6: fping uses -p for inter-packet spacing.
    FIX 7: fping exception falls through cleanly to OS ping.
    """
    if rate_limiter:
        rate_limiter.acquire(count)

    icmp_alive: bool = False
    ttl:   Optional[int] = None

    if _use_fping():
        try:
            icmp_alive, ttl = _ping_via_fping(ip, timeout, count)
        except Exception:
            # FIX 7: fping found but failed to execute → fall through to OS ping
            try:
                icmp_alive, ttl = _ping_via_system(ip, timeout, count)
            except Exception:
                icmp_alive, ttl = False, None
    else:
        if _PING_PATH is None and _PING6_PATH is None:
            # No tool available at all
            icmp_alive, ttl = False, None
        else:
            try:
                icmp_alive, ttl = _ping_via_system(ip, timeout, count)
            except Exception:
                icmp_alive, ttl = False, None

    open_tcp_ports = tcp_open_ports(ip, tcp_ports, tcp_timeout) if tcp_ports else []
    alive = icmp_alive or bool(open_tcp_ports)
    os_guess = ttl_to_os(ttl) if icmp_alive else ""
    hostname = reverse_dns(ip) if (alive and do_dns) else ""
    classify = ip_classify(ip)

    return {
        "ip":       ip,
        "alive":    alive,
        "icmp_alive": icmp_alive,
        "tcp_open": open_tcp_ports,
        "ttl":      ttl,
        "os_guess": os_guess,
        "hostname": hostname,
        "scope":    classify["scope"],
        "rfc":      classify["rfc"],
    }


# ─────────────────────────────────────────────────────────────────
# PROGRESS BAR
# ─────────────────────────────────────────────────────────────────
def _progress_bar(done: int, total: int, alive: int, dead: int, width: int = 38):
    pct  = done / total if total else 0
    fill = int(pct * width)
    bar  = f"{C.GREEN}{'█' * fill}{C.DIM}{'░' * (width - fill)}{C.RESET}"
    sys.stdout.write(
        f"\r  [{bar}] {C.BOLD}{pct*100:5.1f}%{C.RESET}  "
        f"{C.DIM}{done}/{total}{C.RESET}  "
        f"{C.GREEN}▲{alive}{C.RESET}  {C.RED}▼{dead}{C.RESET}   "
    )
    sys.stdout.flush()


# ─────────────────────────────────────────────────────────────────
# SCAN ENGINE
# ─────────────────────────────────────────────────────────────────
def run_scan(
    ip_list:      list[str],
    threads:      int         = 20,
    timeout:      int         = 6,
    count:        int         = 8,
    retry:        int         = 0,
    rate:         int         = 0,
    label:        str         = "scan",
    quiet:        bool        = False,
    do_dns:       bool        = False,
    resume:       bool        = False,
    tcp_ports:    Optional[list[int]] = None,
    tcp_timeout:  int         = 2,
) -> list[dict]:
    """
    Scan all IPs. Returns list of result dicts.
    Supports: retry, rate-limit, resume (Ctrl+C safe), DNS, TTL.
    """
    # ── resume: skip already-done IPs ───────────────────────────
    done_results: list[dict] = []
    partial = load_partial(label) if resume else None
    if partial:
        done_ips  = {r["ip"] for r in partial["done"]}
        done_results = partial["done"]
        ip_list   = [ip for ip in ip_list if ip not in done_ips]
        print(f"  {C.YELLOW}↺  Resuming — {len(done_results)} already done, "
              f"{len(ip_list)} remaining{C.RESET}")

    total   = len(ip_list)
    if total == 0:
        print(f"  {C.LIME}✔  All IPs already scanned (resume complete).{C.RESET}")
        clear_partial(label)
        return done_results

    rl        = RateLimiter(rate) if rate > 0 else None
    results:  list[dict] = []
    done_n    = 0
    t_start   = time.time()
    interrupted = False

    est_sec = (total / max(threads, 1)) * (timeout + 1)
    rate_str = f"  rate≤{rate}pkt/s" if rate > 0 else ""
    retry_str = f"  retry={retry}" if retry > 0 else ""
    dns_str  = "  +dns" if do_dns else ""
    tcp_str  = f"  tcp={','.join(str(port) for port in tcp_ports)}" if tcp_ports else ""
    print(
        f"\n  {C.CYAN}⠿ Scanning {C.BOLD}{total:,}{C.RESET}{C.CYAN} hosts"
        f"  │  threads={C.BOLD}{threads}{C.RESET}{C.CYAN}"
        f"  timeout={timeout}s  pkt/host={count}"
        f"{retry_str}{rate_str}{dns_str}{tcp_str}"
        f"  est≈{est_sec:.0f}s{C.RESET}\n"
    )

    # ── Ctrl+C handler: save partial and exit gracefully ────────
    def _sigint(sig, frame):
        nonlocal interrupted
        interrupted = True
        sys.stdout.write(f"\n\n  {C.YELLOW}⚠  Interrupted — saving partial results...{C.RESET}\n")
        sys.stdout.flush()

    old_handler = signal.signal(signal.SIGINT, _sigint)

    try:
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(_ping_one, ip, timeout, count, rl, do_dns, tcp_ports, tcp_timeout): ip
                for ip in ip_list
            }
            for fut in as_completed(futures):
                if interrupted:
                    # Cancel remaining futures
                    for f in futures:
                        f.cancel()
                    break

                try:
                    res = fut.result()
                except Exception as exc:
                    ip = futures[fut]
                    classify = ip_classify(ip)
                    res = {
                        "ip": ip, "alive": False, "ttl": None, "os_guess": "",
                        "icmp_alive": False, "tcp_open": [], "hostname": "",
                        "scope": classify["scope"], "rfc": classify["rfc"],
                    }
                    if not quiet:
                        print(C.warn(f"\n  ⚠  Scan failed for {ip}: {exc}"))
                ip     = res["ip"]
                alive  = res["alive"]
                done_n += 1

                # ── retry logic: re-ping dead hosts once ────────
                if not alive and retry > 0:
                    for _ in range(retry):
                        res2 = _ping_one(ip, timeout, count, rl, do_dns, tcp_ports, tcp_timeout)
                        if res2["alive"]:
                            res = res2
                            break

                results.append(res)

                if res["alive"]:
                    if not quiet:
                        os_g = res["os_guess"]
                        ttl_s = f"TTL={res['ttl']}" if res["ttl"] else "TTL=?"
                        reach_s = "ICMP" if res["icmp_alive"] else f"TCP:{','.join(str(port) for port in res['tcp_open'])}"
                        dns_s = f"  {C.DIM}{res['hostname'][:28]}{C.RESET}" if res["hostname"] else ""
                        oscol = ttl_color(os_g)
                        sys.stdout.write(
                            f"\r  {C.GREEN}✔ {ip:<18}{C.RESET}"
                            f"  {C.DIM}{reach_s:<12} {ttl_s:<8}{C.RESET}"
                            f"  {oscol}{os_g:<16}{C.RESET}"
                            f"  {C.CYAN}[{res['scope']}]{C.RESET}"
                            f"{dns_s}\n"
                        )
                        sys.stdout.flush()
                elif not quiet:
                    sys.stdout.write(
                        f"\r  {C.RED}✘ {ip:<18}{C.RESET}"
                        f"  {C.DIM}{'NO RESPONSE':<12} {'TTL=?':<8}{C.RESET}"
                        f"  {C.DIM}{'Unknown':<16}{C.RESET}"
                        f"  {C.CYAN}[{res['scope']}]{C.RESET}\n"
                    )
                    sys.stdout.flush()
                _progress_bar(done_n, total, sum(1 for r in results if r["alive"]),
                              sum(1 for r in results if not r["alive"]))

    finally:
        signal.signal(signal.SIGINT, old_handler)

    elapsed = time.time() - t_start

    if interrupted:
        # Save what we have so far for resume
        remaining = [ip for ip in ip_list if ip not in {r["ip"] for r in results}]
        all_done  = done_results + results
        save_partial(label, all_done, remaining)
        print(f"  {C.YELLOW}Partial results saved. Re-run with --resume to continue.{C.RESET}\n")
        # Return what we have so alive/dead files are still written
        return all_done

    print(f"\n\n  {C.DIM}Scan finished in {elapsed:.1f}s{C.RESET}\n")
    clear_partial(label)

    # Merge with any previously-resumed results
    all_results = done_results + results

    # Sort by IP
    try:
        all_results.sort(key=lambda r: ipaddress.ip_address(r["ip"]))
    except Exception:
        all_results.sort(key=lambda r: r["ip"])

    return all_results


# ─────────────────────────────────────────────────────────────────
# WRITE OUTPUT FILES  (plain + rich CSV + JSON)
# ─────────────────────────────────────────────────────────────────
def write_results(
    results:    list[dict],
    alive_file: str  = "alive.txt",
    dead_file:  str  = "dead.txt",
    out_format: str  = "txt",
):
    alive = [r for r in results if r["alive"]]
    dead  = [r for r in results if not r["alive"]]
    total = len(results)
    pct_a = (len(alive) / total * 100) if total else 0
    pct_d = (len(dead)  / total * 100) if total else 0

    if out_format == "json":
        Path(alive_file).write_text(json.dumps([r for r in alive], indent=2) + "\n")
        Path(dead_file).write_text(json.dumps([r for r in dead],  indent=2) + "\n")
    elif out_format == "csv":
        fields = ["ip", "alive", "icmp_alive", "tcp_open", "ttl", "os_guess", "hostname", "scope", "rfc"]
        for path, rows in ((alive_file, alive), (dead_file, dead)):
            with Path(path).open("w", newline="") as output:
                writer = csv.DictWriter(output, fieldnames=fields)
                writer.writeheader()
                writer.writerows(
                    {
                        field: ";".join(str(port) for port in row.get("tcp_open", []))
                        if field == "tcp_open" else row.get(field, "")
                        for field in fields
                    }
                    for row in rows
                )
    else:  # txt — plain IPs, one per line
        Path(alive_file).write_text("\n".join(r["ip"] for r in alive) + ("\n" if alive else ""))
        Path(dead_file).write_text("\n".join(r["ip"] for r in dead)  + ("\n" if dead  else ""))

    box_w = 58
    div   = f"  {C.CYAN}{'─' * box_w}{C.RESET}"
    print(f"\n  {C.BOLD}{C.LIME}┌{'─' * (box_w + 2)}┐")
    print(f"  │{'  📊  SCAN RESULTS':^{box_w + 2}}│")
    print(f"  └{'─' * (box_w + 2)}┘{C.RESET}")
    print(div)
    print(f"  {C.DIM}│{C.RESET}  {'Total scanned':<28}{C.BOLD}{C.WHITE}{total:>6}{C.RESET}")
    print(f"  {C.DIM}│{C.RESET}  {C.GREEN}{'Reachable (ICMP/TCP)':<28}{C.BOLD}{len(alive):>6}{C.RESET}  {C.DIM}({pct_a:.1f}%){C.RESET}")
    print(f"  {C.DIM}│{C.RESET}  {C.RED}{'No ICMP/TCP response':<28}{C.BOLD}{len(dead):>6}{C.RESET}  {C.DIM}({pct_d:.1f}%){C.RESET}")
    print(div)

    # OS breakdown from TTL
    os_counts: dict[str, int] = {}
    for r in alive:
        g = r.get("os_guess") or "Unknown"
        os_counts[g] = os_counts.get(g, 0) + 1
    if os_counts:
        print(f"  {C.DIM}│{C.RESET}  {C.BOLD}OS fingerprint (TTL-based):{C.RESET}")
        for os_g, cnt in sorted(os_counts.items(), key=lambda x: -x[1]):
            col = ttl_color(os_g)
            print(f"  {C.DIM}│{C.RESET}    {col}{os_g:<20}{C.RESET}  {C.BOLD}{cnt}{C.RESET}")
        print(div)

    print(f"  {C.DIM}│{C.RESET}  {C.CYAN}alive → {alive_file}  ({out_format}){C.RESET}")
    print(f"  {C.DIM}│{C.RESET}  {C.CYAN}dead  → {dead_file}  ({out_format}){C.RESET}")
    print(div)

    if total:
        bar_w = 40
        n   = int(pct_a / 100 * bar_w)
        bar = f"{C.GREEN}{'█' * n}{C.RED}{'█' * (bar_w - n)}{C.RESET}"
        print(f"\n  Alive/Dead ratio:  {bar}  {C.GREEN}{pct_a:.0f}%{C.RESET} alive\n")


# ─────────────────────────────────────────────────────────────────
# HISTORY COMPARISON
# ─────────────────────────────────────────────────────────────────
def compare_history(label: str, current_alive: list[str], current_dead: list[str]):
    history = load_history(label)
    if len(history) < 2:
        print(f"\n  {C.warn('⚠  Not enough history for comparison (need ≥ 2 scans).')}")
        return

    prev       = history[-2]
    prev_alive = set(prev.get("alive", []))
    curr_alive = set(current_alive)
    curr_dead  = set(current_dead)
    prev_dead  = set(prev.get("dead",  []))
    prev_ts    = prev.get("timestamp", "unknown")

    newly_up   = sorted(curr_alive - prev_alive)
    newly_down = sorted(prev_alive - curr_alive)
    stayed_up  = sorted(curr_alive & prev_alive)
    stayed_dn  = sorted(curr_dead  & prev_dead)

    box_w = 60
    div   = f"  {C.PURPLE}{'─' * box_w}{C.RESET}"
    print(f"\n  {C.BOLD}{C.PURPLE}┌{'─' * (box_w + 2)}┐")
    print(f"  │{'  🕐  HISTORY COMPARISON':^{box_w + 2}}│")
    print(f"  └{'─' * (box_w + 2)}┘{C.RESET}")
    print(div)
    print(f"  {C.DIM}Previous scan : {prev_ts}{C.RESET}")
    print(f"  {C.DIM}Current scan  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")
    print(div)
    print(f"  {C.GREEN}  ↑ Newly UP      : {len(newly_up):>4}{C.RESET}")
    print(f"  {C.RED}  ↓ Newly DOWN    : {len(newly_down):>4}{C.RESET}")
    print(f"  {C.LIME}  ✔ Stayed ALIVE  : {len(stayed_up):>4}{C.RESET}")
    print(f"  {C.DIM}  ✘ Stayed DEAD   : {len(stayed_dn):>4}{C.RESET}")
    print(div)

    if newly_up:
        print(f"\n  {C.GREEN}{C.BOLD}⬆  Hosts that came ONLINE:{C.RESET}")
        for ip in newly_up:
            print(f"     {C.GREEN}+ {ip}{C.RESET}")
    if newly_down:
        print(f"\n  {C.RED}{C.BOLD}⬇  Hosts that went OFFLINE:{C.RESET}")
        for ip in newly_down:
            print(f"     {C.RED}✘ {ip}{C.RESET}")
    if not newly_up and not newly_down:
        print(f"\n  {C.LIME}  No changes since last scan.{C.RESET}")

    if len(history) >= 2:
        print(f"\n  {C.BOLD}{C.CYAN}Full Scan History — Alive Counts:{C.RESET}")
        max_alive = max(len(s.get("alive", [])) for s in history) or 1
        for i, s in enumerate(history, 1):
            cnt  = len(s.get("alive", []))
            ts_s = s.get("timestamp", "?")[:16]
            bw   = 30
            n    = int(cnt / max_alive * bw)
            bar  = f"{C.GREEN}{'█' * n}{C.DIM}{'░' * (bw - n)}{C.RESET}"
            mark = "◀ current" if i == len(history) else ""
            print(f"  {C.DIM}#{i:02d}{C.RESET}  {C.DIM}{ts_s}{C.RESET}  {bar}  {C.BOLD}{cnt:>4}{C.RESET}  {C.YELLOW}{mark}{C.RESET}")
    print()


# ─────────────────────────────────────────────────────────────────
# DIFF TWO FILES
# ─────────────────────────────────────────────────────────────────
def diff_files(file_a: str, file_b: str):
    def read_ips(path: str) -> set[str]:
        p = Path(path)
        if not p.exists():
            print(C.err(f"  ✗ File not found: {path}")); sys.exit(1)
        return {l.strip() for l in p.read_text().splitlines() if l.strip()}

    ips_a = read_ips(file_a); ips_b = read_ips(file_b)
    only_a = sorted(ips_a - ips_b); only_b = sorted(ips_b - ips_a)
    common = sorted(ips_a & ips_b)

    box_w = 60
    div   = f"  {C.PURPLE}{'─' * box_w}{C.RESET}"
    print(f"\n  {C.BOLD}{C.PURPLE}┌{'─' * (box_w + 2)}┐")
    print(f"  │{'  📂  FILE DIFF COMPARISON':^{box_w + 2}}│")
    print(f"  └{'─' * (box_w + 2)}┘{C.RESET}")
    print(div)
    print(f"  {C.DIM}File A: {file_a}  ({len(ips_a)} IPs){C.RESET}")
    print(f"  {C.DIM}File B: {file_b}  ({len(ips_b)} IPs){C.RESET}")
    print(div)
    print(f"  {C.LIME}  In A only (went offline) : {len(only_a)}")
    print(f"  {C.GREEN}  In B only (came online)  : {len(only_b)}{C.RESET}")
    print(f"  {C.DIM}  In both                  : {len(common)}{C.RESET}")
    print(div)
    if only_a:
        print(f"\n  {C.RED}{C.BOLD}✘  Only in {file_a}:{C.RESET}")
        for ip in only_a: print(f"     {C.RED}- {ip}{C.RESET}")
    if only_b:
        print(f"\n  {C.GREEN}{C.BOLD}+  Only in {file_b}:{C.RESET}")
        for ip in only_b: print(f"     {C.GREEN}+ {ip}{C.RESET}")
    if not only_a and not only_b:
        print(f"\n  {C.LIME}  Identical — no change.{C.RESET}")
    print()


# ─────────────────────────────────────────────────────────────────
# READ TARGETS
# ─────────────────────────────────────────────────────────────────
def _extract_ip_addresses(text: str) -> list[str]:
    """Extract unique IPv4/IPv6 addresses from command output."""
    addresses: list[str] = []

    # IPv4 is intentionally parsed separately. It is the most common result
    # from Windows DNS, ping, nslookup, LLMNR, and NetBIOS resolution.
    for candidate in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", text):
        try:
            address = str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
        if address not in addresses:
            addresses.append(address)

    # IPv6 tokens may include a scope identifier such as %12.
    for token in re.findall(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:%\d+)?(?![0-9A-Fa-f:])", text):
        candidate = token.split("%", 1)[0].strip("[](),")
        try:
            address = str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
        if address not in addresses:
            addresses.append(address)

    return addresses


def _run_resolution_command(command: list[str], timeout: int = 8) -> str:
    """Run a resolver command and decode Windows output robustly."""
    try:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""

    raw = proc.stdout or b""
    for encoding in ("utf-8", "utf-16", "cp1252", "cp437", "mbcs"):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode(errors="ignore")


def _resolve_with_windows_tools(hostname: str) -> list[str]:
    """Resolve Windows DNS/search-suffix/LLMNR/NetBIOS names.

    The host does not need to answer ICMP. Windows ping prints the resolved
    address before sending packets, so its header is enough for discovery.
    """
    if sys.platform != "win32":
        return []

    hostname = hostname.strip().strip('"').strip("'")
    if not hostname:
        return []

    commands: list[tuple[str, list[str]]] = []
    powershell = shutil.which("powershell.exe") or shutil.which("powershell") or shutil.which("pwsh.exe") or shutil.which("pwsh")
    if powershell:
        escaped = hostname.replace("'", "''")
        # System.Net.Dns and Resolve-DnsName use the Windows DNS client and
        # therefore respect connection-specific DNS suffixes.
        commands.append(("powershell-dns", [
            powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
            f"[System.Net.Dns]::GetHostAddresses('{escaped}') | ForEach-Object {{ $_.IPAddressToString }}",
        ]))
        commands.append(("resolve-dnsname", [
            powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
            f"Resolve-DnsName -Name '{escaped}' -ErrorAction SilentlyContinue | "
            "Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress }",
        ]))

    ping_binary = shutil.which("ping.exe") or shutil.which("ping") or "ping"
    commands.append(("ping4", [ping_binary, "-4", "-n", "1", "-w", "1000", hostname]))
    commands.append(("ping6", [ping_binary, "-6", "-n", "1", "-w", "1000", hostname]))

    nslookup = shutil.which("nslookup.exe") or shutil.which("nslookup")
    if nslookup:
        commands.append(("nslookup", [nslookup, hostname]))

    # nbtstat can resolve short Windows computer names on LANs where DNS is
    # incomplete but NetBIOS name service is available.
    nbtstat = shutil.which("nbtstat.exe") or shutil.which("nbtstat")
    if nbtstat:
        commands.append(("nbtstat", [nbtstat, "-a", hostname]))

    for kind, command in commands:
        output = _run_resolution_command(command)
        if not output:
            continue

        # Prefer the address shown in the Windows ping header. This avoids
        # accidentally taking a DNS server address from nslookup output.
        if kind.startswith("ping"):
            match = re.search(r"^\s*Pinging\s+.+?\s+\[([^\]]+)\]", output, re.IGNORECASE | re.MULTILINE)
            if match:
                candidate = match.group(1).split("%", 1)[0]
                try:
                    return [str(ipaddress.ip_address(candidate))]
                except ValueError:
                    pass

        found = _extract_ip_addresses(output)
        if not found:
            continue

        if kind == "nslookup":
            # nslookup commonly prints the DNS server first. The answer is at
            # the end, so use the last unique address.
            return [found[-1]]
        return found

    return []


def _resolve_with_getent(hostname: str) -> list[str]:
    """Resolve through the system NSS database using getent when available."""
    getent = shutil.which("getent")
    if not getent:
        return []

    addresses: list[str] = []
    for database in ("hosts", "ahosts"):
        output = _run_resolution_command([getent, database, hostname], timeout=8)
        if not output:
            continue
        for line in output.splitlines():
            fields = line.split()
            if not fields:
                continue
            candidate = fields[0].split("%", 1)[0]
            try:
                address = str(ipaddress.ip_address(candidate))
            except ValueError:
                continue
            if address not in addresses:
                addresses.append(address)
        if addresses:
            break
    return addresses


def resolve_hostname(hostname: str) -> list[str]:
    """Resolve names through Python, system NSS, and Windows LAN providers."""
    hostname = hostname.strip().strip('"').strip("'")
    if not hostname:
        return []

    addresses: list[str] = []

    # Use the broadest getaddrinfo form. Supplying SOCK_DGRAM can prevent some
    # Windows name providers from participating in resolution.
    try:
        records = socket.getaddrinfo(hostname, None)
    except (OSError, UnicodeError, socket.gaierror):
        records = []

    for _family, _type, _proto, _canonname, sockaddr in records:
        if not sockaddr:
            continue
        candidate = str(sockaddr[0]).split("%", 1)[0]
        try:
            address = str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
        if address not in addresses:
            addresses.append(address)

    # Additional legacy API. On some corporate Windows endpoints this succeeds
    # for short hostnames even when getaddrinfo does not.
    if not addresses:
        try:
            _canonical, _aliases, legacy = socket.gethostbyname_ex(hostname)
        except (OSError, UnicodeError, socket.gaierror):
            legacy = []
        for candidate in legacy:
            try:
                address = str(ipaddress.ip_address(candidate))
            except ValueError:
                continue
            if address not in addresses:
                addresses.append(address)

    # getent follows the system NSS configuration (DNS, /etc/hosts, mDNS,
    # winbind and other configured providers). This mirrors the known-good
    # shell workflow used by PingMe users.
    if not addresses:
        addresses.extend(_resolve_with_getent(hostname))

    if not addresses:
        addresses.extend(_resolve_with_windows_tools(hostname))

    return list(dict.fromkeys(addresses))

def show_host_resolution(rows: list[dict], source: str) -> None:
    """Display original file entries and their resolved IP addresses."""
    if not rows:
        return

    display_rows = [row for row in rows if row.get("ip")]
    if not display_rows:
        return

    host_w = min(34, max(12, max(len(str(row["host"])) for row in display_rows)))
    ip_w = min(45, max(15, max(len(str(row["ip"])) for row in display_rows)))
    type_w = 12
    line = f"  {C.CYAN}+{'-'*(host_w+2)}+{'-'*(ip_w+2)}+{'-'*(type_w+2)}+{C.RESET}"
    print(f"\n  {C.BOLD}{C.MAGENTA}HOST RESOLUTION · {source}{C.RESET}")
    print(line)
    print(f"  {C.CYAN}|{C.RESET} {C.BOLD}{'HOST':<{host_w}}{C.RESET} {C.CYAN}|{C.RESET} "
          f"{C.BOLD}{'IP ADDRESS':<{ip_w}}{C.RESET} {C.CYAN}|{C.RESET} "
          f"{C.BOLD}{'TYPE':<{type_w}}{C.RESET} {C.CYAN}|{C.RESET}")
    print(line)
    for row in display_rows:
        row_type = str(row.get("type", "DNS"))
        kind_color = C.LIME if row_type == "DNS" else (C.YELLOW if row_type == "DIRECT IP" else C.RED)
        print(f"  {C.CYAN}|{C.RESET} {str(row['host'])[:host_w]:<{host_w}} {C.CYAN}|{C.RESET} "
              f"{C.WHITE}{str(row['ip'])[:ip_w]:<{ip_w}}{C.RESET} {C.CYAN}|{C.RESET} "
              f"{kind_color}{row_type[:type_w]:<{type_w}}{C.RESET} {C.CYAN}|{C.RESET}")
    print(line + "\n")


def build_file_status_records(rows: list[dict], results: list[dict]) -> list[dict]:
    """Build plain status records for file-mode display and reports."""
    by_ip = {str(result.get("ip")): result for result in results}
    records: list[dict] = []

    for row in rows:
        host = str(row.get("host", ""))
        ip_value = str(row.get("ip") or "UNRESOLVED")
        row_type = str(row.get("type", "DNS"))
        excluded = bool(row.get("excluded"))

        if row_type == "UNRESOLVED" or ip_value == "UNRESOLVED":
            status = "UNRESOLVED"
            method = "-"
            ttl = "-"
            os_guess = "-"
        elif excluded:
            status = "EXCLUDED"
            method = "-"
            ttl = "-"
            os_guess = "-"
        else:
            result = by_ip.get(ip_value)
            if result is None:
                status = "NOT SCANNED"
                method = "-"
                ttl = "-"
                os_guess = "-"
            else:
                alive = bool(result.get("alive"))
                status = "REACHABLE" if alive else "NO RESPONSE"
                if result.get("icmp_alive"):
                    method = "ICMP"
                elif result.get("tcp_open"):
                    method = "TCP:" + ",".join(str(port) for port in result.get("tcp_open", []))
                else:
                    method = "-"
                ttl_value = result.get("ttl")
                ttl = str(ttl_value) if ttl_value is not None else "?"
                os_guess = str(result.get("os_guess") or "Unknown")

        records.append({
            "host": host,
            "ip": ip_value,
            "status": status,
            "method": method,
            "ttl": ttl,
            "os_guess": os_guess,
        })

    return records


def _status_counts(records: list[dict]) -> dict[str, int]:
    return {
        "reachable": sum(1 for record in records if record["status"] == "REACHABLE"),
        "no_response": sum(1 for record in records if record["status"] == "NO RESPONSE"),
        "unresolved": sum(1 for record in records if record["status"] == "UNRESOLVED"),
        "other": sum(1 for record in records if record["status"] in {"EXCLUDED", "NOT SCANNED"}),
    }


def _plain_table(records: list[dict], title: str) -> str:
    """Return a portable ASCII table with no ANSI escape sequences."""
    headers = ["HOST", "IP ADDRESS", "STATUS", "METHOD", "TTL", "OS GUESS"]
    keys = ["host", "ip", "status", "method", "ttl", "os_guess"]
    minimums = [12, 15, 13, 18, 5, 18]
    maximums = [40, 48, 16, 24, 8, 24]

    widths: list[int] = []
    for header, key, minimum, maximum in zip(headers, keys, minimums, maximums):
        longest = max([len(header)] + [len(str(record.get(key, ""))) for record in records])
        widths.append(min(max(minimum, longest), maximum))

    line = "+" + "+".join("-" * (width + 2) for width in widths) + "+"
    output = [title, "", line]
    output.append("| " + " | ".join(f"{header:<{width}}" for header, width in zip(headers, widths)) + " |")
    output.append(line)
    for record in records:
        values = [str(record.get(key, ""))[:width] for key, width in zip(keys, widths)]
        output.append("| " + " | ".join(f"{value:<{width}}" for value, width in zip(values, widths)) + " |")
    output.append(line)

    counts = _status_counts(records)
    summary = (
        f"Reachable: {counts['reachable']}  "
        f"No response: {counts['no_response']}  "
        f"Unresolved: {counts['unresolved']}"
    )
    if counts["other"]:
        summary += f"  Not scanned/excluded: {counts['other']}"
    output.extend([summary, ""])
    return "\n".join(output)


def write_hostnames_report(
    records: list[dict],
    source: str,
    output_file: str = "hostnames.txt",
) -> Path:
    """Save HOST, IP, STATUS, METHOD, TTL, and OS details after every file scan."""
    destination = Path(output_file).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    report = _plain_table(records, f"FILE SCAN STATUS · {source}")
    destination.write_text(report, encoding="utf-8")
    print(f"  {C.CYAN}[report] host details → {destination}{C.RESET}")
    return destination


def _changes_state_file(label: str) -> Path:
    directory = _data_dir()
    directory.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.\-]", "_", label)
    return directory / f".{safe}_changes.json"


def load_changes_state(label: str) -> Optional[dict]:
    path = _changes_state_file(label)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def save_changes_state(label: str, source: str, records: list[dict]) -> None:
    path = _changes_state_file(label)
    path.write_text(json.dumps({
        "source": source,
        "timestamp": datetime.now().isoformat(),
        "records": records,
    }, indent=2), encoding="utf-8")


def _compact_host_table(title: str, records: list[dict]) -> list[str]:
    host_w = min(40, max(12, max([len("HOST")] + [len(str(r.get("host", ""))) for r in records])))
    ip_w = min(48, max(15, max([len("IP ADDRESS")] + [len(str(r.get("ip", ""))) for r in records])))
    line = "+" + "-" * (host_w + 2) + "+" + "-" * (ip_w + 2) + "+"
    lines = [title, line, f"| {'HOST':<{host_w}} | {'IP ADDRESS':<{ip_w}} |", line]
    for record in records:
        lines.append(f"| {str(record.get('host', ''))[:host_w]:<{host_w}} | {str(record.get('ip', ''))[:ip_w]:<{ip_w}} |")
    lines.append(line)
    return lines


def create_changes_report(
    previous: Optional[dict],
    current_records: list[dict],
    source: str,
) -> tuple[str, dict[str, list[dict]]]:
    """Create a simple, hostname-aware comparison report."""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    current_map = {(r["host"], r["ip"]): r for r in current_records}
    groups: dict[str, list[dict]] = {
        "newly_online": [],
        "went_offline": [],
        "new_targets": [],
        "removed_targets": [],
        "still_online": [],
        "still_offline": [],
    }

    if not previous:
        counts = _status_counts(current_records)
        text = "\n".join([
            f"CHANGE TRACKING · {source}",
            "",
            "This is the first scan for this file.",
            "PingMe saved the current result for future comparison.",
            "",
            f"Current scan : {current_time}",
            f"Online       : {counts['reachable']}",
            f"Offline      : {counts['no_response']}",
            f"Unresolved   : {counts['unresolved']}",
            "",
            "Run the same command again with --changes to see what changed.",
            "",
        ])
        return text, groups

    previous_records = previous.get("records", []) if isinstance(previous, dict) else []
    previous_map = {
        (str(r.get("host", "")), str(r.get("ip", ""))): r
        for r in previous_records if isinstance(r, dict)
    }

    for key, current in current_map.items():
        old = previous_map.get(key)
        if old is None:
            groups["new_targets"].append(current)
            continue
        old_online = old.get("status") == "REACHABLE"
        now_online = current.get("status") == "REACHABLE"
        if not old_online and now_online:
            groups["newly_online"].append(current)
        elif old_online and not now_online:
            groups["went_offline"].append(current)
        elif now_online:
            groups["still_online"].append(current)
        else:
            groups["still_offline"].append(current)

    for key, old in previous_map.items():
        if key not in current_map:
            groups["removed_targets"].append(old)

    previous_time = str(previous.get("timestamp", "unknown")).replace("T", " ")[:19]
    lines = [
        f"CHANGES SINCE LAST SCAN · {source}",
        "",
        f"Previous scan : {previous_time}",
        f"Current scan  : {current_time}",
        "",
    ]

    important = groups["newly_online"] or groups["went_offline"] or groups["new_targets"] or groups["removed_targets"]
    if not important:
        lines.extend([
            "NO CHANGES DETECTED",
            "",
            "All hosts have the same status as the previous scan.",
            "",
        ])
    else:
        if groups["newly_online"]:
            lines.extend(_compact_host_table("NEWLY ONLINE", groups["newly_online"]))
            lines.append("")
        if groups["went_offline"]:
            lines.extend(_compact_host_table("WENT OFFLINE", groups["went_offline"]))
            lines.append("")
        if groups["new_targets"]:
            lines.extend(_compact_host_table("NEW TARGETS ADDED TO FILE", groups["new_targets"]))
            lines.append("")
        if groups["removed_targets"]:
            lines.extend(_compact_host_table("TARGETS REMOVED FROM FILE", groups["removed_targets"]))
            lines.append("")

    current_counts = _status_counts(current_records)
    lines.extend([
        "SUMMARY",
        f"Newly online : {len(groups['newly_online'])}",
        f"Went offline : {len(groups['went_offline'])}",
        f"Still online : {len(groups['still_online'])}",
        f"Still offline: {len(groups['still_offline'])}",
        f"New targets  : {len(groups['new_targets'])}",
        f"Removed      : {len(groups['removed_targets'])}",
        f"Unresolved   : {current_counts['unresolved']}",
        "",
    ])
    return "\n".join(lines), groups


def write_changes_report(
    previous: Optional[dict],
    current_records: list[dict],
    source: str,
    output_file: str = "changes.txt",
) -> Path:
    report, _groups = create_changes_report(previous, current_records, source)
    destination = Path(output_file).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(report, encoding="utf-8")

    # Keep the terminal output easy to understand while the saved report stays plain.
    print(f"\n  {C.BOLD}{C.MAGENTA}{report.splitlines()[0]}{C.RESET}\n")
    for line in report.splitlines()[1:]:
        if line in {"NEWLY ONLINE", "NO CHANGES DETECTED"}:
            print(f"  {C.GREEN}{C.BOLD}{line}{C.RESET}")
        elif line == "WENT OFFLINE":
            print(f"  {C.RED}{C.BOLD}{line}{C.RESET}")
        elif line in {"NEW TARGETS ADDED TO FILE", "TARGETS REMOVED FROM FILE", "SUMMARY"}:
            print(f"  {C.YELLOW}{C.BOLD}{line}{C.RESET}")
        else:
            print(f"  {line}")
    print(f"\n  {C.CYAN}[report] changes → {destination}{C.RESET}\n")
    return destination


def show_file_scan_status(rows: list[dict], results: list[dict], source: str) -> list[dict]:
    """Show every file entry, resolved IP, and final reachability in one table."""
    if not rows:
        return []

    records = build_file_status_records(rows, results)
    host_w = min(40, max(12, max(len(record["host"]) for record in records)))
    ip_w = min(48, max(15, max(len(record["ip"]) for record in records)))
    status_w, method_w, ttl_w, os_w = 13, 18, 5, 18
    widths = [host_w, ip_w, status_w, method_w, ttl_w, os_w]
    line = "  " + C.PURPLE + "+" + "+".join("-" * (width + 2) for width in widths) + "+" + C.RESET

    print(f"\n  {C.BOLD}{C.MAGENTA}FILE SCAN STATUS · {source}{C.RESET}")
    print(line)
    headers = ["HOST", "IP ADDRESS", "STATUS", "METHOD", "TTL", "OS GUESS"]
    print("  " + C.PURPLE + "|" + C.RESET + " " + (" " + C.PURPLE + "|" + C.RESET + " ").join(
        f"{C.BOLD}{header:<{width}}{C.RESET}" for header, width in zip(headers, widths)
    ) + " " + C.PURPLE + "|" + C.RESET)
    print(line)

    for record in records:
        status = record["status"]
        if status == "REACHABLE":
            status_color = C.GREEN
        elif status == "NO RESPONSE":
            status_color = C.RED
        elif status == "UNRESOLVED":
            status_color = C.YELLOW
        else:
            status_color = C.DIM

        os_guess = record["os_guess"]
        values = [
            (record["host"], C.WHITE),
            (record["ip"], C.CYAN if record["ip"] != "UNRESOLVED" else C.YELLOW),
            (status, status_color),
            (record["method"], C.YELLOW),
            (record["ttl"], C.WHITE),
            (os_guess, ttl_color(os_guess) if os_guess not in {"-", "Unknown"} else C.DIM),
        ]
        print("  " + C.PURPLE + "|" + C.RESET + " " + (" " + C.PURPLE + "|" + C.RESET + " ").join(
            f"{color}{str(value)[:width]:<{width}}{C.RESET}" for (value, color), width in zip(values, widths)
        ) + " " + C.PURPLE + "|" + C.RESET)

    print(line)
    counts = _status_counts(records)
    summary = (
        f"  {C.GREEN}Reachable: {counts['reachable']}{C.RESET}  "
        f"{C.RED}No response: {counts['no_response']}{C.RESET}  "
        f"{C.YELLOW}Unresolved: {counts['unresolved']}{C.RESET}"
    )
    if counts["other"]:
        summary += f"  {C.DIM}Not scanned/excluded: {counts['other']}{C.RESET}"
    print(summary + "\n")
    return records

def read_target_file(path: str) -> tuple[list[str], list[dict]]:
    p = Path(path)
    if not p.exists():
        print(C.err(f"  ✗ File not found: {path}")); sys.exit(1)

    targets: list[str] = []
    mappings: list[dict] = []
    bad: list[str] = []

    for raw_line in p.read_text(encoding="utf-8-sig").splitlines():
        entry = raw_line.split("#", 1)[0].strip()
        if not entry:
            continue

        # Accept simple CSV input by using the first column as the hostname/IP.
        if "," in entry:
            entry = entry.split(",", 1)[0].strip()
        entry = entry.strip('"').strip("'").strip()
        if not entry:
            continue

        try:
            address = str(ipaddress.ip_address(entry))
            targets.append(address)
            mappings.append({"host": entry, "ip": address, "type": "DIRECT IP"})
            continue
        except ValueError:
            pass

        resolved = resolve_hostname(entry)
        if resolved:
            for address in resolved:
                targets.append(address)
                mappings.append({"host": entry, "ip": address, "type": "DNS"})
        else:
            bad.append(entry)
            mappings.append({"host": entry, "ip": "UNRESOLVED", "type": "UNRESOLVED"})

    # Remove duplicate host/IP rows and duplicate scan targets while preserving order.
    unique_rows: list[dict] = []
    seen_rows: set[tuple[str, str]] = set()
    for row in mappings:
        key = (str(row["host"]), str(row["ip"]))
        if key not in seen_rows:
            seen_rows.add(key)
            unique_rows.append(row)
    mappings = unique_rows
    targets = list(dict.fromkeys(targets))

    if bad:
        print(f"  {C.YELLOW}⚠  Unresolvable entries in {path}: {len(bad)}{C.RESET}")
        for entry in bad:
            print(f"     {C.RED}✗ {entry}{C.RESET}")

    if not targets:
        # Still show the final file-oriented table so the user can see exactly
        # which hostname failed instead of receiving only a generic error.
        unresolved_records = show_file_scan_status(mappings, [], path)
        write_hostnames_report(unresolved_records, path, "hostnames.txt")
        print(C.err(f"  ✗ No valid IPs or resolvable hostnames found in {path}"))
        sys.exit(1)

    print(f"  {C.CYAN}Loaded {C.BOLD}{len(targets)}{C.RESET}{C.CYAN} resolved targets from {path}{C.RESET}")
    return targets, mappings


def resolve_host_arguments(hostnames: list[str]) -> list[str]:
    """Resolve --host values and fail clearly if none resolve."""
    targets: list[str] = []
    bad: list[str] = []
    for hostname in hostnames:
        try:
            targets.append(str(ipaddress.ip_address(hostname)))
            continue
        except ValueError:
            pass
        resolved = resolve_hostname(hostname)
        if resolved:
            targets.extend(resolved)
        else:
            bad.append(hostname)
    if bad:
        print(C.warn(f"  ⚠  Could not resolve: {', '.join(bad)}"))
    targets = list(dict.fromkeys(targets))
    if not targets:
        print(C.err("  ✗ No valid IPs or resolvable hostnames supplied.")); sys.exit(1)
    return targets


# ─────────────────────────────────────────────────────────────────
# CHECK DEPENDENCIES + TOOL SELECTION  (FIX 5)
# ─────────────────────────────────────────────────────────────────
def check_deps(ping_tool: str = "auto") -> str:
    """
    Detect available ping tools, honour --ping-tool flag, and
    offer an interactive prompt if neither fping nor ping is found.
    Returns the resolved tool name: "fping" | "ping".
    """
    global _PING_TOOL, _FPING_PATH, _PING_PATH, _PING6_PATH

    has_fping = _FPING_PATH is not None
    has_ping  = _PING_PATH is not None or _PING6_PATH is not None

    # ── Print availability ──────────────────────────────────────
    print(f"\n  {C.CYAN}[tools]{C.RESET}")
    print(f"  {C.DIM}┌{'─'*44}┐{C.RESET}")
    if has_fping:
        print(f"  {C.DIM}│{C.RESET}  {C.GREEN}fping  ✔  {_FPING_PATH:<32}{C.RESET}{C.DIM}│{C.RESET}")
    else:
        print(f"  {C.DIM}│{C.RESET}  {C.RED}fping  ✘  not found{'':<26}{C.RESET}{C.DIM}│{C.RESET}")
    if has_ping:
        ping_path = _PING_PATH or _PING6_PATH
        print(f"  {C.DIM}│{C.RESET}  {C.GREEN}ping   ✔  {ping_path:<32}{C.RESET}{C.DIM}│{C.RESET}")
    else:
        print(f"  {C.DIM}│{C.RESET}  {C.RED}ping   ✘  not found{'':<26}{C.RESET}{C.DIM}│{C.RESET}")
    print(f"  {C.DIM}└{'─'*44}┘{C.RESET}")

    # ── Neither available → interactive fallback ────────────────
    if not has_fping and not has_ping:
        print(f"\n  {C.RED}✗ No ping tool found on PATH.{C.RESET}")
        print(f"  {C.YELLOW}Install one of:{C.RESET}")
        print(f"  {C.DIM}  sudo apt install fping   # Debian/Ubuntu/Kali")
        print(f"       sudo dnf install fping   # RHEL/Fedora")
        print(f"       brew install fping       # macOS{C.RESET}")
        sys.exit(3)

    # ── Honour --ping-tool flag ─────────────────────────────────
    if ping_tool == "fping":
        if not has_fping:
            print(f"  {C.RED}✗ --ping-tool=fping requested but fping not found.{C.RESET}")
            sys.exit(3)
        _PING_TOOL = "fping"
    elif ping_tool == "ping":
        if not has_ping:
            print(f"  {C.RED}✗ --ping-tool=ping requested but ping not found.{C.RESET}")
            sys.exit(3)
        _PING_TOOL = "ping"
    else:
        # auto mode: prompt user if both are available
        if has_fping and has_ping and sys.stdin.isatty():
            print(f"\n  {C.BOLD}{C.CYAN}Select ping backend:{C.RESET}")
            print(f"  {C.GREEN}  [1]{C.RESET}  fping  {C.DIM}(faster, better for large subnets){C.RESET}")
            print(f"  {C.YELLOW}  [2]{C.RESET}  ping   {C.DIM}(OS built-in, more compatible){C.RESET}")
            print(f"  {C.DIM}  [↵]  auto-select (fping){C.RESET}\n")
            try:
                choice = input(f"  {C.BOLD}Choice [1/2, default=1]:{C.RESET} ").strip()
            except (EOFError, KeyboardInterrupt):
                choice = ""
            if choice == "2":
                _PING_TOOL = "ping"
                print(f"  {C.YELLOW}→ Using: ping{C.RESET}\n")
            else:
                _PING_TOOL = "fping"
                print(f"  {C.GREEN}→ Using: fping{C.RESET}\n")
        elif has_fping:
            _PING_TOOL = "fping"
        else:
            _PING_TOOL = "ping"

    # Print resolved selection
    tool_label = f"{C.GREEN}fping{C.RESET}" if _PING_TOOL == "fping" else f"{C.YELLOW}ping{C.RESET}"
    print(f"  {C.DIM}Backend:{C.RESET}  {tool_label}")

    return _PING_TOOL


# ─────────────────────────────────────────────────────────────────
# SHOW HISTORY LIST
# ─────────────────────────────────────────────────────────────────
def show_history_list():
    d = _data_dir(); d.mkdir(parents=True, exist_ok=True)
    files = sorted(f for f in d.glob("*.json") if not f.name.startswith("."))
    if not files:
        print(f"  {C.YELLOW}No scan history found.{C.RESET}\n"); return
    box_w = 70
    div   = f"  {C.CYAN}{'─' * box_w}{C.RESET}"
    print(f"\n  {C.BOLD}{C.CYAN}Stored Scan History:{C.RESET}"); print(div)
    for f in files:
        try:
            data  = json.loads(f.read_text())
            n     = len(data); last = data[-1] if data else {}
            ts    = last.get("timestamp", "?")[:16]
            alive = len(last.get("alive", []))
            print(f"  {C.LIME}{f.stem:<30}{C.RESET}  {C.DIM}{n} scans  last: {ts}  alive: {alive}{C.RESET}")
        except Exception:
            print(f"  {C.RED}{f.stem}  (corrupt){C.RESET}")
    print(div + "\n")


# ─────────────────────────────────────────────────────────────────
# CLEAR HISTORY
# ─────────────────────────────────────────────────────────────────
def clear_history(label: str):
    hf = history_file(label)
    if not hf.exists():
        print(C.warn(f"  ⚠  No history found for label: {label}")); return
    hf.unlink()
    print(C.ok(f"  ✔  History cleared for: {label}"))
    # Also clear any leftover resume and simplified comparison state.
    clear_partial(label)
    changes_file = _changes_state_file(label)
    if changes_file.exists():
        changes_file.unlink()


# ─────────────────────────────────────────────────────────────────
# CLI HELP / ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────────
HELP_TOPICS = ("targets", "scan", "discovery", "output", "history", "advanced", "examples")


class ColorArgumentParser(argparse.ArgumentParser):
    """ArgumentParser with ANSI-colored headings, flags, metavars, and examples."""

    def format_help(self) -> str:
        text = super().format_help()
        if not sys.stdout.isatty():
            return text

        # Section headings.
        text = re.sub(
            r"(?m)^(usage:|Targets:|Discovery:|Scan Control:|Output:|History:|Advanced:|Help:|options:)$",
            lambda m: f"{C.BOLD}{C.MAGENTA}{m.group(1)}{C.RESET}",
            text,
        )
        # Option flags. Applied after argparse has aligned the plain text.
        text = re.sub(
            r"(?<![\w])(--?[a-zA-Z][\w-]*)(?=[,\s=]|$)",
            lambda m: f"{C.CYAN}{C.BOLD}{m.group(1)}{C.RESET}",
            text,
        )
        # Common metavars and choice groups.
        text = re.sub(
            r"\b(CIDR|FILE|HOST|IP|PORTS|SEC|PPS|NAME|N|TOPIC|A|B)\b",
            lambda m: f"{C.YELLOW}{m.group(1)}{C.RESET}",
            text,
        )
        text = re.sub(
            r"(\{(?:auto|fping|ping|txt|csv|json)[^}]*\})",
            lambda m: f"{C.ORANGE}{m.group(1)}{C.RESET}",
            text,
        )
        return text


def _topic_header(title: str, description: str) -> None:
    print(f"\n  {C.BOLD}{C.MAGENTA}{title}{C.RESET}")
    print(f"  {C.DIM}{description}{C.RESET}\n")


def print_topic_help(topic: str) -> None:
    """Show focused nested help without changing the existing CLI syntax."""
    topic = topic.lower().strip()
    if topic not in HELP_TOPICS:
        print(C.err(f"  ✗ Unknown help topic: {topic}"))
        print(f"  {C.DIM}Available topics: {', '.join(HELP_TOPICS)}{C.RESET}\n")
        return

    if topic == "targets":
        _topic_header("TARGET SELECTION", "Choose one or more sources of IP addresses or hostnames.")
        rows = [
            ("-s, --sub CIDR", "Analyze a subnet; add --scan to probe its hosts."),
            ("-f, --file FILE", "Read IPs/hostnames from a file; scanning is implied."),
            ("--host HOST ...", "Resolve and scan individual hosts or IP addresses."),
            ("--exclude IP/CIDR ...", "Skip selected IP addresses or complete networks."),
            ("--max-hosts N", "Safety limit for CIDR expansion; default 65,536."),
        ]
    elif topic == "scan":
        _topic_header("SCAN CONTROL", "Tune speed, retries, packet count, and backend behavior.")
        rows = [
            ("--scan", "Run discovery for --sub targets."),
            ("-t, --threads N", "Concurrent workers; default 20."),
            ("--timeout SEC", "Per-packet wait; default 6 seconds."),
            ("--count N", "Packets sent per host; default 8."),
            ("--retry N", "Retry hosts that did not respond."),
            ("--rate PPS", "Global packet-rate limit; 0 means unlimited."),
            ("--fast", "Use 100 threads, 1-second timeout, and 1 packet."),
            ("--resume", "Continue an interrupted scan from saved state."),
            ("--ping-tool auto|fping|ping", "Select the ICMP backend."),
        ]
    elif topic == "discovery":
        _topic_header("DISCOVERY FEATURES", "Add DNS and TCP checks to standard ICMP discovery.")
        rows = [
            ("--dns", "Perform reverse DNS lookups for reachable hosts."),
            ("--tcp-ports PORTS", "Check ports such as 22,80,443 or 8000-8010."),
            ("--tcp-timeout SEC", "TCP connection timeout per port; default 2 seconds."),
            ("--ipinfo IP ...", "Classify addresses as public, private, or special-use."),
        ]
    elif topic == "output":
        _topic_header("OUTPUT", "Control result files, formats, and terminal verbosity.")
        rows = [
            ("--alive-out FILE", "Destination for reachable hosts."),
            ("--dead-out FILE", "Destination for non-responsive hosts."),
            ("--hostnames-out FILE", "Complete HOST/IP/STATUS/METHOD/TTL/OS report (default: hostnames.txt)."),
            ("--changes-out FILE", "Saved change summary when --changes is used (default: changes.txt)."),
            ("--out-format txt|csv|json", "Choose the file format."),
            ("--quiet", "Hide per-host output while retaining progress."),
            ("--no-banner", "Suppress the startup banner."),
            ("--label NAME", "Set a stable label for history and resume data."),
        ]
    elif topic == "history":
        _topic_header("HISTORY AND COMPARISON", "Track changes across scans or compare saved snapshots.")
        rows = [
            ("--history", "List stored scan histories."),
            ("--changes", "Simple hostname-aware comparison with the last file scan."),
            ("--compare", "Legacy IP-only history comparison."),
            ("--diff A B", "Compare two plain-text IP snapshot files."),
            ("--clear-history NAME", "Delete stored history for a label."),
            ("--no-history", "Do not save the current scan."),
        ]
    elif topic == "advanced":
        _topic_header("ADVANCED NOTES", "Operational behavior and safety controls.")
        rows = [
            ("IPv6", "Supported for individual hosts and practical CIDRs."),
            ("Reachability", "A host is alive when ICMP responds or a requested TCP port opens."),
            ("TTL fingerprint", "OS guesses are heuristic and should not be treated as definitive."),
            ("Authorization", "Only scan systems and networks you are authorized to assess."),
        ]
    else:
        _topic_header("EXAMPLES", "Common PingMe workflows.")
        examples = [
            "pingme --sub 192.168.1.0/24",
            "pingme --sub 192.168.1.0/24 --scan",
            "pingme --sub 192.168.1.0/24 --scan --fast",
            "pingme --file targets.txt --dns",
            "pingme --host server.local 10.0.0.10 --tcp-ports 22,443",
            "pingme --file endpoints.txt --changes",
            "pingme --sub 10.0.0.0/24 --scan --compare --label office",
            "pingme --ipinfo 8.8.8.8 192.168.1.1",
            "pingme --diff alive_old.txt alive_new.txt",
        ]
        for command in examples:
            print(f"  {C.CYAN}${C.RESET} {C.BOLD}{command}{C.RESET}")
        print()
        return

    width = max(len(flag) for flag, _ in rows)
    for flag, description in rows:
        print(f"  {C.CYAN}{C.BOLD}{flag:<{width}}{C.RESET}  {description}")
    print()


def build_parser() -> argparse.ArgumentParser:
    examples = (
        f"{C.BOLD}Nested help:{C.RESET}\n"
        "  pingme help targets       Target selection and exclusions\n"
        "  pingme help scan          Threads, retries, speed, and backend\n"
        "  pingme help discovery     ICMP, TCP, DNS, and IP classification\n"
        "  pingme help output        Files, formats, and terminal controls\n"
        "  pingme help history       History, comparison, and diff mode\n"
        "  pingme help examples      Ready-to-run command examples\n\n"
        f"{C.BOLD}Quick examples:{C.RESET}\n"
        "  pingme --sub 192.168.1.0/24\n"
        "  pingme --sub 192.168.1.0/24 --scan --fast\n"
        "  pingme --file targets.txt --dns --tcp-ports 22,80,443\n"
    )

    p = ColorArgumentParser(
        prog="pingme",
        description=(
            f"{C.BOLD}{C.MAGENTA}PingMe v{VERSION}{C.RESET} — advanced ICMP/TCP host discovery, "
            "subnet analysis, history, and IP classification."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
        epilog=examples,
    )

    tg = p.add_argument_group("Targets")
    tg.add_argument("-s", "--sub", metavar="CIDR",
                    help="Analyze a subnet; add --scan to probe its hosts")
    tg.add_argument("-f", "--file", metavar="FILE",
                    help="Scan IPs/hostnames from a file (scan implied)")
    tg.add_argument("--host", metavar="HOST", nargs="+",
                    help="Scan one or more IP addresses or hostnames")
    tg.add_argument("--exclude", metavar="IP/CIDR", nargs="+",
                    help="Skip one or more IP addresses or CIDRs")
    tg.add_argument("--max-hosts", type=int, default=65536, metavar="N",
                    help="Maximum CIDR targets to expand (default: 65536)")

    dg = p.add_argument_group("Discovery")
    dg.add_argument("--scan", action="store_true",
                    help="Run discovery (required with --sub)")
    dg.add_argument("--dns", action="store_true",
                    help="Reverse DNS lookup for reachable hosts")
    dg.add_argument("--tcp-ports", metavar="PORTS",
                    help="TCP checks, e.g. 22,80,443 or 8000-8010")
    dg.add_argument("--tcp-timeout", type=int, default=2, metavar="SEC",
                    help="TCP connect timeout per port (default: 2)")
    dg.add_argument("--ipinfo", metavar="IP", nargs="+",
                    help="Classify IP addresses as public/private/special")

    sg = p.add_argument_group("Scan Control")
    sg.add_argument("-t", "--threads", type=int, default=20, metavar="N",
                    help="Concurrent workers (default: 20)")
    sg.add_argument("--timeout", type=int, default=6, metavar="SEC",
                    help="Per-packet wait seconds (default: 6)")
    sg.add_argument("--count", type=int, default=8, metavar="N",
                    help="Packets per host (default: 8)")
    sg.add_argument("--retry", type=int, default=0, metavar="N",
                    help="Retries for non-responsive hosts (default: 0)")
    sg.add_argument("--rate", type=int, default=0, metavar="PPS",
                    help="Maximum packets/sec; 0 = unlimited")
    sg.add_argument("--ping-tool", default="auto", choices=["auto", "fping", "ping"],
                    help="ICMP backend (default: auto)")
    sg.add_argument("--fast", action="store_true",
                    help="100 threads, 1s timeout, 1 packet")
    sg.add_argument("--resume", action="store_true",
                    help="Resume an interrupted scan")

    og = p.add_argument_group("Output")
    og.add_argument("--alive-out", default="alive.txt", metavar="FILE",
                    help="Reachable-host output file (default: alive.txt)")
    og.add_argument("--dead-out", default="dead.txt", metavar="FILE",
                    help="Non-responsive-host output file (default: dead.txt)")
    og.add_argument("--hostnames-out", default="hostnames.txt", metavar="FILE",
                    help="Complete file-scan table (default: hostnames.txt)")
    og.add_argument("--changes-out", default="changes.txt", metavar="FILE",
                    help="Change report written by --changes (default: changes.txt)")
    og.add_argument("--out-format", default="txt", choices=["txt", "csv", "json"],
                    help="Output format (default: txt)")
    og.add_argument("--label", metavar="NAME",
                    help="History/resume label (default: target-derived)")
    og.add_argument("--quiet", action="store_true",
                    help="Suppress per-host output")
    og.add_argument("--no-banner", action="store_true",
                    help="Suppress the ASCII banner")

    hg = p.add_argument_group("History")
    hg.add_argument("--history", action="store_true",
                    help="List stored scan history")
    hg.add_argument("--changes", action="store_true",
                    help="Compare this file scan with its previous result")
    hg.add_argument("--compare", action="store_true",
                    help="Legacy IP-only comparison with previous scan")
    hg.add_argument("--diff", metavar=("A", "B"), nargs=2,
                    help="Compare two alive-host snapshot files")
    hg.add_argument("--clear-history", metavar="NAME",
                    help="Delete history for a label")
    hg.add_argument("--no-history", action="store_true",
                    help="Do not save this scan to history")

    ag = p.add_argument_group("Advanced")
    ag.add_argument("--help-topic", choices=HELP_TOPICS, metavar="TOPIC",
                    help="Show focused help for one topic")
    ag.add_argument("--help-all", action="store_true",
                    help="Show complete grouped help")

    help_group = p.add_argument_group("Help")
    help_group.add_argument("--version", action="version",
                            version=f"%(prog)s {VERSION} ({BUILD})",
                            help="Show PingMe version and build")
    help_group.add_argument("-h", "--help", action="help",
                            help="Show grouped help and nested-help topics")

    return p


# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────
def main():
    # Keep output visible immediately when launched through wrappers, symlinks,
    # PowerShell, redirected terminals, or CI.
    try:
        sys.stdout.reconfigure(line_buffering=True)
        sys.stderr.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass

    if not sys.stdout.isatty():
        for attr in dir(C):
            if not attr.startswith("_") and isinstance(getattr(C, attr), str):
                setattr(C, attr, "")

    # Nested help syntax: pingme help <topic>
    if len(sys.argv) >= 2 and sys.argv[1] == "help":
        topic = sys.argv[2] if len(sys.argv) >= 3 else "examples"
        print_topic_help(topic)
        return

    parser = build_parser()
    args   = parser.parse_args()

    if args.help_topic:
        print_topic_help(args.help_topic)
        return
    if args.help_all:
        parser.print_help()
        return

    if args.max_hosts < 1:
        parser.error("--max-hosts must be at least 1")
    if args.tcp_ports:
        try:
            args.tcp_ports = parse_tcp_ports(args.tcp_ports)
        except ValueError as exc:
            parser.error(str(exc))
    if (args.file or args.host) and not args.scan:
        args.scan = True
    if args.changes and not args.file:
        parser.error("--changes currently requires --file")

    banner(no_banner=args.no_banner)

    # ── clear history ───────────────────────────────────────────
    if args.clear_history:
        clear_history(args.clear_history); return

    # ── list history ────────────────────────────────────────────
    if args.history:
        show_history_list(); return

    # ── ip classify ─────────────────────────────────────────────
    if args.ipinfo:
        show_ipinfo(args.ipinfo); return

    # ── diff ────────────────────────────────────────────────────
    if args.diff:
        diff_files(args.diff[0], args.diff[1]); return

    # ── need a scan target ──────────────────────────────────────
    if not args.sub and not args.file and not args.host:
        parser.print_help()
        print(f"\n  {C.YELLOW}Tip: use --sub 192.168.1.0/24 --scan, --file targets.txt, or --host example.com{C.RESET}\n")
        sys.exit(0)

    # ── build IP list ───────────────────────────────────────────
    ip_list: list[str] = []
    file_mappings: list[dict] = []
    label = args.label
    subnet_target_count: Optional[int] = None

    if args.sub:
        net     = show_subnet_info(args.sub)
        subnet_target_count = max(net.num_addresses - 2, 0) if net.version == 4 and net.prefixlen <= 30 else net.num_addresses
        if args.scan:
            if subnet_target_count > args.max_hosts:
                print(C.err(
                    f"  ✗ {args.sub} expands to {subnet_target_count:,} targets, exceeding "
                    f"--max-hosts {args.max_hosts:,}. Use a smaller CIDR or raise the limit deliberately."
                ))
                sys.exit(1)
            addresses = net.hosts() if net.version == 4 else iter(net)
            ip_list = [str(host) for host in addresses]
        if not label:
            label = re.sub(r"[/]", "_", args.sub)

    if args.file:
        file_targets, file_mappings = read_target_file(args.file)
        # Always show the original hostname-to-IP mapping before scanning.
        # This makes file mode auditable and prevents users from seeing only
        # anonymous IP addresses during the scan.
        show_host_resolution(file_mappings, args.file)
        ip_list.extend(file_targets)
        if not label:
            label = Path(args.file).stem

    if args.host:
        ip_list.extend(resolve_host_arguments(args.host))
        if not label:
            label = re.sub(r"[^\w.\-]", "_", "_".join(args.host))

    ip_list = list(dict.fromkeys(ip_list))

    # ── apply --exclude ─────────────────────────────────────────
    if args.exclude:
        excluded_ips, excluded_nets = build_exclude_filter(args.exclude)
        before = len(ip_list)
        ip_list = [ip for ip in ip_list if not is_excluded(ip, excluded_ips, excluded_nets)]
        if file_mappings:
            remaining_ips = set(ip_list)
            for row in file_mappings:
                row_ip = str(row.get("ip", ""))
                if row_ip not in {"", "UNRESOLVED"} and row_ip not in remaining_ips:
                    row["excluded"] = True
        skipped = before - len(ip_list)
        if skipped:
            print(f"  {C.DIM}[exclude] Skipped {skipped} IPs{C.RESET}")

    if args.scan and not ip_list:
        print(C.err("  ✗ No scan targets remain after exclusions.")); sys.exit(1)

    # ── scan ────────────────────────────────────────────────────
    if args.scan:
        if not args.tcp_ports or _FPING_PATH or _PING_PATH or _PING6_PATH:
            check_deps(ping_tool=args.ping_tool)

        if args.fast:
            args.threads = 100; args.timeout = 1; args.count = 1
            print(f"  {C.YELLOW}⚡ Fast mode — less accurate on slow/busy hosts.{C.RESET}")

        args.threads = max(1,  min(1000, args.threads))
        args.timeout = max(1,  min(30,   args.timeout))
        args.count   = max(1,  min(20,   args.count))
        args.retry   = max(0,  min(5,    args.retry))
        args.rate    = max(0,           args.rate)
        args.tcp_timeout = max(1, min(30, args.tcp_timeout))

        results = run_scan(
            ip_list,
            threads = args.threads,
            timeout = args.timeout,
            count   = args.count,
            retry   = args.retry,
            rate    = args.rate,
            label   = label,
            quiet   = args.quiet,
            do_dns  = args.dns,
            resume  = args.resume,
            tcp_ports = args.tcp_ports,
            tcp_timeout = args.tcp_timeout,
        )

        alive = [r["ip"] for r in results if r["alive"]]
        dead  = [r["ip"] for r in results if not r["alive"]]

        if args.file and file_mappings:
            status_records = show_file_scan_status(file_mappings, results, args.file)
            write_hostnames_report(status_records, args.file, args.hostnames_out)

            if args.changes:
                previous_changes = load_changes_state(label)
                write_changes_report(previous_changes, status_records, args.file, args.changes_out)
                save_changes_state(label, args.file, status_records)

        write_results(results, args.alive_out, args.dead_out, args.out_format)

        if not args.no_history:
            save_scan(label, results)

        if args.compare:
            compare_history(label, alive, dead)

    elif args.sub and not args.scan:
        print(f"  {C.DIM}Tip: add {C.BOLD}--scan{C.RESET}{C.DIM} to ping all {subnet_target_count or 0:,} hosts.{C.RESET}\n")

    print()


if __name__ == "__main__":
    main()
