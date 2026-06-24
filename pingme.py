#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║              PingMe — Advanced Ping Scanner v3.0 by Madhav       ║
║   Subnet Info · Ping Scan · TTL Fingerprint · Reverse DNS        ║
║   History · Diff · IP Classify · Retry · Resume · Rate-Limit     ║
╚══════════════════════════════════════════════════════════════════╝
"""

import argparse
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


def load_partial(label: str) -> dict | None:
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
def ttl_to_os(ttl: int | None) -> str:
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
        return {"scope": "Loopback",       "color": C.DIM,    "rfc": "RFC 5735", "description": "Loopback (127.0.0.0/8)"}
    if ip.is_link_local:
        return {"scope": "Link-Local",     "color": C.YELLOW, "rfc": "RFC 3927", "description": "Link-local (169.254.0.0/16) — APIPA"}
    if ip.is_multicast:
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
        f"  {C.PURPLE}Advanced Ping Scanner v3.0 By Madhav {C.RESET}  {C.DIM}│{C.RESET}  {C.DIM}{ts}{C.RESET}",
        f"  {C.DIM}{'─' * 70}{C.RESET}",
    ]
    print("\n".join(lines))


# ─────────────────────────────────────────────────────────────────
# SUBNET INFO
# ─────────────────────────────────────────────────────────────────
def show_subnet_info(cidr: str) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        print(C.err(f"\n  ✗ Invalid CIDR: {e}"))
        sys.exit(1)

    total  = max(net.num_addresses - 2, 0)
    hosts_iter = net.hosts()
    first_host = next(hosts_iter, None)
    last_host = None
    if total > 0:
        try:
            last_host = ipaddress.ip_address(int(net.broadcast_address) - 1)
        except Exception:
            last_host = None
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
    print(row("Broadcast Address", str(net.broadcast_address), C.YELLOW))
    print(row("Subnet Mask",       str(net.netmask),           C.WHITE))
    print(row("Wildcard Mask",     str(net.hostmask),          C.WHITE))
    print(row("Prefix Length",     f"/{prefix}",               C.ORANGE))
    print(row("IP Version",        f"IPv{net.version}",        C.CYAN))
    if total > 0:
        print(sep)
        print(row("First Host",       str(first_host),         C.GREEN))
        print(row("Last Host",        str(last_host),          C.GREEN))
        print(row("Total Usable IPs", f"{total:,}",            C.BOLD + C.LIME))
    print(bot)

    bar_w = 32
    pct   = (total / (2 ** (32 - prefix))) * 100 if prefix < 32 else 100
    fill  = max(1, int((prefix / 32) * bar_w))
    bar   = f"{C.TEAL}{'█' * fill}{C.DIM}{'░' * (bar_w - fill)}{C.RESET}"
    print(f"\n  {C.DIM}Prefix /{prefix} usage:{C.RESET}  {bar}  {C.DIM}/{prefix} of /32  ({pct:.1f}% host space){C.RESET}")

    print(f"\n  {C.BOLD}{C.MAGENTA}┌{'─' * BW}┐{C.RESET}")
    print(hdr("📐  SUBNET BREAKDOWN"))
    print(f"  {C.MAGENTA}{C.BOLD}├{'─' * BW}┤{C.RESET}")
    for sub_prefix in [24, 25, 26, 27, 28, 29, 30]:
        if sub_prefix <= prefix:
            continue
        n_subnets  = 2 ** (sub_prefix - prefix)
        hosts_each = max(2 ** (32 - sub_prefix) - 2, 0)
        print(row(f"/{sub_prefix} subnets", f"{n_subnets:>5,}  ×  {hosts_each} hosts each", C.WHITE))
    print(f"  {C.MAGENTA}{C.BOLD}├{'─' * BW}┤{C.RESET}")
    class_label = ("Class A (/8)" if prefix <= 8 else
                   "Class B (/16)" if prefix <= 16 else
                   "Class C (/24)" if prefix <= 24 else "Subnetted")
    scope = f"{'Private' if net.is_private else 'Public'} · {class_label}"
    print(row("Address Scope",           scope,                   C.PINK))
    print(row("Total IPs (incl. net+bc)", f"{2**(32-prefix):,}", C.DIM + C.WHITE))
    print(f"  {C.MAGENTA}{C.BOLD}└{'─' * BW}┘{C.RESET}\n")
    return net


# ─────────────────────────────────────────────────────────────────
# EXCLUDE FILTER
# ─────────────────────────────────────────────────────────────────
def build_exclude_set(exclude_args: list[str]) -> set[str]:
    """Parse --exclude values (IPs or CIDRs) into a set of IP strings."""
    excluded: set[str] = set()
    for item in (exclude_args or []):
        item = item.strip()
        try:
            # Try as CIDR first
            net = ipaddress.ip_network(item, strict=False)
            excluded.update(str(h) for h in net.hosts())
            excluded.add(str(net.network_address))
            excluded.add(str(net.broadcast_address))
        except ValueError:
            try:
                excluded.add(str(ipaddress.ip_address(item)))
            except ValueError:
                print(C.warn(f"  ⚠  Invalid --exclude value ignored: {item}"))
    return excluded


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
# TOOL SELECTION
# ─────────────────────────────────────────────────────────────────
# Resolved once at startup by check_deps(); never changes after that.
_BACKEND: str = "none"   # "fping" | "ping" | "none"


def _ping_one(
    ip:           str,
    timeout:      int              = 2,
    count:        int              = 3,
    rate_limiter: "RateLimiter | None" = None,
    do_dns:       bool             = False,
) -> dict:
    """
    Ping one IP using whichever backend check_deps() selected.

    DESIGN RULES (no more false positives):
      - fping and OS ping NEVER both run for the same IP.
      - We ONLY parse actual received-packet counts from output text.
        Exit codes are NEVER trusted (fping exits 0 on ICMP-unreachable).
      - subprocess timeout is always generously larger than the actual
        time fping/ping needs, so partial output never leaks through.
      - NO -p flag on fping (was causing premature subprocess timeout
        which killed fping mid-run, leaving partial xmt/rcv in stderr
        that showed false rcv>0 counts).
    """
    if rate_limiter:
        rate_limiter.acquire(count)

    alive: bool       = False
    ttl:   int | None = None

    if _BACKEND == "fping":
        alive, ttl = _run_fping(ip, timeout, count)
    elif _BACKEND == "ping":
        alive, ttl = _run_ping(ip, timeout, count)
    # else "none" → alive stays False

    os_guess = ttl_to_os(ttl) if alive else ""
    hostname  = reverse_dns(ip) if (alive and do_dns) else ""
    classify  = ip_classify(ip)

    return {
        "ip":       ip,
        "alive":    alive,
        "ttl":      ttl,
        "os_guess": os_guess,
        "hostname": hostname,
        "scope":    classify["scope"],
        "rfc":      classify["rfc"],
    }


def _run_fping(ip: str, timeout: int, count: int) -> tuple[bool, int | None]:
    """
    Run fping for one IP. Returns (alive, ttl).

    KEY DECISIONS:
    - NO -p flag. -p adds inter-packet delay which made total fping runtime
      exceed our subprocess timeout, causing fping to be killed mid-run.
      Partial stderr then had misleading rcv>0 counts → false positives.
    - subprocess timeout = count * timeout + 10 (very generous headroom).
    - Parse xmt/rcv/%loss from stderr. rcv>0 = alive. Anything else = dead.
    - Exit code NEVER used (fping exits 0 on ICMP-unreachable → false +ve).
    """
    fping_bin = shutil.which("fping")
    if not fping_bin:
        return False, None

    # Generous timeout: fping sends count packets each waiting up to timeout sec
    proc_timeout = (count * timeout) + 10

    try:
        r = subprocess.run(
            [fping_bin, "-c", str(count), "-t", str(timeout * 1000), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=proc_timeout,
        )
    except subprocess.TimeoutExpired:
        return False, None
    except Exception:
        return False, None

    stderr_text = r.stderr.decode(errors="ignore")

    # Parse the summary line: "ip : xmt/rcv/%loss = N/M/P%[, ...]"
    # This is the ONLY reliable indicator. Exit code is NOT used.
    alive = False
    ttl   = None

    for line in stderr_text.splitlines():
        if "xmt/rcv/%loss" not in line:
            continue
        try:
            # Everything after "xmt/rcv/%loss = "
            after = line.split("xmt/rcv/%loss =", 1)[1].strip()
            # Take only the "N/M/P%" part before any comma (v5 appends min/avg/max)
            counts = after.split(",")[0].strip()   # e.g. "8/0/100%"
            parts  = counts.split("/")              # ["8", "0", "100%"]
            rcv    = int(parts[1].strip())
            alive  = rcv > 0
            break
        except (IndexError, ValueError):
            # Malformed line → fail-safe dead
            alive = False
            break

    # TTL: parse from per-packet lines e.g. "[0], 84 bytes, 1.23 ms (ttl=64)"
    if alive:
        for line in stderr_text.splitlines():
            m = re.search(r"ttl[=:](\d+)", line, re.IGNORECASE)
            if m:
                ttl = int(m.group(1))
                break

    return alive, ttl


def _run_ping(ip: str, timeout: int, count: int) -> tuple[bool, int | None]:
    """
    Run OS ping for one IP. Returns (alive, ttl).

    Parse "X received" (or "X packets received") from stdout.
    Exit code NOT trusted. Tries with -i 0.5 first, then without.
    """
    ping_bin = shutil.which("ping")
    if not ping_bin:
        return False, None

    if sys.platform == "win32":
        cmd_variants = [
            [ping_bin, "-n", str(count), "-w", str(timeout * 1000), ip]
        ]
        proc_timeout = (count * timeout) + 5
    else:
        # -W = per-packet wait seconds, -i = inter-packet interval
        # Try with -i first; if kernel rejects it (some embedded distros),
        # fall back to the same command without -i.
        cmd_variants = [
            [ping_bin, "-c", str(count), "-W", str(timeout), "-i", "0.5", ip],
            [ping_bin, "-c", str(count), "-W", str(timeout), ip],
        ]
        # Each packet can take up to timeout seconds; add buffer
        proc_timeout = (count * timeout) + 10

    stdout_text = ""
    for cmd in cmd_variants:
        try:
            r = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=proc_timeout,
            )
            stdout_text = r.stdout.decode(errors="ignore")
            break       # ran successfully (regardless of host alive/dead)
        except subprocess.TimeoutExpired:
            return False, None
        except Exception:
            continue    # try next variant (e.g. without -i)

    if not stdout_text:
        return False, None

    # Parse "X received" — the only trustworthy alive signal
    m = re.search(r'(\d+)\s+(?:packets?\s+)?received', stdout_text, re.IGNORECASE)
    if not m:
        return False, None
    alive = int(m.group(1)) > 0

    # Parse TTL
    ttl = None
    if alive:
        t = re.search(r'ttl[=:](\d+)', stdout_text, re.IGNORECASE)
        if t:
            ttl = int(t.group(1))

    return alive, ttl


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
    print(
        f"\n  {C.CYAN}⠿ Scanning {C.BOLD}{total:,}{C.RESET}{C.CYAN} hosts"
        f"  │  threads={C.BOLD}{threads}{C.RESET}{C.CYAN}"
        f"  timeout={timeout}s  pkt/host={count}"
        f"{retry_str}{rate_str}{dns_str}"
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
                pool.submit(_ping_one, ip, timeout, count, rl, do_dns): ip
                for ip in ip_list
            }
            for fut in as_completed(futures):
                if interrupted:
                    # Cancel remaining futures
                    for f in futures:
                        f.cancel()
                    break

                res    = fut.result()
                ip     = res["ip"]
                alive  = res["alive"]
                done_n += 1

                # ── retry logic: re-ping dead hosts once ────────
                if not alive and retry > 0:
                    for _ in range(retry):
                        res2 = _ping_one(ip, timeout, count, rl, do_dns)
                        if res2["alive"]:
                            res = res2
                            break

                results.append(res)

                if res["alive"]:
                    if not quiet:
                        os_g = res["os_guess"]
                        ttl_s = f"TTL={res['ttl']}" if res["ttl"] else "TTL=?"
                        dns_s = f"  {C.DIM}{res['hostname'][:28]}{C.RESET}" if res["hostname"] else ""
                        oscol = ttl_color(os_g)
                        sys.stdout.write(
                            f"\r  {C.GREEN}✔ {ip:<18}{C.RESET}"
                            f"  {C.DIM}{ttl_s:<8}{C.RESET}"
                            f"  {oscol}{os_g:<16}{C.RESET}"
                            f"  {C.CYAN}[{res['scope']}]{C.RESET}"
                            f"{dns_s}\n"
                        )
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
        header = "ip,alive,ttl,os_guess,hostname,scope,rfc\n"
        def to_csv(r):
            return f"{r['ip']},{r['alive']},{r.get('ttl','')},{r.get('os_guess','')},{r.get('hostname','')},{r.get('scope','')},{r.get('rfc','')}\n"
        Path(alive_file).write_text(header + "".join(to_csv(r) for r in alive))
        Path(dead_file).write_text(header  + "".join(to_csv(r) for r in dead))
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
    print(f"  {C.DIM}│{C.RESET}  {C.GREEN}{'Alive (reachable)':<28}{C.BOLD}{len(alive):>6}{C.RESET}  {C.DIM}({pct_a:.1f}%){C.RESET}")
    print(f"  {C.DIM}│{C.RESET}  {C.RED}{'Dead (no response)':<28}{C.BOLD}{len(dead):>6}{C.RESET}  {C.DIM}({pct_d:.1f}%){C.RESET}")
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
# READ IP FILE
# ─────────────────────────────────────────────────────────────────
def read_ip_file(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        print(C.err(f"  ✗ File not found: {path}")); sys.exit(1)
    ips, bad = [], []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ipaddress.ip_address(line); ips.append(line)
        except ValueError:
            bad.append(line)
    if bad:
        print(f"  {C.YELLOW}⚠  Skipped {len(bad)} invalid entries in {path}{C.RESET}")
    if not ips:
        print(C.err(f"  ✗ No valid IPs found in {path}")); sys.exit(1)
    print(f"  {C.CYAN}Loaded {C.BOLD}{len(ips)}{C.RESET}{C.CYAN} IPs from {path}{C.RESET}")
    return ips


# ─────────────────────────────────────────────────────────────────
# CHECK DEPENDENCIES + TOOL SELECTION
# ─────────────────────────────────────────────────────────────────
def check_deps(ping_tool: str = "auto") -> str:
    """
    Detect available ping tools, honour --ping-tool, prompt if both
    available, then SET _BACKEND so every _ping_one() call uses the
    correct tool without re-checking.
    Returns resolved backend: "fping" | "ping".
    """
    global _BACKEND

    fping_bin = shutil.which("fping")
    ping_bin  = shutil.which("ping")
    has_fping = fping_bin is not None
    has_ping  = ping_bin  is not None

    # ── Print availability table ────────────────────────────────
    W = 44
    print(f"\n  {C.CYAN}[tools]{C.RESET}")
    print(f"  {C.DIM}┌{'─'*W}┐{C.RESET}")
    if has_fping:
        p = (fping_bin or "")[:W-12]
        print(f"  {C.DIM}│{C.RESET}  {C.GREEN}fping  ✔  {p:<{W-12}}{C.RESET}{C.DIM}│{C.RESET}")
    else:
        print(f"  {C.DIM}│{C.RESET}  {C.RED}fping  ✘  not found{'':<{W-20}}{C.RESET}{C.DIM}│{C.RESET}")
    if has_ping:
        p = (ping_bin or "")[:W-12]
        print(f"  {C.DIM}│{C.RESET}  {C.GREEN}ping   ✔  {p:<{W-12}}{C.RESET}{C.DIM}│{C.RESET}")
    else:
        print(f"  {C.DIM}│{C.RESET}  {C.RED}ping   ✘  not found{'':<{W-20}}{C.RESET}{C.DIM}│{C.RESET}")
    print(f"  {C.DIM}└{'─'*W}┘{C.RESET}")

    # ── Neither available ───────────────────────────────────────
    if not has_fping and not has_ping:
        print(f"\n  {C.RED}✗ No ping tool found on PATH.{C.RESET}")
        print(f"  {C.YELLOW}Install one:{C.RESET}")
        print(f"  {C.DIM}  sudo apt install fping   # Kali / Debian / Ubuntu")
        print(f"       sudo dnf install fping   # RHEL / Fedora")
        print(f"       brew install fping       # macOS{C.RESET}")
        sys.exit(3)

    # ── --ping-tool explicit flag ───────────────────────────────
    if ping_tool == "fping":
        if not has_fping:
            print(f"  {C.RED}✗ --ping-tool=fping requested but fping not found.{C.RESET}")
            sys.exit(3)
        _BACKEND = "fping"

    elif ping_tool == "ping":
        if not has_ping:
            print(f"  {C.RED}✗ --ping-tool=ping requested but ping not found.{C.RESET}")
            sys.exit(3)
        _BACKEND = "ping"

    else:
        # auto: prompt when both available and running interactively
        if has_fping and has_ping and sys.stdin.isatty():
            print(f"\n  {C.BOLD}{C.CYAN}Select ping backend:{C.RESET}")
            print(f"  {C.GREEN}  [1]{C.RESET}  fping  {C.DIM}(recommended — faster, accurate){C.RESET}")
            print(f"  {C.YELLOW}  [2]{C.RESET}  ping   {C.DIM}(OS built-in, always available){C.RESET}")
            print(f"  {C.DIM}  [Enter] = fping{C.RESET}\n")
            try:
                choice = input(f"  {C.BOLD}Choice [1/2]:{C.RESET} ").strip()
            except (EOFError, KeyboardInterrupt):
                choice = "1"
            _BACKEND = "ping" if choice == "2" else "fping"
            col = C.YELLOW if _BACKEND == "ping" else C.GREEN
            print(f"  {col}→ Using: {_BACKEND}{C.RESET}\n")

        elif has_fping:
            _BACKEND = "fping"
        else:
            _BACKEND = "ping"

    # Print resolved choice
    col   = C.GREEN if _BACKEND == "fping" else C.YELLOW
    label = f"{col}{C.BOLD}{_BACKEND}{C.RESET}"
    print(f"  {C.DIM}Backend:{C.RESET}  {label}\n")
    return _BACKEND


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
    # Also clear any leftover resume file
    clear_partial(label)


# ─────────────────────────────────────────────────────────────────
# ARG PARSER
# ─────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pingme",
        description="PingMe v3.0 — Advanced Ping Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
    )

    mg = p.add_argument_group(f"{C.BOLD}Modes{C.RESET}")
    mg.add_argument("-s", "--sub",    metavar="CIDR",
                    help="Show subnet info (add --scan to ping)")
    mg.add_argument("-f", "--file",   metavar="FILE",
                    help="Load IPs from a file (one per line)")
    mg.add_argument("--diff",         metavar=("A", "B"), nargs=2,
                    help="Compare two alive.txt snapshots")
    mg.add_argument("--history",      action="store_true",
                    help="List all stored scan history")
    mg.add_argument("--clear-history",metavar="LABEL",
                    help="Delete history for a label")
    mg.add_argument("--ipinfo",       metavar="IP", nargs="+",
                    help="Classify IPs as Public/Private/Special")

    sg = p.add_argument_group(f"{C.BOLD}Scan Options{C.RESET}")
    sg.add_argument("--scan",         action="store_true",
                    help="Run ping scan (use with --sub or --file)")
    sg.add_argument("-t", "--threads",type=int, default=20, metavar="N",
                    help="Concurrent threads (default: 20)")
    sg.add_argument("--timeout",      type=int, default=6,  metavar="SEC",
                    help="Per-packet wait seconds (default: 6)")
    sg.add_argument("--count",        type=int, default=8,  metavar="N",
                    help="Packets per host — alive if ≥1 reply (default: 8)")
    sg.add_argument("--retry",        type=int, default=0,  metavar="N",
                    help="Extra ping attempts for dead hosts (default: 0)")
    sg.add_argument("--rate",         type=int, default=0,  metavar="PPS",
                    help="Max packets/sec total — 0 = unlimited (default: 0)")
    sg.add_argument("--exclude",      metavar="IP/CIDR", nargs="+",
                    help="IPs or CIDRs to skip (e.g. --exclude 10.0.0.1 10.0.0.0/28)")
    sg.add_argument("--dns",          action="store_true",
                    help="Reverse DNS lookup for alive hosts")
    sg.add_argument("--resume",       action="store_true",
                    help="Resume a previously interrupted scan")
    sg.add_argument("--ping-tool",     default="auto",
                    choices=["auto", "fping", "ping"],
                    help="Ping backend: auto (default) | fping | ping")
    sg.add_argument("--fast",         action="store_true",
                    help="Fast mode: threads=100 timeout=1s count=1 (less accurate)")
    sg.add_argument("--no-history",   action="store_true",
                    help="Don't save this scan to history")
    sg.add_argument("--compare",      action="store_true",
                    help="Compare with previous scan of same target")
    sg.add_argument("--quiet",        action="store_true",
                    help="Suppress per-IP output during scan")

    og = p.add_argument_group(f"{C.BOLD}Output{C.RESET}")
    og.add_argument("--alive-out",    default="alive.txt", metavar="FILE",
                    help="Output file for alive IPs (default: alive.txt)")
    og.add_argument("--dead-out",     default="dead.txt",  metavar="FILE",
                    help="Output file for dead IPs (default: dead.txt)")
    og.add_argument("--out-format",   default="txt", choices=["txt","csv","json"],
                    help="Output format: txt | csv | json (default: txt)")
    og.add_argument("--label",        metavar="NAME",
                    help="Custom history label (default: CIDR or filename)")
    og.add_argument("--no-banner",    action="store_true",
                    help="Suppress the ASCII banner (clean output for piping)")
    og.add_argument("-h", "--help",   action="help",
                    help="Show this help message")

    return p


# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────
def main():
    if not sys.stdout.isatty():
        for attr in dir(C):
            if not attr.startswith("_") and isinstance(getattr(C, attr), str):
                setattr(C, attr, "")

    parser = build_parser()
    args   = parser.parse_args()

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

    # ── need --sub or --file ────────────────────────────────────
    if not args.sub and not args.file:
        parser.print_help()
        print(f"\n  {C.YELLOW}Tip: use --sub 192.168.1.0/24 --scan or --file ips.txt{C.RESET}\n")
        sys.exit(0)

    # ── build IP list ───────────────────────────────────────────
    ip_list: list[str] = []
    label = args.label

    if args.sub:
        net     = show_subnet_info(args.sub)
        ip_list = [str(h) for h in net.hosts()]
        if not label:
            label = re.sub(r"[/]", "_", args.sub)

    if args.file:
        file_ips = read_ip_file(args.file)
        if ip_list:
            print(f"  {C.YELLOW}⚠  Both --sub and --file given — using --file IPs only.{C.RESET}")
        ip_list = file_ips
        if not label:
            label = Path(args.file).stem

    # ── apply --exclude ─────────────────────────────────────────
    if args.exclude:
        excl = build_exclude_set(args.exclude)
        before = len(ip_list)
        ip_list = [ip for ip in ip_list if ip not in excl]
        skipped = before - len(ip_list)
        if skipped:
            print(f"  {C.DIM}[exclude] Skipped {skipped} IPs{C.RESET}")

    # ── scan ────────────────────────────────────────────────────
    if args.scan:
        check_deps(ping_tool=args.ping_tool)

        if args.fast:
            args.threads = 100; args.timeout = 1; args.count = 1
            print(f"  {C.YELLOW}⚡ Fast mode — less accurate on slow/busy hosts.{C.RESET}")

        args.threads = max(1,  min(1000, args.threads))
        args.timeout = max(1,  min(30,   args.timeout))
        args.count   = max(1,  min(20,   args.count))
        args.retry   = max(0,  min(5,    args.retry))
        args.rate    = max(0,           args.rate)

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
        )

        alive = [r["ip"] for r in results if r["alive"]]
        dead  = [r["ip"] for r in results if not r["alive"]]

        write_results(results, args.alive_out, args.dead_out, args.out_format)

        if not args.no_history:
            save_scan(label, results)

        if args.compare:
            compare_history(label, alive, dead)

    elif args.sub and not args.scan:
        print(f"  {C.DIM}Tip: add {C.BOLD}--scan{C.RESET}{C.DIM} to ping all {len(ip_list):,} hosts.{C.RESET}\n")

    print()


if __name__ == "__main__":
    main()
