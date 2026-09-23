#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║              PingMe — Advanced Ping Scanner v3.3.0 by Madhav       ║
║   Subnet Info · Ping Scan · TTL Fingerprint · Reverse DNS        ║
║   History · Diff · IP Classify · Retry · Resume · Rate-Limit     ║
╚══════════════════════════════════════════════════════════════════╝
"""

import argparse
import asyncio
import csv
import difflib
import hashlib
import ipaddress
import math
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
from typing import Callable, Optional, Union


APP_NAME = "PingMe"
VERSION = "3.3.0"
BUILD = "reliable-cross-platform"


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


_COLOR_ENABLED = True


def disable_colors() -> None:
    """Blank every palette entry so output contains no ANSI escape sequences."""
    global _COLOR_ENABLED
    _COLOR_ENABLED = False
    for attr in dir(C):
        if not attr.startswith("_") and isinstance(getattr(C, attr), str):
            setattr(C, attr, "")


def colors_wanted(mode: Optional[str]) -> bool:
    """Resolve --color auto|always|never, honouring the NO_COLOR convention."""
    if mode == "always":
        return True
    if mode == "never":
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


# ─────────────────────────────────────────────────────────────────
# HISTORY / PERSISTENCE
# ─────────────────────────────────────────────────────────────────
_DATA_DIR_OVERRIDE: Optional[Path] = None

# Maps a current state label to the label a pre-3.3 release used for the same
# targets, so existing baselines in ./data keep working after an upgrade.
_LEGACY_LABELS: dict[str, str] = {}

DEFAULT_HISTORY_KEEP = 50


def _default_data_dir() -> Path:
    """Per-user state directory, independent of the current working directory."""
    override = os.environ.get("PINGME_DATA_DIR")
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        return (Path(base) if base else Path.home() / "AppData" / "Local") / "PingMe"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "PingMe"
    base = os.environ.get("XDG_DATA_HOME")
    return (Path(base) if base else Path.home() / ".local" / "share") / "pingme"


def _data_dir() -> Path:
    return _DATA_DIR_OVERRIDE or _default_data_dir()


def _legacy_data_dir() -> Path:
    """Releases before 3.3 stored state in ./data under the working directory."""
    return Path.cwd() / "data"


_MAX_LABEL_LENGTH = 80


def _safe_label(label: str) -> str:
    """Filesystem-safe label; long ones are shortened with a hash so they stay unique.

    Labels built from many hosts, subnets, or interfaces would otherwise exceed
    the 255-byte filename limit once state-file prefixes are added.
    """
    safe = re.sub(r"[^\w.\-]", "_", label)
    if len(safe) > _MAX_LABEL_LENGTH:
        digest = hashlib.sha1(safe.encode("utf-8")).hexdigest()[:10]
        safe = f"{safe[:_MAX_LABEL_LENGTH - 11]}-{digest}"
    return safe


def _state_name(kind: str, label: str) -> str:
    safe = _safe_label(label)
    return {
        "history": f"{safe}.json",
        "resume": f".resume_{safe}.json",
        "changes": f".{safe}_changes.json",
    }[kind]


def _state_path(kind: str, label: str, create: bool = True) -> Path:
    directory = _data_dir()
    if create:
        directory.mkdir(parents=True, exist_ok=True)
    return directory / _state_name(kind, label)


def _legacy_state_path(kind: str, label: str) -> Path:
    return _legacy_data_dir() / _state_name(kind, _LEGACY_LABELS.get(label, label))


def _read_state(kind: str, label: str) -> object:
    """Read a JSON state file, falling back to the pre-3.3 ./data location."""
    candidates = [_state_path(kind, label, create=False)]
    legacy = _legacy_state_path(kind, label)
    if legacy.resolve() != candidates[0].resolve():
        candidates.append(legacy)
    for path in candidates:
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return None
    return None


def _write_json_atomic(path: Path, data: object) -> None:
    """Write JSON through a temporary file so an interrupted write never corrupts state."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def _remove_state(kind: str, label: str) -> bool:
    removed = False
    for path in (_state_path(kind, label, create=False), _legacy_state_path(kind, label)):
        if path.is_file():
            path.unlink()
            removed = True
    return removed


def history_file(label: str) -> Path:
    return _state_path("history", label)


def save_scan(label: str, results: list[dict], announce: bool = True, keep: int = DEFAULT_HISTORY_KEEP):
    """Append a scan to the label's history, keeping only the newest ``keep`` entries (0 = all)."""
    alive = sorted(r["ip"] for r in results if r["alive"])
    dead  = sorted(r["ip"] for r in results if r.get("status") == "NO RESPONSE")
    errors = sorted(r["ip"] for r in results if r.get("status") == "PROBE ERROR")
    data  = {
        "label":     label,
        "timestamp": datetime.now().isoformat(),
        "alive":     alive,
        "dead":      dead,
        "errors":    errors,
        "results":   results,
    }
    existing = load_history(label)
    existing.append(data)
    if keep > 0:
        existing = existing[-keep:]
    hf = history_file(label)
    _write_json_atomic(hf, existing)
    if announce:
        print(f"  {C.DIM}[data] saved → {hf}{C.RESET}")


def load_history(label: str) -> list[dict]:
    data = _read_state("history", label)
    return data if isinstance(data, list) else []


# ─────────────────────────────────────────────────────────────────
# RESUME / PARTIAL SAVE
# ─────────────────────────────────────────────────────────────────
def save_partial(label: str, done_results: list[dict], remaining: list[str]):
    _write_json_atomic(_state_path("resume", label), {
        "label":     label,
        "timestamp": datetime.now().isoformat(),
        "done":      done_results,
        "remaining": remaining,
    })


def load_partial(label: str) -> Optional[dict]:
    data = _read_state("resume", label)
    return data if isinstance(data, dict) and isinstance(data.get("done"), list) else None


def clear_partial(label: str):
    _remove_state("resume", label)


# ─────────────────────────────────────────────────────────────────
# TTL FINGERPRINTING
# ─────────────────────────────────────────────────────────────────
def ttl_to_os(ttl: Optional[int]) -> str:
    """
    Give a deliberately qualified OS-family hint from the observed TTL.

    Routers decrement TTL, so an observed value must be compared with the
    next common initial TTL (64, 128, or 255). TTL is never proof of an OS.
    """
    if ttl is None or ttl <= 0:
        return "Unknown"
    if ttl <= 64:
        return "Likely Unix (≤64)"
    if ttl <= 128:
        return "Likely Windows (≤128)"
    if ttl <= 255:
        return "Likely network (≤255)"
    return "Unknown"


def ttl_color(os_guess: str) -> str:
    return {
        "Likely Windows (≤128)": C.BLUE,
        "Likely Unix (≤64)": C.LIME,
        "Likely network (≤255)": C.ORANGE,
        "Unknown":       C.DIM,
    }.get(os_guess, C.DIM)


# ─────────────────────────────────────────────────────────────────
# REVERSE DNS  (IP → hostname)
# ─────────────────────────────────────────────────────────────────
_dns_cache: dict[tuple[str, bool], tuple[str, str]] = {}
_dns_lock  = threading.Lock()


def _clean_reverse_name(name: str, ip: str) -> str:
    name = name.strip().rstrip(".")
    if not name or _same_ip(name, ip) or not is_safe_hostname(name):
        return ""
    return name


def _reverse_with_system(ip: str, timeout: float) -> str:
    """Ask the OS resolver (DNS PTR, hosts file, and NSS providers) with a deadline."""
    getent = shutil.which("getent") if sys.platform.startswith("linux") else None
    if getent:
        output = _run_resolution_command([getent, "hosts", ip], timeout=max(1, math.ceil(timeout)))
        for line in output.splitlines():
            fields = line.split()
            if len(fields) >= 2 and _same_ip(fields[0], ip):
                return _clean_reverse_name(fields[1], ip)
        return ""

    result = ""

    def _lookup():
        nonlocal result
        try:
            result = socket.gethostbyaddr(ip)[0]
        except Exception:
            result = ""

    worker = threading.Thread(target=_lookup, daemon=True)
    worker.start()
    worker.join(timeout)
    return _clean_reverse_name(result, ip)


def _reverse_with_mdns(ip: str) -> str:
    """Resolve a LAN device's .local name through Avahi when it is installed."""
    avahi = shutil.which("avahi-resolve-address")
    if not avahi:
        return ""
    output = _run_resolution_command([avahi, ip], timeout=2)
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 2 and _same_ip(fields[0], ip):
            return _clean_reverse_name(fields[1], ip)
    return ""


def _reverse_with_netbios(ip: str) -> str:
    """Read a Windows computer name through NetBIOS (nbtstat or Samba's nmblookup)."""
    if sys.platform == "win32":
        nbtstat = shutil.which("nbtstat.exe") or shutil.which("nbtstat")
        if not nbtstat:
            return ""
        output = _run_resolution_command([nbtstat, "-A", ip], timeout=3)
        match = re.search(r"^\s*([^\s<]+)\s*<00>\s+UNIQUE", output, re.IGNORECASE | re.MULTILINE)
        return _clean_reverse_name(match.group(1), ip) if match else ""
    nmblookup = shutil.which("nmblookup")
    if not nmblookup:
        return ""
    output = _run_resolution_command([nmblookup, "-A", ip], timeout=3)
    for line in output.splitlines():
        match = re.match(r"^\s*(\S+)\s+<00>\s+-\s+(?!<GROUP>)\S", line)
        if match:
            return _clean_reverse_name(match.group(1), ip)
    return ""


def reverse_lookup(ip: str, timeout: float = 1.5, deep: bool = False) -> tuple[str, str]:
    """Resolve an IP to a hostname, returning ``(name, source)``.

    The system resolver is always tried. With ``deep`` (used for hosts that
    answered), private and link-local addresses also try mDNS and NetBIOS,
    which name many LAN devices that have no DNS PTR record. Every step is
    bounded, and results are cached per address.
    """
    key = (ip, deep)
    with _dns_lock:
        if key in _dns_cache:
            return _dns_cache[key]

    address = ip.split("%", 1)[0]
    lookups: list[tuple[str, Callable[[str], str]]] = [("dns", lambda value: _reverse_with_system(value, timeout))]
    if deep and ip_classify(address)["scope"] in {"Private", "Link-Local"}:
        lookups += [("mdns", _reverse_with_mdns), ("netbios", _reverse_with_netbios)]
    found = ("", "")
    for source, lookup in lookups:
        name = lookup(address)
        if name:
            found = (name, source)
            break
    with _dns_lock:
        _dns_cache[key] = found
    return found


def reverse_dns(ip: str, timeout: float = 1.5, deep: bool = False) -> str:
    """Hostname for an IP, or an empty string when none is known."""
    return reverse_lookup(ip, timeout, deep)[0]


# ─────────────────────────────────────────────────────────────────
# IP CLASSIFIER
# ─────────────────────────────────────────────────────────────────
_IPV6_SPECIAL: list[tuple[str, str, str, str, str]] = [
    # (network, scope, rfc, description, colour attribute)
    ("::ffff:0:0/96", "IPv4-mapped", "RFC 4291", "IPv4-mapped IPv6 address", "CYAN"),
    ("64:ff9b::/96", "NAT64", "RFC 6052", "NAT64 well-known prefix", "CYAN"),
    ("64:ff9b:1::/48", "NAT64", "RFC 8215", "Local-use NAT64 prefix", "CYAN"),
    ("100::/64", "Reserved", "RFC 6666", "Discard-only prefix", "PURPLE"),
    ("2001:db8::/32", "Documentation", "RFC 3849", "Documentation/example (2001:db8::/32)", "DIM"),
    ("3fff::/20", "Documentation", "RFC 9637", "Documentation/example (3fff::/20)", "DIM"),
    ("2001:2::/48", "Reserved", "RFC 5180", "Benchmarking (2001:2::/48)", "PURPLE"),
    ("2001:20::/28", "Reserved", "RFC 7343", "ORCHIDv2 identifiers", "PURPLE"),
    ("2001::/32", "Teredo", "RFC 4380", "Teredo tunnel", "ORANGE"),
    ("2002::/16", "6to4", "RFC 3056", "6to4 tunnel", "ORANGE"),
    ("fc00::/7", "Private", "RFC 4193", "IPv6 unique local address (fc00::/7)", "CYAN"),
    ("fec0::/10", "Reserved", "RFC 3879", "Deprecated site-local address", "PURPLE"),
]


def ipv6_embedded_ipv4(address: ipaddress.IPv6Address) -> Optional[ipaddress.IPv4Address]:
    """Return the IPv4 address carried by a mapped, NAT64, 6to4, or Teredo address."""
    if address.ipv4_mapped:
        return address.ipv4_mapped
    if address.sixtofour:
        return address.sixtofour
    if address.teredo:
        return address.teredo[1]  # the client's public address
    if address in ipaddress.ip_network("64:ff9b::/96"):
        return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    return None


def ipv6_interface_id(address: ipaddress.IPv6Address) -> str:
    """Describe the last 64 bits: an EUI-64 ID reveals the interface's MAC address."""
    raw = address.packed
    if raw[11] == 0xFF and raw[12] == 0xFE:
        mac = bytes([raw[8] ^ 0x02]) + raw[9:11] + raw[13:16]
        return "EUI-64 · MAC " + ":".join(f"{byte:02x}" for byte in mac)
    if int(address) & 0xFFFFFFFFFFFFFFFF < 0x10000:
        return "Manually assigned (low value)"
    return "Random / privacy (no MAC exposed)"


def ip_classify(ip_str: str) -> dict:
    try:
        ip = ipaddress.ip_address(str(ip_str).strip().strip("[]").split("%", 1)[0])
    except ValueError:
        return {"scope": "Invalid", "color": C.RED, "rfc": "", "description": "Not a valid IP"}

    if ip.version == 6:
        return _classify_ipv6(ip)

    if ip.is_loopback:
        return {"scope": "Loopback", "color": C.DIM, "rfc": "RFC 5735", "description": "Loopback (127.0.0.0/8)"}
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


def _classify_ipv6(ip: ipaddress.IPv6Address) -> dict:
    details: dict[str, str] = {}
    embedded = ipv6_embedded_ipv4(ip)
    if embedded is not None:
        inner = ip_classify(str(embedded))
        details["Embedded IPv4"] = f"{embedded} ({inner['scope']})"

    if ip.is_loopback:
        info = {"scope": "Loopback", "color": C.DIM, "rfc": "RFC 4291", "description": "IPv6 loopback (::1/128)"}
    elif ip.is_unspecified:
        info = {"scope": "Reserved", "color": C.PURPLE, "rfc": "RFC 4291", "description": "Unspecified address (::)"}
    elif ip.is_link_local:
        info = {"scope": "Link-Local", "color": C.YELLOW, "rfc": "RFC 4291", "description": "IPv6 link-local (fe80::/10)"}
    elif ip.is_multicast:
        info = {"scope": "Multicast", "color": C.ORANGE, "rfc": "RFC 4291", "description": "IPv6 multicast (ff00::/8)"}
    else:
        info = None
        for network, scope, rfc, description, colour in _IPV6_SPECIAL:
            if ip in ipaddress.ip_network(network):
                info = {"scope": scope, "color": getattr(C, colour), "rfc": rfc, "description": description}
                break
        if info is None:
            if ip in ipaddress.ip_network("2000::/3"):
                info = {"scope": "Public", "color": C.LIME, "rfc": "RFC 4291", "description": "Global unicast address"}
            else:
                info = {"scope": "Reserved", "color": C.PURPLE, "rfc": "IANA", "description": "Unallocated / reserved IPv6 space"}

    if not (ip.is_loopback or ip.is_unspecified or ip.is_multicast or embedded is not None):
        details["Interface ID"] = ipv6_interface_id(ip)
    if details:
        info["details"] = details
    return info


def show_ipinfo(targets: list[str]):
    LABEL_W, VALUE_W = 18, 44
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
        if info["scope"] != "Invalid":
            parsed = ipaddress.ip_address(ip_str.strip().strip("[]").split("%", 1)[0])
            print(row("Version",  f"IPv{parsed.version}", C.WHITE))
            if parsed.version == 6:
                print(row("Expanded", parsed.exploded, C.DIM + C.WHITE))
        print(row("Scope",        info["scope"],         info["color"] + C.BOLD))
        print(row("RFC / Auth",   info["rfc"],           C.DIM + C.WHITE))
        print(row("Description",  info["description"],   C.WHITE))
        for label, value in info.get("details", {}).items():
            print(row(label, value, C.TEAL))

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
def show_subnet_info(
    cidr: str, display: bool = True
) -> Union[ipaddress.IPv4Network, ipaddress.IPv6Network]:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        print(C.err(f"\n  ✗ Invalid CIDR: {e}"), file=sys.stderr)
        sys.exit(EXIT_USAGE)

    if not display:
        return net

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
        """Block until n tokens are available.

        A request larger than the bucket (n > rate) waits for a full bucket and
        then borrows the rest, so later callers repay the debt. Waiting for n
        tokens directly would never succeed because the bucket caps at rate.
        """
        if self.rate <= 0:
            return
        n = max(1, n)
        needed = min(n, self.rate)
        while True:
            with self._lock:
                now    = time.monotonic()
                delta  = now - self.last_time
                self.tokens    = min(self.rate, self.tokens + delta * self.rate)
                self.last_time = now
                if self.tokens >= needed:
                    self.tokens -= n
                    return
                wait = (needed - self.tokens) / self.rate
            time.sleep(min(max(wait, 0.001), 0.05))


# ─────────────────────────────────────────────────────────────────
# TOOL SELECTION  (cached at module level — FIX 4)
# ─────────────────────────────────────────────────────────────────
_FPING_PATH: Optional[str] = shutil.which("fping")
_PING_PATH:  Optional[str] = shutil.which("ping")
_PING6_PATH: Optional[str] = shutil.which("ping6")

# User-selected tool: "auto" | "fping" | "ping"
_PING_TOOL: str = "auto"

# Set on Ctrl+C so workers stop starting new probes while the scan winds down.
_STOP_EVENT = threading.Event()


def _use_fping() -> bool:
    """Return True if fping should be used for this scan."""
    if _PING_TOOL == "fping":
        return _FPING_PATH is not None
    if _PING_TOOL in {"ping", "native"}:
        return False
    # auto: prefer fping if available
    return _FPING_PATH is not None


def _use_native() -> bool:
    return _PING_TOOL == "native"


def _is_ipv6(ip: str) -> bool:
    return ipaddress.ip_address(ip).version == 6


def _normalise_probe_address(value: str) -> Optional[str]:
    """Return a safe unicast probe address, or None for non-host destinations.

    Accepts the bracketed IPv6 form used in URLs (``[2001:db8::1]``) and keeps
    an IPv6 zone (``fe80::1%eth0``), which link-local addresses need.
    """
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    base, separator, scope = value.partition("%")
    try:
        parsed = ipaddress.ip_address(base)
    except ValueError:
        return None
    if parsed.is_unspecified or parsed.is_multicast or str(parsed) == "255.255.255.255":
        return None
    normalized = str(parsed)
    if parsed.version == 6 and separator and scope:
        normalized += f"%{scope}"
    return normalized


class ProbeExecutionError(RuntimeError):
    """The probe command could not complete normally or returned unusable output."""


class EchoResult(tuple):
    """An ``(alive, ttl)`` pair that also carries round-trip and loss evidence.

    It compares equal to a plain tuple, so callers that only need the verdict
    can keep unpacking two values.
    """

    rtts: list[float]
    sent: int
    received: int

    def __new__(
        cls,
        alive: bool,
        ttl: Optional[int],
        rtts: Optional[list[float]] = None,
        sent: int = 0,
        received: int = 0,
    ):
        obj = super().__new__(cls, (alive, ttl))
        obj.rtts = list(rtts or [])
        obj.sent = sent
        obj.received = received
        return obj


def _decode_probe_output(raw: object) -> str:
    """Decode command output without depending on translated human-readable text."""
    if isinstance(raw, str):
        return raw
    if not isinstance(raw, (bytes, bytearray)):
        return ""
    data = bytes(raw)
    # UTF-16 is only plausible with a BOM or a high share of NUL bytes. Trying it
    # unconditionally "succeeds" on most even-length byte strings and yields garbage.
    if data.startswith((b"\xff\xfe", b"\xfe\xff")) or (data and data.count(b"\x00") * 4 >= len(data)):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            pass
    for encoding in ("utf-8", "mbcs", "cp437"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    # IP addresses, TTL, and millisecond values are ASCII even in localized output.
    return data.decode("ascii", errors="ignore")


def _same_ip(candidate: str, target: str) -> bool:
    """Compare addresses canonically while tolerating an IPv6 scope identifier."""
    try:
        return ipaddress.ip_address(candidate.split("%", 1)[0]) == ipaddress.ip_address(target.split("%", 1)[0])
    except ValueError:
        return False


def _line_mentions_target(line: str, target: str) -> bool:
    return any(_same_ip(candidate, target) for candidate in _extract_ip_addresses(line))


def _parse_fping_output(ip: str, stdout_text: str, stderr_text: str) -> tuple[bool, Optional[int]]:
    """Parse only fping alive-mode output, which is one exact address per line."""
    del stderr_text
    expected = _normalise_probe_address(ip)
    for line in stdout_text.splitlines():
        candidate = _normalise_probe_address(line.strip())
        if expected is not None and candidate == expected:
            return True, None
    return False, None


def _ping_integrity_error(stdout_text: str, stderr_text: str) -> Optional[str]:
    """Detect iputils evidence that an echo payload does not match our request."""
    combined = stdout_text + "\n" + stderr_text
    if re.search(r"\bwrong data byte\b", combined, re.IGNORECASE):
        return "echo reply payload does not match the transmitted request"
    if re.search(r"\binvalid tv_usec\b", combined, re.IGNORECASE):
        return "echo reply contains an invalid timestamp payload"
    return None


_RTT_RE = re.compile(r"\btime\s*[=<]\s*(\d+(?:[.,]\d+)?)\s*ms\b", re.IGNORECASE)


def _parse_system_ping_output(ip: str, stdout_text: str, windows: bool) -> EchoResult:
    """Accept only direct echo-reply lines whose source is the requested target.

    Packet summaries are intentionally ignored. In particular, Windows counts
    ICMP errors such as ``Destination host unreachable`` as received packets.
    """
    ipv6 = _is_ipv6(ip)
    ttl: Optional[int] = None
    rtts: list[float] = []
    replies = 0
    for line in stdout_text.splitlines():
        if not _line_mentions_target(line, ip):
            continue

        # IPv4 reports TTL; IPv6 reports the hop limit ("ttl=" on Linux, "hlim=" on BSD/macOS).
        ttl_match = re.search(r"\b(?:ttl|hlim)\s*[=:]\s*(\d+)\b", line, re.IGNORECASE)
        if windows:
            # Windows IPv4 echo replies include TTL. Its IPv6 replies omit TTL,
            # so require a target-sourced line containing an RTT in milliseconds.
            direct_reply = bool(ttl_match) if not ipv6 else bool(
                re.search(r"(?:[=<]\s*\d+(?:[.,]\d+)?|\d+(?:[.,]\d+)?\s*)ms\b", line, re.IGNORECASE)
            )
        else:
            # iputils, BusyBox, and BSD ping identify echo replies as byte-count
            # lines from the source. ICMP error lines use "From" without bytes.
            direct_reply = bool(re.search(r"\b\d+\s+bytes\s+from\s+", line, re.IGNORECASE))

        if direct_reply:
            replies += 1
            if ttl is None and ttl_match:
                ttl = int(ttl_match.group(1))
            rtt_match = _RTT_RE.search(line)
            if rtt_match:
                rtts.append(float(rtt_match.group(1).replace(",", ".")))
    if replies:
        return EchoResult(True, ttl, rtts, received=replies)
    return EchoResult(False, None)


def _ping_via_fping(ip: str, timeout: float, count: int) -> tuple[bool, Optional[int]]:
    """
    Use fping's script-oriented alive mode, matching ``fping -a`` control runs.

    Rules:
      - Send at most ``count`` attempts using retry mode rather than count mode
      - Require stdout to contain only the exact requested address as alive
      - Require fping's documented success exit status for the single target
    """
    if not _FPING_PATH:
        return False, None

    proc_timeout = (count * timeout) + 5

    try:
        command = [_FPING_PATH]
        if _is_ipv6(ip):
            command.append("-6")
        command.extend([
            "-a",
            "-r", str(max(count - 1, 0)),
            "-B", "1.0",
            "-t", str(_timeout_ms(timeout)),
            ip,
        ])
        r = subprocess.run(
            command,
            stdout=subprocess.PIPE,   # per-packet lines + TTL
            stderr=subprocess.PIPE,   # xmt/rcv/%loss summary
            timeout=proc_timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise ProbeExecutionError(f"fping exceeded its process deadline for {ip}") from exc
    except OSError as exc:
        raise ProbeExecutionError(f"fping could not execute for {ip}: {exc}") from exc

    stdout_text = _decode_probe_output(r.stdout)
    stderr_text = _decode_probe_output(r.stderr)
    alive, ttl = _parse_fping_output(ip, stdout_text, stderr_text)
    if alive and r.returncode == 0:
        return True, ttl
    if r.returncode not in (0, 1):
        detail = (stderr_text or stdout_text).strip().splitlines()
        message = detail[-1] if detail else f"exit code {r.returncode}"
        raise ProbeExecutionError(f"fping failed for {ip}: {message}")
    return False, None


def _timeout_ms(timeout: float) -> int:
    return max(1, int(round(timeout * 1000)))


def _format_seconds(timeout: float) -> str:
    """Render a timeout without a trailing .0 so integer-only pings accept it."""
    return str(int(timeout)) if float(timeout).is_integer() else f"{timeout:g}"


def _is_bsd_ping() -> bool:
    """macOS and the BSDs share a ping whose -W is in milliseconds and exits 2 on no reply."""
    return sys.platform == "darwin" or "bsd" in sys.platform


def _system_ping_commands(ip: str, timeout: float, count: int) -> tuple[list[list[str]], float, tuple[int, ...], bool]:
    """Build platform-specific ping commands.

    Returns the command variants to try in order, the process deadline, the exit
    codes that mean "completed with no reply", and whether a process deadline
    should also be read as "no reply" (for pings without a per-reply timeout).
    """
    ipv6 = _is_ipv6(ip)
    if sys.platform == "win32":
        command = [_PING_PATH or "ping", "-n", str(count), "-w", str(_timeout_ms(timeout)), ip]
        return [command], (count * timeout) + 5, (1,), False

    if _is_bsd_ping():
        if ipv6:
            # BSD/macOS ping6 has no per-reply timeout option, so the process
            # deadline bounds the wait and expiry means no reply was printed.
            binary = _PING6_PATH or _PING_PATH or "ping6"
            flag = [] if _PING6_PATH else ["-6"]
            return [[binary, *flag, "-c", str(count), ip]], (count * timeout) + 1, (2,), True
        binary = _PING_PATH or "ping"
        return [
            # -W is milliseconds here; a value in seconds would drop real replies.
            [binary, "-c", str(count), "-W", str(_timeout_ms(timeout)), ip],
            [binary, "-c", str(count), ip],
        ], (count * timeout) + 10, (2,), False

    if ipv6:
        binary = _PING6_PATH or _PING_PATH or "ping"
        flag = [] if _PING6_PATH else ["-6"]
    else:
        binary = _PING_PATH or "ping"
        flag = []
    interval = ["-i", "0.2"] if count > 1 else []
    return [
        [binary, *flag, "-c", str(count), "-W", _format_seconds(timeout), *interval, ip],
        # Older or BusyBox pings reject fractional -W and sub-second intervals.
        [binary, *flag, "-c", str(count), "-W", str(max(1, math.ceil(timeout))), ip],
    ], (count * timeout) + 10, (1,), False


def _ping_via_system(ip: str, timeout: float, count: int) -> EchoResult:
    """
    Run the OS ping and accept only direct echo-reply lines from the target.

    Rules:
      - Require a direct echo-reply line from the exact requested target
      - Ignore summary receive counts, which can include ICMP error packets
      - Treat the platform's documented "no reply" exit status as NO RESPONSE
      - Try a compatible command variant when the first one is rejected
    """
    commands, proc_timeout, no_reply_codes, deadline_is_no_reply = _system_ping_commands(ip, timeout, count)
    windows = sys.platform == "win32"

    command_errors: list[str] = []
    for cmd in commands:
        try:
            r = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=proc_timeout,
            )
        except subprocess.TimeoutExpired as exc:
            if deadline_is_no_reply:
                partial = _parse_system_ping_output(ip, _decode_probe_output(exc.stdout), windows)
                return EchoResult(partial[0], partial[1], partial.rtts, count, partial.received)
            command_errors.append(f"process deadline exceeded: {exc}")
            continue
        except OSError as exc:
            command_errors.append(str(exc))
            continue

        stdout_text = _decode_probe_output(r.stdout)
        stderr_text = _decode_probe_output(r.stderr)
        integrity_error = _ping_integrity_error(stdout_text, stderr_text)
        if integrity_error:
            raise ProbeExecutionError(f"invalid ICMP reply for {ip}: {integrity_error}")
        parsed = _parse_system_ping_output(ip, stdout_text, windows)
        if parsed[0] and r.returncode == 0:
            return EchoResult(True, parsed[1], parsed.rtts, count, min(parsed.received, count))
        if r.returncode == 0 or r.returncode in no_reply_codes:
            return EchoResult(False, None, [], count, 0)

        detail = (stderr_text or stdout_text).strip().splitlines()
        command_errors.append(detail[-1] if detail else f"exit code {r.returncode}")

    if command_errors:
        raise ProbeExecutionError(f"system ping failed for {ip}: {command_errors[-1]}")
    raise ProbeExecutionError(f"system ping produced no usable result for {ip}")


# A host that has answered at least once gets this many extra attempts to reach
# --min-replies, so one lost packet on a lossy link cannot hide a live host.
CONFIRM_EXTRA_ATTEMPTS = 2


def echo_attempt_allowed(replies: int, attempt: int, attempts: int, required: int) -> bool:
    """Decide whether attempt number ``attempt`` (0-based) should be sent.

    Silent targets get ``attempts`` tries. Once a target has replied, it may
    use up to ``max(attempts, required) + CONFIRM_EXTRA_ATTEMPTS`` tries, as
    long as ``required`` replies are still reachable. Shared by every engine
    so they reach identical verdicts.
    """
    if replies >= required:
        return False
    if replies == 0:
        return attempt < attempts
    budget = max(attempts, required) + CONFIRM_EXTRA_ATTEMPTS
    return attempt < budget and replies + (budget - attempt) >= required


def _confirm_direct_echo(
    ip: str,
    timeout: float,
    attempts: int = 3,
    min_replies: int = 2,
    rate_limiter: Optional[RateLimiter] = None,
) -> EchoResult:
    """Require ``min_replies`` independent ping processes to see a direct reply.

    Attempts follow ``echo_attempt_allowed``: silent hosts get ``attempts``
    tries, responders a few more to confirm. Separate processes use separate
    ICMP request state, so one stray, duplicated, or stale reply cannot
    satisfy the decision. Integrity errors abort at once.
    """
    required = max(1, min_replies)
    ttl: Optional[int] = None
    rtts: list[float] = []
    sent = replies = 0
    while echo_attempt_allowed(replies, sent, attempts, required) and not _STOP_EVENT.is_set():
        if rate_limiter:
            rate_limiter.acquire(1)
        outcome = _ping_via_system(ip, timeout, 1)
        sent += 1
        if outcome[0]:
            replies += 1
            if outcome[1] is not None:
                ttl = outcome[1]
            rtts.extend(getattr(outcome, "rtts", []))
    if replies >= required:
        return EchoResult(True, ttl, rtts, sent, replies)
    return EchoResult(False, None, [], sent, replies)


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


TCP_CONCURRENCY = 64


async def _tcp_port_accepts(ip: str, port: int, timeout: float, gate: asyncio.Semaphore) -> Optional[int]:
    async with gate:
        try:
            _reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        except (OSError, asyncio.TimeoutError, ValueError):
            return None
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1)
        except (OSError, asyncio.TimeoutError):
            pass
        return port


def tcp_open_ports(ip: str, ports: list[int], timeout: float) -> list[int]:
    """Try every port concurrently so one host costs about one timeout, not one per port."""
    async def _check_all() -> list[int]:
        gate = asyncio.Semaphore(TCP_CONCURRENCY)
        found = await asyncio.gather(*(_tcp_port_accepts(ip, port, timeout, gate) for port in ports))
        return [port for port in found if port is not None]

    return asyncio.run(_check_all())


TCP_CANARY_COUNT = 2


def tcp_evidence(ip: str, ports: list[int], timeout: float) -> tuple[list[int], bool]:
    """Open ports plus whether the address accepts connections on *any* port.

    Two random high "canary" ports are tried together with the requested
    ones. Real hosts almost never listen on both, but SYN proxies, tarpits,
    and some firewalls accept every connection for every address. When both
    canaries connect, the open ports are not evidence that a host exists.
    """
    import random
    canaries: list[int] = []
    while len(canaries) < TCP_CANARY_COUNT:
        port = random.randint(40000, 65000)
        if port not in ports and port not in canaries:
            canaries.append(port)
    accepted = tcp_open_ports(ip, list(ports) + canaries, timeout)
    suspicious = all(port in accepted for port in canaries)
    return [port for port in accepted if port not in canaries], suspicious


TCP_PROXY_NOTE = "accepts TCP on every port (SYN proxy, tarpit, or firewall); TCP is not evidence here"


def _build_probe_result(
    ip: str,
    icmp_alive: bool,
    ttl: Optional[int],
    open_tcp_ports: list[int],
    probe_error: str = "",
    do_dns: bool = False,
    echo: Optional[EchoResult] = None,
    tcp_suspect: bool = False,
) -> dict:
    """Build one normalized tri-state result from validated evidence."""
    if tcp_suspect and not icmp_alive:
        # Connections that anything would accept prove nothing about this address.
        probe_error = probe_error or TCP_PROXY_NOTE
        open_tcp_ports = []
    alive = icmp_alive or bool(open_tcp_ports)
    if alive:
        status = "REACHABLE"
        evidence = "ICMP echo reply" if icmp_alive else "TCP connection accepted"
    elif probe_error:
        status = "PROBE ERROR"
        evidence = ""
    else:
        status = "NO RESPONSE"
        evidence = ""
    rtts = list(getattr(echo, "rtts", []) or [])
    sent = int(getattr(echo, "sent", 0) or 0)
    received = int(getattr(echo, "received", 0) or 0)
    classify = ip_classify(ip)
    return {
        "ip": ip,
        "alive": alive,
        "status": status,
        "evidence": evidence,
        "probe_error": probe_error,
        "icmp_alive": icmp_alive,
        "tcp_open": open_tcp_ports,
        "tcp_suspect": tcp_suspect,
        "ttl": ttl,
        "rtt_min": round(min(rtts), 2) if rtts else None,
        "rtt_avg": round(sum(rtts) / len(rtts), 2) if rtts else None,
        "loss_pct": round((sent - received) / sent * 100) if sent and not probe_error else None,
        "os_guess": ttl_to_os(ttl) if icmp_alive else "",
        "mac": "",
        "vendor": "",
        "arp": False,
        # Every scanned address gets a PTR/hosts lookup; LAN-only mDNS and
        # NetBIOS queries are reserved for hosts that answered.
        "hostname": reverse_dns(ip, deep=alive) if do_dns else "",
        "scope": classify["scope"],
        "rfc": classify["rfc"],
    }


def _fping_stream(command: list[str], payload: bytes, proc_timeout: float,
                  on_line: Callable[[str], None]) -> tuple[int, str, str]:
    """Run fping, handing each stdout line to ``on_line`` as soon as it is printed."""
    try:
        proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        raise ProbeExecutionError(f"batch fping could not execute: {exc}") from exc

    def _feed() -> None:
        try:
            proc.stdin.write(payload)
            proc.stdin.close()
        except OSError:
            pass

    stderr_chunks: list[bytes] = []
    feeder = threading.Thread(target=_feed, daemon=True)
    drainer = threading.Thread(target=lambda: stderr_chunks.append(proc.stderr.read()), daemon=True)
    feeder.start()
    drainer.start()
    killer = threading.Timer(proc_timeout, proc.kill)
    killer.start()
    stdout_lines: list[str] = []
    try:
        for raw in proc.stdout:
            line = _decode_probe_output(raw).strip()
            stdout_lines.append(line)
            on_line(line)
        returncode = proc.wait()
    finally:
        killer.cancel()
    drainer.join(2)
    if returncode < 0 and not _STOP_EVENT.is_set():
        raise ProbeExecutionError("batch fping exceeded its process deadline")
    return returncode, "\n".join(stdout_lines), _decode_probe_output(b"".join(stderr_chunks))


def _fping_batch_alive(
    ip_list: list[str],
    timeout: float,
    attempts: int,
    rate: int = 0,
    on_alive: Optional[Callable[[str], None]] = None,
) -> set[str]:
    """Discover all fping-positive targets in one process using stdin.

    With ``on_alive`` the output is streamed, so each positive can be confirmed
    while fping is still sweeping the rest of the list.
    """
    if not _FPING_PATH:
        raise ProbeExecutionError("fping is unavailable")
    command = [
        _FPING_PATH,
        "-a",
        "-r", str(max(attempts - 1, 0)),
        "-B", "1.0",
        "-t", str(_timeout_ms(timeout)),
    ]
    if rate > 0:
        interval_ms = max(1, (1000 + rate - 1) // rate)
        command.extend(["-i", str(interval_ms)])
    payload = ("\n".join(ip_list) + "\n").encode()
    interval_budget = (len(ip_list) * max(attempts, 1) / max(rate, 100)) + 2
    proc_timeout = (max(attempts, 1) * timeout) + interval_budget + 10
    requested = {_normalise_probe_address(ip) for ip in ip_list}
    if on_alive is not None:
        streamed: set[str] = set()

        def _line(line: str) -> None:
            candidate = _normalise_probe_address(line)
            if candidate is not None and candidate in requested and candidate not in streamed:
                streamed.add(candidate)
                on_alive(candidate)

        returncode, stdout_text, stderr_text = _fping_stream(command, payload, proc_timeout, _line)
        if returncode not in (0, 1) and not _STOP_EVENT.is_set():
            detail = (stderr_text or stdout_text).strip().splitlines()
            raise ProbeExecutionError(f"batch fping failed: {detail[-1] if detail else f'exit code {returncode}'}")
        return streamed
    try:
        result = subprocess.run(
            command,
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=proc_timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise ProbeExecutionError("batch fping exceeded its process deadline") from exc
    except OSError as exc:
        raise ProbeExecutionError(f"batch fping could not execute: {exc}") from exc

    stdout_text = _decode_probe_output(result.stdout)
    stderr_text = _decode_probe_output(result.stderr)
    if result.returncode not in (0, 1):
        detail = (stderr_text or stdout_text).strip().splitlines()
        message = detail[-1] if detail else f"exit code {result.returncode}"
        raise ProbeExecutionError(f"batch fping failed: {message}")

    alive: set[str] = set()
    for line in stdout_text.splitlines():
        candidate = _normalise_probe_address(line.strip())
        if candidate is not None and candidate in requested:
            alive.add(candidate)
    return alive


def _scan_fping_batch(
    ip_list: list[str],
    timeout: float,
    count: int,
    retry: int,
    rate: int,
    do_dns: bool,
    tcp_ports: Optional[list[int]],
    tcp_timeout: float,
    progress_callback: Optional[Callable[[dict, int, int], None]] = None,
    threads: int = 20,
    min_replies: int = 2,
    rate_limiter: Optional[RateLimiter] = None,
) -> list[dict]:
    """Batch discovery with positives confirmed in parallel while fping is still running."""
    attempts = count * (retry + 1)
    def _validate(ip: str) -> dict:
        icmp_alive = False
        ttl = None
        probe_error = ""
        echo: Optional[EchoResult] = None
        if _normalise_probe_address(ip) in candidates:
            if _PING_PATH is None and _PING6_PATH is None:
                probe_error = "fping positive could not be integrity-confirmed: system ping unavailable"
            else:
                try:
                    echo = _confirm_direct_echo(ip, timeout, count, min_replies, rate_limiter)
                    icmp_alive, ttl = echo[0], echo[1]
                except Exception as exc:
                    probe_error = f"invalid ICMP confirmation: {exc}"
                if not icmp_alive and not probe_error:
                    probe_error = "fping positive was not confirmed by a valid echo reply"
        open_ports, tcp_suspect = tcp_evidence(ip, tcp_ports, tcp_timeout) if tcp_ports else ([], False)
        return _build_probe_result(ip, icmp_alive, ttl, open_ports, probe_error, do_dns, echo, tcp_suspect)

    candidates: set[str] = set()
    pool = ThreadPoolExecutor(max_workers=max(1, threads))
    futures: dict = {}
    by_address = {_normalise_probe_address(ip): ip for ip in ip_list}

    def _on_alive(address: str) -> None:
        candidates.add(address)
        ip = by_address.get(address)
        if ip is not None and ip not in futures.values():
            futures[pool.submit(_validate, ip)] = ip

    try:
        candidates |= _fping_batch_alive(ip_list, timeout, attempts, rate, on_alive=_on_alive)
    except Exception as exc:
        pool.shutdown(wait=True, cancel_futures=True)
        failed = [
            _build_probe_result(ip, False, None, [], f"fping batch failed: {exc}", do_dns)
            for ip in ip_list
        ]
        if progress_callback:
            for index, result in enumerate(failed, 1):
                progress_callback(result, index, len(ip_list))
        return failed

    by_ip: dict[str, dict] = {}
    with pool:
        started = set(futures.values())
        for ip in ip_list:
            if ip not in started:
                futures[pool.submit(_validate, ip)] = ip
        for future in as_completed(list(futures)):
            ip = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = _build_probe_result(ip, False, None, [], f"validation failed: {exc}", do_dns)
            by_ip[ip] = result
            if progress_callback:
                progress_callback(result, len(by_ip), len(ip_list))
    return [by_ip[ip] for ip in ip_list]


# ─────────────────────────────────────────────────────────────────
# SINGLE-IP PING  — returns rich result dict
# ─────────────────────────────────────────────────────────────────
def _ping_one(
    ip:           str,
    timeout:      float            = 2,
    count:        int              = 3,
    rate_limiter: Optional[RateLimiter] = None,
    do_dns:       bool             = False,
    tcp_ports:    Optional[list[int]] = None,
    tcp_timeout:  float            = 2,
    min_replies:  int              = 2,
) -> dict:
    """
    Ping one IP. Cleanly separated fping / OS-ping backends.
    Reachability is fail-closed: ``alive`` is true only with direct ICMP
    echo replies from this target or a successful TCP connection to this target.
    """
    icmp_alive: bool = False
    ttl:   Optional[int] = None
    probe_error = ""
    echo: Optional[EchoResult] = None

    if _use_fping():
        if rate_limiter:
            rate_limiter.acquire(count)
        try:
            icmp_alive, ttl = _ping_via_fping(ip, timeout, count)
            if icmp_alive:
                if _PING_PATH is None and _PING6_PATH is None:
                    icmp_alive = False
                    probe_error = "fping reply could not be integrity-confirmed because system ping is unavailable"
                else:
                    try:
                        echo = _confirm_direct_echo(ip, timeout, count, min_replies, rate_limiter)
                    except Exception as confirmation_error:
                        icmp_alive = False
                        probe_error = f"fping reply failed integrity confirmation: {confirmation_error}"
                    else:
                        if echo[0]:
                            ttl = echo[1]
                        else:
                            icmp_alive = False
                            probe_error = "fping reported alive but system ping did not confirm a valid echo reply"
        except Exception as fping_error:
            # A broken fping invocation falls back to system ping. It becomes a
            # probe error only when that independent backend also fails.
            try:
                echo = _confirm_direct_echo(ip, timeout, count, min_replies, rate_limiter)
                icmp_alive, ttl = echo[0], echo[1]
            except Exception as system_error:
                icmp_alive, ttl = False, None
                probe_error = f"fping: {fping_error}; ping: {system_error}"
    else:
        if _PING_PATH is None and _PING6_PATH is None:
            icmp_alive, ttl = False, None
            if not tcp_ports:
                probe_error = "no ICMP probe tool is available"
        else:
            try:
                echo = _confirm_direct_echo(ip, timeout, count, min_replies, rate_limiter)
                icmp_alive, ttl = echo[0], echo[1]
            except Exception as exc:
                icmp_alive, ttl = False, None
                probe_error = str(exc)

    open_ports, tcp_suspect = tcp_evidence(ip, tcp_ports, tcp_timeout) if tcp_ports else ([], False)
    return _build_probe_result(ip, icmp_alive, ttl, open_ports, probe_error, do_dns, echo, tcp_suspect)


def _probe_with_retry(
    ip: str,
    timeout: float,
    count: int,
    retry: int,
    rate_limiter: Optional[RateLimiter],
    do_dns: bool,
    tcp_ports: Optional[list[int]],
    tcp_timeout: float,
    min_replies: int,
) -> dict:
    """Probe one target and retry it inside the worker until it answers or retries run out."""
    result = _ping_one(ip, timeout, count, rate_limiter, do_dns, tcp_ports, tcp_timeout, min_replies)
    for _ in range(retry):
        if result["alive"] or _STOP_EVENT.is_set():
            break
        again = _ping_one(ip, timeout, count, rate_limiter, do_dns, tcp_ports, tcp_timeout, min_replies)
        if again["alive"] or (result.get("status") == "PROBE ERROR" and again.get("status") == "NO RESPONSE"):
            result = again
    return result


# ─────────────────────────────────────────────────────────────────
# NATIVE ICMP ENGINE  (one socket, no ping process per host)
# ─────────────────────────────────────────────────────────────────
_ICMP_TYPES = {4: (8, 0), 6: (128, 129)}  # family: (echo request, echo reply)
_IP_RECVTTL = getattr(socket, "IP_RECVTTL", 12)
_IP_TTL = getattr(socket, "IP_TTL", 2)
_IPV6_RECVHOPLIMIT = getattr(socket, "IPV6_RECVHOPLIMIT", 51)
_IPV6_HOPLIMIT = getattr(socket, "IPV6_HOPLIMIT", 52)
NATIVE_DEFAULT_INTERVAL = 0.002  # seconds between requests unless --rate is set
# Requests to local addresses wait in the kernel for ARP/ND and stay charged to the
# sending socket's buffer; ~200 unresolved neighbours can block sendto() for seconds.
# Spreading requests over several sockets keeps every buffer well below that.
NATIVE_REQUESTS_PER_SOCKET = 100
NATIVE_MAX_SOCKETS = 64  # per family; stays far below default open-file limits (macOS: 256)
ADAPTIVE_TIMEOUT_CAP = 3.0


def _icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _open_icmp_socket(family: int) -> tuple[socket.socket, str]:
    """Open an unprivileged ICMP datagram socket, or a raw socket when running as root."""
    domain = socket.AF_INET if family == 4 else socket.AF_INET6
    protocol = socket.IPPROTO_ICMP if family == 4 else socket.IPPROTO_ICMPV6
    errors = []
    for kind, sock_type in (("dgram", socket.SOCK_DGRAM), ("raw", socket.SOCK_RAW)):
        try:
            sock = socket.socket(domain, sock_type, protocol)
        except OSError as exc:
            errors.append(f"{kind}: {exc}")
            continue
        for option in (socket.SO_RCVBUF, socket.SO_SNDBUF):
            try:
                sock.setsockopt(socket.SOL_SOCKET, option, 4 * 1024 * 1024)
            except OSError:
                pass
        try:
            if family == 4:
                sock.setsockopt(socket.IPPROTO_IP, _IP_RECVTTL, 1)
            else:
                sock.setsockopt(socket.IPPROTO_IPV6, _IPV6_RECVHOPLIMIT, 1)
        except OSError:
            pass
        return sock, kind
    raise ProbeExecutionError("cannot open an ICMP socket (" + "; ".join(errors) + ")")


def native_engine_available() -> bool:
    """True when this process may send ICMP from its own socket (no ping process needed)."""
    if sys.platform == "win32":
        return False
    try:
        sock, _kind = _open_icmp_socket(4)
    except ProbeExecutionError:
        return False
    sock.close()
    return True


def _zone_index(zone: str) -> int:
    if not zone:
        return 0
    if zone.isdigit():
        return int(zone)
    try:
        return socket.if_nametoindex(zone)
    except OSError:
        return -1


class _TargetState:
    __slots__ = ("ip", "family", "sockaddr", "scope", "sent", "received", "rtts", "ttl", "error", "round_seen")

    def __init__(self, ip: str):
        base, _separator, zone = ip.partition("%")
        self.ip = ip
        self.family = ipaddress.ip_address(base).version
        self.scope = _zone_index(zone) if self.family == 6 else 0
        self.sockaddr = (base, 0) if self.family == 4 else (base, 0, 0, max(self.scope, 0))
        self.sent = 0
        self.received: set[int] = set()
        self.rtts: list[float] = []
        self.ttl: Optional[int] = None
        self.error = ""
        self.round_seen = -1


class NativePinger:
    """Send ICMP echo requests to many targets and accept only exact replies.

    A reply counts only when it comes from the target address, carries this
    run's random token and the counter of a request sent to that target, and
    its payload is byte-for-byte what was sent. Duplicates are ignored, and a
    reply whose payload was altered marks the target as a probe error.
    """

    def __init__(self):
        self.token = os.urandom(8)
        self.ident = int.from_bytes(os.urandom(2), "big")
        self.sockets: dict[int, list[tuple[socket.socket, str]]] = {}
        self.sends: dict[int, int] = {}
        self.lock = threading.Lock()
        self.outstanding: dict[int, tuple[_TargetState, float, int]] = {}  # counter -> (target, sent at, round)
        self.counter = int.from_bytes(os.urandom(2), "big")
        self.stop = threading.Event()

    def _socket(self, family: int) -> tuple[socket.socket, str]:
        """Return the family's current socket, opening another every N requests."""
        with self.lock:
            pool = self.sockets.setdefault(family, [])
            sends = self.sends.get(family, 0)
            wanted = min(sends // NATIVE_REQUESTS_PER_SOCKET + 1, NATIVE_MAX_SOCKETS)
            if len(pool) < wanted:
                try:
                    pool.append(_open_icmp_socket(family))
                except ProbeExecutionError:
                    if not pool:
                        raise
                except OSError:
                    if not pool:
                        raise  # e.g. out of file descriptors; reuse what exists
            self.sends[family] = sends + 1
            if len(pool) >= NATIVE_MAX_SOCKETS:
                # Pool is full: rotate so no single socket's buffer fills up.
                return pool[(sends // NATIVE_REQUESTS_PER_SOCKET) % len(pool)]
            return pool[-1]

    def close(self) -> None:
        for pool in self.sockets.values():
            for sock, _kind in pool:
                sock.close()

    def _payload(self, counter: int) -> bytes:
        return self.token + counter.to_bytes(4, "big") + b"PingMe" + bytes(range(14))

    def send(self, target: _TargetState, round_index: int) -> None:
        sock, kind = self._socket(target.family)
        with self.lock:
            self.counter = (self.counter + 1) & 0xFFFFFFFF
            counter = self.counter
        request, _reply = _ICMP_TYPES[target.family]
        payload = self._payload(counter)
        header = request.to_bytes(1, "big") + b"\x00\x00\x00" + self.ident.to_bytes(2, "big") + (counter & 0xFFFF).to_bytes(2, "big")
        packet = header + payload
        if target.family == 4:
            checksum = _icmp_checksum(packet)
            packet = packet[:2] + checksum.to_bytes(2, "big") + packet[4:]
        with self.lock:
            self.outstanding[counter] = (target, time.monotonic(), round_index)
            target.sent += 1
        try:
            sock.sendto(packet, target.sockaddr)
        except OSError as exc:
            with self.lock:
                self.outstanding.pop(counter, None)
                target.error = target.error or f"send failed: {exc.strerror or exc}"

    def _handle(self, family: int, kind: str, data: bytes, ancdata: list, source: tuple) -> None:
        received_at = time.monotonic()
        ttl: Optional[int] = None
        if family == 4 and len(data) >= 20 and data[0] >> 4 == 4:
            # Raw sockets (and macOS datagram sockets) include the IPv4 header.
            ttl = data[8]
            data = data[(data[0] & 0x0F) * 4:]
        for level, kind_type, value in ancdata:
            if (level, kind_type) in ((socket.IPPROTO_IP, _IP_TTL), (socket.IPPROTO_IPV6, _IPV6_HOPLIMIT)) and value:
                ttl = int.from_bytes(value[:4], sys.byteorder) if len(value) >= 4 else value[0]
        _request, reply_type = _ICMP_TYPES[family]
        if len(data) < 8 + 12 or data[0] != reply_type:
            return
        if kind == "raw" and int.from_bytes(data[4:6], "big") != self.ident:
            return  # another program's echo reply
        payload = data[8:]
        if payload[:8] != self.token:
            return
        counter = int.from_bytes(payload[8:12], "big")
        with self.lock:
            entry = self.outstanding.get(counter)
            if entry is None:
                return
            target, sent_at, round_index = entry
            if not _same_ip(str(source[0]), target.ip):
                return  # a different host answered with our payload; never credit the target
            if family == 6 and target.scope > 0 and len(source) >= 4 and source[3] not in (0, target.scope):
                return
            if payload != self._payload(counter):
                target.error = "echo reply payload does not match the transmitted request"
                return
            if counter in target.received:
                return  # duplicate (DUP!) reply
            target.received.add(counter)
            target.rtts.append((received_at - sent_at) * 1000)
            target.round_seen = max(target.round_seen, round_index)
            if ttl is not None:
                target.ttl = ttl

    def receive_loop(self) -> None:
        import select
        while not self.stop.is_set():
            with self.lock:
                sockets = {sock: (family, kind) for family, pool in self.sockets.items() for sock, kind in pool}
            if not sockets:
                time.sleep(0.01)
                continue
            try:
                readable, _w, _x = select.select(list(sockets), [], [], 0.05)
            except (OSError, ValueError):
                return
            for sock in readable:
                family, kind = sockets[sock]
                try:
                    data, ancdata, _flags, source = sock.recvmsg(2048, 256)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    continue  # ICMP errors surface here on some systems; they are not replies
                self._handle(family, kind, data, ancdata, source)


def native_icmp_sweep(
    ip_list: list[str],
    timeout: Optional[float],
    attempts: int,
    min_replies: int,
    rate: int = 0,
    on_done: Optional[Callable[[str, EchoResult, str], None]] = None,
) -> dict[str, tuple[EchoResult, str]]:
    """Probe every target in rounds from one socket; returns {ip: (echo, probe error)}.

    Rounds follow ``echo_attempt_allowed``: silent targets get ``attempts``
    rounds, responders extra rounds to reach ``min_replies``. ``timeout=None``
    adapts the wait to observed round-trip times (capped at 3 s).
    """
    required = max(1, min_replies)
    attempts = max(1, attempts)
    total_rounds = max(attempts, required) + CONFIRM_EXTRA_ATTEMPTS
    interval = 1.0 / rate if rate > 0 else NATIVE_DEFAULT_INTERVAL
    pinger = NativePinger()
    targets = [_TargetState(ip) for ip in ip_list]
    for target in targets:
        if target.family == 6 and target.scope < 0:
            target.error = f"unknown interface in {target.ip}"
    for family in sorted({target.family for target in targets}):
        try:
            pinger._socket(family)
        except ProbeExecutionError as exc:
            for target in targets:
                if target.family == family:
                    target.error = str(exc)
    receiver = threading.Thread(target=pinger.receive_loop, daemon=True)
    receiver.start()
    finished: set[str] = set()

    def _finish(target: _TargetState) -> None:
        if target.ip in finished:
            return
        finished.add(target.ip)
        if on_done:
            alive = len(target.received) >= required and not target.error
            on_done(target.ip, EchoResult(alive, target.ttl if alive else None, target.rtts if alive else [],
                                          target.sent, len(target.received)), target.error)

    try:
        for round_index in range(total_rounds):
            if _STOP_EVENT.is_set():
                break
            with pinger.lock:
                active = [
                    target for target in targets
                    if not target.error
                    and echo_attempt_allowed(len(target.received), target.sent, attempts, required)
                ]
                for target in targets:
                    if target not in active:
                        _finish(target)
            if not active:
                break
            last_send = time.monotonic()
            for target in active:
                if _STOP_EVENT.is_set():
                    break
                pinger.send(target, round_index)
                last_send = time.monotonic()
                time.sleep(interval)
            # Wait for this round's replies; stop early when every active target answered.
            while not _STOP_EVENT.is_set():
                with pinger.lock:
                    waiting = [t for t in active if t.round_seen < round_index and not t.error]
                    if timeout is None:
                        samples = sorted(rtt for t in targets for rtt in t.rtts)
                        wait = ADAPTIVE_TIMEOUT_CAP if len(samples) < 3 else min(
                            ADAPTIVE_TIMEOUT_CAP, max(0.3, 4 * samples[int(len(samples) * 0.95) - 1] / 1000))
                    else:
                        wait = timeout
                if not waiting or time.monotonic() >= last_send + wait:
                    break
                time.sleep(0.01)
        with pinger.lock:
            for target in targets:
                _finish(target)
    finally:
        pinger.stop.set()
        receiver.join(1)
        pinger.close()

    results: dict[str, tuple[EchoResult, str]] = {}
    for target in targets:
        alive = len(target.received) >= required and not target.error
        results[target.ip] = (
            EchoResult(alive, target.ttl if alive else None, target.rtts if alive else [], target.sent, len(target.received)),
            target.error,
        )
    return results


def _scan_native_batch(
    ip_list: list[str],
    timeout: Optional[float],
    count: int,
    retry: int,
    rate: int,
    do_dns: bool,
    tcp_ports: Optional[list[int]],
    tcp_timeout: float,
    progress_callback: Optional[Callable[[dict, int, int], None]] = None,
    threads: int = 20,
    min_replies: int = 2,
) -> list[dict]:
    """Native ICMP sweep, with TCP checks and name lookups finished in a worker pool."""
    attempts = count * (retry + 1)
    by_ip: dict[str, dict] = {}
    lock = threading.Lock()
    pool = ThreadPoolExecutor(max_workers=max(1, threads))
    futures = []

    def _complete(ip: str, echo: EchoResult, error: str) -> dict:
        open_ports, tcp_suspect = tcp_evidence(ip, tcp_ports, tcp_timeout) if tcp_ports else ([], False)
        return _build_probe_result(ip, bool(echo[0]), echo[1], open_ports, error, do_dns, echo, tcp_suspect)

    def _on_done(ip: str, echo: EchoResult, error: str) -> None:
        # TCP checks and DNS start as soon as a target's ICMP verdict is known.
        futures.append(pool.submit(_complete, ip, echo, error))

    try:
        native_icmp_sweep(ip_list, timeout, attempts, min_replies, rate, _on_done)
        for future in as_completed(list(futures)):
            result = future.result()
            with lock:
                by_ip[result["ip"]] = result
            if progress_callback:
                progress_callback(result, len(by_ip), len(ip_list))
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
    return [by_ip[ip] for ip in ip_list if ip in by_ip]


# ─────────────────────────────────────────────────────────────────
# IPv6 HELPERS AND NEIGHBOR DISCOVERY
# ─────────────────────────────────────────────────────────────────
# Restricts hostname resolution and scanning to one family: None, 4, or 6.
_ADDRESS_FAMILY: Optional[int] = None


def address_family(ip: str) -> int:
    return ipaddress.ip_address(ip.split("%", 1)[0]).version


def ip_sort_key(ip: str) -> tuple[int, int, str]:
    """Order IPv4 before IPv6 and numerically within each; string sort mixes them up."""
    base, _separator, zone = ip.partition("%")
    try:
        parsed = ipaddress.ip_address(base)
    except ValueError:
        return (9, 0, ip)
    return (parsed.version, int(parsed), zone)


def link_local_needs_zone(ip: str) -> bool:
    """An IPv6 link-local address without %interface is ambiguous outside Windows."""
    if sys.platform == "win32" or "%" in ip:
        return False
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return parsed.version == 6 and parsed.is_link_local


def ipv6_interfaces() -> list[str]:
    """Names (Windows: indexes) of active non-loopback interfaces with IPv6 link-local addresses."""
    names: list[str] = []
    if sys.platform.startswith("linux") and shutil.which("ip"):
        output = _run_resolution_command(["ip", "-6", "-o", "addr", "show", "scope", "link"], timeout=4)
        for line in output.splitlines():
            match = re.match(r"^\d+:\s+([^\s@:]+)", line)
            if not match:
                continue
            name = match.group(1)
            try:
                state = Path(f"/sys/class/net/{name}/operstate").read_text().strip()
            except OSError:
                state = "unknown"
            # veth* are container-side ends; their bridge already reaches the same hosts.
            if state in {"up", "unknown"} and name not in names and not name.startswith("veth"):
                names.append(name)
        return names
    if sys.platform == "win32":
        netsh = shutil.which("netsh.exe") or shutil.which("netsh")
        if netsh:
            output = _run_resolution_command([netsh, "interface", "ipv6", "show", "interfaces"], timeout=6)
            for line in output.splitlines():
                fields = line.split()
                if len(fields) >= 5 and fields[0].isdigit() and fields[3].lower() == "connected" \
                        and "loopback" not in line.lower():
                    names.append(fields[0])
        return names
    try:
        interfaces = [name for _index, name in socket.if_nameindex()]
    except (OSError, AttributeError):
        return []
    return [name for name in interfaces if not name.startswith(("lo", "gif", "stf", "awdl", "llw", "anpi", "ap"))]


def interface_exists(name: str) -> bool:
    """True for a known interface name (or a Windows interface index)."""
    if sys.platform == "win32" and name.isdigit():
        return True
    try:
        socket.if_nametoindex(name)
    except (OSError, AttributeError):
        return False
    return True


def _with_zone(address: str, zone: str) -> Optional[str]:
    normalized = _normalise_probe_address(address)
    if normalized is None or "%" in normalized:
        return normalized
    return f"{normalized}%{zone}" if ipaddress.ip_address(normalized).is_link_local else normalized


def _multicast_echo_replies(interface: str, timeout: float) -> set[str]:
    """Ping all-nodes and all-routers multicast; every host that answers is a candidate."""
    found: set[str] = set()
    if sys.platform == "win32":
        return found  # Windows ping reports only one multicast responder; the neighbor cache is used instead.
    binary = _PING6_PATH or _PING_PATH or "ping"
    flag = [] if (_PING6_PATH and _is_bsd_ping()) else ["-6"]
    for group in ("ff02::1", "ff02::2"):
        command = [binary, *flag, "-c", "2", f"{group}%{interface}"]
        if not _is_bsd_ping():
            command[-1:-1] = ["-W", _format_seconds(timeout)]
        try:
            proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout + 4)
            output = _decode_probe_output(proc.stdout)
        except subprocess.TimeoutExpired as exc:
            output = _decode_probe_output(exc.stdout)
        except OSError:
            continue
        for match in re.finditer(r"bytes from \[?([0-9A-Fa-f:.]+)(?:%[\w.\-]+)?\]?", output):
            address = _with_zone(match.group(1), interface)
            if address:
                found.add(address)
    return found


_NEIGHBOR_STATES = {
    "reachable": "REACHABLE", "r": "REACHABLE",
    "stale": "STALE", "s": "STALE",
    "delay": "DELAY", "d": "DELAY",
    "probe": "PROBE", "p": "PROBE",
    "permanent": "PERMANENT",
    "failed": "FAILED", "incomplete": "INCOMPLETE", "unreachable": "FAILED",
}


def read_neighbor_entries(family: int) -> list[tuple[str, str, str, str]]:
    """Read the OS neighbor (ARP/ND) table as (address, interface, MAC, state) rows.

    ``state`` is REACHABLE, STALE, DELAY, PROBE, PERMANENT, FAILED, INCOMPLETE,
    or "" when the platform does not report one (macOS ``arp``).
    """
    rows: list[tuple[str, str, str, str]] = []
    if sys.platform.startswith("linux") and shutil.which("ip"):
        output = _run_resolution_command(["ip", f"-{family}", "neigh", "show"], timeout=4)
        for line in output.splitlines():
            match = re.match(r"^(\S+)\s+dev\s+(\S+)(?:\s+lladdr\s+(\S+))?", line)
            if not match:
                continue
            state = next((_NEIGHBOR_STATES[word.lower()] for word in reversed(line.split())
                          if word.lower() in _NEIGHBOR_STATES and word.isupper()), "")
            rows.append((match.group(1), match.group(2), match.group(3) or "", state))
    elif sys.platform == "win32":
        netsh = shutil.which("netsh.exe") or shutil.which("netsh")
        if netsh:
            output = _run_resolution_command(
                [netsh, "interface", f"ipv{family}", "show", "neighbors"], timeout=8)
            zone = ""
            for line in output.splitlines():
                header = re.match(r"^\s*Interface\s+(\d+)\s*:", line, re.IGNORECASE)
                if header:
                    zone = header.group(1)
                    continue
                fields = line.split()
                if len(fields) < 2 or not zone or _normalise_probe_address(fields[0].split("%", 1)[0]) is None:
                    continue
                has_mac = re.fullmatch(r"[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}", fields[1]) is not None
                mac = fields[1] if has_mac else ""
                state_word = (fields[2] if has_mac and len(fields) > 2 else fields[1]).lower()
                rows.append((fields[0], zone, mac, _NEIGHBOR_STATES.get(state_word, "")))
    elif family == 6 and shutil.which("ndp"):
        output = _run_resolution_command(["ndp", "-an"], timeout=4)
        for line in output.splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 3:
                incomplete = "incomplete" in fields[1]
                state = "INCOMPLETE" if incomplete else _NEIGHBOR_STATES.get((fields[4] if len(fields) > 4 else "").lower(), "")
                rows.append((fields[0].split("%", 1)[0], fields[2], "" if incomplete else fields[1], state))
    elif family == 4 and shutil.which("arp"):
        output = _run_resolution_command(["arp", "-an"], timeout=4)
        for line in output.splitlines():
            match = re.search(r"\(([\d.]+)\) at (\S+)(?: on (\S+))?", line)
            if match and "incomplete" not in match.group(2):
                rows.append((match.group(1), match.group(3) or "", match.group(2), ""))
    return rows


def _normalise_mac(mac: str) -> str:
    """aa:bb:cc:dd:ee:ff form; also pads macOS's short octets (0:11:2 → 00:11:02)."""
    parts = re.split(r"[:\-]", mac.strip().lower())
    if len(parts) != 6 or not all(re.fullmatch(r"[0-9a-f]{1,2}", part) for part in parts):
        return mac.strip().lower()
    return ":".join(part.zfill(2) for part in parts)


def ipv6_neighbor_cache(interfaces: Optional[list[str]] = None) -> dict[str, str]:
    """Read the OS IPv6 neighbor cache as {address: MAC}, skipping failed entries."""
    wanted = set(interfaces or [])
    neighbors: dict[str, str] = {}
    for address, zone, mac, state in read_neighbor_entries(6):
        if state in {"FAILED", "INCOMPLETE"} or (sys.platform == "win32" and state == "PERMANENT"):
            continue
        if wanted and zone not in wanted:
            continue
        normalized = _with_zone(address, zone)
        if normalized:
            neighbors[normalized] = mac.lower().replace("-", ":")
    return neighbors


class NeighborEvidence:
    """Add MAC/vendor details and ARP/ND reachability evidence to scan results.

    Sending a probe to an on-link address makes the kernel resolve it with
    ARP (IPv4) or neighbor discovery (IPv6). A neighbor entry in the
    REACHABLE state therefore proves the host answered at layer 2, even when
    it drops ICMP. Only REACHABLE entries count (never STALE ones, which can
    be minutes old), and a MAC that answers for several scanned addresses is
    treated as proxy ARP and ignored as evidence.
    """

    PROXY_THRESHOLD = 3

    def __init__(self, use_as_evidence: bool = True, max_age: float = 1.0):
        self.use_as_evidence = use_as_evidence and sys.platform != "darwin"  # macOS arp shows no state
        self.max_age = max_age
        self.table: dict[str, tuple[str, str]] = {}
        self.read_at = 0.0
        self.lock = threading.Lock()

    def _refresh(self) -> None:
        if time.monotonic() - self.read_at < self.max_age:
            return
        table: dict[str, tuple[str, str]] = {}
        for family in (4, 6):
            for address, zone, mac, state in read_neighbor_entries(family):
                key = _with_zone(address, zone) if family == 6 else _normalise_probe_address(address)
                if key and mac:
                    table[key] = (_normalise_mac(mac), state)
        self.table = table
        self.read_at = time.monotonic()

    def enrich(self, result: dict) -> dict:
        with self.lock:
            self._refresh()
            entry = self.table.get(result["ip"])
            if entry is None:
                return result
            mac, state = entry
            sharing = sum(1 for other_mac, _state in self.table.values() if other_mac == mac)
        result["mac"] = mac
        result["vendor"] = mac_vendor(mac)
        if (
            self.use_as_evidence and not result["alive"] and state == "REACHABLE"
            and sharing < self.PROXY_THRESHOLD
        ):
            result.update(alive=True, status="REACHABLE", evidence="ARP/ND reply", arp=True)
        return result


# ─────────────────────────────────────────────────────────────────
# MAC VENDOR (OUI) LOOKUP
# ─────────────────────────────────────────────────────────────────
_OUI_TABLE: Optional[dict[str, str]] = None
_OUI_LOCK = threading.Lock()
OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"

# Used only when no OUI database is installed; covers common LAN vendors.
_BUILTIN_OUI = {
    "000C29": "VMware", "005056": "VMware", "000569": "VMware", "080027": "VirtualBox",
    "525400": "QEMU/KVM", "00155D": "Microsoft Hyper-V", "0242AC": "Docker", "B827EB": "Raspberry Pi",
    "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi", "D83ADD": "Raspberry Pi", "28CDC1": "Raspberry Pi",
    "001B63": "Apple", "3C0754": "Apple", "A4C361": "Apple", "F01898": "Apple", "ACBC32": "Apple",
    "001A11": "Google", "F4F5D8": "Google", "3C5AB4": "Google", "00000C": "Cisco", "0019E7": "Cisco",
    "001D7E": "Cisco-Linksys", "C0C1C0": "Cisco-Linksys", "00095B": "Netgear", "A42B8C": "Netgear",
    "F4F26D": "TP-Link", "50C7BF": "TP-Link", "C025E9": "TP-Link", "001E58": "D-Link", "00265A": "D-Link",
    "001132": "Synology", "0011D8": "ASUSTek", "2C56DC": "ASUSTek", "001372": "Dell", "F8BC12": "Dell",
    "3417EB": "Dell", "001B78": "HP", "3C4A92": "HP", "001E0B": "HP", "D8D385": "HP", "00215A": "HP",
    "001CBF": "Intel", "3C970E": "Intel", "A0369F": "Intel", "0024D7": "Intel", "00E04C": "Realtek",
    "001E06": "Wibrain", "34E6D7": "Dell", "000D93": "Apple", "00163E": "Xensource", "001F3B": "Intel",
    "5CA6E6": "TP-Link", "F09FC2": "Ubiquiti", "24A43C": "Ubiquiti", "788A20": "Ubiquiti", "FCECDA": "Ubiquiti",
    "0017C8": "Kyocera", "00807F": "Dayna", "0000AA": "Xerox", "00206B": "Konica Minolta", "001599": "Samsung",
    "5CF370": "CC&C", "8C8590": "Apple", "E0D55E": "Giga-Byte", "18C04D": "Giga-Byte", "40B076": "ASUSTek",
    "001EC9": "Dell", "002590": "Super Micro", "0CC47A": "Super Micro", "AC1F6B": "Super Micro",
    "00A0C9": "Intel", "001517": "Intel", "E4B97A": "Dell", "B8AC6F": "Dell", "F48E38": "Dell",
    "C8D3FF": "HP", "9457A5": "HP", "70106F": "HP", "B05ADA": "HP", "0050B6": "Good Way",
    "44D9E7": "Ubiquiti", "74DA38": "Edimax", "801F02": "Edimax", "00E018": "ASUSTek", "D850E6": "ASUSTek",
    "B0BE76": "TP-Link", "98DAC4": "TP-Link", "60E327": "TP-Link", "30B5C2": "TP-Link",
    "FCFBFB": "Cisco", "0026CB": "Cisco", "B4A4E3": "Cisco", "70B3D5": "IEEE Registration Authority",
    "D0034B": "Apple", "BC926B": "Apple", "A860B6": "Apple", "1C1AC0": "Apple",
    "00259C": "Cisco-Linksys", "001A70": "Cisco-Linksys", "000E08": "Cisco-Linksys",
    "B0C420": "Nmap (test)", "00113D": "KN Soltec",
}


def _oui_sources() -> list[Path]:
    return [
        _data_dir() / "oui.txt",
        Path("/usr/share/ieee-data/oui.txt"),
        Path("/usr/share/nmap/nmap-mac-prefixes"),
        Path("/usr/local/share/nmap/nmap-mac-prefixes"),
        Path("/opt/homebrew/share/nmap/nmap-mac-prefixes"),
        Path("/usr/share/arp-scan/ieee-oui.txt"),
        Path("/usr/share/wireshark/manuf"),
        Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Nmap" / "nmap-mac-prefixes",
        Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Wireshark" / "manuf",
    ]


def _parse_oui_file(path: Path) -> dict[str, str]:
    table: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return table
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        match = (
            re.match(r"^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$", line)   # IEEE
            or re.match(r"^([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2})\s+\S+\s+(.+)$", line)     # Wireshark
        )
        if match:
            table["".join(match.groups()[:3]).upper()] = match.group(4).strip()
            continue
        match = re.match(r"^([0-9A-Fa-f]{6})\s+(?:\(base 16\)\s+)?(.+)$", line)  # nmap, arp-scan, IEEE base-16 rows
        if match:
            table[match.group(1).upper()] = match.group(2).strip()
    return table


def _load_oui_table() -> dict[str, str]:
    global _OUI_TABLE
    with _OUI_LOCK:
        if _OUI_TABLE is None:
            table: dict[str, str] = dict(_BUILTIN_OUI)
            for source in reversed(_oui_sources()):  # earlier sources win
                if source.is_file():
                    table.update(_parse_oui_file(source))
            _OUI_TABLE = table
        return _OUI_TABLE


def mac_vendor(mac: str) -> str:
    """Manufacturer for a MAC address, "Private (randomized MAC)", or ""."""
    digits = re.sub(r"[^0-9A-Fa-f]", "", _normalise_mac(mac)).upper()
    if len(digits) != 12:
        return ""
    if digits == "000000000000" or digits == "FFFFFFFFFFFF":
        return ""
    if digits.startswith("0242"):
        return "Docker (virtual)"
    if int(digits[:2], 16) & 0x02:
        return "Private (randomized MAC)"
    vendor = _load_oui_table().get(digits[:6], "")
    return re.sub(r",?\s+(Inc|Ltd|Co|Corp|Corporation|LLC|GmbH|AG|S\.A)\.?$", "", vendor)


def update_oui_database() -> int:
    """Download the IEEE OUI registry into the data directory (explicit --update-oui only)."""
    import urllib.request
    destination = _data_dir() / "oui.txt"
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(OUI_URL, headers={"User-Agent": f"PingMe/{VERSION}"})
    print(f"  {C.CYAN}Downloading {OUI_URL} ...{C.RESET}", flush=True)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read()
    except OSError as exc:
        print(C.err(f"  ✗ Download failed: {exc}"), file=sys.stderr)
        return EXIT_ENVIRONMENT
    temporary = destination.with_suffix(".tmp")
    temporary.write_bytes(data)
    entries = len(_parse_oui_file(temporary))
    if entries < 1000:
        temporary.unlink()
        print(C.err("  ✗ The download did not look like the IEEE OUI registry; keeping the old one."), file=sys.stderr)
        return EXIT_ENVIRONMENT
    os.replace(temporary, destination)
    print(C.ok(f"  ✔  Saved {entries:,} vendor prefixes to {destination}"))
    return EXIT_OK


def discover_ipv6_neighbors(interfaces: list[str], timeout: float = 1.0) -> dict[str, str]:
    """Find IPv6 hosts on the local links, returning {address: MAC or ""}.

    A /64 cannot be swept, so candidates come from multicast echo replies and
    the neighbor cache that those replies refresh. Every candidate still goes
    through the normal fail-closed probe before it is reported as reachable.
    """
    candidates: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(len(interfaces), 16))) as pool:
        for replies in pool.map(lambda name: _multicast_echo_replies(name, timeout), interfaces):
            for address in replies:
                candidates.setdefault(address, "")
    for address, mac in ipv6_neighbor_cache(interfaces).items():
        if mac or address not in candidates:
            candidates[address] = mac
    own = _local_ipv6_addresses()
    return {address: mac for address, mac in sorted(candidates.items(), key=lambda item: ip_sort_key(item[0]))
            if address.split("%", 1)[0] not in own and not ipaddress.ip_address(address.split("%", 1)[0]).is_multicast}


def _local_ipv6_addresses() -> set[str]:
    """This machine's own IPv6 addresses, so discovery lists only other hosts."""
    own: set[str] = set()
    if sys.platform.startswith("linux") and shutil.which("ip"):
        output = _run_resolution_command(["ip", "-6", "-o", "addr", "show"], timeout=4)
        for match in re.finditer(r"inet6\s+([0-9A-Fa-f:]+)/", output):
            own.add(str(ipaddress.ip_address(match.group(1))))
        return own
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6):
            own.add(str(ipaddress.ip_address(info[4][0].split("%", 1)[0])))
    except (OSError, ValueError):
        pass
    return own


# ─────────────────────────────────────────────────────────────────
# PROGRESS BAR
# ─────────────────────────────────────────────────────────────────
_CLEAR_LINE = "\r\033[K"


def _line_start() -> str:
    """Return to column 0, erasing a progress bar drawn on a terminal."""
    return _CLEAR_LINE if sys.stdout.isatty() else "\r"


def _progress_bar(done: int, total: int, alive: int, no_response: int, errors: int, width: int = 38):
    if not sys.stdout.isatty():
        return  # a redirected log should hold result lines, not bar redraws
    pct  = done / total if total else 0
    fill = int(pct * width)
    bar  = f"{C.GREEN}{'█' * fill}{C.DIM}{'░' * (width - fill)}{C.RESET}"
    sys.stdout.write(
        f"{_CLEAR_LINE}  [{bar}] {C.BOLD}{pct*100:5.1f}%{C.RESET}  "
        f"{C.DIM}{done}/{total}{C.RESET}  "
        f"{C.GREEN}▲{alive}{C.RESET}  {C.RED}▼{no_response}{C.RESET}  {C.YELLOW}!{errors}{C.RESET}   "
    )
    sys.stdout.flush()


# ─────────────────────────────────────────────────────────────────
# SCAN ENGINE
# ─────────────────────────────────────────────────────────────────
def _fping_chunk_size(total: int) -> int:
    """Split large fping discoveries so progress and resume advance in steps.

    Each chunk pays one trailing timeout, so the count is capped at about 16
    chunks; a /24 is still discovered by a single fping process.
    """
    return max(256, math.ceil(total / 16))


def run_scan(
    ip_list:      list[str],
    threads:      int         = 20,
    timeout:      float       = 2,
    count:        int         = 2,
    retry:        int         = 0,
    rate:         int         = 0,
    label:        str         = "scan",
    quiet:        bool        = False,
    do_dns:       bool        = False,
    resume:       bool        = False,
    tcp_ports:    Optional[list[int]] = None,
    tcp_timeout:  float       = 2,
    min_replies:  int         = 2,
    resumable:    bool        = True,
    neighbors:    Optional["NeighborEvidence"] = None,
) -> list[dict]:
    """
    Scan all IPs. Returns list of result dicts.
    Supports: retry, rate-limit, resume (Ctrl+C safe with both backends), DNS, TTL.
    """
    # ── resume: skip already-done IPs ───────────────────────────
    done_results: list[dict] = []
    partial = load_partial(label) if resume else None
    if partial:
        done_ips  = {r["ip"] for r in partial["done"]}
        done_results = partial["done"]
        # Migrate resume files written before explicit probe-error statuses.
        for result in done_results:
            result.setdefault("status", "REACHABLE" if result.get("alive") else "NO RESPONSE")
            result.setdefault("evidence", "legacy result")
            result.setdefault("probe_error", "")
        ip_list   = [ip for ip in ip_list if ip not in done_ips]
        if not quiet:
            print(f"  {C.YELLOW}↺  Resuming — {len(done_results)} already done, "
                  f"{len(ip_list)} remaining{C.RESET}")
    elif resume and not quiet:
        print(f"  {C.DIM}No saved partial scan for '{label}'; starting a full scan.{C.RESET}")

    # A zone-less link-local address cannot be routed; report why instead of a silent no-response.
    zoneless = [ip for ip in ip_list if link_local_needs_zone(ip)]
    if zoneless:
        interfaces = ", ".join(ipv6_interfaces()[:6]) or "your interface"
        done_results = done_results + [
            _build_probe_result(
                ip, False, None, [],
                f"link-local address needs an interface zone, e.g. {ip}%{interfaces.split(',')[0]} "
                f"(interfaces: {interfaces})",
            )
            for ip in zoneless
        ]
        ip_list = [ip for ip in ip_list if ip not in set(zoneless)]

    total   = len(ip_list)
    if total == 0:
        if not quiet and not zoneless:
            print(f"  {C.LIME}✔  All IPs already scanned (resume complete).{C.RESET}")
        clear_partial(label)
        return done_results

    rl        = RateLimiter(rate) if rate > 0 else None
    results:  list[dict] = []
    _STOP_EVENT.clear()
    t_start   = time.time()
    interrupted = False
    use_native = _use_native()
    use_fping = _use_fping()
    batch_mode = use_native or use_fping
    required = max(1, min_replies)
    wait = timeout if timeout is not None else ADAPTIVE_TIMEOUT_CAP

    waves = (total + max(threads, 1) - 1) // max(threads, 1)
    confirm_est = max(count, required) * wait
    if use_native:
        # Requests are paced from one socket; silent hosts cost a single timeout.
        interval = 1.0 / rate if rate > 0 else NATIVE_DEFAULT_INTERVAL
        icmp_est = total * interval + max(count, required) * wait
        waves = 1
    elif use_fping:
        # Alive mode makes at most ``count`` attempts; positives then receive
        # independent integrity confirmations through system ping.
        icmp_est = count * wait + confirm_est
    else:
        icmp_est = confirm_est
    tcp_est = tcp_timeout if tcp_ports else 0
    est_sec = waves * (icmp_est + tcp_est) * (retry + 1)
    rate_str = f"  rate≤{rate}pkt/s" if rate > 0 else ""
    retry_str = f"  retry={retry}" if retry > 0 else ""
    dns_str  = "  +dns" if do_dns else ""
    tcp_str  = f"  tcp={','.join(str(port) for port in tcp_ports)}" if tcp_ports else ""
    if not quiet:
        print(
            f"\n  {C.CYAN}⠿ Scanning {C.BOLD}{total:,}{C.RESET}{C.CYAN} hosts"
            f"  │  threads={C.BOLD}{threads}{C.RESET}{C.CYAN}"
            f"  engine={_PING_TOOL}  timeout={'auto' if timeout is None else _format_seconds(timeout) + 's'}"
            f"  pkt/host={count}  replies≥{required}"
            f"{retry_str}{rate_str}{dns_str}{tcp_str}"
            f"  est≤{est_sec:.0f}s{C.RESET}\n"
        )

    counts = {"alive": 0, "no_response": 0, "errors": 0}

    def _report(result: dict, done: int) -> None:
        """Enrich one finished target, print it, and advance the progress bar in O(1)."""
        if neighbors is not None:
            neighbors.enrich(result)
        if result["alive"]:
            counts["alive"] += 1
        elif result.get("status") == "PROBE ERROR":
            counts["errors"] += 1
        else:
            counts["no_response"] += 1
        if quiet:
            return
        ip = result["ip"]
        if result["alive"]:
            os_g = result["os_guess"]
            ttl_s = f"TTL={result['ttl']}" if result["ttl"] else "TTL=?"
            reach_s = "ICMP" if result["icmp_alive"] else (
                f"TCP:{','.join(str(port) for port in result['tcp_open'])}" if result["tcp_open"] else "ARP/ND")
            rtt_s = f"{result['rtt_avg']}ms" if result.get("rtt_avg") is not None else ""
            dns_s = f"  {C.DIM}{result['hostname'][:28]}{C.RESET}" if result["hostname"] else ""
            sys.stdout.write(
                f"{_line_start()}  {C.GREEN}✔ {ip:<18}{C.RESET}"
                f"  {C.DIM}{reach_s:<12} {ttl_s:<8} {rtt_s:<9}{C.RESET}"
                f"  {ttl_color(os_g)}{os_g:<16}{C.RESET}"
                f"  {C.CYAN}[{result['scope']}]{C.RESET}"
                f"{dns_s}\n"
            )
        elif result.get("status") == "PROBE ERROR":
            sys.stdout.write(
                f"{_line_start()}  {C.YELLOW}! {ip:<18}{C.RESET}"
                f"  {C.YELLOW}{'PROBE ERROR':<12}{C.RESET}"
                f"  {C.DIM}{result.get('probe_error', '')[:44]}{C.RESET}\n"
            )
        elif not batch_mode:
            # Batch modes list only positives; a /16 of silent hosts would flood the terminal.
            sys.stdout.write(
                f"{_line_start()}  {C.RED}✘ {ip:<18}{C.RESET}"
                f"  {C.DIM}{'NO RESPONSE':<12} {'TTL=?':<8}{C.RESET}"
                f"  {C.DIM}{'Unknown':<16}{C.RESET}"
                f"  {C.CYAN}[{result['scope']}]{C.RESET}\n"
            )
        _progress_bar(done, total, counts["alive"], counts["no_response"], counts["errors"])

    # ── Ctrl+C handler: stop cleanly and keep finished work for --resume ──
    def _sigint(sig, frame):
        nonlocal interrupted
        if interrupted:
            raise KeyboardInterrupt
        interrupted = True
        _STOP_EVENT.set()
        if resumable:
            sys.stdout.write(f"\n\n  {C.YELLOW}⚠  Interrupted — saving partial results (Ctrl+C again to abort)...{C.RESET}\n")
            sys.stdout.flush()

    try:
        old_handler = signal.signal(signal.SIGINT, _sigint)
    except ValueError:  # not in the main thread (embedded use)
        old_handler = None

    try:
        if batch_mode:
            chunk_size = _fping_chunk_size(total)
            for start in range(0, total, chunk_size):
                if interrupted:
                    break
                chunk = ip_list[start:start + chunk_size]
                if not quiet and total > chunk_size and sys.stdout.isatty():
                    sys.stdout.write(
                        f"{_line_start()}  {C.DIM}Discovering {start + 1:,}–{start + len(chunk):,} of {total:,} with {_PING_TOOL}...{C.RESET}   "
                    )
                    sys.stdout.flush()
                base = len(results)
                report = (lambda result, completed, _total, base=base: _report(result, base + completed))
                if use_native:
                    chunk_results = _scan_native_batch(
                        chunk, timeout, count, retry, rate, do_dns, tcp_ports, tcp_timeout,
                        report, threads=threads, min_replies=required,
                    )
                else:
                    chunk_results = _scan_fping_batch(
                        chunk, wait, count, retry, rate, do_dns, tcp_ports, tcp_timeout,
                        report, threads=threads, min_replies=required, rate_limiter=rl,
                    )
                if interrupted:
                    # The signal also reached fping and ping children, so this
                    # chunk's evidence is incomplete. It will be rescanned.
                    break
                results.extend(chunk_results)
        else:
            pool = ThreadPoolExecutor(max_workers=threads)
            try:
                futures = {
                    pool.submit(
                        _probe_with_retry, ip, wait, count, retry, rl,
                        do_dns, tcp_ports, tcp_timeout, required,
                    ): ip
                    for ip in ip_list
                }
                for fut in as_completed(futures):
                    if interrupted:
                        break
                    try:
                        res = fut.result()
                    except Exception as exc:
                        ip = futures[fut]
                        res = _build_probe_result(ip, False, None, [], str(exc) or type(exc).__name__)
                        if not quiet:
                            print(C.warn(f"\n  ⚠  Scan failed for {ip}: {exc}"))
                    if interrupted:
                        # The result may come from a ping the signal cut short.
                        break
                    _report(res, len(results) + 1)
                    results.append(res)
            finally:
                pool.shutdown(wait=True, cancel_futures=True)
    finally:
        if old_handler is not None:
            signal.signal(signal.SIGINT, old_handler)

    elapsed = time.time() - t_start

    if interrupted and not resumable:
        return done_results + results

    if interrupted:
        finished = {r["ip"] for r in results}
        remaining = [ip for ip in ip_list if ip not in finished]
        all_done  = done_results + results
        save_partial(label, all_done, remaining)
        if not quiet:
            print(f"  {C.YELLOW}Partial results saved ({len(all_done)} done, {len(remaining)} remaining). "
                  f"Re-run the same command with --resume to continue.{C.RESET}\n")
        # Return what we have so alive/dead files are still written
        return all_done

    if not quiet:
        print(f"\n\n  {C.DIM}Scan finished in {elapsed:.1f}s{C.RESET}\n")
    clear_partial(label)

    # Merge with any previously-resumed results
    all_results = done_results + results

    # Sort by IP
    all_results.sort(key=lambda r: ip_sort_key(r["ip"]))

    return all_results


# ─────────────────────────────────────────────────────────────────
# WRITE OUTPUT FILES  (plain + rich CSV + JSON)
# ─────────────────────────────────────────────────────────────────
def write_results(
    results:    list[dict],
    alive_file: str  = "alive.txt",
    dead_file:  str  = "dead.txt",
    out_format: str  = "txt",
    error_file: str  = "errors.txt",
    quiet:      bool = False,
    verbose:    bool = False,
):
    alive = [r for r in results if r["alive"]]
    dead  = [r for r in results if r.get("status") == "NO RESPONSE"]
    errors = [r for r in results if r.get("status") == "PROBE ERROR"]
    total = len(results)
    pct_a = (len(alive) / total * 100) if total else 0
    pct_d = (len(dead)  / total * 100) if total else 0
    pct_e = (len(errors) / total * 100) if total else 0

    alive_path, dead_path, error_path = (Path(path).expanduser() for path in (alive_file, dead_file, error_file))
    for destination in (alive_path, dead_path, error_path):
        destination.parent.mkdir(parents=True, exist_ok=True)

    if out_format == "json":
        alive_path.write_text(json.dumps([r for r in alive], indent=2) + "\n", encoding="utf-8")
        dead_path.write_text(json.dumps([r for r in dead], indent=2) + "\n", encoding="utf-8")
        error_path.write_text(json.dumps([r for r in errors], indent=2) + "\n", encoding="utf-8")
    elif out_format == "csv":
        fields = [
            "ip", "status", "alive", "evidence", "probe_error", "icmp_alive", "tcp_open",
            "ttl", "rtt_min", "rtt_avg", "loss_pct", "os_guess", "hostname", "mac", "vendor", "scope", "rfc",
        ]
        for path, rows in ((alive_path, alive), (dead_path, dead), (error_path, errors)):
            with path.open("w", newline="", encoding="utf-8") as output:
                writer = csv.DictWriter(output, fieldnames=fields)
                writer.writeheader()
                writer.writerows(
                    {
                        field: ";".join(str(port) for port in row.get("tcp_open", []))
                        if field == "tcp_open" else ("" if row.get(field) is None else row.get(field))
                        for field in fields
                    }
                    for row in rows
                )
    else:  # txt — plain IPs, one per line
        alive_path.write_text("\n".join(r["ip"] for r in alive) + ("\n" if alive else ""), encoding="utf-8")
        dead_path.write_text("\n".join(r["ip"] for r in dead) + ("\n" if dead else ""), encoding="utf-8")
        error_path.write_text("\n".join(r["ip"] for r in errors) + ("\n" if errors else ""), encoding="utf-8")

    if quiet:
        return

    if not verbose:
        print(
            f"Scan complete: total={total} reachable={len(alive)} "
            f"no_response={len(dead)} errors={len(errors)}"
        )
        print(f"Saved: {alive_file}, {dead_file}, {error_file}")
        return

    box_w = 58
    div   = f"  {C.CYAN}{'─' * box_w}{C.RESET}"
    print(f"\n  {C.BOLD}{C.LIME}┌{'─' * (box_w + 2)}┐")
    print(f"  │{'  📊  SCAN RESULTS':^{box_w + 2}}│")
    print(f"  └{'─' * (box_w + 2)}┘{C.RESET}")
    print(div)
    print(f"  {C.DIM}│{C.RESET}  {'Total scanned':<28}{C.BOLD}{C.WHITE}{total:>6}{C.RESET}")
    print(f"  {C.DIM}│{C.RESET}  {C.GREEN}{'Reachable (ICMP/TCP)':<28}{C.BOLD}{len(alive):>6}{C.RESET}  {C.DIM}({pct_a:.1f}%){C.RESET}")
    print(f"  {C.DIM}│{C.RESET}  {C.RED}{'No ICMP/TCP response':<28}{C.BOLD}{len(dead):>6}{C.RESET}  {C.DIM}({pct_d:.1f}%){C.RESET}")
    print(f"  {C.DIM}│{C.RESET}  {C.YELLOW}{'Probe errors':<28}{C.BOLD}{len(errors):>6}{C.RESET}  {C.DIM}({pct_e:.1f}%){C.RESET}")
    print(div)

    # OS breakdown from TTL
    os_counts: dict[str, int] = {}
    for r in alive:
        g = r.get("os_guess") or "Unknown"
        os_counts[g] = os_counts.get(g, 0) + 1
    if os_counts:
        print(f"  {C.DIM}│{C.RESET}  {C.BOLD}OS-family hints (TTL heuristic):{C.RESET}")
        for os_g, cnt in sorted(os_counts.items(), key=lambda x: -x[1]):
            col = ttl_color(os_g)
            print(f"  {C.DIM}│{C.RESET}    {col}{os_g:<20}{C.RESET}  {C.BOLD}{cnt}{C.RESET}")
        print(div)

    print(f"  {C.DIM}│{C.RESET}  {C.CYAN}alive → {alive_file}  ({out_format}){C.RESET}")
    print(f"  {C.DIM}│{C.RESET}  {C.CYAN}no response → {dead_file}  ({out_format}){C.RESET}")
    print(f"  {C.DIM}│{C.RESET}  {C.CYAN}probe errors → {error_file}  ({out_format}){C.RESET}")
    print(div)

    if total:
        bar_w = 40
        n   = int(pct_a / 100 * bar_w)
        bar = f"{C.GREEN}{'█' * n}{C.RED}{'█' * (bar_w - n)}{C.RESET}"
        print(f"\n  Reachable/other ratio:  {bar}  {C.GREEN}{pct_a:.0f}%{C.RESET} reachable\n")


# ─────────────────────────────────────────────────────────────────
# HISTORY COMPARISON
# ─────────────────────────────────────────────────────────────────
def history_changes(
    previous: dict,
    current_alive: list[str],
    current_dead: list[str],
    current_errors: Optional[list[str]] = None,
) -> dict[str, list[str]]:
    """Classify IP transitions between two scans.

    Only a completed probe with no response counts as offline. A previously
    reachable host whose probe now failed is indeterminate, not down.
    """
    prev_alive = set(previous.get("alive", []))
    prev_dead  = set(previous.get("dead", []))
    curr_alive = set(current_alive)
    curr_dead  = set(current_dead)
    curr_errors = set(current_errors or [])
    return {
        "newly_up": sorted(curr_alive - prev_alive),
        "newly_down": sorted(prev_alive & curr_dead),
        "stayed_up": sorted(curr_alive & prev_alive),
        "stayed_down": sorted(curr_dead & prev_dead),
        "indeterminate": sorted(prev_alive & curr_errors),
    }


def compare_history(
    label: str,
    current_alive: list[str],
    current_dead: list[str],
    current_errors: Optional[list[str]] = None,
    saved_current: bool = True,
):
    """Compare this scan with the previous one for the label.

    ``saved_current`` is False with --no-history: the newest stored entry is
    then the previous scan, not this one.
    """
    history = load_history(label)
    if not saved_current:
        history = history + [{
            "timestamp": datetime.now().isoformat(),
            "alive": sorted(current_alive),
            "dead": sorted(current_dead),
        }]
    if len(history) < 2:
        print(f"\n  {C.warn('⚠  Not enough history for comparison (need ≥ 2 scans).')}")
        return

    prev       = history[-2]
    prev_ts    = prev.get("timestamp", "unknown")
    changes    = history_changes(prev, current_alive, current_dead, current_errors)
    newly_up   = changes["newly_up"]
    newly_down = changes["newly_down"]
    stayed_up  = changes["stayed_up"]
    stayed_dn  = changes["stayed_down"]
    unknown    = changes["indeterminate"]

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
    print(f"  {C.YELLOW}  ? Probe error   : {len(unknown):>4}{C.RESET}  {C.DIM}(was alive; not counted as down){C.RESET}")
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
def read_snapshot_ips(path: str) -> set[str]:
    """Read the addresses in a txt, csv, or json result file written by PingMe.

    Plain files may also hold hostnames or comments; the first field of each
    line is used so hand-written snapshots keep working.
    """
    p = Path(path).expanduser()
    if not p.is_file():
        print(C.err(f"  ✗ File not found: {path}"), file=sys.stderr); sys.exit(EXIT_USAGE)
    text = p.read_text(encoding="utf-8-sig", errors="replace")
    stripped = text.lstrip()

    def _canonical(value: object) -> str:
        token = str(value).strip().strip('"').strip("'")
        address = _normalise_probe_address(token)
        return address if address is not None else token

    if stripped.startswith(("[", "{")):
        try:
            data = json.loads(stripped)
        except ValueError:
            data = None
        if isinstance(data, dict):
            data = data.get("results", data.get("alive", []))
        if isinstance(data, list):
            found = {
                _canonical(item.get("ip", "")) if isinstance(item, dict) else _canonical(item)
                for item in data
            }
            return {item for item in found if item}

    lines = [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if lines:
        header = [field.strip().lower() for field in next(csv.reader([lines[0]]))]
        if "ip" in header:
            column = header.index("ip")
            rows = csv.reader(lines[1:])
            return {_canonical(row[column]) for row in rows if len(row) > column and row[column].strip()}

    found: set[str] = set()
    for line in lines:
        first = re.split(r"[\s,]+", line.strip(), maxsplit=1)[0]
        if first:
            found.add(_canonical(first))
    return found


def diff_files(file_a: str, file_b: str):
    read_ips = read_snapshot_ips
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
    print(f"  {C.RED}  In A only (went offline) : {len(only_a)}{C.RESET}")
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
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if _normalise_probe_address(str(parsed)) is None:
            continue
        address = str(parsed)
        if address not in addresses:
            addresses.append(address)

    # IPv6 can use leading/trailing compression (for example ::1 or
    # 2001:db8::). Extract broad colon-containing tokens, then let ipaddress
    # perform strict validation.
    for token in re.findall(r"[0-9A-Fa-f:%]*:[0-9A-Fa-f:.%]+", text):
        candidate = token.split("%", 1)[0].strip("[](),;")
        if candidate.endswith(":") and not candidate.endswith("::"):
            candidate = candidate[:-1]
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if _normalise_probe_address(str(parsed)) is None:
            continue
        address = str(parsed)
        if address not in addresses:
            addresses.append(address)

    return addresses


def _run_resolution_command(
    command: list[str],
    timeout: int = 8,
    accepted_returncodes: tuple[int, ...] = (0,),
) -> str:
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

    if proc.returncode not in accepted_returncodes:
        return ""

    return _decode_probe_output(proc.stdout or b"")


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
        # ping exits 1 for a resolved host that sends no echo reply; its header
        # is still valid resolution evidence. Other tools must exit cleanly so
        # that error text cannot be mistaken for an address.
        accepted_returncodes = (0, 1) if kind.startswith("ping") else (0,)
        output = _run_resolution_command(command, accepted_returncodes=accepted_returncodes)
        if not output:
            continue

        # Prefer the address shown in the Windows ping header. This avoids
        # accidentally taking a DNS server address from nslookup output.
        if kind.startswith("ping"):
            match = re.search(r"^\s*Pinging\s+.+?\s+\[([^\]]+)\]", output, re.IGNORECASE | re.MULTILINE)
            if match:
                candidate = match.group(1).split("%", 1)[0]
                address = _normalise_probe_address(candidate)
                if address is not None:
                    return [address]

        found = _extract_ip_addresses(output)
        if not found:
            continue

        if kind == "nslookup":
            # nslookup prints the DNS server before any answer and may exit 0
            # even after a timeout. Require a separate answer address; this
            # intentionally favors a false negative over scanning the resolver.
            if len(found) < 2:
                continue
            return found[1:]
        return found

    return []


def _resolve_with_getent(hostname: str) -> list[str]:
    """Resolve through Linux NSS with a hard process deadline."""
    getent = shutil.which("getent")
    if not getent:
        return []

    addresses: list[str] = []
    output = _run_resolution_command([getent, "ahosts", hostname], timeout=4)
    for line in output.splitlines():
        fields = line.split()
        if not fields:
            continue
        candidate = fields[0].split("%", 1)[0]
        address = _normalise_probe_address(candidate)
        if address is None:
            continue
        if address not in addresses:
            addresses.append(address)
    return addresses


def _resolve_with_bounded_python(hostname: str) -> list[str]:
    """Run Python's socket resolver out-of-process so it can be timed out."""
    resolver_code = (
        "import socket,sys\n"
        "seen=set()\n"
        "for row in socket.getaddrinfo(sys.argv[1],None):\n"
        " address=str(row[4][0]).split('%',1)[0]\n"
        " if address not in seen:\n"
        "  print(address)\n"
        "  seen.add(address)\n"
    )
    output = _run_resolution_command(
        [sys.executable, "-c", resolver_code, hostname], timeout=4
    )
    addresses: list[str] = []
    for line in output.splitlines():
        try:
            address = _normalise_probe_address(line.strip())
        except ValueError:
            address = None
        if address is not None and address not in addresses:
            addresses.append(address)
    return addresses


def is_safe_hostname(hostname: str) -> bool:
    """Reject names that a resolver command could parse as an option or split.

    Hostnames are passed as arguments to getent, ping, nslookup, and nbtstat.
    A leading "-" would be read as a flag (for example "-t" makes Windows ping
    run forever), and whitespace or control characters are never valid.
    """
    return bool(hostname) and not hostname.startswith("-") and not any(
        character.isspace() or ord(character) < 32 for character in hostname
    )


def resolve_hostname(hostname: str) -> list[str]:
    """Resolve names through bounded OS-specific resolver processes."""
    hostname = hostname.strip().strip('"').strip("'")
    if not is_safe_hostname(hostname):
        return []

    if sys.platform.startswith("linux") and shutil.which("getent"):
        # getent follows NSS (DNS, /etc/hosts, mDNS, winbind, and configured
        # providers). Running it out-of-process lets PingMe enforce a deadline.
        addresses = _resolve_with_getent(hostname)
    else:
        addresses = _resolve_with_bounded_python(hostname)

    if not addresses:
        addresses.extend(_resolve_with_windows_tools(hostname))

    if _ADDRESS_FAMILY:
        addresses = [address for address in addresses if address_family(address) == _ADDRESS_FAMILY]
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
        kind_color = {
            "DNS": C.LIME,
            "DIRECT IP": C.YELLOW,
            "FILE MAP": C.CYAN,
        }.get(row_type, C.RED)
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
        rtt = loss = "-"
        name = mac = vendor = ""

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
                status = str(result.get("status") or ("REACHABLE" if result.get("alive") else "NO RESPONSE"))
                if result.get("icmp_alive"):
                    method = "ICMP"
                elif result.get("tcp_open"):
                    method = "TCP:" + ",".join(str(port) for port in result.get("tcp_open", []))
                elif result.get("arp"):
                    method = "ARP/ND"
                elif status == "PROBE ERROR":
                    method = "ERROR"
                else:
                    method = "-"
                ttl_value = result.get("ttl")
                ttl = str(ttl_value) if ttl_value is not None else "?"
                os_guess = str(result.get("os_guess") or "Unknown")
                if result.get("rtt_avg") is not None:
                    rtt = f"{result['rtt_avg']:g}"
                if result.get("loss_pct") is not None:
                    loss = f"{result['loss_pct']}%"
                name = str(result.get("hostname") or "")
                mac = str(result.get("mac") or "")
                vendor = str(result.get("vendor") or "")

        records.append({
            "host": host,
            "ip": ip_value,
            "status": status,
            "method": method,
            "ttl": ttl,
            "rtt": rtt,
            "loss": loss,
            "os_guess": os_guess,
            "name": name,
            "mac": mac,
            "vendor": vendor,
            "tags": " ".join(row.get("tags") or []),
        })

    return records


def _status_counts(records: list[dict]) -> dict[str, int]:
    return {
        "reachable": sum(1 for record in records if record["status"] == "REACHABLE"),
        "no_response": sum(1 for record in records if record["status"] == "NO RESPONSE"),
        "unresolved": sum(1 for record in records if record["status"] == "UNRESOLVED"),
        "probe_error": sum(1 for record in records if record["status"] == "PROBE ERROR"),
        "other": sum(1 for record in records if record["status"] in {"EXCLUDED", "NOT SCANNED"}),
    }


# (header, record key, minimum width, maximum width)
_STATUS_COLUMNS = [
    ("HOST", "host", 12, 48),
    ("IP ADDRESS", "ip", 15, 56),
    ("STATUS", "status", 11, 13),
    ("METHOD", "method", 6, 24),
    ("TTL", "ttl", 3, 5),
    ("RTT ms", "rtt", 6, 9),
    ("LOSS", "loss", 4, 5),
    ("OS GUESS", "os_guess", 8, 24),
    ("REVERSE DNS", "name", 11, 40),
    ("MAC", "mac", 17, 17),
    ("VENDOR", "vendor", 6, 24),
    ("TAGS", "tags", 4, 24),
]


def _status_columns(
    records: list[dict], hide_host: bool = False, host_header: str = "HOST"
) -> list[tuple[str, str, int]]:
    """Choose visible columns and widths; reverse DNS appears only when some name is known."""
    columns: list[tuple[str, str, int]] = []
    for header, key, minimum, maximum in _STATUS_COLUMNS:
        if key in {"name", "mac", "vendor", "tags"} and not any(record.get(key) for record in records):
            continue
        if key == "host" and hide_host:
            continue
        if key == "host":
            header = host_header
        longest = max([len(header)] + [len(str(record.get(key, ""))) for record in records])
        columns.append((header, key, min(max(minimum, longest), maximum)))
    return columns


def _status_summary(records: list[dict]) -> str:
    counts = _status_counts(records)
    summary = (
        f"Reachable: {counts['reachable']}  "
        f"No response: {counts['no_response']}  "
        f"Probe errors: {counts['probe_error']}  "
        f"Unresolved: {counts['unresolved']}"
    )
    if counts["other"]:
        summary += f"  Not scanned/excluded: {counts['other']}"
    return summary


def _plain_table(records: list[dict], title: str) -> str:
    """Return a portable ASCII table with no ANSI escape sequences."""
    columns = _status_columns(records)
    line = "+" + "+".join("-" * (width + 2) for _header, _key, width in columns) + "+"
    output = [title, "", line]
    output.append("| " + " | ".join(f"{header:<{width}}" for header, _key, width in columns) + " |")
    output.append(line)
    for record in records:
        values = [str(record.get(key, ""))[:width] for _header, key, width in columns]
        output.append("| " + " | ".join(
            f"{value:<{width}}" for value, (_header, _key, width) in zip(values, columns)
        ) + " |")
    output.append(line)
    output.extend([_status_summary(records), ""])
    return "\n".join(output)


def write_hostnames_report(
    records: list[dict],
    source: str,
    output_file: str = "hostnames.txt",
    announce: bool = True,
) -> Path:
    """Save HOST, IP, STATUS, METHOD, TTL, and OS details after every file scan."""
    destination = Path(output_file).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    report = _plain_table(records, f"FILE SCAN STATUS · {source}")
    destination.write_text(report, encoding="utf-8")
    if announce:
        print(f"  {C.CYAN}[report] host details → {destination}{C.RESET}")
    return destination


def load_changes_state(label: str) -> Optional[dict]:
    data = _read_state("changes", label)
    return data if isinstance(data, dict) else None


def save_changes_state(label: str, source: str, records: list[dict]) -> None:
    _write_json_atomic(_state_path("changes", label), {
        "source": source,
        "timestamp": datetime.now().isoformat(),
        "records": records,
    })


def _compact_host_table(title: str, records: list[dict]) -> list[str]:
    host_w = min(40, max(12, max([len("HOST")] + [len(str(r.get("host", ""))) for r in records])))
    ip_w = min(48, max(15, max([len("IP ADDRESS")] + [len(str(r.get("ip", ""))) for r in records])))
    line = "+" + "-" * (host_w + 2) + "+" + "-" * (ip_w + 2) + "+"
    lines = [title, line, f"| {'HOST':<{host_w}} | {'IP ADDRESS':<{ip_w}} |", line]
    for record in records:
        lines.append(f"| {str(record.get('host', ''))[:host_w]:<{host_w}} | {str(record.get('ip', ''))[:ip_w]:<{ip_w}} |")
    lines.append(line)
    return lines


def _ip_change_table(title: str, changes: list[dict]) -> list[str]:
    host_w = min(40, max([12] + [len(str(change["host"])) for change in changes]))
    ip_w = min(48, max([15] + [len(str(change["old_ip"])) for change in changes]
                       + [len(str(change["ip"])) for change in changes]))
    status_w = 13
    line = "+" + "-" * (host_w + 2) + "+" + "-" * (ip_w + 2) + "+" + "-" * (ip_w + 2) + "+" + "-" * (status_w + 2) + "+"
    lines = [title, line, f"| {'HOST':<{host_w}} | {'OLD IP':<{ip_w}} | {'NEW IP':<{ip_w}} | {'STATUS NOW':<{status_w}} |", line]
    for change in changes:
        lines.append(
            f"| {str(change['host'])[:host_w]:<{host_w}} | {str(change['old_ip'])[:ip_w]:<{ip_w}} "
            f"| {str(change['ip'])[:ip_w]:<{ip_w}} | {str(change['status'])[:status_w]:<{status_w}} |"
        )
    lines.append(line)
    return lines


def _value_change_table(title: str, changes: list[dict], old_label: str, new_label: str) -> list[str]:
    widths = [
        min(40, max([12] + [len(str(c["host"])) for c in changes])),
        min(48, max([15] + [len(str(c["ip"])) for c in changes])),
        min(40, max([len(old_label)] + [len(str(c["old"])) for c in changes])),
        min(40, max([len(new_label)] + [len(str(c["new"])) for c in changes])),
    ]
    line = "+" + "+".join("-" * (width + 2) for width in widths) + "+"
    headers = ["HOST", "IP ADDRESS", old_label, new_label]
    lines = [title, line, "| " + " | ".join(f"{h:<{w}}" for h, w in zip(headers, widths)) + " |", line]
    for change in changes:
        values = [change["host"], change["ip"], change["old"], change["new"]]
        lines.append("| " + " | ".join(f"{str(v)[:w]:<{w}}" for v, w in zip(values, widths)) + " |")
    lines.append(line)
    return lines


def _pair_ip_changes(groups: dict[str, list[dict]]) -> None:
    """Turn a removed (host, old IP) plus an added (host, new IP) into one IP change.

    Without this, a DHCP renumbering shows up as a target removed from the file
    and a new one added, which hides that the host itself is unchanged.
    """
    def _resolved(record: dict) -> bool:
        return str(record.get("ip", "")) not in {"", "UNRESOLVED"}

    added: dict[str, list[dict]] = {}
    for record in groups["new_targets"]:
        if _resolved(record):
            added.setdefault(str(record["host"]), []).append(record)
    removed: dict[str, list[dict]] = {}
    for record in groups["removed_targets"]:
        if _resolved(record):
            removed.setdefault(str(record.get("host", "")), []).append(record)

    paired_new: set[int] = set()
    paired_old: set[int] = set()
    for host in added.keys() & removed.keys():
        for new, old in zip(added[host], removed[host]):
            groups["ip_changed"].append({
                "host": host,
                "old_ip": old.get("ip", ""),
                "ip": new.get("ip", ""),
                "old_status": old.get("status", ""),
                "status": new.get("status", ""),
            })
            paired_new.add(id(new))
            paired_old.add(id(old))
    groups["new_targets"] = [r for r in groups["new_targets"] if id(r) not in paired_new]
    groups["removed_targets"] = [r for r in groups["removed_targets"] if id(r) not in paired_old]


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
        "indeterminate": [],
        "ip_changed": [],
        "name_changed": [],
        "mac_changed": [],
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
            f"Probe errors : {counts['probe_error']}",
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
        for field, group in (("name", "name_changed"), ("mac", "mac_changed")):
            before, after = str(old.get(field) or ""), str(current.get(field) or "")
            if before and after and before != after:
                groups[group].append({**current, "old": before, "new": after})
        old_status = old.get("status")
        now_status = current.get("status")
        if old_status == "NO RESPONSE" and now_status == "REACHABLE":
            groups["newly_online"].append(current)
        elif old_status == "REACHABLE" and now_status == "NO RESPONSE":
            groups["went_offline"].append(current)
        elif old_status == "REACHABLE" and now_status == "REACHABLE":
            groups["still_online"].append(current)
        elif old_status == "NO RESPONSE" and now_status == "NO RESPONSE":
            groups["still_offline"].append(current)
        else:
            groups["indeterminate"].append(current)

    for key, old in previous_map.items():
        if key not in current_map:
            groups["removed_targets"].append(old)
    _pair_ip_changes(groups)

    previous_time = str(previous.get("timestamp", "unknown")).replace("T", " ")[:19]
    lines = [
        f"CHANGES SINCE LAST SCAN · {source}",
        "",
        f"Previous scan : {previous_time}",
        f"Current scan  : {current_time}",
        "",
    ]

    important = (
        groups["newly_online"] or groups["went_offline"] or groups["new_targets"]
        or groups["removed_targets"] or groups["ip_changed"]
        or groups["name_changed"] or groups["mac_changed"]
    )
    if not important:
        lines.extend([
            "NO CONCLUSIVE CHANGES DETECTED",
            "",
            (
                "Some hosts are indeterminate because a probe or resolution failed."
                if groups["indeterminate"]
                else "All conclusively tested hosts have the same status as the previous scan."
            ),
            "",
        ])
    else:
        if groups["newly_online"]:
            lines.extend(_compact_host_table("NEWLY ONLINE", groups["newly_online"]))
            lines.append("")
        if groups["went_offline"]:
            lines.extend(_compact_host_table("WENT OFFLINE", groups["went_offline"]))
            lines.append("")
        if groups["ip_changed"]:
            lines.extend(_ip_change_table("IP ADDRESS CHANGED", groups["ip_changed"]))
            lines.append("")
        for group, title, old_label, new_label in (
            ("mac_changed", "MAC ADDRESS CHANGED (device replaced or IP conflict?)", "OLD MAC", "NEW MAC"),
            ("name_changed", "REVERSE DNS NAME CHANGED", "OLD NAME", "NEW NAME"),
        ):
            if groups[group]:
                lines.extend(_value_change_table(title, groups[group], old_label, new_label))
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
        f"Indeterminate: {len(groups['indeterminate'])}",
        f"IP changed   : {len(groups['ip_changed'])}",
        f"MAC changed  : {len(groups['mac_changed'])}",
        f"Name changed : {len(groups['name_changed'])}",
        f"New targets  : {len(groups['new_targets'])}",
        f"Removed      : {len(groups['removed_targets'])}",
        f"Unresolved   : {current_counts['unresolved']}",
        f"Probe errors : {current_counts['probe_error']}",
        "",
    ])
    return "\n".join(lines), groups


def write_changes_report(
    previous: Optional[dict],
    current_records: list[dict],
    source: str,
    output_file: str = "changes.txt",
    display: str = "full",
) -> dict[str, list[dict]]:
    """Save the change report; ``display`` is "full", "summary" (one line), or "none"."""
    report, groups = create_changes_report(previous, current_records, source)
    destination = Path(output_file).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(report, encoding="utf-8")
    if display == "none":
        return groups
    if display == "summary":
        if previous:
            print(
                f"Changes: newly_online={len(groups['newly_online'])} went_offline={len(groups['went_offline'])} "
                f"ip_changed={len(groups['ip_changed'])} mac_changed={len(groups['mac_changed'])} "
                f"name_changed={len(groups['name_changed'])} new={len(groups['new_targets'])} "
                f"removed={len(groups['removed_targets'])} → {destination}"
            )
        else:
            print(f"Changes: baseline saved → {destination}")
        return groups

    # Keep the terminal output easy to understand while the saved report stays plain.
    print(f"\n  {C.BOLD}{C.MAGENTA}{report.splitlines()[0]}{C.RESET}\n")
    for line in report.splitlines()[1:]:
        if line in {"NEWLY ONLINE", "NO CONCLUSIVE CHANGES DETECTED"}:
            print(f"  {C.GREEN}{C.BOLD}{line}{C.RESET}")
        elif line == "WENT OFFLINE":
            print(f"  {C.RED}{C.BOLD}{line}{C.RESET}")
        elif line in {"NEW TARGETS ADDED TO FILE", "TARGETS REMOVED FROM FILE", "IP ADDRESS CHANGED",
                      "REVERSE DNS NAME CHANGED", "SUMMARY"} or line.startswith("MAC ADDRESS CHANGED"):
            print(f"  {C.YELLOW}{C.BOLD}{line}{C.RESET}")
        else:
            print(f"  {line}")
    print(f"\n  {C.CYAN}[report] changes → {destination}{C.RESET}\n")
    return groups


_STATUS_COLORS = {
    "REACHABLE": "GREEN",
    "NO RESPONSE": "RED",
    "UNRESOLVED": "YELLOW",
    "PROBE ERROR": "YELLOW",
}


def show_file_scan_status(
    rows: list[dict],
    results: list[dict],
    source: str,
    title: str = "FILE SCAN STATUS",
    hide_host: bool = False,
    host_header: str = "HOST",
) -> list[dict]:
    """Show every target entry, resolved IP, and final reachability in one table."""
    if not rows:
        return []

    records = build_file_status_records(rows, results)
    columns = _status_columns(records, hide_host, host_header)
    line = "  " + C.PURPLE + "+" + "+".join("-" * (width + 2) for _h, _k, width in columns) + "+" + C.RESET
    bar = " " + C.PURPLE + "|" + C.RESET + " "

    print(f"\n  {C.BOLD}{C.MAGENTA}{title} · {source}{C.RESET}")
    print(line)
    print("  " + C.PURPLE + "|" + C.RESET + " " + bar.join(
        f"{C.BOLD}{header:<{width}}{C.RESET}" for header, _key, width in columns
    ) + bar.rstrip())
    print(line)

    for record in records:
        cells = []
        for _header, key, width in columns:
            value = str(record.get(key, ""))
            if key == "status":
                color = getattr(C, _STATUS_COLORS.get(value, "DIM"))
            elif key == "ip":
                color = C.CYAN if value != "UNRESOLVED" else C.YELLOW
            elif key == "method":
                color = C.YELLOW
            elif key == "os_guess":
                color = ttl_color(value) if value not in {"-", "Unknown"} else C.DIM
            elif key in {"name", "vendor"}:
                color = C.TEAL
            elif key == "mac":
                color = C.DIM + C.WHITE
            elif key in {"rtt", "loss"}:
                color = C.DIM if value == "-" else C.WHITE
            else:
                color = C.WHITE
            cells.append(f"{color}{value[:width]:<{width}}{C.RESET}")
        print("  " + C.PURPLE + "|" + C.RESET + " " + bar.join(cells) + bar.rstrip())

    print(line)
    counts = _status_counts(records)
    summary = (
        f"  {C.GREEN}Reachable: {counts['reachable']}{C.RESET}  "
        f"{C.RED}No response: {counts['no_response']}{C.RESET}  "
        f"{C.YELLOW}Probe errors: {counts['probe_error']}{C.RESET}  "
        f"{C.YELLOW}Unresolved: {counts['unresolved']}{C.RESET}"
    )
    if counts["other"]:
        summary += f"  {C.DIM}Not scanned/excluded: {counts['other']}{C.RESET}"
    print(summary + "\n")
    return records


RESOLVE_WORKERS = 16


def _target_file_entries(path: str, text: str, column: Optional[str]) -> list[str]:
    """Turn a target file into entry lines: plain lists, CSV columns, or nmap XML."""
    stripped = text.lstrip()
    if Path(path).suffix.lower() == ".xml" or stripped.startswith(("<?xml", "<nmaprun")):
        try:
            pairs = read_nmap_xml_targets(text)
        except Exception as exc:
            print(C.err(f"  ✗ Cannot read nmap XML {path}: {exc}"), file=sys.stderr); sys.exit(EXIT_USAGE)
        return [address if name == address else f"{address} {name}" for name, address in pairs]
    if column:
        reader = csv.DictReader(text.splitlines())
        headers = {name.strip().lower(): name for name in (reader.fieldnames or [])}
        if column.lower() not in headers:
            available = ", ".join(reader.fieldnames or []) or "no header row"
            print(C.err(f"  ✗ Column '{column}' not found in {path} (columns: {available})"), file=sys.stderr)
            sys.exit(EXIT_USAGE)
        key = headers[column.lower()]
        return [str(row.get(key) or "").strip() for row in reader]
    return text.splitlines()


def read_target_file(
    path: str,
    hostnames_out: str = "hostnames.txt",
    quiet: bool = False,
    progress: bool = True,
    column: Optional[str] = None,
    only_tags: Optional[set[str]] = None,
) -> tuple[list[str], list[dict]]:
    """Read and resolve a target file. ``quiet`` hides warnings; ``progress`` hides status lines.

    Lines may carry ``@tags`` (``web01 @prod @web``); ``only_tags`` keeps lines
    with at least one of them. Hostnames are resolved in parallel.
    """
    p = Path(path)
    if not p.exists():
        print(C.err(f"  ✗ File not found: {path}")); sys.exit(1)
    if not p.is_file():
        print(C.err(f"  ✗ Target path is not a file: {path}")); sys.exit(1)

    try:
        text = p.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        print(C.err(f"  ✗ Cannot read target file {path}: {exc}")); sys.exit(1)
    lines = _target_file_entries(path, text, column)

    targets: list[str] = []
    mappings: list[dict] = []
    bad: list[str] = []
    if progress and not quiet:
        print(f"  {C.DIM}Resolving targets from {path} (deadline: 4s per hostname)...{C.RESET}", flush=True)
    unsafe: list[str] = []

    def _field_ip(value: str) -> Optional[str]:
        try:
            return _normalise_probe_address(value)
        except ValueError:
            return None

    # First pass: parse every line; names are collected for parallel resolution.
    parsed: list[tuple[str, object, list[str]]] = []
    for raw_line in lines:
        entry = raw_line.split("#", 1)[0].strip()
        tags = re.findall(r"(?<!\S)@([\w.\-]+)", entry)
        entry = re.sub(r"(?<!\S)@[\w.\-]+", "", entry).strip()
        if not entry:
            continue
        if only_tags and not (set(tag.lower() for tag in tags) & only_tags):
            continue

        # Portable explicit mappings avoid relying on OS-specific short-name
        # discovery. Accepted forms are "IP HOST [ALIAS ...]", "HOST,IP",
        # and "IP,HOST".
        fields = (
            [field.strip().strip('"').strip("'") for field in next(csv.reader([entry]))]
            if "," in entry else entry.split()
        )
        explicit_rows: list[tuple[str, str]] = []
        if len(fields) >= 2:
            first_ip = _field_ip(fields[0])
            second_ip = _field_ip(fields[1])
            if first_ip:
                explicit_rows = [
                    (alias, first_ip) for alias in fields[1:]
                    if alias and _field_ip(alias) is None
                ]
            elif second_ip and fields[0]:
                explicit_rows = [(fields[0], second_ip)]
        if explicit_rows:
            parsed.append(("map", explicit_rows, tags))
            continue

        # Accept simple CSV input by using the first column as the hostname/IP.
        if "," in entry:
            entry = entry.split(",", 1)[0].strip()
        entry = entry.strip('"').strip("'").strip()
        if not entry:
            continue
        address = _field_ip(entry)
        if address is not None:
            parsed.append(("ip", (entry, address), tags))
        else:
            if not is_safe_hostname(entry):
                unsafe.append(entry)
            parsed.append(("name", entry, tags))

    names = list(dict.fromkeys(str(item) for kind, item, _tags in parsed if kind == "name"))
    resolved_names: dict[str, list[str]] = {}
    if names:
        with ThreadPoolExecutor(max_workers=min(RESOLVE_WORKERS, len(names))) as pool:
            resolved_names = dict(zip(names, pool.map(resolve_hostname, names)))

    # Second pass: build rows in file order.
    for kind, item, tags in parsed:
        extra = {"tags": tags} if tags else {}
        if kind == "map":
            for hostname, address in item:  # type: ignore[union-attr]
                targets.append(address)
                mappings.append({"host": hostname, "ip": address, "type": "FILE MAP", **extra})
        elif kind == "ip":
            entry, address = item  # type: ignore[misc]
            targets.append(address)
            mappings.append({"host": entry, "ip": address, "type": "DIRECT IP", **extra})
        else:
            entry = str(item)
            resolved = resolved_names.get(entry, [])
            if resolved:
                for address in resolved:
                    targets.append(address)
                    mappings.append({"host": entry, "ip": address, "type": "DNS", **extra})
            else:
                bad.append(entry)
                mappings.append({"host": entry, "ip": "UNRESOLVED", "type": "UNRESOLVED", **extra})

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

    if bad and not quiet:
        print(f"  {C.YELLOW}⚠  Unresolvable entries in {path}: {len(bad)}{C.RESET}")
        for entry in bad:
            note = "  (rejected: not a valid hostname)" if entry in unsafe else ""
            print(f"     {C.RED}✗ {entry}{C.RESET}{C.DIM}{note}{C.RESET}")

    if not targets:
        # Still show the final file-oriented table so the user can see exactly
        # which hostname failed instead of receiving only a generic error.
        if quiet or not progress:
            unresolved_records = build_file_status_records(mappings, [])
        else:
            unresolved_records = show_file_scan_status(mappings, [], path)
        write_hostnames_report(unresolved_records, path, hostnames_out, announce=not quiet)
        print(C.err(f"  ✗ No valid IPs or resolvable hostnames found in {path}"), file=sys.stderr)
        sys.exit(1)

    if progress and not quiet:
        print(f"  {C.CYAN}Loaded {C.BOLD}{len(targets)}{C.RESET}{C.CYAN} resolved targets from {path}{C.RESET}")
    return targets, mappings


def resolve_host_arguments(hostnames: list[str], quiet: bool = False) -> tuple[list[str], list[dict]]:
    """Resolve command-line hosts into (addresses, host/IP rows); fail clearly if none resolve."""
    targets: list[str] = []
    rows: list[dict] = []
    bad: list[str] = []
    for hostname in hostnames:
        address = _normalise_probe_address(hostname)
        if address is not None:
            targets.append(address)
            rows.append({"host": hostname, "ip": address, "type": "DIRECT IP"})
            continue
        resolved = resolve_hostname(hostname)
        if resolved:
            targets.extend(resolved)
            rows.extend({"host": hostname, "ip": ip, "type": "DNS"} for ip in resolved)
        else:
            bad.append(hostname)
            rows.append({"host": hostname, "ip": "UNRESOLVED", "type": "UNRESOLVED"})
    if bad and not quiet:
        print(C.warn(f"  ⚠  Could not resolve: {', '.join(bad)}"))
    targets = list(dict.fromkeys(targets))
    if not targets:
        print(C.err("  ✗ No valid IPs or resolvable hostnames supplied."), file=sys.stderr); sys.exit(1)
    return targets, rows


# ─────────────────────────────────────────────────────────────────
# CHECK DEPENDENCIES + TOOL SELECTION  (FIX 5)
# ─────────────────────────────────────────────────────────────────
def _native_auto_platform() -> bool:
    """Platforms where auto mode picks the native engine (verified in CI)."""
    return sys.platform.startswith("linux")


def check_deps(
    ping_tool: str = "auto", verbose: bool = False, interactive: bool = False
) -> str:
    """
    Detect available ICMP engines, honour --ping-tool, and optionally ask an
    interactive user to choose. Returns "native" | "fping" | "ping".

    auto prefers the native engine (one ICMP socket, no process per host) on
    platforms where it is verified, then fping, then the system ping.
    """
    global _PING_TOOL, _FPING_PATH, _PING_PATH, _PING6_PATH

    has_fping = _FPING_PATH is not None
    has_ping  = _PING_PATH is not None or _PING6_PATH is not None
    has_native = native_engine_available()

    if verbose:
        print(f"\n  {C.CYAN}[tools]{C.RESET}")
        print(f"  native: {'available (ICMP socket)' if has_native else 'unavailable'}")
        print(f"  fping:  {_FPING_PATH or 'not found'}")
        print(f"  ping:   {_PING_PATH or _PING6_PATH or 'not found'}")

    if not has_fping and not has_ping and not has_native:
        print(f"\n  {C.RED}✗ No ping tool found on PATH.{C.RESET}")
        print(f"  {C.YELLOW}Install one of:{C.RESET}")
        print(f"  {C.DIM}  sudo apt install fping   # Debian/Ubuntu/Kali")
        print("       sudo dnf install fping   # RHEL/Fedora")
        print(f"       brew install fping       # macOS{C.RESET}")
        sys.exit(3)

    requirements = {"native": has_native, "fping": has_fping, "ping": has_ping}
    if ping_tool in requirements:
        if not requirements[ping_tool]:
            reason = "ICMP sockets are not permitted for this user" if ping_tool == "native" else f"{ping_tool} not found"
            print(f"  {C.RED}✗ --ping-tool={ping_tool} requested but {reason}.{C.RESET}")
            sys.exit(3)
        _PING_TOOL = ping_tool
    else:
        choices = [name for name in ("native", "fping", "ping") if requirements[name]]
        if interactive and len(choices) > 1 and sys.stdin.isatty():
            descriptions = {
                "native": "built-in ICMP socket, fastest",
                "fping": "batch discovery + strict ping confirmation",
                "ping": "system ping only",
            }
            print(f"\n  {C.BOLD}{C.CYAN}Select ping backend:{C.RESET}")
            for index, name in enumerate(choices, 1):
                print(f"  {C.GREEN}[{index}]{C.RESET} {name:<6} {C.DIM}({descriptions[name]}){C.RESET}")
            try:
                choice = input(f"  {C.BOLD}Choice [1-{len(choices)}, default=1]:{C.RESET} ").strip()
            except (EOFError, KeyboardInterrupt):
                choice = ""
            index = int(choice) - 1 if choice.isdigit() and 1 <= int(choice) <= len(choices) else 0
            _PING_TOOL = choices[index]
        elif has_native and _native_auto_platform():
            _PING_TOOL = "native"
        elif has_fping:
            _PING_TOOL = "fping"
        elif has_ping:
            _PING_TOOL = "ping"
        else:
            _PING_TOOL = "native"

    if verbose:
        colour = {"native": C.LIME, "fping": C.GREEN, "ping": C.YELLOW}[_PING_TOOL]
        print(f"  {C.DIM}Backend:{C.RESET}  {colour}{_PING_TOOL}{C.RESET}")

    return _PING_TOOL


# ─────────────────────────────────────────────────────────────────
# SHOW HISTORY LIST
# ─────────────────────────────────────────────────────────────────
def show_history_list():
    d = _data_dir()
    files = sorted(f for f in d.glob("*.json") if not f.name.startswith(".")) if d.is_dir() else []
    legacy = _legacy_data_dir()
    legacy_files = (
        sorted(f for f in legacy.glob("*.json") if not f.name.startswith("."))
        if legacy.is_dir() and legacy.resolve() != d.resolve() else []
    )
    if not files and not legacy_files:
        print(f"  {C.YELLOW}No scan history found in {d}.{C.RESET}\n"); return
    box_w = 70
    div   = f"  {C.CYAN}{'─' * box_w}{C.RESET}"
    print(f"\n  {C.BOLD}{C.CYAN}Stored Scan History:{C.RESET}  {C.DIM}{d}{C.RESET}"); print(div)
    for f in files + legacy_files:
        try:
            data  = json.loads(f.read_text(encoding="utf-8"))
            n     = len(data); last = data[-1] if data else {}
            ts    = last.get("timestamp", "?")[:16]
            alive = len(last.get("alive", []))
            where = f"  {C.YELLOW}(legacy ./data){C.RESET}" if f in legacy_files else ""
            print(f"  {C.LIME}{f.stem:<30}{C.RESET}  {C.DIM}{n} scans  last: {ts}  alive: {alive}{C.RESET}{where}")
        except Exception:
            print(f"  {C.RED}{f.stem}  (corrupt){C.RESET}")
    print(div)
    print(f"  {C.DIM}Clear one with: pingme --clear-history <label>{C.RESET}\n")


# ─────────────────────────────────────────────────────────────────
# CLEAR HISTORY
# ─────────────────────────────────────────────────────────────────
def clear_history(label: str):
    """Delete history, resume, and --changes state for a label (new and legacy locations)."""
    removed = [kind for kind in ("history", "resume", "changes") if _remove_state(kind, label)]
    if not removed:
        print(C.warn(f"  ⚠  No history found for label: {label}")); return
    print(C.ok(f"  ✔  Cleared {', '.join(removed)} data for: {label}"))


# ─────────────────────────────────────────────────────────────────
# TCP PORT PRESETS
# ─────────────────────────────────────────────────────────────────
TCP_PORT_PRESETS: dict[str, str] = {
    "web": "80,443,8080,8443",
    "windows": "135,139,445,3389,5985",
    "linux": "22,111,2049",
    "mail": "25,110,143,465,587,993,995",
    "db": "1433,1521,3306,5432,6379,27017",
    "printers": "515,631,9100",
    "network": "22,23,53,80,443,8291",
    "common": "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443",
}


def expand_port_presets(value: str) -> str:
    """Replace preset names such as 'web' or 'windows' with their port lists."""
    items = []
    for item in value.split(","):
        name = item.strip().lower()
        if name and not name[0].isdigit():
            if name not in TCP_PORT_PRESETS:
                raise ValueError(f"unknown port preset '{item.strip()}' (presets: {', '.join(TCP_PORT_PRESETS)})")
            items.append(TCP_PORT_PRESETS[name])
        else:
            items.append(item)
    return ",".join(items)


# ─────────────────────────────────────────────────────────────────
# NOTIFICATIONS
# ─────────────────────────────────────────────────────────────────
def build_notification(title: str, events: dict[str, list[dict]]) -> str:
    """Plain-text summary of status changes for chat and e-mail notifications."""
    labels = {
        "went_offline": "🔴 Went offline", "newly_online": "🟢 Came online",
        "down": "🔴 Not responding", "ip_changed": "🔁 IP changed",
        "mac_changed": "⚠️ MAC changed", "unresolved": "❓ Unresolved",
    }
    lines = [title]
    for key, label in labels.items():
        items = events.get(key) or []
        if not items:
            continue
        lines.append(f"{label} ({len(items)}):")
        for item in items[:25]:
            host = item.get("host") or item.get("hostname") or ""
            ip = item.get("ip", "")
            extra = f" ({item['old_ip']} → {ip})" if key == "ip_changed" else ""
            lines.append(f"  • {host + ' ' if host and host != ip else ''}{ip}{extra}")
        if len(items) > 25:
            lines.append(f"  … and {len(items) - 25} more")
    return "\n".join(lines)


def _post_json(url: str, payload: dict, timeout: float = 10) -> None:
    import urllib.request
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": f"PingMe/{VERSION}"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        response.read()


def _send_email(recipients: str, subject: str, body: str) -> None:
    import smtplib
    from email.message import EmailMessage
    host = os.environ.get("PINGME_SMTP_HOST", "localhost")
    port = int(os.environ.get("PINGME_SMTP_PORT", "587" if os.environ.get("PINGME_SMTP_USER") else "25"))
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = os.environ.get("PINGME_SMTP_FROM", f"pingme@{socket.gethostname()}")
    message["To"] = recipients
    message.set_content(body)
    with smtplib.SMTP(host, port, timeout=15) as smtp:
        if os.environ.get("PINGME_SMTP_STARTTLS", "1" if port == 587 else "0") == "1":
            smtp.starttls()
        if os.environ.get("PINGME_SMTP_USER"):
            smtp.login(os.environ["PINGME_SMTP_USER"], os.environ.get("PINGME_SMTP_PASSWORD", ""))
        smtp.send_message(message)


def send_notification(target: str, title: str, text: str, events: dict[str, list[dict]]) -> None:
    """Deliver one notification. The URL decides the format:

    Slack/Teams webhooks get {"text"}, Discord {"content"}, telegram://TOKEN@CHAT
    uses the Bot API, mailto:a@b,c@d sends e-mail (PINGME_SMTP_* settings), and
    any other http(s) URL receives the full JSON event payload.
    """
    lowered = target.lower()
    if lowered.startswith("mailto:"):
        _send_email(target[len("mailto:"):], title, text)
    elif lowered.startswith("telegram://"):
        token, _at, chat = target[len("telegram://"):].partition("@")
        if not token or not chat:
            raise ValueError("use telegram://BOT_TOKEN@CHAT_ID")
        _post_json(f"https://api.telegram.org/bot{token}/sendMessage", {"chat_id": chat, "text": text})
    elif "hooks.slack.com" in lowered or "webhook.office.com" in lowered or "logic.azure.com" in lowered:
        _post_json(target, {"text": text})
    elif "discord.com/api/webhooks" in lowered or "discordapp.com/api/webhooks" in lowered:
        _post_json(target, {"content": text[:1900]})
    elif lowered.startswith(("http://", "https://")):
        _post_json(target, {
            "source": "pingme", "version": VERSION, "title": title, "text": text,
            "time": datetime.now().isoformat(timespec="seconds"),
            "events": {key: [{k: v for k, v in item.items() if not isinstance(v, (list, dict))} for item in items]
                       for key, items in events.items() if items},
        })
    else:
        raise ValueError(f"unsupported notification target: {target}")


def notify_all(targets: list[str], title: str, events: dict[str, list[dict]], quiet: bool = False) -> int:
    """Send to every target; failures are reported but never abort the scan. Returns failures."""
    if not targets or not any(events.values()):
        return 0
    text = build_notification(title, events)
    failures = 0
    for target in targets:
        shown = re.sub(r"(telegram://)[^@]+", r"\1***", target)
        shown = re.sub(r"(/webhooks?/|/services/).*", r"\1***", shown)
        try:
            send_notification(target, title, text, events)
            if not quiet:
                print(f"  {C.DIM}[notify] sent → {shown}{C.RESET}")
        except Exception as exc:
            failures += 1
            print(C.warn(f"  ⚠  Notification to {shown} failed: {exc}"), file=sys.stderr)
    return failures


# ─────────────────────────────────────────────────────────────────
# UPTIME FROM HISTORY
# ─────────────────────────────────────────────────────────────────
def compute_uptime(history: list[dict]) -> list[dict]:
    """Per-address availability across stored scans (probe errors are not counted as down)."""
    stats: dict[str, dict] = {}
    for scan in history:
        timestamp = str(scan.get("timestamp", ""))[:19]
        names = {r.get("ip"): r.get("hostname") or "" for r in scan.get("results", []) if isinstance(r, dict)}
        for status, addresses in (("up", scan.get("alive", [])), ("down", scan.get("dead", [])),
                                  ("error", scan.get("errors", []))):
            for ip in addresses:
                entry = stats.setdefault(ip, {"ip": ip, "name": "", "up": 0, "down": 0, "error": 0,
                                              "last_up": "", "last_status": "", "streak": 0, "changes": 0})
                entry[status] += 1
                entry["name"] = names.get(ip) or entry["name"]
                if status == "up":
                    entry["last_up"] = timestamp
                if status != "error":
                    if entry["last_status"] and entry["last_status"] != status:
                        entry["changes"] += 1
                        entry["streak"] = 0
                    entry["streak"] += 1
                    entry["last_status"] = status
    rows = []
    for entry in stats.values():
        tested = entry["up"] + entry["down"]
        entry["availability"] = round(entry["up"] / tested * 100, 1) if tested else None
        rows.append(entry)
    return sorted(rows, key=lambda row: (row["availability"] if row["availability"] is not None else 101, ip_sort_key(row["ip"])))


def show_uptime(label: str) -> int:
    history = load_history(label)
    if not history:
        print(C.warn(f"  ⚠  No history for '{label}'. Run a scan first (without --no-history)."))
        return EXIT_NOT_ALL_UP
    rows = compute_uptime(history)
    first, last = str(history[0].get("timestamp", ""))[:16], str(history[-1].get("timestamp", ""))[:16]
    print(f"\n  {C.BOLD}{C.MAGENTA}UPTIME · {label}{C.RESET}  {C.DIM}{len(history)} scans, {first} → {last}{C.RESET}")
    ip_w = max([15] + [len(r["ip"]) for r in rows])
    name_w = min(32, max([8] + [len(r["name"]) for r in rows]))
    header = f"  {'IP ADDRESS':<{ip_w}}  {'NAME':<{name_w}}  {'UPTIME':>7}  {'UP':>4}  {'DOWN':>4}  {'FLAPS':>5}  {'NOW':<10}  LAST SEEN UP"
    print(f"{C.BOLD}{header}{C.RESET}")
    for row in rows:
        availability = row["availability"]
        colour = C.GREEN if availability is not None and availability >= 99 else (
            C.YELLOW if availability is not None and availability >= 90 else C.RED)
        shown = "n/a" if availability is None else f"{availability:.1f}%"
        now = f"{row['last_status'] or 'error'} ×{row['streak']}" if row["last_status"] else "error"
        print(f"  {row['ip']:<{ip_w}}  {row['name'][:name_w]:<{name_w}}  {colour}{shown:>7}{C.RESET}  "
              f"{row['up']:>4}  {row['down']:>4}  {row['changes']:>5}  {now:<10}  {row['last_up'] or '-'}")
    print()
    return EXIT_OK


# ─────────────────────────────────────────────────────────────────
# TRACEROUTE FOR DOWN HOSTS
# ─────────────────────────────────────────────────────────────────
TRACE_MAX_HOPS = 15
TRACE_LIMIT = 10


def _trace_command(ip: str) -> Optional[list[str]]:
    base = ip.split("%", 1)[0]
    ipv6 = ipaddress.ip_address(base).version == 6
    if sys.platform == "win32":
        tracert = shutil.which("tracert.exe") or shutil.which("tracert")
        return [tracert, "-d", "-h", str(TRACE_MAX_HOPS), "-w", "1000", *(["-6"] if ipv6 else []), ip] if tracert else None
    traceroute = shutil.which("traceroute6" if ipv6 and _is_bsd_ping() else "traceroute")
    if traceroute:
        family = ["-6"] if ipv6 and not traceroute.endswith("6") else []
        return [traceroute, *family, "-n", "-q", "1", "-w", "1", "-m", str(TRACE_MAX_HOPS), ip]
    tracepath = shutil.which("tracepath")
    if tracepath:
        return [tracepath, *(["-6"] if ipv6 else []), "-n", "-m", str(TRACE_MAX_HOPS), ip]
    return None


def parse_trace_output(ip: str, output: str) -> dict:
    """Summarise traceroute/tracert/tracepath output: last answering hop and whether the target replied."""
    hops: list[tuple[int, str]] = []
    for line in output.splitlines():
        match = re.match(r"^\s*(\d+)[:?]?\s+(.*)$", line)
        if not match:
            continue
        number = int(match.group(1))
        addresses = [a for a in _extract_ip_addresses(match.group(2)) if a != "0.0.0.0"]
        if addresses:
            hops.append((number, addresses[0]))
    reached = any(_same_ip(address, ip) for _number, address in hops)
    if not hops:
        verdict = "no hop answered (local firewall, no route, or traceroute blocked)"
        return {"last_hop": "", "hop": 0, "reached": False, "verdict": verdict}
    number, address = hops[-1]
    if reached:
        verdict = "path is fine; the host itself ignores ping (try --tcp-ports)"
    else:
        verdict = f"path stops after {address} (hop {number})"
    return {"last_hop": address, "hop": number, "reached": reached, "verdict": verdict}


def trace_down_hosts(results: list[dict], quiet: bool = False) -> list[dict]:
    """Run a traceroute to up to TRACE_LIMIT down hosts to show where the path breaks."""
    down = [r for r in results if r.get("status") == "NO RESPONSE"][:TRACE_LIMIT]
    if not down:
        return []
    if _trace_command(down[0]["ip"]) is None:
        print(C.warn("  ⚠  --trace-down needs traceroute, tracepath, or tracert."), file=sys.stderr)
        return []
    if not quiet:
        print(f"  {C.DIM}Tracing the path to {len(down)} down host(s)...{C.RESET}", flush=True)

    def _trace(result: dict) -> dict:
        command = _trace_command(result["ip"])
        output = _run_resolution_command(command, timeout=TRACE_MAX_HOPS * 3 + 5, accepted_returncodes=(0, 1, 2)) if command else ""
        return {"ip": result["ip"], **parse_trace_output(result["ip"], output)}

    with ThreadPoolExecutor(max_workers=5) as pool:
        traces = list(pool.map(_trace, down))
    # An on-link host that never answered ARP/ND needs no router to explain it.
    unanswered = {
        _normalise_probe_address(address) if family == 4 else _with_zone(address, zone)
        for family in (4, 6) for address, zone, _mac, state in read_neighbor_entries(family)
        if state in {"FAILED", "INCOMPLETE"}
    }
    for trace in traces:
        if trace["ip"] in unanswered and not trace["reached"]:
            trace["verdict"] = "on your local network but silent at layer 2: powered off, unplugged, or moved to another IP"
    for trace in traces:
        for result in results:
            if result["ip"] == trace["ip"]:
                result["trace"] = trace["verdict"]
    if not quiet:
        ip_w = max([15] + [len(t["ip"]) for t in traces])
        print(f"\n  {C.BOLD}{C.MAGENTA}PATH TO DOWN HOSTS{C.RESET}")
        for trace in traces:
            colour = C.YELLOW if trace["reached"] else C.RED
            print(f"  {C.WHITE}{trace['ip']:<{ip_w}}{C.RESET}  {colour}{trace['verdict']}{C.RESET}")
        print()
    return traces


# ─────────────────────────────────────────────────────────────────
# WAKE-ON-LAN
# ─────────────────────────────────────────────────────────────────
def magic_packet(mac: str) -> bytes:
    digits = re.sub(r"[^0-9A-Fa-f]", "", _normalise_mac(mac))
    if len(digits) != 12:
        raise ValueError(f"invalid MAC address: {mac}")
    return b"\xff" * 6 + bytes.fromhex(digits) * 16


def send_wake_on_lan(macs: list[str], broadcast: str = "255.255.255.255") -> list[str]:
    """Send magic packets to UDP ports 9 and 7; returns the MACs that were sent."""
    sent = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for mac in macs:
            packet = magic_packet(mac)
            for port in (9, 7):
                sock.sendto(packet, (broadcast, port))
            sent.append(_normalise_mac(mac))
    return sent


def known_macs(label: str, addresses: set[str]) -> dict[str, str]:
    """MAC addresses remembered for these IPs in history, newest first, plus the live neighbor table."""
    found: dict[str, str] = {}
    for scan in reversed(load_history(label)):
        for result in scan.get("results", []):
            if isinstance(result, dict) and result.get("ip") in addresses and result.get("mac"):
                found.setdefault(result["ip"], result["mac"])
    for family in (4, 6):
        for address, _zone, mac, _state in read_neighbor_entries(family):
            normalized = _normalise_probe_address(address)
            if normalized in addresses and mac:
                found.setdefault(normalized, _normalise_mac(mac))
    return found


# ─────────────────────────────────────────────────────────────────
# NMAP XML EXPORT / IMPORT
# ─────────────────────────────────────────────────────────────────
def write_nmap_xml(results: list[dict], path: str, command: str, started: float) -> Path:
    """Write results as nmap-compatible XML (-oX), readable by tools that import nmap scans."""
    from xml.sax.saxutils import quoteattr
    destination = Path(path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    finished = time.time()
    up = sum(1 for r in results if r["alive"])
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<nmaprun scanner="pingme" args={quoteattr(command)} start="{int(started)}" version="{VERSION}" xmloutputversion="1.05">',
    ]
    for result in results:
        base = result["ip"].split("%", 1)[0]
        family = "ipv6" if ipaddress.ip_address(base).version == 6 else "ipv4"
        state = "up" if result["alive"] else "down"
        reason = "echo-reply" if result.get("icmp_alive") else ("syn-ack" if result.get("tcp_open") else (
            "arp-response" if result.get("arp") else "no-response"))
        lines.append(f'<host><status state="{state}" reason="{reason}"/>')
        lines.append(f'<address addr={quoteattr(base)} addrtype="{family}"/>')
        if result.get("mac"):
            vendor = f" vendor={quoteattr(result['vendor'])}" if result.get("vendor") else ""
            lines.append(f'<address addr={quoteattr(result["mac"].upper())} addrtype="mac"{vendor}/>')
        if result.get("hostname"):
            lines.append(f'<hostnames><hostname name={quoteattr(result["hostname"])} type="PTR"/></hostnames>')
        if result.get("tcp_open"):
            lines.append("<ports>" + "".join(
                f'<port protocol="tcp" portid="{port}"><state state="open" reason="syn-ack"/></port>'
                for port in result["tcp_open"]) + "</ports>")
        if result.get("rtt_avg") is not None:
            lines.append(f'<times srtt="{int(result["rtt_avg"] * 1000)}" rttvar="0" to="0"/>')
        lines.append("</host>")
    lines.append(f'<runstats><finished time="{int(finished)}" elapsed="{finished - started:.2f}"/>'
                 f'<hosts up="{up}" down="{len(results) - up}" total="{len(results)}"/></runstats>')
    lines.append("</nmaprun>")
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return destination


def read_nmap_xml_targets(text: str) -> list[tuple[str, str]]:
    """(hostname, address) pairs from an nmap -oX file; hosts nmap saw as down are kept too."""
    import xml.etree.ElementTree as ElementTree
    # nmap writes a bare <!DOCTYPE nmaprun>. Entity declarations or an internal DTD
    # subset could expand maliciously, so those are refused.
    if "<!ENTITY" in text or re.search(r"<!DOCTYPE[^>]*\[", text):
        raise ValueError("XML with entity declarations or an internal DTD is not accepted")
    text = re.sub(r"<!DOCTYPE[^>]*>", "", text, count=1)
    root = ElementTree.fromstring(text)
    pairs: list[tuple[str, str]] = []
    for host in root.iter("host"):
        address = next((a.get("addr", "") for a in host.iter("address") if a.get("addrtype") in {"ipv4", "ipv6"}), "")
        name = next((h.get("name", "") for h in host.iter("hostname")), "")
        if address:
            pairs.append((name or address, address))
    return pairs


# ─────────────────────────────────────────────────────────────────
# HTML REPORT
# ─────────────────────────────────────────────────────────────────
_HTML_STYLE = """
:root{--bg:#f7f8fa;--card:#fff;--text:#1d2330;--muted:#687083;--line:#e3e6ec;--up:#1f9d55;--down:#d64545;
--warn:#c98a00;--other:#8a93a6;--accent:#5b5bd6}
@media (prefers-color-scheme:dark){:root{--bg:#12151c;--card:#1a1f29;--text:#e6e9ef;--muted:#9aa3b5;--line:#2a3140;
--up:#3ccf7e;--down:#ff6b6b;--warn:#f0b429;--other:#8a93a6;--accent:#8b8bff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px 48px}h1{margin:0 0 4px;font-size:22px}h2{font-size:16px;margin:32px 0 12px}
.meta{color:var(--muted);font-size:13px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}.card b{display:block;font-size:26px;font-variant-numeric:tabular-nums}
.card span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.bar{display:flex;height:10px;border-radius:5px;overflow:hidden;background:var(--line);margin:4px 0 20px}
.bar i{display:block;height:100%}.controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
.controls input{flex:1;min-width:180px;padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--text)}
.chip{border:1px solid var(--line);background:var(--card);color:var(--text);border-radius:999px;padding:6px 12px;cursor:pointer;font:inherit}
.chip[aria-pressed=true]{background:var(--accent);border-color:var(--accent);color:#fff}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--card)}
table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}th,td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}
th{position:sticky;top:0;background:var(--card);cursor:pointer;user-select:none;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
tr:last-child td{border-bottom:0}.s{font-weight:600}.REACHABLE{color:var(--up)}.NO.RESPONSE,.NO_RESPONSE{color:var(--down)}
.PROBE_ERROR,.UNRESOLVED{color:var(--warn)}.EXCLUDED,.NOT_SCANNED{color:var(--other)}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
footer{margin-top:32px;color:var(--muted);font-size:12px}
"""

_HTML_SCRIPT = """
const rows=[...document.querySelectorAll('#t tbody tr')];let filter='all';
function apply(){const q=document.getElementById('q').value.toLowerCase();
rows.forEach(r=>{const okS=filter==='all'||r.dataset.status===filter;const okQ=!q||r.textContent.toLowerCase().includes(q);r.hidden=!(okS&&okQ);});}
document.getElementById('q').addEventListener('input',apply);
document.querySelectorAll('.chip').forEach(c=>c.addEventListener('click',()=>{filter=c.dataset.f;
document.querySelectorAll('.chip').forEach(x=>x.setAttribute('aria-pressed',x===c));apply();}));
document.querySelectorAll('#t th').forEach((th,i)=>th.addEventListener('click',()=>{const asc=th.dataset.asc!=='1';th.dataset.asc=asc?'1':'0';
const key=r=>{const v=r.children[i].dataset.v??r.children[i].textContent;const n=parseFloat(v);return isNaN(n)?v:n;};
rows.sort((a,b)=>{const x=key(a),y=key(b);return (x>y?1:x<y?-1:0)*(asc?1:-1);});const tb=document.querySelector('#t tbody');rows.forEach(r=>tb.appendChild(r));}));
"""


def render_html_report(title: str, records: list[dict], uptime: Optional[list[dict]] = None, meta: str = "") -> str:
    """A self-contained HTML report (no external files) with filters and sortable columns."""
    from html import escape
    counts = _status_counts(records)
    total = len(records) or 1
    columns = [c for c in _STATUS_COLUMNS
               if c[1] not in {"mac", "vendor", "name", "tags"} or any(r.get(c[1]) for r in records)]
    uptime_by_ip = {row["ip"]: row for row in (uptime or [])}
    if uptime_by_ip:
        columns.append(("UPTIME", "uptime", 0, 0))

    def cell(record: dict, key: str) -> str:
        if key == "uptime":
            row = uptime_by_ip.get(record.get("ip", ""))
            value = "" if not row or row["availability"] is None else f"{row['availability']:.1f}%"
            return f'<td data-v="{escape(value.rstrip("%") or "-1")}">{escape(value)}</td>'
        value = record.get(key, "")
        value = " ".join(value) if isinstance(value, list) else str(value)
        css = f' class="s {escape(value.replace(" ", "_"))}"' if key == "status" else (
            ' class="mono"' if key in {"ip", "mac"} else "")
        sort_value = ""
        if key == "ip":
            base = value.split("%", 1)[0]
            try:
                sort_value = f' data-v="{ipaddress.ip_address(base).version}{int(ipaddress.ip_address(base)):040d}"'
            except ValueError:
                sort_value = ""
        return f"<td{css}{sort_value}>{escape(value)}</td>"

    head = "".join(f"<th>{escape(header)}</th>" for header, _key, *_ in columns)
    body = "\n".join(
        f'<tr data-status="{escape(r.get("status", ""))}">' + "".join(cell(r, key) for _h, key, *_ in columns) + "</tr>"
        for r in records
    )
    segments = [("REACHABLE", counts["reachable"], "var(--up)"), ("NO RESPONSE", counts["no_response"], "var(--down)"),
                ("PROBE ERROR", counts["probe_error"], "var(--warn)"), ("UNRESOLVED", counts["unresolved"], "var(--warn)"),
                ("OTHER", counts["other"], "var(--other)")]
    bar = "".join(f'<i style="width:{n / total * 100:.2f}%;background:{colour}" title="{label}: {n}"></i>'
                  for label, n, colour in segments if n)
    cards = "".join(f'<div class="card"><b>{n}</b><span>{label}</span></div>'
                    for label, n in (("Targets", len(records)), ("Reachable", counts["reachable"]),
                                     ("No response", counts["no_response"]), ("Probe errors", counts["probe_error"]),
                                     ("Unresolved", counts["unresolved"])))
    chips = "".join(f'<button class="chip" data-f="{value}" aria-pressed="{str(value == "all").lower()}">{label}</button>'
                    for value, label in (("all", "All"), ("REACHABLE", "Reachable"), ("NO RESPONSE", "No response"),
                                         ("PROBE ERROR", "Errors"), ("UNRESOLVED", "Unresolved")))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)}</title><style>{_HTML_STYLE}</style></head>
<body><main>
<h1>{escape(title)}</h1><div class="meta">{escape(meta)}</div>
<div class="cards">{cards}</div><div class="bar">{bar}</div>
<h2>Targets</h2>
<div class="controls"><input id="q" type="search" placeholder="Filter by name, IP, MAC, vendor…" aria-label="Filter">{chips}</div>
<div class="wrap"><table id="t"><thead><tr>{head}</tr></thead><tbody>
{body}
</tbody></table></div>
<footer>Generated by PingMe {VERSION} · {escape(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))} · click a column to sort</footer>
</main><script>{_HTML_SCRIPT}</script></body></html>
"""


def write_html_report(path: str, title: str, records: list[dict], uptime: Optional[list[dict]], meta: str) -> Path:
    destination = Path(path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_html_report(title, records, uptime, meta), encoding="utf-8")
    return destination


def records_for_results(results: list[dict], rows: list[dict]) -> list[dict]:
    """Status records for every scanned target: the given host/file rows plus bare IP rows for the rest."""
    covered = {str(row.get("ip")) for row in rows}
    extra = [{"host": r.get("hostname") or r["ip"], "ip": r["ip"], "type": "DIRECT IP"}
             for r in results if r["ip"] not in covered]
    return build_file_status_records(rows + extra, results)


# ─────────────────────────────────────────────────────────────────
# SERVE: PROMETHEUS METRICS AND JSON API
# ─────────────────────────────────────────────────────────────────
def _prom_label(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def render_metrics(results: list[dict], names: dict[str, str], duration: float, finished_at: float) -> str:
    """Prometheus text exposition for the latest scan."""
    lines = [
        "# HELP pingme_up 1 if the target answered (ICMP, TCP, or ARP/ND), else 0.",
        "# TYPE pingme_up gauge",
    ]
    for r in results:
        labels = f'ip="{_prom_label(r["ip"])}",host="{_prom_label(names.get(r["ip"]) or r.get("hostname") or "")}"'
        lines.append(f"pingme_up{{{labels}}} {1 if r['alive'] else 0}")
    lines += ["# HELP pingme_rtt_milliseconds Average echo round-trip time.", "# TYPE pingme_rtt_milliseconds gauge"]
    lines += [f'pingme_rtt_milliseconds{{ip="{_prom_label(r["ip"])}"}} {r["rtt_avg"]}' for r in results if r.get("rtt_avg") is not None]
    lines += ["# HELP pingme_packet_loss_ratio Share of echo requests without a reply.", "# TYPE pingme_packet_loss_ratio gauge"]
    lines += [f'pingme_packet_loss_ratio{{ip="{_prom_label(r["ip"])}"}} {r["loss_pct"] / 100:.4f}'
              for r in results if r.get("loss_pct") is not None]
    lines += ["# HELP pingme_probe_error 1 if the probe itself failed.", "# TYPE pingme_probe_error gauge"]
    lines += [f'pingme_probe_error{{ip="{_prom_label(r["ip"])}"}} 1' for r in results if r.get("status") == "PROBE ERROR"]
    lines += [
        "# HELP pingme_targets Targets by status in the latest scan.", "# TYPE pingme_targets gauge",
        *(f'pingme_targets{{status="{status}"}} {sum(1 for r in results if r.get("status") == status)}'
          for status in ("REACHABLE", "NO RESPONSE", "PROBE ERROR")),
        "# HELP pingme_scan_duration_seconds Duration of the latest scan.", "# TYPE pingme_scan_duration_seconds gauge",
        f"pingme_scan_duration_seconds {duration:.3f}",
        "# HELP pingme_last_scan_timestamp_seconds Unix time the latest scan finished.",
        "# TYPE pingme_last_scan_timestamp_seconds gauge",
        f"pingme_last_scan_timestamp_seconds {finished_at:.0f}",
    ]
    return "\n".join(lines) + "\n"


def serve_scans(bind: str, interval: float, run_once: Callable[[], list[dict]], names: dict[str, str],
                rows: list[dict], title: str) -> int:
    """Rescan every ``interval`` seconds and serve /metrics, /api/results, and an HTML page."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    host, _sep, port_text = bind.rpartition(":")
    host = (host or "127.0.0.1").strip("[]")
    try:
        port = int(port_text)
    except ValueError:
        print(C.err(f"  ✗ --serve expects [HOST:]PORT, got '{bind}'"), file=sys.stderr)
        return EXIT_USAGE
    state = {"results": [], "duration": 0.0, "finished": 0.0}
    state_lock = threading.Lock()
    stop = threading.Event()

    def _loop() -> None:
        while not stop.is_set():
            started = time.time()
            try:
                results = run_once()
            except Exception as exc:  # keep serving the last good scan
                print(C.warn(f"  ⚠  Scan failed: {exc}"), file=sys.stderr)
                results = None
            if results is not None:
                with state_lock:
                    state.update(results=results, duration=time.time() - started, finished=time.time())
            stop.wait(interval)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:
            pass

        def _send(self, body: str, content_type: str, status: int = 200) -> None:
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            with state_lock:
                results, duration, finished = list(state["results"]), state["duration"], state["finished"]
            path = self.path.split("?", 1)[0]
            if path == "/metrics":
                self._send(render_metrics(results, names, duration, finished), "text/plain; version=0.0.4; charset=utf-8")
            elif path == "/api/results":
                self._send(json.dumps({"finished": finished, "duration": duration, "results": results}, indent=1),
                           "application/json")
            elif path in {"/", "/index.html"}:
                records = records_for_results(results, rows)
                meta = (f"Last scan {datetime.fromtimestamp(finished).strftime('%H:%M:%S')} · refreshes every "
                        f"{_format_seconds(interval)} s") if finished else "First scan in progress…"
                page = render_html_report(title, records, None, meta).replace(
                    "<head>", f'<head><meta http-equiv="refresh" content="{max(5, int(interval))}">', 1)
                self._send(page, "text/html; charset=utf-8")
            elif path == "/healthz":
                self._send("ok\n" if finished else "starting\n", "text/plain", 200 if finished else 503)
            else:
                self._send("not found\n", "text/plain", 404)

    try:
        server = ThreadingHTTPServer((host, port), Handler)
    except OSError as exc:
        print(C.err(f"  ✗ Cannot listen on {host}:{port}: {exc}"), file=sys.stderr)
        return EXIT_ENVIRONMENT
    worker = threading.Thread(target=_loop, daemon=True)
    worker.start()
    shown = f"[{host}]" if ":" in host else host
    print(f"  {C.CYAN}Serving on http://{shown}:{port}/  (metrics: /metrics, JSON: /api/results) — "
          f"rescanning every {_format_seconds(interval)} s. Ctrl+C stops.{C.RESET}")
    if host not in {"127.0.0.1", "::1", "localhost"}:
        print(C.warn("  ⚠  Listening beyond localhost: anyone who can reach this port can read the scan results."))
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.server_close()
    print(f"\n  {C.DIM}Server stopped.{C.RESET}")
    return EXIT_OK


# ─────────────────────────────────────────────────────────────────
# CONFIG FILE
# ─────────────────────────────────────────────────────────────────
CONFIG_TYPES: dict[str, type] = {
    "threads": int,
    "timeout": float,
    "count": int,
    "retry": int,
    "rate": int,
    "min_replies": int,
    "ping_tool": str,
    "tcp_ports": str,
    "tcp_timeout": float,
    "dns": bool,
    "out_format": str,
    "keep": int,
    "color": str,
    "data_dir": str,
    "max_hosts": int,
    "no_banner": bool,
    "exit_zero": bool,
    "notify": list,
    "notify_on": str,
    "arp": bool,
}

CONFIG_TEMPLATE = """\
# PingMe configuration. Every setting is optional; command-line flags win.
# Remove the leading '#' to activate a line.

# threads = 20          # concurrent workers
# timeout = 2           # seconds to wait per ping (fractions like 0.5 work)
# count = 3             # ping attempts for a silent host
# min_replies = 2       # replies needed before a host counts as reachable
# retry = 0             # extra rounds for hosts that did not answer
# rate = 0              # packets per second, 0 = unlimited
# ping_tool = "auto"    # auto | fping | ping | ask
# tcp_ports = "22,80,443,3389"
# tcp_timeout = 2
# dns = true            # reverse-resolve IPs to hostnames (default: auto)
# out_format = "txt"    # txt | csv | json
# keep = 50             # history entries kept per label, 0 = unlimited
# color = "auto"        # auto | always | never
# data_dir = "~/pingme-data"
# max_hosts = 65536
# no_banner = false
# exit_zero = false
# arp = true            # count ARP/ND replies as reachability evidence
# notify = ["https://hooks.slack.com/services/XXX", "mailto:ops@example.com"]
# notify_on = "changes" # changes | down | always
"""


def default_config_path() -> Path:
    override = os.environ.get("PINGME_CONFIG")
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        base = os.environ.get("APPDATA")
        return (Path(base) if base else Path.home() / "AppData" / "Roaming") / "PingMe" / "config.toml"
    base = os.environ.get("XDG_CONFIG_HOME")
    return (Path(base) if base else Path.home() / ".config") / "pingme" / "config.toml"


def _strip_toml_comment(line: str) -> str:
    quote = ""
    for index, character in enumerate(line):
        if quote:
            if character == quote:
                quote = ""
        elif character in "\"'":
            quote = character
        elif character == "#":
            return line[:index]
    return line


def _parse_toml_value(raw: str) -> object:
    raw = raw.strip()
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        if not inner:
            return []
        return [_parse_toml_value(item) for item in next(csv.reader([inner], skipinitialspace=True)) if item.strip()]
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
        return raw[1:-1]
    if raw in {"true", "false"}:
        return raw == "true"
    for convert in (int, float):
        try:
            return convert(raw.replace("_", ""))
        except ValueError:
            continue
    raise ValueError(f"unsupported value: {raw}")


def parse_simple_toml(text: str) -> dict:
    """Read the flat ``key = value`` subset of TOML PingMe uses (Python < 3.11 has no tomllib)."""
    data: dict = {}
    for number, line in enumerate(text.splitlines(), 1):
        stripped = _strip_toml_comment(line).strip()
        if not stripped or stripped == "[pingme]":
            continue
        if stripped.startswith("["):
            raise ValueError(f"line {number}: tables are not supported; use top-level keys")
        key, separator, value = stripped.partition("=")
        if not separator:
            raise ValueError(f"line {number}: expected key = value")
        try:
            data[key.strip().strip('"')] = _parse_toml_value(value)
        except ValueError as exc:
            raise ValueError(f"line {number}: {exc}") from exc
    return data


def load_config(path: Path) -> dict:
    """Load and type-check a config file; returns argparse destinations and values."""
    text = path.read_text(encoding="utf-8")
    try:
        import tomllib
    except ModuleNotFoundError:
        raw = parse_simple_toml(text)
    else:
        raw = tomllib.loads(text)
    if isinstance(raw.get("pingme"), dict):
        raw = raw["pingme"]

    config: dict = {}
    for key, value in raw.items():
        dest = key.replace("-", "_")
        expected = CONFIG_TYPES.get(dest)
        if expected is None:
            close = difflib.get_close_matches(dest, CONFIG_TYPES, n=1)
            hint = f" (did you mean '{close[0]}'?)" if close else ""
            raise ValueError(f"unknown setting '{key}'{hint}")
        if dest == "notify" and isinstance(value, str):
            value = [value]
        if dest == "notify" and isinstance(value, list) and not all(isinstance(item, str) for item in value):
            raise ValueError("'notify' must be a string or a list of strings")
        if dest == "tcp_ports" and isinstance(value, (list, int)) and not isinstance(value, bool):
            value = ",".join(str(item) for item in value) if isinstance(value, list) else str(value)
        if dest == "timeout" and isinstance(value, str):
            try:
                value = _timeout_argument(value)
            except argparse.ArgumentTypeError as exc:
                raise ValueError(f"'{key}': {exc}") from None
            config[dest] = value
            continue
        if expected is float and isinstance(value, int) and not isinstance(value, bool):
            value = float(value)
        if not isinstance(value, expected) or (expected is not bool and isinstance(value, bool)):
            raise ValueError(f"'{key}' must be a {expected.__name__}")
        config[dest] = value
    return config


# ─────────────────────────────────────────────────────────────────
# CLI HELP / ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────────
HELP_TOPICS = (
    "targets", "scan", "discovery", "output", "history", "alerts", "config",
    "exitcodes", "advanced", "examples",
)

EXIT_OK = 0
EXIT_NOT_ALL_UP = 1
EXIT_USAGE = 2
EXIT_ENVIRONMENT = 3
EXIT_PROBE_ERRORS = 4
EXIT_INTERRUPTED = 130

DNS_AUTO_LIMIT = 1024


class ColorArgumentParser(argparse.ArgumentParser):
    """ArgumentParser with colored help and friendly, suggestion-bearing errors."""

    def format_help(self) -> str:
        text = super().format_help()
        if not _COLOR_ENABLED:
            return text

        text = re.sub(
            r"(?m)^(usage:|Targets:|Discovery:|Scan Control:|Output:|History:|Alerts and Integrations:|Advanced:|Help:|options:|positional arguments:)$",
            lambda m: f"{C.BOLD}{C.MAGENTA}{m.group(1)}{C.RESET}",
            text,
        )
        text = re.sub(
            r"(?<![\w])(--?[a-zA-Z][\w-]*)(?=[,\s=]|$)",
            lambda m: f"{C.CYAN}{C.BOLD}{m.group(1)}{C.RESET}",
            text,
        )
        text = re.sub(
            r"\b(CIDR|FILE|HOST|IP|PORTS|SEC|PPS|NAME|N|TOPIC|TARGET|MODE|DIR|A|B)\b",
            lambda m: f"{C.YELLOW}{m.group(1)}{C.RESET}",
            text,
        )
        text = re.sub(
            r"(\{(?:auto|fping|ping|txt|csv|json|always|never)[^}]*\})",
            lambda m: f"{C.ORANGE}{m.group(1)}{C.RESET}",
            text,
        )
        return text

    def error(self, message: str):
        hint = ""
        unknown = re.search(r"unrecognized arguments?: (\S+)", message)
        if unknown:
            options = [option for action in self._actions for option in action.option_strings]
            close = difflib.get_close_matches(unknown.group(1).split("=", 1)[0], options, n=1)
            if close:
                hint = f"Did you mean {close[0]}?"
        sys.stderr.write(f"\n  {C.RED}✗ {message}{C.RESET}\n")
        if hint:
            sys.stderr.write(f"  {C.YELLOW}{hint}{C.RESET}\n")
        sys.stderr.write(f"  {C.DIM}Run 'pingme -h' for quick help or 'pingme help examples'.{C.RESET}\n\n")
        sys.exit(EXIT_USAGE)


class _QuickHelpAction(argparse.Action):
    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings, dest=dest, default=default, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        print_quick_help()
        parser.exit()


def print_quick_help() -> None:
    """The short, task-oriented help shown by -h and by a bare 'pingme'."""
    def section(title: str) -> None:
        print(f"\n  {C.BOLD}{C.MAGENTA}{title}{C.RESET}")

    def line(left: str, right: str, width: int = 42) -> None:
        print(f"    {C.CYAN}{left:<{width}}{C.RESET} {right}")

    print(f"\n  {C.BOLD}{C.MAGENTA}PingMe {VERSION}{C.RESET} — find which hosts are up, what they are called, and what changed.")
    section("USAGE")
    print(f"    pingme {C.YELLOW}TARGET{C.RESET} [{C.YELLOW}TARGET{C.RESET} ...] [OPTIONS]")
    print(f"    pingme help {C.YELLOW}TOPIC{C.RESET}")

    section("TARGETS  (mix them freely)")
    line("192.168.1.10   2001:db8::10", "an IP address (IPv4 or IPv6; fe80::1%eth0)")
    line("server01   web.example.com", "a hostname (DNS, hosts file, NetBIOS...)")
    line("192.168.1.0/24", "every host in a subnet")
    line("hosts.txt", "a file with one target per line")

    section("EVERYDAY EXAMPLES")
    line("pingme 192.168.1.0/24", "find live hosts and their names")
    line("pingme hosts.txt --changes", "what came up / went down since last run")
    line("pingme web01 db01 --tcp-ports 22,443", "also count open ports (for hosts that block ping)")
    line("pingme --reverse 10.0.0.0/28", "look up hostnames for IPs, no ping")
    line("pingme 10.0.0.0/24 --watch 60", "rescan every minute and report changes")
    line("pingme --discover6", "find IPv6 hosts on your local networks")
    line("pingme hosts.txt --html report.html", "shareable HTML report")
    line("pingme hosts.txt --watch 60 --notify URL", "alert Slack/Teams/Discord/e-mail on changes")
    line("pingme --sub 10.0.0.0/22", "subnet calculator only")

    section("COMMON OPTIONS")
    line("--fast", "quick sweep: 100 threads, 1 s timeout")
    line("--tcp-ports PORTS", "treat an accepted TCP connection as reachable")
    line("--dns / --no-dns", f"IP → hostname lookups (auto: on up to {DNS_AUTO_LIMIT:,} targets)")
    line("--changes", "compare a file scan with the previous one")
    line("--out-format txt|csv|json", "format for alive/dead/errors files")
    line("--compact / -q, --quiet", "less terminal output / files only")
    line("--exclude IP/CIDR ...", "skip addresses")

    section("MORE HELP")
    print(f"    pingme help {C.CYAN}{' | '.join(HELP_TOPICS)}{C.RESET}")
    print(f"    pingme {C.CYAN}--help-all{C.RESET}   every option in one list")
    print(f"\n  {C.DIM}Only scan networks you are authorized to test.{C.RESET}\n")


def _topic_header(title: str, description: str) -> None:
    print(f"\n  {C.BOLD}{C.MAGENTA}{title}{C.RESET}")
    print(f"  {C.DIM}{description}{C.RESET}\n")


def print_topic_help(topic: str) -> int:
    """Show focused nested help. Returns an exit status."""
    topic = topic.lower().strip()
    if not topic:
        print_quick_help()
        return EXIT_OK
    if topic not in HELP_TOPICS:
        print(C.err(f"  ✗ Unknown help topic: {topic}"))
        close = difflib.get_close_matches(topic, HELP_TOPICS, n=1)
        if close:
            print(C.warn(f"  Did you mean: pingme help {close[0]}"))
        print(f"  {C.DIM}Available topics: {', '.join(HELP_TOPICS)}{C.RESET}\n")
        return EXIT_USAGE

    if topic == "targets":
        _topic_header("TARGET SELECTION", "Give targets as plain arguments, or use the explicit flags.")
        rows = [
            ("TARGET ...", "IP, hostname, CIDR, or existing file; detected automatically."),
            ("-s, --sub CIDR", "Subnet calculator; add --scan to probe its hosts."),
            ("-f, --file FILE", "Read IPs/hostnames from a file (one per line, # comments)."),
            ("--host HOST ...", "Resolve and scan hosts (use when a name matches a file)."),
            ("--exclude IP/CIDR ...", "Skip addresses or whole networks."),
            ("--max-hosts N", "Safety limit for subnet expansion (default 65,536)."),
            ("--discover6 [IFACE ...]", "Find IPv6 hosts on local links (multicast + neighbor cache)."),
            ("-4 / -6", "Use only IPv4 or only IPv6 addresses (resolution and scanning)."),
            ("IPv6 forms", "2001:db8::10, [2001:db8::10], fe80::1%eth0, 2001:db8::/120."),
            ("@tags / --tag TAG", "Tag file lines (web01 @prod) and scan only matching ones."),
            ("--column NAME", "Take targets from one column of a CSV file with headers."),
            ("scan.xml", "nmap -oX output files are read directly as target lists."),
            ("File lines", "'host', 'IP', 'IP host', 'host,IP', or 'IP,host'."),
        ]
    elif topic == "scan":
        _topic_header("SCAN CONTROL", "Tune speed, accuracy, and backend behavior.")
        rows = [
            ("--scan", "Probe the hosts of --sub (targets given directly are always scanned)."),
            ("-t, --threads N", "Concurrent workers (default 20, max 1000)."),
            ("--timeout SEC", "Wait per ping, fractions allowed (default 2)."),
            ("--count N", "Attempts for a silent host (default 3); responders get 2 extra to confirm."),
            ("--min-replies N", "Replies needed to count as reachable (default 2)."),
            ("--retry N", "Extra rounds for hosts that did not answer (max 5)."),
            ("--rate PPS", "Global packets-per-second cap; 0 = unlimited."),
            ("--fast", "100 threads, 1 s timeout, 1 attempt (positives are still confirmed)."),
            ("--resume", "Continue a scan interrupted with Ctrl+C."),
            ("--watch SEC", "Rescan every SEC seconds and print only changes."),
            ("--ping-tool MODE", "auto | native | fping | ping | ask (ask = choose interactively)."),
            ("--timeout auto", "Adapt the wait to measured round-trip times (native engine)."),
        ]
    elif topic == "discovery":
        _topic_header("DISCOVERY FEATURES", "Names, ports, and classification on top of ICMP.")
        rows = [
            ("--dns", "Resolve every scanned IP to a hostname (DNS, hosts, mDNS, NetBIOS)."),
            ("--no-dns", f"Skip name lookups (auto mode resolves up to {DNS_AUTO_LIMIT:,} targets)."),
            ("-r, --reverse IP/CIDR ...", "Only look up hostnames for addresses; no ping."),
            ("--tcp-ports PORTS", "Also try ports: 22,443 or 8000-8010 or presets " + "|".join(TCP_PORT_PRESETS) + "."),
            ("--no-arp", "Do not count ARP/ND replies as evidence (on by default for LAN hosts)."),
            ("--trace-down", f"Traceroute up to {TRACE_LIMIT} down hosts to show where the path breaks."),
            ("--update-oui", "Download the IEEE MAC vendor list (otherwise nmap/IEEE files are used)."),
            ("--tcp-timeout SEC", "TCP connect timeout (default 2); ports are tried in parallel."),
            ("--ipinfo IP ...", "Classify addresses as public, private, or special-use."),
        ]
    elif topic == "output":
        _topic_header("OUTPUT", "Result files, formats, and terminal verbosity.")
        rows = [
            ("--alive-out FILE", "Reachable hosts (default alive.txt)."),
            ("--dead-out FILE", "Completed probes with no response (default dead.txt)."),
            ("--error-out FILE", "Probes that failed to run (default errors.txt)."),
            ("--hostnames-out FILE", "Full HOST/IP/STATUS/RTT/LOSS/OS table (file scans: hostnames.txt)."),
            ("--changes-out FILE", "Change summary written by --changes (default changes.txt)."),
            ("--out-format FMT", "txt | csv | json for the alive/dead/errors files."),
            ("-q, --quiet", "Write files only; no terminal output."),
            ("--compact", "Summary line and file paths only."),
            ("--verbose", "Full interface even when output is redirected."),
            ("--html FILE", "Self-contained HTML report with filters, sorting, and uptime."),
            ("--nmap-xml FILE", "nmap-compatible XML for tools that import nmap scans."),
            ("--color MODE", "auto | always | never (NO_COLOR is honoured)."),
            ("--no-banner", "Hide the startup banner."),
        ]
    elif topic == "history":
        _topic_header("HISTORY AND COMPARISON", "Track changes across scans or compare saved snapshots.")
        rows = [
            ("--changes", "Hostname-aware comparison with the previous file scan."),
            ("--compare", "IP-only comparison with the previous scan of the label."),
            ("--diff A B", "Compare two result files (txt, csv, or json)."),
            ("--history", "List stored scan histories."),
            ("--clear-history NAME|FILE", "Delete stored data for a label or target file."),
            ("--no-history", "Do not save this scan."),
            ("--uptime LABEL|FILE", "Availability %, flaps, and last-seen per host from history."),
            ("--keep N", f"History entries kept per label (default {DEFAULT_HISTORY_KEEP}; 0 = all)."),
            ("--label NAME", "Stable name for history/resume data."),
            ("--data-dir DIR", f"Where state lives (default {_default_data_dir()})."),
        ]
    elif topic == "alerts":
        _topic_header("ALERTS AND INTEGRATIONS", "Get told when something changes, or feed dashboards.")
        rows = [
            ("--notify URL", "Slack/Teams/Discord webhook, any https:// JSON endpoint (repeatable)."),
            ("--notify telegram://T@C", "Telegram bot token T and chat id C."),
            ("--notify mailto:a@b.c", "E-mail via PINGME_SMTP_HOST/PORT/USER/PASSWORD/FROM."),
            ("--notify-on MODE", "changes (default) | down | always. --watch alerts on changes."),
            ("--serve [HOST:]PORT", "Rescan every --watch SEC (default 60); /metrics, /api/results, /."),
            ("--wake", "Wake-on-LAN for down hosts whose MAC was seen before."),
            ("--wol MAC ...", "Send magic packets now (--wol-broadcast to pick the subnet)."),
        ]
    elif topic == "config":
        _topic_header("CONFIGURATION FILE", "Save your preferred defaults once.")
        rows = [
            ("Location", str(default_config_path())),
            ("--init-config", "Create a commented template at that location."),
            ("--config FILE", "Use a different config file (or set PINGME_CONFIG)."),
            ("--no-config", "Ignore the config file for this run."),
            ("Keys", ", ".join(CONFIG_TYPES)),
            ("Precedence", "command-line flag > config file > built-in default."),
        ]
    elif topic == "exitcodes":
        _topic_header("EXIT CODES", "For scripts, cron jobs, and monitoring checks.")
        rows = [
            ("0", "Hosts/files: every target reachable. Subnets: at least one host found."),
            ("1", "Hosts/files: a target is down or unresolved. Subnets: nothing found."),
            ("2", "Usage or configuration error."),
            ("3", "No usable ping tool is installed."),
            ("4", "At least one probe failed to run (see errors.txt)."),
            ("130", "Interrupted with Ctrl+C (use --resume to continue)."),
            ("--exit-zero", "Always exit 0 after a completed scan."),
        ]
    elif topic == "advanced":
        _topic_header("ADVANCED NOTES", "Operational behavior and safety controls.")
        rows = [
            ("Fail closed", "Reachable only with direct echo replies, an accepted TCP connection,"
                            " or a fresh (REACHABLE) ARP/ND entry for an on-link host."),
            ("Confirmation", "Replies must come from separate ping processes (--min-replies)."),
            ("native", "Built-in ICMP socket: exact payload/source matching, no process per host."),
            ("fping", "Batch discovery; every positive is re-confirmed with the system ping."),
            ("TTL hint", "OS-family guesses are heuristic, never definitive."),
            ("IPv6", "Hosts, files, CIDRs up to --max-hosts, and --discover6 for /64 LANs."),
            ("Link-local", "fe80:: addresses need a zone: fe80::1%eth0 (Windows: %12)."),
            ("State", "History, resume, and baselines live in --data-dir, not the cwd."),
            ("Authorization", "Only scan systems and networks you are authorized to assess."),
        ]
    else:
        _topic_header("EXAMPLES", "Common PingMe workflows.")
        examples = [
            ("pingme 192.168.1.0/24", "find live hosts and their names"),
            ("pingme 192.168.1.0/24 --fast", "quicker, less tolerant of slow hosts"),
            ("pingme targets.txt", "scan a file of hostnames/IPs"),
            ("pingme targets.txt --changes", "report what changed since last time"),
            ("pingme server.local 10.0.0.10 --tcp-ports 22,443", "hosts that may block ping"),
            ("pingme 10.0.0.0/24 --watch 30", "live monitoring"),
            ("pingme --reverse 10.0.0.1 10.0.0.0/29", "IP → hostname only"),
            ("pingme --discover6", "find IPv6 hosts on every local link"),
            ("pingme server01 -6", "scan only the IPv6 addresses of a host"),
            ("pingme 10.0.0.0/24 --out-format csv --alive-out up.csv", "spreadsheet output"),
            ("pingme --sub 10.0.0.0/22", "subnet calculator"),
            ("pingme --ipinfo 8.8.8.8 192.168.1.1", "classify addresses"),
            ("pingme --diff alive_old.txt alive_new.txt", "compare two result files"),
            ("pingme hosts.txt --changes --notify https://hooks.slack.com/…", "Slack alert on changes"),
            ("pingme hosts.txt --html report.html", "shareable HTML report"),
            ("pingme --uptime hosts.txt", "availability from history"),
            ("pingme 10.0.0.0/24 --serve 9109", "Prometheus metrics + live page"),
            ("pingme web01 --tcp-ports web,windows", "port presets"),
            ("pingme --wol aa:bb:cc:dd:ee:ff", "wake a machine"),
            ("pingme --init-config", "create a config file for your defaults"),
        ]
        width = max(len(command) for command, _ in examples)
        for command, description in examples:
            print(f"  {C.CYAN}${C.RESET} {C.BOLD}{command:<{width}}{C.RESET}  {C.DIM}{description}{C.RESET}")
        print()
        return EXIT_OK

    width = max(len(flag) for flag, _ in rows)
    for flag, description in rows:
        print(f"  {C.CYAN}{C.BOLD}{flag:<{width}}{C.RESET}  {description}")
    print()
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    epilog = (
        f"{C.BOLD}Topics:{C.RESET} pingme help {' | '.join(HELP_TOPICS)}\n"
        f"{C.BOLD}Quick help:{C.RESET} pingme -h\n"
    )

    p = ColorArgumentParser(
        prog="pingme",
        usage="pingme [TARGET ...] [OPTIONS]",
        description=(
            f"{C.BOLD}{C.MAGENTA}PingMe v{VERSION}{C.RESET} — ICMP/TCP host discovery with hostnames, "
            "change tracking, and subnet tools."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
        epilog=epilog,
    )

    p.add_argument("targets", nargs="*", metavar="TARGET",
                   help="IP, hostname, CIDR, or target file (type detected automatically)")

    tg = p.add_argument_group("Targets")
    tg.add_argument("-s", "--sub", metavar="CIDR",
                    help="Subnet calculator; add --scan to probe its hosts")
    tg.add_argument("-f", "--file", metavar="FILE",
                    help="Scan IPs/hostnames from a file")
    tg.add_argument("--host", metavar="HOST", nargs="+",
                    help="Scan one or more IP addresses or hostnames")
    tg.add_argument("--exclude", metavar="IP/CIDR", nargs="+",
                    help="Skip one or more IP addresses or CIDRs")
    tg.add_argument("--max-hosts", type=int, default=65536, metavar="N",
                    help="Maximum subnet targets to expand (default: 65536)")
    tg.add_argument("--tag", metavar="TAG", action="append",
                    help="Only file lines tagged @TAG (repeatable)")
    tg.add_argument("--column", metavar="NAME",
                    help="Read targets from this column of a CSV file with a header row")
    tg.add_argument("--discover6", nargs="*", metavar="IFACE",
                    help="Find IPv6 hosts on local links (all interfaces if none given)")
    family = tg.add_mutually_exclusive_group()
    family.add_argument("-4", "--ipv4-only", dest="family", action="store_const", const=4,
                        help="Resolve and scan IPv4 addresses only")
    family.add_argument("-6", "--ipv6-only", dest="family", action="store_const", const=6,
                        help="Resolve and scan IPv6 addresses only")

    dg = p.add_argument_group("Discovery")
    dg.add_argument("--scan", action="store_true",
                    help="Probe the hosts of --sub")
    dg.add_argument("--dns", dest="dns", action="store_const", const=True, default=None,
                    help=f"Resolve every scanned IP to a hostname (auto: up to {DNS_AUTO_LIMIT} targets)")
    dg.add_argument("--no-dns", dest="dns", action="store_const", const=False,
                    help="Skip IP → hostname lookups")
    dg.add_argument("-r", "--reverse", metavar="IP/CIDR", nargs="+",
                    help="Only look up hostnames for addresses (no ping)")
    dg.add_argument("--no-arp", dest="arp", action="store_false", default=True,
                    help="Do not count ARP/ND replies as reachability evidence")
    dg.add_argument("--update-oui", action="store_true",
                    help="Download the IEEE MAC vendor database")
    dg.add_argument("--tcp-ports", metavar="PORTS",
                    help="TCP checks, e.g. 22,80,443 or 8000-8010")
    dg.add_argument("--tcp-timeout", type=float, default=2, metavar="SEC",
                    help="TCP connect timeout (default: 2)")
    dg.add_argument("--trace-down", action="store_true",
                    help=f"Traceroute up to {TRACE_LIMIT} down hosts to show where the path breaks")
    dg.add_argument("--ipinfo", metavar="IP", nargs="+",
                    help="Classify IP addresses as public/private/special")

    sg = p.add_argument_group("Scan Control")
    sg.add_argument("-t", "--threads", type=int, default=20, metavar="N",
                    help="Concurrent workers (default: 20)")
    sg.add_argument("--timeout", type=_timeout_argument, default=2, metavar="SEC",
                    help="Wait per ping in seconds, fractions allowed, or 'auto' (default: 2)")
    sg.add_argument("--count", type=int, default=3, metavar="N",
                    help="Ping attempts for a silent host (default: 3)")
    sg.add_argument("--min-replies", type=int, default=2, metavar="N",
                    help="Replies required for REACHABLE (default: 2)")
    sg.add_argument("--retry", type=int, default=0, metavar="N",
                    help="Extra rounds for non-responsive hosts (default: 0)")
    sg.add_argument("--rate", type=int, default=0, metavar="PPS",
                    help="Maximum packets/sec; 0 = unlimited")
    sg.add_argument("--ping-tool", default="auto", choices=["auto", "native", "fping", "ping", "ask"],
                    help="ICMP backend (default: auto)")
    sg.add_argument("--fast", action="store_true",
                    help="100 threads, 1s timeout, 1 attempt")
    sg.add_argument("--resume", action="store_true",
                    help="Resume an interrupted scan")
    sg.add_argument("--watch", type=float, metavar="SEC",
                    help="Rescan every SEC seconds and report changes (Ctrl+C stops)")

    og = p.add_argument_group("Output")
    og.add_argument("--alive-out", default="alive.txt", metavar="FILE",
                    help="Reachable-host output file (default: alive.txt)")
    og.add_argument("--dead-out", default="dead.txt", metavar="FILE",
                    help="Non-responsive-host output file (default: dead.txt)")
    og.add_argument("--error-out", default="errors.txt", metavar="FILE",
                    help="Probe-execution-error output file (default: errors.txt)")
    og.add_argument("--hostnames-out", default=None, metavar="FILE",
                    help="Full status table (file scans default to hostnames.txt)")
    og.add_argument("--changes-out", default="changes.txt", metavar="FILE",
                    help="Change report written by --changes (default: changes.txt)")
    og.add_argument("--out-format", default="txt", choices=["txt", "csv", "json"],
                    help="Output format (default: txt)")
    og.add_argument("--html", metavar="FILE",
                    help="Write a self-contained HTML report")
    og.add_argument("--nmap-xml", metavar="FILE",
                    help="Write results as nmap-compatible XML")
    og.add_argument("--label", metavar="NAME",
                    help="History/resume label (default: derived from targets)")
    og.add_argument("-q", "--quiet", action="store_true",
                    help="Write files only; suppress terminal output")
    og.add_argument("--compact", action="store_true",
                    help="Show only the summary and saved file paths")
    og.add_argument("--verbose", action="store_true",
                    help="Full interface even when output is redirected")
    og.add_argument("--color", default="auto", choices=["auto", "always", "never"],
                    help="Colored output (default: auto; NO_COLOR honoured)")
    og.add_argument("--no-banner", action="store_true",
                    help="Suppress the ASCII banner")
    og.add_argument("--exit-zero", action="store_true",
                    help="Exit 0 after any completed scan")

    hg = p.add_argument_group("History")
    hg.add_argument("--history", action="store_true",
                    help="List stored scan history")
    hg.add_argument("--changes", action="store_true",
                    help="Compare this file scan with its previous result")
    hg.add_argument("--compare", action="store_true",
                    help="IP-only comparison with the previous scan")
    hg.add_argument("--diff", metavar=("A", "B"), nargs=2,
                    help="Compare two result files (txt/csv/json)")
    hg.add_argument("--clear-history", metavar="NAME",
                    help="Delete stored data for a label or target file")
    hg.add_argument("--no-history", action="store_true",
                    help="Do not save this scan to history")
    hg.add_argument("--uptime", nargs="?", const=True, metavar="LABEL|FILE",
                    help="Availability per host from stored history")
    hg.add_argument("--keep", type=int, default=DEFAULT_HISTORY_KEEP, metavar="N",
                    help=f"History entries kept per label (default: {DEFAULT_HISTORY_KEEP}; 0 = all)")
    hg.add_argument("--data-dir", metavar="DIR",
                    help="State directory (default: per-user data directory)")

    ng = p.add_argument_group("Alerts and Integrations")
    ng.add_argument("--notify", metavar="TARGET", action="append",
                    help="Alert via Slack/Teams/Discord webhook, telegram://TOKEN@CHAT, mailto:, or any URL")
    ng.add_argument("--notify-on", choices=["changes", "down", "always"], default="changes",
                    help="When to alert (default: changes)")
    ng.add_argument("--serve", metavar="[HOST:]PORT",
                    help="Keep scanning and serve /metrics (Prometheus), /api/results, and a live page")
    ng.add_argument("--wake", action="store_true",
                    help="Send Wake-on-LAN to down hosts whose MAC is known")
    ng.add_argument("--wol", metavar="MAC", nargs="+",
                    help="Send Wake-on-LAN magic packets to MAC addresses and exit")
    ng.add_argument("--wol-broadcast", metavar="IP", default="255.255.255.255",
                    help="Broadcast address for Wake-on-LAN (default: 255.255.255.255)")

    ag = p.add_argument_group("Advanced")
    ag.add_argument("--config", metavar="FILE",
                    help=f"Config file (default: {default_config_path()})")
    ag.add_argument("--no-config", action="store_true",
                    help="Ignore the config file")
    ag.add_argument("--init-config", action="store_true",
                    help="Create a commented config template")

    help_group = p.add_argument_group("Help")
    help_group.add_argument("-h", "--help", action=_QuickHelpAction,
                            help="Quick, task-oriented help")
    help_group.add_argument("--help-all", action="help",
                            help="Show every option (this list)")
    help_group.add_argument("--help-topic", choices=HELP_TOPICS, metavar="TOPIC",
                            help="Show focused help for one topic")
    help_group.add_argument("--version", action="version",
                            version=f"%(prog)s {VERSION} ({BUILD})",
                            help="Show PingMe version and build")

    return p


def _timeout_argument(value: str) -> Optional[float]:
    """--timeout accepts seconds or 'auto' (adapt to measured round-trip times)."""
    if str(value).strip().lower() == "auto":
        return None
    try:
        return float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected seconds or 'auto', got '{value}'") from None


def _preparse(argv: list[str]) -> argparse.Namespace:
    """Read the options that must act before the full parser is built."""
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config")
    pre.add_argument("--no-config", action="store_true")
    pre.add_argument("--color")
    namespace, _unknown = pre.parse_known_args(argv)
    return namespace


def _file_label(path: str) -> str:
    """Stable per-file label: two hosts.txt files in different folders never share state."""
    resolved = str(Path(path).expanduser().resolve())
    digest = hashlib.sha1(resolved.encode("utf-8")).hexdigest()[:8]
    return f"{_safe_label(Path(path).stem)}-{digest}"


_FILE_LIKE_SUFFIXES = {".txt", ".csv", ".lst", ".list", ".tsv", ".json"}


def classify_targets(values: list[str]) -> tuple[list[str], list[str], list[str]]:
    """Split positional targets into (subnets, files, hosts), or raise ValueError."""
    subnets: list[str] = []
    files: list[str] = []
    hosts: list[str] = []
    for value in values:
        if Path(value).expanduser().is_file():
            files.append(value)
            continue
        if "/" in value:
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError:
                raise ValueError(f"'{value}' is neither an existing file nor a valid CIDR subnet") from None
            subnets.append(value)
            continue
        if Path(value).suffix.lower() in _FILE_LIKE_SUFFIXES and not _normalise_probe_address(value):
            raise ValueError(f"target file not found: {value}")
        hosts.append(value)
    return subnets, files, hosts


def scan_exit_code(results: list[dict], monitored: set[str], unresolved: int) -> int:
    """Exit status for a completed scan (see 'pingme help exitcodes')."""
    if any(result.get("status") == "PROBE ERROR" for result in results):
        return EXIT_PROBE_ERRORS
    if monitored or unresolved:
        down = any(result["ip"] in monitored and not result["alive"] for result in results)
        return EXIT_NOT_ALL_UP if unresolved or down else EXIT_OK
    return EXIT_OK if any(result["alive"] for result in results) else EXIT_NOT_ALL_UP


def show_reverse_lookups(values: list[str], threads: int, max_hosts: int) -> int:
    """Print an IP → hostname table for addresses and subnets without probing them."""
    addresses: list[str] = []
    for value in values:
        address = _normalise_probe_address(value)
        if address is not None:
            addresses.append(address)
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            print(C.err(f"  ✗ Not an IP address or CIDR: {value}"), file=sys.stderr)
            return EXIT_USAGE
        size = max(network.num_addresses - 2, 0) if network.version == 4 and network.prefixlen <= 30 else network.num_addresses
        if len(addresses) + size > max_hosts:
            print(C.err(f"  ✗ {value} expands beyond --max-hosts {max_hosts:,}."), file=sys.stderr)
            return EXIT_USAGE
        hosts = network.hosts() if network.version == 4 else iter(network)
        addresses.extend(str(host) for host in hosts)
    addresses = list(dict.fromkeys(addresses))

    rows: dict[str, tuple[str, str]] = {}
    interactive = sys.stdout.isatty()
    with ThreadPoolExecutor(max_workers=max(1, min(max(threads, 50), 200))) as pool:
        futures = {pool.submit(reverse_lookup, ip, 1.5, True): ip for ip in addresses}
        for future in as_completed(futures):
            rows[futures[future]] = future.result()
            if interactive:
                sys.stdout.write(f"{_CLEAR_LINE}  {C.DIM}Looking up names… {len(rows)}/{len(addresses)}{C.RESET}")
                sys.stdout.flush()
    if interactive:
        sys.stdout.write(_CLEAR_LINE)

    named = [(ip, *rows[ip]) for ip in addresses if rows[ip][0]]
    ip_w = max([15] + [len(ip) for ip in addresses])
    name_w = max([len("(no name)")] + [len(name) for _ip, name, _source in named])
    line = f"  {C.CYAN}+{'-' * (ip_w + 2)}+{'-' * (name_w + 2)}+{'-' * 9}+{C.RESET}"
    print(f"\n  {C.BOLD}{C.MAGENTA}REVERSE LOOKUP · IP → HOSTNAME{C.RESET}")
    print(line)
    print(f"  {C.CYAN}|{C.RESET} {C.BOLD}{'IP ADDRESS':<{ip_w}}{C.RESET} {C.CYAN}|{C.RESET} "
          f"{C.BOLD}{'HOSTNAME':<{name_w}}{C.RESET} {C.CYAN}|{C.RESET} {C.BOLD}{'SOURCE':<7}{C.RESET} {C.CYAN}|{C.RESET}")
    print(line)
    # Large ranges list only named addresses; a handful of lookups lists everything.
    shown = [(ip, *rows[ip]) for ip in addresses] if len(addresses) <= 32 else named
    for ip, name, source in shown:
        print(f"  {C.CYAN}|{C.RESET} {ip:<{ip_w}} {C.CYAN}|{C.RESET} "
              f"{(C.TEAL + name) if name else (C.DIM + '(no name)')}{' ' * (name_w - len(name or '(no name)'))}{C.RESET} "
              f"{C.CYAN}|{C.RESET} {C.DIM}{source or '-':<7}{C.RESET} {C.CYAN}|{C.RESET}")
    print(line)
    print(f"  {C.GREEN}Named: {len(named)}{C.RESET}  {C.DIM}No name: {len(addresses) - len(named)}{C.RESET}\n")
    return EXIT_OK if named else EXIT_NOT_ALL_UP


def _live_rows(results: list[dict]) -> list[dict]:
    """Rows for the subnet summary table: hosts that answered or failed to probe."""
    return [
        {"host": result["ip"], "ip": result["ip"], "type": "DIRECT IP"}
        for result in results
        if result["alive"] or result.get("status") == "PROBE ERROR"
    ]


def watch_scans(
    args: argparse.Namespace,
    ip_list: list[str],
    label: str,
    scan_kwargs: dict,
    first: list[dict],
    status_rows: Optional[list[dict]] = None,
) -> int:
    """Rescan on an interval and print one line per status change until Ctrl+C.

    Each round's changes are also sent to --notify targets, and --html is refreshed.
    """
    status_rows = status_rows or []
    names = {str(row["ip"]): str(row["host"]) for row in status_rows}
    interval = args.watch
    previous = {result["ip"]: result for result in first}
    print(f"  {C.CYAN}👁  Watching {len(ip_list):,} targets every {_format_seconds(interval)}s — "
          f"press Ctrl+C to stop.{C.RESET}\n")
    rounds = 0
    try:
        while True:
            time.sleep(interval)
            results = run_scan(ip_list, label=label, quiet=True, resume=False, resumable=False, **scan_kwargs)
            if _STOP_EVENT.is_set():
                break
            rounds += 1
            stamp = datetime.now().strftime("%H:%M:%S")
            changes = 0
            events: dict[str, list[dict]] = {"went_offline": [], "newly_online": []}
            for result in results:
                before = previous.get(result["ip"])
                old_status = before.get("status") if before else None
                if old_status == result["status"]:
                    continue
                changes += 1
                if changes == 1:
                    sys.stdout.write(_line_start())
                name = f"  {C.DIM}{result['hostname']}{C.RESET}" if result.get("hostname") else ""
                event = {"ip": result["ip"], "host": names.get(result["ip"]) or result.get("hostname", "")}
                if result["alive"]:
                    events["newly_online"].append(event)
                elif result["status"] == "NO RESPONSE" and old_status == "REACHABLE":
                    events["went_offline"].append(event)
                if result["alive"]:
                    rtt = f"  {result['rtt_avg']}ms" if result.get("rtt_avg") is not None else ""
                    print(f"  {C.DIM}{stamp}{C.RESET}  {C.GREEN}▲ UP     {result['ip']:<18}{C.RESET}{rtt}{name}")
                elif result["status"] == "NO RESPONSE":
                    print(f"  {C.DIM}{stamp}{C.RESET}  {C.RED}▼ DOWN   {result['ip']:<18}{C.RESET}{name}")
                else:
                    print(f"  {C.DIM}{stamp}{C.RESET}  {C.YELLOW}! ERROR  {result['ip']:<18}{C.RESET}  "
                          f"{C.DIM}{result.get('probe_error', '')[:50]}{C.RESET}")
            if changes == 0 and sys.stdout.isatty():
                alive = sum(1 for result in results if result["alive"])
                sys.stdout.write(f"{_CLEAR_LINE}  {C.DIM}{stamp}  round {rounds}: no changes ({alive} up){C.RESET}   ")
                sys.stdout.flush()
            previous = {result["ip"]: result for result in results}
            write_results(
                results, alive_file=args.alive_out, dead_file=args.dead_out,
                error_file=args.error_out, out_format=args.out_format, quiet=True,
            )
            # Watch mode alerts on transitions only; a repeating "still down" alert every round is noise.
            if args.notify and any(events.values()):
                notify_all(args.notify, f"PingMe watch · {stamp}", events, quiet=True)
            if args.html:
                write_html_report(args.html, f"PingMe watch · {label}", records_for_results(results, status_rows),
                                  None, f"Round {rounds} · {stamp}")
    except KeyboardInterrupt:
        pass
    print(f"\n  {C.DIM}Watch stopped after {rounds} round(s).{C.RESET}\n")
    return EXIT_OK


# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────
def _configure_streams() -> None:
    # Keep output visible immediately when launched through wrappers, symlinks,
    # PowerShell, redirected terminals, or CI.
    try:
        stream_options = {"line_buffering": True}
        if sys.platform == "win32":
            # The UI uses Unicode box drawing and symbols. Explicit UTF-8 also
            # prevents redirected Windows output from crashing under cp1252.
            stream_options.update(encoding="utf-8", errors="replace")
        sys.stdout.reconfigure(**stream_options)
        sys.stderr.reconfigure(**stream_options)
    except (AttributeError, ValueError):
        pass


BLANKET_TCP_MIN_TARGETS = 16
BLANKET_TCP_SHARE = 0.9


def downgrade_blanket_tcp(results: list[dict]) -> int:
    """Refuse TCP-only evidence when nearly every address "accepts" connections.

    A transparent proxy or captive portal can answer port 80/443 for every IP,
    including unused ones, on ports the canary check does not cover. If at
    least 90% of 16+ scanned addresses are reachable only through TCP, those
    results become PROBE ERROR instead of REACHABLE. Returns how many changed.
    """
    if len(results) < BLANKET_TCP_MIN_TARGETS:
        return 0
    tcp_only = [r for r in results if r["alive"] and not r.get("icmp_alive") and not r.get("arp") and r.get("tcp_open")]
    if len(tcp_only) < BLANKET_TCP_SHARE * len(results):
        return 0
    for result in tcp_only:
        result.update(alive=False, status="PROBE ERROR", evidence="",
                      probe_error="TCP accepted for nearly every scanned address (proxy?); not counted as reachable")
    return len(tcp_only)


def scan_events(
    mode: str,
    results: list[dict],
    status_rows: list[dict],
    change_groups: Optional[dict[str, list[dict]]],
    previous_scan: Optional[dict],
) -> dict[str, list[dict]]:
    """Choose what a notification reports for --notify-on changes|down|always."""
    names = {str(row["ip"]): str(row["host"]) for row in status_rows}
    by_ip = {r["ip"]: {"ip": r["ip"], "host": names.get(r["ip"]) or r.get("hostname", "")} for r in results}
    # Only targets someone listed (files, --host) are expected to be up; empty subnet
    # addresses are not outages.
    expected = {str(row["ip"]) for row in status_rows if not row.get("excluded")}
    down = [by_ip[r["ip"]] for r in results if r.get("status") == "NO RESPONSE" and r["ip"] in expected]
    unresolved = [{"host": row["host"], "ip": ""} for row in status_rows if row.get("ip") == "UNRESOLVED"]
    if mode == "down":
        return {"down": down, "unresolved": unresolved}
    if mode == "always":
        return {"down": down, "unresolved": unresolved,
                "newly_online": [by_ip[r["ip"]] for r in results if r["alive"]]}
    if change_groups is not None:
        return {key: change_groups.get(key, []) for key in ("went_offline", "newly_online", "ip_changed", "mac_changed")}
    if not previous_scan:
        return {}
    changes = history_changes(
        previous_scan,
        [r["ip"] for r in results if r["alive"]],
        [r["ip"] for r in results if r.get("status") == "NO RESPONSE"],
        [r["ip"] for r in results if r.get("status") == "PROBE ERROR"],
    )
    return {"went_offline": [by_ip[ip] for ip in changes["newly_down"] if ip in by_ip],
            "newly_online": [by_ip[ip] for ip in changes["newly_up"] if ip in by_ip]}


def _validate_ranges(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    checks = [
        ("--threads", args.threads, 1, 1000),
        ("--count", args.count, 1, 20),
        ("--min-replies", args.min_replies, 1, 20),
        ("--retry", args.retry, 0, 5),
        ("--rate", args.rate, 0, 1_000_000),
        ("--tcp-timeout", args.tcp_timeout, 0.1, 30),
        ("--max-hosts", args.max_hosts, 1, 2 ** 32),
        ("--keep", args.keep, 0, 100_000),
    ]
    for name, value, low, high in checks:
        if not low <= value <= high:
            parser.error(f"{name} must be between {low:g} and {high:,} (got {value:g})")
    if args.timeout is not None and not 0.1 <= args.timeout <= 30:
        parser.error(f"--timeout must be between 0.1 and 30 or 'auto' (got {args.timeout:g})")
    if args.watch is not None and args.watch < 1:
        parser.error("--watch must be at least 1 second")
    for name, value, choices in (
        ("ping_tool", args.ping_tool, ("auto", "native", "fping", "ping", "ask")),
        ("out_format", args.out_format, ("txt", "csv", "json")),
        ("color", args.color, ("auto", "always", "never")),
        ("notify_on", args.notify_on, ("changes", "down", "always")),
    ):
        if value not in choices:
            parser.error(f"{name} must be one of {', '.join(choices)} (got '{value}')")


def main(argv: Optional[list[str]] = None) -> int:
    global _DATA_DIR_OVERRIDE
    _configure_streams()
    argv = list(sys.argv[1:] if argv is None else argv)

    pre = _preparse(argv)
    if not colors_wanted(pre.color or "auto"):
        disable_colors()
    config: dict = {}
    if not pre.no_config:
        config_path = Path(pre.config).expanduser() if pre.config else default_config_path()
        if pre.config and not config_path.is_file() and "--init-config" not in argv:
            print(C.err(f"  ✗ Config file not found: {config_path}"), file=sys.stderr)
            return EXIT_USAGE
        if config_path.is_file():
            try:
                config = load_config(config_path)
            except (OSError, ValueError) as exc:
                print(C.err(f"  ✗ Config file {config_path}: {exc}"), file=sys.stderr)
                return EXIT_USAGE

    if _COLOR_ENABLED and not colors_wanted(pre.color or config.get("color") or "auto"):
        disable_colors()

    # Nested help syntax: pingme help <topic>
    if argv and argv[0] == "help":
        topics = [value for value in argv[1:] if not value.startswith("-")]
        return print_topic_help(topics[0] if topics else "")

    parser = build_parser()
    parser.set_defaults(**config)
    args   = parser.parse_args(argv)

    if args.help_topic:
        return print_topic_help(args.help_topic)

    if args.init_config:
        destination = Path(args.config).expanduser() if args.config else default_config_path()
        if destination.exists():
            print(C.warn(f"  ⚠  Config already exists: {destination}"))
            return EXIT_OK
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(CONFIG_TEMPLATE, encoding="utf-8")
        print(C.ok(f"  ✔  Created {destination}"))
        print(f"  {C.DIM}Edit it and remove the '#' in front of any setting you want.{C.RESET}")
        return EXIT_OK

    _validate_ranges(parser, args)
    if args.data_dir:
        _DATA_DIR_OVERRIDE = Path(args.data_dir).expanduser()
    global _ADDRESS_FAMILY
    _ADDRESS_FAMILY = args.family
    if args.tcp_ports:
        try:
            args.tcp_ports = parse_tcp_ports(expand_port_presets(args.tcp_ports))
        except ValueError as exc:
            parser.error(str(exc))

    try:
        positional_subs, positional_files, positional_hosts = classify_targets(args.targets)
    except ValueError as exc:
        parser.error(str(exc))
    subnets = ([args.sub] if args.sub else []) + positional_subs
    files = ([args.file] if args.file else []) + positional_files
    hosts = list(args.host or []) + positional_hosts
    if len(files) > 1:
        parser.error("scan one target file at a time (merge the files, or run pingme once per file)")
    target_file = files[0] if files else None
    if args.targets or target_file or hosts or args.discover6 is not None:
        args.scan = True

    if args.quiet and (args.compact or args.verbose):
        parser.error("--quiet cannot be combined with --compact or --verbose")
    if args.compact and args.verbose:
        parser.error("--compact and --verbose cannot be combined")
    if args.changes and not target_file:
        parser.error("--changes needs a target file (for example: pingme hosts.txt --changes)")
    if args.watch and not args.scan:
        parser.error("--watch needs scan targets (for example: pingme 10.0.0.0/24 --watch 60)")
    if args.watch and args.resume:
        parser.error("--watch and --resume cannot be combined")
    if (args.tag or args.column) and not target_file:
        parser.error("--tag and --column filter a target file (for example: pingme hosts.txt --tag prod)")
    if args.serve and not args.scan:
        parser.error("--serve needs scan targets (for example: pingme 10.0.0.0/24 --serve 9109)")
    hostnames_out = args.hostnames_out or ("hostnames.txt" if target_file else None)
    output_options = {
        "--alive-out": args.alive_out,
        "--dead-out": args.dead_out,
        "--error-out": args.error_out,
    }
    if hostnames_out:
        output_options["--hostnames-out"] = hostnames_out
    if args.changes:
        output_options["--changes-out"] = args.changes_out
    seen_output_paths: dict[str, str] = {}
    for option, output_path in output_options.items():
        normalized = os.path.normcase(os.path.abspath(os.path.expanduser(output_path)))
        previous_option = seen_output_paths.get(normalized)
        if previous_option:
            parser.error(f"{option} and {previous_option} must use different files")
        seen_output_paths[normalized] = option

    # Interactive terminals get the graphical UI. Redirected output is compact
    # unless --verbose explicitly requests the full diagnostic interface.
    rich_output = args.verbose or (
        sys.stdout.isatty() and not args.compact and not args.quiet
    )
    banner(no_banner=args.no_banner or not rich_output)

    # ── one-shot utilities ──────────────────────────────────────
    if args.clear_history:
        label = args.clear_history
        if Path(label).expanduser().is_file():
            label = _file_label(label)
            _LEGACY_LABELS[label] = Path(args.clear_history).stem
        clear_history(label); return EXIT_OK

    if args.history:
        show_history_list(); return EXIT_OK

    if args.ipinfo:
        show_ipinfo(args.ipinfo); return EXIT_OK

    if args.reverse:
        return show_reverse_lookups(args.reverse, args.threads, args.max_hosts)

    if args.update_oui:
        return update_oui_database()

    if args.wol:
        try:
            sent = send_wake_on_lan(args.wol, args.wol_broadcast)
        except (ValueError, OSError) as exc:
            print(C.err(f"  ✗ Wake-on-LAN failed: {exc}"), file=sys.stderr)
            return EXIT_USAGE
        print(C.ok(f"  ✔  Magic packet sent to {', '.join(sent)} via {args.wol_broadcast}"))
        return EXIT_OK

    if args.uptime is not None and not (args.targets or args.sub or args.file or args.host):
        if args.uptime is True:
            parser.error("--uptime needs a label or target file (see: pingme --history)")
        uptime_label = args.uptime
        if Path(uptime_label).expanduser().is_file():
            uptime_label = _file_label(uptime_label)
            _LEGACY_LABELS[uptime_label] = Path(args.uptime).stem
        return show_uptime(uptime_label)

    if args.diff:
        diff_files(args.diff[0], args.diff[1]); return EXIT_OK

    # ── need a scan target ──────────────────────────────────────
    if not subnets and not target_file and not hosts and args.discover6 is None:
        print_quick_help()
        return EXIT_OK

    # ── build IP list ───────────────────────────────────────────
    ip_list: list[str] = []
    file_mappings: list[dict] = []
    host_rows: list[dict] = []
    subnet_ips: set[str] = set()
    label = args.label
    subnet_target_count = 0

    for cidr in subnets:
        net = show_subnet_info(cidr, display=not args.scan or rich_output)
        count = max(net.num_addresses - 2, 0) if net.version == 4 and net.prefixlen <= 30 else net.num_addresses
        subnet_target_count += count
        if args.scan:
            if subnet_target_count > args.max_hosts:
                print(C.err(
                    f"  ✗ {', '.join(subnets)} expands to {subnet_target_count:,}+ targets, exceeding "
                    f"--max-hosts {args.max_hosts:,}. Use a smaller CIDR or raise the limit deliberately."
                ), file=sys.stderr)
                if net.version == 6:
                    print(f"  {C.YELLOW}IPv6 networks are too large to sweep. To find hosts on your local "
                          f"link use: pingme --discover6{C.RESET}", file=sys.stderr)
                return EXIT_USAGE
            addresses = [str(host) for host in (net.hosts() if net.version == 4 else iter(net))]
            ip_list.extend(addresses)
            subnet_ips.update(addresses)
    if subnets and not label:
        label = "+".join(re.sub(r"[/]", "_", cidr) for cidr in subnets)

    if target_file:
        file_targets, file_mappings = read_target_file(
            target_file, hostnames_out or "hostnames.txt", args.quiet, progress=rich_output,
            column=args.column, only_tags={tag.lower().lstrip("@") for tag in args.tag} if args.tag else None,
        )
        # Always show the original hostname-to-IP mapping before scanning.
        if rich_output:
            show_host_resolution(file_mappings, target_file)
        ip_list.extend(file_targets)
        if not label:
            label = _file_label(target_file)
            _LEGACY_LABELS[label] = Path(target_file).stem
            if args.tag or args.column:
                # A filtered view needs its own baseline, or every skipped line looks "removed".
                label += "-" + _safe_label("+".join(sorted(args.tag or [])) + (f"@{args.column}" if args.column else ""))

    neighbor_rows: list[dict] = []
    if args.discover6 is not None:
        interfaces = args.discover6 or ipv6_interfaces()
        unknown = [name for name in args.discover6 if not interface_exists(name)]
        if unknown:
            available = ", ".join(ipv6_interfaces()) or "none found"
            parser.error(f"unknown interface: {', '.join(unknown)} (IPv6 interfaces: {available})")
        if not interfaces:
            print(C.err("  ✗ No active IPv6 interfaces found for --discover6."), file=sys.stderr)
            return EXIT_ENVIRONMENT
        if not args.quiet:
            shown = ", ".join(interfaces[:8]) + (f" (+{len(interfaces) - 8} more)" if len(interfaces) > 8 else "")
            print(f"  {C.CYAN}Discovering IPv6 neighbors on {shown}...{C.RESET}", flush=True)
        neighbors = discover_ipv6_neighbors(interfaces, min(args.timeout or 2, 2))
        for address, mac in neighbors.items():
            neighbor_rows.append({"host": mac or "-", "ip": address, "type": "IPv6 ND"})
        ip_list.extend(neighbors)
        subnet_ips.update(neighbors)
        if not label:
            label = "ipv6-lan-" + ("+".join(args.discover6) if args.discover6 else "all")
        if not neighbors and not args.quiet:
            print(f"  {C.YELLOW}No IPv6 neighbors answered on {', '.join(interfaces)}.{C.RESET} "
                  f"{C.DIM}Many hosts ignore multicast ping; known addresses can be scanned directly.{C.RESET}")

    if hosts:
        host_targets, host_rows = resolve_host_arguments(hosts, args.quiet)
        ip_list.extend(host_targets)
        if not label:
            label = re.sub(r"[^\w.\-]", "_", "_".join(hosts))

    ip_list = list(dict.fromkeys(ip_list))
    label = label or "scan"

    if args.family:
        before = len(ip_list)
        ip_list = [ip for ip in ip_list if address_family(ip) == args.family]
        kept = set(ip_list)
        for row in file_mappings + host_rows:
            if row.get("ip") not in {"", "UNRESOLVED"} and row["ip"] not in kept:
                row["excluded"] = True
        if before != len(ip_list) and rich_output:
            print(f"  {C.DIM}[-{args.family}] Skipped {before - len(ip_list)} IPv{10 - args.family} address(es){C.RESET}")

    unsafe_targets = [ip for ip in ip_list if _normalise_probe_address(ip) is None]
    if unsafe_targets:
        if not args.quiet:
            print(C.warn(
                f"  ⚠  Skipped {len(unsafe_targets)} non-host destination(s) "
                "(unspecified, multicast, or limited broadcast)."
            ))
        ip_list = [ip for ip in ip_list if _normalise_probe_address(ip) is not None]

    # ── apply --exclude ─────────────────────────────────────────
    if args.exclude:
        excluded_ips, excluded_nets = build_exclude_filter(args.exclude)
        before = len(ip_list)
        ip_list = [ip for ip in ip_list if not is_excluded(ip, excluded_ips, excluded_nets)]
        remaining_ips = set(ip_list)
        for row in file_mappings + host_rows:
            row_ip = str(row.get("ip", ""))
            if row_ip not in {"", "UNRESOLVED"} and row_ip not in remaining_ips:
                row["excluded"] = True
        skipped = before - len(ip_list)
        if skipped and rich_output:
            print(f"  {C.DIM}[exclude] Skipped {skipped} IPs{C.RESET}")

    if not args.scan:
        print(f"  {C.DIM}Tip: add {C.BOLD}--scan{C.RESET}{C.DIM} (or run 'pingme {subnets[0]}') "
              f"to ping all {subnet_target_count:,} hosts.{C.RESET}\n")
        return EXIT_OK

    if not ip_list:
        if args.discover6 is not None and not subnets and not hosts and not target_file:
            return EXIT_NOT_ALL_UP
        reason = f"the -{args.family} filter" if args.family else "exclusions"
        print(C.err(f"  ✗ No scan targets remain after {reason}."), file=sys.stderr)
        return EXIT_USAGE

    # ── scan ────────────────────────────────────────────────────
    if not args.tcp_ports or _FPING_PATH or _PING_PATH or _PING6_PATH:
        check_deps(
            ping_tool="auto" if args.ping_tool == "ask" else args.ping_tool,
            verbose=rich_output,
            interactive=args.ping_tool == "ask",
        )

    if args.fast:
        args.threads = 100; args.timeout = 1; args.count = 1
        if rich_output:
            print(f"  {C.YELLOW}⚡ Fast mode — less accurate on slow/busy hosts.{C.RESET}")

    do_dns = args.dns if args.dns is not None else len(ip_list) <= DNS_AUTO_LIMIT
    if rich_output and args.dns is None and not do_dns:
        print(f"  {C.DIM}Hostname lookups skipped for {len(ip_list):,} targets; add --dns to force them.{C.RESET}")

    scan_kwargs = dict(
        threads = args.threads,
        timeout = args.timeout,
        count   = args.count,
        retry   = args.retry,
        rate    = args.rate,
        do_dns  = do_dns,
        tcp_ports = args.tcp_ports,
        tcp_timeout = args.tcp_timeout,
        min_replies = args.min_replies,
        neighbors = NeighborEvidence(use_as_evidence=args.arp),
    )
    status_rows = file_mappings + host_rows
    if args.serve:
        names = {str(row["ip"]): str(row["host"]) for row in status_rows if row.get("ip") != row.get("host")}
        return serve_scans(
            args.serve, args.watch or 60,
            lambda: run_scan(ip_list, label=label, quiet=True, resumable=False, **scan_kwargs),
            names, status_rows, f"PingMe · {target_file or ', '.join(subnets + hosts) or 'scan'}",
        )

    started_at = time.time()
    previous_scan = (load_history(label) or [None])[-1]
    results = run_scan(ip_list, label=label, quiet=not rich_output, resume=args.resume, **scan_kwargs)
    interrupted = _STOP_EVENT.is_set()
    blanket = downgrade_blanket_tcp(results) if args.tcp_ports else 0
    if blanket and not args.quiet:
        print(C.warn(f"  ⚠  {blanket} addresses accepted TCP but never answered ping or ARP — nearly every "
                     "address did, which points to a proxy or firewall answering for all of them. "
                     "They are reported as PROBE ERROR, not REACHABLE."))

    alive = [r["ip"] for r in results if r["alive"]]
    dead  = [r["ip"] for r in results if r.get("status") == "NO RESPONSE"]
    errors = [r["ip"] for r in results if r.get("status") == "PROBE ERROR"]

    change_groups: Optional[dict[str, list[dict]]] = None
    if status_rows:
        source = target_file or "command line"
        title = "FILE SCAN STATUS" if target_file else "SCAN STATUS"
        if rich_output:
            status_records = show_file_scan_status(status_rows, results, source, title)
        else:
            status_records = build_file_status_records(status_rows, results)
        if hostnames_out:
            write_hostnames_report(status_records, source, hostnames_out, announce=rich_output)

        if args.changes and not interrupted:
            previous_changes = load_changes_state(label)
            change_groups = write_changes_report(
                previous_changes, status_records, target_file, args.changes_out,
                display="none" if args.quiet else ("full" if rich_output else "summary"),
            )
            save_changes_state(label, target_file, status_records)
    if neighbor_rows and rich_output:
        show_file_scan_status(neighbor_rows, results, "local links", "IPv6 NEIGHBORS", host_header="MAC ADDRESS")
    subnet_only = subnet_ips - {row["ip"] for row in neighbor_rows}
    if subnet_only and rich_output:
        live = _live_rows([r for r in results if r["ip"] in subnet_only])
        if live:
            show_file_scan_status(live, results, ", ".join(subnets), "LIVE HOSTS", hide_host=True)
        elif not interrupted:
            print(f"\n  {C.YELLOW}No hosts answered in {', '.join(subnets)}.{C.RESET} "
                  f"{C.DIM}Hosts that block ping can be found with --tcp-ports 22,80,443,445,3389.{C.RESET}\n")

    write_results(
        results,
        alive_file=args.alive_out,
        dead_file=args.dead_out,
        error_file=args.error_out,
        out_format=args.out_format,
        quiet=args.quiet,
        verbose=rich_output,
    )

    if args.trace_down and not interrupted:
        trace_down_hosts(results, quiet=args.quiet)

    if args.wake and not interrupted:
        down = {r["ip"] for r in results if not r["alive"]}
        macs = known_macs(label, down)
        if macs:
            try:
                send_wake_on_lan(list(macs.values()), args.wol_broadcast)
                if not args.quiet:
                    print(C.ok(f"  ✔  Wake-on-LAN sent to {len(macs)} down host(s): "
                               + ", ".join(f"{ip} ({mac})" for ip, mac in macs.items())))
            except OSError as exc:
                print(C.warn(f"  ⚠  Wake-on-LAN failed: {exc}"), file=sys.stderr)
        elif down and not args.quiet:
            print(C.warn("  ⚠  --wake: no MAC address is known for the down hosts yet "
                         "(PingMe learns MACs from earlier scans on the same LAN)."))

    if args.nmap_xml:
        destination = write_nmap_xml(results, args.nmap_xml, " ".join(["pingme", *argv]), started_at)
        if rich_output:
            print(f"  {C.CYAN}[report] nmap XML → {destination}{C.RESET}")

    if not args.no_history and not interrupted:
        save_scan(label, results, announce=rich_output, keep=args.keep)

    if args.uptime is not None and not interrupted:
        show_uptime(label)

    if args.html:
        records = records_for_results(results, status_rows)
        uptime_rows = compute_uptime(load_history(label)) if not args.no_history else None
        meta = (f"{datetime.now().strftime('%Y-%m-%d %H:%M')} · engine {_PING_TOOL} · "
                f"{len(results)} addresses · {time.time() - started_at:.1f} s")
        destination = write_html_report(args.html, f"PingMe · {target_file or ', '.join(subnets + hosts) or label}",
                                        records, uptime_rows, meta)
        if not args.quiet:
            print(f"  {C.CYAN}[report] HTML → {destination}{C.RESET}")

    if args.notify and not interrupted:
        events = scan_events(args.notify_on, results, status_rows, change_groups, previous_scan)
        notify_all(args.notify, f"PingMe · {target_file or ', '.join(subnets + hosts) or label}", events, args.quiet)

    if args.compare:
        compare_history(label, alive, dead, errors, saved_current=not args.no_history and not interrupted)

    if interrupted:
        return EXIT_INTERRUPTED

    if args.watch:
        watch_scans(args, ip_list, label, scan_kwargs, results, status_rows)

    if rich_output:
        print()

    if args.exit_zero:
        return EXIT_OK
    monitored = {str(row["ip"]) for row in status_rows if not row.get("excluded")} - {"UNRESOLVED"}
    unresolved = sum(1 for row in status_rows if row.get("ip") == "UNRESOLVED")
    return scan_exit_code(results, monitored, unresolved)


def _terminate(_signum, _frame) -> None:
    """Treat SIGTERM (systemd, Docker, kill) like Ctrl+C so watch/serve shut down cleanly."""
    raise KeyboardInterrupt


def entrypoint() -> None:
    """Console entry point: maps interrupts and closed pipes to clean exits."""
    try:
        signal.signal(signal.SIGTERM, _terminate)
    except (ValueError, OSError, AttributeError):
        pass
    try:
        code = main()
    except KeyboardInterrupt:
        print(f"\n  {C.YELLOW}Interrupted.{C.RESET}", file=sys.stderr)
        code = EXIT_INTERRUPTED
    except BrokenPipeError:
        # Output piped into head/less that exited early; not an error.
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except OSError:
            pass
        code = EXIT_OK
    sys.exit(code)


if __name__ == "__main__":
    entrypoint()
