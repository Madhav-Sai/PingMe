#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║              PingMe — Advanced Ping Scanner v2.0               ║
║        Subnet Info · Ping Scan · File Scan · History Diff        ║
╚══════════════════════════════════════════════════════════════════╝
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
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

    # Foreground
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

    # Background
    BG_RED   = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_BLUE  = "\033[44m"
    BG_DARK  = "\033[40m"

    @staticmethod
    def b(text): return f"{C.BOLD}{text}{C.RESET}"
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
HISTORY_DIR = Path(os.getcwd()) / "data"


def history_file(label: str) -> Path:
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.\-]", "_", label)
    return HISTORY_DIR / f"{safe}.json"


def save_scan(label: str, alive: list[str], dead: list[str]):
    data = {
        "label":     label,
        "timestamp": datetime.now().isoformat(),
        "alive":     sorted(alive),
        "dead":      sorted(dead),
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
# IP CLASSIFIER  (public / private / special)
# ─────────────────────────────────────────────────────────────────
def ip_classify(ip_str: str) -> dict:
    """
    Returns a dict with:
      scope      : "Private" | "Public" | "Loopback" | "Link-Local" |
                   "Multicast" | "Reserved" | "Documentation"
      color      : ANSI color for scope
      rfc        : RFC that defines this range (if private/special)
      description: human-readable note
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return {"scope": "Invalid", "color": C.RED, "rfc": "", "description": "Not a valid IP"}

    if ip.is_loopback:
        return {"scope": "Loopback",    "color": C.DIM,    "rfc": "RFC 5735", "description": "Loopback address (127.0.0.0/8)"}
    if ip.is_link_local:
        return {"scope": "Link-Local",  "color": C.YELLOW, "rfc": "RFC 3927", "description": "Link-local (169.254.0.0/16) — APIPA"}
    if ip.is_multicast:
        return {"scope": "Multicast",   "color": C.ORANGE, "rfc": "RFC 5771", "description": "Multicast range (224.0.0.0/4)"}
    if ip.is_reserved:
        return {"scope": "Reserved",    "color": C.PURPLE, "rfc": "RFC 1112", "description": "Reserved / future use"}

    # Documentation ranges
    doc_ranges = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    ]
    for doc in doc_ranges:
        if ip in doc:
            return {"scope": "Documentation", "color": C.DIM, "rfc": "RFC 5737", "description": f"Documentation/example range ({doc})"}

    # CGNAT / shared address space — Python's is_private misses this
    if ip in ipaddress.ip_network("100.64.0.0/10"):
        return {"scope": "Private", "color": C.CYAN, "rfc": "RFC 6598", "description": "Shared address space / CGNAT (100.64.0.0/10)"}

    if ip.is_private:
        # Narrow down which RFC 1918 range
        privates = [
            (ipaddress.ip_network("10.0.0.0/8"),    "RFC 1918", "Class A private (10.0.0.0/8)"),
            (ipaddress.ip_network("172.16.0.0/12"), "RFC 1918", "Class B private (172.16.0.0/12)"),
            (ipaddress.ip_network("192.168.0.0/16"),"RFC 1918", "Class C private (192.168.0.0/16)"),
        ]
        for net, rfc, desc in privates:
            if ip in net:
                return {"scope": "Private", "color": C.CYAN, "rfc": rfc, "description": desc}
        return {"scope": "Private", "color": C.CYAN, "rfc": "RFC 1918", "description": "Private address"}

    # Everything else is public
    return {"scope": "Public", "color": C.LIME, "rfc": "IANA", "description": "Publicly routable address"}


def show_ipinfo(targets: list[str]):
    """Pretty-print public/private classification for a list of IPs."""
    LABEL_W = 18
    VALUE_W = 32
    BW      = LABEL_W + VALUE_W + 3

    def _border(l, r):
        return f"  {C.MAGENTA}{C.BOLD}{l}{'─' * BW}{r}{C.RESET}"

    def row(label, value, vcol=C.WHITE):
        val_str = str(value)[:VALUE_W]
        return (
            f"  {C.MAGENTA}{C.BOLD}│{C.RESET}"
            f" {C.CYAN}{C.BOLD}{label:<{LABEL_W}}{C.RESET}"
            f" {vcol}{val_str:<{VALUE_W}}{C.RESET}"
            f"{C.MAGENTA}{C.BOLD}│{C.RESET}"
        )

    print(f"\n  {C.BOLD}{C.MAGENTA}┌{'─' * BW}┐")
    print(f"  │{'  🔍  IP CLASSIFICATION':^{BW}}│")
    print(f"  └{'─' * BW}┘{C.RESET}")

    for ip_str in targets:
        info = ip_classify(ip_str)
        scope = info["scope"]
        col   = info["color"]
        print(_border("├", "┤"))
        print(row("IP Address",   ip_str,           C.WHITE))
        print(row("Scope",        scope,             col + C.BOLD))
        print(row("RFC / Auth",   info["rfc"],       C.DIM + C.WHITE))
        print(row("Description",  info["description"], C.WHITE))

    print(_border("└", "┘"))
    print()

# ─────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────
def banner():
    ts = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    lines = [
        f"{C.TEAL}{C.BOLD}",
        "  ██████╗ ██╗███╗   ██╗ ██████╗ ███╗   ███╗███████╗",
        "  ██╔══██╗██║████╗  ██║██╔════╝ ████╗ ████║██╔════╝",
        "  ██████╔╝██║██╔██╗ ██║██║  ███╗██╔████╔██║█████╗  ",
        "  ██╔═══╝ ██║██║╚██╗██║██║   ██║██║╚██╔╝██║██╔══╝  ",
        "  ██║     ██║██║ ╚████║╚██████╔╝██║ ╚═╝ ██║███████╗",
        "  ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝",
        f"{C.RESET}",
        f"  {C.PURPLE}Advanced Ping Scanner v2.0{C.RESET}  {C.DIM}│{C.RESET}  {C.DIM}{ts}{C.RESET}",
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

    hosts  = list(net.hosts())
    total  = len(hosts)
    prefix = net.prefixlen

    # Box geometry — all measurements in visible characters (no ANSI)
    LABEL_W = 24   # left column
    VALUE_W = 26   # right column
    IW      = LABEL_W + VALUE_W + 3   # 1 space left pad + label + 1 sep + value + 1 right pad = 55
    BW      = IW   # border inner span (between ┌ and ┐)

    def _border(l, m, r):
        return f"  {C.MAGENTA}{C.BOLD}{l}{'─' * BW}{r}{C.RESET}"

    top = _border("┌", "", "┐")
    bot = _border("└", "", "┘")
    sep = _border("├", "", "┤")

    def hdr(title):
        # title contains an emoji (2 cols wide) — compensate with -1
        vis_len = len(title) + 1          # emoji adds 1 extra visual col
        pad     = BW - vis_len - 2        # 2 for the leading spaces
        return (
            f"  {C.MAGENTA}{C.BOLD}│{C.RESET}"
            f"  {C.BOLD}{C.WHITE}{title}{' ' * max(pad, 0)}{C.RESET}"
            f"{C.MAGENTA}{C.BOLD}│{C.RESET}"
        )

    def row(label, value, vcol=C.WHITE):
        val_str = str(value)[:VALUE_W]    # hard-cap so box never overflows
        content = (
            f" {C.CYAN}{C.BOLD}{label:<{LABEL_W}}{C.RESET}"
            f" {vcol}{val_str:<{VALUE_W}}{C.RESET}"
        )
        return (
            f"  {C.MAGENTA}{C.BOLD}│{C.RESET}"
            f"{content}"
            f"{C.MAGENTA}{C.BOLD}│{C.RESET}"
        )

    # ── main info box ──────────────────────────────────────────
    print()
    print(top)
    print(hdr("🌐  SUBNET INFORMATION"))
    print(sep)
    print(row("CIDR",              cidr,                        C.LIME))
    print(row("Network Address",   str(net.network_address),    C.YELLOW))
    print(row("Broadcast Address", str(net.broadcast_address),  C.YELLOW))
    print(row("Subnet Mask",       str(net.netmask),            C.WHITE))
    print(row("Wildcard Mask",     str(net.hostmask),           C.WHITE))
    print(row("Prefix Length",     f"/{prefix}",                C.ORANGE))
    print(row("IP Version",        f"IPv{net.version}",         C.CYAN))
    if total > 0:
        print(sep)
        print(row("First Host",    str(hosts[0]),               C.GREEN))
        print(row("Last Host",     str(hosts[-1]),              C.GREEN))
        print(row("Total Usable IPs", f"{total:,}",             C.BOLD + C.LIME))
    print(bot)

    # ── prefix usage bar ──────────────────────────────────────
    bar_w = 32
    pct   = (total / (2 ** (32 - prefix))) * 100 if prefix < 32 else 100
    fill  = prefix
    bar   = f"{C.TEAL}{'█' * fill}{C.DIM}{'░' * (bar_w - fill)}{C.RESET}"
    print(f"\n  {C.DIM}Prefix /{prefix} usage:{C.RESET}  {bar}  {C.DIM}({pct:.1f}% host space){C.RESET}")

    # ── subnet breakdown ──────────────────────────────────────
    print(f"\n  {C.BOLD}{C.MAGENTA}┌{'─' * BW}┐{C.RESET}")
    print(hdr("📐  SUBNET BREAKDOWN"))
    print(f"  {C.MAGENTA}{C.BOLD}├{'─' * BW}┤{C.RESET}")

    # How many of common subnet sizes fit inside this network
    breakdown_sizes = [24, 25, 26, 27, 28, 29, 30]
    for sub_prefix in breakdown_sizes:
        if sub_prefix <= prefix:
            continue
        count      = 2 ** (sub_prefix - prefix)
        hosts_each = max(2 ** (32 - sub_prefix) - 2, 0)
        label      = f"/{sub_prefix} subnets"
        val        = f"{count:>5,}  ×  {hosts_each} hosts each"
        print(row(label, val, C.WHITE))

    # Summary line
    print(f"  {C.MAGENTA}{C.BOLD}├{'─' * BW}┤{C.RESET}")
    class_label = (
        "Class A (/8)"  if prefix <= 8  else
        "Class B (/16)" if prefix <= 16 else
        "Class C (/24)" if prefix <= 24 else
        "Subnetted"
    )
    private = net.is_private
    scope   = f"{'Private' if private else 'Public'} · {class_label}"
    print(row("Address Scope", scope, C.PINK))
    total_ips_incl = 2 ** (32 - prefix)
    print(row("Total IPs (incl. net+bc)", f"{total_ips_incl:,}", C.DIM + C.WHITE))
    print(f"  {C.MAGENTA}{C.BOLD}└{'─' * BW}┘{C.RESET}")
    print()

    return net


# ─────────────────────────────────────────────────────────────────
# SINGLE-IP PING  (pure Python, cross-platform)
# ─────────────────────────────────────────────────────────────────
def _ping_one(ip: str, timeout: int = 2, count: int = 3) -> tuple[str, bool]:
    """
    Ping an IP sending `count` packets with `timeout` seconds each.
    Returns (ip, is_alive).  A host is ALIVE if at least 1 of `count`
    packets gets a reply — prevents false-dead from a single dropped packet.
    Uses fping if available, otherwise falls back to OS ping.
    """
    if shutil.which("fping"):
        try:
            r = subprocess.run(
                ["fping", "-c", str(count), "-t", str(timeout * 1000), "-q", ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=(timeout * count) + 2,
            )
            return ip, r.returncode == 0
        except Exception:
            pass

    # Fallback: OS ping
    if sys.platform == "win32":
        cmd          = ["ping", "-n", str(count), "-w", str(timeout * 1000), ip]
        proc_timeout = (timeout * count) + 3
    else:
        # -i 0.5  →  0.5 s between packets (avoids flooding the network)
        # -W      →  per-reply wait in seconds
        cmd          = ["ping", "-c", str(count), "-W", str(timeout), "-i", "0.5", ip]
        proc_timeout = (timeout * count) + (0.5 * count) + 2

    try:
        r = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=proc_timeout,
        )
        return ip, r.returncode == 0
    except subprocess.TimeoutExpired:
        return ip, False
    except Exception:
        return ip, False


# ─────────────────────────────────────────────────────────────────
# PROGRESS BAR
# ─────────────────────────────────────────────────────────────────
def _progress_bar(done: int, total: int, alive: int, dead: int, width: int = 40):
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
    ip_list: list[str],
    threads: int = 20,
    timeout: int = 6,
    count:   int = 8,
    label: str = "scan",
    quiet: bool = False,
) -> tuple[str, str]:

    alive_list: list[str] = []
    dead_list:  list[str] = []
    total   = len(ip_list)
    done    = 0
    t_start = time.time()

    # Estimate time so user knows what to expect
    est_sec = (total / threads) * (timeout * count + 0.5 * count)
    print(
        f"\n  {C.CYAN}⠿ Scanning {C.BOLD}{total:,}{C.RESET}{C.CYAN} hosts"
        f"  │  threads={C.BOLD}{threads}{C.RESET}{C.CYAN}"
        f"  timeout={timeout}s  packets/host={count}"
        f"  est≈{est_sec:.0f}s{C.RESET}\n"
    )

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_ping_one, ip, timeout, count): ip for ip in ip_list}
        for fut in as_completed(futures):
            ip, alive = fut.result()
            done += 1
            if alive:
                alive_list.append(ip)
                if not quiet:
                    info  = ip_classify(ip)
                    scope = f"[{info['scope']}]"
                    scol  = info["color"]
                    sys.stdout.write(
                        f"\r  {C.GREEN}✔ {ip:<18}{C.RESET}  "
                        f"{scol}{scope:<14}{C.RESET}\n"
                    )
            else:
                dead_list.append(ip)
            _progress_bar(done, total, len(alive_list), len(dead_list))

    elapsed = time.time() - t_start
    print(f"\n\n  {C.DIM}Scan finished in {elapsed:.1f}s{C.RESET}\n")

    # Sort results
    def ip_sort(lst):
        try:
            return sorted(lst, key=lambda x: ipaddress.ip_address(x))
        except Exception:
            return sorted(lst)

    alive_list = ip_sort(alive_list)
    dead_list  = ip_sort(dead_list)

    return alive_list, dead_list


# ─────────────────────────────────────────────────────────────────
# WRITE OUTPUT FILES
# ─────────────────────────────────────────────────────────────────
def write_results(
    alive: list[str],
    dead:  list[str],
    alive_file: str = "alive.txt",
    dead_file:  str = "dead.txt",
):
    Path(alive_file).write_text("\n".join(alive) + ("\n" if alive else ""))
    Path(dead_file).write_text("\n".join(dead)  + ("\n" if dead  else ""))

    total = len(alive) + len(dead)
    pct_a = (len(alive) / total * 100) if total else 0
    pct_d = (len(dead)  / total * 100) if total else 0

    box_w = 56
    div   = f"  {C.CYAN}{'─' * box_w}{C.RESET}"
    print(f"\n  {C.BOLD}{C.LIME}┌{'─' * (box_w + 2)}┐")
    print(f"  │{'  📊  SCAN RESULTS':^{box_w + 2}}│")
    print(f"  └{'─' * (box_w + 2)}┘{C.RESET}")
    print(div)
    print(f"  {C.DIM}│{C.RESET}  {'Total scanned':<26}{C.BOLD}{C.WHITE}{total:>6}{C.RESET}")
    print(f"  {C.DIM}│{C.RESET}  {C.GREEN}{'Alive (reachable)':<26}{C.BOLD}{len(alive):>6}{C.RESET}  {C.DIM}({pct_a:.1f}%){C.RESET}")
    print(f"  {C.DIM}│{C.RESET}  {C.RED}{'Dead (no response)':<26}{C.BOLD}{len(dead):>6}{C.RESET}  {C.DIM}({pct_d:.1f}%){C.RESET}")
    print(div)
    print(f"  {C.DIM}│{C.RESET}  {C.CYAN}alive.txt  →  {alive_file}{C.RESET}")
    print(f"  {C.DIM}│{C.RESET}  {C.CYAN}dead.txt   →  {dead_file}{C.RESET}")
    print(div)

    # Sparkline-style alive bar
    if total:
        bar_w = 40
        n = int(pct_a / 100 * bar_w)
        bar = f"{C.GREEN}{'█' * n}{C.RED}{'█' * (bar_w - n)}{C.RESET}"
        print(f"\n  Alive/Dead ratio:  {bar}  {C.GREEN}{pct_a:.0f}%{C.RESET} alive\n")


# ─────────────────────────────────────────────────────────────────
# HISTORY COMPARISON
# ─────────────────────────────────────────────────────────────────
def compare_history(label: str, current_alive: list[str], current_dead: list[str]):
    history = load_history(label)
    if len(history) < 2:
        print(f"\n  {C.WARN if False else C.warn('⚠  Not enough history for comparison (need ≥ 2 scans).')}")
        return

    # Compare current scan vs the previous one
    prev = history[-2]   # second-to-last (last is the one we just saved)
    prev_alive = set(prev.get("alive", []))
    prev_dead  = set(prev.get("dead",  []))
    curr_alive = set(current_alive)
    curr_dead  = set(current_dead)
    prev_ts    = prev.get("timestamp", "unknown")

    newly_up   = sorted(curr_alive - prev_alive)   # was dead/unknown, now alive
    newly_down = sorted(prev_alive - curr_alive)   # was alive, now dead
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
        print(f"\n  {C.GREEN}{C.BOLD}⬆  Hosts that came ONLINE since last scan:{C.RESET}")
        for ip in newly_up:
            print(f"     {C.GREEN}+ {ip}{C.RESET}")

    if newly_down:
        print(f"\n  {C.RED}{C.BOLD}⬇  Hosts that went OFFLINE since last scan:{C.RESET}")
        for ip in newly_down:
            print(f"     {C.RED}✘ {ip}{C.RESET}")

    if not newly_up and not newly_down:
        print(f"\n  {C.LIME}  No changes since last scan — all hosts in same state.{C.RESET}")

    # Full history trend (all scans for this label)
    if len(history) >= 2:
        print(f"\n  {C.BOLD}{C.CYAN}Full Scan History — Alive Counts:{C.RESET}")
        max_alive = max(len(s.get("alive", [])) for s in history) or 1
        for i, s in enumerate(history, 1):
            cnt   = len(s.get("alive", []))
            ts_s  = s.get("timestamp", "?")[:16]
            bar_w = 30
            n     = int(cnt / max_alive * bar_w)
            bar   = f"{C.GREEN}{'█' * n}{C.DIM}{'░' * (bar_w - n)}{C.RESET}"
            marker = "◀ current" if i == len(history) else ""
            print(f"  {C.DIM}#{i:02d}{C.RESET}  {C.DIM}{ts_s}{C.RESET}  {bar}  {C.BOLD}{cnt:>4}{C.RESET}  {C.YELLOW}{marker}{C.RESET}")

    print()


# ─────────────────────────────────────────────────────────────────
# DIFF TWO FILES (standalone mode)
# ─────────────────────────────────────────────────────────────────
def diff_files(file_a: str, file_b: str):
    """Compare two alive.txt snapshots directly."""
    def read_ips(path: str) -> set[str]:
        p = Path(path)
        if not p.exists():
            print(C.err(f"  ✗ File not found: {path}"))
            sys.exit(1)
        lines = {l.strip() for l in p.read_text().splitlines() if l.strip()}
        return lines

    ips_a = read_ips(file_a)
    ips_b = read_ips(file_b)

    only_in_a = sorted(ips_a - ips_b)
    only_in_b = sorted(ips_b - ips_a)
    common    = sorted(ips_a & ips_b)

    box_w = 60
    div   = f"  {C.PURPLE}{'─' * box_w}{C.RESET}"
    print(f"\n  {C.BOLD}{C.PURPLE}┌{'─' * (box_w + 2)}┐")
    print(f"  │{'  📂  FILE DIFF COMPARISON':^{box_w + 2}}│")
    print(f"  └{'─' * (box_w + 2)}┘{C.RESET}")
    print(div)
    print(f"  {C.DIM}File A: {file_a}  ({len(ips_a)} IPs){C.RESET}")
    print(f"  {C.DIM}File B: {file_b}  ({len(ips_b)} IPs){C.RESET}")
    print(div)
    print(f"  {C.LIME}  In A only (maybe went offline) : {len(only_in_a)}")
    print(f"  {C.GREEN}  In B only (came online)        : {len(only_in_b)}{C.RESET}")
    print(f"  {C.DIM}  In both                         : {len(common)}{C.RESET}")
    print(div)

    if only_in_a:
        print(f"\n  {C.RED}{C.BOLD}✘  Only in {file_a} (LOST since then):{C.RESET}")
        for ip in only_in_a:
            print(f"     {C.RED}- {ip}{C.RESET}")

    if only_in_b:
        print(f"\n  {C.GREEN}{C.BOLD}+  Only in {file_b} (GAINED since then):{C.RESET}")
        for ip in only_in_b:
            print(f"     {C.GREEN}+ {ip}{C.RESET}")

    if not only_in_a and not only_in_b:
        print(f"\n  {C.LIME}  Both files contain identical IPs — no change.{C.RESET}")
    print()


# ─────────────────────────────────────────────────────────────────
# READ IP FILE
# ─────────────────────────────────────────────────────────────────
def read_ip_file(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        print(C.err(f"  ✗ File not found: {path}"))
        sys.exit(1)
    ips = []
    bad = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ipaddress.ip_address(line)
            ips.append(line)
        except ValueError:
            bad.append(line)
    if bad:
        print(f"  {C.YELLOW}⚠  Skipped {len(bad)} invalid entries in {path}{C.RESET}")
    if not ips:
        print(C.err(f"  ✗ No valid IPs found in {path}"))
        sys.exit(1)
    print(f"  {C.CYAN}Loaded {C.BOLD}{len(ips)}{C.RESET}{C.CYAN} IPs from {path}{C.RESET}")
    return ips


# ─────────────────────────────────────────────────────────────────
# CHECK DEPENDENCIES
# ─────────────────────────────────────────────────────────────────
def check_deps():
    has_fping = shutil.which("fping") is not None
    has_ping  = shutil.which("ping")  is not None

    print(f"\n  {C.CYAN}[deps]{C.RESET}", end="  ")
    if has_fping:
        print(f"{C.GREEN}fping ✔{C.RESET}", end="  ")
    else:
        print(f"{C.YELLOW}fping ✘ (using system ping — slower){C.RESET}", end="  ")
    if has_ping:
        print(f"{C.GREEN}ping ✔{C.RESET}")
    else:
        print(f"{C.RED}ping ✘{C.RESET}")
        if not has_fping:
            print(C.err("  ✗ Neither fping nor ping found. Install one to continue."))
            sys.exit(3)


# ─────────────────────────────────────────────────────────────────
# SHOW HISTORY LIST
# ─────────────────────────────────────────────────────────────────
def show_history_list():
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    files = sorted(HISTORY_DIR.glob("*.json"))
    if not files:
        print(f"  {C.YELLOW}No scan history found.{C.RESET}\n")
        return
    box_w = 70
    div   = f"  {C.CYAN}{'─' * box_w}{C.RESET}"
    print(f"\n  {C.BOLD}{C.CYAN}Stored Scan History:{C.RESET}")
    print(div)
    for f in files:
        try:
            data = json.loads(f.read_text())
            n    = len(data)
            label = f.stem
            last = data[-1] if data else {}
            ts   = last.get("timestamp", "?")[:16]
            alive = len(last.get("alive", []))
            print(f"  {C.LIME}{label:<30}{C.RESET}  {C.DIM}{n} scans  last: {ts}  alive: {alive}{C.RESET}")
        except Exception:
            print(f"  {C.RED}{f.stem}  (corrupt){C.RESET}")
    print(div + "\n")


# ─────────────────────────────────────────────────────────────────
# ARG PARSER
# ─────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pingme",
        description="PingMe — Advanced Ping Scanner with History",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
    )

    # Modes
    mg = p.add_argument_group(f"{C.BOLD}Modes{C.RESET}")
    mg.add_argument("-s", "--sub",   metavar="CIDR",
                    help="Show subnet info (and optionally scan)")
    mg.add_argument("-f", "--file",  metavar="FILE",
                    help="Load IPs from a file (one per line)")
    mg.add_argument("--diff",        metavar=("FILE_A", "FILE_B"), nargs=2,
                    help="Compare two alive.txt snapshots")
    mg.add_argument("--history",     action="store_true",
                    help="List all stored scan history")
    mg.add_argument("--ipinfo",       metavar="IP", nargs="+",
                    help="Classify one or more IPs as Public/Private/Special")

    # Scan options
    sg = p.add_argument_group(f"{C.BOLD}Scan Options{C.RESET}")
    sg.add_argument("--scan",        action="store_true",
                    help="Run ping scan (required with --sub or --file)")
    sg.add_argument("-t", "--threads", type=int, default=20, metavar="N",
                    help="Concurrent threads (default: 20 — accurate & non-flooding)")
    sg.add_argument("--timeout",     type=int, default=6, metavar="SEC",
                    help="Per-packet wait in seconds (default: 6)")
    sg.add_argument("--count",       type=int, default=8, metavar="N",
                    help="Packets per host — host alive if ≥1 reply (default: 8)")
    sg.add_argument("--fast",        action="store_true",
                    help="Fast mode: 100 threads, timeout=1s, count=1  (less accurate)")
    sg.add_argument("--no-history",  action="store_true",
                    help="Don't save this scan to history")
    sg.add_argument("--compare",     action="store_true",
                    help="Compare with previous scan of same target")
    sg.add_argument("--quiet",       action="store_true",
                    help="Suppress per-IP alive output during scan")

    # Output
    og = p.add_argument_group(f"{C.BOLD}Output{C.RESET}")
    og.add_argument("--alive-out",   default="alive.txt", metavar="FILE",
                    help="Output file for alive IPs (default: alive.txt)")
    og.add_argument("--dead-out",    default="dead.txt",  metavar="FILE",
                    help="Output file for dead IPs  (default: dead.txt)")
    og.add_argument("--label",       metavar="NAME",
                    help="Custom label for history (default: CIDR or filename)")

    og.add_argument("-h", "--help",  action="help",
                    help="Show this help message")

    return p


# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────
def main():
    # Disable color if not a TTY
    if not sys.stdout.isatty():
        for attr in dir(C):
            if not attr.startswith("_") and isinstance(getattr(C, attr), str):
                setattr(C, attr, "")

    banner()

    parser = build_parser()
    args   = parser.parse_args()

    # ── mode: list history ──────────────────────────────────────
    if args.history:
        show_history_list()
        return

    # ── mode: ip classify ──────────────────────────────────────
    if args.ipinfo:
        show_ipinfo(args.ipinfo)
        return

    # ── mode: diff two files ────────────────────────────────────
    if args.diff:
        diff_files(args.diff[0], args.diff[1])
        return

    # ── need at least --sub or --file ───────────────────────────
    if not args.sub and not args.file:
        parser.print_help()
        print(f"\n  {C.YELLOW}Tip: use --sub 192.168.1.0/24 or --file ips.txt{C.RESET}\n")
        sys.exit(0)

    # ── subnet info ─────────────────────────────────────────────
    net       = None
    ip_list   = []
    label     = args.label

    if args.sub:
        net     = show_subnet_info(args.sub)
        ip_list = [str(h) for h in net.hosts()]
        if not label:
            label = re.sub(r"[/]", "_", args.sub)

    # ── file mode ───────────────────────────────────────────────
    if args.file:
        file_ips = read_ip_file(args.file)
        ip_list  = file_ips if not ip_list else ip_list  # file overrides subnet if both given
        if not label:
            label = Path(args.file).stem

    # ── scan ────────────────────────────────────────────────────
    if args.scan or args.file:
        check_deps()

        # --fast overrides individual flags with speed-optimised values
        if args.fast:
            args.threads = 100
            args.timeout = 1
            args.count   = 1
            print(
                f"  {C.YELLOW}⚡ Fast mode: threads=100 timeout=1s count=1 — "
                f"may produce false-dead results on slow/busy hosts.{C.RESET}"
            )

        args.threads = max(1, min(1000, args.threads))
        args.timeout = max(1, min(10,   args.timeout))
        args.count   = max(1, min(5,    args.count))

        alive, dead = run_scan(
            ip_list,
            threads=args.threads,
            timeout=args.timeout,
            count=args.count,
            label=label,
            quiet=args.quiet,
        )

        write_results(alive, dead, args.alive_out, args.dead_out)

        # Save history
        if not args.no_history:
            save_scan(label, alive, dead)

        # Comparison
        if args.compare:
            compare_history(label, alive, dead)

    elif args.sub and not args.scan:
        # Just showed subnet info, no scan requested
        print(f"  {C.DIM}Tip: add {C.BOLD}--scan{C.RESET}{C.DIM} to ping all {len(ip_list):,} hosts.{C.RESET}\n")

    print()


if __name__ == "__main__":
    main()
