<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Share+Tech+Mono&size=52&duration=1800&pause=650&color=00F7FF&center=true&vCenter=true&width=760&height=100&lines=PINGME;PING+ME;P+I+N+G+M+E;PINGME+v3.3.0" alt="PingMe animated title" />

<img src="https://readme-typing-svg.demolab.com?font=Share+Tech+Mono&size=19&duration=2400&pause=700&color=BB86FC&center=true&vCenter=true&width=920&height=110&lines=Advanced+Network+Discovery+Scanner;Hostname+%E2%86%92+IP+%E2%86%92+Reachability+Status;hostnames.txt+%C2%B7+changes.txt+%C2%B7+alive.txt+%C2%B7+dead.txt;Linux+%C2%B7+Kali+%C2%B7+macOS+%C2%B7+Windows" alt="PingMe animated subtitle" />

<br/>

[![Version](https://img.shields.io/badge/version-3.3.0-00F7FF?style=for-the-badge&labelColor=0d1117)](#)
[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white&labelColor=0d1117)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-BB86FC?style=for-the-badge&labelColor=0d1117)](#)
[![License](https://img.shields.io/badge/License-MIT-39FF14?style=for-the-badge&labelColor=0d1117)](LICENSE)
[![Dependencies](https://img.shields.io/badge/Python%20Dependencies-Zero-FF4ECD?style=for-the-badge&labelColor=0d1117)](#)
[![fping](https://img.shields.io/badge/fping-Optional-FFD700?style=for-the-badge&labelColor=0d1117)](#)

<br/>

```text
  ██████╗ ██╗███╗   ██╗ ██████╗ ███╗   ███╗███████╗
  ██╔══██╗██║████╗  ██║██╔════╝ ████╗ ████║██╔════╝
  ██████╔╝██║██╔██╗ ██║██║  ███╗██╔████╔██║█████╗
  ██╔═══╝ ██║██║╚██╗██║██║   ██║██║╚██╔╝██║██╔══╝
  ██║     ██║██║ ╚████║╚██████╔╝██║ ╚═╝ ██║███████╗
  ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝

  Advanced Ping Scanner v3.3.0
  Hostname · IP Address · Reachability · RTT · Loss · TTL · OS Guess
```

</div>

---

## ⚡ What is PingMe?

**PingMe** is a fast, cross-platform host discovery and network reachability scanner written in pure Python.

It accepts:

- CIDR networks
- Individual IP addresses
- Hostnames
- Files containing IPs and hostnames
- IPv4 and IPv6 targets

PingMe resolves hostnames, scans every resolved address, looks up the hostname of every IP, displays live progress, saves scan history, and presents a final status table showing:

```text
HOST | IP ADDRESS | STATUS | METHOD | TTL | RTT ms | LOSS | OS GUESS | REVERSE DNS
```

For file-based scans, PingMe can also maintain five clear reports:

```text
hostnames.txt  → Complete hostname, IP, status, method, TTL, and OS report
changes.txt    → Newly online and went-offline changes
alive.txt      → IP addresses that are currently reachable
dead.txt       → IP addresses that are currently not responding
errors.txt     → IP addresses whose probe command failed (not treated as offline)
```

It is designed for network engineers, system administrators, VAPT teams, penetration testers, and anyone who needs a clear answer to:

> Which hosts resolved, which IP belongs to each hostname, and which systems are reachable?

### 🆕 What's new in 3.3

- **Built-in ICMP engine:** one socket instead of one `ping` process per host — a /24 in about 2.6 s on Linux, with exact payload and source matching.
- **MAC address, vendor, and ARP/ND evidence:** see who made each device, and find LAN hosts that block ping.
- **Alerts and integrations:** `--notify` (Slack, Teams, Discord, Telegram, e-mail, webhooks), `--html` reports, `--uptime`, `--serve` Prometheus metrics, `--trace-down`, Wake-on-LAN, nmap XML import/export, `@tags`, port presets, Docker and systemd units.
- **Just type a target:** `pingme 192.168.1.0/24`, `pingme hosts.txt`, `pingme server01` — no flags needed.
- **IP → hostname for every address** through DNS, the hosts file, mDNS and NetBIOS, plus `--reverse` for lookups without pinging.
- **Watch mode** (`--watch 60`) prints a line whenever a host goes up or down.
- **Lossy hosts no longer look dead:** silent hosts get 3 tries and responders 2 extra to confirm; at 5% packet loss the chance of missing a live host drops from 9.7% to 0.013%.
- **Latency and packet loss** columns, and IP-change detection in `changes.txt`.
- **Friendlier help:** a short `-h`, focused `pingme help <topic>` pages, and "did you mean" suggestions for mistyped options.
- **Config file** (`pingme --init-config`), `--color`/`NO_COLOR`, fractional timeouts, and meaningful exit codes.
- **Full IPv6:** `--discover6` finds IPv6 hosts on your LAN, `-4`/`-6` filters, `[addr]` and `fe80::1%eth0` forms, and IPv6-aware `--ipinfo`.
- **Reliability fixes:** macOS ping, `--rate` hang, Ctrl+C/`--resume` with fping, parallel TCP and fping confirmation, faster progress on large scans. See [RELEASE_NOTES_v3.3.0.md](RELEASE_NOTES_v3.3.0.md).

---

## 🎬 Animated Demo

<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Share+Tech+Mono&size=15&duration=65&pause=1200&color=39FF14&center=true&vCenter=false&multiline=true&width=1080&height=235&lines=%24+pingme+-f+endpoints.txt;HOST+RESOLUTION+%C2%B7+endpoints.txt;DSIN10329+%E2%86%92+10.100.6.53;FILE+SCAN+STATUS+%C2%B7+endpoints.txt;DSIN10329+%7C+10.100.6.53+%7C+REACHABLE+%7C+ICMP+%7C+TTL+128+%7C+Windows" alt="PingMe animated terminal demo" />

</div>

Example final output:

```text
FILE SCAN STATUS · endpoints.txt

+-----------+-------------+-------------+---------+-----+--------+------+-----------------------+----------------------+
| HOST      | IP ADDRESS  | STATUS      | METHOD  | TTL | RTT ms | LOSS | OS GUESS              | REVERSE DNS          |
+-----------+-------------+-------------+---------+-----+--------+------+-----------------------+----------------------+
| DSIN10329 | 10.100.6.53 | REACHABLE   | ICMP    | 128 | 1.8    | 0%   | Likely Windows (≤128) | dsin10329.corp.local |
| DSIN10343 | 10.100.6.12 | NO RESPONSE | -       | ?   | -      | 100% | Unknown               |                      |
| web01     | 10.100.6.90 | REACHABLE   | TCP:443 | ?   | -      | 100% | Unknown               | web01.corp.local     |
+-----------+-------------+-------------+---------+-----+--------+------+-----------------------+----------------------+

Reachable: 2  No response: 1  Probe errors: 0  Unresolved: 0
```

---

## ✨ Features

<div align="center">

| 🌐 Target Handling | 🔍 Discovery | 📊 Reporting |
|:---:|:---:|:---:|
| CIDR, IP, hostname, file — auto-detected | ICMP with `ping` or `fping` | Hostname → IP resolution table |
| IPv4 and IPv6 | Parallel TCP reachability | Reachable / no-response status |
| Duplicate removal | IP → hostname (DNS, mDNS, NetBIOS) | RTT, packet loss, TTL, OS guess |
| Inline comments in files | Retry, rate limiting, `--min-replies` | `hostnames.txt`, `changes.txt`, alive/dead reports |

| 📜 History | ⚙️ CLI Experience | 🛡️ Safety |
|:---:|:---:|:---:|
| Automatic, rotated scan history | Quick help + nested topics | CIDR expansion limit |
| `--changes` incl. IP changes | "Did you mean" suggestions | Validated ports and ranges |
| Resume interrupted scans | Bash/Zsh/Fish/PowerShell completion | Thread and timeout limits |
| `--watch` live monitoring | Config file, `NO_COLOR` | Scripting-friendly exit codes |

| 🔔 Alerts | 📈 Integrations | 🧰 LAN Tools |
|:---:|:---:|:---:|
| Slack / Teams / Discord / Telegram | Prometheus `/metrics` + JSON API | MAC address + vendor |
| E-mail and generic webhooks | HTML report with uptime | ARP/ND evidence for ping-blocking hosts |
| On changes, down, or always | nmap XML import/export | Wake-on-LAN, traceroute to down hosts |

</div>

---

## 🚀 Installation

### Linux / Kali / Parrot / Ubuntu

```bash
git clone https://github.com/Madhav-Sai/pingme.git
cd pingme

chmod +x pingme.py install.py
python3 install.py
exec zsh
```

For Bash:

```bash
python3 install.py --shell bash
exec bash
```

Install the recommended discovery tools:

```bash
sudo apt update
sudo apt install -y fping iputils-ping
```

### macOS

```bash
git clone https://github.com/Madhav-Sai/pingme.git
cd pingme

python3 install.py
exec zsh
```

Optional faster backend:

```bash
brew install fping
```

### Windows PowerShell

```powershell
git clone https://github.com/Madhav-Sai/pingme.git
cd pingme

python .\install.py
```

Open a new PowerShell window, then verify:

```powershell
pingme --version
pingme --help
```

If upgrading an older Windows installation, run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\repair-windows.ps1
```

### User-only installation

```bash
python3 install.py --user
```

### Verify

```bash
pingme --version
pingme --help
```

Expected version:

```text
pingme 3.3.0 (reliable-cross-platform)
```

---

## ⌨️ Automatic Tab Completion

`python3 install.py` installs completion for **Zsh, Bash, Fish, and PowerShell**. The scripts are generated from PingMe's own option list, so every flag is covered, and pressing TAB after a flag offers the values *that flag* accepts:

```text
pingme --ping-tool <TAB>
auto    -- pick the best available      native  -- built-in ICMP engine
fping   -- fping sweep                  ping    -- system ping          ask -- choose interactively

pingme --sub 10.10.11.0/24 --scan --hostnames-out <TAB>
hostnames.txt  -- live-host report   hostnames.csv  -- CSV rows   hostnames.json -- JSON rows   (+ files)

pingme -I <TAB>
eth0  lo  wlan0  docker0 ...          10.10.11.30 -- wlan0   127.0.0.1 -- lo

pingme --tcp-ports <TAB>
web -- 80,443,8080,8443   windows -- 135,139,445,3389,5985   linux -- 22,111,2049   db -- ...

pingme --sub <TAB>
10.10.11.0/24  172.17.0.0/16 ...      (networks this machine is connected to)
```

| After | TAB offers |
|---|---|
| a flag with fixed choices (`--ping-tool`, `--out-format`, `--color`, `--notify-on`, `--help-topic`) | the choices, with descriptions |
| an output flag (`--hostnames-out`, `--alive-out`, `--html`, `--nmap-xml`, …) | files, plus the usual file names and formats |
| `-I`/`--interface`, `--discover6` | adapter names and their IP addresses |
| `--sub` or a bare target | the networks this machine is on |
| `--tcp-ports` | port presets with the ports they expand to |
| numbers (`--timeout`, `--threads`, `--count`, `--keep`, …) | common values, with the default marked |
| free text (`--host`, `--label`, `--wol`, …) | a hint describing what to type (zsh) |

Re-run `python3 install.py` after updating PingMe to refresh completion. Zsh and PowerShell show descriptions; Bash shows the values only.

---

## 🧭 Help System

### Main help

```bash
pingme --help
```

### Full help

```bash
pingme --help-all
```

### Nested help topics

```bash
pingme help targets
pingme help scan
pingme help discovery
pingme help output
pingme help history
pingme help advanced
pingme help examples
```

Alternative syntax:

```bash
pingme --help-topic targets
pingme --help-topic scan
pingme --help-topic output
```

### Help for one flag

Put `-h` after any flag, even in the middle of a command, to see what that flag does, the values it accepts, its default, the flags that go with it, and examples:

```bash
pingme --sub 10.10.11.0/24 --scan --hostnames-out -h
pingme -I -h
pingme help --names-only
```

```text
  --hostnames-out, --hostfile-out FILE
  Live-host report: IP, hostname, MAC, vendor, notes (file scans: hostnames.txt)

  Value       FILE: a file path
  Suggested   hostnames.txt   live-host report
              hostnames.csv   CSV rows
              hostnames.json  JSON rows
  Works with  --names-only  --out-format

  Examples
    $ pingme 10.10.11.0/24 --hostnames-out hostnames.txt               # live-host report
    $ pingme 10.10.11.0/24 --hostnames-out hostnames.txt --names-only  # only IP ADDRESS | HOSTNAME
```

---

## 📖 Usage

### 0. Just give it a target

PingMe detects what each argument is, so most scans need no flags at all:

```bash
pingme 192.168.1.10          # one IP
pingme server01              # a hostname
pingme 192.168.1.0/24        # every host in a subnet
pingme endpoints.txt         # a target file
pingme web01 10.0.0.0/28     # mix them
```

An existing file always wins over a hostname of the same name; use `--host NAME` to force a hostname.
Run `pingme -h` for the short help or `pingme help examples` for more recipes.

### 1. Subnet information only

```bash
pingme --sub 192.168.1.0/24
pingme --sub 10.10.0.0/22
```

PingMe displays:

- Network address
- Broadcast address
- Subnet mask
- Wildcard mask
- Prefix length
- First and last host
- Usable host count
- Subnet breakdown

### 2. Scan a subnet

```bash
pingme --sub 192.168.1.0/24 --scan
```

Fast mode:

```bash
pingme --sub 192.168.1.0/24 --scan --fast
```

Custom tuning:

```bash
pingme --sub 10.0.0.0/22 --scan --threads 30 --timeout 4 --count 5
```

### 3. Scan a file containing hostnames or IPs

```bash
pingme --file endpoints.txt
```

Short form:

```bash
pingme -f endpoints.txt
```

Example `endpoints.txt`:

```text
# Windows endpoints
DSIN10329
DSIN10343
DSIN10418

# Direct IPs
10.100.6.90
10.100.6.21

# Inline comments are supported
web01.corp.local  # production web server

# Portable mappings (work without DNS on Linux and Windows)
172.31.100.2 VAPT-01
VAPT-02,172.31.100.3
```

Explicit `IP HOST`, `HOST,IP`, and `IP,HOST` mappings are accepted. Use them for short Windows/NetBIOS names that Linux cannot resolve through DNS or `/etc/hosts`.

PingMe first displays:

```text
HOST RESOLUTION · endpoints.txt
```

Then scans all resolved addresses and displays:

```text
FILE SCAN STATUS · endpoints.txt
```

The final table contains:

```text
HOST | IP ADDRESS | STATUS | METHOD | TTL | OS GUESS
```

Example:

```text
FILE SCAN STATUS · endpoints.txt

+------------+--------------+-------------+--------+-----+----------+
| HOST       | IP ADDRESS   | STATUS      | METHOD | TTL | OS GUESS |
+------------+--------------+-------------+--------+-----+----------+
| DSIN10661  | 10.100.6.161 | NO RESPONSE | -      | ?   | Unknown  |
| DSIN10657  | 10.100.6.106 | REACHABLE   | ICMP   | 128 | Windows  |
+------------+--------------+-------------+--------+-----+----------+
```

#### File scan reports and simple change tracking

Run:

```bash
pingme -f endpoints.txt --changes
```

PingMe creates or updates:

| File | Purpose |
|---|---|
| `hostnames.txt` | Complete `HOST`, `IP ADDRESS`, `STATUS`, `METHOD`, `TTL`, and `OS GUESS` report |
| `changes.txt` | Newly online and went-offline systems since the previous `--changes` run |
| `alive.txt` | IP addresses currently reachable |
| `dead.txt` | IP addresses currently not responding |
| `errors.txt` | Probe failures, excluded from `dead.txt` and offline alerts |

`hostnames.txt` always contains the complete current file-scan table, including reachable, non-responsive, and unresolved hosts.

On the first `--changes` run, PingMe saves the current scan as the baseline:

```text
FIRST SCAN · endpoints.txt

Baseline saved.

Online     : 7
Offline    : 2
Unresolved : 1
```

On later runs, `changes.txt` contains only the important differences:

```text
CHANGES SINCE LAST SCAN · endpoints.txt

NEWLY ONLINE
+------------+--------------+
| HOST       | IP ADDRESS   |
+------------+--------------+
| DSIN10661  | 10.100.6.161 |
+------------+--------------+

WENT OFFLINE
+------------+--------------+
| HOST       | IP ADDRESS   |
+------------+--------------+
| DSIN10657  | 10.100.6.106 |
+------------+--------------+

Newly online : 1
Went offline : 1
Still online : 6
Still offline: 1
```

When a host keeps its name but gets a new address (for example after a DHCP renewal):

```text
IP ADDRESS CHANGED
+-----------+--------------+--------------+---------------+
| HOST      | OLD IP       | NEW IP       | STATUS NOW    |
+-----------+--------------+--------------+---------------+
| DSIN10661 | 10.100.6.161 | 10.100.6.172 | REACHABLE     |
+-----------+--------------+--------------+---------------+
```

When nothing changed:

```text
CHANGES SINCE LAST SCAN · endpoints.txt

NO CONCLUSIVE CHANGES DETECTED

All conclusively tested hosts have the same status as the previous scan.
```

Custom report names:

```bash
pingme -f endpoints.txt \
  --changes \
  --hostnames-out reports/hostnames.txt \
  --changes-out reports/changes.txt
```

Custom alive/dead report names:

```bash
pingme -f endpoints.txt \
  --alive-out reports/alive.txt \
  --dead-out reports/dead.txt
```

### 4. Scan one or more hosts directly

```bash
pingme --host server01
pingme --host server01 server02 10.10.10.10
```

Use `--host` for a few quick targets. Use `--file` for reusable or larger target lists.

### 5. Detect systems that block ICMP

Some hosts reject ICMP but accept TCP connections.

```bash
pingme -f endpoints.txt --tcp-ports 22,80,135,139,443,445,3389
```

A host is marked reachable when:

- a direct ICMP echo reply comes from the exact requested address, or
- At least one requested TCP port accepts a connection

Packet-summary counters are not accepted as proof. This prevents Windows
`Destination host unreachable` packets from being counted as live targets.

### 6. IP → hostname (reverse lookup)

For scans of up to 1,024 targets, PingMe looks up the hostname of every scanned IP automatically and shows it in the **REVERSE DNS** column. It uses:

1. The system resolver: DNS PTR records, `/etc/hosts`, and NSS providers such as winbind (through bounded `getent` on Linux).
2. For private or link-local hosts that answered: **mDNS** (`avahi-resolve-address`, e.g. `printer.local`) and **NetBIOS** (`nmblookup -A` on Linux/macOS with Samba, `nbtstat -A` on Windows). These name most Windows PCs and LAN devices that have no DNS record.

```bash
pingme 192.168.1.0/24            # names shown automatically
pingme 10.0.0.0/20 --dns         # force lookups above 1,024 targets
pingme endpoints.txt --no-dns    # skip lookups
```

Look up names **without pinging**:

```bash
pingme --reverse 10.10.10.10
pingme -r 192.168.1.0/24         # lists every address that has a name
```

```text
REVERSE LOOKUP · IP → HOSTNAME
+-----------------+-------------+---------+
| IP ADDRESS      | HOSTNAME    | SOURCE  |
+-----------------+-------------+---------+
| 192.168.1.1     | _gateway    | dns     |
| 192.168.1.20    | DESKTOP-42  | netbios |
| 192.168.1.31    | nas.local   | mdns    |
+-----------------+-------------+---------+
```

Tip: `sudo apt install samba-common-bin avahi-utils` enables the NetBIOS and mDNS lookups on Debian/Kali.

### 7. Watch mode (live monitoring)

```bash
pingme 10.0.0.0/24 --watch 60
pingme endpoints.txt --watch 30 --tcp-ports 443
```

PingMe scans once, shows the normal report, then rescans every N seconds and prints one line per change:

```text
09:14:02  ▼ DOWN   10.0.0.23           fileserver.corp.local
09:15:02  ▲ UP     10.0.0.23   1.9ms   fileserver.corp.local
```

`alive.txt`/`dead.txt` are refreshed each round. Press Ctrl+C to stop.

### 8. IPv6

Every feature works with IPv6: hosts, files, subnets, TCP checks, hostname lookups, `--changes`, and `--watch`.

```bash
pingme 2001:db8::10                    # an address
pingme [2001:db8::10]                  # bracketed form is accepted too
pingme fe80::1%wlan0                   # link-local needs the interface (Windows: fe80::1%12)
pingme 2001:db8:1234::/120             # small IPv6 subnets can be swept
pingme server01 -6                     # only the IPv6 addresses of a dual-stack host
pingme endpoints.txt -4                # only IPv4
```

**Finding IPv6 hosts on your LAN.** A /64 holds 18 quintillion addresses, so it cannot be swept. Use neighbor discovery instead:

```bash
pingme --discover6                     # every active interface
pingme --discover6 wlan0 eth0          # chosen interfaces
```

PingMe pings the all-nodes and all-routers multicast groups (`ff02::1`, `ff02::2`) on each link and reads the OS neighbor cache (`ip -6 neigh`, `ndp -an`, or `netsh interface ipv6 show neighbors`). Every candidate is then probed normally, so only confirmed hosts are REACHABLE:

```text
IPv6 NEIGHBORS · local links
+-------------------+---------------------------------+-----------+--------+-----+--------+------+-----------------------+
| MAC ADDRESS       | IP ADDRESS                      | STATUS    | METHOD | TTL | RTT ms | LOSS | OS GUESS              |
+-------------------+---------------------------------+-----------+--------+-----+--------+------+-----------------------+
| 5c:a6:e6:cc:0e:fb | fe80::5ea6:e6ff:fecc:efb%wlan0  | REACHABLE | ICMP   | 64  | 1.45   | 0%   | Likely Unix (≤64)     |
| e6:d4:87:71:a9:38 | fe80::e4d4:87ff:fe71:a938%wlan0 | REACHABLE | ICMP   | 254 | 3.75   | 0%   | Likely network (≤255) |
+-------------------+---------------------------------+-----------+--------+-----+--------+------+-----------------------+
```

Some hosts (notably Windows) ignore multicast echo requests; they are still found when they appear in the neighbor cache, and any known address can be scanned directly.

`--ipinfo` understands IPv6 special ranges (documentation, ULA, 6to4, Teredo, NAT64, IPv4-mapped), shows the embedded IPv4 address, and reveals the MAC address behind EUI-64 interface IDs:

```bash
pingme --ipinfo 64:ff9b::808:808 fe80::34de:75ff:fe8e:8955
```

### 9. IP classification

```bash
pingme --ipinfo 8.8.8.8
pingme --ipinfo 10.0.0.1 172.16.0.10 192.168.1.1 100.64.0.1
```

Recognized categories include:

- Public
- RFC 1918 private
- CGNAT
- Loopback
- Link-local
- Multicast
- Documentation
- Reserved
- IPv6 unique local

---

### 10. Scan engines

| Engine | How it works | When it is used |
|---|---|---|
| `native` | One ICMP socket sends to every target and matches each reply by source address, random token, and exact payload. No process per host. | Default on Linux when unprivileged ICMP sockets are allowed (most distributions) |
| `fping` | fping sweeps the list; every positive is re-confirmed with separate system `ping` processes while the sweep continues. | Default when the native engine is unavailable and fping is installed |
| `ping` | Separate system `ping` processes per host, in parallel. | Fallback everywhere, including Windows |

```bash
pingme 10.0.0.0/24 --ping-tool native     # force an engine
pingme 10.0.0.0/24 --timeout auto         # native: adapt the wait to measured RTTs
```

All engines need `--min-replies` (default 2) replies from separate requests before a host is REACHABLE, and a reply whose payload was altered becomes a PROBE ERROR.

### 11. MAC address, vendor, and hosts that block ping

For hosts on your local network PingMe reads the operating system's neighbor table (ARP for IPv4, ND for IPv6) and adds **MAC** and **VENDOR** columns:

```text
| 192.168.0.1   | REACHABLE | ICMP   | ... | 5c:a6:e6:cc:0e:fb | TP-Link Systems          |
| 192.168.0.162 | REACHABLE | ARP/ND | ... | a6:71:b5:07:b4:46 | Private (randomized MAC) |
```

A LAN host that drops every ping still has to answer ARP to receive traffic. When the neighbor entry for a scanned address is fresh (**REACHABLE**) after the probe, PingMe reports the host as REACHABLE with method `ARP/ND`. Stale entries never count, and a MAC answering for several addresses (proxy ARP) is ignored. Turn this off with `--no-arp`. macOS does not report neighbor state, so it shows MACs but does not use them as evidence.

Vendors come from the nmap or IEEE databases when installed (`/usr/share/nmap/nmap-mac-prefixes`, `/usr/share/ieee-data/oui.txt`), otherwise from a built-in list. `pingme --update-oui` downloads the full IEEE registry. Phones and laptops often use randomized MACs, shown as `Private (randomized MAC)`.

### 12. Alerts

```bash
pingme hosts.txt --changes --notify https://hooks.slack.com/services/T/B/X
pingme hosts.txt --watch 60 --notify "https://outlook.office.com/webhook/…"
pingme hosts.txt --notify https://discord.com/api/webhooks/…
pingme hosts.txt --notify telegram://BOT_TOKEN@CHAT_ID
pingme hosts.txt --notify mailto:ops@example.com       # uses PINGME_SMTP_HOST/PORT/USER/PASSWORD/FROM
pingme hosts.txt --notify https://example.com/hook     # JSON payload with every event
```

`--notify-on changes` (default) alerts when hosts go offline or come online, or when an IP or MAC changes. `down` alerts whenever something is not responding, and `always` sends a summary every run. In `--watch` mode an alert is sent only when something changes, never repeatedly for the same outage. A failed alert is reported but never stops the scan. `--notify` can be repeated and set in the config file.

### 13. HTML report, uptime, and dashboards

```bash
pingme hosts.txt --html report.html      # self-contained page: summary, filters, sortable table, uptime
pingme --uptime hosts.txt                # availability %, flaps, and last-seen from history
pingme hosts.txt --serve 9109 --watch 60 # rescan every minute; serve /metrics, /api/results, and a live page
```

`--serve` binds to 127.0.0.1 unless you give an address (`--serve 0.0.0.0:9109`). Prometheus metrics include `pingme_up`, `pingme_rtt_milliseconds`, `pingme_packet_loss_ratio`, `pingme_probe_error`, `pingme_targets`, and scan duration/timestamp. `/healthz` returns 200 once the first scan finished.

### 14. More tools

```bash
pingme web01 --tcp-ports web,windows        # presets: web, windows, linux, mail, db, printers, network, common
pingme hosts.txt --trace-down               # where does the path to each down host stop?
pingme --wol aa:bb:cc:dd:ee:ff              # Wake-on-LAN
pingme hosts.txt --wake                     # wake down hosts whose MAC was seen in earlier scans
pingme scan.xml                             # use an nmap -oX file as the target list
pingme hosts.txt --nmap-xml out.xml         # export for tools that import nmap scans
pingme inventory.csv --column ip_address    # take targets from one CSV column
pingme hosts.txt --tag prod                 # only lines tagged @prod (web01 @prod @web)
```

`--trace-down` explains each outage: "path stops after 10.0.0.1 (hop 3)", "on your local network but silent at layer 2: powered off, unplugged, or moved to another IP", or "path is fine; the host itself ignores ping".

### 15. Choosing the network adapter (`-I` / `--interface`)

On a machine with several adapters (Ethernet, Wi-Fi, VPN, Docker bridges), pin the whole scan to the in-scope one:

```bash
pingme 10.10.11.0/24 -I wlan0 --hostnames-out hostnames.txt
pingme -f scope.txt --interface 10.10.11.30     # the adapter's IP works too (required on Windows)
```

- **Everything goes out that adapter:** ICMP (all engines), TCP checks, traceroute, Wake-on-LAN, and name lookups. Reverse and forward DNS go to *that adapter's* DNS server through a bound socket, and mDNS/NetBIOS name queries go to the target itself. Nothing falls back to another adapter silently.
- **ARP evidence** only counts replies seen on that adapter.
- **Checked before the scan:** unknown or down adapters and adapters without an address are refused, with a list of the valid ones. PingMe warns when targets normally route through a different adapter.
- **Recorded in the report:** `Interface : wlan0, forced with -I` and `Name lookups : DNS 10.10.11.1 via wlan0`.
- **Platforms:** Linux pins sockets to the device (`SO_BINDTODEVICE`), macOS uses `IP_BOUND_IF`, and Windows uses `IP_UNICAST_IF` for PingMe's own sockets. Windows `ping.exe` can only set the source address, and the report says so.
- Set it permanently with `interface = "wlan0"` in the config file.

### 16. Running as a service

- **Docker:** `docker build -t pingme .` then `docker run --rm --network host pingme 192.168.1.0/24`
- **systemd:** `contrib/systemd/pingme-check.{service,timer}` (every 5 min, alerts via `/etc/pingme/pingme.env`) and `pingme-serve.service` (metrics exporter)
- **Windows:** `contrib/windows/Register-PingMeTask.ps1 -Targets C:\pingme\targets.txt -Minutes 15`
- **Homebrew / AUR:** templates in `contrib/homebrew` and `contrib/aur`

---

## 📊 Output Files and Formats

### Default file-scan reports

```bash
pingme -f endpoints.txt --changes
```

Produces or updates:

```text
hostnames.txt
changes.txt
alive.txt
dead.txt
```

### `hostnames.txt` — live host report

A report you can attach to an assessment: scan evidence, **live hosts only** (one row per IP), notes, and limitations.

```text
PingMe Live Host Report
=======================

Scope        : 10.10.11.0/24 (254 addresses)
Scan started : 2026-09-23 17:43:11 IST (UTC+0530)
Duration     : 8.2 s
Scanner      : IT-Serv (10.10.11.30, wlan0), PingMe 3.3.0
Method       : ICMP echo via native engine (3 attempts, 2 replies required, timeout 2 s) + ARP/ND replies
Result       : 8 live hosts; 246 no response; 0 probe errors; 0 unresolved

LIVE HOSTS
+---+--------------+----------+--------------------------+-----+--------+-------------------+----------------------+--------------------+
| # | IP ADDRESS   | HOSTNAME | DETECTED BY              | TTL | RTT ms | MAC ADDRESS       | VENDOR               | OS HINT            |
+---+--------------+----------+--------------------------+-----+--------+-------------------+----------------------+--------------------+
| 1 | 10.10.11.1   | _gateway | ICMP                     | 64  | 3.41   | 50:91:e3:ba:c0:98 | TP-Link Systems      | Unix-like          |
| 2 | 10.10.11.30  | IT-Serv  | ICMP                     | 64  | 0.16   | -                 | This scanner         | Unix-like          |
| 3 | 10.10.11.41  | -        | ICMP                     | 255 | 37.47  | 34:fc:99:a1:46:e5 | SJIT                 | Network device     |
| 4 | 10.10.11.70  | -        | ICMP                     | 32  | 401.52 | da:c0:89:9a:84:29 | Randomized MAC       | Embedded / unknown |
| 5 | 10.10.11.86  | -        | ICMP                     | 64  | 114.86 | 1a:89:1e:f9:a0:0e | Randomized MAC       | Unix-like          |
| 6 | 10.10.11.116 | -        | ICMP                     | 64  | 7.06   | b0:19:21:ff:cb:ea | TP-Link Systems      | Unix-like          |
| 7 | 10.10.11.182 | -        | ARP reply (ICMP blocked) | -   | -      | 3c:84:6a:26:6f:0b | TP-LINK TECHNOLOGIES | -                  |
| 8 | 10.10.11.215 | -        | ICMP                     | 64  | 36.87  | 4a:5d:5d:49:2a:34 | Randomized MAC       | Unix-like          |
+---+--------------+----------+--------------------------+-----+--------+-------------------+----------------------+--------------------+

NOTES
  - 10.10.11.1 is the scanner's default gateway (router).
  - 10.10.11.30 is the scanning machine itself, not a discovered asset.
  - 1 host drops ICMP echo and was found only by ARP or TCP: 10.10.11.182. ...
  - 3 hosts use randomized (private) MAC addresses ...

LIMITATIONS
  - Point-in-time result: devices that were off, asleep, or disconnected during the scan are not listed.
  - Hosts that drop ICMP are detected only on the local network segment (ARP) or with --tcp-ports.
  - OS hints come from the reply TTL only; they are indicative, not a fingerprint.
```

- File scans (`-f`) also list **in-scope targets without response** and **unresolved names**, so the report shows what was tested but not reached.
- Empty columns are dropped; several names for one IP are merged (`web01, www`).
- `--names-only` keeps just `# | IP ADDRESS | HOSTNAME`.
- A `.csv` or `.json` file name writes machine-readable rows instead: `--hostnames-out live.csv`.
- Written automatically for file scans; add `--hostnames-out FILE` (alias `--hostfile-out`) for subnet and host scans.

```bash
pingme 10.10.11.0/24 --hostnames-out hostnames.txt
pingme -f scope.txt --hostnames-out names.txt --names-only
pingme 10.10.11.0/24 --hostnames-out live.csv
```

### `changes.txt`

Stores only the changes since the previous run using the same target file:

```text
NEWLY ONLINE
WENT OFFLINE
IP ADDRESS CHANGED
NEW TARGETS ADDED TO FILE
TARGETS REMOVED FROM FILE
```

### `alive.txt`

Stores one currently reachable IP address per line.

### `dead.txt`

Stores one currently non-responsive IP address per line.

### Plain text

```bash
pingme -f endpoints.txt --out-format txt
```

### CSV

```bash
pingme -f endpoints.txt --out-format csv
```

CSV and JSON rows include `ip, status, evidence, probe_error, tcp_open, ttl, rtt_min, rtt_avg, loss_pct, os_guess, hostname, scope, rfc`.

### JSON

```bash
pingme -f endpoints.txt --out-format json
```

### Custom report paths

```bash
pingme -f endpoints.txt \
  --changes \
  --hostnames-out reports/hostnames.txt \
  --changes-out reports/changes.txt \
  --alive-out reports/alive.txt \
  --dead-out reports/dead.txt
```

When using CSV or JSON for the alive/dead result files:

```bash
pingme -f endpoints.txt \
  --out-format csv \
  --alive-out reports/alive.csv \
  --dead-out reports/dead.csv
```

---

## 📜 History, Changes, Comparison, and Resume

### Simple file change tracking

```bash
pingme -f endpoints.txt --changes
```

Run the same command again later. PingMe automatically compares the current status with the previous `--changes` run for that file and writes the result to `changes.txt`.

### Advanced history comparison

```bash
pingme --sub 192.168.1.0/24 --scan --compare --label office
```

### List history

```bash
pingme --history
```

### Clear history

```bash
pingme --clear-history office
```

### Skip history

```bash
pingme -f endpoints.txt --no-history
```

### Resume an interrupted scan

```bash
pingme -f endpoints.txt --resume
```

### Compare two snapshot files

```bash
pingme --diff alive_monday.txt alive_friday.txt
pingme --diff monday.csv friday.json     # csv and json results work too
```

### Where history is stored

History, resume data, and `--changes` baselines are saved in a `data/` folder next to where you run PingMe. Every scan also copies its output files (`alive.txt`, `dead.txt`, `errors.txt`, the hostnames file, and any `--html`/`--nmap-xml` report) into a timestamped folder, so the next run never loses them:

```text
data/
├── hosts-1a2b3c4d.json                 # scan history used by --compare, --uptime, --changes
└── hosts-1a2b3c4d/
    ├── 2026-09-23_09-00-00/alive.txt  dead.txt  errors.txt  hostnames.txt
    └── 2026-09-23_17-00-00/alive.txt  dead.txt  errors.txt  hostnames.txt
```

`alive.txt` in your working folder is always the latest scan. To see what changed:

```bash
pingme -f hosts.txt --compare                 # compares with the previous scan; prints where its files are
pingme --history                              # lists labels, scan counts, and snapshot folders
pingme --diff data/hosts-1a2b3c4d/2026-09-23_09-00-00/alive.txt alive.txt
```

Override the location with `--data-dir DIR` or `PINGME_DATA_DIR` (the Docker image and systemd units use `/data` and `/var/lib/pingme`). History and snapshots keep the newest 50 scans per label (`--keep N`, `0` = all); `--no-history` saves neither.
History saved by 3.3 in the per-user directory (`~/.local/share/pingme`, `~/Library/Application Support/PingMe`, or `%LOCALAPPDATA%\PingMe`) is still read, so `--compare` keeps working after upgrading.
Target files are labelled by name plus a short hash of their full path, so two `hosts.txt` files in different folders never share a baseline. `pingme --clear-history endpoints.txt` accepts the file path directly.

---

## ⚙️ Configuration File

Save your preferred defaults once:

```bash
pingme --init-config          # creates a commented template
pingme help config            # shows the location and every key
```

Example `~/.config/pingme/config.toml` (Windows: `%APPDATA%\PingMe\config.toml`):

```toml
threads = 50
timeout = 1.5
count = 4
min_replies = 2
tcp_ports = "22,80,443,445,3389"
out_format = "csv"
```

Command-line flags always win over the config file. Use `--config FILE` (or `PINGME_CONFIG`) for another file and `--no-config` to ignore it. Unknown keys are reported with a suggestion.

---

## 🚦 Exit Codes

| Code | Meaning |
|---:|---|
| `0` | Hosts/files: every target reachable. Subnets: at least one host found. |
| `1` | Hosts/files: a target is down or unresolved. Subnets: nothing answered. |
| `2` | Usage or configuration error. |
| `3` | No usable ping tool is installed. |
| `4` | At least one probe failed to run (see `errors.txt`). |
| `130` | Interrupted with Ctrl+C; rerun with `--resume`. |

Use `--exit-zero` when a wrapper expects 0 after every completed scan.

```bash
pingme critical-servers.txt --quiet || notify-send "PingMe" "A critical server is down"
```

---

## 🎛️ Complete Option Reference

### Targets and modes

```text
TARGET [TARGET ...]
    IP, hostname, CIDR, or existing file. Detected automatically; implies a scan.

-s, --sub CIDR
    Show subnet information. Add --scan to scan it.

-f, --file FILE
    Resolve and scan IP addresses or hostnames from a file.

--host HOST [HOST ...]
    Resolve and scan one or more direct targets.

--ipinfo IP [IP ...]
    Classify addresses as public, private, loopback, and more.

-r, --reverse IP/CIDR [...]
    Look up hostnames for addresses without pinging them.

--tag TAG
    Only target-file lines tagged @TAG (repeatable).

--column NAME
    Read targets from one column of a CSV file with a header row.

--discover6 [IFACE ...]
    Find IPv6 hosts on local links (multicast echo + neighbor cache).

-4, --ipv4-only / -6, --ipv6-only
    Resolve and scan only one address family.

--diff FILE_A FILE_B
    Compare two host snapshot files.

--history
    List stored scan history.

--clear-history LABEL|FILE
    Delete history, resume, and baseline data for a label or target file.
```

### Discovery and scan control

```text
--scan
    Start scanning a --sub CIDR. Implied by --file, --host, and plain targets.

-t, --threads N
    Number of concurrent workers. Default: 20.

--timeout SEC
    Wait per ping; fractions such as 0.5 are allowed. Default: 2.

--count N
    Ping attempts for a silent host. Default: 3.
    A host that answers gets 2 extra attempts to reach --min-replies.

--min-replies N
    Replies needed before a host is REACHABLE. Default: 2.
    Example: --count 5 --min-replies 2 tolerates a lossy Wi-Fi link.

--tcp-ports PORTS
    TCP ports or ranges, such as 22,80,443 or 8000-8010.

--tcp-timeout SEC
    TCP connection timeout. Default: 2. All ports of a host are tried in parallel.

--retry N
    Retry hosts that did not respond.

--rate PPS
    Maximum packet rate. 0 means unlimited.

--dns / --no-dns
    Force or skip IP → hostname lookups. Default: automatic (on up to 1,024 targets).

--resume
    Continue an interrupted scan (works with both fping and ping).

--watch SEC
    Rescan every SEC seconds and print only changes.

--ping-tool auto|native|fping|ping|ask
    Select the ICMP engine. "ask" chooses interactively.

--no-arp
    Do not count fresh ARP/ND replies as reachability evidence.

--trace-down
    Traceroute up to 10 down hosts and explain where the path stops.

--update-oui
    Download the IEEE MAC vendor registry.

--fast
    Use 100 threads, one-second timeout, and one attempt. Positives are still confirmed.

--exclude IP/CIDR [...]
    Skip selected IP addresses or networks.

--max-hosts N
    Maximum number of addresses expanded from a CIDR.
```

### Output and display

```text
--alive-out FILE
    Output path for currently reachable IP addresses.

--dead-out FILE
    Output path for currently non-responsive IP addresses.

--error-out FILE
    Output path for inconclusive probe-execution failures.

--hostnames-out FILE
    Save the live-host report: scan details, live hosts only, notes, and
    limitations. .csv/.json names write data rows. Default for file scans:
    hostnames.txt. Works for every scan type. Alias: --hostfile-out.

--names-only
    Make the hostnames file list only IP ADDRESS | HOSTNAME.

--changes-out FILE
    Save newly-online and went-offline changes. Default: changes.txt.

--changes
    Compare the current file scan with the previous --changes run and
    update changes.txt.

--out-format txt|csv|json
    Select the alive/dead output format.

--label NAME
    Custom history label.

-q, --quiet
    Write result files without normal terminal output.

--compact
    Show only the final summary and saved file paths.

--verbose
    Force diagnostic tables and live progress when output is redirected.

--no-banner
    Hide the ASCII banner.

--color auto|always|never
    Colored output. NO_COLOR is honoured in auto mode.

--html FILE
    Self-contained HTML report with filters, sorting, and uptime.

--nmap-xml FILE
    nmap-compatible XML output.

--exit-zero
    Exit 0 after any completed scan.

--no-history
    Do not store the scan.

--compare
    IP-only comparison with the previous scan of the label.
    Probe errors are reported separately, never as "went offline".

--keep N
    History entries kept per label. Default: 50. 0 keeps everything.

--uptime LABEL|FILE
    Availability per host from stored history.
```

### Alerts and integrations

```text
--notify TARGET         Slack/Teams/Discord webhook, telegram://TOKEN@CHAT, mailto:, or any URL (repeatable)
--notify-on MODE        changes (default) | down | always
--serve [HOST:]PORT     Rescan every --watch SEC and serve /metrics, /api/results, and a live page
--wake                  Wake-on-LAN for down hosts whose MAC is known
--wol MAC [...]         Send Wake-on-LAN magic packets and exit
--wol-broadcast IP      Broadcast address for Wake-on-LAN (default 255.255.255.255)

--data-dir DIR
    State directory. Default: per-user data directory.
```

### Configuration

```text
--config FILE      Use another config file.
--no-config        Ignore the config file.
--init-config      Create a commented template.
```

### Help

```text
-h, --help           Quick, task-oriented help
--help-all           Every option
pingme help TOPIC    targets | scan | discovery | output | history | alerts | config | exitcodes | advanced | examples
--help-topic TOPIC   Same as "pingme help TOPIC"
--version
```

---

## 🧪 Real-World Workflows

### Corporate Windows endpoint check

```bash
pingme -f endpoints.txt --ping-tool ping
```

### Windows endpoints with TCP fallback

```bash
pingme -f endpoints.txt \
  --tcp-ports 135,139,445,3389 \
  --ping-tool ping
```

### Quick local-network discovery

```bash
pingme --sub 192.168.1.0/24 --scan --fast
```

### Accurate infrastructure scan

```bash
pingme -f production.txt \
  --threads 20 \
  --timeout 6 \
  --count 8 \
  --min-replies 2 \
  --retry 1 \
  --dns
```

### Lossy Wi-Fi or VPN link

```bash
pingme 192.168.1.0/24 --count 5 --min-replies 2 --timeout 1.5
```

### Name every device on the LAN

```bash
pingme --reverse 192.168.1.0/24
```

### Monitoring from cron

```bash
*/5 * * * * pingme /etc/pingme/critical.txt --changes --quiet || /usr/local/bin/alert-oncall
```

### Rate-limited customer assessment

```bash
pingme -f scope.txt \
  --rate 100 \
  --threads 10 \
  --label customer-network
```

### Daily endpoint change check

```bash
pingme -f endpoints.txt --changes
```

This updates:

```text
hostnames.txt
changes.txt
alive.txt
dead.txt
```

### Advanced subnet history comparison

```bash
pingme --sub 192.168.10.0/24 \
  --scan \
  --compare \
  --label office
```

### Structured report data

```bash
pingme -f endpoints.txt \
  --changes \
  --tcp-ports 22,80,443,445,3389 \
  --hostnames-out reports/hostnames.txt \
  --changes-out reports/changes.txt \
  --out-format csv \
  --alive-out reports/reachable.csv \
  --dead-out reports/no-response.csv
```

---

## 🧾 Cheatsheet

```bash
# Help
pingme -h
pingme --help-all
pingme help examples

# Just scan something
pingme 192.168.1.0/24
pingme endpoints.txt
pingme server01 10.0.0.5

# IP → hostname only
pingme --reverse 192.168.1.0/24

# IPv6 hosts on the local network
pingme --discover6

# Only IPv6 / only IPv4
pingme server01 -6
pingme endpoints.txt -4

# Watch for changes every minute
pingme 10.0.0.0/24 --watch 60

# Tolerate packet loss (2 of 5)
pingme endpoints.txt --count 5 --min-replies 2

# Create a config file
pingme --init-config

# Alerts, reports, dashboards
pingme hosts.txt --changes --notify https://hooks.slack.com/services/T/B/X
pingme hosts.txt --html report.html
pingme --uptime hosts.txt
pingme hosts.txt --serve 9109 --watch 60

# LAN tools
pingme hosts.txt --trace-down
pingme --wol aa:bb:cc:dd:ee:ff
pingme web01 --tcp-ports web,windows

# Version
pingme --version

# File scan
pingme -f endpoints.txt

# File scan + simple change tracking
pingme -f endpoints.txt --changes

# Custom full hostname and change reports
pingme -f endpoints.txt --changes \
  --hostnames-out reports/hostnames.txt \
  --changes-out reports/changes.txt

# Host scan
pingme --host server01 10.10.10.10

# CIDR information
pingme -s 192.168.1.0/24

# CIDR scan
pingme -s 192.168.1.0/24 --scan

# Fast scan
pingme -s 192.168.1.0/24 --scan --fast

# Force system ping
pingme -f endpoints.txt --ping-tool ping

# Force fping
pingme -f endpoints.txt --ping-tool fping

# ICMP + TCP discovery
pingme -f endpoints.txt --tcp-ports 22,80,443,445,3389

# Reverse DNS
pingme -f endpoints.txt --dns

# CSV output
pingme -f endpoints.txt --out-format csv

# JSON output
pingme -f endpoints.txt --out-format json

# Simple comparison with previous file scan
pingme -f endpoints.txt --changes

# Advanced labeled history comparison
pingme -f endpoints.txt --compare --label endpoints

# Resume
pingme -f endpoints.txt --resume

# Diff snapshots
pingme --diff old-alive.txt new-alive.txt

# IP classification
pingme --ipinfo 8.8.8.8 192.168.1.1
```

---

## 🧠 Why the Defaults?

| Setting | Default | Purpose |
|---|---:|---|
| Threads | `20` | Avoids flooding smaller networks |
| Timeout | `2s` | Practical default for automated discovery |
| Count | `3` | Attempts for a silent host; responders get 2 more to confirm |
| TCP timeout | `2s` | Keeps fallback checks practical |
| Maximum CIDR targets | `65,536` | Prevents accidental huge expansion |
| Minimum replies | `2` | Two independent echo replies before REACHABLE |
| History kept | `50` scans per label | Bounded disk use |
| Reverse lookups | automatic up to `1,024` targets | Names without slowing huge sweeps |

A target is reachable only after `--min-replies` (default two) independent validated direct ICMP echo replies, or when a configured TCP port accepts a connection. With `--count` higher than `--min-replies`, lost packets are tolerated (for example 2 of 5). With `fping`, PingMe runs batch discovery (split into steps on very large scans so progress and `--resume` advance), then validates positive candidates **in parallel** with separate system `ping` processes; malformed or inconsistent replies go to `errors.txt`, never `alive.txt`.

Interactive scans show the graphical subnet/backend interface, live progress, reachable-host events, and final tables. `auto` picks fping when installed without prompting; use `--ping-tool ask` to choose interactively. Use `--compact` for a short summary or `--quiet` for file-only automation; redirected output becomes compact automatically.

---

## 🎯 Accuracy

PingMe is built for engagements where both mistakes are costly: reporting a host that is not there (false positive) and missing one that is (false negative).

**False positives are prevented by design.** A host is REACHABLE only with:
- `--min-replies` (default 2) echo replies from the target itself, each matching a random per-run token and the exact payload that was sent (native engine), or confirmed by separate `ping` processes (fping/ping engines). Replies from other addresses, duplicates, and altered payloads never count; altered payloads become PROBE ERROR.
- or an accepted TCP connection, **unless** the address also accepts two random high "canary" ports (SYN proxy / tarpit), or nearly every scanned address accepts TCP without ever answering ping or ARP (transparent proxy). Those become PROBE ERROR.
- or a fresh (REACHABLE, never STALE) ARP/ND entry for an on-link host, ignoring MACs that answer for several addresses (proxy ARP).

**False negatives are kept rare by retrying.** Silent hosts get `--count` attempts; a host that answered once gets two extra attempts to confirm. Simulated miss rate for a live host (200,000 trials per row):

| Packet loss | PingMe 3.2 default | **3.3 default** | `--count 4` |
|---:|---:|---:|---:|
| 1% | 2.0% | **< 0.001%** | < 0.001% |
| 5% | 9.7% | **0.013%** | 0.001% |
| 10% | 19.0% | **0.11%** | 0.013% |
| 20% | 36.1% | 1.2% | 0.24% |

For the remaining blind spots — hosts that drop ICMP — use `--tcp-ports common` (routed networks) and keep ARP/ND evidence on (local networks). A host that drops ICMP, has no open port, and is not on your LAN cannot be seen by any ping scanner.

Recommended engagement profile:

```bash
pingme scope.txt --tcp-ports common --count 4 --retry 1 --html report.html
```

`tests/test_accuracy.py` enforces the loss table and the false-positive guards on every CI run.

## 🗂️ Repository Structure

```text
pingme/
├── pingme.py                 # the whole scanner (no dependencies)
├── install.py                # launcher + shell completion installer
├── pyproject.toml            # pipx/pip packaging and ruff config
├── repair-windows.ps1
├── README.md
├── RELEASE_NOTES_v3.3.0.md
├── PingMe_v3.0_Manual.pdf
├── LICENSE
├── Dockerfile
├── .github/workflows/ci.yml  # Linux/macOS/Windows tests, real pings, Docker build
├── contrib/
│   ├── systemd/              # pingme-check.service/.timer, pingme-serve.service
│   ├── windows/              # Register-PingMeTask.ps1
│   ├── homebrew/             # formula template
│   └── aur/                  # PKGBUILD template
├── examples/
│   └── targets.txt
└── tests/
    ├── smoke_test.py
    ├── test_reachability.py
    ├── test_improvements.py
    ├── test_ipv6.py
    ├── test_native.py
    ├── test_addons.py
    └── test_accuracy.py
```

Generated during file scans (in the current directory):

```text
hostnames.txt   # Complete HOST/IP/STATUS/METHOD/TTL/RTT/LOSS/OS/REVERSE DNS report
changes.txt     # Newly online, went offline, IP changes
alive.txt       # Currently reachable IPs
dead.txt        # Currently non-responsive IPs
errors.txt      # Probes that failed to run
```

History and baselines go to the per-user data directory (see "Where history is stored").

---

## 🔬 How PingMe Works

```text
Targets
   │
   ├── CIDR
   ├── Direct IP
   ├── Hostname
   └── Target file
          │
          ▼
Hostname resolution (bounded, per-OS)
          │
          ▼
IPv4 / IPv6 address list
          │
          ▼
ICMP discovery ──────┐
                     ├── Reachability decision
TCP fallback ────────┘
          │
          ▼
TTL, RTT, loss, OS estimation + IP → hostname lookup
          │
          ▼
Live scan output
          │
          ▼
HOST | IP | STATUS | METHOD | TTL | RTT | LOSS | OS | REVERSE DNS
          │
          ▼
hostnames.txt / changes.txt / alive.txt / dead.txt + history
```

---

## 🛠️ Troubleshooting

### `pingme` command not found

Linux/macOS:

```bash
python3 install.py
exec zsh
```

Windows:

```powershell
python .\install.py
```

Open a new PowerShell window.

### Verify the running version

```bash
pingme --version
```

### Test the local script directly

Linux/macOS:

```bash
python3 ./pingme.py --help
```

Windows:

```powershell
python .\pingme.py --help
```

### Hostname is unresolved

Linux:

```bash
getent hosts HOSTNAME
ping HOSTNAME
```

Windows:

```powershell
Resolve-DnsName HOSTNAME
ping HOSTNAME
nslookup HOSTNAME
```

Corporate hostnames may require the correct VPN, DNS server, domain suffix, or internal network connection.

### `fping` is missing

```bash
sudo apt install fping
```

PingMe automatically falls back to system `ping`.

### Host appears dead but is online

Use TCP fallback:

```bash
pingme -f endpoints.txt --tcp-ports 22,80,443,445,3389
```

Firewalls commonly block ICMP. On a lossy link, allow a few lost packets:

```bash
pingme -f endpoints.txt --count 5 --min-replies 2
```

### No hostnames in the REVERSE DNS column

Many LAN devices have no DNS PTR record. Install the NetBIOS and mDNS helpers, then try again:

```bash
sudo apt install samba-common-bin avahi-utils
pingme --reverse 192.168.1.0/24
```

### I mistyped an option

PingMe suggests the closest match:

```text
✗ unrecognized arguments: --tpc-ports
Did you mean --tcp-ports?
```

### `changes.txt` shows a first-scan baseline

This is expected on the first run:

```bash
pingme -f endpoints.txt --changes
```

Run the same command again later to see newly online and went-offline systems.

### Save reports in another directory

Create the directory first:

```bash
mkdir -p reports
```

Then run:

```bash
pingme -f endpoints.txt \
  --changes \
  --hostnames-out reports/hostnames.txt \
  --changes-out reports/changes.txt
```

### Windows still runs an older copy

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\repair-windows.ps1
pingme --version
```

---

## 🛡️ Accuracy and Safety

- TTL-based operating-system detection is an estimate, not definitive fingerprinting.
- A no-response result does not always mean a system is powered off.
- `PROBE ERROR` is inconclusive and is never converted to `NO RESPONSE`.
- PingMe fails closed: only direct target evidence can produce `REACHABLE`.
- Firewalls may block ICMP while allowing application traffic.
- IPv6 link-local addresses may require an interface scope identifier.
- Use TCP checks for systems expected to block ICMP.
- Scan only systems and networks you own or are explicitly authorized to assess.

---

## 📘 Detailed Manual

The repository includes:

```text
PingMe_v3.0_Manual.pdf
```

It covers installation, commands, options, workflows, cheatsheets, output formats, file reports, history, troubleshooting, and production usage.

---

## 🤝 Contributing

1. Fork the repository.
2. Create a feature branch.
3. Test on at least one supported platform.
4. Commit the change.
5. Push the branch.
6. Open a pull request.

Keep the core scanner lightweight, dependency-free, and compatible with Python 3.9 or newer.

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Share+Tech+Mono&size=15&duration=2500&pause=850&color=00F7FF&center=true&vCenter=true&width=760&height=85&lines=Built+by+Madhav;Fast+%C2%B7+Accurate+%C2%B7+Cross-platform;Star+the+repo+if+PingMe+helped+you" alt="PingMe animated footer" />

**[⬆ Back to top](#)**

</div>
