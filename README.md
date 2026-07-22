<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Share+Tech+Mono&size=52&duration=1800&pause=650&color=00F7FF&center=true&vCenter=true&width=760&height=100&lines=PINGME;PING+ME;P+I+N+G+M+E;PINGME+v3.2.2" alt="PingMe animated title" />

<img src="https://readme-typing-svg.demolab.com?font=Share+Tech+Mono&size=19&duration=2400&pause=700&color=BB86FC&center=true&vCenter=true&width=920&height=110&lines=Advanced+Network+Discovery+Scanner;Hostname+%E2%86%92+IP+%E2%86%92+Reachability+Status;hostnames.txt+%C2%B7+changes.txt+%C2%B7+alive.txt+%C2%B7+dead.txt;Linux+%C2%B7+Kali+%C2%B7+macOS+%C2%B7+Windows" alt="PingMe animated subtitle" />

<br/>

[![Version](https://img.shields.io/badge/version-3.2.2-00F7FF?style=for-the-badge&labelColor=0d1117)](#)
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

  Advanced Ping Scanner v3.2.2
  Hostname · IP Address · Reachability · TTL · OS Guess
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

PingMe resolves hostnames, scans every resolved address, displays live progress, saves scan history, and presents a final status table showing:

```text
HOST | IP ADDRESS | STATUS | METHOD | TTL | OS GUESS
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

---

## 🎬 Animated Demo

<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Share+Tech+Mono&size=15&duration=65&pause=1200&color=39FF14&center=true&vCenter=false&multiline=true&width=1080&height=235&lines=%24+pingme+-f+endpoints.txt;HOST+RESOLUTION+%C2%B7+endpoints.txt;DSIN10329+%E2%86%92+10.100.6.53;FILE+SCAN+STATUS+%C2%B7+endpoints.txt;DSIN10329+%7C+10.100.6.53+%7C+REACHABLE+%7C+ICMP+%7C+TTL+128+%7C+Windows" alt="PingMe animated terminal demo" />

</div>

Example final output:

```text
FILE SCAN STATUS · endpoints.txt

+--------------+-----------------+--------------+----------+-------+------------+
| HOST         | IP ADDRESS      | STATUS       | METHOD   | TTL   | OS GUESS   |
+--------------+-----------------+--------------+----------+-------+------------+
| DSIN10329    | 10.100.6.53     | REACHABLE    | ICMP     | 128   | Windows    |
| DSIN10343    | 10.100.6.12     | NO RESPONSE  | -        | ?     | Unknown    |
| web01        | 10.100.6.90     | REACHABLE    | TCP:443  | ?     | Unknown    |
+--------------+-----------------+--------------+----------+-------+------------+

Reachable: 2  No response: 1  Unresolved: 0
```

---

## ✨ Features

<div align="center">

| 🌐 Target Handling | 🔍 Discovery | 📊 Reporting |
|:---:|:---:|:---:|
| CIDR, IP, hostname, file | ICMP with `ping` or `fping` | Hostname → IP resolution table |
| IPv4 and IPv6 | Optional TCP reachability | Reachable / no-response status |
| Duplicate removal | Reverse DNS | TTL and OS guess |
| Inline comments in files | Retry and rate limiting | `hostnames.txt`, `changes.txt`, alive/dead reports |

| 📜 History | ⚙️ CLI Experience | 🛡️ Safety |
|:---:|:---:|:---:|
| Automatic scan history | Nested help topics | CIDR expansion limit |
| Simple `--changes` tracking | Colored flags and output | Validated ports and ranges |
| Resume interrupted scans | Bash/Zsh/Fish/PowerShell completion | Thread and timeout limits |
| Snapshot diff mode | Cross-platform installer | Graceful error handling |

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
pingme 3.2.2
```

---

## ⌨️ Automatic Tab Completion

PingMe installs completion for:

- Zsh
- Bash
- Fish
- PowerShell

Examples:

```bash
pingme --<TAB>
pingme help <TAB>
pingme --ping-tool <TAB>
pingme --out-format <TAB>
```

Completion suggestions include:

```text
auto  fping  ping
txt   csv    json
targets  scan  discovery  output  history  advanced  examples
```

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

---

## 📖 Usage

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

When nothing changed:

```text
CHANGES SINCE LAST SCAN · endpoints.txt

No changes detected.

Online     : 7
Offline    : 2
Unresolved : 0
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

### 6. Reverse DNS

```bash
pingme --host 10.10.10.10 --dns
pingme -f endpoints.txt --dns
```

### 7. IPv6

```bash
pingme --host 2001:db8::10
pingme --sub 2001:db8:1234::/120 --scan
```

Large IPv6 networks are protected by `--max-hosts`.

### 8. IP classification

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

### `hostnames.txt`

Stores the complete current file-scan report:

```text
HOST | IP ADDRESS | STATUS | METHOD | TTL | OS GUESS
```

### `changes.txt`

Stores only the changes since the previous run using the same target file:

```text
NEWLY ONLINE
WENT OFFLINE
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
```

---

## 🎛️ Complete Option Reference

### Targets and modes

```text
-s, --sub CIDR
    Show subnet information. Add --scan to scan it.

-f, --file FILE
    Resolve and scan IP addresses or hostnames from a file.

--host HOST [HOST ...]
    Resolve and scan one or more direct targets.

--ipinfo IP [IP ...]
    Classify addresses as public, private, loopback, and more.

--diff FILE_A FILE_B
    Compare two host snapshot files.

--history
    List stored scan history.

--clear-history LABEL
    Delete history for one label.
```

### Discovery and scan control

```text
--scan
    Start scanning a CIDR. Implied by --file and --host.

-t, --threads N
    Number of concurrent workers. Default: 20.

--timeout SEC
    Per-packet wait time. Default: 2.

--count N
    Packets sent per host. Default: 2.

--tcp-ports PORTS
    TCP ports or ranges, such as 22,80,443 or 8000-8010.

--tcp-timeout SEC
    TCP connection timeout. Default: 2.

--retry N
    Retry hosts that did not respond.

--rate PPS
    Maximum packet rate. 0 means unlimited.

--dns
    Perform reverse DNS for reachable hosts.

--resume
    Continue an interrupted scan.

--ping-tool auto|fping|ping
    Select the ICMP backend.

--fast
    Use 100 threads, one-second timeout, and one packet.

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
    Save the complete file-scan report containing HOST, IP ADDRESS,
    STATUS, METHOD, TTL, and OS GUESS. Default: hostnames.txt.

--changes-out FILE
    Save newly-online and went-offline changes. Default: changes.txt.

--changes
    Compare the current file scan with the previous --changes run and
    update changes.txt.

--out-format txt|csv|json
    Select the alive/dead output format.

--label NAME
    Custom history label.

--quiet
    Write result files without normal terminal output.

--compact
    Show only the final summary and saved file paths.

--verbose
    Force diagnostic tables and live progress when output is redirected.

--no-banner
    Hide the ASCII banner.

--no-history
    Do not store the scan.

--compare
    Advanced history comparison using the selected history label.
```

### Help

```text
-h, --help
--help-all
--help-topic TOPIC
help TOPIC
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
  --retry 1 \
  --dns
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
pingme --help
pingme --help-all
pingme help examples

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
| Count | `2` | Confirms responses without excessive delay |
| TCP timeout | `2s` | Keeps fallback checks practical |
| Maximum CIDR targets | `65,536` | Prevents accidental huge expansion |

A target is reachable only after two independent validated direct ICMP echo confirmations or a configured TCP port accepts a connection. With `fping`, PingMe performs one batch discovery process and then validates positive candidates serially with separate system `ping` processes; malformed or inconsistent replies go to `errors.txt`, never `alive.txt`.

Interactive scans show the graphical subnet/backend interface, live progress, reachable-host events, and final tables. When both backends exist, `auto` asks which one to use. Use `--compact` for a two-line summary or `--quiet` for file-only automation; redirected output becomes compact automatically.

---

## 🗂️ Repository Structure

```text
pingme/
├── pingme.py
├── install.py
├── repair-windows.ps1
├── README.md
├── RELEASE_NOTES_v3.2.2.md
├── PingMe_v3.0_Manual.pdf
├── LICENSE
├── examples/
│   └── targets.txt
├── tests/
│   └── smoke_test.py
└── data/
    └── scan-history.json
```

Generated during file scans:

```text
hostnames.txt   # Complete HOST/IP/STATUS/METHOD/TTL/OS report
changes.txt     # Newly online and went-offline changes
alive.txt       # Currently reachable IPs
dead.txt        # Currently non-responsive IPs
data/<label>.json
```

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
Hostname resolution
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
TTL and OS estimation
          │
          ▼
Live scan output
          │
          ▼
HOST | IP | STATUS | METHOD | TTL | OS
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

Firewalls commonly block ICMP.

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
