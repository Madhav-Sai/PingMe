<div align="center">

# PINGME

### Advanced ICMP/TCP Host Discovery and Subnet Scanner

**PingMe v3.0.4** · Linux · Kali · Parrot · Arch · macOS · Windows

</div>

PingMe is a zero-Python-dependency network discovery utility for subnet analysis, hostname resolution, ICMP/TCP reachability checks, scan history, comparison, resume support, and IP classification.

> Use PingMe only against networks and systems you own or are explicitly authorized to assess.

## Highlights

- Cross-platform `install.py` with a global `pingme` command.
- Automatic tab completion for Zsh, Bash, Fish, and PowerShell.
- Grouped colorful help and nested help topics.
- IPv4 and IPv6 target support.
- Hostname and target-file resolution.
- File results retain the original hostname beside every resolved IP.
- Final `FILE SCAN STATUS` table shows reachable, no-response, and unresolved hosts.
- ICMP discovery using `fping` or the operating-system `ping` command.
- Optional TCP reachability checks for hosts that block ICMP.
- TTL-based operating-system estimation.
- Reverse DNS, retries, rate limiting, exclusions, and resume support.
- TXT, CSV, and JSON output.
- Scan history, comparison, and snapshot diffing.

## Repository contents

```text
PingMe-v3.0.4/
├── pingme.py
├── install.py
├── repair-windows.ps1
├── README.md
├── RELEASE_NOTES_v3.0.4.md
├── LICENSE
├── .gitignore
├── docs/
│   └── PingMe_v3.0_Manual.pdf
├── examples/
│   └── targets.txt
└── tests/
    └── smoke_test.py
```

## Installation

### Kali, Debian, Ubuntu, Parrot

```bash
sudo apt update
sudo apt install -y python3 iputils-ping fping

git clone https://github.com/Madhav-Sai/pingme.git
cd pingme
python3 install.py
exec zsh   # use exec bash when Bash is your shell
```

User-only installation:

```bash
python3 install.py --user
```

### Arch Linux

```bash
sudo pacman -S --needed python iputils fping
python3 install.py
```

### macOS

```bash
brew install python fping
python3 install.py
exec zsh
```

### Windows PowerShell

```powershell
python .\install.py
```

Open a new PowerShell window after installation. If Windows is still launching a stale copy, use:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\repair-windows.ps1
```

Verify:

```text
pingme --version
pingme --help
```

Expected version:

```text
pingme 3.0.4 (cross-platform-file-status-final)
```

## File-based hostname scanning

Create `hosts.txt`:

```text
# Internal endpoints
DSIN10329
DSIN10343
192.168.1.10
```

Run:

```bash
pingme -f hosts.txt
```

PingMe first displays hostname resolution:

```text
HOST RESOLUTION · hosts.txt
+------------+---------------+-----------+
| HOST       | IP ADDRESS    | TYPE      |
+------------+---------------+-----------+
| DSIN10329  | 10.100.6.53   | DNS       |
| DSIN10343  | 10.100.6.12   | DNS       |
| 192.168.1.10 | 192.168.1.10 | DIRECT IP |
+------------+---------------+-----------+
```

After discovery it displays the final status table:

```text
FILE SCAN STATUS · hosts.txt
+------------+---------------+-------------+---------+-----+-----------+
| HOST       | IP ADDRESS    | STATUS      | METHOD  | TTL | OS GUESS  |
+------------+---------------+-------------+---------+-----+-----------+
| DSIN10329  | 10.100.6.53   | REACHABLE   | ICMP    | 128 | Windows   |
| DSIN10343  | 10.100.6.12   | NO RESPONSE | -       | ?   | Unknown   |
| bad-host   | UNRESOLVED    | UNRESOLVED  | -       | -   | -         |
+------------+---------------+-------------+---------+-----+-----------+
```

A hostname can appear more than once when it resolves to both IPv4 and IPv6. Each address is tested independently.

For systems that block ICMP, add TCP ports:

```bash
pingme -f hosts.txt --tcp-ports 22,80,135,139,443,445,3389
```

## Nested help

```bash
pingme --help
pingme --help-all
pingme help targets
pingme help scan
pingme help discovery
pingme help output
pingme help history
pingme help advanced
pingme help examples
```

The equivalent topic form is:

```bash
pingme --help-topic scan
```

## Common usage

Subnet information only:

```bash
pingme --sub 192.168.1.0/24
```

Subnet discovery:

```bash
pingme --sub 192.168.1.0/24 --scan
```

Fast LAN discovery:

```bash
pingme --sub 192.168.1.0/24 --scan --fast
```

Direct hosts:

```bash
pingme --host server01.example.local 10.0.0.10
```

Reverse DNS and TCP discovery:

```bash
pingme -f targets.txt --dns --tcp-ports 22,80,443,445,3389
```

Retries and rate limiting:

```bash
pingme --sub 10.10.0.0/24 --scan --retry 2 --rate 100
```

Exclude addresses or networks:

```bash
pingme --sub 10.10.0.0/24 --scan --exclude 10.10.0.1 10.10.0.128/28
```

Output formats:

```bash
pingme -f targets.txt --out-format txt
pingme -f targets.txt --out-format csv --alive-out alive.csv --dead-out dead.csv
pingme -f targets.txt --out-format json --alive-out alive.json --dead-out dead.json
```

History comparison:

```bash
pingme -f targets.txt --label office --compare
pingme --history
pingme --clear-history office
```

Snapshot diff:

```bash
pingme --diff alive-old.txt alive-new.txt
```

IP classification:

```bash
pingme --ipinfo 8.8.8.8 192.168.1.1 100.64.0.1 127.0.0.1
```

## Options overview

### Targets

```text
-s, --sub CIDR
-f, --file FILE
--host HOST [HOST ...]
--exclude IP/CIDR [IP/CIDR ...]
--max-hosts N
```

### Discovery

```text
--scan
--dns
--tcp-ports PORTS
--tcp-timeout SEC
--ipinfo IP [IP ...]
```

### Scan control

```text
-t, --threads N
--timeout SEC
--count N
--retry N
--rate PPS
--ping-tool auto|fping|ping
--fast
--resume
```

### Output and history

```text
--alive-out FILE
--dead-out FILE
--out-format txt|csv|json
--label NAME
--quiet
--no-banner
--history
--compare
--diff A B
--clear-history NAME
--no-history
```

## Output files

By default PingMe creates:

```text
alive.txt
dead.txt
data/<label>.json
```

`alive.txt` contains reachable IP addresses. `dead.txt` contains addresses that did not respond to ICMP or requested TCP checks. In file mode, the terminal `FILE SCAN STATUS` table preserves the hostname-to-IP relationship.

## Accuracy notes

- `NO RESPONSE` does not always mean a system is powered off. A firewall may block ICMP and the selected TCP ports.
- Use `--tcp-ports` when assessing hardened endpoints.
- TTL fingerprinting is an estimate, not authoritative operating-system detection.
- `fping` is preferred for large Linux/macOS scans, but the built-in `ping` command is supported.
- Windows does not normally include `fping`; PingMe automatically uses Windows `ping`.

## Testing

Run the bundled smoke test:

```bash
python3 tests/smoke_test.py
```

On Windows:

```powershell
python .\tests\smoke_test.py
```

The test checks compilation, version output, nested help, subnet/IP information, target-file mapping, TCP reachability, and the final file status table.

## Documentation

The detailed manual is available at:

```text
docs/PingMe_v3.0_Manual.pdf
```

## License

MIT License. See `LICENSE`.
