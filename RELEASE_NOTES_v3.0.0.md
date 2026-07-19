# PingMe v3.0.0

PingMe v3.0.0 introduces a more capable network discovery engine, improved host classification, TCP reachability checks, scan history, and a cross-platform installer.

## Highlights

- Added cross-platform `install.py`
- Installs the global `pingme` command
- Automatic shell detection
- Zsh, Bash, Fish, and PowerShell tab completion
- Colored installer output
- Linux, macOS, and Windows support
- IPv4 and IPv6 target support
- Hostname resolution support
- TCP reachability checks with `--tcp-ports`
- ICMP and TCP reachability shown separately
- TTL-based operating-system fingerprinting
- Reverse DNS lookup support
- Scan history and comparison
- Interrupted-scan resume support
- Rate limiting and retry controls
- TXT, CSV, and JSON output
- CIDR expansion safety with `--max-hosts`
- Automatic `fping` or system `ping` backend selection

## Installation

```bash
git clone https://github.com/Madhav-Sai/pingme.git
cd pingme
python3 install.py
exec zsh
```

Verify the installation:

```bash
pingme --help
```

For a user-only installation:

```bash
python3 install.py --user
```

## Examples

```bash
pingme --sub 192.168.1.0/24 --scan
pingme --sub 192.168.1.0/24 --scan --fast
pingme --file targets.txt --dns
pingme --host example.com 10.0.0.10
pingme --file servers.txt --tcp-ports 22,80,443
pingme --sub 192.168.1.0/24 --scan --compare --label office
pingme --ipinfo 8.8.8.8 192.168.1.1
```

## Requirements

- Python 3.9 or newer
- `ping` or `fping`
- No third-party Python packages

> Only scan networks and systems you are authorized to assess.
