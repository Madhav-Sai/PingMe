# PingMe 3.2.1 — strict rich UI

- Replaces concurrent per-host `fping` processes with one batch discovery process.
- Requires at least two independent system `ping` confirmations for every ICMP-positive target.
- Keeps malformed, corrupt, or inconsistent replies out of `alive.txt` and records them in `errors.txt`.
- Restores backend selection when both tools exist in an interactive terminal.
- Restores the graphical subnet display, live progress, reachable-host events, and final result tables.
- Adds `--compact` for a two-line summary and keeps `--quiet` for file-only automation.
- Uses two packets and a two-second timeout by default.
- Supports direct single-target scans with `pingme --host IP`.
