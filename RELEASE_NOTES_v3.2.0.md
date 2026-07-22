# PingMe 3.2.0 — batch automation

- Replaces concurrent per-host `fping` processes with one batch discovery process.
- Serially integrity-confirms every `fping`-positive target using system `ping`.
- Keeps malformed, corrupt, or inconsistent ICMP replies out of `alive.txt` and records them in `errors.txt`.
- Removes the interactive backend prompt; `auto` deterministically prefers `fping` and falls back to system `ping`.
- Makes scan output compact by default; `--verbose` enables diagnostic tables and progress.
- Changes normal scan defaults to two packets with a two-second timeout.
- Supports direct single-target scans with `pingme --host IP`.
