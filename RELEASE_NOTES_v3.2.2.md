# PingMe 3.2.2 — portable host mapping

- Adds portable explicit file mappings: `IP HOST`, `HOST,IP`, and `IP,HOST`.
- Keeps automatic DNS/NSS/Windows name resolution for hostname-only entries.
- Cleanly rejects directories passed to `--file` instead of showing a traceback.
- Requires at least two independent system `ping` confirmations for every ICMP-positive target.
- Keeps the interactive graphical interface, backend selection, and live progress.
- Provides `--compact` and `--quiet` automation modes.
