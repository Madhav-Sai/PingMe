# PingMe 3.2.3 — bounded Linux resolution

- Replaces blocking in-process Linux hostname resolution with a timed `getent ahosts` subprocess.
- Enforces a four-second deadline for every hostname resolution attempt.
- Displays resolution activity immediately so the terminal never appears silently frozen.
- Supports portable explicit file mappings: `IP HOST`, `HOST,IP`, and `IP,HOST`.
- Cleanly rejects directories passed to `--file`.
- Retains strict two-confirmation reachability and the interactive graphical UI.
