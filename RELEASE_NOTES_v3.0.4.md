# PingMe v3.0.4

PingMe v3.0.4 is the stable cross-platform file-status release.

## Major improvements

- Added a clear `HOST RESOLUTION` table for file-based scans.
- Added a final `FILE SCAN STATUS` table containing:
  - Original hostname
  - Resolved IP address
  - Reachability status
  - ICMP or TCP detection method
  - TTL
  - TTL-based OS estimate
- Added explicit `NO RESPONSE` rows so dead hosts are visible without opening `dead.txt`.
- Added explicit `UNRESOLVED` rows for names that cannot be resolved.
- Preserved multiple IPv4/IPv6 resolutions for the same hostname.
- Improved Windows internal-hostname resolution and Windows installation verification.
- Added a Windows stale-install repair helper.
- Retained Linux/Kali/macOS compatibility with `fping` and system `ping`.
- Added grouped colorful help and nested help topics.
- Added Zsh, Bash, Fish, and PowerShell completion through `install.py`.

## Installation

```bash
python3 install.py
```

Windows PowerShell:

```powershell
python .\install.py
```

Windows repair, when required:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\repair-windows.ps1
```

## Verification

```text
pingme --version
pingme -f targets.txt
```

Expected version:

```text
pingme 3.0.4 (cross-platform-file-status-final)
```
