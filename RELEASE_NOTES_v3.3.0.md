# PingMe 3.3.0 — reliable, cross-platform, and easier to use

## Easier to use
- Plain targets: `pingme 192.168.1.0/24`, `pingme hosts.txt`, `pingme server01`. Each argument is detected as a subnet, file, or host, and a scan is implied.
- New short `-h` help with everyday examples. `pingme help <topic>` gains `config` and `exitcodes` topics, and `--help-all` lists every option.
- Mistyped options and help topics get a "did you mean" suggestion.
- Config file for your own defaults (`pingme --init-config`, `--config`, `--no-config`).
- `--color auto|always|never`, and `NO_COLOR` is honoured.
- Out-of-range values (for example `--threads 0`) are reported instead of silently clamped.
- `--ping-tool auto` no longer prompts on every interactive run. Use `--ping-tool ask` to choose interactively.

## New features
- **IP → hostname for every scanned address.** Uses DNS PTR, the hosts file and NSS, plus mDNS and NetBIOS for LAN hosts that answered. On automatically for up to 1,024 targets; `--dns` / `--no-dns` override it.
- `-r, --reverse IP/CIDR` looks up hostnames without pinging.
- **IPv6:**
  - `--discover6 [IFACE ...]` finds hosts on local links through all-nodes/all-routers multicast and the OS neighbor cache (Linux, macOS, Windows), then confirms each one.
  - `-4` / `-6` restrict resolution and scanning to one address family.
  - `[2001:db8::1]` bracketed addresses are accepted, and link-local addresses without `%interface` get a clear error listing your interfaces instead of a silent NO RESPONSE.
  - `--ipinfo` classifies documentation, ULA, 6to4, Teredo, NAT64, and IPv4-mapped ranges, shows embedded IPv4 addresses, and recovers the MAC behind EUI-64 interface IDs.
  - BSD/macOS hop limits (`hlim=`) are read as TTL, and mixed IPv4/IPv6 results sort numerically.
  - The /64 "too many targets" error now points to `--discover6`.
- `--watch SEC` rescans on an interval and prints one line per status change.
- `--min-replies N` sets the number of replies required, so `--count 5 --min-replies 2` accepts a lossy host.
- RTT (min/avg) and packet-loss columns in tables, CSV, and JSON.
- `changes.txt` reports hosts whose IP address changed instead of listing them as removed plus added.
- Fractional `--timeout` and `--tcp-timeout` values (for example `0.5`).
- Status tables for `--host` and subnet scans (LIVE HOSTS), not only for file scans.
- Exit codes: 0 all up / host found, 1 down or unresolved, 2 usage, 3 no ping tool, 4 probe errors, 130 interrupted. `--exit-zero` keeps the old behaviour.
- `pyproject.toml` (`pipx install .`) and GitHub Actions CI on Linux, macOS, and Windows.

## Engines and accuracy
- **Native ICMP engine** (`--ping-tool native`, default on Linux): one socket instead of a `ping` process per host. Replies must come from the target and carry this run's random token and the exact payload; duplicates are ignored and altered payloads become PROBE ERROR. Requests are spread over a pool of sockets so unresolved LAN neighbours cannot stall sending.
- fping output is streamed, so positives are confirmed while the sweep continues.
- `--timeout auto` adapts the wait to measured round-trip times (native engine).
- Target files resolve hostnames in parallel (16 at a time) instead of one after another.

## LAN visibility
- MAC address and vendor for on-link hosts (neighbor table + nmap/IEEE OUI databases, built-in fallback, `--update-oui`).
- Fresh ARP/ND replies count as reachability evidence for hosts that drop ICMP (REACHABLE entries only; proxy-ARP MACs ignored; `--no-arp` disables).
- `--changes` reports MAC changes (replaced device or IP conflict) and reverse-DNS name changes.

## Alerts and integrations
- `--notify` for Slack, Microsoft Teams, Discord, Telegram (`telegram://TOKEN@CHAT`), e-mail (`mailto:` + `PINGME_SMTP_*`), and generic JSON webhooks; `--notify-on changes|down|always`; watch mode alerts on transitions only.
- `--html` self-contained report with summary, filters, sortable columns, and uptime.
- `--uptime LABEL|FILE` availability, flaps, and last-seen per host from history.
- `--serve [HOST:]PORT` long-running exporter with Prometheus `/metrics`, `/api/results`, `/healthz`, and a live page.
- `--trace-down` explains where the path to each down host stops.
- Wake-on-LAN: `--wol MAC` and `--wake` (down hosts with a known MAC).
- nmap XML: import `-oX` files as target lists, export with `--nmap-xml`.
- `@tags` in target files with `--tag`, `--column` for CSV inventories, TCP port presets (`web`, `windows`, `linux`, `mail`, `db`, `printers`, `network`, `common`).
- SIGTERM stops `--watch` and `--serve` cleanly (systemd, Docker).
- Dockerfile, systemd service/timer units, Windows scheduled-task script, Homebrew and AUR templates.

## Bug fixes
- `--rate` below `--count` hung forever (the token bucket could never hold the requested packets).
- macOS/BSD: `ping -W` was given seconds but expects milliseconds, so live hosts were reported as down.
- macOS/BSD: ping exit status 2 ("no reply") was reported as PROBE ERROR instead of NO RESPONSE.
- `--count N` required all N replies, so one lost packet marked a host down. `--count` now means attempts.
- fping mode confirmed positives and ran TCP checks one host at a time, ignoring `--threads`.
- Ctrl+C in fping mode (the default) printed a traceback and `--resume` could never continue it.
- fping mode showed no progress until the whole sweep finished. Large scans now advance in steps.
- The progress bar recounted every result on every update (quadratic time on large scans).
- Retries ran one at a time on the main thread, blocking every other result.
- TCP ports were tried one after another. They are now tried concurrently per host.
- `--compare` counted probe errors as "went offline", and compared against the wrong scan with `--no-history`.
- A file with no resolvable targets wrote `hostnames.txt` even when `--hostnames-out` was given.
- Resolver output from non-English Windows could be decoded as UTF-16 garbage, losing the address.
- `--diff` compared raw lines of CSV/JSON results. It now reads the IP column.
- Hostnames beginning with `-` were passed to `ping`/`getent`/`nbtstat` as options (for example `-t` made Windows ping run forever). They are now rejected.
- `--quiet` still printed resolution progress. `--compact` printed the full change report.
- Scan state was written to `./data` in whatever directory PingMe ran from. It now lives in a per-user data directory; existing `./data` baselines are still read.
- Target files with the same name in different folders shared a `--changes` baseline.
- History files grew without limit. They now keep the newest 50 scans per label (`--keep`).
- State files are written atomically, so an interrupted write cannot corrupt history.
- Long labels (many hosts, subnets, or interfaces) produced state filenames over the OS limit and crashed the save. Labels are now shortened with a hash.
- Invalid `--sub` CIDRs and missing `--diff` files now exit with the usage status (2), and the banner no longer appears in piped output.
- Closing a pipe early (`pingme ... | head`) no longer raises `BrokenPipeError`.
