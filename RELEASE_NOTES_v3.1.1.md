# PingMe v3.1.1

This is the fail-closed reachability correctness release.

## Correctness and safety fixes

- Requires an explicit echo-reply line from the exact requested IP before ICMP can mark a target `REACHABLE`.
- Rejects Windows `Destination host unreachable` packets even when Windows reports a nonzero `Received` count.
- Requires exact-target per-packet evidence from `fping`; summary counters are no longer sufficient.
- Separates command failures into `PROBE ERROR` and `errors.txt` instead of mislabeling them `NO RESPONSE` or triggering offline alerts.
- Retries the compatible Unix `ping` command when the first option set fails.
- Discards failed resolver-command output and prevents DNS server/error text from becoming scan targets.
- Rejects unspecified, multicast, and limited-broadcast addresses as host targets.
- Corrects TTL-family hints by comparing observed TTL with the next common initial TTL and labels every result as "Likely".
- Uses UTF-8-safe Windows console output in both PingMe and its installer.
- Rejects colliding output paths and creates requested output directories.

## Verification

- 20 deterministic reachability regression tests.
- Cross-platform smoke test covering file resolution, ICMP/TCP scanning, reports, and output files.
- Live Windows verification against a responding loopback address and a non-responding LAN address.

`NO RESPONSE` is not proof that a device is powered off; firewalls and packet loss can suppress replies. `REACHABLE`, however, now requires direct evidence from the requested target (or an explicitly requested TCP connection that was accepted).
