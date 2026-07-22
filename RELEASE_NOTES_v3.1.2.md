# PingMe v3.1.2

This release closes an `fping -c` false-positive path found during Kali validation.

## Fix

An ICMP error packet can produce an exact-target count-mode line containing a byte count. PingMe 3.1.1 accepted that line before consulting fping's final result, so unreachable targets could be labeled `REACHABLE` with `TTL=?`.

The fping backend now requires all three signals for its single-target probe:

1. An exact-target per-packet response line.
2. Exact-target count statistics with `rcv > 0`.
3. fping exit status `0`.

Any missing or contradictory signal fails closed. This matches fping's documented exit semantics and prevents ICMP error packets from becoming live hosts.

## Verification

- 23 deterministic reachability regression tests.
- Regression coverage for deceptive byte-count ICMP-error lines, zero-receive summaries, and exit-status disagreement.
- Full cross-platform smoke test.
