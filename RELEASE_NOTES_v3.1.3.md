# PingMe v3.1.3

This release handles malformed or spoofed ICMP echo traffic observed during real Kali validation.

## Observed network behavior

The Linux `ping` command received packets claiming to originate from every target, but reported `wrong data byte`, invalid timestamp fields, duplicate replies, and impossible clock values. Those packets did not contain the payload transmitted by the probe and therefore were not valid reachability evidence.

## Strict validation changes

- Rejects iputils `wrong data byte` and `invalid tv_usec` integrity failures.
- Reports malformed replies as `PROBE ERROR`, never `REACHABLE`.
- Uses fping's normal `-a` alive-discovery mode instead of `-c` count mode.
- Requires exact-address alive output and fping exit status `0`.
- Independently confirms every fping-positive through system ping payload validation.
- Treats disagreement between fping and the confirmation probe as inconclusive.

## Verification

- 26 deterministic reachability and reporting regression tests.
- Exact regression coverage derived from the captured Kali malformed-reply output.
- Full cross-platform smoke test.
