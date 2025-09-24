#!/usr/bin/env bash
# Short fping scan: ./ping_scan_fping.sh --sub 192.160.0.1/24
set -euo pipefail

usage(){ cat <<USAGE
Usage: $0 --sub <CIDR>
Example: $0 --sub 192.168.1.0/24
Outputs: alive.txt dead.txt
USAGE
}

# parse args
SUB=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -s|--sub) SUB="${2:-}"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 2;;
  esac
done

[[ -n "$SUB" ]] || { echo "Missing --sub"; usage; exit 2; }

command -v fping >/dev/null 2>&1 || { echo "fping required"; exit 3; }
command -v python3 >/dev/null 2>&1 || { echo "python3 required"; exit 4; }

TD=$(mktemp -d)
ALL="$TD/all.txt"
ALIVE_TMP="$TD/alive.tmp"

# generate host list (python handles CIDR validation)
python3 - <<PY > "$ALL"
import sys,ipaddress
try:
    net = ipaddress.ip_network(sys.argv[1], strict=False)
except Exception as e:
    print("Invalid CIDR:", e, file=sys.stderr); sys.exit(2)
for ip in net.hosts(): print(ip)
PY "$SUB"

# fping: -a prints alive; -g expands CIDR
fping -a -g "$SUB" 2>/dev/null | sort -V -u > "$ALIVE_TMP" || true

sort -V -u "$ALIVE_TMP" > alive.txt || true
grep -Fxv -f alive.txt "$ALL" | sort -V -u > dead.txt || true

rm -rf "$TD"
echo "Done. Alive: $(wc -l < alive.txt) | Dead: $(wc -l < dead.txt)"
