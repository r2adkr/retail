#!/usr/bin/env bash
# Runs bench.sh N times (default 3) and prints per-implementation averages,
# to see past run-to-run variance.
# Usage: sudo scripts/bench-repeat.sh [N] [BIN_DIR]
cd "$(dirname "$0")/.."
N="${1:-3}"
OUT=$(mktemp)
for i in $(seq "$N"); do
    echo "--- run $i"
    KERNEL="${KERNEL:-0}" bash scripts/bench.sh "${2:-target/release}" 2>&1 \
        | grep -E '^(retail|wireguard-go|kernel WireGuard|underlay) ' | tee -a "$OUT"
done
echo "--- average of $N runs (Mbit/s)"
awk '
    /^underlay/ { next }
    {
        name = ($1 == "kernel") ? "kernel WireGuard" : $1
        for (i = 1; i <= NF; i++) {
            if ($i == "stream")  one[name] += $(i+1)
            if ($i == "reverse") rev[name] += $(i+1)
            if ($i == "streams") four[name] += $(i+1)
        }
        n[name]++
    }
    END { for (k in n) printf "%-16s 1 stream %6.0f | reverse %6.0f | 4 streams %6.0f\n", k, one[k]/n[k], rev[k]/n[k], four[k]/n[k] }
' "$OUT"
rm -f "$OUT"
