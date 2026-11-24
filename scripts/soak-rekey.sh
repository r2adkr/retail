#!/usr/bin/env bash
# Long-running transfer across WireGuard's rekey points (new handshake after
# ~120 s, old keys rejected after ~180 s), on the double-NAT topology of
# e2e-netns.sh. Samples throughput, handshake age and peak memory every 10 s.
#
# Usage: sudo scripts/soak-rekey.sh [BIN_DIR] [SECONDS]   (default 240 s)
set -u
cd "$(dirname "$0")/.."
BIN="$(cd "${1:-target/release}" && pwd)"
DUR="${2:-240}"

KEEP=1 IPERF=0 bash scripts/e2e-netns.sh "$BIN" | tail -1
nsx() { local ns=$1; shift; ip netns exec "$ns" "$@"; }
daemon_pid() { for p in $(ip netns pids "$1"); do [ "$(cat /proc/$p/comm 2>/dev/null)" = retaild ] && echo "$p"; done | head -1; }
PA=$(daemon_pid hA); PB=$(daemon_pid hB)
IP_B=$(nsx hB "$BIN/retail" ip)
hwm() { awk '/^VmHWM/ { printf "%.1f", $2/1024 }' "/proc/$1/status"; }
hs() { nsx "$1" "$BIN/retail" status --json | jq -r '.peers[0].last_handshake_secs // "none"'; }

nsx hB iperf3 -s -D -B "$IP_B" >/dev/null; sleep 0.3
nsx hA iperf3 -c "$IP_B" -t "$DUR" -i 10 -f m --forceflush >/root/soak-iperf.txt 2>&1 &
IPERF_PID=$!
echo "  t(s)  handshake-age A/B (s)  peak RSS A/B (MiB)"
for t in $(seq 10 10 "$DUR"); do
    sleep 10
    printf "%6s  %8s / %-8s     %s / %s\n" "$t" "$(hs hA)" "$(hs hB)" "$(hwm "$PA")" "$(hwm "$PB")"
done
wait "$IPERF_PID"
echo "--- iperf3 intervals (Mbit/s, retransmits)"
grep -E "^\[ *[0-9]+\] +[0-9.]+-[0-9.]+ +sec" /root/soak-iperf.txt | awk '{ printf "%s-%s s: %s %s  retr %s\n", $3, $4, $7, $8, $9 }' | sed 's/-/ /;s/ / -/'
grep -E "sender|receiver" /root/soak-iperf.txt
pkill -x iperf3 || true
