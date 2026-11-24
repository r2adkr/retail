#!/usr/bin/env bash
# Throughput comparison over the double-NAT namespace topology of e2e-netns.sh.
# Each tunnel gets a 1-stream, reverse and 4-stream iperf3 run from hA to hB.
#
#   underlay          plain TCP from hA through its NAT, no tunnel
#   retail            also peak RSS, offload and batching stats from the logs
#   wireguard-go      Tailscale's userspace engine with GSO/GRO (needs
#                     wireguard-go and wireguard-tools)
#   kernel WireGuard  in-kernel reference (needs wireguard-tools)
#
# Usage: sudo scripts/bench.sh [BIN_DIR]     (default: target/release)
#   SECONDS_IPERF=10   duration of each iperf3 run
#   WGGO=0             skip the wireguard-go reference
#   KERNEL=0           skip the kernel WireGuard reference
set -euo pipefail

BIN="$(cd "${1:-target/release}" && pwd)"
WORK=/tmp/retail-bench
T="${SECONDS_IPERF:-10}"

nsx() { local ns=$1; shift; ip netns exec "$ns" "$@"; }
cli() { local s=$1; shift; ip netns exec "h$s" env RETAIL_API_TOKEN_FILE="$WORK/$s.token" "$BIN/retail" "$@"; }

cleanup() {
    pkill -f "$BIN/retaild" 2>/dev/null || true
    pkill -x iperf3 2>/dev/null || true
    for _ in $(seq 50); do pgrep -f "$BIN/retaild" >/dev/null || break; sleep 0.1; done
    for ns in hA hB rA rB; do ip netns del "$ns" 2>/dev/null || true; done
    ip link del inetA 2>/dev/null || true
    ip link del inetB 2>/dev/null || true
    iptables -D FORWARD -i inetA -o inetB -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i inetB -o inetA -j ACCEPT 2>/dev/null || true
}
trap cleanup EXIT
cleanup
rm -rf "$WORK" && mkdir -p "$WORK"

for ns in hA hB rA rB; do ip netns add "$ns"; nsx "$ns" ip link set lo up; done
sysctl -qw net.ipv4.ip_forward=1
setup_site() {
    local s=$1 wan=$2 lan=$3
    ip link add "inet$s" type veth peer name "wan$s"
    ip link set "wan$s" netns "r$s"
    ip addr add "$wan.1/24" dev "inet$s" && ip link set "inet$s" up
    nsx "r$s" ip addr add "$wan.2/24" dev "wan$s"
    nsx "r$s" ip link set "wan$s" up
    nsx "r$s" ip route add default via "$wan.1"
    ip link add "lan$s" netns "r$s" type veth peer name eth0 netns "h$s"
    nsx "r$s" ip addr add "$lan.1/24" dev "lan$s"
    nsx "r$s" ip link set "lan$s" up
    nsx "h$s" ip addr add "$lan.10/24" dev eth0
    nsx "h$s" ip link set eth0 up
    nsx "h$s" ip route add default via "$lan.1"
    nsx "r$s" sysctl -qw net.ipv4.ip_forward=1
    nsx "r$s" iptables -t nat -A POSTROUTING -o "wan$s" -j MASQUERADE
    for chain in FORWARD INPUT; do
        nsx "r$s" iptables -A "$chain" -i "wan$s" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        nsx "r$s" iptables -A "$chain" -i "wan$s" -j DROP
    done
}
setup_site A 198.51.100 192.168.1
setup_site B 198.51.101 192.168.2
iptables -I FORWARD 1 -i inetA -o inetB -j ACCEPT
iptables -I FORWARD 1 -i inetB -o inetA -j ACCEPT

# Prints received Mbit/s of one iperf3 run from hA, or ERR after two failed attempts
bw() {  # target [iperf args...]
    local ip=$1; shift
    for attempt in 1 2; do
        local out
        out=$(nsx hA iperf3 -c "$ip" -t "$T" -J "$@" 2>&1 || true)
        if echo "$out" | jq -e '.end.sum_received.bits_per_second' >/dev/null 2>&1; then
            [ "$#" -eq 0 ] && echo "$out" >"$WORK/last-single.json"
            echo "$out" | jq -r '.end.sum_received.bits_per_second / 1e6 | floor'
            return
        fi
        echo "iperf3 attempt $attempt failed: $(echo "$out" | jq -r '.error // empty' 2>/dev/null)" >&2
        sleep 1
    done
    echo "ERR"
}

# Prints one line per iperf3 test. Given the two endpoint PIDs, also samples
# their per-thread CPU and B's write() calls during the 1-stream run
run_suite() {  # label target_ip [pid_a] [pid_b]
    local label=$1 ip=$2
    rm -f "$WORK/top.txt" "$WORK/syscw.txt" "$WORK/cpu.txt" "$WORK/last-single.json"
    nsx hB iperf3 -s -D -B "$ip" >/dev/null; sleep 0.3
    (sleep 2; echo "$(cpu_busy 3)" >"$WORK/cpu.txt") &
    if [ -n "${3:-}" ]; then
        (sleep 3; top -H -b -d 2 -n 2 -p "$3,$4" | awk '/^ *PID/ {n++} n==2 && $9+0 > 3 { printf "      %-16s %5s%%  (pid %s)\n", $12, $9, $1 }' >"$WORK/top.txt") &
    fi
    local one rev four w0
    [ -n "${4:-}" ] && w0=$(awk '/^syscw/ {print $2}' "/proc/$4/io")
    one=$(bw "$ip")
    [ -n "${4:-}" ] && echo "$(( $(awk '/^syscw/ {print $2}' "/proc/$4/io") - w0 ))" >"$WORK/syscw.txt"
    rev=$(bw "$ip" -R)
    four=$(bw "$ip" -P 4)
    pkill -x iperf3 || true; sleep 0.3
    printf "%-16s 1 stream %6s Mbit/s | reverse %6s Mbit/s | 4 streams %6s Mbit/s | CPU busy %s%% (1-stream, all cores)\n" \
        "$label" "$one" "$rev" "$four" "$(cat "$WORK/cpu.txt" 2>/dev/null)"
    jq -r '.end.streams[0].sender | "    TCP (1 stream): mean RTT \(.mean_rtt) us, max RTT \(.max_rtt) us, max cwnd \(.max_snd_cwnd / 1024 | floor) KiB"' \
        "$WORK/last-single.json" 2>/dev/null || true
    if [ -s "$WORK/syscw.txt" ]; then
        local pkts
        pkts=$(jq -r '.end.sum_received.bytes / 1280 | floor' "$WORK/last-single.json")
        echo "    receiver write() calls during 1-stream run: $(cat "$WORK/syscw.txt") for ~$pkts packets"
    fi
    if [ -s "$WORK/top.txt" ]; then echo "    busiest threads during 1-stream run (A=sender, B=receiver):"; cat "$WORK/top.txt"; fi
}

iperf3 -s -D -B 198.51.100.1 >/dev/null; sleep 0.3
plain=$(bw 198.51.100.1)
pkill -x iperf3 || true; sleep 0.3
printf "%-16s 1 stream %6s Mbit/s  (plain TCP through one NAT, MTU 1500, no encryption)\n" "underlay" "$plain"

# System-wide CPU busy % over the next $1 seconds
cpu_busy() {
    read -r _ a1 b1 c1 d1 e1 f1 g1 _ < /proc/stat; sleep "$1"
    read -r _ a2 b2 c2 d2 e2 f2 g2 _ < /proc/stat
    local busy=$(( (a2+b2+c2+f2+g2) - (a1+b1+c1+f1+g1) )) idle=$(( (d2+e2) - (d1+e1) ))
    echo $(( 100 * busy / (busy + idle) ))
}

. "$(dirname "$0")/lib-server.sh"
server_start 443
INVITE=$(server_invite)
declare -A PID
for s in A B; do
    ip netns exec "h$s" env RETAIL_API_TOKEN_FILE="$WORK/$s.token" RUST_LOG=retaild=debug "$BIN/retaild" --state-dir "$WORK/$s" >"$WORK/node$s.log" 2>&1 &
    PID[$s]=$!
done
sleep 0.5
cli A up --invite "$INVITE" --hostname a >/dev/null
cli B up --invite "$INVITE" --hostname b >/dev/null
IP_B=$(cli B ip)
for _ in $(seq 100); do nsx hA ping -c1 -W0.2 "$IP_B" >/dev/null 2>&1 && break; sleep 0.1; done
if ! nsx hA ping -c1 -W1 "$IP_B" >/dev/null; then
    echo "!! retail tunnel did not come up"
    cli A status; cli B status
    sed 's/\x1b\[[0-9;]*m//g' "$WORK/nodeA.log" "$WORK/nodeB.log" | tail -40
    exit 1
fi
run_suite "retail" "$IP_B" "${PID[A]}" "${PID[B]}"
mem() { awk '/^VmHWM/ { printf "%.1f MiB", $2/1024 }' "/proc/$1/status"; }
echo "    peak RSS: A $(mem "${PID[A]}"), B $(mem "${PID[B]}"); threads: $(ls /proc/"${PID[A]}"/task | wc -l)"
echo "    offload: $(grep -hoE '(tso|uso|gso_segments|gro_segments)=[a-z0-9]+' "$WORK/nodeA.log" | sort -u | tr '\n' ' ')"
for s in A B; do grep -h 'batching:' "$WORK/node$s.log" | head -2 | sed "s/.*batching:/    $s batching:/"; done
for s in A B; do grep -h 'stages:' "$WORK/node$s.log" | head -2 | sed "s/.*stages:/    $s stages:/"; done
kill "${PID[A]}" "${PID[B]}"; server_kill
for _ in $(seq 50); do pgrep -f "$BIN/retaild" >/dev/null || break; sleep 0.1; done

if [ "${WGGO:-1}" = 1 ] && command -v wireguard-go >/dev/null && command -v wg >/dev/null; then
    ka=$(wg genkey); kb=$(wg genkey)
    pa=$(echo "$ka" | wg pubkey); pb=$(echo "$kb" | wg pubkey)
    setup_wggo() {  # site key ip peer_pub peer_endpoint
        local dev="wggo$1"
        WG_PROCESS_FOREGROUND=1 ip netns exec "h$1" wireguard-go "$dev" >"$WORK/wggo$1.log" 2>&1 &
        for _ in $(seq 50); do [ -S "/var/run/wireguard/$dev.sock" ] && break; sleep 0.1; done
        echo "$2" >"$WORK/gokey$1"
        nsx "h$1" wg set "$dev" listen-port 51821 private-key "$WORK/gokey$1" \
            peer "$4" allowed-ips 10.98.0.0/24 endpoint "$5" persistent-keepalive 25
        nsx "h$1" ip addr add "$3/24" dev "$dev"
        nsx "h$1" ip link set "$dev" mtu 1280 up
    }
    setup_wggo A "$ka" 10.98.0.1 "$pb" 198.51.101.2:51821
    setup_wggo B "$kb" 10.98.0.2 "$pa" 198.51.100.2:51821
    for _ in $(seq 150); do nsx hA ping -c1 -W0.2 10.98.0.2 >/dev/null 2>&1 && break; sleep 0.1; done
    if nsx hA ping -c1 -W1 10.98.0.2 >/dev/null; then
        GOA=$(pgrep -f "wireguard-go wggoA" | head -1); GOB=$(pgrep -f "wireguard-go wggoB" | head -1)
        run_suite "wireguard-go" 10.98.0.2 "$GOA" "$GOB"
        echo "    peak RSS: A $(mem "$GOA"), B $(mem "$GOB"); threads: $(ls /proc/"$GOA"/task | wc -l)"
    else
        echo "!! wireguard-go tunnel did not come up"
    fi
    pkill -f "wireguard-go wggo" || true
    sleep 0.5
fi

if [ "${KERNEL:-1}" = 1 ] && command -v wg >/dev/null; then
    ka=$(wg genkey); kb=$(wg genkey)
    pa=$(echo "$ka" | wg pubkey); pb=$(echo "$kb" | wg pubkey)
    setup_wg() {  # site key ip peer_pub peer_endpoint
        nsx "h$1" ip link add wg0 type wireguard
        echo "$2" >"$WORK/key$1"
        nsx "h$1" wg set wg0 listen-port 51820 private-key "$WORK/key$1" \
            peer "$4" allowed-ips 10.99.0.0/24 endpoint "$5" persistent-keepalive 25
        nsx "h$1" ip addr add "$3/24" dev wg0
        nsx "h$1" ip link set wg0 mtu 1280 up
    }
    setup_wg A "$ka" 10.99.0.1 "$pb" 198.51.101.2:51820
    setup_wg B "$kb" 10.99.0.2 "$pa" 198.51.100.2:51820
    for _ in $(seq 150); do nsx hA ping -c1 -W0.2 10.99.0.2 >/dev/null 2>&1 && break; sleep 0.1; done
    nsx hA ping -c1 -W1 10.99.0.2 >/dev/null || { echo "!! kernel WireGuard tunnel did not come up"; nsx hA wg show; exit 1; }
    run_suite "kernel WireGuard" 10.99.0.2
fi
