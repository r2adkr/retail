#!/usr/bin/env bash
# End-to-end test of retail on Linux using network namespaces.
#
#   hA (192.168.1.10) -- rA [NAT] --+                     +-- rB [NAT] -- hB (192.168.2.10)
#                                   +-- root ns "internet" +
#                                       control server + STUN
#
# Both nodes sit behind a masquerading router that drops unsolicited inbound
# traffic, so a working tunnel proves STUN discovery and UDP hole punching.
#
# Checks, in order:
#   connectivity     A reaches B directly through both NATs
#   throughput       iperf3 A -> B, reverse and 4 streams (IPERF=0 skips it)
#   memory           RSS and thread count of each retaild
#   recovery         B's daemon exits on SIGTERM and the tunnel comes back
#                    after a restart
#   control outage   the tunnel survives the control server going down, and
#                    both nodes reconnect when it returns
#
# Usage: sudo scripts/e2e-netns.sh [BIN_DIR]   (default: target/release)
#   KEEP=1             leave namespaces and processes running afterwards
#   IPERF=0            skip throughput measurement
#   SECONDS_IPERF=10   duration of each iperf3 run
set -euo pipefail

BIN="${1:-target/release}"
BIN="$(cd "$BIN" && pwd)"
WORK=/tmp/retail-e2e
IPERF="${IPERF:-1}"
SECONDS_IPERF="${SECONDS_IPERF:-10}"

cleanup() {
    pkill -f "$BIN/retaild" 2>/dev/null || true
    pkill -x iperf3 2>/dev/null || true
    # A namespace (and its veths) lives until the last process inside it exits
    for _ in $(seq 50); do pgrep -f "$BIN/retaild" >/dev/null || break; sleep 0.1; done
    for ns in hA hB rA rB; do ip netns del "$ns" 2>/dev/null || true; done
    ip link del inetA 2>/dev/null || true
    ip link del inetB 2>/dev/null || true
    iptables -D FORWARD -i inetA -o inetB -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i inetB -o inetA -j ACCEPT 2>/dev/null || true
}

if [ "${KEEP:-0}" != 1 ]; then trap cleanup EXIT; fi
cleanup
rm -rf "$WORK" && mkdir -p "$WORK"

nsx() { local ns=$1; shift; ip netns exec "$ns" "$@"; }
cli() { local s=$1; shift; ip netns exec "h$s" env RETAIL_API_TOKEN_FILE="$WORK/$s.token" "$BIN/retail" "$@"; }
elapsed() { awk -v a="$1" -v b="$2" 'BEGIN { print b - a }'; }

for ns in hA hB rA rB; do ip netns add "$ns"; nsx "$ns" ip link set lo up; done
sysctl -qw net.ipv4.ip_forward=1

setup_site() {  # site wan_net lan_net
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
    # Typical home-router firewall: nothing unsolicited from the WAN side gets in,
    # neither forwarded nor to the router itself
    for chain in FORWARD INPUT; do
        nsx "r$s" iptables -A "$chain" -i "wan$s" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        nsx "r$s" iptables -A "$chain" -i "wan$s" -j DROP
    done
}
setup_site A 198.51.100 192.168.1
setup_site B 198.51.101 192.168.2
# Docker (if installed) sets the root FORWARD policy to DROP
iptables -I FORWARD 1 -i inetA -o inetB -j ACCEPT
iptables -I FORWARD 1 -i inetB -o inetA -j ACCEPT
echo "== topology ready"

. "$(dirname "$0")/lib-server.sh"
server_start 443
INVITE=$(server_invite)
[ -n "$INVITE" ] || { echo "!! server did not start"; tail -20 "$WORK/control.log"; exit 1; }
echo "== control server up"

declare -A PID
run_daemon() {  # site
    local s=$1
    # Not via the nsx function: a backgrounded function runs in a subshell and $!
    # would be that shell. `ip netns exec` and `env` both exec, so $! is retaild.
    ip netns exec "h$s" env RETAIL_API_TOKEN_FILE="$WORK/$s.token" RUST_LOG="${RUST_LOG:-retaild=info}" "$BIN/retaild" --state-dir "$WORK/$s" >>"$WORK/node$s.log" 2>&1 &
    PID[$s]=$!
    for _ in $(seq 50); do cli "$s" status >/dev/null 2>&1 && break; sleep 0.1; done
}
start_node() {  # site server_ip
    local s=$1 srv=$2
    run_daemon "$s"
    cli "$s" up --invite "$INVITE" --hostname "node-${s,,}" >/dev/null
}
wait_ping() {  # target timeout_s
    local deadline=$(( $(date +%s) + $2 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        nsx hA ping -c1 -W0.2 "$1" >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    return 1
}

t0=$(date +%s.%N)
start_node A 198.51.100.1
start_node B 198.51.101.1
IP_A=$(cli A ip)
IP_B=$(cli B ip)
echo "== nodes up: A=$IP_A B=$IP_B"

ok=0
wait_ping "$IP_B" 60 && ok=1
t1=$(date +%s.%N)
if [ "$ok" != 1 ]; then
    echo "!! ping A -> B failed"
    cli A status || true
    cli B status || true
    tail -n 30 "$WORK"/node*.log
    exit 1
fi
printf "== first ping A -> B %.2fs after 'retail up' on A\n" "$(elapsed "$t0" "$t1")"
nsx hB ping -c3 -i0.2 -q "$IP_A" | tail -2
nsx hA ping -c20 -i0.05 -q "$IP_B" | tail -2

echo; echo "== status on A"; cli A status
echo; echo "== status on B"; cli B status

if ! cli A status --json | grep -q '"endpoint": "198.51.101.2:'; then
    echo "!! expected A to reach B directly through B's NAT (198.51.101.2)"
    exit 1
fi
echo; echo "== direct path through both NATs confirmed"

if [ "$IPERF" = 1 ] && command -v iperf3 >/dev/null; then
    nsx hB iperf3 -s -D -B "$IP_B" >/dev/null
    sleep 0.3
    echo; echo "== iperf3 TCP A -> B over retail (${SECONDS_IPERF}s)"
    nsx hA iperf3 -c "$IP_B" -t "$SECONDS_IPERF" -f m | grep -E "sender|receiver"
    echo "== iperf3 TCP B -> A over retail (reverse, ${SECONDS_IPERF}s)"
    sleep 0.5
    nsx hA iperf3 -c "$IP_B" -t "$SECONDS_IPERF" -f m -R | grep -E "sender|receiver"
    echo "== iperf3 TCP 4 streams A -> B (${SECONDS_IPERF}s)"
    sleep 0.5
    nsx hA iperf3 -c "$IP_B" -t "$SECONDS_IPERF" -f m -P 4 | grep -E "SUM.*(sender|receiver)"
fi

mem() { awk '/^(VmRSS|VmHWM|RssAnon|RssFile)/ { printf "%s %.1f MiB  ", $1, $2/1024 }' "/proc/$1/status"; }
echo; echo "== retaild memory (cores: $(nproc))"
for s in A B; do
    [ "$(cat /proc/"${PID[$s]}"/comm)" = retaild ] || { echo "!! PID ${PID[$s]} is not retaild"; exit 1; }
done
echo "   A: $(mem "${PID[A]}") threads $(ls /proc/"${PID[A]}"/task | wc -l)"
echo "   B: $(mem "${PID[B]}") threads $(ls /proc/"${PID[B]}"/task | wc -l)"

echo; echo "== restarting node B daemon (SIGTERM, then start again)"
kill -TERM "${PID[B]}"
for _ in $(seq 50); do kill -0 "${PID[B]}" 2>/dev/null || break; sleep 0.1; done
if kill -0 "${PID[B]}" 2>/dev/null; then echo "!! retaild ignored SIGTERM"; exit 1; fi
echo "   stopped gracefully"
t0=$(date +%s.%N); ok=0
run_daemon B
wait_ping "$IP_B" 60 && ok=1
t1=$(date +%s.%N)
[ "$ok" = 1 ] || { echo "!! tunnel did not recover"; tail -n 30 "$WORK"/node*.log; exit 1; }
printf "== tunnel recovered %.2fs after restart\n" "$(elapsed "$t0" "$t1")"

echo; echo "== stopping the control server"
server_kill
sleep 1
nsx hA ping -c10 -i0.1 -q "$IP_B" | grep -q " 0% packet loss" \
    || { echo "!! tunnel broke while the control server was down"; exit 1; }
echo "   tunnel still up without the control server"
server_run  # resumes the server it hosted
t0=$(date +%s.%N); ok=0
for _ in $(seq 400); do
    if cli A status --json | grep -q '"control_connected": true' \
        && cli B status --json | grep -q '"control_connected": true'; then ok=1; break; fi
    sleep 0.1
done
t1=$(date +%s.%N)
[ "$ok" = 1 ] || { echo "!! nodes did not reconnect to the control server"; exit 1; }
printf "== both nodes reconnected %.2fs after the control server came back\n" "$(elapsed "$t0" "$t1")"

echo; echo "E2E PASSED"
