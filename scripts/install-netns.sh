#!/usr/bin/env bash
# Client package end to end: a server in the root namespace hands out a Linux
# client with a named invite through its web admin page, and a fresh host in
# its own namespace runs it, which installs retail under a temporary prefix
# (no systemd, no autostart) and joins. Then the invite gets a new code: the
# old package no longer joins, while the joined device stays.
#
# Usage: sudo scripts/install-netns.sh [BIN_DIR]
set -u

BIN="$(cd "${1:-target/release}" && pwd)"
WORK=/tmp/retail-install
. "$(dirname "$0")/lib-server.sh"

nsx() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

cleanup() {
    pkill -f "$WORK/" 2>/dev/null || true
    server_kill 2>/dev/null || true
    pkill -f "$BIN/retaild" 2>/dev/null || true
    for ns in hC hD; do ip netns del "$ns" 2>/dev/null || true; done
    ip link del vC 2>/dev/null || true
    ip link del vD 2>/dev/null || true
    iptables -D FORWARD -i vC -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i vD -j ACCEPT 2>/dev/null || true
}
[ "${KEEP:-0}" = 1 ] || trap cleanup EXIT
cleanup
rm -rf "$WORK" && mkdir -p "$WORK"

host() {  # name veth subnet
    ip netns add "$1"; nsx "$1" ip link set lo up
    ip link add "$2" type veth peer name eth0 netns "$1"
    ip addr add "$3.1/24" dev "$2"; ip link set "$2" up
    nsx "$1" ip addr add "$3.10/24" dev eth0; nsx "$1" ip link set eth0 up
    nsx "$1" ip route add default via "$3.1"
    iptables -I FORWARD 1 -i "$2" -j ACCEPT
}
host hC vC 10.77.1
host hD vD 10.77.2
sysctl -qw net.ipv4.ip_forward=1

ok=1
server_start 443
# The server's own web admin page, signed in from this machine
link=$(srv server web --print 2>/dev/null)
port=$(echo "$link" | sed -E 's#http://127.0.0.1:([0-9]+)/.*#\1#')
W="http://127.0.0.1:$port"
jar="$WORK/jar"
curl -s -m 3 -c "$jar" -o /dev/null "$link"
post() { curl -s -m 10 -b "$jar" -H 'X-Retail-Web: 1' -H 'Content-Type: application/json' -d "$2" "$W$1"; }
post /api/invites '{"name":"office"}' >/dev/null
id=$(curl -s -m 3 -b "$jar" "$W/api/status" | jq -r '.server.invites[] | select(.name=="office") | .id')
variants=$(curl -s -m 3 -b "$jar" "$W/api/status" | jq -r '.clients[] | "\(.id) missing=\(.missing|join(","))"')
echo "  clients offered: $variants"
curl -s -m 60 -b "$jar" -o "$WORK/pkg-old" "$W/download/$id/linux-x86_64"
chmod +x "$WORK/pkg-old"
echo "  package: $(( $(stat -c %s "$WORK/pkg-old") / 1048576 )) MiB"

# hC runs the package: install under a prefix, start retaild, join
t0=$(date +%s.%N)
nsx hC env RETAIL_INSTALL_YES=1 RETAIL_API_TOKEN_FILE="$WORK/hC.token" \
    "$WORK/pkg-old" --prefix "$WORK/hC" --no-service --no-autostart >"$WORK/install-hC.log" 2>&1
rc=$?
st=$(nsx hC env RETAIL_API_TOKEN_FILE="$WORK/hC.token" "$WORK/hC/bin/retail" status --json 2>/dev/null)
state=$(echo "$st" | jq -r .state)
echo "  hC: installer exit $rc, state $state after $(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN{printf "%.1f", b-a}')s"
ls "$WORK/hC/bin" | tr '\n' ' '; echo
[ "$rc" = 0 ] && [ "$state" = running ] || { ok=0; cat "$WORK/install-hC.log"; }
cmp -s <(head -c "$(stat -c %s "$BIN/retail-tray")" "$WORK/pkg-old") "$BIN/retail-tray" && echo "  installed tray is the plain program" || true
cmp -s "$WORK/hC/bin/retail-tray" "$BIN/retail-tray" || { echo "  installed tray differs from the original"; ok=0; }

# A new code for the invite: the old package cannot join anymore
post /api/invites '{"name":"office"}' >/dev/null
nsx hD env RETAIL_INSTALL_YES=1 RETAIL_API_TOKEN_FILE="$WORK/hD.token" \
    "$WORK/pkg-old" --prefix "$WORK/hD" --no-service --no-autostart >"$WORK/install-hD.log" 2>&1
rc=$?
if [ "$rc" != 0 ] && grep -qE "invalid, used or expired|만료됐습니다" "$WORK/install-hD.log"; then
    echo "  the old package no longer joins after a new code"
else
    echo "  the old package still joined (exit $rc)"; cat "$WORK/install-hD.log"; ok=0
fi
nodes=$(curl -s -m 3 -b "$jar" "$W/api/status" | jq '[.server.nodes[]] | length')
[ "$nodes" = 1 ] && echo "  hC is still a member" || { echo "  members: $nodes"; ok=0; }

[ "$ok" = 1 ] && echo "PASS install" || { echo "FAIL install"; exit 1; }
