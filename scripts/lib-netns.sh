# Shared by the netns test scripts (sourced). Needs BIN and WORK.
#
# The topology: two sites, each a host behind a home router (NAT plus a
# firewall that drops anything unsolicited), joined through the root namespace,
# which plays the internet:
#
#   hA 192.168.1.10 -- rA [NAT] 198.51.100.2 --+-- root ns --+-- 198.51.101.2 [NAT] rB -- 192.168.2.10 hB
#                                                     server :443, STUN :3478
#
# The coordination server is a server-only retaild in the root namespace,
# administered through its own local API, as on a VPS. Router port mapping is
# off so the tests never talk to the real network.

nsx() { local ns=$1; shift; ip netns exec "$ns" "$@"; }
cli() { local s=$1; shift; ip netns exec "h$s" env RETAIL_API_TOKEN_FILE="$WORK/$s.token" "$BIN/retail" "$@"; }

# Daemons, iperf3 and the topology; scripts that start more add their own
# cleanup on top
teardown() {
    pkill -f "$BIN/retaild" 2>/dev/null || true
    pkill -x iperf3 2>/dev/null || true
    # A namespace (and its veths) lives until the last process inside it exits
    for _ in $(seq 50); do pgrep -f "$BIN/retaild" >/dev/null || break; sleep 0.1; done
    for ns in hA hB rA rB; do ip netns del "$ns" 2>/dev/null || true; done
    ip link del inetA 2>/dev/null || true
    ip link del inetB 2>/dev/null || true
    for t in iptables ip6tables; do
        $t -D FORWARD -i inetA -o inetB -j ACCEPT 2>/dev/null || true
        $t -D FORWARD -i inetB -o inetA -j ACCEPT 2>/dev/null || true
    done
}

# site wan4 lan4 wan6 lan6 masquerade-options
setup_site() {
    local s=$1 wan=$2 lan=$3 wan6=$4 lan6=$5 masq=$6
    ip link add "inet$s" type veth peer name "wan$s"
    ip link set "wan$s" netns "r$s"
    ip addr add "$wan.1/24" dev "inet$s"
    ip -6 addr add "$wan6::1/64" dev "inet$s" nodad
    ip link set "inet$s" up
    nsx "r$s" ip addr add "$wan.2/24" dev "wan$s"
    nsx "r$s" ip -6 addr add "$wan6::2/64" dev "wan$s" nodad
    nsx "r$s" ip link set "wan$s" up
    nsx "r$s" ip route add default via "$wan.1"
    nsx "r$s" ip -6 route add default via "$wan6::1"
    ip -6 route add "$lan6::/64" via "$wan6::2"

    ip link add "lan$s" netns "r$s" type veth peer name eth0 netns "h$s"
    nsx "r$s" ip addr add "$lan.1/24" dev "lan$s"
    nsx "r$s" ip -6 addr add "$lan6::1/64" dev "lan$s" nodad
    nsx "r$s" ip link set "lan$s" up
    [ "${NAT64:-0}" = 1 ] || nsx "h$s" ip addr add "$lan.10/24" dev eth0
    # Hosts get global IPv6 only when HOST_V6=1, since otherwise it would
    # bypass the IPv4 NAT/firewall under test
    [ "${HOST_V6:-0}" = 1 ] && nsx "h$s" ip -6 addr add "$lan6::10/64" dev eth0 nodad
    nsx "h$s" ip link set eth0 up
    [ "${NAT64:-0}" = 1 ] || nsx "h$s" ip route add default via "$lan.1"
    [ "${HOST_V6:-0}" = 1 ] && nsx "h$s" ip -6 route add default via "$lan6::1"

    nsx "r$s" sysctl -qw net.ipv4.ip_forward=1
    nsx "r$s" sysctl -qw net.ipv6.conf.all.forwarding=1
    # shellcheck disable=SC2086
    nsx "r$s" iptables -t nat -A POSTROUTING -o "wan$s" -j MASQUERADE $masq
    # Home-router firewall: nothing unsolicited from the WAN side, v4 and v6,
    # except ICMPv6 to the router itself (neighbour discovery, as on real routers)
    nsx "r$s" ip6tables -A INPUT -i "wan$s" -p ipv6-icmp -j ACCEPT
    for t in iptables ip6tables; do
        for chain in FORWARD INPUT; do
            nsx "r$s" $t -A "$chain" -i "wan$s" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
            nsx "r$s" $t -A "$chain" -i "wan$s" -j DROP
        done
    done
}

# topology_up [MASQUERADE OPTIONS]: both sites, ready for traffic
topology_up() {
    for ns in hA hB rA rB; do ip netns add "$ns"; nsx "$ns" ip link set lo up; done
    sysctl -qw net.ipv4.ip_forward=1
    sysctl -qw net.ipv6.conf.all.forwarding=1
    setup_site A 198.51.100 192.168.1 2001:db8:100 2001:db8:a "${1:-}"
    setup_site B 198.51.101 192.168.2 2001:db8:101 2001:db8:b "${1:-}"
    for t in iptables ip6tables; do
        $t -I FORWARD 1 -i inetA -o inetB -j ACCEPT
        $t -I FORWARD 1 -i inetB -o inetA -j ACCEPT
    done
    # Fresh veths need a few seconds of link-local DAD before IPv6 neighbour
    # discovery works. A real network is already warm, so wait it out here
    # instead of charging it to the connect time
    local warm="rA:2001:db8:101::2"
    [ "${HOST_V6:-0}" = 1 ] && warm="hA:2001:db8:100::1 hB:2001:db8:101::1 $warm"
    for pair in $warm; do
        for _ in $(seq 50); do
            nsx "${pair%%:*}" ping -6 -c1 -W0.2 "${pair#*:}" >/dev/null 2>&1 && break
        done
    done
}

# start_node SITE [ENV...]: retaild on host SITE, logging to $WORK/nodeSITE.log;
# sets NODE_PID. Not a backgrounded function, whose $! would be a subshell:
# `ip netns exec` and `env` both exec, so $! is retaild itself
start_node() {
    local s=$1; shift
    ip netns exec "h$s" env RETAIL_API_TOKEN_FILE="$WORK/$s.token" RUST_LOG="${RUST_LOG:-retaild=debug}" "$@" \
        "$BIN/retaild" --state-dir "$WORK/$s" >>"$WORK/node$s.log" 2>&1 &
    NODE_PID=$!
    for _ in $(seq 50); do cli "$s" status >/dev/null 2>&1 && break; sleep 0.1; done
}

SERVER_API=127.0.0.1:41190
SERVER_PID=

srv() { RETAIL_API_TOKEN_FILE="$WORK/server.token" "$BIN/retail" --api "$SERVER_API" "$@"; }

server_run() {
    RETAIL_API_TOKEN_FILE="$WORK/server.token" RETAIL_NO_PORTMAP=1 RUST_LOG="${SERVER_LOG:-retail_control=info,retaild=info}" \
        "$BIN/retaild" --state-dir "$WORK/server" --api "$SERVER_API" --port 41690 >>"$WORK/control.log" 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 50); do srv server status >/dev/null 2>&1 && break; sleep 0.1; done
}

# server_start [PORT [EXTRA ARGS]]: a fresh server with its own certificate
# (self-signed, pinned by invites).
server_start() {
    local port=${1:-443}
    shift || true
    server_run
    srv server start --no-join --port "$port" "$@" >/dev/null
}

server_invite() { srv server invite --reusable 2>/dev/null; }

server_kill() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    for _ in $(seq 50); do kill -0 "$SERVER_PID" 2>/dev/null || break; sleep 0.1; done
}

# The daemon starts the server again on its own since it was left running
server_restart() {
    server_kill
    server_run
    for _ in $(seq 50); do srv server status 2>/dev/null | grep -q running && break; sleep 0.1; done
}
