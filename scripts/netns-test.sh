#!/usr/bin/env bash
# End-to-end tests on Linux network namespaces: every way retail connects, falls
# back and recovers, on the double-NAT topology of lib-netns.sh.
#
# Usage: sudo scripts/netns-test.sh [BIN_DIR] [SCENARIO|all]
#   KEEP=1              leave namespaces and processes running afterwards
#   DEBUG=1             KEEP=1, and print what each node knows (endpoints,
#                       candidates, path) and its interesting log lines
#   CONNECT_TIMEOUT=5   seconds A gets to reach B (more for slow ways)
#   SOAK_SECONDS=240    length of the rekey scenario's transfer
#
# Scenarios (filters on both routers unless noted):
#   direct        plain home-router NAT                      -> direct path. Also:
#                 the local API refuses changes without its token, B's daemon
#                 stops on SIGTERM and the tunnel comes back after a restart,
#                 and the tunnel outlives the server going down while both
#                 nodes reconnect once it is back
#   udp-blocked   all outbound UDP dropped                   -> relay over TCP 443
#   symmetric     symmetric NAT (MASQUERADE --random-fully)  -> relay
#   tcp443-only   everything but TCP 443 dropped             -> relay over TCP 443
#   udp443-only   UDP dropped except to port 443             -> relay
#   ipv6          IPv4 symmetric NAT, IPv6 routed (no NAT)   -> direct over IPv6
#   recover       udp-blocked, then the block is lifted      -> relay, then direct
#   idle-relay    udp-blocked, then 40 s idle                -> still relay, no loss
#   failover      direct, then UDP blocked mid-ping          -> relay, outage < 6 s
#   failover-a/-b as failover, but only router A (B) drops UDP, so one direction
#                 dies, then the cut is lifted               -> relay, then direct
#   control-drop  udp-blocked, TCP 443 silently dropped 30 s -> relay back < 20 s after
#   exit          A uses B as exit node to reach a web server A's router blocks,
#                 and the web server must see B's public address
#   exit-relay    the same with UDP blocked, so exit traffic goes through the relay
#   exit-offline  B (the exit) stops: A's internet is blocked (fail closed) while
#                 its control connection stays up, and `--exit-node none` restores it
#   host-nat      B hosts the network behind its router, which runs miniupnpd:
#                 ports open automatically and A joins from outside by invite.
#                 Stopping the server drops A, starting it again brings A back
#                 It also checks B's web admin page: closed to A until B allows A,
#                 then A makes a named invite and downloads a client carrying it
#   host-upnp     host-nat with NAT-PMP off on the router (UPnP IGD only)
#   reality       UDP blocked and every TLS handshake not naming the allowed
#                 website dropped: devices join and relay through REALITY, and a
#                 probe naming that website gets the real website
#   proxy         nothing leaves but through an HTTP proxy with a password on
#                 each router: A has it set with `retail set --proxy`, B finds
#                 it in HTTPS_PROXY                          -> relay via the proxy
#   inspect       the proxy decrypts TLS, refuses self-signed servers and
#                 strips WebSocket upgrades                  -> relay over HTTP polling
#   cdn           only a CDN edge (own certificate, forwards to the server) is
#                 reachable, by name                         -> relay over a tunnel
#                 through the CDN
#   nat64         hosts are IPv6-only behind NAT64/DNS64 and native IPv6 to the
#                 server is cut                              -> connected through NAT64
#   helper        B hosts the network behind a router that opens nothing; a
#                 helper node on the internet makes it reachable, and A joins
#                 through it
#   switch        a second server in its own namespace: A and B join it with
#                 an invite, then switch back to the first without one and get
#                 their old addresses back; a forgotten server leaves the list
#   install       a client package from the server's web admin page installs
#                 under a temporary prefix and joins; after the invite gets a
#                 new code the old package is refused and the member stays
#   rekey         (not in `all`) a long transfer across WireGuard's rekey points
#                 (new handshake after ~120 s, old keys dropped after ~180 s),
#                 sampling throughput, handshake age and peak memory
#
# Each scenario passes if A reaches B within CONNECT_TIMEOUT, the reported path
# matches the expectation, a short iperf3 runs, idle RSS stays below 20 MiB
# and peak RSS below 20 MiB (the user's budget). Except in host-* and helper,
# the server is a retaild hosting the network in the root namespace (HTTPS
# with its own certificate), and nodes join with an invite code.
set -u

BIN="$(cd "${1:-target/release}" && pwd)"
SCRIPTS="$(cd "$(dirname "$0")" && pwd)"
WHICH="${2:-all}"
WORK=/tmp/retail-netns
[ "${DEBUG:-0}" = 1 ] && KEEP=1
SOAK_SECONDS="${SOAK_SECONDS:-240}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-5}"
IDLE_LIMIT_KB=$((20 * 1024))
PEAK_LIMIT_KB=$((20 * 1024))
. "$SCRIPTS/lib-netns.sh"

cleanup() {
    pkill -x miniupnpd 2>/dev/null || true
    pkill -f "s_server -accept 203.0.113.81:8443" 2>/dev/null || true
    pkill -x tinyproxy 2>/dev/null || true
    pkill -x tayga 2>/dev/null || true
    pkill -f "scripts/netns/" 2>/dev/null || true
    pkill -f "http.server 8080 --bind 203.0.113.80" 2>/dev/null || true
    pkill -f "$WORK/" 2>/dev/null || true
    server_kill 2>/dev/null || true
    ip link del web0 2>/dev/null || true
    ip link del web1 2>/dev/null || true
    ip link del web2 2>/dev/null || true
    rm -rf /etc/netns/hA /etc/netns/hB
    for ns in hC hD s2; do ip netns del "$ns" 2>/dev/null || true; done
    ip link del vS2 2>/dev/null || true
    iptables -D FORWARD -i vS2 -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o vS2 -j ACCEPT 2>/dev/null || true
    ip link del vC 2>/dev/null || true
    ip link del vD 2>/dev/null || true
    iptables -D FORWARD -i vC -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i vD -j ACCEPT 2>/dev/null || true
    teardown
}

# Outbound filters on both routers (LAN -> WAN), inserted ahead of everything
block() {  # scenario
    for s in A B; do
        case $1 in
            udp-blocked | recover | idle-relay | control-drop | exit-relay | reality)
                nsx "r$s" iptables -I FORWARD 1 -i "lan$s" -p udp -j DROP
                nsx "r$s" ip6tables -I FORWARD 1 -i "lan$s" -p udp -j DROP ;;
            tcp443-only)
                for t in iptables ip6tables; do
                    nsx "r$s" $t -I FORWARD 1 -i "lan$s" -j DROP
                    nsx "r$s" $t -I FORWARD 1 -i "lan$s" -p tcp --dport 443 -j ACCEPT
                done ;;
            udp443-only)
                for t in iptables ip6tables; do
                    nsx "r$s" $t -I FORWARD 1 -i "lan$s" -p udp -j DROP
                    nsx "r$s" $t -I FORWARD 1 -i "lan$s" -p udp --dport 443 -j ACCEPT
                done ;;
            proxy | inspect)
                nsx "r$s" iptables -I FORWARD 1 -i "lan$s" -j DROP
                nsx "r$s" ip6tables -I FORWARD 1 -i "lan$s" -j DROP ;;
            cdn)
                # Only the edge's port: its address also belongs to the server here
                nsx "r$s" iptables -I FORWARD 1 -i "lan$s" -j DROP
                nsx "r$s" iptables -I FORWARD 1 -i "lan$s" -d 203.0.113.82 -p tcp --dport 8443 -j ACCEPT
                nsx "r$s" ip6tables -I FORWARD 1 -i "lan$s" -j DROP ;;
            nat64)
                # Native IPv6 to the server is cut; only NAT64 leads out
                nsx "r$s" ip6tables -I FORWARD 1 -i "lan$s" ! -d 2001:db8:64::/96 -j DROP ;;
        esac
    done
}

unblock_udp() {
    for s in A B; do
        nsx "r$s" iptables -D FORWARD -i "lan$s" -p udp -j DROP
        nsx "r$s" ip6tables -D FORWARD -i "lan$s" -p udp -j DROP
    done
}

path_of() {  # site -> "direct <addr>" | "relay <...>" | "none"
    cli "$1" status --json 2>/dev/null | jq -r '
        .peers[0] as $p | if $p == null then "none"
        elif ($p.path // null) != null then $p.path
        elif $p.endpoint != null then "direct \($p.endpoint)"
        else "none" end'
}

wait_ping() {  # target timeout_s -> seconds taken, or fails
    local t0 deadline
    t0=$(date +%s.%N)
    deadline=$(( $(date +%s) + $2 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if nsx hA ping -c1 -W0.3 "$1" >/dev/null 2>&1; then
            awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN { printf "%.2f", b - a }'
            return 0
        fi
        sleep 0.1
    done
    return 1
}

# A web server on the "internet" (root namespace) that A's router blocks, so A
# can only reach it through the exit node. It logs client addresses
start_web() {
    ip link add web0 type dummy
    ip addr add 203.0.113.80/32 dev web0
    ip link set web0 up
    nsx rA iptables -I FORWARD 1 -d 203.0.113.80 -j DROP
    python3 -m http.server 8080 --bind 203.0.113.80 --directory "$WORK" >"$WORK/web.log" 2>&1 &
    for _ in $(seq 50); do curl -s -o /dev/null "http://203.0.113.80:8080/" && break; sleep 0.1; done
}

exit_checks() {  # scenario ip_b
    local sc=$1 ip_b=$2 ok=1
    start_web
    nsx hA curl -s -m 2 -o /dev/null "http://203.0.113.80:8080/" && { echo "  web server reachable without an exit node (harness error)"; return 1; }
    cli B set --advertise-exit-node >/dev/null || { echo "  advertising B as exit node failed"; return 1; }
    for _ in $(seq 50); do
        [ "$(cli A status --json | jq -r '.peers[0].exit_node')" = true ] && break; sleep 0.1
    done
    if ! cli A set --exit-node b >"$WORK/set.txt" 2>&1; then
        echo "  selecting the exit node failed: $(tail -1 "$WORK/set.txt")"; return 1
    fi
    sleep 1
    if nsx hA curl -s -m 5 -o /dev/null "http://203.0.113.80:8080/"; then
        local seen
        seen=$(grep -aoE '^[0-9]+(\.[0-9]+){3} - -' "$WORK/web.log" | tail -1 | cut -d' ' -f1)
        echo "  web server reached through the exit node; it saw $seen"
        [ "$seen" = 198.51.101.2 ] || { echo "  expected B's public address 198.51.101.2"; ok=0; }
    else
        echo "  web server NOT reachable through the exit node"; ok=0
    fi
    # The daemon's own connections bypass the exit routes (no loop)
    sleep 2
    [ "$(cli A status --json | jq -r .control_connected)" = true ] || { echo "  A lost its control connection"; ok=0; }
    echo "  A's path to B: $(path_of A)"
    iperf3 -s -D -B 203.0.113.80 >/dev/null; sleep 0.3
    local bw
    bw=$(nsx hA iperf3 -c 203.0.113.80 -t 4 -J 2>/dev/null | jq -r '.end.sum_received.bits_per_second / 1e6 | floor' 2>/dev/null)
    echo "  iperf3 A->internet via exit: ${bw:-failed} Mbit/s"
    pkill -x iperf3 || true
    [ -n "$bw" ] && [ "$bw" != null ] || ok=0

    if [ "$sc" = exit-offline ]; then
        # 198.51.101.1 is reachable from A now, and with the exit gone it must not be
        nsx hA ping -c1 -W1 198.51.101.1 >/dev/null || { echo "  harness: 198.51.101.1 unreachable via exit"; }
        pkill -f "$BIN/retaild --state-dir $WORK/B"
        sleep 3
        if nsx hA ping -c2 -W1 -q 198.51.101.1 >/dev/null 2>&1; then
            echo "  internet still reachable with the exit node offline (leak)"; ok=0
        else
            echo "  exit node offline: internet blocked (fail closed)"
        fi
        sleep 12
        [ "$(cli A status --json | jq -r .control_connected)" = true ] || { echo "  A lost its control connection while the exit was offline"; ok=0; }
        cli A set --exit-node none >/dev/null || { echo "  clearing the exit node failed"; ok=0; }
        if nsx hA ping -c2 -W1 -q 198.51.101.1 >/dev/null 2>&1; then
            echo "  exit node cleared: direct internet access restored"
        else
            echo "  internet NOT restored after clearing the exit node"; ok=0
        fi
        [ -z "$(nsx hA ip rule | grep 5230)" ] || { echo "  exit rules left behind"; ok=0; }
    fi
    [ "$ok" = 1 ]
}

# A UPnP/NAT-PMP router: miniupnpd on site's router, with its iptables chains
# ahead of the home-router firewall
start_upnp_router() {  # site
    local s=$1
    # miniupnpd edits legacy iptables (libiptc). The rest of the harness uses
    # the nft backend, which lets forwarded (DNAT) traffic through
    local ipt=iptables-legacy
    nsx "r$s" $ipt -t nat -N MINIUPNPD
    nsx "r$s" $ipt -t nat -I PREROUTING 1 -i "wan$s" -j MINIUPNPD
    nsx "r$s" $ipt -t nat -N MINIUPNPD-POSTROUTING
    nsx "r$s" $ipt -t nat -I POSTROUTING 1 -o "wan$s" -j MINIUPNPD-POSTROUTING
    nsx "r$s" $ipt -N MINIUPNPD
    nsx "r$s" $ipt -I FORWARD 1 -i "wan$s" ! -o "wan$s" -j MINIUPNPD
    nsx "r$s" iptables -I FORWARD 1 -i "wan$s" -m conntrack --ctstate DNAT -j ACCEPT
    cat >"$WORK/miniupnpd.conf" <<EOF
ext_ifname=wan$s
listening_ip=lan$s
port=5000
enable_natpmp=${NATPMP:-yes}
enable_upnp=yes
secure_mode=yes
system_uptime=yes
allow 1024-65535 0.0.0.0/0 1024-65535
allow 443 0.0.0.0/0 443
deny 0-65535 0.0.0.0/0 0-65535
EOF
    ip netns exec "r$s" miniupnpd -f "$WORK/miniupnpd.conf" -d >"$WORK/upnp.log" 2>&1 &
    sleep 0.5
}

# The allowed website, on the "internet", and a DPI box on each router that
# drops TLS handshakes naming anything else
start_camouflage() {
    ip link add web1 type dummy
    ip addr add 203.0.113.81/32 dev web1
    ip link set web1 up
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
        -subj /CN=www.camouflage.test -keyout "$WORK/site.key" -out "$WORK/site.pem" 2>/dev/null
    openssl s_server -accept 203.0.113.81:8443 -cert "$WORK/site.pem" -key "$WORK/site.key" -www -quiet >/dev/null 2>&1 &
    for s in A B; do
        nsx "r$s" iptables -t mangle -A FORWARD -i "lan$s" -p tcp --dport 443 \
            -m string --algo bm --string www.camouflage.test -j CONNMARK --set-mark 7
        nsx "r$s" iptables -I FORWARD 1 -i "lan$s" -p tcp --dport 443 -m connmark ! --mark 7 \
            -m string --algo bm --hex-string "|160301|" -j DROP
    done
    sleep 0.3
}

# An HTTP proxy with a password on each router's LAN address
start_proxies() {
    for s in A B; do
        local lan=192.168.1; [ "$s" = B ] && lan=192.168.2
        touch "$WORK/tinyproxy-$s.log" && chmod 666 "$WORK/tinyproxy-$s.log"
        cat >"$WORK/tinyproxy-$s.conf" <<EOF
Port 3128
Listen $lan.1
Timeout 600
Allow $lan.0/24
BasicAuth u p4ss
LogFile "$WORK/tinyproxy-$s.log"
LogLevel Info
MaxClients 100
EOF
        ip netns exec "r$s" tinyproxy -d -c "$WORK/tinyproxy-$s.conf" >/dev/null 2>&1 &
    done
    sleep 0.5
}

# A TLS-inspecting proxy on each router's LAN address
start_inspecting_proxies() {
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
        -subj /CN=inspector -keyout "$WORK/mitm.key" -out "$WORK/mitm.pem" 2>/dev/null
    for s in A B; do
        local lan=192.168.1; [ "$s" = B ] && lan=192.168.2
        ip netns exec "r$s" python3 "$SCRIPTS/netns/mitm_proxy.py" "$lan.1" 3128 "$WORK/mitm.pem" "$WORK/mitm.key" >"$WORK/mitm-$s.log" 2>&1 &
    done
    sleep 0.5
}

# A CDN edge for cdn.test on the "internet", forwarding to the server
start_cdn() {
    ip link add web2 type dummy
    ip addr add 203.0.113.82/32 dev web2
    ip link set web2 up
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
        -subj /CN=cdn.test -keyout "$WORK/cdn.key" -out "$WORK/cdn.pem" 2>/dev/null
    python3 "$SCRIPTS/netns/cdn.py" 203.0.113.82 8443 "$WORK/cdn.pem" "$WORK/cdn.key" 127.0.0.1 443 >"$WORK/cdn.log" 2>&1 &
    for h in hA hB; do
        mkdir -p "/etc/netns/$h"
        printf '127.0.0.1 localhost\n203.0.113.82 cdn.test\n' >"/etc/netns/$h/hosts"
    done
    sleep 0.3
}

# NAT64 (tayga) and DNS64 on each router; hosts get IPv6 only
start_nat64() {
    for s in A B; do
        local lan6=2001:db8:a; [ "$s" = B ] && lan6=2001:db8:b
        mkdir -p "$WORK/tayga-$s"
        cat >"$WORK/tayga-$s.conf" <<EOF
tun-device nat64
ipv4-addr 192.168.255.1
ipv6-addr fd00:64::1
prefix 2001:db8:64::/96
dynamic-pool 192.168.255.0/24
data-dir $WORK/tayga-$s
EOF
        nsx "r$s" tayga -c "$WORK/tayga-$s.conf" --mktun >/dev/null
        nsx "r$s" ip link set nat64 up
        nsx "r$s" ip addr add 192.168.254.1 dev nat64
        nsx "r$s" ip route add 192.168.255.0/24 dev nat64
        nsx "r$s" ip route add 2001:db8:64::/96 dev nat64
        ip netns exec "r$s" tayga -c "$WORK/tayga-$s.conf" -d >"$WORK/tayga-$s.log" 2>&1 &
        ip netns exec "r$s" python3 "$SCRIPTS/netns/dns64.py" "$lan6::1" 2001:db8:64:: >"$WORK/dns64-$s.log" 2>&1 &
        mkdir -p "/etc/netns/h$s"
        echo "nameserver $lan6::1" >"/etc/netns/h$s/resolv.conf"
    done
    sleep 0.5
}

# A helper node on the "internet" (as on a VPS), administered through its own
# local API; prints its code
start_helper() {
    RETAIL_API_TOKEN_FILE="$WORK/helper.token" RETAIL_NO_PORTMAP=1 RUST_LOG=retail_control=info,retaild=info \
        "$BIN/retaild" --state-dir "$WORK/helperd" --api 127.0.0.1:41191 --port 41691 --helper --helper-public 198.51.100.1 \
        >"$WORK/helper.log" 2>&1 &
    local code=
    for _ in $(seq 50); do
        code=$(RETAIL_API_TOKEN_FILE="$WORK/helper.token" "$BIN/retail" --api 127.0.0.1:41191 helper status 2>/dev/null | awk '/^code:/ {print $2}')
        [ -n "$code" ] && break
        sleep 0.1
    done
    echo "$code"
}

# B's web admin page: closed to A until B allows it, then A creates a named
# invite and downloads a Linux client package carrying it
web_checks() {  # ip_b
    local ip_b=$1 W=http://127.0.0.1:41180 jar="$WORK/jar" code
    code=$(nsx hA curl -s -m 3 -o /dev/null -w '%{http_code}' "http://$ip_b:41180/api/status")
    [ "$code" != 200 ] || { echo "  web admin open to A before being allowed"; return 1; }
    local link
    link=$(cli B server web --print 2>/dev/null)
    nsx hB curl -s -m 3 -c "$jar" -o /dev/null "$link"
    nsx hB curl -s -m 3 -b "$jar" -o /dev/null -w '%{http_code}' "$W/api/status" | grep -q 200 || { echo "  local sign-in failed"; return 1; }
    [ "$(nsx hB curl -s -m 3 -o /dev/null -w '%{http_code}' "$W/api/status")" = 401 ] || { echo "  web admin open without signing in"; return 1; }
    local id_a
    id_a=$(nsx hB curl -s -m 3 -b "$jar" "$W/api/status" | jq -r '.server.nodes[] | select(.hostname=="a") | .id')
    nsx hB curl -s -m 3 -b "$jar" -H 'X-Retail-Web: 1' -H 'Content-Type: application/json' -d '{"allowed":true}' "$W/api/nodes/$id_a/admin" >/dev/null
    local up=0
    for i in $(seq 40); do
        [ "$(nsx hA curl -s -m 2 -o /dev/null -w '%{http_code}' "http://$ip_b:41180/api/status")" = 200 ] && { up=$i; break; }
        sleep 0.25
    done
    [ "$up" -gt 0 ] || { echo "  A was allowed but cannot open B's web admin"; return 1; }
    echo "  web admin: closed to A, open $(awk -v t="$up" 'BEGIN{printf "%.1f", t/4}')s after B allowed it"
    local M="http://$ip_b:41180" inv pkg="$WORK/client"
    inv=$(nsx hA curl -s -m 5 -H 'X-Retail-Web: 1' -H 'Content-Type: application/json' -d '{"name":"family"}' "$M/api/invites" | jq -r .code)
    [[ $inv == retail1.* ]] || { echo "  named invite failed"; return 1; }
    local id
    id=$(nsx hA curl -s -m 3 "$M/api/status" | jq -r '.server.invites[] | select(.name=="family") | .id')
    nsx hA curl -s -m 30 -o "$pkg" -w '%{http_code}' "$M/download/$id/linux-x86_64" | grep -q 200 || { echo "  client download failed"; return 1; }
    chmod +x "$pkg"
    local size got
    size=$(stat -c %s "$pkg")
    got=$("$pkg" --package-info | jq -r .invite)
    [ "$got" = "$inv" ] || { echo "  the package does not carry the named invite"; return 1; }
    echo "  named invite and a $(( size / 1048576 )) MiB Linux client carrying it, downloaded by A"
    return 0
}

invite_first_addr() {
    python3 -c 'import sys,json,base64; c=sys.argv[1].split(".",1)[1]; print(json.loads(base64.urlsafe_b64decode(c+"="*(-len(c)%4)))["a"][0])' "$1"
}

# B's daemon restarts; the server goes away and comes back
lifecycle_checks() {  # ip_b
    local ip_b=$1 took
    kill -TERM "${pid[B]}"
    for _ in $(seq 50); do kill -0 "${pid[B]}" 2>/dev/null || break; sleep 0.1; done
    if kill -0 "${pid[B]}" 2>/dev/null; then echo "  retaild ignored SIGTERM"; return 1; fi
    start_node B
    pid[B]=$NODE_PID
    took=$(wait_ping "$ip_b" 60) || { echo "  tunnel did not come back after B restarted"; return 1; }
    echo "  B stopped on SIGTERM; tunnel back ${took}s after it started again"

    server_kill
    sleep 1
    nsx hA ping -c10 -i0.1 -q "$ip_b" | grep -q " 0% packet loss" \
        || { echo "  tunnel broke while the server was down"; return 1; }
    server_run
    local t0 i
    t0=$(date +%s.%N)
    for i in $(seq 400); do
        [ "$(cli A status --json | jq -r .control_connected)" = true ] \
            && [ "$(cli B status --json | jq -r .control_connected)" = true ] && break
        sleep 0.1
    done
    [ "$i" -lt 400 ] || { echo "  nodes did not reconnect to the server"; return 1; }
    echo "  tunnel kept up without the server; both reconnected $(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN{printf "%.1f", b-a}')s after it came back"
}

# A second network, then back to the first without an invite
switch_checks() {  # ip_b
    local ip_a ip_b=$1 first second invite2 n
    ip_a=$(cli A ip)
    first=$(cli A status --json | jq -r .server)
    # The second server: a server-only retaild in namespace s2, on the "internet"
    ip netns add s2; nsx s2 ip link set lo up
    ip link add vS2 type veth peer name eth0 netns s2
    ip addr add 10.88.0.1/24 dev vS2; ip link set vS2 up
    nsx s2 ip addr add 10.88.0.2/24 dev eth0; nsx s2 ip link set eth0 up
    nsx s2 ip route add default via 10.88.0.1
    iptables -I FORWARD 1 -i vS2 -j ACCEPT
    iptables -I FORWARD 1 -o vS2 -j ACCEPT
    s2() { nsx s2 env RETAIL_API_TOKEN_FILE="$WORK/s2.token" "$BIN/retail" "$@"; }
    nsx s2 env RETAIL_API_TOKEN_FILE="$WORK/s2.token" RETAIL_NO_PORTMAP=1 RUST_LOG=retail_control=info \
        "$BIN/retaild" --state-dir "$WORK/server2" --port 41690 >"$WORK/control2.log" 2>&1 &
    for _ in $(seq 50); do s2 server status >/dev/null 2>&1 && break; sleep 0.1; done
    s2 server start --no-join --port 443 >/dev/null || { echo "  second server did not start"; return 1; }
    invite2=$(s2 server invite --reusable 2>/dev/null)

    for s in A B; do
        cli "$s" up --invite "$invite2" >/dev/null || { echo "  $s could not join the second server"; return 1; }
    done
    second=$(cli A status --json | jq -r .server)
    n=$(cli A servers | wc -l)
    echo "  joined $second; A lists $n servers"
    [ "$n" = 2 ] && [ "$second" != "$first" ] || return 1
    local ip_b2
    ip_b2=$(cli B ip)
    wait_ping "$ip_b2" 15 >/dev/null || { echo "  no ping to B in the second network"; return 1; }
    [ "$(s2 server status --json | jq '.nodes | length')" = 2 ] || { echo "  the second server does not have both"; return 1; }

    for s in A B; do
        cli "$s" switch "$first" >/dev/null || { echo "  $s could not switch back"; return 1; }
    done
    [ "$(cli A ip)" = "$ip_a" ] && [ "$(cli B ip)" = "$ip_b" ] || { echo "  addresses changed: A $(cli A ip), B $(cli B ip)"; return 1; }
    local took
    took=$(wait_ping "$ip_b" 15) || { echo "  no ping after switching back"; return 1; }
    echo "  switched back without an invite, same addresses, B answers after ${took}s"

    cli A forget "$second" >/dev/null || { echo "  forget failed"; return 1; }
    [ "$(cli A servers | wc -l)" = 1 ] || { echo "  the forgotten server is still listed"; return 1; }
    echo "  the second server is forgotten"
}

# A long transfer across WireGuard's rekey points
soak() {  # ip_b
    local ip_b=$1
    hs() { cli "$1" status --json | jq -r '.peers[0].last_handshake_secs // "none"'; }
    hwm() { awk '/^VmHWM/ { printf "%.1f", $2/1024 }' "/proc/$1/status"; }
    nsx hB iperf3 -s -D -B "$ip_b" >/dev/null; sleep 0.3
    nsx hA iperf3 -c "$ip_b" -t "$SOAK_SECONDS" -i 10 -f m --forceflush >"$WORK/soak.txt" 2>&1 &
    local iperf=$!
    echo "    t(s)  handshake age A/B (s)  peak RSS A/B (MiB)"
    for t in $(seq 10 10 "$SOAK_SECONDS"); do
        sleep 10
        printf "  %6s  %8s / %-8s     %s / %s\n" "$t" "$(hs A)" "$(hs B)" "$(hwm "${pid[A]}")" "$(hwm "${pid[B]}")"
    done
    wait "$iperf"
    grep -E "^\[ *[0-9]+\] +[0-9.]+-[0-9.]+ +sec" "$WORK/soak.txt" | grep -vE "sender|receiver" \
        | awk '{ printf "    %s s: %s %s, %s retransmits\n", $3, $7, $8, $9 }'
    grep -E "sender|receiver" "$WORK/soak.txt" | sed 's/^/  /'
    pkill -x iperf3 || true
    # Every 10 s interval must have moved data
    ! grep -E "^\[ *[0-9]+\] +[0-9.]+-[0-9.]+ +sec +0\.00 Bytes" "$WORK/soak.txt" | grep -q . \
        || { echo "  the transfer stalled"; return 1; }
}

# The client package handed out by the web admin page. Its own topology: two
# hosts straight on the "internet", hC installs and joins, hD gets refused
install_test() {
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

    local ok=1 link port W jar id rc st state nodes
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
    echo "  clients offered: $(curl -s -m 3 -b "$jar" "$W/api/status" | jq -r '[.clients[] | "\(.id) missing=\(.missing|join(","))"] | join("; ")')"
    curl -s -m 60 -b "$jar" -o "$WORK/pkg-old" "$W/download/$id/linux-x86_64"
    chmod +x "$WORK/pkg-old"
    echo "  package: $(( $(stat -c %s "$WORK/pkg-old") / 1048576 )) MiB"

    # hC runs the package: install under a prefix, start retaild, join
    local t0
    t0=$(date +%s.%N)
    nsx hC env RETAIL_INSTALL_YES=1 RETAIL_API_TOKEN_FILE="$WORK/hC.token" \
        "$WORK/pkg-old" --prefix "$WORK/hC" --no-service --no-autostart >"$WORK/install-hC.log" 2>&1
    rc=$?
    st=$(nsx hC env RETAIL_API_TOKEN_FILE="$WORK/hC.token" "$WORK/hC/bin/retail" status --json 2>/dev/null)
    state=$(echo "$st" | jq -r .state)
    echo "  hC: installer exit $rc, state $state after $(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN{printf "%.1f", b-a}')s; installed: $(ls "$WORK/hC/bin" | tr '\n' ' ')"
    [ "$rc" = 0 ] && [ "$state" = running ] || { ok=0; cat "$WORK/install-hC.log"; }
    cmp -s "$WORK/hC/bin/retail-tray" "$BIN/retail-tray" || { echo "  installed tray differs from the original"; ok=0; }

    # A new code for the invite: the old package cannot join anymore
    post /api/invites '{"name":"office"}' >/dev/null
    nsx hD env RETAIL_INSTALL_YES=1 RETAIL_API_TOKEN_FILE="$WORK/hD.token" \
        "$WORK/pkg-old" --prefix "$WORK/hD" --no-service --no-autostart >"$WORK/install-hD.log" 2>&1
    rc=$?
    if [ "$rc" != 0 ] && grep -qE "invalid, used or expired|wrong, already used, or expired" "$WORK/install-hD.log"; then
        echo "  the old package no longer joins after a new code"
    else
        echo "  the old package still joined (exit $rc)"; cat "$WORK/install-hD.log"; ok=0
    fi
    nodes=$(curl -s -m 3 -b "$jar" "$W/api/status" | jq '[.server.nodes[]] | length')
    [ "$nodes" = 1 ] && echo "  hC is still a member" || { echo "  members: $nodes"; ok=0; }
    [ "$ok" = 1 ]
}

# What each node knows, for DEBUG=1
debug_dump() {
    for s in A B; do
        echo "--- node $s"
        cli "$s" status --json 2>/dev/null \
            | jq -c '{self: .self_node.endpoints, peer_candidates: .peers[0].candidates, endpoint: .peers[0].endpoint, path: .peers[0].path, hs: .peers[0].last_handshake_secs}'
        grep -hE "STUN|dual_stack|endpoint|WARN|ERROR|relay|path" "$WORK/node$s.log" 2>/dev/null | sed 's/^.\{28\}//' | cut -c1-170 | head -12
    done
}

run_scenario() {
    local sc=$1 masq="" expect="direct"
    case $sc in
        symmetric | ipv6) masq="--random-fully" ;;
    esac
    case $sc in
        udp-blocked | symmetric | tcp443-only | udp443-only | recover | idle-relay | control-drop | exit-relay | reality) expect="relay" ;;
        proxy | inspect | cdn) expect="relay" ;;
        ipv6) expect="direct6" ;;
        nat64 | helper) expect="any" ;;
    esac
    cleanup
    rm -rf "$WORK" && mkdir -p "$WORK"
    [ "$sc" = install ] && { install_test; return; }
    HOST_V6=0; [ "$sc" = ipv6 ] || [ "$sc" = nat64 ] && HOST_V6=1
    NAT64=0; [ "$sc" = nat64 ] && NAT64=1
    topology_up "$masq"
    block "$sc"

    local invite
    declare -A pid
    # Extra environment per node: B finds proxies in HTTPS_PROXY
    declare -A envs=([A]="" [B]="")
    case $sc in
        proxy) start_proxies; envs[B]="HTTPS_PROXY=http://u:p4ss@192.168.2.1:3128" ;;
        inspect)
            start_inspecting_proxies
            envs[A]="HTTPS_PROXY=http://192.168.1.1:3128"
            envs[B]="HTTPS_PROXY=http://192.168.2.1:3128" ;;
        nat64) start_nat64 ;;
    esac
    if [ "$sc" = helper ]; then
        local code
        code=$(start_helper)
        [ -n "$code" ] || { echo "  helper node did not start"; tail -5 "$WORK/helper.log"; return 1; }
        for s in A B; do
            RUST_LOG="${RUST_LOG:-retaild=debug,retail_control=info}" start_node "$s"
            pid[$s]=$NODE_PID
        done
        sleep 0.5
        cli B server start --helper "$code" >/dev/null || { echo "  hosting on B failed"; return 1; }
        local linked=
        for _ in $(seq 100); do
            linked=$(cli B server status --json | jq -r '.helper_linked')
            [ "$linked" = true ] && break
            sleep 0.1
        done
        echo "  B linked to the helper: $linked"
        [ "$linked" = true ] || return 1
        invite=$(cli B server invite 2>/dev/null)
        echo "  invite leads with $(invite_first_addr "$invite")"
        cli A up --invite "$invite" --hostname a >/dev/null || { echo "  A could not join through the helper"; return 1; }
    elif [[ $sc == host-* ]]; then
        NATPMP=yes; [ "$sc" = host-upnp ] && NATPMP=no
        start_upnp_router B
        for s in A B; do
            RUST_LOG="${RUST_LOG:-retaild=debug,retail_control=info}" start_node "$s"
            pid[$s]=$NODE_PID
        done
        sleep 0.5
        cli B server start >/dev/null || { echo "  hosting on B failed"; return 1; }
        local public=
        for _ in $(seq 100); do
            public=$(cli B server status --json | jq -r '.public // empty')
            [ -n "$public" ] && break
            sleep 0.1
        done
        echo "  router: $(cli B server status --json | jq -r '.port_mapping // "nothing"'), public address ${public:-none}"
        [ "$public" = 198.51.101.2:443 ] || { echo "  expected the router's public address 198.51.101.2:443"; return 1; }
        invite=$(cli B server invite 2>/dev/null)
        echo "  invite leads with $(invite_first_addr "$invite")"
        cli A up --invite "$invite" --hostname a >/dev/null || { echo "  A could not join from outside"; return 1; }
    else
        if [ "$sc" = reality ]; then
            start_camouflage
            server_start 443 --reality "www.camouflage.test=203.0.113.81:8443"
        elif [ "$sc" = cdn ]; then
            # The edge listens on 8443: the server holds 443 on every address here
            server_start 443 --front https://cdn.test:8443
            start_cdn
        else
            server_start 443
        fi
        invite=$(server_invite)
        [ -n "$invite" ] || { echo "  server did not start"; tail -5 "$WORK/control.log"; return 1; }
        for s in A B; do
            # shellcheck disable=SC2086
            start_node "$s" ${envs[$s]}
            pid[$s]=$NODE_PID
        done
        sleep 0.5
        [ "$sc" = proxy ] && cli A set --proxy http://u:p4ss@192.168.1.1:3128 >/dev/null
        cli A up --invite "$invite" --hostname a >/dev/null || { echo "  up A failed"; return 1; }
        cli B up --invite "$invite" --hostname b >/dev/null || { echo "  up B failed"; return 1; }
    fi
    local ip_b took path ok=1
    ip_b=$(cli B ip)
    # Through REALITY, joining waits out the blocked plain-HTTPS attempt first
    local limit=$CONNECT_TIMEOUT
    [ "$sc" = reality ] && limit=40
    # HTTP polling starts after the faster ways have failed
    [ "$sc" = inspect ] && limit=20
    [ "$sc" = nat64 ] || [ "$sc" = helper ] && limit=15
    if took=$(wait_ping "$ip_b" "$limit"); then
        path=$(path_of A)
        printf "  connected after %ss, path: %s\n" "$took" "$path"
        sleep 2
        local idle_a idle_b
        idle_a=$(awk '/^VmRSS/ {print $2}' "/proc/${pid[A]}/status" 2>/dev/null)
        idle_b=$(awk '/^VmRSS/ {print $2}' "/proc/${pid[B]}/status" 2>/dev/null)
        printf "  idle RSS: A %.1f MiB, B %.1f MiB\n" "$(awk -v k="${idle_a:-0}" 'BEGIN{print k/1024}')" "$(awk -v k="${idle_b:-0}" 'BEGIN{print k/1024}')"
        [ "${idle_a:-0}" -le "$IDLE_LIMIT_KB" ] || { echo "  idle RSS of A above 20 MiB"; ok=0; }
        # A device hosting the network also runs the server
        local limit_b=$IDLE_LIMIT_KB
        [[ $sc == host-* || $sc == helper ]] && limit_b=$((20 * 1024))
        [ "${idle_b:-0}" -le "$limit_b" ] || { echo "  idle RSS of B above $((limit_b / 1024)) MiB"; ok=0; }
    else
        path=$(path_of A)
        printf "  NO CONNECTION within %ss (path: %s)\n" "$CONNECT_TIMEOUT" "$path"
        ok=0
    fi
    if [ "$ok" = 1 ]; then
        case $expect in
            direct) [[ $path == direct\ [0-9]* ]] || { echo "  expected a direct IPv4 path"; ok=0; } ;;
            direct6) [[ $path == direct\ \[* ]] || { echo "  expected a direct IPv6 path"; ok=0; } ;;
            relay) [[ $path == relay* ]] || { echo "  expected a relay path"; ok=0; } ;;
        esac
        local via_a via_b
        via_a=$(cli A status --json | jq -r '.control_via // "-"')
        via_b=$(cli B status --json | jq -r '.control_via // "-"')
        echo "  control: A $via_a, B $via_b"
        case $sc in
            proxy) [[ $via_a == *"via proxy http://192.168.1.1:3128"* && $via_b == *"via proxy http://192.168.2.1:3128"* ]] || { echo "  expected both through their proxy"; ok=0; } ;;
            inspect) [[ $via_a == "HTTP polling"*"via proxy"* ]] || { echo "  expected HTTP polling through the proxy"; ok=0; } ;;
            cdn) [[ $via_a == *"https://cdn.test:8443"* ]] || { echo "  expected a tunnel through the CDN"; ok=0; } ;;
            nat64) grep -q "NAT64" "$WORK/nodeA.log" && echo "  A found the NAT64 prefix" || { echo "  A did not find NAT64"; ok=0; } ;;
        esac
        nsx hB iperf3 -s -D -B "$ip_b" >/dev/null; sleep 0.3
        local bw
        bw=$(nsx hA timeout 20 iperf3 -c "$ip_b" -t 4 -J 2>/dev/null | jq -r '.end.sum_received.bits_per_second / 1e6 | floor' 2>/dev/null)
        echo "  iperf3 A->B: ${bw:-failed} Mbit/s"
        pkill -x iperf3 || true
    fi
    if [ "$sc" = direct ] && [ "$ok" = 1 ]; then
        # Changes without the API token are refused, but reads are not
        if ip netns exec hA env RETAIL_API_TOKEN_FILE=/nonexistent "$BIN/retail" down 2>&1 | grep -q "not allowed"; then
            echo "  local API refuses changes without the token"
        else
            echo "  local API accepted a change without the token"; ok=0
        fi
        ip netns exec hA env RETAIL_API_TOKEN_FILE=/nonexistent "$BIN/retail" status >/dev/null || { echo "  status needs no token"; ok=0; }
        lifecycle_checks "$ip_b" || ok=0
    fi
    if [ "$sc" = switch ] && [ "$ok" = 1 ]; then
        switch_checks "$ip_b" || ok=0
    fi
    if [ "$sc" = rekey ] && [ "$ok" = 1 ]; then
        soak "$ip_b" || ok=0
    fi
    if [[ $sc == exit* ]] && [ "$ok" = 1 ]; then
        exit_checks "$sc" "$ip_b" || ok=0
    fi
    if [ "$sc" = reality ] && [ "$ok" = 1 ]; then
        grep -q "REALITY" "$WORK/nodeA.log" && echo "  A reached the server through REALITY" || { echo "  A did not use REALITY"; ok=0; }
        # An active probe (not a REALITY client) naming the website gets the website
        local page
        page=$(nsx hA curl -sk -m 5 --resolve www.camouflage.test:443:198.51.100.1 https://www.camouflage.test/ | head -c 2000)
        if echo "$page" | grep -q "s_server"; then
            echo "  a probe of the server got the real website"
        else
            echo "  a probe of the server did NOT get the website"; ok=0
        fi
        # Plain HTTPS to the server really is blocked here
        nsx hA curl -sk -m 3 -o /dev/null https://198.51.100.1/health && { echo "  plain HTTPS was not blocked (harness error)"; ok=0; }
    fi
    if [ "$sc" = host-nat ] && [ "$ok" = 1 ]; then
        web_checks "$ip_b" || ok=0
    fi
    if [[ $sc == host-* ]] && [ "$ok" = 1 ]; then
        cli B server stop >/dev/null
        local down=0
        for i in $(seq 80); do
            [ "$(cli A status --json | jq -r .control_connected)" = false ] && { down=$i; break; }
            sleep 0.1
        done
        if [ "$down" -gt 0 ]; then echo "  server stopped: A disconnected after $(awk -v t="$down" 'BEGIN{printf "%.1f", t/10}')s"; else echo "  A still connected 8s after the server stopped"; ok=0; fi
        local left
        left=$(nsx rB iptables-legacy -t nat -S MINIUPNPD | grep -c -- '-A MINIUPNPD')
        [ "$left" = 0 ] && echo "  router mappings removed" || { echo "  $left router mappings left behind"; ok=0; }
        cli B server start >/dev/null
        local up=0
        for i in $(seq 300); do
            [ "$(cli A status --json | jq -r .control_connected)" = true ] && { up=$i; break; }
            sleep 0.1
        done
        if [ "$up" -gt 0 ]; then echo "  server started again: A reconnected after $(awk -v t="$up" 'BEGIN{printf "%.1f", t/10}')s"; else echo "  A did not reconnect within 30s"; ok=0; fi
        nsx hA ping -c3 -i0.2 -q "$ip_b" | grep -q " 0% packet loss" || { echo "  no ping after the restart"; ok=0; }
    fi
    if [ "$sc" = idle-relay ] && [ "$ok" = 1 ]; then
        sleep 40
        local pa pb
        pa=$(path_of A); pb=$(path_of B)
        echo "  after 40 s idle: A sees '$pa', B sees '$pb'"
        [[ $pa == relay* && $pb == relay* ]] || { echo "  relay path not kept while idle"; ok=0; }
        nsx hA ping -c5 -i0.2 -q "$ip_b" | grep -q " 0% packet loss" || { echo "  packet loss when resuming"; ok=0; }
    fi
    if [[ $sc == failover* ]] && [ "$ok" = 1 ]; then
        # 0.1 s pings for 20 s, with UDP cut 3 s in
        nsx hA ping -i0.1 -c200 -W1 -q "$ip_b" >"$WORK/ping.txt" 2>&1 &
        local pp=$!
        sleep 3
        case $sc in
            failover) block udp-blocked ;;
            failover-a | failover-b)
                local site=${sc#failover-}; site=${site^^}
                nsx "r$site" iptables -I FORWARD 1 -i "lan$site" -p udp -j DROP
                nsx "r$site" ip6tables -I FORWARD 1 -i "lan$site" -p udp -j DROP ;;
        esac
        wait $pp
        local rcvd lost
        rcvd=$(grep -oE '[0-9]+ received' "$WORK/ping.txt" | cut -d' ' -f1)
        lost=$((200 - ${rcvd:-0}))
        echo "  outage after UDP was cut: ~$(awk -v l="$lost" 'BEGIN { printf "%.1f", l / 10 }')s, now $(path_of A)"
        [ "$lost" -le 60 ] || { echo "  failover too slow"; ok=0; }
        [[ $(path_of A) == relay* ]] || { echo "  not on the relay after failover"; ok=0; }
        if [ "$sc" != failover ]; then
            # Lift the one-sided cut, after which both sides must go direct again
            local site=${sc#failover-}; site=${site^^}
            nsx "r$site" iptables -D FORWARD -i "lan$site" -p udp -j DROP
            nsx "r$site" ip6tables -D FORWARD -i "lan$site" -p udp -j DROP
            nsx hA ping -i0.2 -c75 -q "$ip_b" >/dev/null 2>&1 &
            local up=0
            for i in $(seq 15); do
                sleep 1
                if [[ $(path_of A) == direct* ]] && [[ $(path_of B) == direct* ]]; then up=$i; break; fi
            done
            pkill -f "ping -i0.2 -c75" || true
            if [ "$up" -gt 0 ]; then echo "  back to direct ${up}s after the cut was lifted"; else echo "  did NOT return to direct within 15s"; ok=0; fi
        fi
    fi
    if [ "$sc" = control-drop ] && [ "$ok" = 1 ]; then
        # The control connection's packets vanish (no RST), as when a NAT
        # forgets the flow, and then the path comes back
        for t in iptables ip6tables; do
            nsx rA $t -I FORWARD 1 -p tcp --dport 443 -j DROP
            nsx rA $t -I FORWARD 1 -p tcp --sport 443 -j DROP
        done
        sleep 30
        for t in iptables ip6tables; do
            nsx rA $t -D FORWARD -p tcp --dport 443 -j DROP
            nsx rA $t -D FORWARD -p tcp --sport 443 -j DROP
        done
        local back
        if back=$(wait_ping "$ip_b" 40); then
            echo "  relay back ${back}s after the control path returned"
            awk -v b="$back" 'BEGIN { exit !(b <= 20) }' || { echo "  recovery too slow"; ok=0; }
        else
            echo "  relay did NOT come back within 40s"; ok=0
        fi
    fi
    if [ "$sc" = recover ] && [ "$ok" = 1 ]; then
        unblock_udp
        local up=0
        for i in $(seq 60); do
            sleep 1
            if [[ $(path_of A) == direct* ]] && [[ $(path_of B) == direct* ]]; then up=$i; break; fi
        done
        if [ "$up" -gt 0 ]; then echo "  upgraded to direct ${up}s after the block was lifted"; else echo "  did NOT return to a direct path within 60s"; ok=0; fi
        nsx hA ping -c5 -i0.2 -q "$ip_b" | grep -q " 0% packet loss" || { echo "  packet loss after upgrade"; ok=0; }
    fi
    for s in A B; do
        local hwm
        hwm=$(awk '/^VmHWM/ {print $2}' "/proc/${pid[$s]}/status" 2>/dev/null || echo 0)
        if [ "${hwm:-0}" -gt "$PEAK_LIMIT_KB" ]; then echo "  node $s peak RSS ${hwm} kB exceeds 20 MiB"; ok=0; fi
        printf "  node %s peak RSS %.1f MiB\n" "$s" "$(echo "${hwm:-0}" | awk '{print $1/1024}')"
    done
    [ "$ok" = 1 ]
}

[ "${KEEP:-0}" = 1 ] || trap cleanup EXIT
if [ "$WHICH" = all ]; then
    set -- direct udp-blocked symmetric tcp443-only udp443-only ipv6 recover idle-relay failover failover-a failover-b control-drop exit exit-relay exit-offline host-nat host-upnp reality proxy inspect cdn nat64 helper switch install
else
    set -- "$WHICH"
fi
results=()
for sc in "$@"; do
    echo "== $sc"
    if run_scenario "$sc"; then results+=("PASS $sc"); else results+=("FAIL $sc"); fi
done
[ "${DEBUG:-0}" = 1 ] && debug_dump
echo "== summary"
printf '  %s\n' "${results[@]}"
printf '%s\n' "${results[@]}" | grep -q FAIL && exit 1 || exit 0
