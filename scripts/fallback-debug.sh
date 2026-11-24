#!/usr/bin/env bash
# Runs one fallback scenario, keeps the namespaces, and prints what each node
# knows (endpoints, candidates, path) plus the interesting log lines.
#   sudo scripts/fallback-debug.sh [BIN_DIR] SCENARIO
set -u
cd "$(dirname "$0")/.."
BIN="$(cd "${1:-target/release}" && pwd)"
KEEP=1 CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-6}" bash scripts/fallback-netns.sh "$BIN" "$2" | grep -v summary
for s in A B; do
    echo "--- node $s"
    ip netns exec "h$s" "$BIN/retail" status --json \
        | jq -c '{self: .self_node.endpoints, peer_candidates: .peers[0].candidates, endpoint: .peers[0].endpoint, path: .peers[0].path, hs: .peers[0].last_handshake_secs}'
    grep -hE "STUN|dual_stack|endpoint|WARN|ERROR|relay|path" "/tmp/retail-fallback/node$s.log" | sed 's/^.\{28\}//' | cut -c1-170 | head -12
done
