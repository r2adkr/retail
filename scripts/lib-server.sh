# Shared by the netns test scripts (sourced): the coordination server is a
# server-only retaild in the root namespace (the "internet"), administered
# through its own local API, as on a VPS. Router port mapping is off so the
# tests never talk to the real network.
#
# Needs BIN and WORK.

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
