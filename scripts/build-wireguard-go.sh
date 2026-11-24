#!/usr/bin/env bash
# Builds wireguard-go (the official userspace WireGuard implementation,
# including its GSO/GRO work) for use as a reference in scripts/bench.sh.
# Installs Go from apt. Go may fetch a newer toolchain if go.mod requires it.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
command -v go >/dev/null || apt-get install -y -qq golang-go git make >/dev/null
SRC=/opt/wireguard-go
[ -d "$SRC" ] || git clone --depth 1 https://git.zx2c4.com/wireguard-go "$SRC"
cd "$SRC"
git log -1 --format='wireguard-go %h %cd' --date=short
GOTOOLCHAIN=auto make >/dev/null
install -m 0755 wireguard-go /usr/local/bin/wireguard-go
wireguard-go --version
