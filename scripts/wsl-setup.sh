#!/usr/bin/env bash
# Installs the toolchain needed to build retail and run scripts/e2e-netns.sh
# inside a Debian/Ubuntu (WSL) environment. Run as root.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y -qq build-essential iptables iperf3 iproute2 curl iputils-ping >/dev/null
echo "apt packages installed"

if ! command -v cargo >/dev/null && [ ! -x "$HOME/.cargo/bin/cargo" ]; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
fi
"$HOME/.cargo/bin/cargo" --version
