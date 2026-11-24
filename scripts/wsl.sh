#!/usr/bin/env bash
# Runs the Linux tests in WSL (or any Debian/Ubuntu) from a Windows checkout.
#
#   wsl -u root -- bash /root/retail/scripts/wsl.sh setup
#       installs the toolchain and the tools the netns tests use
#   wsl -u root -- bash /root/retail/scripts/wsl.sh run netns-test.sh target/release ipv6
#       normalises line endings, builds in release mode, then runs the script
set -euo pipefail
cd "$(dirname "$0")/.."

case "${1:-}" in
    setup)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq build-essential iptables iperf3 iproute2 curl iputils-ping jq python3 openssl \
            miniupnpd tinyproxy tayga >/dev/null
        echo "apt packages installed"
        if ! command -v cargo >/dev/null && [ ! -x "$HOME/.cargo/bin/cargo" ]; then
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
        fi
        "$HOME/.cargo/bin/cargo" --version
        ;;
    run)
        shift
        . "$HOME/.cargo/env"
        sed -i 's/\r$//' scripts/*.sh
        cargo build --release 2>&1 | grep -E '^(error|warning)|Finished'
        script=$1; shift
        exec bash "scripts/$script" "$@"
        ;;
    *)
        echo "usage: wsl.sh setup | run SCRIPT [ARGS...]" >&2
        exit 2
        ;;
esac
