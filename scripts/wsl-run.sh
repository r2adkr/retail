#!/usr/bin/env bash
# Helper for driving tests in WSL from Windows: normalises line endings,
# builds in release mode, then runs the given script with its arguments.
#   wsl -u root -- bash /root/retail/scripts/wsl-run.sh fallback-netns.sh target/release ipv6
set -u
cd "$(dirname "$0")/.."
sed -i 's/\r$//' scripts/*.sh
cargo build --release 2>&1 | grep -E '^(error|warning)|Finished'
script=$1; shift
exec bash "scripts/$script" "$@"
