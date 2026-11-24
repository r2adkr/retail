# Development

## Building

retail builds with the Rust toolchain pinned in `rust-toolchain.toml` (rustup installs it on the first build).

```sh
cargo build --release          # target/release/retaild, retail, retail-tray
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

On Windows, `retaild.exe` needs [wintun.dll](https://www.wintun.net/) (amd64) in the same folder to create its network device.

## End-to-end tests

The end-to-end tests run on Linux in network namespaces: two sites, each behind a NAT router with a home-router firewall, joined through the root namespace as "the internet". They need root, `iptables`, `iperf3`, `jq`, `python3` and `openssl`; the router port scenarios also need `miniupnpd`, the proxy scenarios `tinyproxy`, and the NAT64 scenario `tayga`. `scripts/wsl.sh setup` installs all of them on Debian, Ubuntu or WSL.

```sh
sudo scripts/netns-test.sh target/release all      # every scenario (the list is at the top of the script)
sudo scripts/netns-test.sh target/release ipv6     # one scenario; DEBUG=1 keeps it running and shows node state
sudo SOAK_SECONDS=240 scripts/netns-test.sh target/release rekey   # a long transfer across WireGuard rekeys
sudo RUNS=3 scripts/bench.sh target/release        # throughput against wireguard-go and kernel WireGuard, if installed
```

From a Windows checkout, copy the tree into WSL and run `bash scripts/wsl.sh run netns-test.sh target/release all` there as root; it normalises line endings and builds first.

## Screens without a window

The tray app renders its screens to PNG for checking layouts and translations:

```sh
retail-tray --preview popup.png --state connected --dark
retail-tray --preview settings.png --settings --state login --lang ja
retail-tray --preview server.png --server --state running
```

## Releases

Pushing a tag `vX.Y.Z` that matches the version in `Cargo.toml` runs `.github/workflows/release.yml`: it builds every platform, writes `SHA256SUMS` and `VERSION`, and publishes the GitHub release that servers fetch clients from and daemons update from.

## Layout

The design, including the protocols, the data plane and the measurements, is in [DESIGN.md](DESIGN.md).

| Crate | What it is |
|---|---|
| `retail-proto` | Wire types, invite codes, access-rule types |
| `retail-control` | The coordination server (runs inside `retaild` when it hosts) |
| `retail-daemon` | `retaild`: data plane, NAT traversal, hosting, local API |
| `retail-cli` | `retail` and `retail tui` |
| `retail-web` | The web admin page and installer packages |
| `retail-tray` | The tray / menu bar app |
