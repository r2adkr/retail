# retail

A **self-hosted mesh VPN**, written in Rust, with WireGuard (boringtun) as the data tunnel.

- Every device gets a `100.64.x.y` virtual IP and talks to the others **directly**, wherever they are. STUN and UDP hole punching (IPv4 and IPv6) get through NATs.
- When a direct connection is impossible (blocked UDP, symmetric NAT), traffic **switches to a relay** over the server's HTTPS port 443 on its own, and goes back to direct once a path opens. If the direct path dies mid-transfer (even in one direction only), the relay takes over within about 3 seconds. The way to the server races several methods too: when HTTPS is blocked it uses **REALITY** (looking like a visit to another website), company **proxies** (signing in with the Windows account automatically), **HTTP tunnels** through firewalls that open TLS, **CDNs**, and **NAT64** on IPv6-only networks.
- **No separate server program.** One button in the tray's server window makes this device the network's server; other devices join with an invite code or QR code. Router ports open automatically (PCP, NAT-PMP, UPnP). Behind carrier-grade NAT, add one VPS as a **helper node**. The **web admin page** opens on the server PC and on devices you allow; from there you download an **installer** that carries an invite, and whoever runs it joins.
- **Several networks**: the device remembers every server it joined and switches between them from Settings without new invites. An installer from another server asks before switching.
- **Exit node**: reach the internet through another device. Turn it on from the ⋯ menu next to a device.
- **Light**: the daemon idles at about 12 MB of memory and outruns wireguard-go in the same environment (measured twice in one session: single stream +34–37%, 4 streams +28–94%). You can also set a memory limit (`retail set --memory-limit`). The numbers are in the [design document](docs/DESIGN.md).
- The app follows the system's light or dark theme and speaks English, Korean, Japanese, Simplified Chinese and Spanish.

| Tray popup | Server window | Saved servers |
|---|---|---|
| ![](docs/img/tray-connected-dark.png) | ![](docs/img/server-running-light.png) | ![](docs/img/settings-servers-light.png) |

## Programs

| Binary | Role |
|---|---|
| `retaild` | The daemon on each device (needs administrator/root). When it hosts the network, the server runs inside it too |
| `retail-tray` | Tray (Windows/Linux) and menu bar (macOS) app: status, connection, exit node, server window, settings |
| `retail` | CLI |

## Getting started

The easiest way: on the device that will be the server, start retail, create an invite in the web admin page and send the downloaded installer to the others. They only have to run it.

By hand:

1. On each device run `retaild` and open `retail-tray`.
   - Windows: put [wintun.dll](https://www.wintun.net/) (amd64) next to `retaild.exe` and run it as administrator.
   - Linux: use `packaging/systemd/retaild.service`.
2. On one device: tray → gear → **Manage server** → **Open server**, then **Create invite**.
3. On the others: tray → gear → **Settings**, paste the invite code and click **Connect**.

Running only the server on a VPS or in Docker, and setting up REALITY, are covered in [docs/SELF-HOSTING.md](docs/SELF-HOSTING.md).

The CLI does the same:

```sh
retail server start && retail server invite   # open a network on this device
retail up --invite retail1....                # join from another device
retail status
retail set --exit-node <device>               # use an exit node (none: stop)
retail set --advertise-exit-node              # offer this device as an exit node
retail servers                                # servers joined before; retail switch / retail forget <server>
retail down       # disconnect (registration kept)
retail logout     # leave the current server
```

Commands that change things need the local API token: on Windows any user signed in to the computer, on Linux root or the `retail` group, on macOS administrators.

## Building

```sh
cargo build --release
```

## Testing

```sh
cargo test --workspace
```

End-to-end tests run in Linux network namespaces, across two NATs. They need root, `iptables`, `iperf3`, `jq`, `python3` and `openssl`; the router port scenarios also need `miniupnpd`, the proxy scenarios `tinyproxy`, and the NAT64 scenario `tayga` (`scripts/wsl.sh setup` installs them all on Debian/Ubuntu or WSL).

```sh
sudo scripts/netns-test.sh target/release all      # 25 scenarios: paths, failover, exit node, hosting, web admin,
                                                   # REALITY, proxies, CDN, NAT64, helper node, switching servers, installer
sudo scripts/netns-test.sh target/release ipv6     # one scenario (DEBUG=1 keeps it running and shows node state)
sudo SOAK_SECONDS=240 scripts/netns-test.sh target/release rekey   # long transfer across WireGuard rekeys
sudo RUNS=3 scripts/bench.sh target/release        # throughput against wireguard-go and kernel WireGuard, if installed
```

The tray's screens render to PNG without opening a window:

```sh
retail-tray --preview popup.png --state connected --dark
retail-tray --preview settings.png --settings --state login --lang ja
retail-tray --preview server.png --server --state running
```

## Scope and next steps

There are no access controls between devices, no MagicDNS and no automatic updates yet. See the milestones and known limitations in the [design document](docs/DESIGN.md).

> retail uses the `100.64.0.0/10` address range. Do not run it at the same time as another VPN that uses that range on the same device.
