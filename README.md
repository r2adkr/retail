# retail

[![ci](https://github.com/r2adkr/retail/actions/workflows/ci.yml/badge.svg)](https://github.com/r2adkr/retail/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

A self-hosted mesh VPN. Your devices reach each other directly over WireGuard, from any network, through a server you run yourself: on one of your own devices or on a small VPS.

| Tray | Server window | Saved servers |
|---|---|---|
| ![Tray popup](docs/img/tray-connected-dark.png) | ![Server window](docs/img/server-running-light.png) | ![Saved servers](docs/img/settings-servers-light.png) |

## Features

- **Direct connections** through NATs (STUN and hole punching, IPv4 and IPv6), with an automatic relay over HTTPS when no direct path exists.
- **Gets through restrictive networks**: blocked UDP, TLS-inspecting firewalls, company proxies (with Windows sign-in), CDNs, NAT64, and REALITY camouflage.
- **No separate server to install**: any device hosts the network from the tray app. Invite others with a code, a QR code, or an installer that joins on its own.
- **Works behind CGNAT** with a helper node: any member device that other networks can reach, or a VPS.
- **MagicDNS**: reach devices by name, such as `nas.retail.internal`.
- **Access control** with device tags and rules.
- **Subnet routes**: reach a whole LAN (printers, NAS, cameras) through one device in it.
- **Lost devices** are cut off with one click; device keys can expire, and devices gone for long are cleaned up.
- **Encrypted server backups** to restore or move the server; devices keep their addresses and names.
- **Exit nodes**, several saved networks per device, and automatic updates.
- **Small and fast**: about 12 MB of memory, faster than wireguard-go in our [measurements](docs/DESIGN.md), and builds for Raspberry Pi and other ARM machines.
- Desktop app for Windows, macOS and Linux in English, Korean, Japanese, Chinese and Spanish, plus a CLI and a terminal UI.

## Install

Download the programs for your system from [Releases](https://github.com/r2adkr/retail/releases).

| Program | What it is |
|---|---|
| `retaild` | The daemon on each device (runs as administrator/root); also the server when the device hosts |
| `retail-tray` | Tray / menu bar app |
| `retail` | CLI and `retail tui` |

**Desktop**: the easiest way is an installer from your network's server. On the server, create an invite and save the installer for the other person's system from its ⋯ menu (in the server window or the web admin page). Running it installs retail and joins the network.

**Server without a screen** (Linux VPS, Raspberry Pi):

```sh
sudo ./retaild install --server
```

This installs `retaild` and `retail`, starts them at boot, starts the server and prints the first invite. Docker works too; see [Self-hosting](docs/SELF-HOSTING.md).

## Quick start

On the device that will be the server, in the tray app: **⚙ → Manage server → Open server**, then **Create invite**. Or:

```sh
retail server start
retail server invite
```

On the other devices, paste the code in **⚙ → Settings** and click **Connect**. Or:

```sh
retail up --invite retail1.…
retail status            # devices, paths and names
retail tui               # the same in a terminal UI
```

Then, for example:

```sh
retail set --exit-node <device>                                       # send internet traffic through another device
retail server acl allow --from '*' --to tag:server --ports tcp:443    # access rules
retail server helper-device <device>                                  # helper node behind CGNAT
retail set --advertise-routes 192.168.1.0/24                          # route this LAN (then: retail server routes <device>)
retail server backup retail-server.retail-backup                      # encrypted backup of the server
retail server web                                                     # open the web admin page
```

`retail --help` lists every command. Commands that change things need the local API token: on Windows any signed-in user, on Linux root or the `retail` group, on macOS administrators.

## Documentation

- [Self-hosting](docs/SELF-HOSTING.md): servers, helper nodes, CDN and REALITY, access rules, subnet routes, backups, updates
- [Design](docs/DESIGN.md): how it works, security model, performance, known limitations
- [Development](docs/DEVELOPMENT.md): building, tests, releases

## Notes

- retail uses the `100.64.0.0/10` address range. Do not run it on a device together with another VPN that uses that range.
- The programs are not code-signed yet, so Windows SmartScreen and macOS Gatekeeper may warn on first launch. There are no mobile apps yet.

## Contributing

Contributions are welcome, big or small: bug reports, testing on networks and devices we haven't tried, translations, docs and code. Open an [issue](https://github.com/r2adkr/retail/issues) to report a problem or discuss an idea, or send a pull request. [Development](docs/DEVELOPMENT.md) explains how to build and test.

## License

[Apache-2.0](LICENSE). The vendored [boringtun](vendor/boringtun) is BSD-3-Clause.
