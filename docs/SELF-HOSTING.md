# Running your own network

retail has no separate server program. One device acts as the network's server, and other devices join with an invite code. The server registers devices, hands out addresses and passes connection details around; the traffic itself goes straight between devices. Only pairs of devices that cannot reach each other directly relay through the server's port 443.

## On a home PC (one button)

1. Open the server window: the gear at the bottom right of the tray popup → **Manage server**.
2. Click **Open server**. This device becomes the server and the first device of the new network.
   - If this device was in another network, it moves to the new one. The window says so beforehand.
3. **Create invite** shows a one-time invite code and a QR code. Paste the code into the settings window on the other device and click **Connect**.
   - The invite works once and expires after 24 hours. The code carries the server address, the fingerprint of the server certificate's key and an auth key, so there is no domain or certificate to set up.

The CLI does the same:

```sh
retail server start            # start the server (this device joins too)
retail server invite           # print an invite code (--reusable: many uses, --name: a named invite)
retail server web              # open the web admin page
retail server status           # addresses, router state, devices, invites
retail server remove <id>      # remove a device
retail server stop             # stop (registrations stay and resume on the next start)
```

Other devices join with `retail up --invite retail1.…`.

## Web admin page and installers

**Manage on the web** in the server window (or `retail server web`) opens the admin page in the browser. It turns the server on and off and manages invites and devices. It follows the browser's language (English, Korean, Japanese, Simplified Chinese or Spanish).

- **Where it opens**: only on the server PC, and on devices given **Allow managing from this device** in the ⋯ menu of the device list (while connected to retail, at `http://<the server's 100.64 address>:41180`). It is never open to the internet.
  - On the server PC you get in with a sign-in link that works once, within 2 minutes (other programs on the same PC cannot get in without one).
  - Allowed devices need no sign-in, since retail (WireGuard) vouches for their address.
  - A server-only VPS (`--no-join`) is not a member of the network, so its page opens only on the VPS itself. Use SSH port forwarding to see it from elsewhere (`ssh -L 41180:127.0.0.1:41180 vps`).
- **Create invite**: one dialog for both kinds, **Multi-device** (a named, reusable invite) and **One-time** (24 hours, one device). All invites show in one list; a one-time invite's code is shown only when it is created.
- **Multi-device invites**: keep as many named, reusable invites as you like, such as "Family" and "Work". Expire one at any time; **New code** voids only that invite's old code (and the installers that carry it). Devices that already joined stay. CLI: `retail server invite --name Family [--hours N]`, `retail server code <id>`, `retail server revoke <id>`.
  - So that installers can be made again later, a named invite's code is kept in the server's data folder (readable by administrators only). One-time invites are kept as hashes only.
- **Installers**: every multi-device invite has a **Download ▾** menu with Windows, Linux and macOS. Hand the one file to the other person, who only has to run it. It asks for administrator rights once, installs the programs, registers the daemon to start at boot (Windows Task Scheduler, Linux systemd, macOS launchd), joins with the invite and opens the tray app.
  - The server makes the file on the spot by appending the invite to a prebuilt client. Nothing is compiled.
  - For the server's own system it uses the programs installed on the server (on Windows `wintun.dll` must sit in the same folder). For other systems the server downloads the official client of its own version from [GitHub Releases](https://github.com/r2adkr/retail/releases) the first time, checks it against `SHA256SUMS` and keeps it (`RETAIL_RELEASES` changes the address; an empty value turns this off). A server that cannot reach GitHub can take the files through **upload files…** in the download menu: `retail-tray`, `retaild` and `retail` for that system (on Windows the `.exe` files and `wintun.dll`). The server checks that each is an executable for that system (PE, ELF, Mach-O). To place them by hand, put the same files in `clients/<os>-<arch>/` under retaild's state folder (`/var/lib/retail/clients/windows-x86_64/` on Linux, `C:\ProgramData\retail\clients\linux-x86_64\` on Windows, and so on).
  - An installer carries a reusable invite, so do not pass it around freely. If one leaks, use ⋯ → **New code** on that invite.
  - retail is not code-signed yet, so Windows SmartScreen or macOS Gatekeeper may warn.
  - On a device that already belongs to another network, the installer asks whether to switch. On yes the device leaves its current network cleanly, keeps it in its server list (Settings → **Change server** switches back) and joins this one. To remove retail: run the installed `retail-tray --uninstall` (as administrator).

### Reaching the server from outside

When the server starts, retail **opens ports on the router automatically with PCP or NAT-PMP, falling back to UPnP** (TCP 443 and 80, UDP 3478, UDP 41641). The router ports row of the server window shows the result. On Windows it also adds firewall rules that apply only to retaild, and removes them when the server stops.

- If the router does not support automatic port opening, the server window explains how to forward the ports by hand.
- If the router's external address is private (carrier-grade NAT, or two routers in a row), the window warns that the server cannot be reached from outside. Devices on the same network can still join, and devices outside can join through a **helper node** (below).
- If your public IP changes, give a dynamic DNS name with `retail server start --domain myhome.example.net`. Invite codes then carry that name instead of the IP.

## On a VPS or in Docker

On a server without a screen, install retaild and turn on the server only. The server does not join the network itself, so it needs no TUN device either.

```sh
sudo systemctl enable --now retaild                     # packaging/systemd/retaild.service
retail server start --no-join                           # comes back after a reboot
retail server invite                                    # invite a device
```

Docker:

```sh
cp packaging/docker/example.env packaging/docker/.env
docker compose -f packaging/docker/compose.yml up -d
docker compose -f packaging/docker/compose.yml exec retail-server retail server invite
```

Ports to open: TCP 443 (registration, control, relay), UDP 3478 (STUN).

## REALITY for networks that block the server

For company, school or national firewalls that block TLS to the server by its name or by the shape of the handshake. With it on, devices connect over plain HTTPS as usual and, after two failures in a row, connect with **TLS that looks like a connection to another, allowed website**.

```sh
retail server start --reality www.example.com     # look like that website
retail server start --reality off                 # turn it off
```

- Invite codes made after turning it on carry the setting. Devices that already joined use it after joining again with a new invite.
- A connection to the server's address that is not one of our devices (a firewall's probe, say) is passed through to the real website, so the prober sees the real website.
- It does not help against a block of the server's IP itself.
- The clocks of the server and the devices must agree within 2 minutes.
- The chosen website must offer HTTPS (TLS 1.3) and be reachable from the server.
- Devices try plain HTTPS and REALITY 1.5 seconds apart, so even on a blocking network they connect within seconds.

## A server behind CGNAT: helper node

At a home behind carrier-grade NAT (the provider shares one public address among customers), opening router ports does not let anyone in from outside. One small server with a public address (a VPS) as a **helper node** solves this. The helper only passes connections through to the server: it cannot read them and stores no network data.

```sh
# On the VPS (with retaild installed)
retail helper start                  # prints a code (retailh1.…); comes back after a reboot
retail helper start --public vps.example.com   # when it cannot tell its own address

# On the home server device
retail server start --helper retailh1.…
retail server invite                 # invite codes now carry the helper's address
```

Ports to open on the VPS: TCP 443 and 80, UDP 3478. In Docker, turn it on with `retaild --helper` (`RETAIL_HELPER=1`).

## Networks that block the server's address: CDN

If the server's IP itself is blocked, or only web (HTTPS) traffic gets out, connect a domain to a CDN such as Cloudflare, have it forward to port 443 of the server (or of the helper node), and give that address to the server. The CDN must accept the server's self-signed certificate (Cloudflare's "Full (strict)" does not).

```sh
retail server start --front https://vpn.example.com     # repeat for several; --front off clears them
```

Devices use a tunnel through the CDN when nothing else works. Inside it they check the server certificate again, so the CDN cannot read the traffic either.

## Networks that go through a proxy (companies, schools)

Devices follow the system proxy settings on their own (on Windows the tray app passes the signed-in user's settings and PAC file to the daemon). When a proxy on Windows asks for a domain sign-in, the signed-in account authenticates automatically (Negotiate, NTLM). To set one yourself:

```sh
retail set --proxy http://user:password@proxy.corp:3128   # or socks5://…
retail set --proxy off                                     # use no proxy
retail set --proxy auto                                    # follow the system settings (default)
```

Proxies that open up TLS are no obstacle either. Such proxies usually refuse self-signed servers, so devices go in through a tunnel over plain HTTP and check the server certificate inside it. This can be slower.

## Backups

The server's data is one folder, `server` in the state directory (`retail.json`: devices and invites, `tls/`: the server certificate and key, `host.json`: settings). Copy that folder. If the certificate key is lost, devices no longer trust the server and need new invites.

## Tips

- Logs: `RUST_LOG=retaild=debug,retail_control=debug`
- Turn off automatic router port opening: `RETAIL_NO_PORTMAP=1` (for a VPS with a public IP, say)
