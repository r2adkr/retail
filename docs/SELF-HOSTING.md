# Running your own network

retail has no separate server program. One device acts as the network's server, and other devices join with an invite code. The server registers devices, hands out addresses and passes connection details around; the traffic itself goes straight between devices. Only pairs of devices that cannot reach each other directly relay through the server's port 443.

## On a home PC (one button)

1. Open the server window: the gear at the bottom right of the tray popup → **Manage server**.
2. Click **Open server**. This device becomes the server and the first device of the new network.
   - If this device was in another network, it moves to the new one. The window says so beforehand.
3. **Create invite** makes a **Multi-device** invite (named, reusable) or a **One-time** one, and shows its code and QR code. Paste the code into the other device's Settings (**Change server** → **+ Add server**), or send an installer: the ⋯ menu of a multi-device invite saves one for Windows, Linux or macOS to your Downloads folder.
   - A one-time invite works once and expires after 24 hours. The code carries the server address, the fingerprint of the server certificate's key and an auth key, so there is no domain or certificate to set up.

The CLI does the same:

```sh
retail server start            # start the server (this device joins too)
retail server invite           # print an invite code (--reusable: many uses, --name: a named invite)
retail server web              # open the web admin page
retail server status           # addresses, router state, devices, invites
retail server remove <device>  # remove a device (--revoke-invite: and the invite it joined with)
retail server backup <file>    # save the server's data, encrypted with a passphrase
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
  - For the server's own system it uses the programs installed on the server (on Windows `wintun.dll` must sit in the same folder). For other systems the server downloads that system's official installer of its own version from [GitHub Releases](https://github.com/r2adkr/retail/releases) the first time, checks it against `SHA256SUMS` and keeps the programs from it (`RETAIL_RELEASES` changes the address; an empty value turns this off). A server that cannot reach GitHub can take the files through **upload files…** in the download menu: `retail-tray`, `retaild` and `retail` for that system (on Windows the `.exe` files and `wintun.dll`). The server checks that each is an executable for that system (PE, ELF, Mach-O). To place them by hand, put the same files in `clients/<os>-<arch>/` under retaild's state folder (`/var/lib/retail/clients/windows-x86_64/` on Linux, `C:\ProgramData\retail\clients\linux-x86_64\` on Windows, and so on).
  - An installer carries a reusable invite, so do not pass it around freely. If one leaks, use ⋯ → **New code** on that invite.
  - retail is not code-signed yet, so Windows SmartScreen or macOS Gatekeeper may warn.
  - On a device that already belongs to another network, the installer asks whether to switch. On yes the device leaves its current network cleanly, keeps it in its server list (Settings → **Change server** switches back) and joins this one. To remove retail: run the installed `retail-tray --uninstall` (as administrator).

### Reaching the server from outside

When the server starts, retail **opens ports on the router automatically with PCP or NAT-PMP, falling back to UPnP** (TCP 443 and 80, UDP 3478, UDP 41641), and a second TCP port picked at random once per server (20000–31999), for providers that block 80 and 443 coming in and routers that keep 443 for themselves. Invites name the public address on both TCP ports and devices try them at once. The router ports row of the server window shows the result. A router that opens nothing still tells its public address, which invites then name too: forward the same port numbers by hand and devices on other networks can join. On Windows it also adds firewall rules that apply only to retaild, and removes them when the server stops.

- If the router does not support automatic port opening, the server window explains how to forward the ports by hand.
- If the router's external address is private (carrier-grade NAT, or two routers in a row), the window warns that the server cannot be reached from outside. Devices on the same network can still join, and devices outside can join through the **internet tunnel** or a **helper node** (below).
- If your public IP changes, give a dynamic DNS name with `retail server start --domain myhome.example.net`. Invite codes then carry that name instead of the IP.

## On a VPS or in Docker

On a server without a screen, everything works from the command line. One command installs retail from the newest release (checked against its `SHA256SUMS`), starts it at boot, starts a server that does not join its own network and prints the first invite:

```sh
curl -fsSL https://raw.githubusercontent.com/r2adkr/retail/main/scripts/install.sh | sh -s -- --server
retail server invite --name family          # more invites; retail server status, acl, tag, helper-device …
retail tui                                  # the same in a full-screen terminal view
sudo retaild uninstall                      # removes the service and programs (the server data stays)
```

On Debian and Ubuntu the script installs the release's `.deb` with apt (`sudo apt install ./retail-linux-x86_64.deb` does the same by hand, and `sudo apt remove retail` removes it); elsewhere it takes the installer out of the package and runs it. Either way the programs go to `/usr/local/bin` and the daemon is registered with systemd (launchd on macOS). `retaild install --server` starts the server on an installed device; `--port` and `--domain` set the server's port and a name for invites.

On a machine with less than 1 GB of memory the daemon picks its smallest buffers by itself (about 9 MB); `retail set --memory-limit` overrides it. The web admin page is on the server's loopback: `ssh -L 41180:127.0.0.1:41180 server`, then open the link `retail server web --print` prints there.

Docker: every release publishes a server image for 64-bit Intel and ARM, `ghcr.io/r2adkr/retail` (tags `latest` and the version, such as `1.0.0`).

```sh
docker run -d --name retail-server --restart unless-stopped   -p 443:443/tcp -p 80:80/tcp -p 3478:3478/udp   -v retail-data:/data --cap-drop ALL --cap-add NET_BIND_SERVICE   ghcr.io/r2adkr/retail
docker exec retail-server retail server invite
```

Or with Compose, which also takes settings from an `.env` file (domain, CDN, helper):

```sh
cp packaging/docker/example.env packaging/docker/.env
docker compose -f packaging/docker/compose.yml up -d
docker compose -f packaging/docker/compose.yml exec retail-server retail server invite
```

Ports to open: TCP 443 (registration, control, relay), TCP 80 (tunnels from networks that allow only web traffic), UDP 3478 (STUN). `packaging/docker/Dockerfile` builds the same image from source.

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

## A server nobody outside can reach: internet tunnel

Behind carrier-grade NAT, or behind a router that says it opened the ports but lets nothing in, turn on the **internet tunnel**: the **Turn on** switch on the *Internet tunnel* row of the server window, the web admin page, or

```sh
retail server tunnel on              # off turns it off; retail server start --tunnel does it at start
```

retail then runs Cloudflare's `cloudflared` beside the server, which opens a free *quick tunnel* (an `https://….trycloudflare.com` address) from the inside out, so no router port is needed. Invite codes carry that address, and devices use it like a CDN address (below) when nothing else works: inside it they check the server's certificate again, so Cloudflare passes the traffic through without being able to read it. Device-to-device traffic still goes directly between the devices whenever their networks allow it; while the tunnel is up, devices learn their public addresses from Cloudflare's STUN server for that.

- **The first time** it downloads cloudflared (about 20 to 55 MB, by system) from Cloudflare's GitHub releases, checks it against the checksum built into retail, and keeps it in the state folder (`tunnel/`). It takes some tens of MB of memory while it runs.
- **The address changes** when the server's computer restarts or the tunnel is lost and started again. Devices that also reach the server another way (the same network, IPv6, a helper node) learn the new address by themselves. So do devices with a direct connection to the server's computer (shown as *direct* in the tray): they find the server through it, at that computer's retail address. Others lose it: make a new invite code and paste it on them (Settings, or `retail up --invite`). They stay the same devices, with their addresses and names. Invite codes made before carry the old address.
- **Updates** of retail usually keep the address: cloudflared keeps running and the next retaild takes it over. On Linux this needs the service settings of 1.0.1 or later, which installing the 1.0.1 package (or a later one) once puts in place; an installation updated only automatically from 1.0.0 gets a new address at each update.
- **Limits**: quick tunnels are Cloudflare's free service for testing, with no uptime promise and at most 200 requests in flight at once; this is plenty for the control connection of a household's devices, and relayed data (when two devices cannot connect directly) goes through it more slowly than over a direct connection. For a network you depend on, prefer a helper node, a VPS, or a CDN address on your own domain.
- It needs outgoing connections to Cloudflare (port 7844, UDP or TCP). Networks that block those show the error on the tunnel row.

## A server behind CGNAT: helper node

At a home behind carrier-grade NAT (the provider shares one public address among customers), opening router ports does not let anyone in from outside; the server window and web admin page say so. A **helper node** that other networks can reach solves this. It only passes connections through to the server: it cannot read them and stores no network data.

- **A member device**: if a device already in the network can be reached from the internet (one with a public address, or behind a router that opens ports automatically), open the web admin page, then that device's ⋯ menu → **Use as helper node** (or `retail server helper-device <device>`). The server asks the device over its control connection; the device listens, opens its router's ports, and sends back its helper code. Invite codes made afterwards lead with its address. It stops when you turn it off or the device goes offline.
- **A VPS** (below), when no member can be reached.
- **IPv6**: if the server has a global IPv6 address, invites carry it ahead of the local addresses, so devices with IPv6 often connect directly. The router must let inbound IPv6 through to the server.

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

## Names and access control

Every device gets a name, `<device name>.retail.internal`, answered by every device's own daemon at 100.100.100.100. The system sends only that domain there (Windows: a name resolution policy rule, macOS: `/etc/resolver/retail.internal`, Linux: systemd-resolved), so other lookups are untouched. Two devices with the same name get `-2`, `-3`, and so on.

Without rules, every device reaches every other. To limit that, tag devices (web admin page, ⋯ → **Edit tags…**, or `retail server tag <device> <tags>`) and add rules in the **Access** card (or `retail server acl allow --from … --to … [--ports …]`). A rule lets its sources start traffic to its destinations, optionally only to some ports (`tcp:443`, `udp:5000-5100`, `icmp`). Replies always return. Devices with no rule between them in either direction are hidden from each other. **Limit access** starts with one rule that allows everything, so nothing breaks until you change it.

```sh
retail server tag nas server
retail server acl allow --from '*' --to tag:server --ports tcp:443 icmp
retail server acl                    # show the rules
retail server acl remove 1
retail server acl off                # everyone reaches everyone again
```

Rules are enforced by each receiving device; the server only tells each device what to accept from whom.

## Reaching a whole LAN: subnet routes

A device can route its LAN for the others, so printers, NAS boxes and other things that cannot run retail are reachable from anywhere. On a device in that LAN (Linux, Windows or macOS):

```sh
retail set --advertise-routes 192.168.1.0/24      # several: 192.168.1.0/24,10.0.0.0/24; none stops
```

Nothing changes until the server's administrator approves it, since a route sends other devices' traffic through that device: in the web admin page the device shows the networks it offers, and ⋯ → **Approve routes** turns them on (or `retail server routes <device>`; `--off` stops them). Then every device sends traffic for those networks through it. The router masquerades it, so hosts on the LAN need no route back.

- A device on the routed LAN itself keeps using its own LAN directly.
- Access rules: a device reaches routed networks only if it has full access (all ports) to the router device.
- `0.0.0.0/0` is what an exit node is for.
- The router device turns on IP forwarding and NAT for the approved networks: iptables on Linux, `New-NetNat` on Windows, pf (anchor `com.apple/retail`) on macOS.

## Lost devices and old devices

- **Remove a device** (⋯ → **Remove device**, or `retail server remove <device>`) cuts it off at once: every other device drops it and it cannot reconnect. If it joined with a multi-device invite that still works, the page offers to expire that invite too (`--revoke-invite`), so whoever has the device cannot join again with it.
- **Key expiry** (the **Device keys** card, or `retail server expiry --keys 180`): device keys then last that many days from joining. When one expires, the device is cut off from the others until it is renewed (⋯ → **Renew key**, `retail server renew <device>`) or joins again with an invite; its tray says so. Turning expiry on, or changing it, starts the clock for every device on that day; devices whose key already expired stay cut off until renewed. The server's own device and the helper node never expire, and ⋯ → **Key never expires** (`--never`) exempts others, such as a router at home.
- **Removing inactive devices** (`retail server expiry --inactive 90`): devices not seen for that many days of the server running are removed. Devices that are online, or exempt from expiry, stay.

## Backups and moving the server

A backup holds everything the server has: devices, invites, access rules, settings, and the certificate and REALITY keys that devices trust. Make one in the web admin page (the **Backup** card, on the server's own device only) or with:

```sh
retail server backup retail-server.retail-backup
```

It asks for a passphrase (or reads `RETAIL_BACKUP_PASSPHRASE`) and encrypts the backup with it. Keep the file and the passphrase safe: together they let anyone pose as your server.

To restore it, on the same or another device, with its server stopped:

```sh
retail server restore retail-server.retail-backup
retail server start
```

In the web admin page: **Restore from a backup…** while the server is off (the tray's server window opens it). The data the device had is kept in `server.bak` next to it.

- Devices keep their addresses, names and rules. If the server's address stayed the same (same router, or a domain name pointed at the new machine), they reconnect on their own.
- If the address changed, give each device a new invite from the restored server. Since it has the same key, the device recognises it as the same network: it keeps its address and name instead of joining as a new device.
- Devices also learn the server's current addresses while connected, so a change of the server's public address alone does not strand them.
- Do not run the old server again after moving: two servers with the same key confuse the devices.

## Updates

The daemon looks for a new official release every 6 hours (`retail update --check` or **Check now** in Settings asks at once). The tray tells you once per release, and **Update now** (or `retail update`) installs it: this system's installer is downloaded and checked against the release's `SHA256SUMS`, and the programs from it are put in place of the running ones, and the daemon restarts through its service manager; the tray app restarts itself. With **Install updates automatically** (`retail set --auto-update`) this happens on its own.

- Settings shows how far the update is (downloading, checking, putting the programs in place) and then how long the restart is taking.
- If retaild does not come back within a minute or so, the tray shows **Start retaild**, which starts it with administrator rights (and repairs its boot registration). On Windows, devices updated from 1.0.0 or 1.0.1 can stay off after the update; press that button, run the installer once more, or restart the computer.
- On Linux the systemd unit lets the daemon write only its own program folder (`ReadWritePaths=`), to replace the programs.
- `RETAIL_RELEASES` points at another release mirror (an empty value turns checks off); `RETAIL_CA_FILE` adds the mirror's certificate authority (PEM).

## Tips

- Logs: `RUST_LOG=retaild=debug,retail_control=debug`. The service writes them to `C:\ProgramData\retail\retaild.log` on Windows, `/Library/Application Support/retail/retaild.log` on macOS, and the journal on Linux (`journalctl -u retaild`)
- Turn off automatic router port opening: `RETAIL_NO_PORTMAP=1` (for a VPS with a public IP, say)
