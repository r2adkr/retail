# retail design

retail is a **self-hosted mesh VPN**.
It reuses WireGuard (boringtun) as the data tunnel and implements the control and NAT traversal layers above it.

## 1. Components

| Crate | Binary | Role |
|---|---|---|
| `retail-proto` | (library) | Wire types (JSON), key encoding, STUN and relay frames, invite codes, local API token |
| `retail-control` | (library) | Coordination server: node registration, IP allocation, NetMap push, relay, STUN, REALITY, HTTP tunnels, helper nodes. Runs inside retaild when it hosts a network |
| `retail-daemon` | `retaild` | Node daemon: TUN, WireGuard data plane, endpoint discovery, the transport race to the server (proxies, tunnels, NAT64), exit node, hosting (server, router ports, helper node), local API |
| `retail-cli` | `retail` | `up`/`down`/`logout`/`status`/`set`/`server …`/`helper …` (calls the local API), and `retail tui` (ratatui): devices, server and saved servers in a terminal, redrawn on a key or every 2 s |
| `retail-web` | (library) | Web admin page and installer packages |
| `retail-tray` | `retail-tray` | Tray / menu bar app: status popup (⋯ menu per device), settings window, server window |

```
retail (CLI, tray) ──HTTP 127.0.0.1:41112──► retaild ──HTTPS/WSS (REALITY, proxies, tunnels, CDN, helper)──► retaild (hosting device, with the server)
                                                 │                                  │ (UDP 3478 STUN)
                                                 │ WireGuard UDP 41641              │
                                                 ▼                                  │
                                              retaild (other node) ◄────────────────┘
```

## 2. Identity and authentication

- A node generates one WireGuard key pair (Curve25519) and keeps it in its state file.
- The first registration uses an **invite code** (`retail1.` + base64url JSON). It carries the server addresses (public address, helper address, LAN addresses, in that order), the SHA-256 of the server certificate's public key (the pin), a one-time auth key, the public REALITY settings and CDN addresses.
- Invites are one-time (the default, 24 hours) or named and reusable. One-time invites are stored as hashes only; named invites also keep the code itself in the server's data folder (readable by administrators only) so that installers can be made again. Each name has one live code, and a new code removes the old one in the same write.
- The server issues each node a **node token** (256 random bits) and stores only its SHA-256. Later control connections authenticate with `Authorization: Bearer <token>`.
- The server certificate is self-signed (P-256), made the first time the server runs. Instead of a certificate authority the daemon compares against the **public key pin**, and verifies TLS signatures with that very key. A wrong pin fails; it never falls back to another check. When joining by URL without an invite, the webpki roots (and `RETAIL_CA_FILE`) verify the server.

## 3. Control protocol

| Endpoint | Direction | Content |
|---|---|---|
| `POST /api/v1/register` | C→S | `RegisterRequest { auth_key, node_key, hostname, os }` → `RegisterResponse { node_id, ip, prefix_len, token }` |
| `GET /api/v1/poll` (WebSocket) | both | server → `ServerMessage::NetMap`, client → `ClientMessage::Endpoints` |
| `GET /api/v1/tunnel` (WebSocket) | C→S | Tunnel. Binary messages carry a byte stream, inside which pinned TLS talks to the API above |
| `POST /api/v1/tunnel/poll`, `GET`/`POST /api/v1/tunnel/poll/{id}` | C→S | The same tunnel where WebSocket is blocked. `GET` waits until there is data or 15 seconds pass |
| `GET /health` | - | Health check |

- The server port tells TLS from plain HTTP by the first byte. Plain HTTP reaches only the tunnel endpoints; everything else gets 403.
- Registering again with the same `node_key` keeps the node, its IP and its name, and replaces the token. It needs the node's current token as well as an invite: every member sees every key in its netmap, so a key alone never takes a node over. A new hostname gets a free name; it never takes one in use.
- On every change (registration, endpoint update, connect/disconnect, admin command) the server recomputes each connection's NetMap and sends it unless it is unchanged.
- Admin commands come in through the hosting device's local API, so they take effect in the same process at once. Connections of deleted nodes are closed.
- On each connect a node announces whether it offers an exit node with `ClientMessage::Hostinfo { exit_node }`. The server keeps this in memory only and forgets it when the node disconnects.
- Registration is limited to 10 requests per minute per client address.
- Handshake initiations must carry a valid mac1 (which needs the device's public key) before the daemon spends a Diffie-Hellman on them; HTTP long-poll tunnels are capped at 256, 16 per client address; a helper node's link lines are bounded and so are the connections picked up at once.

## 4. Addresses

- Virtual IPs come from `100.64.0.0/10` (the CGNAT range) in order and stay until the node is deleted.
- The TUN interface gets its address with a `/10` prefix, so the OS routes the mesh range by itself (on macOS tun-rs adds the route).
- The MTU is fixed at 1280 (avoids path MTU problems; the IPv6 minimum MTU).

## 5. Data plane

- One UDP socket (41641 by default) carries all peer traffic and STUN.
- **Batched I/O** cuts system calls per packet.
  - TUN reads: on Linux the `IFF_VNET_HDR` offload reads TSO superpackets (up to 64 KB) at once and splits them at the MTU. If the next superpacket is already waiting, it goes into the same job without waiting (up to 128 packets per job). Every hand-off between stages wakes a thread, so bigger jobs mean less CPU per GB.
  - UDP sends: encrypted packets of the same size to the same peer go out in one GSO send (quinn-udp: Linux UDP_SEGMENT, Windows USO, macOS sendmsg_x).
  - UDP receives: `recvmmsg` and UDP GRO take many datagrams at once. The GRO batches of one receive go to a single decryption job, up to 128 datagrams (−20% context switches, −11% CPU per GB).
  - TUN writes: decrypted TCP segments are merged again with GRO before writing (Linux).
- When the send buffer is full, packets wait instead of being dropped (backpressure). The TUN queue paces TCP, and retransmits disappear.
- Socket buffers are raised to 8 MB (as root on Linux, `SO_RCVBUFFORCE` goes past the `rmem_max` limit).
  - STUN and WireGuard packets differ in their second byte (STUN message type high byte `0x01`, WireGuard reserved byte `0x00`).
- Finding the peer of a received packet
  - Handshake initiation: `parse_handshake_anon` recovers the sender's static public key.
  - Anything else: `receiver_idx >> 8` is the local peer index.
- A decrypted packet whose source IP is not that peer's virtual IP is dropped (the allowed-IPs check).
- `update_timers` runs for every peer each 250 ms; the persistent keepalive is 25 seconds.

## 6. NAT traversal

1. The daemon sends Binding requests to the STUN servers (`stun_servers` in the NetMap, or port 3478 on the control server's host) to learn its public address: every 3 seconds until an answer comes, then every 20 seconds. It uses the data plane socket, so the NAT mapping is the same.
   - The UDP socket is a single IPv6 socket with IPv4-mapped addresses (dual stack), so IPv4 and IPv6 candidates are used together, and the public address is learned per address family. Systems without IPv6 use an IPv4 socket.
2. Local interface addresses (LAN, global IPv6) and the STUN results are reported to the server as endpoint candidates.
3. The server passes the candidates to the peers, and both sides at once send handshakes to all of each other's candidates. Since both send at the same time, hole punching works through most cone NATs.
   - Until a session exists, the last handshake initiation is **resent every 250 ms** (WireGuard's own retry is 5 seconds). Duplicate initiations are safe: the receiver ignores them by their timestamp.
4. The source address of the first authenticated packet becomes the confirmed endpoint, and from then on packets go only there. After 20 seconds without anything received, packets go to all candidates again (roaming).
5. Connections to the control server (registration, control connection) use Happy Eyeballs (RFC 8305): the IPv6 and IPv4 addresses of the server name are tried alternately 250 ms apart, and the first to connect wins.

### 6.1 Path choice and fallback

The aim is to **connect on any network, and use a direct path whenever one exists**. Each peer's path is one of three.

| Path | When | Sending |
|---|---|---|
| Direct | an authenticated packet came over UDP in the last 20 seconds, and both directions can be taken to work (below) | GSO batches to that endpoint |
| Relay | an authenticated packet came through the relay in the last 60 seconds | through the control server |
| Probing | neither | to every UDP candidate, and after 1 second through the relay too |

- The **relay** runs over the control server's TCP 443 (HTTPS WebSocket). It rides the already open control connection as binary messages, so it needs no extra connection, and it works on networks that block UDP and between two symmetric NATs. A frame is `node key (32 B) | (length u16, WireGuard datagram)*` (`retail_proto::relay`). The server only swaps the key for the sender's and forwards; the content is WireGuard ciphertext, which it can neither read nor forge.
- **Race**: for 1 second after probing starts (`RELAY_DELAY`) only UDP is used. Where a direct path works it usually succeeds within that time, so the connection starts out direct. After that, handshakes also go through the relay, and the first path to succeed is used. Answers go back the way the request came. A peer that has used the relay uses it from the start of probing for 5 minutes.
- **Upgrade**: while on the relay, keepalives go to the direct candidates every 3 seconds. When one arrives and authenticates, the receiver switches to direct and answers with a keepalive at once, so the sender switches too. When a UDP block is lifted, the path is direct again within about 1–3 seconds.
- **Failover**: if data is being sent and nothing comes back on the direct path for 3 seconds, the path is taken as lost and traffic goes to the relay at once. To avoid false alarms, a side that only receives data sends a keepalive every second (WireGuard's default is 10 seconds). The measured outage is about 3 seconds, for blocks in both directions and in one.
- **One direction cut**: receiving over UDP only proves that the peer reaches me. Hence two rules:
  - The side that lost the path does not go back to direct on anything it receives over UDP. It sends handshakes **over UDP only** every 3 seconds, and goes back to direct only when the answer arrives over UDP (answers go back the way the request came, so this proves both directions).
  - If, 2 seconds after the direct path is up, the peer's **data** arrives through the relay more recently than over UDP, the peer does not get my direct packets, so I send through the relay too. When its data comes over UDP again, I go back to direct. Keepalives and handshakes do not count (the same packet can take both paths, and the later copy is dropped by the replay check).
- **Relay send pacing**: the relay queue holds 16 frames of 60 KB. When it is full the `udp-send` stage waits at most 2 ms **per job** and then drops. The short wait lets the inner TCP match the rate without loss. Since the cap applies per job, a long bulk transfer over a slow relay can slow direct traffic from the same device to other peers. That effect has not been measured yet.
- **Relay efficiency**: the control connection and the server gather queued frames and send them in one go (one flush, up to 128 KB). The receiver decrypts a frame's datagrams in one batch as on the UDP path and merges TCP segments with GRO before writing to TUN. The server's per-node queue is 48 frames (longer only added delay).
- **Control connection liveness**: the daemon pings every 10 seconds and reconnects after 30 seconds without receiving anything, so the relay does not stay down for minutes when a NAT silently forgets the connection. Sends have a 10-second limit too.

- **Round trips** (`ping.rs`): while traffic flows with a peer (more than 400 bytes between two timer ticks, for 10 seconds after), the daemon sends it a 40-byte UDP packet inside the tunnel every 2 seconds (port 41617 both ways, `rtlP`, a nonce). The peer's daemon answers it before its access rules and the system see it, so no firewall or ICMP setting is involved, and a reply must come from the peer's own address like any packet. `PeerStatus.rtt_ms` and `rtt_history` (5 minutes, `u16::MAX` for no answer) feed the tray's graph. Idle peers get no pings, and older peers ignore them.
- **Wake-on-LAN** (`lan.rs`): `Hostinfo.lan` carries the device's network cards on private networks (MAC, address, prefix; at most 8). The server stores the last non-empty report with the node, so peers see it in `Node.lan` while the device is off. `retail wake NAME` (tray: a device's ⋯ menu while it is off) sends the magic packet to that network's broadcast address, port 9: from this device if it is on the same network (same prefix and broadcast address), and through every online peer that is, with a `ping.rs` message inside the tunnel. A peer acts on it only from devices that may reach it in full (no access rule), only for one of its own networks, at most every 200 ms. Two homes on the same private network both send it; a packet for a card that is not there does nothing.

`scripts/netns-test.sh` checks each of these cases end to end (its header lists the scenarios). Relay throughput there is high because the server runs on the same machine; in practice the server's line and CPU are the limit.

**Why not MASQUE**: it pays off where compatibility with standard proxies matters, and retail speaks its own protocol. A QUIC/HTTP/3 stack is larger than the memory budget allows. Networks that open only UDP 443 still connect through the TCP 443 relay. If TCP-over-TCP turns out to hurt on lossy lines, the next step is a UDP datagram relay in the server, with no new dependency.

### 6.2 REALITY

The last resort for networks where HTTPS to the server is itself blocked (firewalls that block by server name or TLS fingerprint, active probing). It follows Xray's REALITY.

- Before handing TLS to rustls, the server (the hosting device) reads the ClientHello on port 443 and sorts it three ways.
  - No SNI, or not the camouflage site's name: plain HTTPS.
  - The camouflage site's name with valid authentication: REALITY. TLS 1.3 with a one-time Ed25519 certificate, then the same HTTP service (registration, control, relay).
  - The camouflage site's name with wrong authentication: the connection is passed straight through to the real site, so a prober sees that site's handshake and content.
- Authentication: the client derives an auth key with HKDF from X25519 (its key share's private key, the server's static public key) and seals version, time and short ID with AES-256-GCM into the session ID (the AAD is the ClientHello with the session ID zeroed). The server checks the time (±120 s), the short ID and replays.
- Server verification: the one-time certificate's signature field holds HMAC-SHA512(auth key, certificate public key), and the client checks it along with the CertificateVerify signature.
- The client must choose the session ID and the key share itself, so instead of rustls it uses a small TLS 1.3 client of its own (`retail-daemon/src/reality.rs`). It uses only TLS_AES_128_GCM_SHA256 and X25519, and its ClientHello mimics Chrome's order and GREASE. Unit tests cover interoperation with a rustls server, wrong keys and probes.
- Switching: in the race of 6.6 it starts 1.5 seconds after plain HTTPS (at once if plain HTTPS fails sooner).
- Limits: it does not help against a block of the server's IP. The ServerHello comes from rustls, so it is not identical to the camouflage site's. Authentication fails if clocks are more than 2 minutes apart.

### 6.3 Names and access control

- **MagicDNS**: the server gives every node a unique `dns_name` (`<hostname>.retail.internal`, later duplicates `-2`, `-3`). Packets to 100.100.100.100 (inside the mesh range, never assigned) reach no peer, so the engine hands UDP queries to port 53 to `magicdns.rs`, which answers A and reverse (PTR) lookups from the netmap and writes the reply to TUN. NXDOMAIN for unknown names in the domain, REFUSED outside it. The system is told to send only `retail.internal` there: an NRPT rule on Windows, `/etc/resolver/retail.internal` on macOS, `resolvectl dns/domain` on Linux; undone when the session ends.
- **Access control** (`retail_proto::acl`, `retail-control/src/acl.rs`, `retail-daemon/src/filter.rs`): the policy is stored with the server data; `None` means everyone reaches everyone. Rules name sources and destinations by `*`, `tag:NAME` or `id:N`, with optional ports. For each pair the server computes what the receiver accepts from the sender (`Accept::All`, or `Ports`), sent with that peer in the receiver's netmap. A pair with no rule either way is left out of both netmaps, so the devices cannot even handshake. When only one side may start traffic, the other gets `Ports { [] }`: replies only. The receiver enforces it after decryption: new traffic must match an allowed port; otherwise it must answer a flow this device started (tracked per peer by protocol, peer address and ports, 10 minutes idle, at most 16k flows). ICMP echo replies match our echo ids; ICMP errors are allowed from peers we have flows with; later fragments of restricted peers are dropped. Internet traffic through an exit node is not filtered by the rules, and routed networks (6.7) take traffic only from peers the router accepts fully.
- **Destination check** (`filter.rs`, for every peer, rules or not): a device takes packets for itself (its mesh, LAN and public addresses, broadcast and multicast), for the networks the server approved it to route, and, while it offers an exit node, for public internet addresses. Anything else is dropped, so a peer cannot use a device to reach other networks it happens to be on.

### 6.4 Exit node

Using the internet through another device.

- Offering side (Linux, Windows): turns on IP forwarding and puts forwarding, `100.64.0.0/10` MASQUERADE and MSS clamping rules into dedicated chains (`RETAIL-FWD`, `RETAIL-NAT`, `RETAIL-MSS`). Traffic is never sent into the exit node's private networks (10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10) other than those it routes (6.7). One `Gateway` (`exit.rs`) owns these chains for both, so neither undoes the other. Leftover chains are removed at start and cleaned up at the end. Windows uses `New-NetNat` and has not been checked on real hardware yet. Tool errors are read in the console's code page and cut to their first line. macOS cannot offer an exit node.
- Without a system NAT (Windows Home has no WinNAT; it comes with Hyper-V) the daemon forwards through the device's own network stack instead (`forward.rs`, the "system stack" of sing-box and clash). A peer's TCP SYN is held while the daemon dials the destination; on success the SYN is readdressed to a listener on the mesh address and written back into the TUN, where the kernel accepts it and the daemon splices the two sockets (a 16 KiB buffer per direction only while data moves, so idle connections hold none), and on failure the peer gets a RST. Replies are readdressed back before encryption. UDP gets one socket per peer port (120 s idle), ICMP echo goes through `IcmpSendEcho`. IP forwarding stays off, and a program-scoped Windows Firewall rule lets the readdressed connections in while it runs. Caps: 4096 TCP connections (1024 per peer), 1024 UDP flows, 32 pings in flight. Routed networks (6.7) use the same path. `RETAIL_USERSPACE_NAT=1` forces it on Linux for tests.
- Using side: packets to destinations outside the mesh go to the chosen exit peer, and source addresses outside the mesh are accepted only from that peer (spoofing other mesh addresses stays blocked).
- No routing loops: the daemon's own sockets (WireGuard and STUN UDP, the control connection) bypass the tunnel: fwmark and policy routing on Linux (as wg-quick does, with connmark restore for strict rp_filter), `IP_UNICAST_IF` on Windows, `IP_BOUND_IF` on macOS. The Windows and macOS paths have not been checked on real hardware yet.
- The tunnel carries IPv4 only, so the IPv6 internet is blocked while an exit node is in use (no leaks).
- If the chosen exit node goes offline, the internet is blocked (fail closed). The tray and `retail status` say so, and clearing the choice restores it. The control connection stays up.
- While an exit node is in use, DNS to a public resolver goes through the tunnel; a resolver on the local network (a private address) is still asked directly, so that network sees the names looked up. If resolving the server name fails, the last address that worked is used.
- **Upload limit** (`shaper.rs`, `Prefs.upload_limit_mbit`, off by default): a download through an exit node fills the exit's upload, and the router's queue then delays everything else (bufferbloat). With a limit set a little under the line's upload speed, one token bucket (burst about 30 ms, at least four 64 KiB bursts) meters what the device sends: the tunnel's datagrams, policed per packet at tun-read before counters are reserved, and, while it offers an exit node, what it forwards on to the internet, at tun-write. Over the limit, packets above 300 bytes are dropped, so their TCP senders slow down; smaller ones (games, calls, ACKs, DNS) still go, down to half a burst of debt. Off, it costs one atomic load per batch. The limit applies to every peer, LAN ones included.

### 6.5 Memory limit

Set with `retail set --memory-limit <MiB|auto>`, `retaild --memory-limit` or `RETAIL_MEMORY_LIMIT` (not in the app). The default is automatic.

- The data plane buffers (number of crypto workers, pipeline depth, receive slots) are the fastest combination that fits the limit. Changing it restarts the tunnel.
- Every 10 seconds the daemon checks the limit and, when over it, returns freed heap to the OS (Linux glibc).

The daemon idles at about 12 MiB and peaks around 15 MiB under load, within the 10–20 MB budget. A limit of 9 MB or less drops to one crypto worker and smaller buffers, at roughly half the throughput.

### 6.6 The way to the server (transport race)

So that the server is reachable from any network with internet access, the control connection and registration race every available way (`retail-daemon/src/transport.rs`). Each way starts when its delay has passed, or at once when all earlier ways have failed, and the first to succeed wins. On an ordinary network it connects at plain HTTPS speed; on a blocking one it tries the rest within seconds. The last way that worked is tried first next time.

| Delay | Way |
|---|---|
| 0 s | pinned HTTPS |
| 1.5 s | REALITY (if the server has it on) |
| 3 s | WebSocket tunnel: the server's plain HTTP (same port and 80), the server's HTTPS, CDN addresses |
| 6 s | HTTP long-polling tunnel to the same places |

- The table runs once directly and once **for each known proxy**.
- A **tunnel**'s outer TLS accepts any certificate (a CDN's, or a TLS-inspecting proxy's). Pinned TLS runs again inside, so whoever opens the outer layer can neither read nor change the content. The server feeds the stream a tunnel carries into its own listener as a new connection.
- **Proxies**: HTTP proxies use `CONNECT` (absolute-form requests for the plain HTTP tunnel), SOCKS5 its own handshake. Authentication: Basic or SOCKS5 user/password from the proxy URL, and on Windows the signed-in user's Negotiate (Kerberos) or NTLM. The daemon runs as a service, so it borrows the console user's token to call SSPI, and with nobody signed in it tries the computer account. No password is stored.
- **Which proxies**: `retail set --proxy` (when set, only that; `off` for none), otherwise the system settings: the signed-in user's Windows proxy as reported by the tray app (including PAC and WPAD results), `HTTPS_PROXY` / `ALL_PROXY`, the WinHTTP settings on Windows, the network settings on macOS. A direct connection is always tried as well.
- **NAT64**: a device without an IPv4 address looks up `ipv4only.arpa` to find the NAT64 prefix (RFC 7050) and adds the server's, STUN's and peers' IPv4 addresses translated into that prefix as candidates. Devices with IPv4 do not look it up (the system resolver module costs memory).
- `retail status` and the status API's `control_via` show the way in use.
- Limits: captive portals before sign-in, allow-list networks (where even the CDN address is not allowed) and DNS-only networks are out of reach. The relay inside a tunnel is slower than over direct TCP, and long polling especially so.

### 6.7 Subnet routes

A device can route networks it is on (its LAN) for the others.

- Offering: `Prefs.advertise_routes` goes to the server in `ClientMessage::Hostinfo { routes }`. The server keeps offers in memory per connection and the administrator's approval per node (`NodeRec.routes`). A netmap lists, for each peer, the networks it both offers and has approved, while it is connected and its key is valid; when several devices route the same network, the oldest wins so the choice does not flap. Networks overlapping `100.64.0.0/10`, loopback, link-local, multicast or `0.0.0.0/0` are refused (`Ipv4Net::check_route`), and a device offers at most 16.
- Router side: IP forwarding and NAT towards the approved networks, so hosts there need no route back. Linux: forwarding and MASQUERADE rules in the `Gateway` chains of 6.4. Windows: the same `New-NetNat` for `100.64.0.0/10` as an exit node. macOS: `net.inet.ip.forwarding` and a pf `nat on <interface>` rule per network in the anchor `com.apple/retail`, which the system's pf.conf loads; pf is enabled with a reference (`pfctl -E`/`-X`) so its state is restored afterwards. On every system the engine's destination check decides what reaches the system at all: only approved networks (and the internet while it is an exit node). The Windows and macOS paths have not been checked on real machines yet.
- Using side: the engine looks up a destination's peer by mesh address, then by the longest matching route, then the exit node. A peer may send from addresses inside its routes (WireGuard's allowed-IPs rule). The system gets a route for each network into the TUN device (`SubnetRoutes`: `ip route` / `netsh` / `route`), except networks overlapping one the device is on itself, and WireGuard endpoints or server addresses inside a routed network are not used (the tunnel would carry itself).
- Access rules: a peer reaches routed networks only with full access (`Accept::All`) to the router, since rules name devices, not hosts behind them.

## 7. Local API (daemon)

Listens on `127.0.0.1:41112`.

- Against browser attacks: every request needs the `X-Retail-Local` header (forcing a CORS preflight), and `Host` must be a loopback name (against DNS rebinding).
- Changes (POST) need `X-Retail-Token`. The daemon writes a new token to a file each time it starts; whoever can read that file can control retail.
  - Windows: `%ProgramData%\retail-api\token`: SYSTEM, Administrators, and users signed in to this computer (INTERACTIVE).
  - Linux: `/run/retail/api-token`: root and the `retail` group. macOS: root and the `admin` group.
  - Reading status (GET) needs no token; it holds no secrets.

| Method | Path | Action |
|---|---|---|
| GET | `/status` | State, own node, per-peer path/handshake/traffic, settings, peak memory |
| POST | `/up` | `{ server?, auth_key?, hostname?, invite? }` registers if needed, then connects |
| POST | `/down` | Disconnect (registration kept) |
| POST | `/logout` | Disconnect, then delete the current registration and its key |
| POST | `/servers/switch`, `/servers/forget` | `{ server }`: connect to a saved server instead of the current one, or remove one from the list |
| POST | `/prefs` | Exit node choice, offering an exit node, memory limit |
| GET | `/server` | Hosting state: addresses, router, devices, invites |
| POST | `/server/start`, `/server/stop` | Start or stop hosting |
| POST | `/server/invite` | Make an invite code |
| POST | `/server/nodes/{id}/delete`, `/server/invites/{id}/revoke` | Remove a device, revoke an invite |
| POST | `/server/invites/{id}/code` | The current code of a named invite (a reusable invite, hence the token) |
| POST | `/server/invites/{id}/package/{os}-{arch}` | The installer of a named invite, as the web page builds it (the tray's server window saves it) |
| POST | `/update/check`, `/update/install` | Look for a newer release; install it and restart |
| POST | `/web/login` | One-time sign-in link for the web admin page |

### 7.1 Web admin page (`retail-web`)

Listens on `127.0.0.1:41180`, and also on this device's mesh address `:41180` only while it hosts, is a member of the network and has devices allowed to manage (checked every 3 seconds). It is a separate crate built for size (`opt-level = "s"`) and talks to the daemon only through a fixed interface (`retail_web::Backend`). The page follows the browser's language (English, Korean, Japanese, Simplified Chinese, Spanish), with English as the fallback.

- Loopback: a one-time sign-in link (2 minutes) is exchanged for an `HttpOnly; SameSite=Strict` session cookie (12 hours). Other programs on the same PC can reach loopback too, hence the sign-in.
- Mesh: source address → node in the server database → allow list (node ids, kept in the host settings). WireGuard vouches for the source address, so there is no sign-in. This device's own mesh address and addresses outside the mesh are refused.
- Both: `Host` must equal the listener's address exactly (against DNS rebinding), and changes (POST) need the `X-Retail-Web` header and a same-origin `Origin`. Unit tests cover each rule.
- Installers: `GET /download/{invite id}/{os}-{arch}` streams a prebuilt tray executable followed by the daemon and CLI (on Windows also `wintun.dll`) and a manifest (invite code, file offsets) (`retail_proto::package`; the last 16 bytes are `RETAIL-PACKAGE-1`). When the executable starts it reads its own tail (at most 64 KB) and, if it is a package, enters install mode. File names are limited to safe characters. Appending breaks code signatures, so signed releases will need the payload where the signature allows it.
- Clients for other systems: taken once out of that system's installer in the official GitHub release of the same version, after checking the installer against `SHA256SUMS` (`retail-daemon/src/releases.rs`), or uploaded with `POST /api/clients/{os}-{arch}/{file name}`. An upload takes only the file names that system needs (no path characters), its content must start like an executable of that system (PE `MZ`, ELF, Mach-O), and it is written as it arrives (at most 200 MB) and renamed at the end. Methods other than GET and POST are refused.
- Installation (tray `install.rs`): confirm → run itself again as administrator (`runas`, `pkexec`, `osascript`) → unpack → register for boot (Windows Task Scheduler XML: SYSTEM, no time limit, no battery conditions, restart on failure, and a trigger every minute that starts retaild when it is not running, ignored while it runs; `retaild service stop` turns the task off until the next `service register` so that trigger cannot start the old program in the middle of a reinstall / systemd / launchd) → wait for the daemon API and join → register the tray to start at sign-in from the user's own process (the original user's HKCU, not the elevated account's). A device that already belongs to another network is left as it is. `--prefix`, `--no-service` and `--no-autostart` exist for testing (the `install` scenario of `scripts/netns-test.sh`).

## 8. State

- Daemon: `<state-dir>/state.json` (private key, server address, pin and REALITY settings, token, IP, settings).
  - Every server joined is kept there as a profile (its own key, token, address, pin and the invite used), so the device switches between networks without new invites and keeps its node and address in each. Joining another server keeps the current one; if joining fails, the device goes back to it. Logging out forgets only the current server.
  - Default location: `%ProgramData%\retail` on Windows, `/var/lib/retail` on Linux, `/Library/Application Support/retail` on macOS.
  - Every save resets the state directory to SYSTEM and Administrators (and the daemon's account) on Windows, and to the owner only (0700) on Unix.
- Hosting: `<state-dir>/server/` holds `retail.json` (devices, invite key hashes, access rules, approved routes, key expiry), `tls/` (certificate and key) and `host.json` (ports, domain, REALITY keys). The data is small and has a single writer, so instead of a database the JSON file is rewritten whole, atomically. Endpoints live in memory only; last-seen times are saved every 10 minutes and on stop.

## 9. Robustness

- If a session task (TUN, UDP, timers, probing, control) ends in an error, a supervisor restarts the session (exponential backoff from 1 to 30 seconds, reset after 60 seconds of normal running).
- A dropped control connection reconnects with backoff from 1 to 30 seconds. Meanwhile the data plane keeps working with the last NetMap.
- On SIGTERM/Ctrl-C the session is cleaned up (TUN released) before exiting. After a restart it reconnects on its own according to `want_running`.
- Endpoints silent for 20 seconds are dropped and all candidates are tried again. While data is being sent, the relay takes over after 3 seconds (6.1).
- The control connection pings every 10 seconds and reconnects after 30 seconds without an answer.

## 10. Server (hosting)

There is no separate server program. The `retail-control` library runs inside the hosting device's retaild (the tray's server window, `retail server start`, or `retail server start --no-join` / `retaild --serve` on a VPS or in Docker). [SELF-HOSTING.md](SELF-HOSTING.md) explains how to use it.

- **TLS**: a self-signed certificate (section 2). No domain or certificate authority is needed, so there is no ACME. Each handshake runs in its own task with a 10-second limit.
- **Administration**: through the local API (token required) and the web admin page of 7.1, which is never open to the internet. There is no admin sign-in page exposed to the internet.
- **Port 80**: besides the server port, port 80 is opened (if free) for the plain HTTP tunnel on networks that let only web ports out.
- **Router ports**: PCP, then NAT-PMP, then UPnP IGD open the TCP server port, 80 and a second server port (random per server in 20000–31999, kept in `host.json`; for providers that block 80 and 443 and routers that keep 443), UDP 3478 and the UDP WireGuard port, renew them every half lease, and remove them on stop. If an external port is taken, another one is used and put into invites. Invites name the public address on both server ports; when nothing is mapped, the router's own address (NAT-PMP, or UPnP GetExternalIPAddress) goes into invites after the helpers, for ports forwarded by hand. Router answers (SSDP, XML) are read with size and time limits. A private external address raises the CGNAT warning. `RETAIL_NO_PORTMAP=1` turns this off.
- **The hosting device itself**: joins its own server over loopback and reports the WireGuard port the router opened as a public endpoint candidate (its own server's STUN only sees loopback). The invite lists the LAN address of the default-route interface first (ahead of virtual machine and container adapters).
- **Helper device**: instead of a VPS, an administrator can pick a member device (`helper_device` in the server data). Its netmap then has `helper: true`; the device (`helper_role.rs`) starts a helper listener on 443 (or 8443), opens its own router's ports, and sends `ClientMessage::HelperCode` with its code, which the server links to like any helper and puts in invites. Only the chosen device's code is used, and only while it is connected.
- **IPv6**: global IPv6 addresses of the server go into invites right after public and helper addresses.
- **Helper node** (for servers that cannot be reached from outside, such as behind CGNAT): `retail helper start` on a machine with a public address (a VPS) prints a code (`retailh1.…`). With `--helper CODE` the server keeps a connection open to the helper, and for each connection the helper receives it asks the server for a new connection and joins the bytes as they are. TLS, REALITY and tunnels end at the server, so the helper never sees content. The server's own connections are told apart by the TLS SNI `link.retail.invalid` and a secret. The helper answers STUN too, and invite codes carry its address.
- **CDN**: `--front https://name` goes into invite codes, and devices try a tunnel through the CDN. The CDN must forward to port 443 of the server (or of the helper). Netmaps carry the server's current list (`server_fronts`; absent from older servers, in which case devices keep their invite's), which replaces the device's.
- **Internet tunnel** (`retail-daemon/src/cloudflared.rs`, opt-in, `tunnel` in `host.json`): for servers nothing outside can reach. retaild fetches a pinned cloudflared release (SHA-256 built in), starts `cloudflared tunnel --url http://127.0.0.1:<server port>` (a Cloudflare quick tunnel) detached from itself, and reads the `….trycloudflare.com` name from cloudflared's metrics server (`/quicktunnel`). The name is added to the server's fronts: invite codes carry it and netmaps push it to devices as it changes. The server's listener takes plain HTTP for the tunnel endpoints only, and trusts `Cf-Connecting-IP` from loopback peers, so per-address limits apply to the devices behind Cloudflare. While the tunnel is up, `stun.cloudflare.com:3478` is advertised as a STUN server so devices outside still find their public addresses. cloudflared outlives retaild (`run.json` records its pid, metrics port and origin; its own process group, systemd `KillMode=process` (written by `retaild service register`, so not on installations only auto-updated from 1.0.0), launchd `AbandonProcessGroup`, on Windows a breakaway from the task's job where the job allows it), so an update usually keeps the address; the next retaild takes it over if it still answers. A new address reaches devices still connected another way. The hosting device's own mesh address (on the server's port) is also among the addresses the server sends every device, last, so a device whose only way in was the old tunnel address finds the server again through its WireGuard path to that device, if it has a direct one, and learns the new address there (the control socket for a mesh address is not pinned to the physical interface as other control sockets are under an exit node). Without such a path (the device restarted, or the two devices only reach each other through the relay, which itself goes through the server) it needs a new invite code (it keeps its node, as for a moved server). A supervisor checks it every 15 s and starts a new one after three missed checks. Turning it off, stopping the server, or removing retail ends it.
- **Windows firewall**: an inbound allow rule for the retaild program only, removed on stop.
- **Stop**: closes all WebSocket (control and relay) connections and releases the ports. Connected devices notice within 0.1 seconds and reconnect within about 1 second when the server starts again.
- **Updates** (`retail-daemon/src/update.rs`): every 6 hours the daemon reads `VERSION` from the newest release (`releases/latest/download/VERSION`). Installing fetches this system's installer from that release (one per system: a package without an invite, `scripts/bundle.py`; for macOS a disk image with `retail.app`, the package also sitting in front of the image's data where it is read without mounting; for Linux a `.deb` whose uncompressed data holds it), checks it against `SHA256SUMS`, takes the programs out of it, and replaces the running ones in their folder (Unix: rename over the old file; Windows: the running file is renamed to `.old` first, removed at the next start). The daemon then shuts down cleanly and exits with code 75, on which systemd (`Restart=on-failure`) and launchd (`KeepAlive`) restart it. Task Scheduler restarts nothing that exits with an error code, so on Windows the daemon first starts a detached `schtasks /Run` a few seconds later, outside the task's job where the job allows it; should that fail, the task's one-minute trigger starts it. A daemon started by an older task definition (1.0.1 or before, which an update leaves in place) registers the current one. While installing, `UpdateStatus` says what it is doing (`stage`: downloading with `done_bytes` of `total_bytes`, checking, replacing, restarting), and the tray shows it as a progress bar; while the daemon is gone after an update the tray shows a restart bar for up to 75 s, then a **Start retaild** button, which runs `retaild service register` with administrator rights (UAC, pkexec, an administrator password on macOS) and so also repairs the boot registration. On Windows and macOS the service's log goes to `retaild.log` in the state folder (1 MiB, then `retaild.log.1`), panics included; on Linux to the journal. The tray app sees the daemon's newer version and a newer file of its own, and starts that one in its place.
- **Command-line install**: `retaild install [--server]` copies `retaild` and `retail` into place, registers the boot service and, with `--server`, starts a server with `join: false` and prints an invite; `retaild uninstall` undoes it. The boot registration lives in `retail-daemon/src/service.rs` and the tray app's installer calls it (`retaild service register|stop|remove`), so both install the same way.
- **Small machines**: below 1 GB of memory the daemon uses the smallest data-plane buffers unless a limit is set; releases include `linux-aarch64` (with the tray) and `linux-arm` (32-bit, daemon and CLI).
- **Removing devices**: deleting a node closes its connection and drops it from every netmap; its token stops working. The node remembers the invite it joined with (`invite_id`), so removal can expire that invite too.
- **Key expiry**: with `key_expiry_days` set, a node's key expires that long after it joined, joined again or was renewed; turning it on or changing it starts the clock anew for every node whose key has not expired (expired ones stay cut off until renewed). An expired node stays connected but gets a netmap with `expired: true` and no peers, is left out of everyone else's netmap, and its relay frames are dropped, so renewing it brings it back at once. Nodes that joined with the hosting device's own invite, and the helper device, never expire. A maintenance task (every minute) sends new netmaps when keys expire, removes nodes not seen for `remove_inactive_days` (counting from the server's start at the earliest, so downtime or an old backup never empties the network; online and exempt nodes stay), and saves last-seen times.
- **Server addresses**: netmaps carry the addresses invites would carry now (`server_addrs`), refreshed every 30 seconds. Devices keep them as alternatives to the invite's addresses, so a new public address does not strand them.
- **Backups** (`retail-daemon/src/backup.rs`): every file of the server directory (with `retail.json` taken from memory) in one JSON document, sealed with AES-256-GCM under a key from the passphrase (PBKDF2-HMAC-SHA256, 600,000 rounds). Made and restored through the local API or the web admin page on the server's own device, never by devices managing it over the network. Restoring needs the server stopped, checks the data, moves the current directory to `server.bak` and puts the backup's in place. A device given an invite whose certificate pin matches the server it belongs to (or a saved one) treats it as the same network at a new address: it keeps its key and registers with its token, so it keeps its node, address and name.
- **Packaging**: `packaging/docker` (retaild in server mode, distroless), `packaging/systemd/retaild.service`, and the release workflow that publishes the official clients (`.github/workflows/release.yml`).

## 11. Tray app

- Every screen is drawn on the CPU (winit + softbuffer + tiny-skia + ab_glyph), with no native widgets or web views.
- Tray icon: `tray-icon` on Windows and macOS, `ksni` on Linux (D-Bus StatusNotifierItem, no GTK). Instead of a menu it opens a popup it draws itself.
- Fonts are the system's, and glyphs are read only when needed. Fallback fonts for Hangul, kana and Han characters open the first time such a character appears; kana go to a Japanese font, Hangul to a Korean one, and Han characters to the font of the interface language. (Expanding every glyph up front costs hundreds of MB with CJK fonts.)
- Languages: English, Korean, Japanese, Simplified Chinese and Spanish, picked in settings or following the system (the default). Source strings are English and double as keys into one table (`i18n.rs`); a unit test checks that every row is complete and keeps its placeholders. Common daemon errors (invite code problems, unreachable server, permissions) are reworded in the chosen language. The server's router result and warnings arrive as values (`router`, `notice`), not sentences, so the tray and the web page word them themselves.
- The accent colour is blue. The theme follows the system by default (light or dark), or is fixed in settings.
- Popup: the gear at the bottom right opens Manage server, Settings and Quit. Each device has a ⋯ menu (copy IP; use or stop using it as exit node when it offers one). An exit node in use shows in the header and on its device row, and in red if it goes offline and the internet is blocked.
- Settings window: sign in with an invite code (or server URL and auth key); **Change server** lists the saved servers: a click switches, the ⋯ menu removes one, and **+ Add server** joins another with its code; log out (click twice to confirm), offer as exit node, theme (System / Light / Dark), language (a drop-down list). Theme and language are saved per user in `tray.json`.
- Server window: gear → Manage server. Start or stop hosting (click twice to confirm), addresses, router state and warnings; invites as in the web page: create (multi-device with a name and expiry, or one-time), and per invite a ⋯ menu to show the code and QR code, copy it, make a new code, save the installer for each system to the Downloads folder, or expire it (click twice). Codes on screen are wiped when the window closes. Device list (last seen, scrolls past six) and removal.
- Updates: Settings shows the state (up to date, a new release, installing, an error) with **Check now** / **Update now**, and the **Install updates automatically** toggle. A new release opens the popup once with a banner and an **Update** button.
- **Manage on the web** in the server window opens the web admin page with a one-time sign-in link.
- Run on a device already in another network, an installer package asks whether to switch; on yes the daemon leaves the current network (kept in the list) and joins the package's.
- `--preview out.png [--settings | --server] [--dark] [--lang <en|ko|ja|zh|es>] [--state ...]` renders a screen to PNG (`docs/img`).

## 12. Performance

Measured with `scripts/bench.sh` on WSL2: two network namespaces, each behind a NAT, joined by veth pairs on one computer. There is no physical NIC limit, so this compares the efficiency of implementations; plain TCP on the same path does over 25 Gbit/s. The machine varies ±25% from run to run, so comparisons are made within one session (`RUNS=3` averages).

| Implementation | Single stream | Reverse | 4 streams | Memory |
|---|---|---|---|---|
| retail | 7,396 | 7,402 | 8,287 Mbit/s | 13 MiB |
| wireguard-go (with GSO/GRO) | 5,387 | 4,056 | 4,273 Mbit/s | 814–944 MiB |

What gets it there:

1. Batched I/O and backpressure (section 5): TSO reads, GSO sends, GRO receives and writes, several reads per job.
2. **TCP GRO of our own** (`gro.rs`). tun-rs gives up merging when the buffer is small, which left the receiver calling `write()` per packet; ours writes 1/26 as often.
3. Data plane stages as a pipeline on dedicated OS threads (no task migration).
4. **Parallel encryption per peer** (below).
5. Relay and tunnels batch too: frames are gathered and flushed together, and received frames are decrypted in one batch and merged with GRO.

The largest remaining cost is encryption (ChaCha20-Poly1305, about 25%), which the WireGuard specification fixes.

**The tunnel MTU stays at 1280.** Against 1420 it costs only 1–2% throughput (most of the cost is per byte), while 1420 lets large packets vanish silently on networks with a smaller path MTU (PPPoE, mobile, tunnels over IPv6), which would need path MTU discovery per device pair.

### Parallel encryption

boringtun's `Tunn` takes `&mut self`, so one peer's encryption would run on a single core. Its session objects can encrypt through `&self`, so boringtun is vendored in `vendor/boringtun` with a minimal patch (`RETAIL-CHANGES.md`): sessions exposed as `Arc`, counters reserved in bulk, batch encryption and decryption, and timers, byte counts and session switches recorded per batch. It passes the original unit tests plus parallel round-trip, replay and tampering tests.

```
tun-read --+-- encrypt[0..K] --+-- udp-send
udp-recv --+-- decrypt[0..K] --+-- tun-write
```

- `tun-read` looks up the peer, **reserves send counters** and hands jobs to the K workers in turn; `udp-send` and `tun-write` take results in the same rotation. The channels are FIFO, so order holds without a reorder buffer and counter order matches send order.
- The pipeline is 4 jobs deep; at 2 the stages wait on each other and lose 30–45%.
- `RETAIL_CRYPTO_THREADS` sets K. The default is 2 on Linux with TUN offload and UDP GRO and at least 4 cores (about 40 packets per job), and 1 elsewhere, where a job can be a single packet.
- A long transfer across WireGuard's rekeys (the `rekey` scenario of `scripts/netns-test.sh`) runs without a break around the new handshakes.

## 13. Next milestones

| Milestone | Content |
|---|---|
| Policy | Key rotation, admin approval of exit nodes, access rules for exit-node use and for hosts on routed networks |
| Convenience | IPv6 inside the mesh, mobile |
| Releases | Code signing, signed update metadata |
| Performance | Measure the worker count (K) on real many-core hardware, the relay on lossy and high-latency lines (a UDP relay if needed), several relay servers, a faster first REALITY connection |
| Verification | Exit node routing, NAT and firewall rules on real Windows and macOS machines. Proxy integrated authentication (Kerberos, NTLM) and PAC on a real corporate network |
| Connectivity | Opening the IPv6 firewall with PCP, choosing a helper device in the tray |

## 14. Known limitations

- Where no direct connection is possible (two symmetric NATs, blocked UDP, ...), traffic relays through the control server, whose line then limits throughput. The control server is the only relay.
- Virtual (mesh) addresses are IPv4 only; the real paths between devices use IPv6 too. Windows and macOS have no TUN offload and may be slower than Linux (UDP batching applies there).
- On Windows every user signed in to the computer can control retail (INTERACTIVE can read the local API token), and so can other programs running as those users.
- Access rules cover traffic to a device itself; internet traffic through an exit node is not filtered by them, and offering an exit node needs no admin approval (the using side chooses).
- MagicDNS needs systemd-resolved on Linux for the system to use it; elsewhere ask 100.100.100.100 directly.
- Idle memory is 11.6–12.4 MiB, at most 14.9 MiB under load (within the 10–20 MB budget).
- Integrated proxy authentication works on Windows only. Linux and macOS use Basic and SOCKS5 passwords only, and Linux reads the system proxy from environment variables only.
- Losing the server certificate key without a backup means inviting every device again.
- Access rules cannot single out hosts on a routed network: a peer reaches all of it or none. Routing networks on Windows and macOS has not been checked on real machines yet.
- **Other VPNs that use `100.64.0.0/10` conflict**: retail takes addresses from that range and UDP 41641. retaild moves to a random port if 41641 is taken (on Windows it holds the port exclusively, since otherwise Tailscale can share it silently and take its datagrams), but the address ranges overlap, so do not run such a VPN on the same device at the same time.
