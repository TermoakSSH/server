# Private networks (Termoak 0.7)

Status: **phase 0 done** (core + server groundwork, 2026-10-21); **phase 1a
done** (2026-10-21): `termoak-netd` with WireGuard (`server/netd/`, Go), the
server's WireGuard keys, netd following the vaults, QA; **phase 1b, part 1
done** (2026-10-22): the UI in the web and the desktop app (§8.1); **phase
1b, part 2 done** (2026-10-22): the UI in Android and iOS; **phase 2a
done** (2026-10-22): Tailscale/Headscale in `termoak-netd` (tsnet, §6.6),
the server and QA (Headscale in Docker). Next: phase 2b, the Tailscale UI
in the apps (§8.1, "Tailscale/Headscale").

This document is the design, the **server ↔ `termoak-netd` protocol**, the
security model and the compatibility notes. Plan: `PLAN-0.7.md` §1. A copy
lives in the server repository (`docs/NETWORKS.md`); keep both equal.

---

## 1. Decisions (owner, 2026-10-21)

- WireGuard, Tailscale/Headscale and ZeroTier live **only on the server**,
  in a separate optional service, `termoak-netd` (Go). The apps never embed
  a VPN: they manage networks and pick one per host or group.
- Two server builds: without networks (`termoak-server` alone, all Rust,
  AGPL) and with networks (`termoak-server` + `termoak-netd`).
- Free plan: **10 networks** (`max_networks`).
- A host with a network:
  - **terminal** → a server session (the server's SSH connection dials
    through netd);
  - **SFTP, tunnels and "local" terminals** of the apps → the **server
    relay**: the app opens a WebSocket to the server, the server dials
    `host:port` through netd and pipes the bytes. SSH stays end to end
    between the device and the host.

## 2. Architecture

```
 app (core) ──WebSocket /hosts/{id}/relay──┐
                                           ▼
                         termoak-server ──Unix socket──► termoak-netd ──► WireGuard / tsnet / libzt
 web ──server session──►  (sessions,                      (user space,      (one isolated node
                          holder, AI,                      no root)          per network)
                          exec, SFTP)
```

- Everything that connects **from the server** (server sessions, in the
  server or in the session holder; `POST /hosts/{id}/test`; `/exec`; SFTP;
  the AI) goes through `termoak_ssh::Connection::connect`, whose first hop
  uses a `NetworkDialer` when the host has a network. On the server that
  dialer is netd (`termoak_server::netd::NetdDialer`); in the holder
  process too (`[networks] netd_socket` is read by `sessions-holder`).
- The **apps** get a `RelayDialer` (`termoak_client::net_relay`): the
  first hop is the relay WebSocket instead of TCP. Jump chains still work:
  the network applies to the first connection only, like the proxy.
- A host with a network **never** falls back to a direct connection: no
  dialer → `network_unavailable`.

## 3. Data model

### `Network` (new synced entity, kind `network`)

```json
{
  "id": "…", "name": "Office", "kind": "wireguard",
  "description": "",
  "wireguard": {
    "addresses": ["10.9.0.2/32"], "dns": [], "mtu": null,
    "peers": [{"public_key": "…", "endpoint": "vpn.example.com:51820",
               "allowed_ips": ["10.9.0.0/24"], "persistent_keepalive": 25}],
    "public_key": "…"
  },
  "tailscale": {"control_url": null, "hostname": null, "tags": [], "ephemeral": null},
  "zerotier": {"network_id": "8056c2e21c000001", "central_url": null}
}
```

- `kind`: `wireguard` | `tailscale` (also Headscale: `control_url`) |
  `zerotier`. An unknown kind (a later version's) is kept as is
  (`NetworkKind::Other`), like `HostProtocol`.
- Only the section of its `kind` matters; the others are ignored.
- **Secret** (`NetworkSecret`, encrypted like passwords, with the vault
  key): `private_key`, `preshared_key` (WireGuard), `auth_key`
  (Tailscale/Headscale), `api_token` (ZeroTier Central). Never in listings;
  `GET /networks/{id}/secret` for Editors (audited); Use-only members never
  see it but the server can use it (`SecretUse::Server`).
- Networks live in **account vaults** only (never on "This device":
  `save_network` refuses). Team vault networks are shared by the team.
- Validation: name required (≤ 100 chars), WireGuard peers need a public
  key, ZeroTier id is 16 hex. Tailscale (core 0.7.0-next.3): `control_url`
  http(s) with a host and no user, query or fragment (`null`: Tailscale's);
  `hostname` a DNS label (letters, digits, `-`, ≤ 63; default
  `termoak-<last 8 hex digits of the id>`); `tags` `tag:name` (≤ 20;
  empty = the auth key's tags); `ephemeral` `null` = yes with an auth key,
  no without one; the secret's `auth_key` printable ASCII without spaces
  (≤ 1024), never echoed in errors (`Entity::validate_secret`, on saves and
  pushed sync records: REST `400`, sync rejected `invalid`).

### `HostSettings.network_id: Option<Uuid>`

- On hosts and groups, inherited through groups like `proxy` and
  `jump_host_ids` (`None` = inherit / direct).
- Same-vault rule: it must point to a network of the same vault
  (`cross_vault_reference` otherwise); the resolver only looks there. A
  network missing from the vault is an error (`network_not_found`), never
  a direct connection.
- `ResolvedHost.network: Option<ResolvedNetwork>` (with the secret) and
  `first_hop_network_id()` / `first_hop_network()` / `first_hop()`: the
  network of the first jump, or else the host's (like the proxy). With a
  network the proxy is ignored.
- Transfers: `settings.network_id` is a dependency like the key or the
  startup snippet (moved/copied with the host; `dependencies: none`
  detaches it). This device cannot hold networks (core 0.7.0-next.2): a
  host or group moved or copied there loses `network_id` (reported in
  `detached`), the network stays in the account, and moving a network
  there is refused.
- **WireGuard public key:** `wireguard.public_key` is derived from the
  private key (the secret). The server fills it in whenever a network is
  saved (REST, sync v2 push, `POST /networks/{id}/wireguard/key`), so every
  client shows the key to add as a peer on the other side.

## 4. Sync and compatibility

The lesson of 0.6 ("the hosts REST API dropped protocol/icon"): older
clients must not lose what they do not know.

1. **Old cores cannot read a `network` record.** `SyncRecord.kind` is a
   closed enum in every core ≤ 0.6: one unknown kind fails the whole sync
   response. So:
   - **legacy sync** (`POST /sync`, cores 0.2/0.3) never sends non-legacy
     kinds and ignores pushed ones;
   - **sync v2** only sends the kinds the client lists in `kinds`
     (0.7 cores send `EntityKind::ALL`); without `kinds`, only the 8 legacy
     kinds (`EntityKind::LEGACY`). Departures (`removed`) too.
   - A 0.7 client whose cursors advanced without `network` (it was older,
     or synced with a server before 0.7) downloads everything once
     (`sync.kinds` meta key in the client store).
2. **Old cores drop `settings.network_id` when they edit a host or group**
   (serde drops unknown fields). 0.7 cores always write the key (`null`
   when empty), so its *absence* means "an older client": the server keeps
   the stored value (`termoak_core::store::keep_omitted_fields`) on:
   - sync pushes (legacy and v2, in `Store::apply_remote_v2`);
   - REST `PUT /hosts/{id}` and `/groups/{id}` (the web and API clients).
   `null` clears it. Tested in core (`old_cores_editing_a_host_keep_its_network`)
   and the server (`networks_sync_only_to_clients_that_know_them_and_old_apps_keep_them`).
   `protocol`/`icon` cannot be protected this way (they are omitted when
   default), `network_id` is never omitted. The same holds for
   `tailscale.ephemeral` of networks (cores before 0.7.0-next.3 drop it;
   0.7.0-next.3 always writes it, `null` when unset).
3. Old apps connecting **from the device** to a host with a network do not
   know it and connect directly (as before; usually unreachable). Their
   server sessions go through the network (the server decides).
4. A 0.7 app on a server **without** networks: `network_unavailable`
   (`TermoakError.NetworkUnavailable`); it should hide networks when
   `features.networks` is false.
5. Old session holders (no `networks` feature in their hello) would dial
   directly: the server keeps the sessions of network hosts in its own
   process until the holder is restarted.

## 5. Server

```toml
[networks]
netd_socket = "/run/termoak-netd/netd.sock"   # absent → feature off
max_relays_per_user = 16
relay_idle_minutes = 30
dial_timeout_secs = 20
```

- `GET /info` → `features.networks`: configured **and** netd answered the
  last `hello` (checked at start and every 30 s, and by every request);
  `features.network_kinds`: the kinds of that `hello` (`["wireguard"]`, or
  `["wireguard", "tailscale"]` with the Tailscale build; `[]` without
  netd). Apps offer a kind only when it is listed.
- `limits.max_networks` per plan (default 10; admins unlimited). Billing
  user of a vault: its owner; for a team vault, the team's first owner (by
  date). Checked on `POST /networks`, on sync v2 pushes of new networks
  (rejected with `plan_limit`, the client keeps them dirty) and on
  transfers into a vault billed to someone else. `GET /me/plan` →
  `usage.networks`.
- Routes: CRUD `/networks` (+ `/secret`), `GET /networks/{id}/status`,
  `POST /networks/{id}/up|down`, `GET /networks/{id}/peers`,
  `POST /networks/{id}/wireguard/key` (the server generates the private
  key, stores it as the secret and returns the public key; `replace: true`
  if it has one), `GET /hosts/{id}/relay` (OpenAPI tag `networks`;
  `docs/API.md`). `TERMOAK_NETD_SOCKET` also sets `netd_socket`.
- **netd follows the vaults:** after a network is updated (REST or sync
  push) the server compares the revision netd runs (`status`) with the
  stored one and sends `down` when they differ; deleting a network, its
  vault, its team or the account sends `down` too. A rename keeps the node
  (the revision covers the kind, the configuration without `public_key`,
  and the secret). Whatever is missed goes down when idle. A deleted
  network gets `down` with `forget` whether it runs or not (netd removes
  what it keeps of it: a persistent Tailscale node logs out and its state
  is deleted).
- **Status for members:** `GET /networks/{id}/status` is for any member,
  but `node.auth_url` (a Tailscale login URL: whoever opens it decides which
  tailnet the server's node joins) only for Editors.
- **Host test** (`POST /hosts/{id}/test`) dials through the network and
  answers `network: {id, name, kind}` with `latency_ms` measured through
  it (the "via Office · 23 ms" of the apps).
- Errors: `network_unavailable` 503, `network_not_found` 404,
  `network_dial_failed` 502 (`netd_code`; with `needs_auth` also `auth`:
  `login` or `approval`), `not_in_network` 422, `relay_limit` 429.

### Relay (`GET /api/v1/hosts/{id}/relay`, WebSocket)

- **By host id, not by address** (choice): the server dials the first hop
  exactly as the vault defines it (address, port, network). Nobody can ask
  the server for arbitrary `ip:port` inside a network (or outside: no
  SSRF), and a Use-only member only reaches hosts an Editor put in the
  network. Jump chains: the server dials the first jump; the app runs the
  rest inside SSH.
- Auth: bearer token (header or `?access_token=`). Access: the same rule as
  just-in-time credentials ("connect from the device"): Editors, and
  Use-only members unless the vault is Strict (`use_only_strict`). No
  access to the vault: `404`.
- Before the upgrade: checks, per-user limit, **dial through netd**. Every
  failure is a JSON error. The server never dials directly.
- After: binary frames both ways (text ignored), server pings every 30 s,
  close `1000 host_closed` / `1000 idle` / `4007 signed_out`.
- Audit (vault): `relay.open` {network_id, network, kind, address, port,
  hop_host_id, device} and `relay.close` (+ bytes_up, bytes_down,
  duration_ms, reason). Byte counts per relay.

## 6. `termoak-netd` protocol (v1)

Simple to implement in Go with `net.Listen("unix", …)`, `bufio.Reader` and
`encoding/json`.

### Transport

- Unix stream socket, path from `[networks] netd_socket`. netd creates it
  with mode `0600` (it runs as the same user as the server, the default) or
  `0660` with `--socket-group <group>`, and checks every connection's peer
  with `SO_PEERCRED`: netd's own user, root, the users of `--allow-uids`
  and, with a socket group, processes in that group (primary or
  supplementary). Others are closed without an answer. A live socket is
  never replaced (a second netd refuses to start); a stale one is.
- **One connection per request.** The server writes **one JSON object on
  one line** (`\n`-terminated, UTF-8), netd answers **one JSON line**.
  Then the connection is closed — except after a successful `dial`, when
  the same connection becomes the raw TCP stream (§6.4).
- Go note: read the request with a `bufio.Reader` (`ReadBytes('\n')`) and
  keep using **that reader** for the stream after `dial` (it may hold
  buffered bytes). Answer with `json.NewEncoder(conn).Encode(v)` (it adds the
  `\n`). Max line: 1 MiB.
- Every request has `"v": 1` (protocol version) and `"op"`.
- Answers: `{"ok": true, …}` or `{"ok": false, "code": "…", "message": "…"}`.

### Error codes (netd → server)

| code | meaning | server maps to |
|---|---|---|
| `invalid` | malformed request | 502 `network_dial_failed` |
| `unsupported_kind` | this build cannot join the kind (e.g. no ZeroTier) | 503 `network_unavailable` |
| `needs_auth` | the node waits for authorization (Tailscale login URL, ZeroTier member not authorized); the line has `auth`: `login` or `approval` | 502 `network_dial_failed` (+ `auth`) |
| `network_error` | the network could not start (bad key, control server down…) | 502 `network_dial_failed` |
| `dial_failed` | connection refused / unreachable inside the network | 502 `network_dial_failed` |
| `timeout` | `timeout_ms` passed | 502 `network_dial_failed` |
| `limit` | netd resource limit (too many networks/streams) | 502 `network_dial_failed` |

The server adds netd's code as `netd_code` to its error. No answer at all
→ `network_unavailable`.

### NetworkSpec

Every request that needs the network carries it whole; netd keeps no
database (it may cache running nodes by id):

```json
{
  "id": "0190…",                 // network id (stable; also the node key)
  "name": "Office",
  "kind": "wireguard",           // wireguard | tailscale | zerotier
  "revision": "3f9a0c1d22e4b7a8", // 16 hex: changes with config or secret
  "config": { …the section of its kind (Network.wireguard / .tailscale / .zerotier)… },
  "secret": {"private_key": "…"},  // NetworkSecret (only the fields set)
  "vault_id": "0190…"            // optional, for logs
}
```

- If a node for `id` runs with another `revision`, netd restarts it with
  the new spec.
- Tailscale defaults: hostname `termoak-<last 8 hex digits of the id>`
  (UUIDv7 ids start with a timestamp: networks created together share
  their first digits), no advertised tags (the auth key's apply;
  `tag:termoak` with an OAuth client secret), ephemeral with an auth key
  and persistent without one (§6.6).
- `secret` must never be logged.

### 6.1 `hello`

```json
→ {"v": 1, "op": "hello"}
← {"ok": true, "v": 1, "version": "0.1.0", "kinds": ["wireguard", "tailscale", "zerotier"]}
```

`kinds`: what this build can join (`["wireguard"]` without the
`tailscale` build tag, `["tailscale", "wireguard"]` with it; ZeroTier
answers `unsupported_kind` until its backend is built in). Used as the
health check (every 30 s); the server passes it on as
`features.network_kinds`.

### 6.2 `up` / `down` / `status`

```json
→ {"v": 1, "op": "up", "network": NetworkSpec}
← {"ok": true, "status": Status}

→ {"v": 1, "op": "down", "network_id": "…", "forget": false}
← {"ok": true}                      // also when it was not up

→ {"v": 1, "op": "status", "network_id": "…"}
← {"ok": true, "status": Status}    // never brings it up
```

```json
Status = {
  "network_id": "…",
  "state": "down" | "starting" | "needs_auth" | "up" | "error",
  "message": "…",                       // optional, for humans
  "node": {"name": "termoak-0190abcd", "addresses": ["100.64.0.5"],
           "public_key": "…",           // WireGuard
           "node_id": "…",              // ZeroTier / Tailscale
           "auth_url": "https://…"},    // when needs_auth
  "revision": "…", "since": 1760000000000, "last_used_at": 1760000000000,
  "rx_bytes": 0, "tx_bytes": 0,         // the tunnel's bytes
  "last_handshake_at": 1760000000000,   // WireGuard; absent: never
  "streams": 0,                         // connections open now
  "dials": 0, "dials_failed": 0,        // since it came up
  // Tailscale only (absent for WireGuard):
  "auth": "login" | "approval",         // with needs_auth: open node.auth_url / approve the device
  "control_url": "https://controlplane.tailscale.com",
  "tailnet": "example.com", "magic_dns_suffix": "tail1234.ts.net",
  "peer_count": 3,                      // when up
  "ephemeral": true,
  "last_error": "…"                     // the latest error (refused key…), also while retrying
}
```

`node` of a Tailscale network: `name` (its hostname), `addresses` (100.x
and fd7a:…), `node_id` (stable id), `dns_name` (MagicDNS name) and
`auth_url` while it waits for a login. `rx_bytes`/`tx_bytes` and
`last_handshake_at` sum its peers.

`down` with `"forget": true` (the server sends it when the network was
deleted): besides stopping the node, netd removes what it keeps of the
network, also when it is not running (a persistent Tailscale node logs out
and its state directory is deleted). Older netd builds ignore the field.

`up` may answer before the node is fully up (`starting`, `needs_auth`).
A start that failed (bad key, unresolvable endpoint…) is `error` with the
reason in `message`; the next `up`/`dial` retries it.

```json
→ {"v": 1, "op": "list"}
← {"ok": true, "networks": [Status, …]}   // every network netd runs
```

`list` is for operators and metrics (`termoak-netd request '{"v":1,"op":"list"}'`).

### 6.3 `peers`

```json
→ {"v": 1, "op": "peers", "network": NetworkSpec}
← {"ok": true, "peers": [{"name": "nas", "dns_name": "nas.tail1234.ts.net",
                          "addresses": ["100.64.0.7"], "os": "linux",
                          "online": true, "last_seen": 1760000000000}]}
```

Brings the network up if needed. WireGuard answers its configured peers
(no discovery): `name` = endpoint (or the start of the key), `addresses` =
allowed IPs, `public_key`, `endpoint`, and `online`/`last_seen` from the
last handshake (online under 3 minutes). Tailscale answers the devices the
node sees (the tailnet's ACLs decide): `name` (hostname), `dns_name`
(MagicDNS, without the final dot), `addresses` (100.x, fd7a:…), `os`,
`online`, `last_seen`, `tags`, `routes` (subnets it routes; exit routes
left out) and `id` (stable id). For "import hosts".

### 6.4 `dial`

```json
→ {"v": 1, "op": "dial", "network": NetworkSpec, "host": "10.9.0.5", "port": 22, "timeout_ms": 20000}
← {"ok": true, "remote": "10.9.0.5:22"}
   …then raw bytes in both directions on the same connection…
```

- netd brings the network up if needed (waiting up to `timeout_ms` for
  `up`; a Tailscale node that needs a login answers `needs_auth` at once),
  resolves `host` **inside the network** (MagicDNS / the WireGuard `dns`),
  and opens TCP to `host:port` through its user-space stack.
  `timeout_ms` is capped by `--max-dial-timeout` (default 20 s when
  missing).
- After the `ok` line, netd copies bytes both ways until either side
  closes (half-close: shutdown the write side when the other side's read
  ends). Closing the Unix connection closes the TCP connection.
- Failure: one error line, then close.

### Requirements for netd (security)

- **Never use the host's kernel network stack to reach a network's
  hosts**: dials only go through that network's user-space stack
  (wireguard-go + netstack, `tsnet`, libzt). The only outside traffic is
  each node's own transport (WireGuard UDP to the endpoint, Tailscale
  control/DERP, ZeroTier roots).
- **Isolation:** one node per network id; a dial for network A never uses
  network B's node.
- No root, no TUN devices, no routes (works in the unprivileged LXC).
- Idle shutdown (phase 1): stop nodes unused for N minutes; limits on
  networks and streams; per-network metrics and logs (without secrets).

### 6.5 `termoak-netd` (phase 1a)

Go module in the server repository, `server/netd/` (a static binary,
`CGO_ENABLED=0`; built in the official Go image, so the build machine needs
no Go):

```
netd/
  cmd/termoak-netd/     main: flags/env, socket, signals; `request` (send one line) and `version`
  cmd/termoak-netd/tailscale.go   (build tag `tailscale`) registers the Tailscale backend
  cmd/termoak-wgpeer/   test tool, never shipped: a WireGuard peer in user space (QA)
  cmd/termoak-tsnode/   test tool, never shipped (tag `tailscale`): a tsnet node forwarding ports (QA)
  internal/proto/       the protocol types and codes (Spec never prints its secret)
  internal/netd/        Manager (nodes, limits, idle reaper), Server (socket, SO_PEERCRED,
                        one request per connection, the byte pipe), Backend/Node interfaces
  internal/wg/          WireGuard: wireguard-go + gVisor netstack, one device and stack per network
  internal/wgtest/      a WireGuard "site" for tests (echo, forward, DNS in its netstack)
  internal/ts/          Tailscale/Headscale: config.go, resolve.go, state.go (no tag: configuration,
                        state mapping, MagicDNS resolution, state directory), node.go (tag
                        `tailscale`: tsnet nodes)
```

- **WireGuard** (`internal/wg`): `device.NewDevice(netstack.CreateNetTUN(…),
  conn.NewDefaultBind())`. The node's addresses are `wireguard.addresses`
  (`10.9.0.2/32` or a bare IP), MTU `mtu` (default 1420), the peers'
  `public_key`, `endpoint` (a name is resolved with the host's resolver
  when the network starts: the endpoint is outside the network),
  `allowed_ips`, `persistent_keepalive`; the secret's `private_key` and
  `preshared_key` (applied to every peer). The host's kernel only carries
  the encrypted UDP; dials go through the network's own netstack. Two
  networks may use the same addresses: they never see each other.
- **Names.** An IP is used as is. A name is resolved with the network's
  `dns` servers through the tunnel when it has them (entries of `dns` that
  are not IPs are search domains, like wg-quick: `nas` → `nas.lan`);
  otherwise with the system resolver (`/etc/hosts`, the host's DNS), for
  public names that point to private addresses. Either way only addresses
  inside some peer's `allowed_ips` are dialed; anything else fails at once
  with `dial_failed` ("outside the network") instead of waiting for a
  timeout. A dial with no handshake ends in `timeout` with a hint (check
  the endpoint and that the peer has the server's public key).
- **Lifecycle.** A network starts on the first `up`/`peers`/`dial` (`up`
  waits up to 10 s, then answers `starting`), restarts when its revision
  changes, and stops on `down`, when idle (`--idle`, default 15 min
  without open connections; checked every quarter of it, at most 30 s), or
  when room is needed. `down` and restarts close its open connections.
- **Limits.** `--max-networks` (64): when full, the least recently used
  network without connections makes room, otherwise `limit`.
  `--max-streams` (256 per network) → `limit`. `--max-dial-timeout` (2
  min). Request line: 1 MiB, 30 s to send it.
- **Pipe.** After `ok`, bytes are copied both ways with half-close. Once
  either side has ended, the other is closed after 30 s without bytes (a
  peer that vanished never sends FIN through the tunnel, and its
  connection must not keep the network busy); an error on either side
  closes both.
- **Logs and metrics** (`log/slog`, text or JSON on stderr): network up
  (addresses, peers, its public key), down (reason: requested, idle,
  replaced, shutdown; dials), each connection closed (host, port,
  bytes up/down, duration), dial failures (code); per-network counters in
  `status`/`list`. Keys and secrets are never logged (`Spec` has a
  `LogValue` without them; wireguard-go only logs peers' short public keys).
- **Kinds.** Backends register by kind (`netd.Register`). WireGuard is
  always built in; Tailscale (`tsnet`, phase 2a, §6.6) is behind the
  `tailscale` build tag and ZeroTier (libzt, phase 6) will be too. Without
  them those kinds answer `unsupported_kind` (→ the server's
  `network_unavailable`) and `hello` does not list them.
- **Shutdown** (SIGTERM/SIGINT): stops accepting, takes every network
  down, removes the socket.


### 6.6 Tailscale / Headscale (phase 2a)

`internal/ts`, compiled in with `go build -tags tailscale` (the "with
networks" bundle, `Dockerfile.netd` and QA build it; `NETD_TAGS=""
scripts/release-local.sh build server` or `--build-arg TAGS=` leave it
out). It uses `tailscale.com/tsnet` (v1.104.2, BSD-3), Tailscale's own
library: each network is a `tsnet.Server` with its own state, magicsock,
WireGuard engine and gVisor netstack (`Tun` unset: user space, no TUN, no
root). Binary: about 23 MB with Tailscale, 7 MB without.

**Configuration** (`Network.tailscale` + secret):

| field | default | notes |
|---|---|---|
| `control_url` | Tailscale's (`https://controlplane.tailscale.com`) | a Headscale URL (http or https) |
| `hostname` | `termoak-<last 8 hex of the id>` | the node's name and MagicDNS label (the control server may add `-1` if taken) |
| `tags` | none: the auth key's tags | Headscale (0.28+) **refuses advertised tags** when a node logs in with a pre-auth key (`requested tags [...] are invalid or not permitted`): the key's tags apply. On Tailscale, advertise tags only with an untagged key whose owner may assign them. A Tailscale OAuth client secret (`tskey-client-…`, which needs tags) gets `tag:termoak` |
| `ephemeral` | yes with an auth key, no without one | see "State" |
| secret `auth_key` | none: interactive login | a reusable pre-auth key, ideally ephemeral and tagged (Tailscale `tskey-auth-…`, Headscale `hskey-auth-…` from `headscale preauthkeys create --reusable --ephemeral --tags tag:termoak`), or a Tailscale OAuth client secret (`tskey-client-…[?ephemeral=…&preauthorized=…]`: tsnet creates a one-off key with it) |

**State** (netd keeps no database; `--state-dir`, default systemd's
`StateDirectory=termoak-netd`, else a directory in `$TMPDIR`):

- **Ephemeral nodes** (the default with a key): the node's state lives in
  memory (`mem.Store`); only tsnet's scratch files go to
  `<state-dir>/tailscale/eph-<id>-<random>/`, removed when the node stops
  (and leftovers of a crash when netd starts). Every stop (`down`, idle,
  revision change, eviction, SIGTERM) **logs the node out first**, so
  Tailscale and Headscale delete it at once (Headscale: "Deleting ephemeral
  node during logout"); only a crash or SIGKILL leaves it until the control
  server's inactivity timeout (Headscale `node.ephemeral.inactivity_timeout`,
  30 min by default). Each start registers a new node with the auth key: a
  new 100.x address for the server (the hosts it dials do not change), so
  the key must be **reusable**. No key ever touches the disk.
- **Persistent nodes** (`ephemeral: false`, the default without a key: a
  login done by hand must survive restarts): tsnet's state (node and
  machine keys, 0600) in `<state-dir>/tailscale/<id>/` with `termoak.json`
  (its control URL). Stops do not log out: the node stays in the tailnet
  (offline) and keeps its name and address. A changed control URL, or a
  network turned ephemeral, logs the old node out and starts afresh. `down`
  with `forget` (the network was deleted) logs it out and removes the
  directory, running or not (Headscale then shows it expired). Trade-off:
  keys on disk and a node listed while netd is down, against no re-login.
- netd never runs two nodes of the same network at once (a restart waits
  for the old one to close).

**Auth flow** (never blocks a request): `Start` only creates the node; a
watcher follows tailscaled's IPN bus. netd's states:

| tailscaled | netd `state` | `auth` | notes |
|---|---|---|---|
| NoState, Starting, NeedsLogin while the key is used | `starting` | | `up` waits up to 10 s (start timeout) for it to settle; dials wait up to their timeout |
| Running | `up` | | |
| NeedsLogin with a login URL | `needs_auth` | `login` | `node.auth_url` (Tailscale login, Headscale `/register/<id>`); no key, or the key was not enough |
| NeedsMachineAuth | `needs_auth` | `approval` | approve the device in the admin console |
| an error while not running | `error` | | `message`: "the control server refused the auth key: …" for key errors, a hint for refused tags; `last_error` keeps the raw one; tsnet retries with a backoff (it can still come up) until the network goes idle |

A dial or `peers` on a `needs_auth` node fails at once with `needs_auth`
(+ `auth`), on an `error` node with `network_error`, on a node still
starting with `timeout`. Status reads come from the node's local API
(in memory). tsnet's log uploads to log.tailscale.com are **disabled**
(`logtail.Disable`, `TS_NO_LOGS_NO_SUPPORT`); its own logs only at debug
level with `TERMOAK_NETD_TAILSCALE_VERBOSE=1`. The auth key is never
logged.

**Dials** stay in the tailnet: `tsnet.Server.Dial` would use the **host's
network** for an address outside the tailnet, so netd never calls it.
Instead it resolves `host` itself and dials through the node's own netstack
(`netstack.Impl.DialContextTCPWithBind` from the node's 100.x address):

- an IP is used as is; a name is looked up as a MagicDNS name in the
  node's network map (`nas`, `nas.tail1234.ts.net`, a unique short name of
  a shared device) and the tailnet's extra DNS records; any other name with
  the system resolver;
- only addresses of the peers (their Tailscale IPs) or inside the subnets
  they route (subnet routers) are dialed; `/0` routes (exit nodes) never
  count, so the internet, 127.0.0.1 or the server's LAN fail at once with
  `dial_failed` ("outside the tailnet"); netd never selects an exit node;
- what a node may reach is decided by the tailnet's ACLs (a device the
  ACLs hide is not a peer: "there is no device named …").

**Limits and memory.** `--max-tailscale` (`TERMOAK_NETD_MAX_TAILSCALE`,
default 16) Tailscale nodes up at once, on top of `--max-networks`: when
full, the least recently used Tailscale network without connections makes
room, else `limit`. Measured (Headscale on the same host, 1–2 devices per
tailnet): netd with Tailscale idles at ~18 MiB RSS (7 MiB without); each
tsnet node adds **2–3 MiB** (5 nodes: 31 MiB; 12 nodes: ~38 MiB), and 12
nodes each moving 16 MiB at once peaked at ~60 MiB. Big tailnets cost more
(the network map grows with the devices). The unit keeps `MemoryMax=512M`
and adds `GOMEMLIMIT=384MiB` so the Go GC works harder before the cap.
Joining takes 3–5 s (registration and the first network map).

**Network access.** HTTPS (or HTTP for a Headscale behind plain HTTP) to
the control server and DERP relays, UDP for STUN (3478) and peer-to-peer
WireGuard; nothing listens. In the systemd unit: `AF_INET`, `AF_INET6`,
`AF_NETLINK` (tsnet watches the interfaces), `AF_UNIX`.

**Tests.** `go test -tags tailscale ./internal/ts/` runs the nodes against
Tailscale's in-process test control server (`tstest/integration/testcontrol`
with its own DERP and STUN on 127.0.0.1): up with MagicDNS, peers, dials by
short name, FQDN and IP (256 KiB echoed), nothing outside the tailnet
(127.0.0.1, 8.8.8.8, `localhost`, unknown names), the manager (up settles,
status fields, `--max-tailscale` eviction and `limit`), needs a login (the
URL, `needs_auth`/`login` on dial, then up after the login), needs approval,
a refused key (never echoed), persistent nodes (same node after a restart,
`Forget`, `CloseAndForget`). Without the tag: configuration, state mapping,
MagicDNS resolution and the state directory. QA (`./run.sh tailscale`):
Headscale in Docker (§9).

## 7. Security model

- The server is the only party that joins networks; the network secrets are
  stored like passwords (vault key, master key) and only leave the server
  process towards netd (and the session holder) over local sockets.
- Who can use a network = who can use a host of its vault. Who can see or
  change it = Editors of its vault. Use-only members can connect (server
  sessions; relay unless Strict) but never see the keys.
- No SSRF: the relay takes a host id, the server dials what the vault
  says, only through netd, only for the user's own vaults (or team vaults
  with access). User A cannot use user B's network (B's vault is not
  visible: `404`; referencing it from A's host: `cross_vault_reference`).
- The relay carries SSH end to end: the server sees encrypted bytes only.
  Rate limits: concurrent relays per user, idle timeout, audit with bytes.
- E2EE vaults (future): the server cannot open the secrets; the device
  will hand them over when bringing the network up (phase 2+).

## 8. Core and FFI (what the apps get)

- `termoak_ssh::net`: `NetworkDialer`, `Dialer`, `DialRequest`,
  `BoxedStream`; `ConnectOptions::with_dialer`, `TelnetOptions.dialer`,
  `ConnectionPool::set_dialer`; `SshError::Network { code, message }`.
- `termoak_client::net_relay::RelayDialer` and `ws_stream` (WebSocket ↔
  `AsyncRead`/`AsyncWrite`); `Workspace::connect_item` and
  `open_telnet_item` pick it for hosts with a network (account scope,
  signed in, `features.networks`; else `network_unavailable`). Reachability
  probes skip those hosts (`Skip::Network`).
- Sync v2 sends `kinds`; one full re-download after upgrading.
- FFI: `PrivateNetwork` (+ `WireguardSettings`, `WireguardPeer`,
  `TailscaleSettings` (`ephemeral` since 0.7.0-next.3), `ZerotierSettings`,
  `NetworkSecrets`),
  `list_networks`, `get_network`, `save_network(network, secrets?)`,
  `network_secrets`, `delete_network`; `HostSettings.network_id`;
  `TermoakError.NetworkUnavailable`; `ProbeSkip.Network`.

### API error details in the FFI

`TermoakError` stays a **flat** error (every variant carries only the
message), so every existing catch site and constructor keeps compiling.
The structured part travels apart:

- `api_error_info(error_message) -> ApiErrorInfo?` with `status` (HTTP; `0`
  for a rule checked on the device), `code`, `message` (without the
  "the server responded …" prefix) and `details_json` (the error object's
  other fields: `vaults` of `shared_vaults`, `teams` of `last_team_owner`,
  `limit`/`max` of `plan_limit`, `field` of `cross_vault_reference`,
  `netd_code`…). The details of the last 64 errors are kept in memory, keyed
  by the message; older ones are parsed from the text (no details).
- Swift: `TermoakError.apiError` (TermoakKit). Kotlin:
  `TermoakException.apiError` (`com.termoak.kit`).

(Non-flat UniFFI errors were rejected: Kotlin would replace `e.message`
with `"field=value, …"` and a field named `message` clashes with
`Throwable.message`; Swift `case .X(let message)` patterns would break.)

### What the apps must change when they bump core to 0.7

Nothing is required to compile, except:

- **Kotlin/Swift:** an exhaustive `when`/`switch` over `TermoakException`
  / `TermoakError` or `ProbeSkip` needs the new `NetworkUnavailable` /
  `Network` case (an `else`/`default` branch is enough).
- **Desktop (Rust):** `ClientError::Api` has a new field `details` (one
  constructor in `views/join.rs`: use `ClientError::api(status, code,
  message)` or add `details: json!({})`); exhaustive matches on
  `EntityKind` (`state.rs`, `accounts.rs`, `views/transfer.rs`) need a
  `Network` arm. (Its own `host_status.rs` copy should skip hosts with a
  network, like the core's `Skip::Network`.)
- **Host and group editors must start from the loaded `HostSettings`**
  (copy it) so `network_id` is kept even before they show it (Android
  already does `s0.copy(…)`).
- Recommended: replace parsing of "the server responded 409 (code): …"
  (AccountDeletion on Android and iOS) with `apiError`.
- Show networks only when the account's `features.networks` is true.

### 8.1 The UI in the apps (phase 1b)

Done in the web (`web/site/js/pages/app/networks.js`), the desktop
(`src/networks.rs`, `src/views/networks.rs`), Android
(`data/Networks.kt`, `NetworksApi.kt`, `NetworkBook.kt`,
`ui/NetworksScreen.kt`, `ui/NetworkUi.kt`) and iOS (`Model/Networks.swift`,
`Model/NetworkBook.swift`, `Views/NetworksView.swift`,
`Views/NetworkViews.swift`), with the same rules. The mobile apps edit a
WireGuard network as `.conf` text like the desktop (the configuration
without keys, "keep the key" unless a `PrivateKey` line is added or a new
key generated), open `.conf` files with the system's picker (Android SAF,
iOS `fileImporter`) and read the errors' details with `apiError`
(`ApiErrors` on Android, `networkErrorText` on iOS) in every error text.

- **Features can be stale:** re-read `/info` when an account starts and
  when the Networks screen opens (the desktop does both).
- **Connecting from the device:** `Workspace::connect_item` and
  `open_telnet_item` already use the relay; any other path that runs the SSH
  engine itself (the desktop's local AI) needs
  `Workspace::network_dialer(scope, &resolved)`. Relay failures arrive as
  `SshError::Network { code }` (FFI: `NetworkUnavailable` + `apiError`):
  map the code to a text. Local reachability probes skip network hosts.
- **Proxy:** with a network the proxy is ignored; the editors say so.

- **Where.** Account → Networks, only when the account's server has
  `features.networks` (never for This device). Host and group editors: a
  "Network" picker. Where host status or latency is shown and in the
  terminal bar: "via Office · 23 ms". The vault page of the web also lists
  groups so their network can be chosen there.
- **List.** `GET /networks` (every vault you can see; `vault_id`,
  `has_secret`, `secret_hidden`, `wireguard.public_key`). State from
  `GET /networks/{id}/status` per network (it never brings it up): `up` with
  `last_handshake_at` = "Connected"; `up` without a handshake (WireGuard) =
  "Waiting for the peer" (check the endpoint and that the peer has the
  server's key); `starting`, `needs_auth`, `error` (+ `message`), `down` =
  "comes up when a host needs it". A status that fails (netd down) = state
  unknown, not an error page.
- **Test** = `POST /networks/{id}/up`, then poll `status` about once a second
  for a few seconds until `last_handshake_at` appears (wireguard-go only
  handshakes when there is traffic or a `persistent_keepalive`: the form
  suggests 25). Editors only; Use-only members see the list and the state.
- **Add / edit (WireGuard).** Two ways:
  1. **Paste or open a `.conf`** (wg-quick): `[Interface]` `Address`
     (repeatable, comma lists), `DNS` (IPs and search domains), `MTU`,
     `PrivateKey`; each `[Peer]` `PublicKey`, `Endpoint` (`host:port`,
     `[v6]:port`), `AllowedIPs` (repeatable), `PersistentKeepalive` (`off` =
     none), `PresharedKey`. `#` starts a comment; keys are case-insensitive;
     the value is everything after the first `=` (base64 keys end in `=`).
     Other keys (`ListenPort`, `PostUp`, `Table`...) are ignored and listed.
     Termoak keeps **one** preshared key for the network (applied to every
     peer): different ones per peer are an error. The parsed values fill
     the form; the secret is `{private_key, preshared_key?}`.
  2. **Generate a key on the server**: create the network without a private
     key (secret only with a preshared key, if any), then
     `POST /networks/{id}/wireguard/key` (`{replace: true}` when it has one:
     otherwise `409 key_exists`). The server keeps the private key (and an
     existing preshared key) and answers `{public_key, network}`: show it
     with a copy button and a `[Peer]` block for the other side
     (`PublicKey = …`, `AllowedIPs = <the network's addresses>`).
  Validation before saving: addresses required; keys are 32 bytes of base64
  (`^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$`); each peer needs a public key
  and allowed IPs; at least one peer needs an endpoint (the server is the
  side that connects). Editing: "keep the key" (no `secret` in the PUT),
  "paste a new one" (the `secret` object replaces both keys) or "generate a
  new one". The private key is **never shown again** (the web never reveals
  secrets; apps follow their reveal rules for `/networks/{id}/secret`).
  Send the whole network object as read on PUT. Tailscale and ZeroTier:
  shown as "coming soon", never created.
- **Plan.** `GET /me/plan` → `usage.networks` of `plan.limits.max_networks`
  (it counts the networks billed to you: your vaults and the team vaults
  of teams you own). Creating over it: `403 plan_limit` with `limit:
  "max_networks"`, `max`.
- **Picker.** Options: the inherited value for `null` ("Same as group
  “Servers” (via Office)", walking `group_id` / `parent_id` for the nearest
  group with `settings.network_id`; else "Direct"), then the networks **of
  the same vault**; a `network_id` that is not there = "Missing network"
  (`network_not_found` when connecting). Show the chosen network's state
  next to it. Save with the whole host or group (`settings.network_id`,
  `null` = inherit/direct). Hosts on This device have no picker.
- **Host test.** `POST /hosts/{id}/test` → `network: {id, name, kind}` and
  `latency_ms` measured through it: "via Office · 23 ms". Failures are
  `ok: false` with `error_code` (`host_key_unknown` → offer "trust and test"
  with `?trust=true`, `host_key_changed`, `auth_failed`, `timeout`,
  `network_unavailable`, `network_dial_failed`, `network_not_found`,
  `telnet_not_supported`, `connect_failed`).
- **Import hosts.** `GET /networks/{id}/peers` (Editor; it brings the
  network up). WireGuard answers its configured peers: `name` = endpoint,
  `addresses` = allowed IPs. A single address (`/32`, `/128`) → "Add host
  10.9.0.1"; a subnet → "Add a host in 10.9.0.0/24" with the address typed.
  `POST /hosts {label, address, settings: {port, username, network_id},
  vault_id: <the network's vault>}`.
- **Errors** (structured, `apiError` in the FFI, `ApiError.data.error` in
  the web): `network_unavailable` (netd missing; `netd_code:
  unsupported_kind` = this server cannot join that kind),
  `network_not_found`, `network_dial_failed` with `netd_code`
  (`dial_failed`, `timeout`, `needs_auth`, `network_error`, `limit`,
  `invalid`), `plan_limit` (`max_networks`), `key_exists`, `not_wireguard`,
  `relay_limit` (`max`), `cross_vault_reference`.
- **Audit** (vault activity): `network.up`, `network.down`,
  `network.key_generated` (`replaced`), `relay.open` / `relay.close`
  (target `host:<id>`, `network`, bytes).

#### Tailscale/Headscale (phase 2b: to do in the web, desktop, Android and iOS)

The server side is done (phase 2a, §6.6); the apps still show Tailscale as
"coming soon". What each app needs:

- **When.** Offer Tailscale only when `/info` → `features.network_kinds`
  contains `"tailscale"` (re-read `/info` as for `features.networks`). A
  server without the field (0.7.0-next.2) means `["wireguard"]`. Without
  it, keep "coming soon" (a Tailscale network synced from elsewhere is
  listed with "this server cannot join Tailscale networks").
- **Core.** Bump to core v0.7.0-next.3: `TailscaleSettings {control_url,
  hostname, tags, ephemeral}` and `NetworkSecrets.auth_key`;
  `save_network` validates (control URL, hostname, tags, key shape:
  `TermoakError.Invalid`). The web mirrors the rules (§3): control URL
  `^https?://` with a host and no `user@`, `?` or `#`; hostname
  `^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`; tags
  `^tag:[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`, at most 20; key printable ASCII
  without spaces. The server answers `400` with the reason otherwise.
- **Add / edit form** (kind Tailscale):
  - Name.
  - Control server: **Tailscale** (default, `control_url: null`) or
    **Headscale** (URL field, `control_url`).
  - Auth key (password field, secret `auth_key`, optional). Hint: "A
    reusable, ephemeral key, tagged (e.g. tag:termoak). Tailscale: Admin
    console → Settings → Keys (Reusable, Ephemeral, Tags); an OAuth client
    secret (tskey-client-…) works too. Headscale: `headscale preauthkeys
    create --user <id> --reusable --ephemeral --tags tag:termoak`. Without a
    key you log the server in from a link." Never shown again after saving;
    editing: "keep the key" (no `secret` in the PUT), "new key"
    (`secret: {auth_key}`), "remove the key" (`secret: {}`).
  - Advanced: Hostname (placeholder "automatic: termoak-xxxxxxxx", the last
    8 hex digits of the id once it exists); Tags (list, empty by default;
    hint: "Empty = the key's tags. Headscale only accepts the key's tags.");
    "Remove the server's node from the tailnet when it stops (ephemeral)":
    send `ephemeral: null` unless the user changes it (default on with a
    key, off without one: say so next to the switch). Send the whole
    network object as read on PUT (`ephemeral` included).
- **List and detail.** `GET /networks/{id}/status` as for WireGuard, but a
  Tailscale network has no public key or handshake: `up` is "Connected"
  whatever `last_handshake_at`. Strings (en / es):
  - `down`: "Comes up when a host needs it" / "Se levanta cuando un host la
    necesita".
  - `starting`: "Connecting to the tailnet…" / "Conectando a la tailnet…".
  - `up`: "Connected · <node.addresses[0]> · <peer_count> devices" /
    "Conectada · … · N dispositivos"; detail: control server (`control_url`,
    "Tailscale" for the default), tailnet (`tailnet`), MagicDNS
    (`magic_dns_suffix`), the server's node (`node.name`, `node.dns_name`,
    `node.addresses`, `node.node_id`), "ephemeral" (`ephemeral`).
  - `needs_auth` + `auth: "login"`: "Log the server in" / "Inicia sesión
    del servidor"; Editors get `node.auth_url` as a button "Open the login
    page" / "Abrir la página de inicio de sesión" ("Sign in to the tailnet
    there; with Headscale an admin approves it with `headscale auth
    register`."), then poll `status` every 2 s until `up` (stop after a few
    minutes or when the screen closes). Use-only members (no `auth_url`):
    "Waiting for an Editor to log the server in" / "Esperando a que un
    editor inicie la sesión del servidor".
  - `needs_auth` + `auth: "approval"`: "Waiting for approval: approve
    <node.name> in the tailnet's admin console (Machines)" / "Esperando
    aprobación: aprueba <node.name> en la consola de la tailnet (Machines)".
  - `error`: `message` (e.g. "the control server refused the auth key:
    …") with "Use another key"; `last_error` in a details line.
- **Test** = `POST /networks/{id}/up` (it already waits up to 10 s for the
  node to settle), then poll `status` about once a second while
  `starting`, up to ~30 s. Editors only.
- **Import hosts.** `GET /networks/{id}/peers` (Editor; it needs the node
  up: a `502 network_dial_failed` with `netd_code: needs_auth` means "log
  the server in first"). Each device: `name`, `dns_name`, `addresses`,
  `os`, `online` (dot) and `last_seen`, `tags` (chips), `routes`. Actions:
  "Add host" → `POST /hosts {label: name, address: dns_name (the MagicDNS
  name; or addresses[0]), settings: {port: 22, network_id}, vault_id: <the
  network's vault>}`; each of `routes` → "Add a host in 192.168.10.0/24"
  with the address typed (as WireGuard subnets). Mark devices already
  imported (a host of that network with that name or address). Only the
  devices the tailnet's ACLs let the server's node see are listed.
- **Host editor.** Same picker; for a Tailscale network the address hint
  says "a MagicDNS name (nas or nas.tail1234.ts.net) or a 100.x address".
- **Errors** (structured): `network_dial_failed` with `netd_code`:
  `needs_auth` + `auth: login` → "The server must be logged in to
  <network> (see Networks)"; `needs_auth` + `auth: approval` → "The
  server's node in <network> waits for approval"; `network_error` → "<network>
  could not join the tailnet: <message>"; `dial_failed` → the message (e.g.
  "outside the tailnet": only devices of the tailnet and the subnets they
  route can be reached; "there is no device named …": the ACLs may hide
  it); `timeout` → "still connecting to the tailnet, try again";
  `limit` → "the server runs too many Tailscale networks right now".
  `network_unavailable` with `netd_code: unsupported_kind` → "this server
  cannot join Tailscale networks". Saving: `400` with the reason.
- **Delete.** As WireGuard; the server makes netd log the node out (a
  persistent one too).
- **Audit:** the same entries (`network.up`, `network.down`,
  `relay.open`/`relay.close` with `kind: "tailscale"`).

## 9. Tests

- Core: `store::vault_tests::{networks_*, old_cores_editing_a_host_keep_its_network,
  first_hop_network_*}`, `termoak-ssh` `net::tests` and
  `tests/openssh.rs::session_through_a_network_dialer` (real sshd),
  `termoak-client` `net_relay::tests` (mock relay) and
  `workspace::tests::network_hosts_never_connect_directly_from_the_device`,
  FFI `error::tests::api_errors_keep_status_code_and_details` and
  `tests_api::private_networks_live_in_accounts_and_hosts_keep_their_network`.
- Server: `tests/networks.rs` with a **fake netd** (`tests/common/netd.rs`,
  tests only: it implements the protocol and dials directly): sync/compat,
  no-netd errors, `max_networks` (personal, shared, team, transfers), relay
  (bytes, audit, authorization: another user, Use-only Strict, no network,
  dial failure, per-user limit), server session, `/test`, `/exec` and an
  app (the FFI engine) over the relay against a real sshd;
  `wireguard_keys_and_netd_follow_the_vaults` (key generation, public keys
  of pasted and pushed keys, `down` on change/delete/vault deletion, not on
  rename, the host test's network);
  `tests/holder.rs::the_holder_dials_network_hosts_through_netd`.
- netd (Go, `go test -tags tailscale ./...`, also with `-race`: 31 tests,
  16 of them since phase 2a): two netstack peers talking
  in process: dial through the tunnel (4 MiB echoed, handshake and
  counters), outside the allowed IPs, refused port, DNS inside the network
  with search domains, invalid configurations (never echoing the key),
  RFC 7748 keys; the manager (revisions, failed starts, limits, LRU
  eviction, idle reaping) with a fake backend; the protocol over a real
  socket (every op, malformed requests, `unsupported_kind`, socket mode and
  peer access); two networks with the same addresses reaching their own
  site, half-close, `down` closing connections, a silent peer timing out;
  nodes that settle in the background (up and dial wait, `needs_auth` with
  its reason on the protocol line), the per-kind limit and `down` with
  `forget`; Tailscale against an in-process control server (§6.6).
- Server (phase 2a): `tests/networks.rs::tailscale_networks_are_validated_and_report_logins_and_tailnets`
  (`network_kinds`, REST and sync validation without echoing the key,
  status and peers fields, `auth_url` only for Editors, `needs_auth` with
  `auth` on the relay and the host test, `forget` on delete); core
  `store::vault_tests::{tailscale_settings_are_validated,
  tailscale_networks_are_checked_on_save_and_push_and_old_cores_keep_ephemeral}`
  and the FFI round trip.
- Core: `transfer::tests::without_networks_keeps_networks_and_detaches_hosts`
  and the FFI test moving a host to This device.
- QA (`qa`, `./run.sh networks`): a real netd and `termoak-wgpeer` (a
  WireGuard peer in user space whose port 22 forwards to the sshd
  container; no TUN needed): generated key, `up`, host test, a server
  session, SFTP of 50 MB with OpenSSH over the relay (checksums, audit
  bytes), never dialing directly, isolation between two users (and two
  networks with the same addresses), idle shutdown and coming back,
  netd stopped → `network_unavailable` and `features.networks` false;
  the web (phase 1b): Account → Networks with a `.conf` and a generated
  key (handshake through Test), peers → a host, the vault page's picker
  and host test, deleting, and the tab hidden without netd.
- QA (`./run.sh tailscale`, phase 2a): Headscale 0.29.5 in Docker with its
  embedded DERP and STUN on 127.0.0.1 (`TS_DEBUG_USE_DERP_HTTP=1` for netd
  and the test nodes: no internet), sites made with `termoak-tsnode`
  (`ssh-site` forwarding port 22 to the sshd container, `other-site` an
  echo in another ACL slice): a tagged ephemeral pre-auth key → `up`,
  peers, host test by MagicDNS name and 100.x address, a server session,
  SFTP of 32 MB over the relay with checksums, nothing outside the tailnet;
  isolation between users and between ACL slices; no key → the login URL,
  registered → up, deleted → logged out and its state removed; a refused
  key; bad settings → 400; idle, `down`, a netd restart and deleting never
  leave nodes in Headscale.

- Apps (phase 1b): the desktop's `networks::tests` (+ the opt-in
  `live_relay_through_a_wireguard_network`); Android's `NetworksTest`
  (`.conf`, states, peers, inheritance and picker, error texts, REST calls),
  `NetworksScreenshotTest` (Robolectric) and the opt-in `LiveNetworksTest`
  (the engine built for the computer, through JNA, against a real server
  and WireGuard site: key generation and `key_exists`, Test with handshake,
  sync, SSH through the relay, the server's host test, peers); iOS's
  `NetworksTests` (XCTest, run on the Mac).

## 10. Phases

Done in phase 1a (2026-10-21):

1. `termoak-netd` in Go with WireGuard (wireguard-go + netstack), the
   systemd unit (`deploy/termoak-netd.service`), socket permissions, idle
   shutdown, limits, per-network logs and counters; the "with networks"
   bundle (`release-local.sh build server`) and `Dockerfile.netd`; QA with
   a WireGuard peer in user space.
2. Server: `down` when a network is deleted (also its vault, team or
   account) or its revision changes; "generate WireGuard key"; the public
   key in network views; the host test's network and latency.
3. Core 0.7.0-next.2: transfers to This device detach `network_id`.

Done in phase 1b, part 1 (2026-10-22): the web and the desktop (§8.1).
Done in phase 1b, part 2 (2026-10-22): Android and iOS (§8.1) on core
v0.7.0-next.2 (Android checked against a real server and WireGuard site
through the engine: `LiveNetworksTest`, opt-in; iOS not compiled yet).

Done in phase 2a (2026-10-22): Tailscale/Headscale in netd (§6.6), core
v0.7.0-next.3 (`ephemeral`, validation), server 0.7.0-next.3
(`network_kinds`, the Tailscale status and peers, `forget`), QA with
Headscale; deployed on next.termoak.com.

Left for later:

1. Phase 2b: the Tailscale UI in the web, desktop, Android and iOS (§8.1,
   "Tailscale/Headscale").
2. Relay/session metrics per network in the server (netd has them per
   network already).
3. Optional: give up on a key the control server refuses (now the node
   retries with tsnet's backoff until the network goes idle); Tailscale
   device approval checked against a real tailnet (only the test control
   server covers `needs_auth`/`approval`).
