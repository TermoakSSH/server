# Private networks (Termoak 0.7)

Status: **phase 0 done** (core + server groundwork, 2026-10-21); **phase 1a
done** (2026-10-21): `termoak-netd` with WireGuard (`server/netd/`, Go), the
server's WireGuard keys, netd following the vaults, QA. Next: the UI in the
apps and the web (phase 1b), then Tailscale/Headscale (phase 2).

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
  "tailscale": {"control_url": null, "hostname": null, "tags": ["tag:termoak"]},
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
  key, Tailscale `control_url` must be http(s), ZeroTier id is 16 hex.

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
   default), `network_id` is never omitted.
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
  last `hello` (checked at start and every 30 s, and by every request).
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
  and the secret). Whatever is missed goes down when idle.
- **Host test** (`POST /hosts/{id}/test`) dials through the network and
  answers `network: {id, name, kind}` with `latency_ms` measured through
  it (the "via Office · 23 ms" of the apps).
- Errors: `network_unavailable` 503, `network_not_found` 404,
  `network_dial_failed` 502 (`netd_code`), `not_in_network` 422,
  `relay_limit` 429.

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
| `needs_auth` | the node waits for authorization (Tailscale login URL, ZeroTier member not authorized) | 502 `network_dial_failed` |
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
- Tailscale defaults: hostname `termoak-<first 8 of id>`, tags
  `["tag:termoak"]`, ephemeral node; state directory per network id.
- `secret` must never be logged.

### 6.1 `hello`

```json
→ {"v": 1, "op": "hello"}
← {"ok": true, "v": 1, "version": "0.1.0", "kinds": ["wireguard", "tailscale", "zerotier"]}
```

`kinds`: what this build can join (`["wireguard"]` since phase 1a;
Tailscale and ZeroTier answer `unsupported_kind` until their backends are
built in). Used as the health check (every 30 s).

### 6.2 `up` / `down` / `status`

```json
→ {"v": 1, "op": "up", "network": NetworkSpec}
← {"ok": true, "status": Status}

→ {"v": 1, "op": "down", "network_id": "…"}
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
  "dials": 0, "dials_failed": 0         // since it came up
}
```

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
last handshake (online under 3 minutes). For "import hosts".

### 6.4 `dial`

```json
→ {"v": 1, "op": "dial", "network": NetworkSpec, "host": "10.9.0.5", "port": 22, "timeout_ms": 20000}
← {"ok": true, "remote": "10.9.0.5:22"}
   …then raw bytes in both directions on the same connection…
```

- netd brings the network up if needed (waiting up to `timeout_ms` for
  `up`), resolves `host` **inside the network** (MagicDNS / the WireGuard
  `dns`), and opens TCP to `host:port` through its user-space stack.
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
  cmd/termoak-wgpeer/   test tool, never shipped: a WireGuard peer in user space (QA)
  internal/proto/       the protocol types and codes (Spec never prints its secret)
  internal/netd/        Manager (nodes, limits, idle reaper), Server (socket, SO_PEERCRED,
                        one request per connection, the byte pipe), Backend/Node interfaces
  internal/wg/          WireGuard: wireguard-go + gVisor netstack, one device and stack per network
  internal/wgtest/      a WireGuard "site" for tests (echo, forward, DNS in its netstack)
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
  always built in; Tailscale (`tsnet`, phase 2) and ZeroTier (libzt, phase
  6) will be files behind build tags (`//go:build tailscale`) that register
  theirs. Without them those kinds answer `unsupported_kind` (→ the
  server's `network_unavailable`) and `hello` does not list them.
- **Shutdown** (SIGTERM/SIGINT): stops accepting, takes every network
  down, removes the socket.

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
  `TailscaleSettings`, `ZerotierSettings`, `NetworkSecrets`),
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
- netd (Go, `go test ./...`, also with `-race`): two netstack peers talking
  in process: dial through the tunnel (4 MiB echoed, handshake and
  counters), outside the allowed IPs, refused port, DNS inside the network
  with search domains, invalid configurations (never echoing the key),
  RFC 7748 keys; the manager (revisions, failed starts, limits, LRU
  eviction, idle reaping) with a fake backend; the protocol over a real
  socket (every op, malformed requests, `unsupported_kind`, socket mode and
  peer access); two networks with the same addresses reaching their own
  site, half-close, `down` closing connections, a silent peer timing out.
- Core: `transfer::tests::without_networks_keeps_networks_and_detaches_hosts`
  and the FFI test moving a host to This device.
- QA (`qa`, `./run.sh networks`): a real netd and `termoak-wgpeer` (a
  WireGuard peer in user space whose port 22 forwards to the sshd
  container; no TUN needed): generated key, `up`, host test, a server
  session, SFTP of 50 MB with OpenSSH over the relay (checksums, audit
  bytes), never dialing directly, isolation between two users (and two
  networks with the same addresses), idle shutdown and coming back,
  netd stopped → `network_unavailable` and `features.networks` false.

## 10. Phase 1

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

Left for phase 1b (UI) and later:

1. Apps and web: Account → Networks (add with a pasted `.conf` or a
   generated key, the server's public key to copy, test with `up` and the
   handshake, state), the "Network" picker in host and group editors, "via
   <network> · 23 ms" in the terminal bar (host test), import hosts from
   `peers`; hide everything without `features.networks`.
2. Desktop: adopt core 0.7 (see §8).
3. Relay/session metrics per network in the server (netd has them per
   network already).
4. Phase 2: Tailscale/Headscale (`tsnet` backend behind a build tag,
   `needs_auth` with the login URL, state directory per network, MagicDNS,
   `peers` for import), Headscale in Docker for QA.
