# Private networks (Termoak 0.7)

Status: **phase 0 done** (core + server groundwork, 2026-10-21). Phase 1
builds `termoak-netd` (Go) and the UI in the apps and the web.

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
  detaches it).

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
  `GET /hosts/{id}/relay` (OpenAPI tag `networks`; `docs/API.md`).
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
  with mode `0660` (owner netd, group `termoak`) or `0600` if both run as
  the same user; it should check the peer uid (`SO_PEERCRED`) like the
  session holder.
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

`kinds`: what this build can join. Used as the health check (every 30 s).

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
  "rx_bytes": 0, "tx_bytes": 0
}
```

`up` may answer before the node is fully up (`starting`, `needs_auth`).

### 6.3 `peers`

```json
→ {"v": 1, "op": "peers", "network": NetworkSpec}
← {"ok": true, "peers": [{"name": "nas", "dns_name": "nas.tail1234.ts.net",
                          "addresses": ["100.64.0.7"], "os": "linux",
                          "online": true, "last_seen": 1760000000000}]}
```

Brings the network up if needed. WireGuard answers its configured peers
(no discovery). For "import hosts".

### 6.4 `dial`

```json
→ {"v": 1, "op": "dial", "network": NetworkSpec, "host": "10.9.0.5", "port": 22, "timeout_ms": 20000}
← {"ok": true, "remote": "10.9.0.5:22"}
   …then raw bytes in both directions on the same connection…
```

- netd brings the network up if needed (waiting up to `timeout_ms` for
  `up`), resolves `host` **inside the network** (MagicDNS / the WireGuard
  `dns`), and opens TCP to `host:port` through its user-space stack.
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
  `tests/holder.rs::the_holder_dials_network_hosts_through_netd`.

## 10. Phase 1 (next)

1. `termoak-netd` in Go (wireguard-go + netstack, tsnet, libzt behind a
   build tag), systemd unit, socket permissions, idle shutdown, limits,
   metrics; QA with a WireGuard peer and Headscale in Docker.
2. Server: tell netd `down` when a network is deleted or changes vault;
   "generate WireGuard key" (server creates the key, shows the public key);
   network status/latency in host status; import hosts from `peers`;
   relay/session metrics per network.
3. Apps and web: Account → Networks (add, test, state, node), the "Network"
   picker in host and group editors, "via <network> · 23 ms" in the
   terminal bar, import hosts; hide everything without `features.networks`.
4. Transfers to This device should detach `network_id` (a network cannot
   live there); today the planner copies it as a dependency.
5. Desktop: adopt core 0.7 (see §8).
