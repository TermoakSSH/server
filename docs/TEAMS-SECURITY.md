# Teams security: SSH CA, temporary access, policies and fine roles (Termoak 0.7, phase 4b)

Status: **phase 4d** (2026-10-24): design (this file, identical copy in
`server/docs/TEAMS-SECURITY.md`), core v0.7.0-next.9, server 0.7.0-next.8
(staging next.termoak.com, schema v13), QA suite `teams-security`; web and
desktop UIs done (4c, §13.1); Android and iOS done (4d, §13.2).
Plan: `PLAN-0.7.md` §3 items 3, 4 and 6. Builds on `VAULTS-MULTISERVER.md`
(vaults, roles, Strict, just-in-time credentials), `PUSH.md` (approvals by
push) and `SSH-PRO.md` (security keys; certificates already work with them).

## 0. Summary

- **SSH certificate authority per team** (and optionally per personal
  account), generated and held by the server (Ed25519 by default), sealed
  with `master.key`. Hosts trust it with one `sshd_config` line
  (`TrustedUserCAKeys`). Members get **short-lived user certificates**
  (minutes to hours) for their own keys, an ephemeral key made by the app,
  or, on the server, for server sessions/SFTP/exec/AI. Rotation publishes the
  old and the new CA during an overlap. Removing a member stops issuance at
  once; a KRL (`RevokedKeys`) can cut certificates that are still valid.
- **Access policies** per host, group or whole vault: `direct` or
  `approval` ("access to Production for 1 h, reason" → an approver says yes →
  a time window). The window gates everything the server serves for those
  hosts: certificates, just-in-time credentials, server sessions, SFTP, exec
  and the AI. Requests are pushed to approvers (`access_request`) and
  withdrawn when decided (`resolved`).
- **Team policies**: require 2FA (grace period, compliance list), mandatory
  session recording, forbid revealing/exporting secrets to Editors, AI
  allowed or not and its approval level, private networks allowed or not.
  Enforced by the server; exposed to clients (`Vault.policy`, FFI) so apps
  hide what they cannot do.
- **Fine roles**: `connect_only` < `use_only` ("Use") < `editor` ("Edit") <
  `manager` ("Admin", now also grantable). `connect_only` never gets secrets,
  not even just in time: it connects through the server or with team
  certificates. Old apps see `connect_only` as `use_only`.

## 1. Goals and non-goals

Goals:
- Stop distributing public keys to hosts: hosts trust the team CA; access
  follows team membership and policies, and ends by itself (short TTLs).
- Temporary, audited, approved access to sensitive hosts.
- One place (the team) to set security rules, enforced where secrets and
  certificates are served (the server), visible to every client.
- Nothing breaks for released apps or for old cores syncing with the new
  server; new things are hidden from clients that do not declare them.

Non-goals (this phase):
- Host certificates (`@cert-authority` in known_hosts): designed in §4.10,
  implementation deferred.
- Device-side enforcement against a modified client: a member who already
  holds a secret (Editor with secrets on the device) can always use it
  outside Termoak. Real enforcement = certificates + no static secrets on
  devices (Connect only, or Forbid reveal). §11.
- SSO/OIDC and extended audit export (phase 5).

## 2. Concepts

| Term | Meaning |
|---|---|
| CA owner | The team of a team vault; the owner user of a personal or shared vault. A host's certificate comes from the CA owner of the host's vault |
| Principal | Name in a certificate that sshd matches against the login user (default) or an `AuthorizedPrincipalsFile` |
| Access policy | Rules for a target (host, group or vault): mode, approvers, max window, certificate options, recording |
| Grant | An approved access request: a time window on a target for one member |
| Team policy | Team-wide rules (2FA, reveal, AI, networks, recording, CA defaults) |
| Effective vault policy | What a team policy means for one member in one vault (`Vault.policy`), computed by the server |

## 3. Fine roles in vaults

| Role (wire) | UI name | Secrets | Local connections | Server use | Edit | Manage |
|---|---|---|---|---|---|---|
| `connect_only` | Connect only | never | only with team certificates (ephemeral key) | yes | no | no |
| `use_only` | Use | never in sync; just in time unless Strict | JIT credentials, or certificates | yes | no | no |
| `editor` | Edit | yes (unless *Forbid reveal*) | yes | yes | yes | no |
| `manager` | Admin | yes | yes | yes | yes | members, settings, policies |

- Rank order (never compare as text): `unknown` < `connect_only` <
  `use_only` < `editor` < `manager`. `VaultRole::can_use()` is now
  `>= connect_only`; places that meant "any access" require `ConnectOnly`.
- `manager` is now grantable explicitly (`POST /vaults/{id}/members {role:
  "manager"}`); implicit managers stay (owner, team owner/admin). An explicit
  Admin manages members, settings and access policies but **cannot delete**
  a team or shared vault (only implicit managers can).
- `connect_only`: `POST /hosts/{id}/credentials` → 403 `connect_only`.
  Certificates for an ephemeral key (with proof of possession) are allowed;
  certificates for a vault key are not (they could not use it anyway).
- **Strict vaults** stay: a `use_only` member in a Strict vault behaves like
  `connect_only` (no JIT). No data migration is needed: existing grants keep
  their exact meaning; the switch is still `settings.use_only_local`.
- **Compatibility**: a client that does not send the feature `roles_v2`
  (§10) sees `connect_only` as `use_only` everywhere the server sends roles
  (`GET /vaults`, `GET /vaults/{id}`, members, sync v2 vault list, events
  `vault/access`). Such a client then tries JIT and gets `connect_only`
  (a clear error text); server sessions work. `manager` grants are known by
  every core.

## 4. Team SSH certificate authority

### 4.1 Storage

- Table `ssh_cas` (§8). One **active** user CA per CA owner, plus
  **retiring** ones during a rotation overlap. Private key: the OpenSSH
  private key sealed with the master key (XChaCha20-Poly1305, AAD
  `termoak:ssh-ca:<ca id>`), never returned by any API, never logged, never
  in sync. Back-up = the database plus `master.key` (as for every secret).
- Algorithms: `ssh-ed25519` (default) or `ecdsa-sha2-nistp256` (older
  sshd/RHEL 7 era hosts). RSA CAs are not offered.
- The CA private key lives only in the server process (signing is local;
  the session holder never sees it).

### 4.2 Lifecycle and rotation

- Create: `POST /teams/{id}/ca {algorithm?}` (team owner/admin) or
  `POST /me/ca` (personal). 409 `ca_exists` if one is active.
- Rotate: `POST …/ca/rotate {overlap_hours?: 1–720, default 24}`: a new CA
  becomes active and signs from now on; the old one becomes `retiring` with
  `retire_at = now + overlap`. During the overlap **both public keys are
  published** (the keys file, the install script, `GET …/ca`), so hosts that
  refresh their keys file keep accepting old certificates (which expire
  anyway within the max TTL). A background job marks it `retired` after
  `retire_at`; retired keys are no longer published.
- Disable: `DELETE …/ca?confirm=<team name|"personal">`: every CA of the
  owner is retired at once, issuance stops (`ca_not_configured`).

### 4.3 Export: keys file, sshd_config, install script

`GET …/ca` returns:

```json
{"ca": {"id":"…","algorithm":"ssh-ed25519","public_key":"ssh-ed25519 AAAA… termoak-ca team=Ops 2026-10-24","fingerprint":"SHA256:…","status":"active","created_at":…},
 "previous": [{…, "status":"retiring","retire_at":…}],
 "keys_file": "ssh-ed25519 AAAA… termoak-ca …\nssh-ed25519 AAAA… (retiring)\n",
 "sshd_config": ["TrustedUserCAKeys /etc/ssh/termoak_user_ca.pub"],
 "sshd_config_optional": ["RevokedKeys /etc/ssh/termoak_revoked.krl",
                          "AuthorizedPrincipalsFile /etc/ssh/termoak_principals/%u"],
 "urls": {"keys": "https://…/api/v1/ssh-ca/<owner>/keys",
          "krl": "https://…/api/v1/ssh-ca/<owner>/krl",
          "install": "https://…/api/v1/teams/<id>/ca/install.sh"},
 "policy": {"default_ttl_minutes":60,"max_ttl_minutes":480,"principals":["{login}"],…}}
```

- Public, unauthenticated: `GET /api/v1/ssh-ca/{owner_id}/keys` (text, the
  `TrustedUserCAKeys` file: active + retiring) and `GET
  /api/v1/ssh-ca/{owner_id}/krl` (binary KRL). Public keys and revoked
  serials are not secret; hosts can refresh them with cron.
- `GET …/ca/install.sh?krl=1&principals=1&refresh=1` (authenticated
  manager; the apps show it for copy-paste): a POSIX `sh` script, run as
  root on the host, that writes `/etc/ssh/termoak_user_ca.pub`, adds the
  `TrustedUserCAKeys` line (a drop-in `/etc/ssh/sshd_config.d/termoak.conf`
  when sshd_config includes that directory, else appended once to
  `/etc/ssh/sshd_config`), optionally `RevokedKeys` with the current KRL,
  `AuthorizedPrincipalsFile` (creates the directory; the admin fills
  `%u` files) and a cron job (`/etc/cron.d/termoak-ca`, every 15 min) that
  refreshes the keys and KRL from the public URLs; validates with `sshd -t`
  and restores the backup on failure; reloads sshd (systemctl, service or
  SIGHUP). Idempotent. Contains only public data.

### 4.4 Issuing (who, for what key)

`POST /api/v1/certificates`:

```json
{"host_id":"…",                      // required: principals and policy come from it
 "key_id":"…",                       // a vault key, or…
 "public_key":"ssh-ed25519 AAAA…",   // …any public key with a proof of possession
 "proof":"-----BEGIN SSH SIGNATURE-----…",
 "timestamp": 1792860000000,
 "ttl_minutes": 30}                  // optional, capped
→ {"certificate":"ssh-ed25519-cert-v01@openssh.com AAAA…","serial":42,
   "key_id":"termoak:ana@example.com:<user id>:<request id|direct>:42",
   "principals":["deploy"],"valid_after":…,"valid_before":…,
   "ca_fingerprint":"SHA256:…","request_id":null,"extensions":[…],
   "record_required":false}
```

Rules, in order:
1. The requester has at least `connect_only` on the host's vault, the vault
   is not hidden by the 2FA policy, and the CA owner of the vault has an
   active CA (`ca_not_configured`).
2. **Key ownership** — never sign for a key the requester does not own:
   - `key_id`: an SSH key entity in the **same vault as the host or the
     requester's personal vault**, which the requester may use locally
     (`SecretUse::Credentials`: Editor+, or Use in a non-Strict vault;
     `connect_only` → `certificate_key_not_owned`), and whose public key
     matches. Security keys (`sk-…`) go this way (no extra touch).
   - otherwise `public_key` + `proof`: an SSHSIG (namespace
     `termoak-cert@termoak.com`, SHA-512) by that key over
     `termoak-cert-request\n<instance_id>\n<user id>\n<key type> <base64>\n<timestamp>`,
     timestamp within ±5 minutes (`certificate_proof_invalid`). The apps use
     it for ephemeral keys and device-only keys.
   - certificate requests for a certificate, a CA key of this server, or a
     revoked key (`ssh_revoked_keys`) are refused.
3. **Access policy** of the host (§5): `direct` → allowed; `approval` →
   needs an active grant of the requester covering the host (or exemption);
   else 403 `access_approval_required` (detail: `target_kind`, `target_id`,
   `policy_id`, `max_minutes`).
4. **Principals** (§4.5), **TTL** (§4.6), **options** (§4.7).
5. Sign, store the row (`ssh_certs`), audit `cert.issue` (serial, key
   fingerprint, principals, validity, host, request, device). Rate limit 60
   per minute per user (`rate_limited`).

### 4.5 Principals mapping

- Templates, from the access policy of the host (`principals`) or else the
  team CA policy (`principals`, default `["{login}"]`):
  - `{login}`: the host's effective username (host, group or identity),
  - `{member}`: the member's principal: `team_members.principal` (set by an
    admin: `PATCH /teams/{id}/members/{user} {principal}`), else the email
    local part lowercased with every char outside `[a-z0-9._-]` → `_`;
    personal CAs: the same from the user's email,
  - `{email}`, `{user_id}`, plus literal names (`prod-admin`, `deploy`).
- Each expanded principal: 1–64 chars of `[A-Za-z0-9._@+-]`; duplicates
  dropped; at most 16; none → 400 `certificate_no_principals`.
- Two typical setups:
  - **Zero config**: hosts only have `TrustedUserCAKeys`; sshd accepts a
    certificate whose principals include the login user, so the default
    `{login}` works. A certificate for `deploy` works on every host that
    trusts the CA and has a `deploy` user; short TTLs and per-host
    issuance keep that small.
  - **Per host group**: the Production group's policy sets
    `principals: ["prod-{member}"]` or `["prod-admin"]` and its hosts list
    allowed principals per login user in `AuthorizedPrincipalsFile
    /etc/ssh/termoak_principals/%u`. Then a certificate obtained for a
    staging host does not open production.

### 4.6 Validity

- `valid_after = now - 5 min` (clock skew), `valid_before = now + ttl`.
- `ttl = min(requested ttl_minutes or policy.cert_ttl_minutes or team
  default_ttl_minutes (60), team max_ttl_minutes (480, at most 1440), the
  end of the grant that allowed it)`. At least 1 minute.
- Serial: unique per server (`ssh_certs.serial`, AUTOINCREMENT); key id
  `termoak:<email>:<user id>:<request id or "direct">:<serial>` (sshd logs it:
  `Accepted publickey … ID termoak:ana@…:…:42 (serial 42) CA ED25519 …`).

### 4.7 Critical options and extensions

- Extensions from the access policy (`extensions`) or the team CA policy,
  default `permit-pty`, `permit-port-forwarding`, `permit-agent-forwarding`
  (the OpenSSH set without `permit-X11-forwarding` and `permit-user-rc`).
  Allowed names: those five; unknown names → 400.
- Critical options: `source-address` (policy `source_address`, a CIDR list
  validated as such) and `force-command` (policy `force_command`, ≤ 1024
  chars). No other critical options are emitted.

### 4.8 Using certificates

**Hosts** get the setting `HostSettings.auth`: `null` (password/key as
always) or `"team_certificate"` ("use the certificate of this vault's team",
inherited from groups like `network_id`; always serialized, and kept when an
old core edits the host: `keep_omitted_fields`). Unknown values from a later
version are kept and ignored.

**Server side** (sessions, the session holder, host tests, `/exec`, SFTP,
network relays, the AI's connection pool): every server resolution goes
through `Store::resolve_in`, which calls the server's **resolve hook**
(`termoak_core::store::ResolveHook`) per hop. For a hop with `auth =
team_certificate` and a CA:
- if the hop has a key (vault key), the server signs a certificate for it
  (it holds the private key: ownership is proven) and sets
  `ResolvedKey.certificate`;
- otherwise it uses an **ephemeral Ed25519 key** kept in memory (per user,
  renewed every 30 minutes) as the hop's key with its certificate; the
  password, if any, is still tried afterwards.
- Certificates are cached per (user, host, key) until 2 minutes before
  expiry; purpose `server` in `ssh_certs`. The session holder needs nothing
  new (the certificate travels in the existing `ResolvedKey.certificate`).

**App side** (`termoak-client`, after resolving a host of an account for a
local connection, also for every jump): for each hop with `auth =
team_certificate`:
1. a JIT credential that already carries a certificate (the server adds one
   to `POST /hosts/{id}/credentials` for team-certificate hosts) is used as is;
2. a usable vault key → `POST /certificates {host_id, key_id}`;
3. a device key → `public_key` + proof;
4. no key (Connect only, or a password-only host) → an **ephemeral Ed25519
   key** generated in memory per account (never written), `public_key` +
   proof, and it becomes the hop's key.
- Cache in memory per (account, host, key fingerprint), reused while more
  than 60 s remain. Nothing is stored on disk.
- `termoak-ssh` tries key + certificate first, then (new) the same key
  without the certificate, then the usual methods.
- Errors reach the apps with their codes: `access_approval_required` (show
  "Request access"), `ca_not_configured`, `team_2fa_required`…

Security keys: `key_id` path, then `authenticate_certificate_with` (3a) —
the touch happens at login as usual.

### 4.9 Revocation

- **Stop issuance immediately**: removing a member from the team, deleting
  the team or the user, downgrading/removing a vault grant, a 2FA policy
  violation, disabling the CA or revoking a grant all take effect on the next
  request (access is checked on every issuance; the server-side certificate
  cache is dropped for that user/vault).
- **Short TTLs end access**: at most `max_ttl_minutes` (default 8 h).
- **Explicit revocation** (managers): `POST …/ca/revoke` with `{serial}`,
  `{user_id}` (every unexpired certificate of that user from this owner's
  CAs) or `{public_key}` (that key forever: no new certificates, and listed
  in the KRL by SHA-256), `reason` optional. Removing a member from a team
  revokes their unexpired certificates of the team's CA automatically.
  Revoking a grant (§5.4) revokes the certificates issued under it.
- **KRL** (`RevokedKeys`): OpenSSH KRL format (`SSHKRL\n\0`, version 1)
  built on demand: per CA (active and retiring) a certificate section with
  the revoked serials that have not expired yet, plus a SHA-256 fingerprint
  section for revoked keys. Served at `…/ca/krl` (managers) and the public
  `ssh-ca/{owner}/krl`. Checked with `ssh-keygen -Q -f` in tests.

### 4.10 Host CA (designed, deferred)

The same machinery can sign **host certificates** so members trust hosts
without TOFU: `ssh_cas.kind = 'host'`, a host enrollment endpoint (`POST
…/ca/host-certificates {host_id, public_key}` by a manager or a one-time
token from the install script), `HostCertificate` lines `@cert-authority
*.example.com ssh-ed25519 …` distributed to clients as a new known-host
source (vault-level), and the verifier accepting a host key whose
certificate chains to a trusted host CA with a matching principal. The
table already has `kind`; nothing else is implemented in 4b (the verifier
and known-hosts model changes touch every app). Deferred to 0.8.

## 5. Access policies and temporary access

### 5.1 Policy model

`access_policies` rows (§8) on a target in a vault (`shared` or `team`;
personal vaults have none), managed by vault managers:

```json
{"mode": "direct" | "approval",
 "approvers": ["<user id>", …],     // empty: the vault's managers
 "max_minutes": 60,                 // longest window a request may ask (1–10080)
 "request_ttl_minutes": 240,        // a pending request expires after this (5–10080)
 "allow_self_approval": false,      // single-person teams
 "require_for_managers": false,     // managers need a request too
 "principals": null,                // certificate principals for these hosts (§4.5)
 "cert_ttl_minutes": null,          // certificate TTL cap for these hosts
 "extensions": null, "source_address": null, "force_command": null,
 "record_sessions": false}          // recording mandatory for these hosts (§6.2)
```

- Unknown `mode` values from a later version are treated as `approval`
  (fail closed).
- **Effective policy of a host**: the host's own policy, else its nearest
  group's (parent chain), else the vault's; one policy applies (no merging);
  `record_sessions` is OR-ed with the team policy. No policy = `direct`.
- `GET /vaults/{id}/access-policies` (any member), `PUT
  /vaults/{id}/access-policies {target_kind, target_id, policy}` (upsert,
  managers), `DELETE /vaults/{id}/access-policies/{id}` (managers). The
  target must be a live host/group of that vault (or the vault itself).
  Policy changes bump the vault (`vault/changed`) and the access cache;
  audit `access_policy.set` / `access_policy.delete`.
- `GET /hosts/{id}/access` (any member) answers what the apps need for one
  host: `{mode, policy (effective, with its target), exempt, grant: {request_id,
  ends_at} | null, pending: {request_id, expires_at} | null, can_request,
  certificate: {available, auth}, record_required, ai_allowed,
  reveal_allowed}`.

### 5.2 Who is exempt, who approves

- Exempt from `approval`: vault managers unless `require_for_managers`.
- Approvers: the listed users that still have access to the vault, or (empty
  list) the vault's managers (implicit and explicit). Server admins are not
  approvers by being admins.
- **No self-approval**: the requester cannot approve their own request
  (`self_approval_forbidden`) unless `allow_self_approval` is set and they
  are an eligible approver (single-person teams); such approvals are audited
  with `self_approved: true`.
- Every decision is an authenticated REST call by the approver (the push
  actions only open the app's confirmation, behind the app lock).

### 5.3 Request lifecycle

```
            ┌──── approve ───> approved ──(window ends)──> approved, inactive (ended)
pending ────┼──── deny ──────> denied            └─ revoke ─> revoked
            ├──── cancel ────> cancelled   (requester; also an approved one before its end)
            └──── (ttl) ─────> expired
```

- `POST /access-requests {host_id | group_id | vault_id, minutes, reason}`:
  the target must have an `approval` policy (else 409
  `access_request_not_needed`), `minutes` ≤ `max_minutes`
  (`access_duration_too_long`), `reason` 1–500 chars. One pending request
  per requester and target (409 `access_request_exists`, detail `id`). Rate
  limit 10 per minute. Requests on a group or vault cover all their hosts.
- `POST /access-requests/{id}/approve {minutes?, reason?}`: an approver
  may shorten the window (never lengthen beyond the request); `starts_at =
  now`, `ends_at = now + minutes`. `…/deny {reason?}`, `…/cancel`
  (requester), `…/revoke {reason?}` (approvers and managers, on an approved
  window that has not ended).
- `GET /access-requests?scope=mine|approvals|vault&status=&vault_id=` and
  `GET /access-requests/{id}`: the requester, the approvers and the vault's
  managers can read a request.
- A background job (every 15 s) expires pending requests, ends windows and
  retires CAs. When a window ends or is revoked: the requester's server
  sessions on hosts no longer allowed are closed (notice reason
  `access_expired` / `access_revoked`), pooled connections of that vault are
  dropped, and certificates issued under a revoked grant are revoked.
  Certificates issued under a grant never outlive it (TTL capped, §4.6).

### 5.4 Enforcement points

The resolve hook (§4.8) checks the effective policy on **every** server
resolution, for the host and every jump:
- `SecretUse::Server` (server sessions, holder, tests, exec, SFTP, network
  relays, AI pool) and `SecretUse::Credentials` (JIT): without an active
  grant (or exemption) → 403 `access_approval_required`.
- `POST /certificates`: the same check (§4.4).
- Apps (UI protection for members who hold secrets): before a local
  connection to a host in a vault whose `policy.access_policies` is true, the
  core asks `GET /hosts/{id}/access` and refuses with
  `access_approval_required` (offline: `access_needs_server`). A modified
  client with synced secrets can skip this: see §11.

### 5.5 Interplay with JIT credentials and Strict vaults

One rule for both: **the window gates what the server hands out**.
- Use-only members in normal vaults: JIT credentials only inside an active
  window for `approval` hosts; with `auth = team_certificate` the JIT key
  comes with a certificate capped to the window.
- Strict vaults / Connect only: no JIT; server-side use (always gated) and
  certificates for ephemeral keys (gated).
- Editors: secrets are synced (unless *Forbid reveal*), so approval is UI
  protection for their local connections; their server-side use and
  certificates are gated. For hard enforcement use team certificates and
  keep static keys out of `authorized_keys`.

### 5.6 Notifications and events

- Push (PUSH.md §10): `access_request` to every eligible approver (generic
  text unless `[push] detailed`), `data.request_id`, collapse
  `access-<id>`, expires with the request; `resolved` (`access-<id>`) to all
  of them when it is approved, denied, cancelled or expires. The requester
  gets the new kind **`access_decided`** (category `info`, channel
  `approvals`, collapse `access-decided-<id>`, `data.request_id`,
  `data.status`) when it is approved, denied, revoked or expires.
- Events WebSocket (to the requester and the approvers):
  `{"type":"access_request","event":"created|approved|denied|cancelled|expired|revoked|ended","request":{AccessRequest}}`.
- Audit (vault audit, `vault_id` set): `access.request`, `access.approve`
  (who, when, minutes, reason, `self_approved`), `access.deny`,
  `access.cancel`, `access.expire`, `access.revoke`, `access.end`,
  `cert.issue` (with `request_id`), `cert.revoke`, `ca.create`,
  `ca.rotate`, `ca.disable`, `access_policy.set|delete`, `team.policy`.

## 6. Team policies

`teams.policy` (JSON, defaults when absent). `GET /teams/{id}/policy`
(members), `PUT /teams/{id}/policy` (owners and admins; full object, missing
fields take defaults). Changes bump the access cache, bump every team
vault's revision (members re-sync their effective `Vault.policy`), send
`{"type":"team","event":"policy","team_id"}` and are audited `team.policy`.

```json
{"require_2fa": false, "grace_days": 7,
 "allow_reveal": true,
 "ai": {"allowed": true, "approval": "default" | "always"},
 "networks_allowed": true,
 "record_sessions": false,
 "ca": {"default_ttl_minutes": 60, "max_ttl_minutes": 480,
        "principals": ["{login}"],
        "extensions": ["permit-pty","permit-port-forwarding","permit-agent-forwarding"],
        "source_address": null},
 "notifications": null}
```

### 6.1 Require 2FA

- Applies to every member (owners and admins included) for the **team's
  vaults** (vaults owned by the team; vaults merely shared with the team are
  governed by their owner).
- Turning it on requires the caller to have 2FA (`policy_requires_2fa`).
  `require_2fa_since` is stamped by the server.
- A member without 2FA has until `max(require_2fa_since, joined_at) +
  grace_days` (0–90). After that the team's vaults drop out of their access
  (`VaultAccess`): they disappear from sync (devices wipe them, as on any
  revocation), and server sessions, JIT, certificates and requests fail;
  enabling 2FA restores access at once.
- Visibility: login and `GET /me` return `team_2fa: [{team_id, team_name,
  deadline, blocked}]` for teams that need it (additive field);
  `GET /teams/{id}/compliance` (admins) lists members with `totp_enabled`,
  `deadline`, `blocked`.
- A member cannot turn off their own 2FA while a team requires it (409
  `team_2fa_required`); a server admin reset still works (the member is then
  blocked after the grace period).

### 6.2 Mandatory session recording

- `record_sessions` (team, all team vaults) or an access policy's
  `record_sessions` (those hosts): **server sessions** are recorded whatever
  the request says (`record: false` is ignored), in the server's recording
  store.
- Managers can list and download recordings of sessions in their vaults:
  `GET /vaults/{id}/recordings`, `GET /vaults/{id}/recordings/{session_id}`
  (asciicast v2; audited `recording.download`).
- **Device-side sessions**: clients that declare the feature `recording`
  (§10) record locally (the existing recorder) and upload the `.cast` when
  the session ends: `POST /recordings?host_id=…&started_at=…&title=…`
  (body: asciicast, ≤ 64 MiB) → a closed session row of kind `device` in the
  host's vault. JIT credentials and certificates for such hosts are only
  given to clients that declare `recording`; others get 403
  `recording_required` ("update the app or open a server session").
- Old clients: no JIT or certificate for those hosts; Editors with synced
  secrets can still connect locally without recording (UI protection only;
  combine with *Forbid reveal*).

### 6.3 Forbid revealing and exporting secrets

- `allow_reveal = false`: **Editors** of the team's vaults (not managers) no
  longer receive secrets in sync (`has_secret: true`, devices wipe what they
  had), `GET …/secret` → 403 `secret_reveal_forbidden`, transfers out of the
  vault do not copy secrets, exports skip them. They still edit items (a
  record pushed without `secret` keeps the stored one; they can set a new
  password but not read it) and connect: server-side, JIT credentials (not
  Strict) or certificates.
- Enforced in `VaultAccess::authorize_secret(Reveal)`, so every path that
  reveals (sync, reveal, transfer) obeys it.
- Clients hide reveal/copy/export for those items (`Vault.policy
  .reveal_allowed = false`, `ItemAccess` stays Editor).

### 6.4 AI

- `ai.allowed = false`: the server AI does not see the team's hosts (they
  are left out of its inventory, so its tools cannot name or reach them).
  Clients hide AI actions on those hosts and their local AI providers leave
  them out (`policy.ai_allowed`; `ai_forbidden_by_policy` is reserved for
  apps that refuse locally).
- `ai.approval = "always"`: every tool that runs on such a host (commands,
  terminal input, file writes) needs an approval even in `auto` or for
  read-only commands (as `confirm` mode).

### 6.5 Private networks

`networks_allowed = false`: hosts of the team's vaults cannot go through a
private network (resolution fails with `networks_forbidden_by_policy`;
server sessions, relays and tests included) and networks cannot be created
in those vaults (REST 403, sync rejection).

### 6.6 Default notification preferences (optional)

`notifications: {<push kind>: bool}`: defaults for members' devices that
never set preferences (`devices.push_prefs IS NULL`). Stored and returned;
**applied by the server in a later phase** (deferred: per-device
preferences already cover the need).

### 6.7 Exposure to clients

`Vault.policy` (in `GET /vaults`, sync v2's vault list; only for clients
with the feature `policies`; `None` for personal vaults without a CA):

```json
{"team_id":"…","reveal_allowed":true,"ai_allowed":true,"ai_approval":"default",
 "networks_allowed":true,"record_sessions":false,"require_2fa":false,
 "access_policies":true,"certificates":true}
```

Effective for the caller (a manager gets `reveal_allowed: true`). Stored in
the client's `vaults.policy`; the FFI exposes it (§9). The server enforces
regardless.

## 7. API summary

| Method | Route | Who |
|---|---|---|
| GET | `/teams/{id}/ca` | members |
| POST | `/teams/{id}/ca` · `/teams/{id}/ca/rotate` | owner/admin |
| DELETE | `/teams/{id}/ca?confirm=` | owner/admin |
| GET | `/teams/{id}/ca/install.sh` · `/teams/{id}/ca/krl` | owner/admin |
| GET | `/teams/{id}/ca/certificates?user_id=&active=` | owner/admin |
| POST | `/teams/{id}/ca/revoke` | owner/admin |
| GET/POST/DELETE | `/me/ca`, `/me/ca/rotate`, `/me/ca/install.sh`, `/me/ca/krl`, `/me/ca/certificates`, `/me/ca/revoke` | the user |
| GET | `/ssh-ca/{owner_id}/keys` · `/ssh-ca/{owner_id}/krl` | public |
| GET/PUT | `/teams/{id}/policy` | members / owner+admin |
| GET | `/teams/{id}/compliance` | owner/admin |
| PATCH | `/teams/{id}/members/{user_id}` `{role?, principal?}` | owner/admin |
| GET/PUT | `/vaults/{id}/access-policies` | members / managers |
| DELETE | `/vaults/{id}/access-policies/{policy_id}` | managers |
| GET | `/hosts/{id}/access` | members |
| GET/POST | `/access-requests` | members |
| GET | `/access-requests/{id}` | requester, approvers, managers |
| POST | `/access-requests/{id}/approve` · `/deny` · `/revoke` | approvers |
| POST | `/access-requests/{id}/cancel` | requester |
| POST/GET | `/certificates` | members |
| POST | `/recordings` | members |
| GET | `/vaults/{id}/recordings`, `/vaults/{id}/recordings/{session_id}` | managers |

`/info` → `features.teams_security: {"ca": true, "access_requests": true,
"policies": true, "roles_v2": true, "recording_upload": true}`.

New error codes: `connect_only`, `secret_reveal_forbidden`,
`access_approval_required`, `access_needs_server` (client),
`access_request_exists`, `access_request_not_needed`,
`access_request_closed`, `access_duration_too_long`,
`self_approval_forbidden`, `not_an_approver`, `ca_not_configured`,
`ca_exists`, `certificate_key_not_owned`, `certificate_key_revoked`,
`certificate_proof_invalid`,
`certificate_no_principals`, `team_2fa_required`, `policy_requires_2fa`,
`ai_forbidden_by_policy`, `networks_forbidden_by_policy`,
`recording_required`.

Session notice close reasons: `access_expired`, `access_revoked`.

## 8. Data model (schema v13, shared migrations)

```sql
CREATE TABLE ssh_cas (
    id TEXT PRIMARY KEY, owner_team_id TEXT, owner_user_id TEXT,
    kind TEXT NOT NULL DEFAULT 'user',          -- user | host (reserved)
    algorithm TEXT NOT NULL, public_key TEXT NOT NULL, fingerprint TEXT NOT NULL,
    private_key BLOB NOT NULL,                  -- sealed with the master key
    status TEXT NOT NULL,                       -- active | retiring | retired
    created_by TEXT NOT NULL, created_at INTEGER NOT NULL,
    retire_at INTEGER, retired_at INTEGER,
    CHECK ((owner_team_id IS NULL) <> (owner_user_id IS NULL)));
CREATE TABLE ssh_certs (
    serial INTEGER PRIMARY KEY AUTOINCREMENT, ca_id TEXT NOT NULL,
    user_id TEXT NOT NULL, vault_id TEXT, host_id TEXT, request_id TEXT,
    device_id TEXT, purpose TEXT NOT NULL,      -- device | server | credentials
    key_fingerprint TEXT NOT NULL, key_id TEXT NOT NULL, principals TEXT NOT NULL,
    valid_after INTEGER NOT NULL, valid_before INTEGER NOT NULL, created_at INTEGER NOT NULL,
    revoked_at INTEGER, revoked_by TEXT, revoke_reason TEXT);
CREATE TABLE ssh_revoked_keys (
    owner_id TEXT NOT NULL, fingerprint TEXT NOT NULL, public_key TEXT NOT NULL,
    revoked_by TEXT NOT NULL, revoked_at INTEGER NOT NULL, reason TEXT,
    PRIMARY KEY (owner_id, fingerprint));
CREATE TABLE access_policies (
    id TEXT PRIMARY KEY, vault_id TEXT NOT NULL, target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL, policy TEXT NOT NULL, updated_by TEXT NOT NULL,
    updated_at INTEGER NOT NULL, UNIQUE (vault_id, target_kind, target_id));
CREATE TABLE access_requests (
    id TEXT PRIMARY KEY, vault_id TEXT NOT NULL, target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL, target_label TEXT NOT NULL, requester_id TEXT NOT NULL,
    reason TEXT NOT NULL, minutes INTEGER NOT NULL, status TEXT NOT NULL,
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    decided_by TEXT, decided_at INTEGER, decision_reason TEXT,
    starts_at INTEGER, ends_at INTEGER, closed_at INTEGER, self_approved INTEGER NOT NULL DEFAULT 0);
ALTER TABLE teams ADD COLUMN policy TEXT NOT NULL DEFAULT '{}';
ALTER TABLE team_members ADD COLUMN principal TEXT;
ALTER TABLE vaults ADD COLUMN policy TEXT;   -- clients: the effective policy from the server
```

(Indexes on `ssh_certs(ca_id, valid_before)`, `ssh_certs(user_id)`,
`access_requests(vault_id, status)`, `access_requests(requester_id, status)`,
`access_policies(vault_id)`.) No data is rewritten: existing roles, teams and
vaults keep their meaning; a dry run on a copy of the staging database is part
of the deployment.

## 9. Core and FFI surface

- `termoak_core::model`: `VaultRole::ConnectOnly`, `HostAuth`
  (`TeamCertificate`, `Other(String)`), `HostSettings.auth`, `TeamPolicy`
  (+ `AiPolicy`, `CaPolicy`), `VaultPolicy`, `Vault.policy`, `AccessPolicy`,
  `AccessMode`, `AccessPolicyRecord`, `AccessRequest`,
  `AccessRequestStatus`, `CaInfo`, `IssuedCertificate`, `HostAccess`.
- `termoak_core::store`: `ResolveHook`, `Store::set_resolve_hook`, CA rows,
  certificates, revoked keys, access policies/requests, team policy and
  member principals, policy flags in `VaultAccess` (`no_reveal`, `no_ai`,
  `ai_confirm`, `no_networks`, `record`, `blocked_2fa`, `valid_until`).
- `termoak_ssh::ca`: CA key generation, certificate signing (`ssh-key`
  builder), SSHSIG proof sign/verify, KRL writer, certificate parsing for
  display; client auth falls back from key + certificate to the plain key.
- `termoak_client`: `X-Termoak-Features` header on every API request,
  `features=` on the events socket, team-certificate resolution and cache
  (§4.8), host access pre-check (§5.4), API calls for everything in §7.
- FFI (`AccountHandle` and `TermoakCore` with `account_id`):
  - `ca_info(team_id?)`, `create_ca(team_id?, algorithm)`, `rotate_ca(team_id?,
    overlap_hours)`, `disable_ca(team_id?, confirm)`, `ca_install_script(team_id?,
    krl, principals, refresh)`, `ca_certificates(team_id?, user_id?, active_only)`,
    `revoke_certificates(team_id?, RevokeTarget)`;
  - `request_certificate(host_id, key_id?, ttl_minutes?)` (normally
    implicit), `my_certificates()`, `parse_certificate(text)` →
    `CertificateDetails` (principals, validity, key id, serial);
  - `team_policy(team_id)`, `set_team_policy(team_id, TeamPolicy)`,
    `team_compliance(team_id)`, `set_member_principal(team_id, user_id, principal?)`;
  - `access_policies(vault_id)`, `set_access_policy(vault_id, target_kind,
    target_id, AccessPolicy)`, `delete_access_policy(vault_id, policy_id)`,
    `host_access(host_id)` → `HostAccess`;
  - `access_requests(scope, status?)`, `create_access_request(target_kind,
    target_id, minutes, reason)`, `approve_access_request(id, minutes?,
    reason?)`, `deny_access_request(id, reason?)`,
    `cancel_access_request(id)`, `revoke_access_request(id, reason?)`;
  - `upload_recording(host_id, path, started_at, title)`,
    `vault_recordings(vault_id)`;
  - `VaultInfo.policy: Option<VaultPolicyInfo>`, `VaultRole.ConnectOnly`,
    `ItemAccess.ConnectOnly`, `HostSettings.auth: Option<String>`.
  - Push: kind `access_decided` in `push_kinds()`, `parse_push_payload`
    routes `access_request` (approval) and `access_decided` (info).

## 10. Compatibility

- **Client features**: cores from v0.7.0-next.8 send `X-Termoak-Features:
  roles_v2,policies,certificates,recording` on every API request (and
  `features=…,roles_v2,policies` on the events socket). The web app adds the
  header in 4c. Without it the server: maps `connect_only` → `use_only` in
  every role it sends, leaves `Vault.policy` out, refuses JIT/certificates
  for recording-mandatory hosts (`recording_required`).
- **Old cores syncing**: no new entity kind; `HostSettings.auth` is a new
  field kept on edits by old cores (`keep_omitted_fields`, like
  `network_id`); new roles mapped as above; `Vault.policy` unknown fields are
  ignored by every core (serde default).
- **Old apps** with *Forbid reveal*: secrets stop arriving (`has_secret`);
  their local connections then ask for the password; server sessions work.
- **Old session holder**: certificates travel in `ResolvedKey.certificate`,
  which every holder understands (the fallback to the plain key needs the
  new holder; restart it when it has no sessions).
- **Old servers**: the new core asks `/info features.teams_security` before
  calling any of the new endpoints; without it `HostSettings.auth` is
  ignored (normal auth) and the apps hide the UI.

## 11. Security notes

- The CA private key never leaves the server process; it is sealed at rest
  with `master.key`; compromise of the database alone does not reveal it.
  Compromise of the running server = compromise of the CA (as for every
  server-managed secret); keep TTLs short and use `AuthorizedPrincipalsFile`
  on sensitive hosts.
- Proof of possession prevents attributing a certificate to the wrong user
  (key ids name the requester) and certificates for keys nobody holds.
- Approval is enforced cryptographically only where the server is the only
  way in (certificates on hosts without static team keys, Connect only,
  Strict, Forbid reveal). Otherwise it is UI protection plus audit; the docs
  and the apps say so.
- Every decision path is authenticated and audited; push payloads carry ids
  only (no reason, host or names unless `detailed`).

## 12. Tests

- Core: role ranks and compat mapping, `HostAuth` serde, keep-omitted
  `auth`, migration v13 on a v12 copy, policy flags in `VaultAccess` (2FA
  with grace, reveal, AI, networks), access request store transitions,
  certificate rows/serials, KRL encoding (`ssh-keygen -Q`), certificate
  signing verified with `ssh-keygen -L` and the `ssh-key` parser, SSHSIG
  proofs (good, wrong user, stale), real sshd login with a CA-signed
  certificate (OpenSSH container/binary) incl. the fallback to the plain key,
  client cert cache.
- Server: CA create/rotate/disable/export/install script, issuance rules
  (ownership, proof, principals, TTL caps, extensions), revocation + KRL,
  approval flow (self-approval refused, approver checks, windows, expiry job,
  revoke closes sessions), policy enforcement (2FA grace and blocking,
  reveal, AI, networks, recording), roles migration and compat mapping,
  push/events for requests.
- QA suite `teams-security` (§13 of NEXT.md for results).

## 13. Checklists for the UIs

### 13.1 Phase 4c — web + desktop (done 2026-10-24)

Web `next` 14b9d59 (staging), desktop 0.7.0-next.4 `next` 2afd3c5, QA
`teams-security` browser tests (qa 15019cf). Every item below is in both
apps unless said otherwise.

- [x] Features: the desktop gets `X-Termoak-Features:
      roles_v2,policies,certificates,recording` and `features=roles_v2,policies`
      from the core. The web sends `roles_v2,policies` only (a fetch wrapper
      for same-origin `/api/` requests, so public-web is untouched): it never
      asks for certificates or JIT credentials, so it does not claim
      `certificates`/`recording`.
- [x] Role picker Connect only / Use / Edit / Admin with help per role
      (servers without `teams_security`: Use and Edit); Connect only badge;
      an explicit Admin sees no Delete (implicit = owner of a shared vault or
      an `implicit` member entry of the team's owners/admins).
- [x] Team → Security: CA, policy form (validated with the core's
      `TeamPolicy::validate` on the desktop), compliance, member principal.
      **Install command**: `install.sh` needs the manager's token, so
      `curl … | sudo sh` cannot work from a host; both apps copy the script
      itself in a heredoc (`sudo sh -s <<'TERMOAK_CA' … TERMOAK_CA`) and offer
      to download it, plus the `sshd_config` lines and the public keys URL.
- [x] Personal CA (desktop: Settings → General under the account; web:
      Account → Certificates), same component.
- [x] Host/group Authentication with the inherited state. There is no
      "password/key" value that opts a host out of its group's Team
      certificate (`auth` is `null` = inherit, or `team_certificate`).
- [x] Access policy editor on vault (desktop: vault dialog → Access tab with
      every policy of the vault), group and host (menus).
- [x] `access_approval_required` → Request access (duration ≤ max, reason,
      this host or what the policy covers); pending state with Cancel;
      the desktop terminal connects by itself when the window opens; host
      chips "Until 15:42 · 42 min", tab time left, bar "Access until 15:42 ·
      42 min left". Server sessions close with `access_expired` /
      `access_revoked` in the session state's `reason` (bare codes), followed
      by the shared-session `ended` with `session_ended`: keep the reason.
- [x] Approvals inbox + My requests (desktop: Access section with sidebar
      badge, toasts, system notifications with their own switch; web:
      `/app/access`, badge on the Vaults link, toasts, live).
- [x] Hide reveal/copy/export (`Vault.policy.reveal_allowed`; the REST host
      list does **not** set `secret_hidden` for Editors under Forbid reveal),
      AI (desktop: hosts left out of "Ask AI"), the network picker;
      "Recorded" badges; desktop uploads recordings through the core;
      recordings list + download + an asciicast player (desktop replays into
      its terminal model, honouring `"r"` resize events).
- [x] 2FA banner (deadline or blocked) with the link to set it up.
- [x] en/es texts for every code (desktop: always the app's text, not the
      server's English message) and the close reasons.
- [x] Desktop: connection details dialog with the certificate in use
      (`parse_certificate`): resolves the host again (cached certificate);
      Use-only members of normal vaults read `GET /certificates` instead so
      no JIT credential is fetched twice.

### 13.2 Phase 4d — Android + iOS (done 2026-10-24)

Android 0.7.0-next.5 (`next` 491bfc3) and iOS (`next` fe1ddf7, not built
here) on core **v0.7.0-next.9** (4a58ce6), which adds two FFI calls the
phones needed: `download_vault_recording` (a `.cast` is not one JSON
document, so `api_request` can't read `GET /vaults/{id}/recordings/{s}`)
and `forget_access` (the desktop forgets the engine's cached host answers
and certificates through termoak-client on every `access_request` event).
Every item below is in both apps unless said otherwise.

- [x] Core bindings v0.7.0-next.9: `VaultRole.ConnectOnly` /
      `ItemAccess.ConnectOnly` in every `when`/`switch` (Android needed one;
      iOS two plus the demo's `VaultInfo`), `HostSettings.auth` kept on
      edits, `VaultInfo.policy` → the gates. ConnectOnly (and Strict Use)
      items open on the device only when the host's effective auth (own or
      nearest group's) is `team_certificate` and `policy.certificates`, else
      as server sessions; files follow the same rule.
- [x] Push: `access_request` (approval: Approve/Deny only open the Access
      screen's confirmation behind the app lock), `resolved` withdraws it
      (its kind is `resolved`, not `access_request`), `access_decided`
      (info) opens My requests; the kind in Settings → Notifications.
- [x] Access screen (Settings; Android: also the desktop layout's sidebar
      and a badge on the Settings tab): waiting for your decision (approve
      with a shorter window starting now and a note, deny with a reason),
      open windows you can end with a reason, recent decisions, my requests
      with cancel/end. The lists and every host asked about are read again
      on every event; snackbars/notices for the events that concern you.
- [x] Connect flow: `access_approval_required` (both detail shapes) →
      "Approval needed" card on the terminal with Request access (duration
      up to the max, reason, this host or what the policy covers), then
      "Waiting for approval" with Cancel request; the terminal connects by
      itself when `host_access` says it is allowed (after an event, or a
      20 s fallback). A server session refused with only the English text
      asks `host_access` to build the card.
- [x] Countdown on host rows/cards and the terminal bar (1 s ticks in the
      last 2 min, amber in the last 5); `access_expired` /
      `access_revoked` close texts, kept over the following
      `session_ended`.
- [x] Host/group editors: Authentication (the group's, or Team
      certificate; a later value kept) with what is inherited and the no-CA
      warning.
- [x] Hidden per `policy`: key export and move/copy out of the vault
      (reveal), terminal AI / Fix chip / new AI tasks (AI), the network
      picker (networks); "Recorded" chips; `upload_recording` is done by the
      core after local recorded sessions (to check on devices).
- [x] Team security with full editing (Teams → a team → Security): CA
      (create, fingerprint, public key, sshd lines, install command as the
      `sudo sh -s <<'TERMOAK_CA'` heredoc to copy or share, rotate, disable
      with the typed name, issued certificates, revoke serial/member/key),
      team policy (read-only for members), 2FA compliance and principals.
      Personal CA and your certificates in Settings → SSH certificates.
- [x] Access policy editor (vault Admins) for the vault (vault page →
      Access policies), groups and hosts (their menus); vault recordings
      with download/share and a player (the engine's terminal emulator).
- [x] 2FA banner (`team2fa_requirements` = `/me` `team_2fa`) with a link to
      two-step verification.
- [x] en/es for every code, close reason and screen (Android
      `strings_teams_security.xml`, iOS `Localizable.xcstrings`; the
      desktop's texts plus the apps'). Role names Use / Edit / Admin.
- [x] Live test against staging (Android `LiveAccessTest`, engine built for
      the PC): team + Connect only vault, CA installed in a
      `termoak-qa-sshd` container with the install script, vault approval
      policy; refused with `access_approval_required`; request pushed to the
      admin's phone through the staging ntfy (Approve/Deny only open),
      approved for 1 min, `access_decided` on the member's phone, admin's
      notification withdrawn; ssh from the phone with a certificate for an
      ephemeral key (principal `qa`, capped to the window); server host test
      inside the window; a server session closed with `access_expired`; a
      second window revoked → `access_revoked`, then refused again.

Found on the way (for the next phases):
- A server session to a new host needs its host key trusted first (a host
  test with `trust=true`), else it times out "negotiating SSH" while the
  holder waits for the prompt; the staging holder reaches Docker containers
  by their bridge IP, not by a port published on 127.0.0.1.
- iOS type-checking on Linux: `swift-frontend -typecheck -primary-file`
  per changed file against the whole app (seconds) instead of the driver
  (ten minutes, one file's errors at a time); the stand-in modules still
  lack some iOS 16 API (`TextField(axis:)`, `ShareLink`, `Timer.publish`,
  `alert(Text)`), added as stubs.

## 14. Deferred / open

- Host CA (§4.10) → 0.8.
- Team default notification preferences applied by the server (§6.6).
- Multi-approver (N of M) requests; scheduled windows (start later).
- Certificates for device-only keys without proof (not planned: proof is
  cheap); SSO-bound certificates (phase 5).
