# WebSocket protocol

## Session terminal: `GET /api/v1/sessions/{id}/ws`

### Access

There are three ways in:

| How | Access |
|---|---|
| `Authorization: Bearer <token>` or `?access_token=<token>` | The owner joins as `owner`. An invited user joins with the best share they have (direct or through a team) |
| `?share_token=<token>` | Link share. No account needed. A signed-in user can use it too (with a bearer token): they join with their account's name, and with their own share if it gives more |
| `?role=host` | Only for `relay` sessions and only for the owner: the client that has the real terminal |

Other query parameters:

| Parameter | Meaning |
|---|---|
| `proto=2` | The client speaks protocol 2 (participants, keyboard, waiting room). Clients that do not send it are "older clients", see [Older clients](#older-clients) |
| `name` | Link guests: display name. Control and direction characters are removed, spaces are collapsed and it is cut to 40 characters. Without one (or if nothing is left) the guest is `Guest 1`, `Guest 2`... |
| `guest` | Link guests: a random key (8-64 letters, digits, `-` or `_`) the client keeps while it reconnects. With it, a guest that reconnects is the same participant (keeps the keyboard, does not wait again, is not a new join) |

### Participants and the keyboard

A **participant** is a person, not a socket: the same user on two devices
(or a guest that reconnects with the same `guest` key) is one participant
with two `devices`. Each one has a participant id (`participant`).

**One driver at a time.** The owner can always type and resize. Everyone
else joins **read-only**; the share's permission is the most the owner can
hand over:

| Access | View | Type and resize | Ask for the keyboard | Owner actions |
|---|---|---|---|---|
| `owner` | yes | always | — | yes |
| `control` | yes | only while they have the keyboard (`driver`) | yes | — |
| `view` | yes | never | no | — |

Input and resizes from someone who cannot write are dropped **without an
error** (clients should not send them: see `can_write`). The resize of the
driver or the owner changes the terminal; in a relay session it is a
request to the host (see [Relay sessions](#relay-sessions)).

The keyboard goes back to the owner when the driver gives it back, when the
owner takes it, when the driver's share goes down to `view` (or is revoked,
or expires), when the driver leaves (no device for 10 seconds), or when a
timed grant ends.

**Timed grants.** The owner can hand the keyboard over for 1 to 240 minutes
(`control_grant` with `minutes`); a share with `auto_grant` can have a
`control_minutes` limit for its automatic grants. While a grant is timed,
`control` (and `driver_until` in the session) says when it ends (`until`,
ms). When the time is up the server takes it back by itself: everyone gets
`control` with `driver: null`, and the driver and the owner get
`control_expired`. Granting it again changes the time (or, without
`minutes`, removes the limit).

**Who typed what.** Every input that reaches the terminal comes from the
owner or the driver, so the server knows who typed it: in recorded
sessions the recording says who typed each part (see
[API.md](API.md#who-typed-what)), and each period someone else had the
keyboard is one `session.control_period` audit entry.

**Waiting room.** If the share has `require_approval` (links by default),
whoever joins gets `waiting` and nothing else until the owner lets them in
(`join_allow`): then `hello` and the snapshot arrive as usual. If the owner
says no (`join_deny`), they are sent away with `join_denied`. Once let in,
reconnects do not wait again. Leaving the waiting room withdraws the
request.

### Frames

- **Binary**: terminal bytes. From the server they are the output; from the
  client, what is typed.
- **Text**: JSON with a `type` field.

### Server to client

On connect, the server sends, in this order:

1. `waiting`, only with a waiting room (until the owner lets them in).
2. `{"type":"hello","proto":2,"session":{…},"you":{…}}`. `you` has `id`
   (this socket), `participant`, `name`, `kind`, `access`, `role`
   (`viewer` or `host`), `since`, `can_write`, `is_driver` and `user_id`
   (your own, if signed in). `session` includes `participants`, `driver`
   and, while a grant is timed, `driver_until` (ms).
3. Owner only: pending `prompt`s, `join_request`s and `control_request`s.
4. A binary frame with the scrollback snapshot. If the session is still
   connecting, it arrives as soon as it becomes `running`.
5. From then on, the live output, with no gaps or duplicates relative to the
   snapshot.

Other messages:

| `type` | Fields | When |
|---|---|---|
| `status` | `status` | The state changes. `status.state` is `connecting` (with `message`), `running`, `host_offline` (relay without its host) or `closed` (with `exit_code` and `reason`) |
| `participants` | `participants[]`, `driver` | Someone joins, leaves, asks for the keyboard, changes devices or permission. See [Participant](#participant) |
| `control` | `driver`, `driver_name`, `can_write`, `until?` | The keyboard changes hands. `driver` is a participant id, or `null` when the owner has it. `can_write`: your input and resizes reach the terminal now. `until` (ms): only for a timed grant, when it ends |
| `control_expired` | `participant` | The driver and the owner only. The timed grant of `participant` ended and the keyboard went back to the owner (a `control` arrives too) |
| `waiting` | `participant`, `name`, `session: {id, title, owner}` | You are in the waiting room |
| `join_request` | `participant` | Owner only. Someone waits to be let in |
| `control_request` | `participant` | Owner only. Someone asks for the keyboard |
| `control_denied` | — | The owner said no to your request |
| `presence` | `viewers[]` | Older clients only (instead of `participants`): the sockets connected |
| `resize` | `cols`, `rows` (`by` for a relay host) | The terminal size changes (a relay host: someone asks for a size) |
| `title` | `title` | The session is renamed |
| `prompt` | `prompt_id`, `kind`, `host`, `message`, `prompts[]`, `fingerprint?`, `key_type?` | Owner only. The server needs an answer: `kind` is `hostkey`, `keyboard_interactive`, `password` or `passphrase` |
| `prompt_done` | `prompt_id` | The prompt was answered, maybe from another device |
| `resync` | — | The client fell behind. A new snapshot follows and replaces the screen |
| `pong` | `ts` | Answer to `ping` |
| `error` | `code`, `message` | Error. See [Errors and close codes](#errors-and-close-codes) |

#### Participant

```json
{"id":"…","name":"Zoe","kind":"guest","access":"control","is_driver":false,
 "since":1791198048458,"devices":1,"requested_control":true,"waiting":false,"you":false}
```

- `kind`: `owner`, `user` (account on this server) or `guest` (link, no
  account).
- `access`: `owner`, `control` or `view`.
- `is_driver`: has the keyboard (the owner, when `driver` is `null`).
- `devices`: sockets attached (0 for a few seconds while reconnecting).
- `requested_control`: asked for the keyboard and waits for the owner.
- `waiting`: in the waiting room. Only the owner's list includes them.
- `you`: it is whoever receives the list.
- Only in the owner's list: `user_id` (users) and `share_id` (the share
  they joined with). Nobody else ever receives user ids or share ids
  (neither in `participants`, nor in `viewers`, nor in `/join/{token}`).

### Client to server

```json
{"type":"resize","cols":120,"rows":40}
{"type":"input","data":"ls -la\r"}
{"type":"prompt_answer","prompt_id":"…","accept":true}
{"type":"prompt_answer","prompt_id":"…","answers":["123456"]}
{"type":"ping"}
{"type":"set_name","name":"Zoe"}
{"type":"control_request"}
{"type":"control_release"}
{"type":"close_session"}
{"type":"host_closed"}
```

Owner only (also from a relay host):

```json
{"type":"join_allow","participant":"…"}
{"type":"join_deny","participant":"…"}
{"type":"control_grant","participant":"…","minutes":15}
{"type":"control_deny","participant":"…"}
{"type":"control_take"}
{"type":"kick","participant":"…","revoke_share":false}
{"type":"stop_sharing"}
```

- `input` is a text alternative to binary frames.
- `set_name`: link guests only (also while waiting).
- `control_request`: with a `view` share it answers `error` `forbidden`.
  With `auto_grant` on the share the keyboard is granted at once (even if
  someone else had it), for the share's `control_minutes` if it has them.
- `control_release`: the driver gives the keyboard back to the owner; whoever
  asked withdraws the request.
- `control_grant`: hands the keyboard to a participant with `control`
  (errors: `forbidden` for a `view` share, `participant_not_found`). Granting
  it to yourself (the owner) is the same as `control_take`. `minutes`
  (optional, 1-240) makes it a timed grant; anything else gets `error`
  `invalid_control_minutes`.
- `kick`: sends the participant away (`kicked`). They can come back with
  their share unless `revoke_share` is `true`: then the share they joined
  with is revoked too (for a team share or a link, that is everyone who uses
  it and has no other valid share).
- `stop_sharing`: same as `DELETE /sessions/{id}/shares`.
- `close_session` closes the session for everyone. Owner only.
- `host_closed` is only sent by the host of a relay session, when its local
  terminal ends.

Owner-only messages from someone else, and `prompt_answer` or
`close_session` from a guest, get `error` `forbidden`; the socket stays
open. An invalid JSON message gets `error` `bad_request`.

### Errors and close codes

When the server sends a socket away, it sends `error` with a stable `code`
and then closes with a close code in the private range and the code as the
reason. Clients must not reconnect after these:

| `code` | Close code | Why |
|---|---|---|
| `revoked` | 4001 | The share was revoked (or sharing stopped, or the account was deleted or disabled), and there is no other valid share |
| `kicked` | 4002 | The owner sent them away |
| `expired` | 4003 | The share expired (also for whoever was already inside) |
| `session_ended` | 4004 | The session ended (the last `status` arrives first) |
| `join_denied` | 4005 | The owner did not let them in |
| `forbidden` | 4006 | No access any more |
| `signed_out` | 4007 | The device of this connection was signed out (the access token no longer works: sign in again) |

Other errors (`forbidden` for a single action, `bad_request`,
`participant_not_found`, `invalid_control_minutes`, `internal`) do not close the socket and must not
stop a client from reconnecting if the connection drops later.

When access changes (a share is revoked, changed with `PATCH`, expires, or a
user leaves a team), the server checks again everyone affected: whoever
still has another valid share (direct, from another team or a link they
used) stays with the best one; the rest are sent away.

### Relay sessions

The host, connected with `?role=host` (and `proto=2`), is an owner socket:

- It sends the output of its local terminal as binary frames. The **first
  binary frame of each connection is the whole screen** and replaces the
  history kept by the server, so a host that reconnects does not duplicate
  it.
- It receives, as binary, what the driver (or the owner from another
  device) types.
- It sends `resize` with the size of its terminal; that is the size guests
  see. When the driver or the owner (from another device) resizes, the host
  receives `resize` with `by` (the participant): it may apply it to its
  terminal or ignore it.
- It receives `participants`, `control`, `control_expired`,
  `join_request` and `control_request`, and can send every owner message
  above.
- If its connection drops, guests see `host_offline` and the server keeps
  the session for `[sessions] relay_grace_minutes`. The client library
  reconnects by itself.

The server connects to no host: it only relays and keeps the scrollback.

### Older clients

Clients without `proto=2` (apps released before protocol 2) keep working:

- They receive `presence` (sockets) instead of `participants`; the other new
  messages arrive too and they ignore them.
- A `control` participant on an older client cannot ask for the keyboard,
  so **typing takes it when nobody else has it** (as before, but one at a
  time). If someone else has it, typing counts as a `control_request` for
  the owner. Once the owner takes it from them or says no, typing does not
  take it back by itself until the owner grants it again.
- Read-only input and resizes are dropped without errors, so older clients
  no longer get errors for them.
- Shares created by older apps get the new defaults: links wait for
  approval (any device of the owner with a current app, the web app or the
  push notification can let guests in).

## User events: `GET /api/v1/events/ws`

Receive only, with user authentication (except the security key answers
below). On connect:

```json
{"type":"hello","user":{…},"pending_approvals":[…],"features":[]}
```

`?features=` (comma list) declares what this client can do; `hello` echoes
the ones the server knows. Today: `security_keys` (see
[Security keys](#security-keys)), `roles_v2` and `policies` (0.7.0-next.8:
without `roles_v2`, `vault/access` shows `connect_only` as `use_only`) and
`e2ee` (0.7.0-next.10: end-to-end encrypted vaults, see below).

and then three kinds of messages (plus `signed_out`, below):

```json
{"type":"ai","task_id":"…","seq":42,"event":{"type":"approval_requested","approval_id":"…","tool":"run_command","summary":"…","input":{…}}}
{"type":"session","notice":{"type":"session_shared","session":{…},"by":"Ana","team":"Ops"}}
{"type":"vault","event":"changed","vault_id":"…","rev":1234}
```

| `ai.event.type` | Meaning |
|---|---|
| `status` | Task state: `queued`, `running`, `waiting_approval`, `completed`, `failed` or `cancelled` |
| `text` / `reasoning` | Chunks (`delta`) of the answer and of the reasoning summary |
| `reset` | Discard the text in progress: the provider failed and the turn is retried with the fallback |
| `notice` | Notice: retry, provider switch... |
| `tool_call` / `tool_result` | A tool call and its result |
| `approval_requested` / `approval_decided` | Approvals |
| `message` | Full message at the end of a turn |
| `usage` | Tokens and cost in micro-dollars (`cost_micros`) |
| `finished` | End of the task, with `result` or `error` |

| `session.notice.type` | Fields | Meaning |
|---|---|---|
| `session_opened` | `session` | One of your sessions was opened |
| `session_closed` | `session_id`, `reason?` | One of your sessions was closed |
| `session_shared` | `session`, `by`, `team?` | Someone shared a session with you. `by` is the name of who shared it; `team` is the name of the team it was shared through, and is absent for a direct share |
| `prompt_pending` | `session_id`, `prompt` | One of your sessions is waiting for an answer (known host, 2FA...) |
| `join_request` | `session_id`, `title`, `participant` | Someone waits to be let into one of your sessions |
| `control_request` | `session_id`, `title`, `participant` | Someone asks for the keyboard of one of your sessions |
| `control_granted` | `session_id` | You got the keyboard of a session shared with you |
| `control_revoked` | `session_id` | You lost the keyboard of a session shared with you |

| `vault.event` | Fields | Meaning |
|---|---|---|
| `changed` | `vault_id`, `rev` | Items of a vault you can access changed: sync (v2). Coalesced per vault (one every 500 ms at most) and sent to every member online |
| `access` | `vault_id`, `role`, `reason` | Your access changed. `role` is the new role (`manager`, `editor`, `use_only`, `connect_only` with `roles_v2`) or `null` when you lost it; `reason` is `granted`, `role_changed`, `revoked`, `deleted` or `updated` (settings such as the Strict switch). Sync after it |

Teams security (0.7.0-next.8, [TEAMS-SECURITY.md](TEAMS-SECURITY.md)) adds:

```json
{"type":"access_request","event":"created","request":{AccessRequest}}
{"type":"team","event":"policy","team_id":"…"}
```

| `access_request.event` | To | Meaning |
|---|---|---|
| `created` | requester, approvers | A request waits for a decision |
| `approved` / `denied` | requester, approvers | Decided (`request.decided_by`, `decision_reason`, `starts_at`, `ends_at`) |
| `cancelled` | requester, approvers | The requester cancelled it (or ended the window) |
| `expired` | requester, approvers | Nobody decided in time |
| `revoked` | requester, approvers | An approver ended the window early |
| `ended` | requester | The window ran out |

`team/policy`: the team's policy changed: sync (the vaults' `policy` and
access may have changed). When a window ends or is revoked, the requester's
server sessions on hosts no longer allowed close with `session_closed` and
`reason: "access_expired"` or `"access_revoked"`.

End-to-end encrypted vaults (0.7.0-next.10, [E2EE-SSO-AUDIT.md](E2EE-SSO-AUDIT.md)) add:

```json
{"type":"e2ee","event":"pairing","pairing":{"id":"…","device_name":"Phone","status":"pending","expires_at":1792976000000}}
```

sent to every events socket of the user when one of their devices asks for
the E2EE key (`status: "pending"`: show the approval with the six-digit
code) and when it is approved or denied (the asking device then fetches
`GET /me/e2ee/pairings/{id}`). Adding wraps for members sends them
`vault/changed`. Clients without `e2ee` may get `vault` events about E2EE
vaults they cannot see: they sync and nothing changes.

When the device is signed out (from another device, a password reset or an
administrator), the server sends `{"type":"signed_out","message":"…"}` and
closes the socket with close code 4007 (`signed_out`): do not reconnect,
the token no longer works.

When access is revoked, your server sessions on hosts of that vault end with
`session_closed` and `reason: "vault_access_revoked"`. Clients must ignore
message types they do not know (older apps ignore `vault`).

The same notices go out as push notifications (`prompt_pending` as
`session_prompt`, `join_request`, `control_request`) when you are not
watching that session, with a generic text unless `[push] detailed = true`.
A device with this socket open gets no push notifications (it shows the
events itself) unless its push preferences say `when_online` (API.md,
Push notifications).

If the client falls behind, `{"type":"lagged","missed":n}` arrives. Then
fetch what was missed with `GET /ai/tasks/{id}/events?after=<last seq>`.

### Security keys

Since server 0.7.0-next.4. When a connection made **by the server**
(server sessions, also in the session holder; `POST /hosts/{id}/test`;
`/exec`; SFTP; AI tools) uses a FIDO2 security key (`sk-*` key), the server
asks the key owner's devices to sign. Only events sockets of that user
opened with `?features=security_keys` get these messages (older clients
never do). Design and security rules: SSH-PRO.md §5 in the core repository.

Server → device:

```json
{"type":"security_key_request","request_id":"…","expires_at":1791198108458,
 "purpose":"server_session","session_id":"…","host":"web1","address":"10.0.0.5",
 "username":"deploy",
 "key":{"id":"…","label":"YubiKey","fingerprint":"SHA256:…","public_key":"sk-ssh-ed25519@openssh.com AAAA…",
        "algorithm":"sk-ssh-ed25519@openssh.com","application":"ssh:",
        "key_handle":"<base64>","device":"YubiKey 5C"},
 "message":"<base64>","client_data_hash":"<base64>",
 "require_presence":true,"require_verification":false}
```

`purpose` is `server_session`, `test`, `server` (`/exec`, SFTP and AI
through the connection pool). The device runs CTAP2 get assertion with
`rpId = key.application`, the allow list `[key_handle]`, `clientDataHash =
client_data_hash` (the SHA-256 of `message`), `up = require_presence` and
`uv = require_verification`, and answers on the same socket:

```json
{"type":"security_key_response","request_id":"…","flags":1,"counter":42,"signature":"<base64>"}
{"type":"security_key_response","request_id":"…","error":{"code":"cancelled","message":"…"}}
```

`flags` and `counter` come from the assertion's authenticator data;
`signature` is DER (ECDSA, as CTAP2 returns it; 64-byte `r || s` works too)
or the 64 Ed25519 bytes. Error codes: `cancelled`, `timeout`, `not_found`,
`pin_required`, `pin_invalid`, `no_device`, `unsupported`, `failed`.

When the request is decided, every device that got it receives:

```json
{"type":"security_key_done","request_id":"…","result":"signed"|"failed"|"timeout"|"cancelled"}
```

Rules: the first answer that verifies wins; an error from one device does
not end the request while other devices can still answer (except
`cancelled`); with no such device online the connection fails at once with
`security_key_no_device`, otherwise after `[sessions]
security_key_timeout_secs` (60) with `security_key_timeout`.

Since server 0.7.0-next.7, when no such device is online but the user has
devices with push notifications that accept `security_key_request` (the
default), the server sends them a push (`security_key_request`, with
`request_id` and `expires_at`) and waits instead of failing: a request
still waiting is sent to every `features=security_keys` socket of that user
that connects meanwhile, so the phone opens the app, connects and answers
it. Without any such push device it still fails at once with
`security_key_no_device`; when nobody answers, `security_key_timeout`. The
notification is withdrawn (`resolved`) when the request ends. Apps must not
connect from the background when that push arrives (they would answer
`no_device`): only when the user opens it. The server
verifies the signature over the exact `message` (which contains the SSH
connection's exchange hash, so it is only valid for that connection) before
using it, and audits every request as `security_key.sign` (`purpose`,
`session`, `host`, `key` fingerprint, answering `device`, `result`, `code`).
While it waits, a server session shows `connecting` with "Touch your
security key (…) on one of your devices…".

