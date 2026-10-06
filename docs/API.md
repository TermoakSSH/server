# HTTP API

- **Base URL:** `https://<server>/api/v1`.
- **Contract:** the server serves its OpenAPI 3.1 document at
  `/api/openapi.json`. `termoak-server openapi` prints it too, which is handy
  to generate Swift or Kotlin clients if you don't use the FFI library.
- **Format:** everything is JSON, except SFTP downloads and uploads and
  session recordings.
- **Authentication:** send `Authorization: Bearer <access_token>` with every
  request. On WebSockets, if the client cannot set headers,
  `?access_token=<token>` works too. The access token lasts 60 minutes and
  the refresh token 90 days by default (both configurable in `[server]`).
- **Errors:** see [Errors](#errors).

## Compatibility

The server, the CLI, the desktop app and the mobile apps are released
separately, and every user updates whenever they want. A client from months
ago must keep working with a new server, so `/api/v1` only grows:

- Routes, response fields and optional request fields can be added: clients
  ignore fields they don't know.
- A route or field cannot be removed or renamed, an optional field cannot
  become required, and the meaning of a field or an error code cannot change.
- Values cannot be added to an enum that clients already receive
  (`SessionStatus`, `EntityKind`, `TeamRole`, `SharePermission`...): current
  clients don't recognize them and the whole response fails to parse. To
  allow it later, the enum first needs a catch-all variant
  (`#[serde(other)]`) shipped in every client.

An incompatible change goes into a new API (`/api/v2`) that lives alongside
the old one while clients still use it. One deliberate exception: since
server 0.3, `control` on a session share means "can ask for the keyboard"
(one person types at a time) instead of "can always type"; older clients
keep a compatible behaviour, described in
[WEBSOCKET-PROTOCOL.md](WEBSOCKET-PROTOCOL.md#older-clients).

`GET /info` returns the server version.

## Errors

Every API error has the same shape, with the matching HTTP status:

```json
{"error": {"code": "plan_limit", "message": "your plan allows at most 3 teams", "limit": "max_teams", "max": 3}}
```

- `code` is a stable snake_case identifier. Clients use it to decide what to
  do and to show their own translation (`error.<code>`, see
  [I18N.md](https://github.com/TermoakSSH/core/blob/main/docs/I18N.md)).
- `message` is English, meant for logs and as a fallback when a client has
  no translation.
- Some errors add extra fields next to `code` and `message` (the
  placeholders of the translation). They are listed below.

A `401` always means the session is not valid (missing, expired or revoked
token). When the password asked to confirm an action is wrong (changing the
password or the email, disabling two-step verification, deleting the
account), the answer is `403` with `invalid_password`, and the session stays
valid.

A body that is not valid JSON, or that misses a required field, is rejected
before reaching the API with a plain-text `400`, `415` or `422`.

### Error codes

Generic codes, used when there is no more specific one:

| Code | Status | Meaning |
|---|---|---|
| `bad_request` | 400 | Invalid request |
| `unauthorized` | 401 | Missing, invalid, expired or revoked token |
| `forbidden` | 403 | You are not allowed to do this (also: the monthly AI budget is spent) |
| `not_found` | 404 | The resource does not exist, or is not yours |
| `conflict` | 409 | Conflicts with the current state |
| `internal` | 500 | Unexpected server error |
| `unavailable` | 503 | The session holder is not responding; try again in a few seconds |

Accounts and sign-in:

| Code | Status | Meaning |
|---|---|---|
| `invalid_credentials` | 401 | Wrong email or password |
| `totp_required` | 401 | The account has two-step verification: repeat the request with the code |
| `totp_invalid` | 401 | The two-step verification code is not correct |
| `too_many_attempts` | 429 | Too many failed attempts (or emails requested too often); wait a few minutes. Extra field when asking for emails too often (`/auth/resend-code`, `/me/verify-email`): `retry_after` (seconds) |
| `invalid_password` | 403 | The password (or code) asked to confirm the action is not correct |
| `registration_closed` | 403 | Registration is closed: an invitation is needed |
| `invalid_invite` | 403, 404 | The invitation is invalid, used, revoked or expired |
| `invite_email_mismatch` | 403 | The invitation is for another email address |
| `invalid_email` | 400 | The email address is not valid |
| `password_too_short` | 400 | The password is too short. Extra field: `min` |
| `email_taken` | 409 | An account with that email already exists |
| `same_email` | 400 | The new email is the current one |
| `email_already_verified` | 400 | The email is already verified |
| `email_not_verified` | 403 | The server requires a verified email to use the account. Extra fields: `email` (the account's address) and `verification` (`["code", "link"]`): show the screen to enter the code from the email. See [Email verification](#email-verification) |
| `invalid_code` | 400 | The email verification code is wrong, has expired or was used up (five wrong tries); the same answer whether or not the account exists |
| `email_disabled` | 400 | The server does not send emails |
| `email_failed` | 502 | The email could not be sent; try again later |
| `invalid_link` | 400, 401, 404 | The link (email link or session share link) is invalid or has expired |
| `invalid_locale` | 400 | The server does not have that language (see `GET /locales`) |
| `terms_not_accepted` | 400 | Registration sent `accept_terms: false` on a server with terms of use |
| `invalid_terms_version` | 400 | `terms_version` is longer than 16 characters or has control characters |
| `last_admin` | 409 | You are the only administrator: appoint another one first |
| `last_team_owner` | 409 | A team would be left without an owner. Extra field when deleting the account: `teams` (names of those teams) |
| `plan_limit` | 403 | Your plan does not allow more. Extra fields: `limit` (`max_teams`, `max_team_members` or `max_server_sessions`) and `max` |

Administration:

| Code | Status | Meaning |
|---|---|---|
| `admin_only` | 403 | Only for server administrators |
| `cannot_modify_self` | 400 | You cannot disable yourself or remove your own administrator role |
| `unknown_plan` | 400 | The plan does not exist (or is a team plan, when assigned to an account) |

Teams:

| Code | Status | Meaning |
|---|---|---|
| `team_owner_only` | 403 | Only a team owner can do this |
| `team_admin_only` | 403 | Only team owners and admins can do this |
| `user_not_found` | 404 | There is no user with that email on this server |
| `account_disabled` | 400 | That account is disabled |
| `already_member` | 409 | Already a member of the team |
| `not_team_member` | 403 | You can only share with teams you belong to |

Server sessions:

| Code | Status | Meaning |
|---|---|---|
| `session_owner_only` | 403 | Only the owner of the session can do this |
| `session_limit` | 409 | You reached the maximum number of active sessions (`[sessions] max_per_user`) |
| `session_connecting` | 409 | The session is still connecting and its input buffer is full |
| `session_ended` | 404 | The session is no longer active (also when sharing a session that just ended) |
| `recording_not_found` | 404 | The session has no recording |
| `title_required` | 400 | The title cannot be empty |
| `cannot_invite_self` | 400 | You cannot share a session with yourself |
| `share_revoked` | 409 | The invitation was revoked: it cannot be changed |
| `invalid_control_minutes` | 400 | A timed grant of the keyboard (`control_minutes`) must be 1 to 240 minutes |

The terminal WebSocket has its own codes (`revoked`, `kicked`, `expired`,
`session_ended`, `join_denied`, `forbidden`, `signed_out`), see
[WEBSOCKET-PROTOCOL.md](WEBSOCKET-PROTOCOL.md#errors-and-close-codes).

SSH and SFTP:

| Code | Status | Meaning |
|---|---|---|
| `ssh_auth_failed` | 502 | SSH authentication failed |
| `host_key_unknown` | 409 | The host key is not known yet |
| `host_key_changed` | 409 | The host key changed (the connection is always refused) |
| `host_key_rejected` | 409 | The host key was rejected |
| `ssh_timeout` | 504 | The SSH connection timed out |
| `ssh_error` | 502 | Other SSH error |
| `invalid_path` | 400 | Invalid path |
| `invalid_mode` | 400 | Invalid mode (use octal, for example `644`) |
| `cannot_delete_root` | 400 | The root directory cannot be deleted |

Sync, AI, push notifications and updates:

| Code | Status | Meaning |
|---|---|---|
| `too_many_changes` | 400 | Too many changes in a single sync request (maximum 5000) |
| `vault_not_found` | 404 | The vault does not exist or you cannot see it |
| `vault_read_only` | 403 | You can use the items of this vault (Use-only) but not change them |
| `vault_manager_only` | 403 | Only the vault's managers (owner, team owners and admins) can do this |
| `secret_hidden` | 403 | Use-only members never see the secrets of the vault |
| `vault_personal` | 409 | The personal vault cannot be shared, deleted or left (and only its name, color and icon change) |
| `use_transfer` | 409 | The item is in another vault: move it with `POST /vaults/{target}/transfer` |
| `cross_vault_reference` | 422 | A reference points to an item of another vault. Extra field: `field` (`group_id`, `settings.key_id`...) |
| `still_referenced` | 409 | You are moving a key or identity that other items still use (`force: true` detaches them). Extra field: `used_by` (`[{kind, id, field}]`) |
| `use_only_strict` | 403 | Strict vault: Use-only members only connect through the server (no `/credentials`) |
| `invalid_role` | 400 | Only `editor` and `use_only` can be granted |
| `member_exists` | 409 | That user or team already has access to the vault |
| `id_in_use` | 409 | The id belongs to an item you cannot see |
| `not_team_member` | 403 | You can only share a vault with a team you belong to |
| `confirmation_required` | 400 | Deleting a vault needs `?confirm=<its name>` |
| `shared_vaults` | 409 | Deleting the account would delete your shared vaults with members: confirm with `delete_shared_vaults: true`. Extra field: `vaults` (`[{id, name, member_count}]`) |
| `rate_limited` | 429 | Too many requests (`/hosts/{id}/credentials`: 30 per minute). Extra field: `retry_ms` |
| `ai_not_configured` | 503 | The AI provider is not configured |
| `ai_key_required` | 403 | The plan does not include the server's AI and you have no API key of your own that can be used: add one in Settings → AI (`PUT /me/ai/keys/{provider}`) |
| `ai_budget_exceeded` | 403 | This month's AI credit for the server's providers is spent (your own API keys keep working) |
| `unknown_provider` | 400 | The provider does not exist or does not accept your own API key. Extra field: `provider` |
| `ai_error` | 502 | The AI provider failed |
| `push_disabled` | 400 | The server has no push notifications configured |
| `push_not_registered` | 400 | This device has no push notifications enabled |
| `push_failed` | 502 | The notification could not be sent |
| `updates_disabled` | 404 | This server does not serve updates |
| `updates_upstream` | 502 | GitHub could not be reached or answered with an error |

`POST /hosts/{id}/test` does not fail when the connection fails: it answers
`200` with `ok: false`, the `error` text and an `error_code`
(`host_key_unknown`, `host_key_changed`, `auth_failed`, `timeout` or
`connect_failed`).

## Authentication and account

| Method | Route | Description |
|---|---|---|
| GET | `/info` | Server version, registration state (`open`/`closed`), `needs_setup`, `features`, contact links and `environment` (e.g. `preprod` on a test server, `null` in production: show a banner when set) |
| GET | `/locales` | Languages the server has for emails and notifications: `{default, locales: [{code, name}]}`. No authentication |
| POST | `/auth/register` | `{email, name, password, device_name, platform, invite?, locale?, accept_terms?, terms_version?}` → `{user, tokens, verification_required}`. The first user becomes an administrator; with registration closed an invitation is needed. See [Terms of use](#terms-of-use) and [Email verification](#email-verification) |
| POST | `/auth/login` | `{email, password, device_name, platform, totp_code?}` → `{user, tokens, verification_required}` |
| POST | `/auth/verify-code` | `{email, code, device_name?, platform?, totp_code?}` → `{user, tokens, verification_required: false}`. Verifies the email with the six-digit code and signs in. No authentication. See [Email verification](#email-verification) |
| POST | `/auth/resend-code` | `{email}` → `{ok: true, resend_after: 60}`. Emails a new code. No authentication |
| POST | `/auth/refresh` | `{refresh_token}` → new tokens. Both rotate |
| POST | `/auth/logout` | Revokes the current device |
| GET | `/me` | `{user, device, plan, verification_required}` |
| PATCH | `/me` | `{name?, locale?}` → the updated `User` |
| DELETE | `/me` | `{password, totp_code?}`. Deletes the account and all its data |
| POST | `/me/password` | `{current_password, new_password}` |
| GET | `/me/2fa` | `{enabled, recovery_codes_left}` |
| POST | `/me/2fa/setup` | → `{secret, otpauth_url, qr_svg}`. A new secret, not enabled yet |
| POST | `/me/2fa/enable` | `{code}` → `{recovery_codes}` (10 single-use codes, shown only now) |
| POST | `/me/2fa/disable` | `{password, code}` (current code or recovery code) |
| GET | `/devices` | Sessions and devices: `{current, devices: [Device]}`. See [Sessions and devices](#sessions-and-devices) |
| POST | `/devices/sign-out-all` | `{include_current?}` → `{revoked}`. Signs out every other device (all of them with `include_current: true`) |
| DELETE | `/devices/{id}` | Signs a device out (this one too, if it is the current one) |
| GET | `/invites/{token}` | Public data of an invitation (no authentication): `{email, team, expires_at}` |

### Sessions and devices

Every sign-in is a device with its own tokens. `GET /devices` lists them,
most recently used first; `current` is the id of the device making the
request. Each `Device` has `id`, `name` and `platform` (as sent on sign-in),
`created_at` (signed in since), `last_seen_at`, `access_expires_at`,
`refresh_expires_at`, `push` (`apns`/`fcm` when it receives notifications)
and:

- `last_ip`: the last address it was used from: the connection's or, with
  `trust_forwarded_for`, the last one in `X-Forwarded-For` (the same one the
  sign-in limits use).
- `user_agent`: a short description of the client from its `User-Agent`
  (`Firefox 131 on Linux`, `Safari 18 on iOS`, `Termoak 0.4.0`...).

Both are recorded on sign-in and on refresh and, while the device is used,
with `last_seen_at` (at most once a minute). They are `null` for devices
signed in before the server recorded them, until they are used again.

Signing a device out (`DELETE /devices/{id}`, `POST /auth/logout`, `POST
/devices/sign-out-all`, a password reset, an administrator) takes effect at
once: its access token gets `401` from the next request (not when it
expires), its refresh token stops working, its push registration goes away
and its WebSockets (events, terminal, sharing) close with `signed_out`
(close code 4007). `POST /devices/sign-out-all` writes one audit entry
`auth.devices_revoked` with `{count, include_current}`; signing out one
device writes `auth.device_revoked`.

### Language

Every user has a `locale` (BCP 47, `en` by default). The server uses it for
emails and push notifications; apps can use it as the account's language.

- On registration, `locale` is optional. Without it, or if the server does
  not have that language, the server picks the best match from the
  `Accept-Language` header, and otherwise `en`.
- `PATCH /me` with `{"locale": "es"}` changes it. A language the server
  doesn't have is rejected with `invalid_locale`. Regional variants are
  normalized (`es-ES` → `es`).
- `GET /locales` lists the available languages.

### Terms of use

`GET /info` returns the server's `terms_url` and `privacy_url` (`null` when
not configured, `[web]` in the configuration). Clients that show them at
sign-up send, with the registration:

- `accept_terms`: `true` when the person ticked "I have read and accept the
  terms of use and the privacy policy".
- `terms_version`: the version of the documents they accepted (`"1.0"`), at
  most 16 characters (`invalid_terms_version` otherwise).

Both are optional, so apps that predate them can still sign up. With
`accept_terms: true`, the acceptance is recorded in the audit entry of the
registration (`auth.register`, readable in `GET /audit` and
`GET /admin/audit`):

```json
{"platform": "web", "invite": null, "terms": {"accepted": true, "version": "1.0"}}
```

On a server with `terms_url`, `accept_terms: false` is rejected with `400`
`terms_not_accepted`. Without `accept_terms`, nothing is recorded.

### Email, forgotten password and plans

| Method | Route | Description |
|---|---|---|
| POST | `/me/verify-email` | Sends the verification email again (once per minute; with a new code too when the server requires verification) |
| POST | `/auth/verify-email` | `{token}` from the email. No authentication |
| POST | `/me/email` | `{email, password}`. With email configured, the change stays pending (`{pending: true}`) until confirmed from the new address |
| POST | `/auth/confirm-email` | `{token}` from the email-change email. No authentication |
| POST | `/auth/forgot-password` | `{email}`. Same answer whether the account exists or not. No authentication |
| POST | `/auth/reset-password` | `{token, password}`. Signs out every device. No authentication |
| GET | `/plans` | Plan catalog `{default, plans}` (no authentication) |
| GET | `/me/plan` | Your plan, its limits and your usage: `{plan, usage: {teams_owned, server_sessions, ai_spent_usd, ai_credit_usd}}` |
| GET | `/downloads` | Files of the latest release of each component. No authentication. See [Updates and downloads](#updates-and-downloads) |

If the server requires a verified email (`[email] require_verification`), an
unverified account can only use `/me*`, `/auth/*` and `/devices*`; everything
else answers `403` with `email_not_verified`. See
[Email verification](#email-verification).

### Email verification

On a server that requires a verified email (`[email] require_verification`
with email configured; `GET /info` says `features.email_verification: true`,
and `features.email_verification_code: true` when the routes below exist),
new accounts confirm their address with a **six-digit code** sent by email.
Accounts created from an invitation sent to their own email, and the first
account of the server, are verified from the start.

1. `POST /auth/register` answers as always, plus `verification_required`:

   ```json
   {"user": {"email": "ana@example.com", "email_verified": false, ...},
    "tokens": {...}, "verification_required": true}
   ```

   The email (subject `Your Termoak code: 123456`, in the account's
   language) carries the code and, for older apps, the verification link.
   While `verification_required` is `true`, the tokens only reach the
   account itself (`/me*`, `/auth/*`, `/devices*`); clients should show a
   "check your email" screen instead of the app. The web app discards them
   (`POST /auth/logout`) and signs in with the tokens of step 2.
2. `POST /auth/verify-code` with `{"email": "ana@example.com", "code": "123456",
   "device_name": "Ana's iPhone", "platform": "ios"}` (`device` is accepted as
   another name for `device_name`; spaces and dashes in the code are
   ignored) verifies the email and signs in: the same response as the login,
   with `verification_required: false`. Errors:
   - `400 invalid_code`: wrong, expired, already used, or invalidated after
     five wrong tries; the same answer when there is no such unverified
     account.
   - `429 too_many_attempts`: too many failures for that email or IP (they
     count together with failed sign-ins: 10 per email or 30 per IP in 10
     minutes).
   - `401 totp_required` / `totp_invalid`: only if the account already has
     two-step verification; repeat with `totp_code`.
3. `POST /auth/resend-code` with `{"email": "ana@example.com"}` emails a new
   code (and link), which replaces the previous one. It always answers
   `{"ok": true, "resend_after": 60}`, whether or not the account exists or
   needs it, except when asked too often: at most once a minute and five
   times an hour per address, and thirty times an hour per IP, counting
   every request, answered with `429 too_many_attempts` and `retry_after`
   (seconds). Registration counts as the first email.

Codes last 15 minutes. Signing in to an unverified account
(`POST /auth/login`) still works and answers `verification_required: true`;
if the last code can no longer be used (expired, used up, invalidated), it
emails a new one, within the same limits. The link in the email
(`POST /auth/verify-email`, 48 hours) keeps working and then invalidates
the code. Any other route answers `403 email_not_verified` with the
account's `email` and `"verification": ["code", "link"]`, so clients can open
the code screen from anywhere.

Plans have a stable `id` (`free`, `pro`), English `name` and `description`,
`price_cents` (`0` = free, `null` = not published yet), `currency`,
`available` (`false` = coming soon), `for_teams`, `highlight`, `features` and
`limits`. `features` are stable ids (`encrypted_sync`, `ai_own_keys`,
`ai_credit`...), not display text: clients translate `plans.<id>.name`,
`plans.<id>.description` and `plans.feature.<feature>`, and fall back to the
English texts and the raw id. The built-in catalog has **Free** (everything
included; AI runs with your own API keys) and **Pro** (coming soon: priority
support and Termoak AI credit).

Plan limits (teams owned, members per team, open server sessions) answer
`403` with `plan_limit`. Server administrators have no limits.

Plans also decide the AI (see [AI with your own keys and AI credit](#ai-with-your-own-keys-and-ai-credit)):
`limits.server_ai` (can use the server's AI providers; `true` when not set)
and `limits.ai_credit_usd` (their monthly credit; when not set, `[ai]
monthly_budget_usd`, and without it no cap). The built-in Free plan has
`server_ai: false`; Pro has `server_ai: true` and `ai_credit_usd: 5`. In
`/me/plan`, `usage.ai_spent_usd` is what you spent this month (UTC) on the
server's providers and `usage.ai_credit_usd` your credit (`null` = none or
no cap).

### Push notifications

| Method | Route | Description |
|---|---|---|
| POST | `/push/register` | `{platform: apns\|fcm, token, sandbox?}`. Binds the token to the device of the session |
| DELETE | `/push/register` | Stops sending notifications to this device |
| POST | `/push/test` | Sends a test notification to this device |

The notification data carries `type` (`ai_approval`, `ai_finished`,
`session_shared`, `session_prompt`, `join_request`, `control_request`,
`team_added`, `test`) and the relevant ids (`task_id`, `approval_id`,
`session_id`, `prompt_id`, `participant`, `team_id`). `session_prompt`,
`join_request` and `control_request` are only sent when you are not watching
that session (no device of yours attached to it). In
APNs they go under the `termoak` key of the payload; in FCM, in `data`. The
text is in the recipient's language.

### Two-step verification

If the account has 2FA and the login has no `totp_code`, the answer is `401`
with `totp_required`; if the code is wrong, `totp_invalid`. The client asks
for the code and repeats the login. Both the 6-digit code of the
authenticator app (TOTP, RFC 6238, 30-second steps) and a recovery code
work. Each TOTP code is accepted only once.

After 10 failed attempts for the same email, or 30 from the same IP, within
10 minutes, the login answers `429` (`too_many_attempts`).

### Administration

Server administrators only.

| Method | Route | Description |
|---|---|---|
| GET, POST | `/admin/users` | Lists users or creates one `{email, name, password, is_admin}` |
| PATCH | `/admin/users/{id}` | `{name?, is_admin?, disabled?, plan?, email_verified?}`. Disabling signs the user out everywhere |
| POST | `/admin/teams/{id}/plan` | `{plan}`. Plan of a team |
| POST | `/admin/users/{id}/password` | `{password}`. Sets a new password and signs the user out |
| POST | `/admin/users/{id}/2fa/reset` | Removes two-step verification |
| GET | `/admin/users/{id}/devices` | The user's devices (with `last_ip` and `user_agent`) |
| DELETE | `/admin/users/{id}/devices/{device_id}` | Signs out one of the user's devices |
| GET, POST | `/admin/invites` | Lists or creates invitations `{email?, team_id?, team_role?, is_admin, expires_in_hours?, send_email?}` → `{invite, token, server, url, web_url, emailed}` |
| DELETE | `/admin/invites/{id}` | Revokes an unused invitation |
| GET | `/admin/audit?limit=&before=` | Audit log of the whole server, newest first |

An invitation lets someone sign up even when registration is closed. It can
be bound to an email, make the account an administrator and add it to a
team. It expires after 7 days unless told otherwise (`0` = never). The
`token` is only shown when it is created; `url` is the
`termoak://invite?server=…&token=…` link that opens the app.

## Teams

| Method | Route | Description |
|---|---|---|
| GET, POST | `/teams` | Your teams (all of them, for server administrators), or creates one `{name}` (you become its owner) |
| GET, PATCH, DELETE | `/teams/{id}` | Shows, renames `{name}` or deletes it. Deleting it revokes what was shared with it |
| GET, POST | `/teams/{id}/members` | Members, or adds one `{email, role}` |
| PATCH, DELETE | `/teams/{id}/members/{user_id}` | Changes the role `{role}` or removes the member. Removing yourself leaves the team |
| GET, POST | `/teams/{id}/invites` | Pending invitations, or invites by email `{email, role}`: someone who already has an account joins directly (`{added: true}`); otherwise they get an invitation to sign up (`{added: false, token, url, web_url, emailed}`) |
| DELETE | `/teams/{id}/invites/{invite_id}` | Revokes a team invitation |

Roles: `member` (sees what is shared with the team), `admin` (also manages
members and invitations and renames the team) and `owner` (also deletes the
team and appoints or removes owners). A team always keeps at least one
owner. Whoever leaves a team immediately loses access to the sessions shared
with it, and to its vaults (their server sessions on those hosts close).
Deleting a team deletes its vaults with their items (`GET /vaults` shows the
item counts first).

## Vaults

A **vault** is the unit of ownership, sharing and sync of entities (hosts,
groups, identities, keys, snippets, forwards, known hosts, memories). Every
item is in exactly one vault (`vault_id`).

- Every user has a **personal** vault whose id is the user id. It cannot be
  shared, deleted or left.
- Users create **shared** vaults (they own them) and team owners and admins
  create **team** vaults (the team owns them).
- **Roles:** `use_only` < `editor` < `manager`. `manager` is computed: the
  owner of a shared vault, the owners and admins of the team of a team
  vault. Grants give `editor` or `use_only` to a user or to a team (you must
  belong to it). Plain members of the owning team get the vault's
  `team_member_role` (default `editor`; `null`: no access). The effective
  role is the maximum of every grant.
- **Use-only** members use the items (server sessions, SFTP, exec, the AI,
  `/hosts/{id}/test`) but never see their secrets: no `secret` in sync,
  `secret_hidden: true` in listings, `GET /{col}/{id}/secret` answers
  `secret_hidden`. For connections from their own device the app asks for
  just-in-time credentials (`POST /hosts/{id}/credentials`), unless the
  vault is **Strict** (`settings.use_only_local: false`): then they only
  connect through the server.
- References (`group_id`, `parent_id`, `settings.identity_id`,
  `settings.key_id`, `settings.jump_host_ids`, `settings.startup_snippet_id`,
  an identity's `key_id`, `host_id` of forwards and memories) stay inside a
  vault: REST refuses others (`cross_vault_reference`) and the server
  resolves a reference outside the host's vault as missing.
- Secrets are encrypted with a key per vault, wrapped with the server's
  master key; deleting a vault deletes its key.

| Method | Route | Who | Description |
|---|---|---|---|
| GET | `/vaults` | any | Vaults you can access (personal first) with `role`, `owner_name`, `member_count` and `item_counts` |
| POST | `/vaults` | any (team: owners, admins) | `{name, description?, color?, icon?, team_id?, team_member_role?, settings?}` → `Vault` |
| GET | `/vaults/{id}` | member | `Vault` |
| PATCH | `/vaults/{id}` | manager | `{name?, description?, color?, icon?, team_member_role?, settings?}` (`null` clears `color`, `icon`, `team_member_role`). Personal: only name, color, icon |
| DELETE | `/vaults/{id}?confirm=<name>` | manager | Deletes it with its items and keys. Members lose access (`vault/access` with `reason: deleted`) |
| POST | `/vaults/{id}/leave` | member with a direct grant | Gives up your own grant |
| GET | `/vaults/{id}/members` | member | `[VaultMember]`: implicit ones first (`implicit: true`: the owner or the team's owners and admins as managers, and the owning team with `team_member_role`), then the grants |
| POST | `/vaults/{id}/members` | manager | `{email, role}` or `{team_id, role}` → `VaultMember`. Unknown email: `user_not_found` |
| PATCH | `/vaults/{id}/members/{member_id}` | manager | `{role}` |
| DELETE | `/vaults/{id}/members/{member_id}` | manager | Revokes the grant |
| POST | `/vaults/{id}/transfer` | see below | Moves or copies items into this vault |
| GET | `/vaults/{id}/audit` | manager | `?before=&limit=`: the vault's audit (`vault.*`, `secret.reveal`, `secret.use`, sessions...) |

`Vault`: `{id, kind: personal|shared|team, name, description, color, icon,
owner_user_id, owner_team_id, team_member_role, crypto: server, key_version,
settings: {use_only_local}, rev, created_by, created_at, updated_at, role,
owner_name, member_count, item_counts}`. New enum values may appear later:
`kind`, `role` and `crypto` decode unknown values as `unknown` (a role
`unknown` gives no access).

When access is revoked (a grant removed, a vault or team deleted, a team
member removed, an account disabled or deleted) the user's server sessions
on hosts of that vault close (`session_closed` with reason
`vault_access_revoked`) and the server drops its pooled connections. A
downgrade to Use-only keeps the sessions running. Session shares are
independent of vaults: sharing a terminal never grants its vault.

### Move and copy

```
POST /vaults/{target}/transfer
{"mode": "move" | "copy", "items": [{"kind": "host", "id": "…"}],
 "dependencies": "auto" | "none", "dry_run": false, "force": false}
→ {"moved": [{"kind", "id"}], "copied": [{"kind", "from", "to"}], "reused": [{"kind", "from", "to"}],
   "detached": [{"kind", "id", "field"}], "warnings": [{"code", "kind", "id"}], "rev": 1234, "dry_run": false}
```

- A group brings its subgroups and their hosts; a host brings its forwards,
  its memories and (copy; move if nothing else uses them) its known hosts.
- `dependencies: auto`: the identity, key, jump hosts and startup snippet of
  each host (from its effective settings). A move moves a dependency when
  everything that uses it moves too, otherwise copies it (new id) and
  rewrites the references; a copy copies it (a key with the same fingerprint
  in the target is reused). `none` clears those references (`detached`).
- An item that leaves its group behind gets the inherited settings written
  into its own (`group_id: null`), so it connects the same way.
- Moving a key or identity explicitly while items that stay still use it:
  `still_referenced`, unless `force: true` (their references are detached).
- Move: Editor on the source and target vaults; the ids are kept and the
  source vault gets a departure (sync v2 `removed`, a deletion for old apps).
  Copy: Editor on the target and the source (Use-only members can copy
  snippets only); a copy never carries secrets out of a vault where you are
  not Editor. Audited as `vault.transfer` in every vault involved.
- `dry_run: true` answers the same without writing (for the confirmation).

## Entities

All of them follow the same CRUD pattern:

| Collection | Route |
|---|---|
| Hosts | `/hosts` |
| Groups | `/groups` |
| Identities | `/identities` |
| SSH keys | `/keys` |
| Snippets | `/snippets` |
| Port forwards | `/forwards` |
| Known hosts | `/known-hosts` |
| AI memories | `/memories` |

| Method | Route | Description |
|---|---|---|
| GET | `/{col}` | List, from every vault you can use (`?vault_id=` for one). Each item has `vault_id`, `updated_by` and `secret_hidden`. Never includes secrets |
| POST | `/{col}` | Create. The body is the entity plus `secret` (optional), `sync_mode` (`synced` or `device_only`) and `vault_id` (default: your personal vault; Editor) |
| GET | `/{col}/{id}` | One entity. Without access to its vault: `404` |
| PUT | `/{col}/{id}` | Update (Editor). Without `secret` the current one is kept, `"secret": null` deletes it and an object replaces it. Another `vault_id`: `use_transfer` |
| DELETE | `/{col}/{id}` | Delete (Editor; leaves a tombstone for sync) |
| GET | `/{col}/{id}/secret` | Reveals the secret (Editor; Use-only: `secret_hidden`). Audited as `secret.reveal` with the vault |

Other entity routes:

| Method | Route | Description |
|---|---|---|
| POST | `/keys/generate` | `{label, key_type, comment?, passphrase?, store_passphrase?, vault_id?}`. Generates the key on the server |
| POST | `/keys/import` | `{label, private_key, passphrase?, store_passphrase?, certificate?, sync_mode?, vault_id?}` |
| POST | `/hosts/{id}/test` | Tests the connection (any role); returns the detected OS (saved by Editors only) and the latency. `?trust=true` accepts a new host key: it is saved in the host's vault if you are Editor there, otherwise in your personal vault |
| GET | `/hosts/{id}/effective` | Effective settings after applying groups and identity (any role) |
| POST | `/hosts/{id}/credentials` | Just-in-time credentials for a connection from this device (below) |
| POST | `/exec` | `{host_ids, command \| snippet_id + variables, timeout_secs?}`. Runs in parallel; any role, each host checked on its own |
| POST | `/sync` | Legacy sync (below) |
| POST | `/vaults/sync` | Sync v2 (below) |
| GET | `/audit` | `?before=&limit=` |

### Just-in-time credentials

`POST /hosts/{id}/credentials {purpose: "ssh" | "sftp" | "forward"}` →
`{vault_id, expires_at, hops: [{host_id, address, port, username, password?,
key?: {private_key, passphrase?, certificate?}, proxy_password?}]}` with the
jumps first and the host last. Editors always; Use-only members only if the
vault is not Strict (`use_only_strict`). The answer has `Cache-Control:
no-store`; the app keeps it in memory only until authentication ends and
never stores or logs it. Limited to 30 per minute per user (`rate_limited`)
and audited as `secret.use` (device and purpose) in the vault. This is
interface protection plus auditing, not cryptography: anyone with the token
can call it, which is what Strict vaults are for.

### Sync v2

`POST /vaults/sync` (when `/info` has `features.sync_v2`):

```json
{"vaults": [{"vault_id": "…", "cursor": 1234, "role": "editor"}],
 "changes": [SyncRecord],
 "limit": 2000}
```

→

```json
{"vaults": [Vault], "cursors": [{"vault_id", "cursor", "role"}],
 "changes": [SyncRecord], "removed": [{"id", "vault_id", "kind", "rev"}],
 "accepted": ["…"], "rejected": [{"id", "code", "message"}],
 "warnings": [{"id", "code", "field"}], "resync": ["…"], "more": false}
```

- `vaults` is **authoritative**: a vault the store has that is not listed
  was lost (revoked or deleted): delete its rows (no tombstones) and count
  its unsynced changes as discarded.
- Cursors are per vault: "the highest revision received for that vault"
  (revisions are global to the server, so a newly granted vault starts at
  0 without touching the others). Keep the returned `cursors`.
- Pushed records carry `vault_id` (missing: the personal vault). Last writer
  wins by `updated_at`. An item moved meanwhile is changed where it is now
  if you are Editor there. Rejections: `vault_read_only`, `vault_not_found`,
  `id_in_use` (an item you cannot see) and `invalid` (keep it dirty). A
  reference to another vault is accepted with a `warnings` entry. A push
  older than the server's version is accepted and the server's version comes
  back in `changes`. `base_rev` (optional) is logged when the client
  overwrites a newer revision.
- `changes` always have `vault_id`. In Use-only vaults the `secret` is
  withheld and `has_secret: true` says there is one.
- `removed`: items that left a vault (moved): delete the local row where
  `vault_id` matches.
- `resync`: your role changed between Use-only and Editor in these vaults:
  drop their local rows (secrets must come, or go). Their `changes` in this
  response already start from 0.
- `more: true`: the limit (default 2000, max 5000) cut the answer; call
  again with the new cursors.
- Sync on the `vault/changed` and `vault/access` events, after local saves,
  periodically and after a `vault_read_only` from REST.

### Legacy sync

`POST /sync {since, changes: [SyncRecord]}` → `{rev, changes, accepted}` is
what apps before vaults use. On a server with vaults it serves **only the
personal vault**: `changes` are the personal vault's records after `since`,
and items that left it (moved to another vault) come as deletions
(`deleted: true`), so an old app drops them. Pushes land in the personal
vault; an existing item that is now in another vault where you are Editor
is changed there (and stays out of the answer). `rev` is the server's
current revision.

## SFTP

All routes live under `/hosts/{id}/sftp/`:

| Method | Route | Parameters |
|---|---|---|
| GET | `home` | — |
| GET | `list` | `?path=` |
| GET | `stat` | `?path=` |
| GET | `download` | `?path=`. Streamed response |
| POST | `upload` | `?path=`. The body is the content, streamed, with no size limit |
| POST | `mkdir` | `{path, parents?}` |
| POST | `rename` | `{from, to}` |
| POST | `delete` | `{path, recursive?}` |
| POST | `chmod` | `{path, mode}` |

## Server sessions

| Method | Route | Description |
|---|---|---|
| GET | `/sessions` | `{active, shared, recent}` |
| POST | `/sessions` | `{host_id, cols, rows, title?, record?}`. Opens a session that lives on the server |
| GET | `/sessions/{id}` | State, size, `participants` and `driver` (see below) |
| PATCH | `/sessions/{id}` | `{title}` |
| DELETE | `/sessions/{id}` | Closes the session |
| GET | `/sessions/{id}/ws` | Terminal WebSocket. See [WEBSOCKET-PROTOCOL.md](WEBSOCKET-PROTOCOL.md) |
| GET | `/sessions/{id}/recording` | asciicast v2 recording (`.cast`). Owner only. See [Who typed what](#who-typed-what) |
| GET | `/sessions/{id}/recording/authors` | Owner only. Who typed in the recording: `{started_at, authors: [{time, participant?, name, kind}]}` (see below) |
| GET | `/sessions/{id}/shares` | Owner. Every share (also revoked and expired ones), with `user_email`/`user_name` or `team_name`, `active` (not revoked nor expired) and `participants` (people inside with it now) |
| POST | `/sessions/{id}/shares` | Owner. `{email? \| team_id? \| link: true, permission: view\|control, expires_in_minutes?, require_approval?, auto_grant?, control_minutes?}`. Returns `{share, token?, link?, app_link?}` (the token only once). `404 session_ended` if the session already ended |
| DELETE | `/sessions/{id}/shares` | Owner. Stops sharing: revokes every share and sends everyone but the owner away (`revoked`). Returns `{ok, revoked}` (shares that were active) |
| PATCH | `/sessions/{id}/shares/{share_id}` | Owner. `{permission?, expires_in_minutes?, expires_at?, no_expiry?, require_approval?, auto_grant?, control_minutes?, no_control_limit?}`. Applied live to whoever uses it; returns the share as in the list |
| DELETE | `/sessions/{id}/shares/{share_id}` | Owner. Revokes the share; whoever joined with it leaves, unless they have another valid share |
| POST | `/relay` | `{title, cols, rows, host_id?}`. Shares a local terminal. Returns `host_ws_path` |
| GET | `/join/{token}` | Public data of a link share (no authentication): `{session: {id, title, kind, state, created_at, cols, rows, access, participants}, owner, permission, require_approval, expires_at, ws_path}`. `participants` is a count: it never lists who is inside |

#### Sharing

A session can be shared with users of the server (`email`), with every
member of a team (`team_id`) or with a link (`link: true`, anyone who has it,
no account needed; signed-in users can use links too). One person drives at
a time: the owner always can, everyone else joins read-only and the share's
`permission` is the most the owner can hand over (`view`: only watch;
`control`: can ask for the keyboard). Details in
[WEBSOCKET-PROTOCOL.md](WEBSOCKET-PROTOCOL.md#participants-and-the-keyboard).

| Field | Default | Meaning |
|---|---|---|
| `permission` | `view` | `view` or `control` |
| `expires_in_minutes` | none | Expiry. It also sends away whoever is already inside when it passes |
| `require_approval` | `true` for links, `false` otherwise | Whoever joins waits until the owner lets them in |
| `auto_grant` | `false` | Requests for the keyboard are granted without asking the owner |
| `control_minutes` | none | With `auto_grant`: each automatic grant lasts at most this many minutes (1-240), then the keyboard goes back to the owner. `PATCH` with `no_control_limit: true` removes it |

`PATCH` changes a share live: going down to `view` takes the keyboard away
at once; `expires_at` (ms) or `expires_in_minutes` set a new expiry and
`no_expiry: true` removes it; turning `require_approval` off lets in whoever
is waiting with that share. A revoked share cannot be changed
(`409 share_revoked`).

When a share is revoked or changed, a team share is revoked, a member
leaves a team or an account is deleted or disabled, the server checks again
everyone affected: whoever has another valid share keeps the best one, the
rest leave with `revoked` (or `expired`). The best share is the one with the
highest permission, then one without a waiting room, then a direct one.

`participants` in a session (`GET /sessions`, `GET /sessions/{id}`, the
WebSocket `hello`) lists people, not sockets (see
[Participant](WEBSOCKET-PROTOCOL.md#participant)); `driver` is the
participant with the keyboard (`null`: the owner) and `driver_until` (ms,
only while it is a timed grant) when the keyboard goes back to the owner.
The owner can hand it over for a while: `control_grant` with `minutes`
over the WebSocket. Only the owner sees user
ids and share ids, in `participants` and in the old `viewers` list.

Everything is audited in the owner's log (`/audit`): `session.join` (once
per person, not per reconnect; guests with their name, actor
`guest:<participant>`), `session.leave`, `session.join_requested`,
`session.join_allowed`, `session.join_denied`, `session.control_requested`,
`session.control_granted`, `session.control_released`,
`session.control_taken`, `session.control_denied`,
`session.control_expired` (a timed grant ended), `session.control_period`
(see below), `session.kicked` (with `reason`: `kicked`, `revoked` or
`expired`), `session.share`, `session.share_changed`,
`session.share_revoked` and `session.sharing_stopped`.

#### Who typed what

One person drives at a time, so every input that reaches the terminal has
an author: the owner, the driver, or the AI (on the owner's behalf).

- **Audit**: each period someone other than the owner had the keyboard is
  one `session.control_period` entry when it ends (not one per keystroke),
  with actor `user:<id>` or `guest:<participant>` and `detail`
  `{participant, name, kind, from, to, until?, bytes, owner_bytes, reason}`:
  `from`/`to` in ms, `until` the end of a timed grant, `bytes` what they
  typed, `owner_bytes` what the owner typed meanwhile, and `reason` why it
  ended (`released`, `taken`, `granted` to someone else, `expired`, `left`,
  `removed`, `permission` (their share went down to `view`) or
  `session_ended`).
- **Recordings** (sessions with `record`): the `.cast` file keeps the
  standard asciicast v2 events and adds an author mark each time the author
  changes, right before their input: an event of type `a` whose data is
  the author as a JSON string,
  `[12.5, "a", "{\"participant\":\"…\",\"name\":\"Zoe\",\"kind\":\"guest\"}"]`
  (`kind`: `owner`, `user`, `guest` or `ai`; no `participant` for the AI).
  It applies to all the input that follows until the next mark. Players
  that do not know it skip it (asciinema ignores unknown event types). The
  marks are written even when the input itself is not recorded
  (`[sessions] record_input = false`, the default): they say who typed and
  when, not what. `GET /sessions/{id}/recording/authors` returns them
  already parsed: `{"started_at": 1791198048000, "authors": [{"time": 12.5,
  "participant": "…", "name": "Zoe", "kind": "guest"}]}` (`time`: seconds
  since `started_at`). Sessions kept by a session holder older than the
  server have no marks until the holder is restarted.

### Files through the server

SFTP downloads (`/hosts/{id}/sftp/download`) and recordings
(`/sessions/{id}/recording`) are streamed; uploads
(`/hosts/{id}/sftp/upload?path=`) carry the file as the body. The mobile
library writes them straight to disk with progress.

## AI

| Method | Route | Description |
|---|---|---|
| GET | `/ai/providers` | Providers, models and whether they are available (`reason_code` and `reason` when not; see below) |
| GET | `/ai/tasks` | `?limit=` |
| POST | `/ai/tasks` | `{prompt, title?, mode?, provider?, host_ids?, session_id?, effort?}` |
| GET | `/ai/tasks/{id}` | The task and its messages |
| DELETE | `/ai/tasks/{id}` | Deletes the task |
| POST | `/ai/tasks/{id}/messages` | `{text}`. Continues the conversation |
| POST | `/ai/tasks/{id}/cancel` | Cancels the task |
| POST | `/ai/tasks/{id}/mode` | `{mode: read_only\|ask\|confirm\|auto}` (also while the task is stopped: it applies to the next messages) |
| GET | `/ai/tasks/{id}/events` | `?after=<seq>`. Stored events, to catch up |
| POST | `/ai/tasks/{id}/approvals/{approval_id}` | `{approve, always?}` |
| GET | `/ai/approvals` | Pending approvals of all your tasks |
| POST | `/ai/suggest` | `{request, context?, provider?}` → suggested command |
| POST | `/ai/explain` | `{text, question?, context?, provider?}` → explanation of an output or an error |
| POST | `/mcp` | MCP server (JSON-RPC 2.0, HTTP transport). See [AI.md](https://github.com/TermoakSSH/core/blob/main/docs/AI.md) |
| GET | `/me/ai/keys` | Your own API keys: `[{provider, label, model, hint, created_at, updated_at}]`. Never the keys: `hint` is their last 4 characters |
| PUT | `/me/ai/keys/{provider}` | `{key?, model?}` → the saved key (same shape as above). With `key`, replaces the one you had. Without it, only changes the model of the saved key (`model` absent or `null` = the provider's default); `404` if you have none |
| DELETE | `/me/ai/keys/{provider}` | → `{ok: true, deleted}` |
| POST | `/me/ai/keys/{provider}/test` | `{key?}` (optional body) → `{ok, error, status}`. Checks the key in the body, or the saved one, with a call to the provider that spends nothing. At most 10 per minute (`429`, `too_many_attempts`) |
| GET | `/me/ai/access` | `{own_keys, server_ai, credit_usd, spent_usd, remaining_usd, providers}`. See below |

### AI with your own keys and AI credit

Who pays for the AI depends on the plan:

- With your **own API key** for a provider, that provider uses it instead
  of the server's key, with the model you chose (or the provider's
  default). It never uses the plan's credit. Providers that accept your key:
  `claude` (Anthropic), `gpt` (OpenAI), `openrouter` and `opencode-api`
  (OpenCode Go). The CLI-based ones (`codex`, `opencode`) and `local` are
  server-only.
- The **server's providers** (its API keys, the Codex subscription...) are
  only used when your plan has `server_ai`, within its monthly credit.
  Once it is spent, they answer `403` with `ai_budget_exceeded`, unless you
  have a key of your own.
- Without either, AI requests (tasks, messages, `/ai/suggest`,
  `/ai/explain`) answer `403` with `ai_key_required`: clients show "add your
  API key in Settings → AI".

The provider chain of a request is: the requested provider (with your key
if you have one), then the providers you have a key for, then (if your plan
allows it and there is credit left) the server's chain. Your own keys go
first even without asking for them.

Keys are stored encrypted with the server's master key and are never
returned. `unknown_provider` (400) means the provider does not accept your
key. The key must be 1 to 512 printable characters without spaces; the
model, at most 128.

`GET /me/ai/access` explains your situation:

```json
{
  "own_keys": ["claude"],
  "server_ai": true,
  "credit_usd": 5.0,
  "spent_usd": 1.25,
  "remaining_usd": 3.75,
  "providers": [{"provider": "claude", "label": "Claude", "default_model": "claude-opus-5", "models": ["claude-opus-5", "..."]}]
}
```

`credit_usd` and `remaining_usd` are `null` without credit (no server AI,
or no cap). `spent_usd` only counts the server's providers, this month
(UTC), by their credit cost: what they cost the server or, for the server's
subscriptions (Codex with ChatGPT, OpenCode Go...) and providers without a
price, their tokens at a reference price (see `docs/AI.md`, "Cost").
`providers` are the ones that accept your own key.

In `GET /ai/providers`, `available` already takes your plan and your keys
into account; `accepts_own_key` and `uses_own_key` tell which providers
accept your key and which ones run with it. When a provider is not
available, `reason_code` says why (clients translate it):

| `reason_code` | Meaning |
|---|---|
| `not_configured` | The server's provider cannot run (missing key, executable, login...) |
| `own_key_required` | Your plan does not include the server's AI; add your own key for it |
| `plan` | Not included in your plan (and it does not accept your own key) |

`reason` is a short English text. For `not_configured` it is the detailed
cause (paths, environment variables...) only for administrators; everybody
else gets `"not available on this server"`. Task `usage` events carry
`cost_micros` (real cost), `credit_micros` (taken from your credit; 0 with
your own key) and `own_key`. A task's `cost_micros` is its real cost.

## Updates and downloads

No authentication. They only exist when the server has `[updates]
github_repo` or `[updates.repos]` configured (see
[DEPLOYMENT.md](DEPLOYMENT.md)). The desktop app, the server, the CLI and
the mobile apps are released separately (`desktop-vX.Y.Z`, `server-vX.Y.Z`,
`cli-vX.Y.Z`, `android-vX.Y.Z`, `ios-vX.Y.Z`), each from its own repository
or all from one; for each one, the latest release is used, skipping drafts
and pre-releases.

| Method | Route | Description |
|---|---|---|
| GET | `/updates/latest.json` | Signed manifest of the latest desktop release, with the downloads pointing to this server. `404` if there is none |
| GET | `/updates/download/{file}` | A file of the latest release of a component, streamed |
| GET | `/api/v1/downloads` | What can be downloaded, for a downloads page |

`/api/v1/downloads` answers:

```json
{
  "version": "0.2.0",
  "tag": "desktop-v0.2.0",
  "components": {
    "desktop": {"version": "0.2.0", "tag": "desktop-v0.2.0"},
    "server": {"version": "0.3.1", "tag": "server-v0.3.1"},
    "cli": {"version": "0.2.0", "tag": "cli-v0.2.0"}
  },
  "files": [
    {"name": "Termoak-linux-x86_64.AppImage", "size": 21936632, "os": "linux",
     "kind": "app", "component": "desktop", "url": "https://…/updates/download/Termoak-linux-x86_64.AppImage"}
  ]
}
```

`version` and `tag` are the desktop ones (`null` if none is published).
`components` may also include `android`. `os` is `windows`, `macos`,
`linux`, `android` or `any`. `kind` is `app` (installer or APK), `update`
(the macOS `.app` used to update), `app-archive` (standalone desktop
binary), `manifest`, `server`, `cli` or `other`. In old `vX.Y.Z` releases,
the same `termoak-vX.Y.Z-…` archive carries both the server and the CLI.

## Events

`GET /events/ws` is a WebSocket with the user's notices, including vault
changes and access changes (`{"type":"vault",...}`). See
[WEBSOCKET-PROTOCOL.md](WEBSOCKET-PROTOCOL.md).
