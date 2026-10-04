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
the old one while clients still use it. `GET /info` returns the server
version.

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
| `session_ended` | 404 | The session is no longer active |
| `recording_not_found` | 404 | The session has no recording |
| `title_required` | 400 | The title cannot be empty |
| `cannot_invite_self` | 400 | You cannot share a session with yourself |

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
| GET | `/info` | Server version, registration state (`open`/`closed`), `needs_setup`, `features` and contact links |
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
| GET | `/devices` | Devices signed in |
| DELETE | `/devices/{id}` | Signs a device out |
| GET | `/invites/{token}` | Public data of an invitation (no authentication): `{email, team, expires_at}` |

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
`session_shared`, `session_prompt`, `team_added`, `test`) and the relevant
ids (`task_id`, `approval_id`, `session_id`, `prompt_id`, `team_id`). In
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
| GET | `/admin/users/{id}/devices` | The user's devices |
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
with it.

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
| GET | `/{col}` | List. Never includes secrets |
| POST | `/{col}` | Create. The body is the entity plus `secret` (optional) and `sync_mode` (`synced` or `device_only`) |
| GET | `/{col}/{id}` | One entity |
| PUT | `/{col}/{id}` | Update. Without `secret` the current one is kept, `"secret": null` deletes it and an object replaces it |
| DELETE | `/{col}/{id}` | Delete (leaves a tombstone for sync) |
| GET | `/{col}/{id}/secret` | Reveals the secret. Audited |

Other entity routes:

| Method | Route | Description |
|---|---|---|
| POST | `/keys/generate` | `{label, key_type, comment?, passphrase?, store_passphrase?}`. Generates the key on the server |
| POST | `/keys/import` | `{label, private_key, passphrase?, store_passphrase?, certificate?, sync_mode?}` |
| POST | `/hosts/{id}/test` | Tests the connection; returns the detected OS and the latency. `?trust=true` accepts a new host key |
| GET | `/hosts/{id}/effective` | Effective settings after applying groups and identity |
| POST | `/exec` | `{host_ids, command \| snippet_id + variables, timeout_secs?}`. Runs in parallel |
| POST | `/sync` | `{since, changes: [SyncRecord]}` → `{rev, changes, accepted}` |
| GET | `/audit` | `?before=&limit=` |

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
| GET | `/sessions/{id}` | State, viewers and size |
| PATCH | `/sessions/{id}` | `{title}` |
| DELETE | `/sessions/{id}` | Closes the session |
| GET | `/sessions/{id}/ws` | Terminal WebSocket. See [WEBSOCKET-PROTOCOL.md](WEBSOCKET-PROTOCOL.md) |
| GET | `/sessions/{id}/recording` | asciicast v2 recording (`.cast`) |
| GET, POST | `/sessions/{id}/shares` | `{email? \| team_id? \| link: true, permission: view\|control, expires_in_minutes?}` |
| DELETE | `/sessions/{id}/shares/{share_id}` | Revokes the share and kicks out whoever joined with it |
| POST | `/relay` | `{title, cols, rows, host_id?}`. Shares a local terminal. Returns `host_ws_path` |
| GET | `/join/{token}` | Public data of a link share (no authentication) |

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

`GET /events/ws` is a WebSocket with the user's notices. See
[WEBSOCKET-PROTOCOL.md](WEBSOCKET-PROTOCOL.md).
