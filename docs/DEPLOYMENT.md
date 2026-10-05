# Deployment

The server is a single binary, `termoak-server`, that stores everything in
SQLite inside `data_dir`.

## Docker

```sh
docker compose up -d
```

`docker-compose.yml` uses the published server image and keeps the data in
the `termoak-data` volume. To build the image locally from the `Dockerfile`
instead, run `docker compose build`. AI keys are passed as environment
variables.

To use Codex with your ChatGPT subscription, sign in once inside the
container. The image does not include the Codex CLI, so mount it first or
build a derived image:

```sh
docker compose exec -e CODEX_HOME=/var/lib/termoak/codex termoak codex login --device-auth
```

## systemd

```sh
sudo useradd --system --home /var/lib/termoak termoak
sudo install -m 755 termoak-server /usr/local/bin/
sudo install -d -m 755 /etc/termoak
sudo install -m 640 -g termoak deploy/config.example.toml /etc/termoak/config.toml
sudo install -m 600 /dev/null /etc/termoak/env   # ANTHROPIC_API_KEY=..., OPENCODE_GO_KEY=...
sudo install -m 644 deploy/termoak-server.service deploy/termoak-sessions.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now termoak-sessions termoak-server
```

`termoak-sessions` is the session holder: a separate process that keeps the
SSH connections of server sessions open, so updating or restarting
`termoak-server` does not cut them (when it comes back, the server recovers
every session with its history and the apps reconnect on their own). Enable
it in the configuration:

```toml
[sessions]
holder_socket = "/run/termoak-sessions/sessions.sock"
```

Without it, sessions live in the server process and close when it restarts.
Restarting the holder does cut them; it is only needed when its protocol
changes (`deploy server` detects and reports it) or to pick up new SSH engine
code (`RESTART_SESSIONS=1 scripts/release-local.sh deploy server`).
A holder older than the server keeps working; additions it does not know
about are simply not used until it restarts (for example, an older holder
does not mark who typed in recordings: the server logs it when it
connects).

The first user to sign up becomes an administrator. You can also create it
from the console:

```sh
sudo -u termoak TERMOAK_PASSWORD='…' /usr/local/bin/termoak-server \
  --config /etc/termoak/config.toml user add you@example.com --name "Your Name" --admin
```

Use the full path: root's `PATH` may not include `/usr/local/bin`, or may
start with directories the `termoak` user cannot read.

To update the server, build and install the new version (see
[Publishing releases](#publishing-releases)):

```sh
scripts/release-local.sh build server
sudo scripts/release-local.sh deploy server
```

## TLS

The simplest option is Caddy:

```
termoak.example.com {
    reverse_proxy 127.0.0.1:7722
}
```

Caddy forwards WebSockets with no extra configuration. With nginx, add
`proxy_http_version 1.1`, the `Upgrade` and `Connection "upgrade"` headers,
and raise `proxy_read_timeout` so long sessions are not cut.

You can also serve TLS directly with `tls_cert` and `tls_key` in `[server]`.

Set the public URL in `public_url` or `TERMOAK_PUBLIC_URL`. It is used in
shared session links, invitations and email links.

Behind Caddy or nginx, set `trust_forwarded_for = true` in `[server]` so the
per-IP sign-in rate limit uses the real client IP (Caddy adds
`X-Forwarded-For` on its own; in nginx, use
`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`). Without a
proxy, leave it `false`.

On a test or pre-production server, set `environment = "preprod"` (any
name) in `[server]`: `GET /api/v1/info` returns it as `environment` and the
web apps show a "pre-production" banner. Leave it unset in production.

## Accounts

`registration` in `[server]` decides who can create accounts:

- `first_user` (default): only the first account, which becomes the
  administrator. After that, nobody can sign up on their own.
- `open`: anyone can sign up. With `[email] require_verification` they must
  confirm their email with the six-digit code (or the link) they get by
  email.
- `closed`: nobody; administrators create the accounts.

To add someone when registration is not open:

- **Invitation** (recommended): `termoak admin invite --email ana@example.com`
  or the administration panel of the desktop app. With email configured, it
  is sent automatically. The invitee signs up with the code or opens the
  `termoak://invite?...` link, and can join a team directly (`--team`).
- **Directly**: `termoak-server user add` on the server machine, the
  desktop administration panel or `POST /api/v1/admin/users`.

If someone loses the phone with their two-step verification and their
recovery codes, an administrator removes it with `termoak admin reset-2fa`.

## Web app

The server serves a basic web app at `/`: sign in and sign up, password
reset, email verification and email change confirmation, sessions with a
terminal in the browser, teams and account settings. Shared session links
and invitations open web pages (`/join/...`, `/invite/...`) that explain how
to join or sign up. The app is embedded in the binary and uses the same API
as the other apps. Disable it with `[web] enabled = false`.

Administration is not part of the web app: use the desktop app, the CLI
(`termoak admin`) or `/api/v1/admin/*`.

The basic web app also answers `/robots.txt` with `Disallow: /`: a
self-hosted server is not meant to show up in search engines. To allow it,
serve your own front-end (below) with its own `robots.txt`.

To serve your own front-end instead, point `[web] dir` to its directory: it
needs an `index.html`, every other file is served under `/assets/`, and every
`GET` outside the API returns `index.html`. termoak.com serves this way the
[public website](https://github.com/TermoakSSH/public-web) together with its full web app.
`TERMOAK_WEB_DIR=<dir>` does the same while developing, without caching.

A front-end directory can also have:

| File in the directory | Served at |
|---|---|
| `robots.txt`, `sitemap.xml`, `favicon.ico`, `favicon.svg`, `apple-touch-icon.png`, `apple-touch-icon-precomposed.png`, `site.webmanifest`, `manifest.webmanifest` | The same name at the root (`/robots.txt`...) |
| `.well-known/<file>` (`security.txt`, `org.flathub.VerifiedApps.txt`...) | `/.well-known/<file>` |
| `prerendered/<path>.html` or `prerendered/<path>/index.html` | `GET /<path>` instead of `index.html` (`prerendered/index.html` for `/`) |

The root files are only served if they exist (otherwise 404), with an ETag
and `Cache-Control: public, max-age=3600` (a day for the icons). Prerendered
pages are static HTML of the front-end's pages, generated when it is built,
so search engines and link previews get the content without running
JavaScript; like `index.html`, they get `{{VERSION}}` replaced and
`Cache-Control: no-cache`. Only plain path segments (letters, digits, `-`,
`_` and `.`, not starting with a dot) are looked up, never outside the
directory. Everything carries the same security headers as the rest of the
web (strict CSP, `nosniff`, `no-referrer`, no frames).

For an open server:

```toml
[server]
public_url = "https://termoak.example.com"
registration = "open"

[web]
support_email = "support@example.com"
terms_url = "https://example.com/terms"        # optional
privacy_url = "https://example.com/privacy"    # optional
```

With `terms_url` (and `privacy_url`), the web sign-up shows a required
"I have read and accept the terms of use and the privacy policy" checkbox
with links to them, and the acceptance (with the version the client sends)
is recorded in the audit entry of the registration (`auth.register`). Apps
that do not send it can still sign up (see `accept_terms` in
[API.md](API.md#terms-of-use)).

## Email

Needed to verify emails, reset passwords and send invitations. Without email,
invitations are shared by copying the link and an administrator changes
forgotten passwords.

```toml
[email]
from = "Termoak <no-reply@example.com>"
require_verification = true    # new accounts must confirm their email (6-digit code or link)
```

The SMTP URL, with the password, goes in `TERMOAK_SMTP_URL`:
`smtps://user:password@smtp.example.com:465` (direct TLS) or
`smtp://user:password@smtp.example.com:587?tls=required` (STARTTLS). To
test without sending anything, `log://` writes the emails to the log (with
their links: do not use it in production). Also set `public_url`: email
links are built with it.

Emails are sent in the recipient's language (the account's `locale`; see
[I18N.md](https://github.com/TermoakSSH/core/blob/main/docs/I18N.md)).

## Plans

The built-in catalog has two plans:

- **Free** (`free`): always free, everything included. AI runs with your own
  API keys (`server_ai = false`).
- **Pro** (`pro`, coming soon): everything in Free, plus priority support and
  Termoak AI credit (`server_ai = true`, `ai_credit_usd = 5.0`).

The catalog is public at `GET /api/v1/plans`. A plan can set limits:
`max_teams` (teams the user owns), `max_team_members` (members per team,
applied with the team's plan) and `max_server_sessions` (persistent sessions
open at the same time). Unset limits are unlimited, and server administrators
have no limits.

AI limits: `server_ai` lets the plan's users use this server's AI providers
(its API keys, the Codex subscription...; `true` when not set) and
`ai_credit_usd` is their monthly credit in USD (when not set, `[ai]
monthly_budget_usd`, and without it no cap). Users can always add their own
API keys in Settings → AI, which never use the credit. If you share the
server with other people and want them to use its AI, give their plan
`server_ai = true` (the built-in Free plan does not). See [AI.md](https://github.com/TermoakSSH/core/blob/main/docs/AI.md).

`features` are stable ids, not display text. Clients translate
`plans.<id>.name`, `plans.<id>.description` and `plans.feature.<id>`, and fall
back to `name`, `description` and the raw id. Known ids:
`unlimited_entities`, `encrypted_sync`, `server_sessions`, `session_sharing`,
`teams`, `two_factor`, `ai_own_keys`, `ai_credit`, `priority_support`,
`desktop_mobile_apps`.

To define your own catalog (it replaces the built-in one):

```toml
[plans]
default = "free"

[[plans.catalog]]
id = "free"
name = "Free"
description = "Everything included. AI runs with your own API keys."
price_cents = 0          # omit while the price is not published
currency = "EUR"
available = true         # false = "coming soon"
for_teams = false        # true = assigned to a team, not to an account
highlight = true
features = ["encrypted_sync", "server_sessions", "ai_own_keys"]

[plans.catalog.limits]
max_teams = 3
max_team_members = 10
max_server_sessions = 5
server_ai = false        # AI only with the users' own API keys
# ai_credit_usd = 5.0    # monthly credit when server_ai = true
```

An administrator changes the plan of an account with
`PATCH /api/v1/admin/users/{id}` (`{"plan": "pro"}`) or
`termoak admin plan <email> <plan>`, and the plan of a team with
`POST /api/v1/admin/teams/{id}/plan`.

## Push notifications

For the iOS and Android apps to notify you even when closed (AI approvals,
finished tasks, shared sessions...):

- **iOS (APNs).** In Apple Developer, create an APNs authentication key
  (`.p8` file) and note its id and your team id:

  ```toml
  [push.apns]
  key_path = "/etc/termoak/AuthKey_ABC123DEFG.p8"   # or its content in TERMOAK_APNS_KEY
  key_id = "ABC123DEFG"
  team_id = "TEAMID1234"
  topic = "com.termoak"                             # bundle id of the app
  ```

- **Android (FCM).** In the Firebase console, generate a private key for a
  service account (JSON):

  ```toml
  [push.fcm]
  service_account_path = "/etc/termoak/firebase.json"   # or its content in TERMOAK_FCM_CREDENTIALS
  ```

By default the notification text is generic, because Apple and Google see
it; with `[push] detailed = true` it includes the commands the AI wants to
run and the session titles. Texts are translated to the recipient's language.

## Environment variables

| Variable | Use |
|---|---|
| `TERMOAK_CONFIG` | Path of the TOML file |
| `TERMOAK_LISTEN`, `TERMOAK_DATA_DIR`, `TERMOAK_PUBLIC_URL` | Override the TOML values |
| `TERMOAK_MASTER_KEY` | Master key in base64. Without it, `<data_dir>/master.key` is used |
| `TERMOAK_UPDATES_REPO` | Overrides `[updates] github_repo` (the single repository, or the fallback of `[updates.repos]`) |
| `TERMOAK_GITHUB_TOKEN` | Read-only GitHub token for `[updates]` (the variable name is set by `github_token_env`) |
| `TERMOAK_SMTP_URL`, `TERMOAK_EMAIL_FROM` | Outgoing email (see [Email](#email)) |
| `TERMOAK_APNS_KEY`, `TERMOAK_FCM_CREDENTIALS` | Push notification keys (content of the `.p8` and the JSON) |
| `TERMOAK_PASSWORD` | Password for `termoak-server user add` |
| `TERMOAK_WEB_DIR` | Development only: serve the web app from this directory instead of the embedded one |
| `AI_PROVIDER`, `AI_FALLBACK` | Default AI provider and fallback chain (comma-separated) |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `CODEX_API_KEY`, `OPENCODE_GO_KEY`, `OPENROUTER_API_KEY` | AI credentials |
| `CODEX_HOME`, `CODEX_COMMAND` | Codex CLI |
| `OPENCODE_BASE_URL`, `OPENCODE_SERVER_PASSWORD` | Local OpenCode server |
| `LOCAL_AI_BASE_URL`, `LOCAL_AI_MODEL` | Local models |
| `RUST_LOG` | Log level, for example `info,termoak_server=debug` |

The AI providers and their settings are described in [AI.md](https://github.com/TermoakSSH/core/blob/main/docs/AI.md).

## Backups

Copy the whole `data_dir`: the `termoak.db` database, `master.key`, the
recordings and the Codex session. SQLite runs in WAL mode. For a hot copy:

```sh
sqlite3 /var/lib/termoak/termoak.db ".backup '/backup/termoak.db'"
```

Without `master.key` the stored secrets cannot be recovered.

## Publishing releases

The server is released on its own, with the version in `Cargo.toml`, as the
`server-vX.Y.Z` GitHub release (Linux x86_64 and aarch64 binaries) plus the
`ghcr.io/termoakssh/termoak-server` Docker image. The other components live
in their own repositories and are released separately:
[core](https://github.com/TermoakSSH/core) (the CLI, `cli-vX.Y.Z`, and the `vX.Y.Z` library tags the
server depends on), [desktop](https://github.com/TermoakSSH/desktop),
[mobile-android](https://github.com/TermoakSSH/mobile-android) and [mobile-ios](https://github.com/TermoakSSH/mobile-ios).

**Compatibility.** Each component moves at its own pace, so a desktop app or
CLI that is months old must keep working with a new server. The `/api/v1`
API only grows: routes and fields can be added, but not removed or changed in
meaning (see [API.md](API.md#compatibility)).

### Publishing from your machine

`scripts/release-local.sh` builds and publishes without spending GitHub
Actions minutes. It needs Docker to build. To publish it uses the GitHub API
with `curl` (no `gh` needed) and a *fine-grained* token different from the
server's: access to the TermoakSSH repositories, with *Contents: Read and
write* permission (and *Actions: Read* if you use `download`). Store it in
`~/.config/termoak/github-token` (mode `600`) or pass it in `GITHUB_TOKEN`.

The release is created as a draft, the files are uploaded and only then is
it published: the server never sees a half-uploaded release. If something
fails on the way, run `publish` again: it completes the draft.

```sh
scripts/release-local.sh status                # unpublished changes since the last release
scripts/release-local.sh version server 0.2.1  # bump the version (Cargo.toml and Cargo.lock)
git commit -am "Server 0.2.1" && git push      # the release is created on a pushed commit

scripts/release-local.sh build server          # builds into dist/server/
scripts/release-local.sh publish server --docker
sudo scripts/release-local.sh deploy server    # installs it on this machine and restarts
```

- `build` compiles in an Ubuntu 22.04 container (`scripts/builder.Dockerfile`),
  so any Linux machine works, or a Mac with Docker Desktop. The binaries run
  on Ubuntu 22.04+ and Debian 12+.
- `--docker` pushes the image to GHCR (`vX.Y.Z` and `latest`). It needs
  `docker login ghcr.io` with a token with `write:packages`, and `buildx`
  with arm64 support: Docker Desktop includes it; on Linux,
  `docker run --privileged --rm tonistiigi/binfmt --install arm64`.
- `deploy server` installs the server from `dist/server/` into
  `/usr/local/bin`, keeps the previous one as `termoak-server.prev` and
  restarts the service. If it does not start, it tells you how to roll back.

To move to a new version of the core libraries, change the `tag` of the
`termoak-*` dependencies in `Cargo.toml` and run `cargo update -p termoak-core`.

### Updates and downloads through the server

Your server can serve the updates and downloads of the apps. This is needed
when the releases are in a private repository (their files cannot be
downloaded without authentication, and the app cannot carry a token), and
keeps the downloads on your domain otherwise:
it reads the releases with a read-only token and offers the latest release of
each component at `/updates/latest.json` (desktop) and `/updates/download/…`,
plus the list at `/api/v1/downloads`. The Ed25519 signature does not depend
on the URL, so the app still verifies every download.

Each component is read from its own repository: desktop from
`TermoakSSH/desktop` (`desktop-vX.Y.Z`, with `latest.json`), server from
`TermoakSSH/server` (`server-vX.Y.Z`), CLI from `TermoakSSH/core`
(`cli-vX.Y.Z`), Android from `TermoakSSH/mobile-android` (`android-vX.Y.Z`)
and iOS from `TermoakSSH/mobile-ios` (`ios-vX.Y.Z`). In a component's own
repository only that component's tags count: the `ffi-vX.Y.Z` releases and
the plain `vX.Y.Z` tag of core are ignored. Each repository is listed once
every 5 minutes (all of them at the same time) and the results are merged
into the same routes; if one cannot be read, the rest is still served.

1. On GitHub, create a *fine-grained* token (*Settings > Developer settings >
   Personal access tokens > Fine-grained tokens*):
   - access to the release repositories only (all of those below);
   - *Contents: Read-only* permission;
   - note when it expires so you can renew it.
2. On the server, add the token to `/etc/termoak/env`:
   ```sh
   TERMOAK_GITHUB_TOKEN=github_pat_...
   ```
   and the repositories to `/etc/termoak/config.toml`:
   ```toml
   [updates.repos]
   desktop = "TermoakSSH/desktop"
   server = "TermoakSSH/server"
   cli = "TermoakSSH/core"
   android = "TermoakSSH/mobile-android"
   ios = "TermoakSSH/mobile-ios"
   ```
   A component left out is not offered, unless `[updates] github_repo` is
   set: that single repository is the fallback for the components missing
   from `[updates.repos]`, with every component's tags in it and the old
   `vX.Y.Z` releases (everything together) still counting for desktop,
   server and CLI. With only `github_repo` it works as before (one
   repository for everything; `TERMOAK_UPDATES_REPO` overrides it):
   ```toml
   [updates]
   github_repo = "owner/repo"
   ```
   Restart the service and check that
   `https://YOUR-SERVER/updates/latest.json` responds once there is a desktop
   release.
3. Build the desktop app (TermoakSSH/desktop) with `TERMOAK_UPDATE_URL` =
   `https://YOUR-SERVER/updates/latest.json` (in Actions, the variable of the
   same name in the **Variables** tab). The app is compiled with that URL.

The `/updates/` routes are public: anyone who knows your domain can download
the installers and binaries (not the source code). Only the files of the
latest release of each component are served.

The Docker image of a private repository is private too: before
`docker compose pull`, sign in with `docker login ghcr.io` and a token with
`read:packages`.
