# Termoak server

`termoak-server`, the optional self-hosted server of
[Termoak](https://termoak.com), the open-source SSH client for desktop and
mobile. A single binary that keeps everything in SQLite and adds to the apps:

- **Server sessions** that stay alive when you close your laptop or lose
  coverage, with the scrollback intact when you attach again from any device
  (and a separate session holder, so restarting the server does not cut them).
- **Shared sessions** with users, teams or a link, in *view* or *control* mode.
- **Sync** of the encrypted vault across devices.
- **Accounts and teams**: two-step verification, invitations, roles,
  administration and an audit log.
- **Background AI** with approvals from your phone, multi-provider, and an
  MCP server for external agents.
- **A basic web app** (`web/`, built into the binary): sign-in, sessions with
  a terminal in the browser, teams and account settings. It is not indexed by
  search engines (`/robots.txt` disallows everything); a custom front-end in
  `[web] dir` can ship its own robots.txt, sitemap, favicons, `.well-known/`
  files and prerendered pages (see [DEPLOYMENT.md](docs/DEPLOYMENT.md#web-app)).
- **Push notifications** (APNs and FCM), **email** and **update downloads**
  for the apps.

It depends on the shared crates of [TermoakSSH/core](https://github.com/TermoakSSH/core) through a git
tag (see `Cargo.toml`).

## Running it

The server is a single binary that keeps everything in SQLite.

With Docker:

```sh
docker compose up -d     # uses docker-compose.yml; data in the termoak-data volume
```

With the binary (from the [server releases](https://github.com/TermoakSSH/server/releases),
or built from this repository with `cargo build --release`):

```sh
termoak-server example-config > config.toml   # edit public_url, data_dir...
termoak-server --config config.toml serve      # listens on 0.0.0.0:7722
```

Open `http://<server>:7722` and sign up: the first account becomes the
administrator, and after that registration is closed (invitations only)
unless you set `registration = "open"`. For production, put it behind TLS
(Caddy or nginx) and run it with the bundled systemd units: see
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## The Termoak repositories

| Repository | Contents |
|---|---|
| [TermoakSSH/core](https://github.com/TermoakSSH/core) | Shared crates (SSH engine, vault, API client, AI engine, FFI bindings, updates) and the `termoak` CLI |
| **[TermoakSSH/server](https://github.com/TermoakSSH/server)** | `termoak-server`: HTTP/WebSocket API, basic web app, deployment files |
| [TermoakSSH/desktop](https://github.com/TermoakSSH/desktop) | Desktop app (GPUI) for Windows, Linux and macOS |
| [TermoakSSH/mobile-android](https://github.com/TermoakSSH/mobile-android) | Android app (Jetpack Compose) |
| [TermoakSSH/mobile-ios](https://github.com/TermoakSSH/mobile-ios) | iOS app (SwiftUI) |
| [TermoakSSH/public-web](https://github.com/TermoakSSH/public-web) | Public website of termoak.com: landing, pricing and downloads |

## Development

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test        # some end-to-end tests use the system sshd (Linux)
```

`tests/ffi_*.rs` run the engine of the mobile apps (`termoak-ffi`, from core)
against this server. To work on core at the same time, see
["Using the libraries"](https://github.com/TermoakSSH/core#using-the-libraries) in the core README.

The server is released with `scripts/release-local.sh` (`server-vX.Y.Z`):

```sh
scripts/release-local.sh status
scripts/release-local.sh version server 0.2.1
scripts/release-local.sh build server
scripts/release-local.sh publish server --docker
```

Details in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#publishing-releases).

## Documentation

- [Deployment](docs/DEPLOYMENT.md)
- [HTTP API](docs/API.md), with the full contract at `/api/openapi.json`
- [WebSocket protocol](docs/WEBSOCKET-PROTOCOL.md)
- [Architecture](https://github.com/TermoakSSH/core/blob/main/docs/ARCHITECTURE.md), [AI engine](https://github.com/TermoakSSH/core/blob/main/docs/AI.md),
  [Security](https://github.com/TermoakSSH/core/blob/main/docs/SECURITY.md) and [Internationalization](https://github.com/TermoakSSH/core/blob/main/docs/I18N.md) (in core)

## Contributing and translations

Bug reports, fixes, features and translations are welcome: see
[CONTRIBUTING.md](CONTRIBUTING.md). Translating Termoak into your language
needs no programming: copy the English strings file of an app, translate it
and open a pull request ([docs/I18N.md](https://github.com/TermoakSSH/core/blob/main/docs/I18N.md)).

## License

Copyright © Ohz Digital SL.

Termoak is free software released under the
[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only).

"Termoak" and the Termoak logo are trademarks of Ohz Digital SL and are not
covered by the code license: see [TRADEMARK.md](TRADEMARK.md).
