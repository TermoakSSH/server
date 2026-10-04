//! Updates served from a private GitHub release: the real desktop updater
//! downloads them through the server.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use serde_json::{Value, json};
use termoak_server::config::{ServerConfig, UpdatesSection};
use termoak_server::{build_state, routes};
use termoak_update::{Install, UpdateConfig, Updater};

const TOKEN: &str = "ghp_test";
const ARTIFACT: &[u8] = b"new Termoak binary";

#[derive(Clone)]
struct Mock {
    manifest: Arc<String>,
    /// `owner/repo` → its releases.
    repos: Arc<HashMap<String, Value>>,
    /// Release listings requested, per repository.
    listed: Arc<Mutex<HashMap<String, usize>>>,
}

/// Fake GitHub: its URL and how many times each repository was listed.
struct Github {
    url: String,
    listed: Arc<Mutex<HashMap<String, usize>>>,
}

impl Github {
    fn listed(&self, repo: &str) -> usize {
        self.listed.lock().unwrap().get(repo).copied().unwrap_or(0)
    }
}

fn authorized(headers: &HeaderMap) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        == Some(&format!("Bearer {TOKEN}"))
}

/// An old-style release (`vX.Y.Z`) with everything together.
fn legacy_releases() -> Value {
    json!([{
        "tag_name": "v0.2.0",
        "assets": [
            {"id": 1, "name": "latest.json"},
            {"id": 2, "name": "Termoak-linux-x86_64.AppImage"},
            {"id": 3, "name": "other-file.txt"}
        ]
    }])
}

/// Fake GitHub with a private repository `o/r`. Asset 1 is `manifest`,
/// asset 2 the artifact (after a redirect) and the rest, text.
async fn mock_github(manifest: String, releases: Value) -> String {
    mock_github_repos(manifest, &[("o/r", releases)]).await.url
}

/// Fake GitHub with several private repositories. An asset is only served
/// from the repository whose releases list it: 1 is `manifest`, 2 the
/// artifact (after a redirect) and the rest, `asset {id} of {owner/repo}`.
/// Repositories not given answer 404, like one the token cannot see.
async fn mock_github_repos(manifest: String, repos: &[(&str, Value)]) -> Github {
    async fn list(
        State(m): State<Mock>,
        Path((owner, repo)): Path<(String, String)>,
        headers: HeaderMap,
    ) -> Response {
        let repo = format!("{owner}/{repo}");
        *m.listed.lock().unwrap().entry(repo.clone()).or_default() += 1;
        if !authorized(&headers) {
            // Like GitHub with a private repository and no credentials.
            return StatusCode::NOT_FOUND.into_response();
        }
        match m.repos.get(&repo) {
            Some(releases) => axum::Json(releases.clone()).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        }
    }
    async fn asset(
        State(m): State<Mock>,
        Path((owner, repo, id)): Path<(String, String, u64)>,
        headers: HeaderMap,
    ) -> Response {
        if !authorized(&headers) {
            return StatusCode::NOT_FOUND.into_response();
        }
        if headers.get(header::ACCEPT).and_then(|v| v.to_str().ok())
            != Some("application/octet-stream")
        {
            return StatusCode::NOT_ACCEPTABLE.into_response();
        }
        let repo = format!("{owner}/{repo}");
        let listed = m.repos.get(&repo).is_some_and(|releases| {
            releases.as_array().unwrap().iter().any(|r| {
                r["assets"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|a| a["id"] == id)
            })
        });
        if !listed {
            return StatusCode::NOT_FOUND.into_response();
        }
        match id {
            1 => m.manifest.to_string().into_response(),
            // GitHub redirects the download to its storage.
            2 => Redirect::to("/storage/2").into_response(),
            _ => format!("asset {id} of {repo}").into_response(),
        }
    }
    let listed = Arc::new(Mutex::new(HashMap::new()));
    let app = Router::new()
        .route("/repos/{owner}/{repo}/releases", get(list))
        .route("/repos/{owner}/{repo}/releases/assets/{id}", get(asset))
        .route("/storage/2", get(|| async { ARTIFACT }))
        .with_state(Mock {
            manifest: Arc::new(manifest),
            repos: Arc::new(
                repos
                    .iter()
                    .map(|(name, releases)| (name.to_string(), releases.clone()))
                    .collect(),
            ),
            listed: listed.clone(),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Github {
        url: format!("http://{addr}"),
        listed,
    }
}

/// Server with updates enabled against `github` (single repository `o/r`).
async fn server_with_updates(github: &str) -> (String, tempfile::TempDir) {
    server_with(github, |u| u.github_repo = Some("o/r".into())).await
}

/// Server with updates against `github`, configured by `setup`.
async fn server_with(
    github: &str,
    setup: impl FnOnce(&mut UpdatesSection),
) -> (String, tempfile::TempDir) {
    // SAFETY: every test sets the same value.
    unsafe { std::env::set_var("AKS_TEST_UPDATES_TOKEN", TOKEN) };
    let data = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut config = ServerConfig::default();
    config.server.listen = addr;
    config.server.data_dir = data.path().to_path_buf();
    setup(&mut config.updates);
    config.updates.github_api = github.to_string();
    config.updates.github_token_env = "AKS_TEST_UPDATES_TOKEN".into();
    let state = build_state(config).await.unwrap();
    tokio::spawn(async move { axum::serve(listener, routes::router(state)).await.unwrap() });
    (format!("http://{addr}"), data)
}

async fn get_json(http: &reqwest::Client, url: String) -> Value {
    http.get(url)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Status and body of a download.
async fn fetch(http: &reqwest::Client, base: &str, name: &str) -> (StatusCode, String) {
    let resp = http
        .get(format!("{base}/updates/download/{name}"))
        .send()
        .await
        .unwrap();
    (resp.status(), resp.text().await.unwrap())
}

/// Component and version of each file of `/api/v1/downloads`, by name.
fn files(list: &Value) -> Vec<(String, String)> {
    list["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["name"].as_str().unwrap().to_string(),
                f["component"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn desktop_manifest(tag: &str) -> Value {
    json!({
        "version": tag.trim_start_matches("desktop-v"),
        "platforms": {
            "linux-x86_64": {
                "url": format!("https://github.com/TermoakSSH/desktop/releases/download/{tag}/Termoak-linux-x86_64.AppImage"),
                "sha256": "abc", "signature": "sig", "size": 3, "format": "appimage"
            }
        }
    })
}

#[tokio::test]
async fn updates_from_private_release() {
    // Release signed the way CI signs it.
    let (secret, public) = termoak_update::generate_keypair();
    let key = termoak_update::signing_key_from_base64(&secret).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let artifact = tmp.path().join("artifact");
    std::fs::write(&artifact, ARTIFACT).unwrap();
    let sha = termoak_update::sha256_file(&artifact).unwrap();
    let manifest = json!({
        "version": "0.2.0",
        "notes": "test",
        "pub_date": "2026-09-26T00:00:00Z",
        "platforms": {
            "linux-x86_64": {
                "url": "https://github.com/o/r/releases/download/v0.2.0/Termoak-linux-x86_64.AppImage",
                "sha256": sha,
                "size": ARTIFACT.len(),
                "signature": termoak_update::sign(&key, "linux-x86_64", "0.2.0", &sha),
                "format": "appimage"
            }
        }
    });
    let github = mock_github(manifest.to_string(), legacy_releases()).await;
    let (base, _data) = server_with_updates(&github).await;

    // The manifest comes out with this server's URLs and the signature intact.
    let http = reqwest::Client::new();
    let served: Value = http
        .get(format!("{base}/updates/latest.json"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let asset = &served["platforms"]["linux-x86_64"];
    assert_eq!(
        asset["url"],
        format!("{base}/updates/download/Termoak-linux-x86_64.AppImage")
    );
    assert_eq!(
        asset["signature"],
        manifest["platforms"]["linux-x86_64"]["signature"]
    );

    // Only files from the latest release are served.
    for (name, expected) in [
        ("other-file.txt", StatusCode::OK),
        ("missing.bin", StatusCode::NOT_FOUND),
        ("..%2F..%2Fetc%2Fpasswd", StatusCode::NOT_FOUND),
    ] {
        let status = http
            .get(format!("{base}/updates/download/{name}"))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, expected, "{name}");
    }

    // List for the web downloads page.
    let list: serde_json::Value = http
        .get(format!("{base}/api/v1/downloads"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list["version"], "0.2.0");
    let app = list["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "Termoak-linux-x86_64.AppImage")
        .expect("the AppImage is in the list");
    assert_eq!(app["os"], "linux");
    assert_eq!(app["kind"], "app");
    assert_eq!(
        app["url"],
        format!("{base}/updates/download/Termoak-linux-x86_64.AppImage")
    );

    // The real desktop updater: checks, downloads and verifies.
    let dir = tempfile::tempdir().unwrap();
    let app = dir.path().join("Termoak.AppImage");
    std::fs::write(&app, b"old binary").unwrap();
    let updater = Updater::new(UpdateConfig {
        manifest_url: format!("{base}/updates/latest.json"),
        public_key: termoak_update::public_key_from_base64(&public).unwrap(),
        current_version: semver::Version::new(0, 1, 0),
        target: "linux-x86_64".into(),
        install: Install::AppImage(app),
        staging_dir: dir.path().join("updates"),
    });
    let available = updater
        .check()
        .await
        .unwrap()
        .expect("a new version is available");
    assert_eq!(available.version, "0.2.0");
    updater.download(&available, |_, _| {}).await.unwrap();
    assert_eq!(updater.pending_version().as_deref(), Some("0.2.0"));
}

#[tokio::test]
async fn updates_disabled_by_default() {
    let data = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut config = ServerConfig::default();
    config.server.listen = addr;
    config.server.data_dir = data.path().to_path_buf();
    let state = build_state(config).await.unwrap();
    tokio::spawn(async move { axum::serve(listener, routes::router(state)).await.unwrap() });
    let status = reqwest::get(format!("http://{addr}/updates/latest.json"))
        .await
        .unwrap()
        .status();
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Desktop, server and CLI published separately.
#[tokio::test]
async fn components_published_separately() {
    let manifest = json!({
        "version": "0.3.0",
        "platforms": {
            "linux-x86_64": {
                "url": "https://github.com/o/r/releases/download/desktop-v0.3.0/Termoak-linux-x86_64.AppImage",
                "sha256": "abc", "signature": "sig", "size": 3, "format": "appimage"
            }
        }
    });
    let releases = json!([
        {"tag_name": "server-v0.4.0", "assets": [
            {"id": 10, "name": "termoak-server-v0.4.0-linux-x86_64.tar.gz", "size": 7}
        ]},
        {"tag_name": "desktop-v0.3.0", "assets": [
            {"id": 1, "name": "latest.json"},
            {"id": 2, "name": "Termoak-linux-x86_64.AppImage"}
        ]},
        {"tag_name": "cli-v0.5.0-beta.1", "prerelease": true, "assets": [
            {"id": 11, "name": "termoak-cli-v0.5.0-beta.1-linux-x86_64.tar.gz"}
        ]},
        {"tag_name": "v0.2.0", "assets": [
            {"id": 12, "name": "latest.json"},
            {"id": 13, "name": "Termoak-windows-x86_64.exe"},
            {"id": 14, "name": "termoak-v0.2.0-linux-x86_64.tar.gz"}
        ]}
    ]);
    let github = mock_github(manifest.to_string(), releases).await;
    let (base, _data) = server_with_updates(&github).await;
    let http = reqwest::Client::new();

    // The desktop updates to its own release.
    let served: Value = http
        .get(format!("{base}/updates/latest.json"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(served["version"], "0.3.0");

    let list: Value = http
        .get(format!("{base}/api/v1/downloads"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list["version"], "0.3.0");
    assert_eq!(list["components"]["desktop"]["tag"], "desktop-v0.3.0");
    assert_eq!(list["components"]["server"]["version"], "0.4.0");
    // The beta does not count: the CLI stays on the old release.
    assert_eq!(list["components"]["cli"]["tag"], "v0.2.0");
    let names: Vec<(&str, &str)> = list["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["name"].as_str().unwrap(),
                f["component"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        names,
        vec![
            ("Termoak-linux-x86_64.AppImage", "desktop"),
            // Desktop 0.3.0 has no Windows build: the 0.2.0 one is offered.
            ("Termoak-windows-x86_64.exe", "desktop"),
            ("latest.json", "desktop"),
            ("termoak-server-v0.4.0-linux-x86_64.tar.gz", "server"),
            ("termoak-v0.2.0-linux-x86_64.tar.gz", "cli"),
        ]
    );

    let file = |name: &str| {
        list["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == name)
            .cloned()
            .unwrap()
    };
    assert_eq!(file("Termoak-windows-x86_64.exe")["version"], "0.2.0");
    assert!(file("Termoak-linux-x86_64.AppImage")["version"].is_null());

    // Files from each component's latest release are served (and, for the
    // desktop, the systems the latest one lacks).
    for (name, expected) in [
        ("termoak-server-v0.4.0-linux-x86_64.tar.gz", StatusCode::OK),
        ("termoak-v0.2.0-linux-x86_64.tar.gz", StatusCode::OK),
        ("Termoak-windows-x86_64.exe", StatusCode::OK),
        (
            "termoak-cli-v0.5.0-beta.1-linux-x86_64.tar.gz",
            StatusCode::NOT_FOUND,
        ),
    ] {
        let status = http
            .get(format!("{base}/updates/download/{name}"))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, expected, "{name}");
    }
}

/// With no desktop published, server downloads still work.
#[tokio::test]
async fn server_only_release() {
    let releases = json!([
        {"tag_name": "server-v0.2.0", "assets": [
            {"id": 10, "name": "termoak-server-v0.2.0-linux-x86_64.tar.gz"}
        ]}
    ]);
    let github = mock_github(String::new(), releases).await;
    let (base, _data) = server_with_updates(&github).await;
    let http = reqwest::Client::new();
    let status = http
        .get(format!("{base}/updates/latest.json"))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, StatusCode::NOT_FOUND);
    let list: Value = http
        .get(format!("{base}/api/v1/downloads"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(list["version"].is_null());
    assert_eq!(list["components"]["server"]["version"], "0.2.0");
    assert_eq!(list["files"].as_array().unwrap().len(), 1);
}

/// Every component in its own repository (TermoakSSH/desktop, server, core,
/// mobile-android, mobile-ios), merged into the same outputs.
#[tokio::test]
async fn one_repository_per_component() {
    let github = mock_github_repos(
        desktop_manifest("desktop-v0.3.0").to_string(),
        &[
            (
                "TermoakSSH/desktop",
                json!([
                    {"tag_name": "desktop-v0.3.0", "assets": [
                        {"id": 1, "name": "latest.json"},
                        {"id": 2, "name": "Termoak-linux-x86_64.AppImage"}
                    ]},
                    {"tag_name": "desktop-v0.2.0", "assets": [
                        {"id": 3, "name": "Termoak-windows-x86_64.exe"}
                    ]},
                    // The old layout does not count in a component's own repository.
                    {"tag_name": "v0.9.0", "assets": [
                        {"id": 4, "name": "Termoak-v0.9.0-macos-universal.dmg"}
                    ]}
                ]),
            ),
            (
                "TermoakSSH/server",
                json!([
                    {"tag_name": "server-v0.2.2", "assets": [
                        {"id": 10, "name": "termoak-server-v0.2.2-linux-x86_64.tar.gz"}
                    ]}
                ]),
            ),
            (
                "TermoakSSH/core",
                json!([
                    {"tag_name": "ffi-v0.9.0", "assets": [
                        {"id": 11, "name": "termoak-ffi-v0.9.0-android.zip"}
                    ]},
                    {"tag_name": "v0.9.0", "assets": [
                        {"id": 12, "name": "termoak-v0.9.0-linux-x86_64.tar.gz"}
                    ]},
                    // Same asset id as the server's: the repository tells them apart.
                    {"tag_name": "cli-v0.2.1", "assets": [
                        {"id": 10, "name": "termoak-cli-v0.2.1-linux-x86_64.tar.gz"}
                    ]}
                ]),
            ),
            (
                "TermoakSSH/mobile-android",
                json!([
                    {"tag_name": "android-v0.1.0", "assets": [
                        {"id": 20, "name": "Termoak-android-v0.1.0.apk"}
                    ]}
                ]),
            ),
            (
                "TermoakSSH/mobile-ios",
                json!([
                    {"tag_name": "ios-v0.3.0", "assets": [
                        {"id": 30, "name": "Termoak-0.3.0-unsigned.ipa"}
                    ]}
                ]),
            ),
        ],
    )
    .await;
    let (base, _data) = server_with(&github.url, |u| {
        u.repos.desktop = Some("TermoakSSH/desktop".into());
        u.repos.server = Some("TermoakSSH/server".into());
        u.repos.cli = Some("TermoakSSH/core".into());
        u.repos.android = Some("TermoakSSH/mobile-android".into());
        u.repos.ios = Some("TermoakSSH/mobile-ios".into());
    })
    .await;
    let http = reqwest::Client::new();

    // The desktop manifest comes from the desktop repository.
    let served = get_json(&http, format!("{base}/updates/latest.json")).await;
    assert_eq!(served["version"], "0.3.0");
    assert_eq!(
        served["platforms"]["linux-x86_64"]["url"],
        format!("{base}/updates/download/Termoak-linux-x86_64.AppImage")
    );

    let list = get_json(&http, format!("{base}/api/v1/downloads")).await;
    assert_eq!(list["version"], "0.3.0");
    assert_eq!(list["tag"], "desktop-v0.3.0");
    let tag = |c: &str| list["components"][c]["tag"].clone();
    assert_eq!(tag("desktop"), "desktop-v0.3.0");
    assert_eq!(tag("server"), "server-v0.2.2");
    // Neither ffi-v0.9.0 nor the plain v0.9.0 of core.
    assert_eq!(tag("cli"), "cli-v0.2.1");
    assert_eq!(tag("android"), "android-v0.1.0");
    assert_eq!(tag("ios"), "ios-v0.3.0");
    let pair = |n: &str, c: &str| (n.to_string(), c.to_string());
    assert_eq!(
        files(&list),
        vec![
            pair("Termoak-0.3.0-unsigned.ipa", "ios"),
            pair("Termoak-android-v0.1.0.apk", "android"),
            pair("Termoak-linux-x86_64.AppImage", "desktop"),
            // Desktop 0.3.0 has no Windows build: the 0.2.0 one is offered.
            pair("Termoak-windows-x86_64.exe", "desktop"),
            pair("latest.json", "desktop"),
            pair("termoak-cli-v0.2.1-linux-x86_64.tar.gz", "cli"),
            pair("termoak-server-v0.2.2-linux-x86_64.tar.gz", "server"),
        ]
    );

    // Each file is downloaded from its own repository.
    for (name, body) in [
        ("Termoak-linux-x86_64.AppImage", "new Termoak binary"),
        (
            "Termoak-windows-x86_64.exe",
            "asset 3 of TermoakSSH/desktop",
        ),
        (
            "termoak-server-v0.2.2-linux-x86_64.tar.gz",
            "asset 10 of TermoakSSH/server",
        ),
        (
            "termoak-cli-v0.2.1-linux-x86_64.tar.gz",
            "asset 10 of TermoakSSH/core",
        ),
        (
            "Termoak-android-v0.1.0.apk",
            "asset 20 of TermoakSSH/mobile-android",
        ),
        (
            "Termoak-0.3.0-unsigned.ipa",
            "asset 30 of TermoakSSH/mobile-ios",
        ),
    ] {
        assert_eq!(
            fetch(&http, &base, name).await,
            (StatusCode::OK, body.to_string()),
            "{name}"
        );
    }
    for name in [
        "termoak-ffi-v0.9.0-android.zip",
        "termoak-v0.9.0-linux-x86_64.tar.gz",
        "Termoak-v0.9.0-macos-universal.dmg",
    ] {
        assert_eq!(
            fetch(&http, &base, name).await.0,
            StatusCode::NOT_FOUND,
            "{name}"
        );
    }

    // One listing per repository, reused while cached.
    for repo in [
        "TermoakSSH/desktop",
        "TermoakSSH/server",
        "TermoakSSH/core",
        "TermoakSSH/mobile-android",
        "TermoakSSH/mobile-ios",
    ] {
        assert_eq!(github.listed(repo), 1, "{repo}");
    }
}

/// Components left out of `[updates.repos]` come from `github_repo`, where
/// the old `vX.Y.Z` still counts; a repository that cannot be read does not
/// take the rest down.
#[tokio::test]
async fn unlisted_components_fall_back_to_github_repo() {
    let manifest = json!({
        "version": "0.2.0",
        "platforms": {
            "linux-x86_64": {
                "url": "https://github.com/o/r/releases/download/v0.2.0/Termoak-linux-x86_64.AppImage",
                "sha256": "abc", "signature": "sig", "size": 3, "format": "appimage"
            }
        }
    });
    let github = mock_github_repos(
        manifest.to_string(),
        &[
            (
                "o/r",
                json!([
                    {"tag_name": "v0.2.0", "assets": [
                        {"id": 1, "name": "latest.json"},
                        {"id": 2, "name": "Termoak-linux-x86_64.AppImage"},
                        {"id": 3, "name": "termoak-v0.2.0-linux-x86_64.tar.gz"}
                    ]},
                    // Not the CLI's: the CLI has its own repository.
                    {"tag_name": "cli-v0.8.0", "assets": [
                        {"id": 4, "name": "termoak-cli-v0.8.0-linux-x86_64.tar.gz"}
                    ]}
                ]),
            ),
            (
                "TermoakSSH/core",
                json!([
                    {"tag_name": "v0.9.0", "assets": [
                        {"id": 12, "name": "termoak-v0.9.0-linux-x86_64.tar.gz"}
                    ]},
                    {"tag_name": "cli-v0.2.1", "assets": [
                        {"id": 13, "name": "termoak-cli-v0.2.1-linux-x86_64.tar.gz"}
                    ]}
                ]),
            ),
        ],
    )
    .await;
    let (base, _data) = server_with(&github.url, |u| {
        u.github_repo = Some("o/r".into());
        u.repos.cli = Some("TermoakSSH/core".into());
        // The token cannot see it (404).
        u.repos.ios = Some("TermoakSSH/missing".into());
    })
    .await;
    let http = reqwest::Client::new();

    let served = get_json(&http, format!("{base}/updates/latest.json")).await;
    assert_eq!(served["version"], "0.2.0");
    let list = get_json(&http, format!("{base}/api/v1/downloads")).await;
    assert_eq!(list["components"]["desktop"]["tag"], "v0.2.0");
    assert_eq!(list["components"]["server"]["tag"], "v0.2.0");
    assert_eq!(list["components"]["cli"]["tag"], "cli-v0.2.1");
    assert!(list["components"]["ios"].is_null());
    let pair = |n: &str, c: &str| (n.to_string(), c.to_string());
    assert_eq!(
        files(&list),
        vec![
            pair("Termoak-linux-x86_64.AppImage", "desktop"),
            pair("latest.json", "desktop"),
            pair("termoak-cli-v0.2.1-linux-x86_64.tar.gz", "cli"),
            // The old combined archive stays with the server only.
            pair("termoak-v0.2.0-linux-x86_64.tar.gz", "server"),
        ]
    );
    assert_eq!(
        fetch(&http, &base, "termoak-cli-v0.2.1-linux-x86_64.tar.gz").await,
        (StatusCode::OK, "asset 13 of TermoakSSH/core".to_string())
    );
    assert_eq!(
        fetch(&http, &base, "termoak-v0.2.0-linux-x86_64.tar.gz").await,
        (StatusCode::OK, "asset 3 of o/r".to_string())
    );
    assert_eq!(
        fetch(&http, &base, "termoak-cli-v0.8.0-linux-x86_64.tar.gz")
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

/// Only `[updates.repos]`, no `github_repo`: the components left out are
/// simply not offered.
#[tokio::test]
async fn repos_without_fallback() {
    let github = mock_github_repos(
        String::new(),
        &[(
            "TermoakSSH/server",
            json!([
                {"tag_name": "server-v0.2.2", "assets": [
                    {"id": 10, "name": "termoak-server-v0.2.2-linux-x86_64.tar.gz"}
                ]}
            ]),
        )],
    )
    .await;
    let (base, _data) = server_with(&github.url, |u| {
        u.repos.server = Some("TermoakSSH/server".into());
    })
    .await;
    let http = reqwest::Client::new();
    let status = http
        .get(format!("{base}/updates/latest.json"))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, StatusCode::NOT_FOUND);
    let list = get_json(&http, format!("{base}/api/v1/downloads")).await;
    assert!(list["version"].is_null());
    assert_eq!(
        list["components"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        vec!["server"]
    );
    assert_eq!(github.listed("TermoakSSH/server"), 1);
}
