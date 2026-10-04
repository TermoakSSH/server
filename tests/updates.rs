//! Updates served from a private GitHub release: the real desktop updater
//! downloads them through the server.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use serde_json::{Value, json};
use termoak_server::config::ServerConfig;
use termoak_server::{build_state, routes};
use termoak_update::{Install, UpdateConfig, Updater};

const TOKEN: &str = "ghp_test";
const ARTIFACT: &[u8] = b"new Termoak binary";

#[derive(Clone)]
struct Mock {
    manifest: Arc<String>,
    releases: Arc<Value>,
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
    async fn list(State(m): State<Mock>, headers: HeaderMap) -> Response {
        if !authorized(&headers) {
            // Like GitHub with a private repository and no credentials.
            return StatusCode::NOT_FOUND.into_response();
        }
        axum::Json(m.releases.as_ref().clone()).into_response()
    }
    async fn asset(State(m): State<Mock>, Path(id): Path<u64>, headers: HeaderMap) -> Response {
        if !authorized(&headers) {
            return StatusCode::NOT_FOUND.into_response();
        }
        if headers.get(header::ACCEPT).and_then(|v| v.to_str().ok())
            != Some("application/octet-stream")
        {
            return StatusCode::NOT_ACCEPTABLE.into_response();
        }
        match id {
            1 => m.manifest.to_string().into_response(),
            // GitHub redirects the download to its storage.
            2 => Redirect::to("/storage/2").into_response(),
            _ => "you should not be able to download this".into_response(),
        }
    }
    let app = Router::new()
        .route("/repos/o/r/releases", get(list))
        .route("/repos/o/r/releases/assets/{id}", get(asset))
        .route("/storage/2", get(|| async { ARTIFACT }))
        .with_state(Mock {
            manifest: Arc::new(manifest),
            releases: Arc::new(releases),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

/// Server with updates enabled against `github`.
async fn server_with_updates(github: &str) -> (String, tempfile::TempDir) {
    // SAFETY: every test sets the same value.
    unsafe { std::env::set_var("AKS_TEST_UPDATES_TOKEN", TOKEN) };
    let data = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut config = ServerConfig::default();
    config.server.listen = addr;
    config.server.data_dir = data.path().to_path_buf();
    config.updates.github_repo = Some("o/r".into());
    config.updates.github_api = github.to_string();
    config.updates.github_token_env = "AKS_TEST_UPDATES_TOKEN".into();
    let state = build_state(config).await.unwrap();
    tokio::spawn(async move { axum::serve(listener, routes::router(state)).await.unwrap() });
    (format!("http://{addr}"), data)
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
