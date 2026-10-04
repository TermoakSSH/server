//! Desktop updates and downloads served from this server.
//!
//! If the GitHub repository is private, its release files cannot be
//! downloaded without authenticating, and the app cannot carry a token. The
//! server acts as a proxy: it reads the releases with a read-only token and
//! offers them on public routes.
//!
//! Desktop, server, CLI, Android and iOS are released separately, each with
//! its own version and tag (`desktop-vX.Y.Z`, `server-vX.Y.Z`,
//! `cli-vX.Y.Z`, `android-vX.Y.Z`, `ios-vX.Y.Z`).
//! The newest release of each component is used. The old `vX.Y.Z` tags,
//! which carried everything, count for the three components until each one
//! has a newer release of its own.
//!
//! - `GET /updates/latest.json`: the manifest of the latest desktop release,
//!   with the download URLs rewritten to point to this server.
//! - `GET /updates/download/{file}`: the artifact, streamed. Only the files
//!   of the latest release of each component are served.
//! - `GET /api/v1/downloads`: what can be downloaded, with the version of
//!   each component (for the web downloads page).
//!
//! Rewriting the URLs breaks nothing: the Ed25519 signature covers platform,
//! version and SHA-256, not the URL, and the app checks both before
//! installing.
//!
//! Disabled unless `[updates] github_repo` is configured.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::config::UpdatesSection;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// How long the latest release information is reused.
const CACHE_FOR: Duration = Duration::from_secs(5 * 60);
const MANIFEST: &str = "latest.json";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/updates/latest.json", get(latest))
        .route("/updates/download/{name}", get(download))
        .route("/api/v1/downloads", get(downloads))
}

/// Proxy for the GitHub releases.
pub struct UpdateProxy {
    http: reqwest::Client,
    api: String,
    repo: String,
    token: Option<String>,
    cache: Mutex<Option<(Instant, Arc<Published>)>>,
}

/// What is released separately, each with its own version and tag.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Component {
    Desktop,
    Server,
    Cli,
    Android,
    Ios,
}

impl Component {
    const ALL: [Component; 5] = [
        Component::Desktop,
        Component::Server,
        Component::Cli,
        Component::Android,
        Component::Ios,
    ];

    /// The mobile apps were not part of the old `vX.Y.Z`.
    fn mobile(self) -> bool {
        matches!(self, Component::Android | Component::Ios)
    }

    fn id(self) -> &'static str {
        match self {
            Component::Desktop => "desktop",
            Component::Server => "server",
            Component::Cli => "cli",
            Component::Android => "android",
            Component::Ios => "ios",
        }
    }
}

/// Component and version of a tag: `desktop-v0.2.0`, `server-v0.2.0`,
/// `cli-v0.2.0` or, from before they were split, `v0.1.2` (all at once: `None`).
fn parse_tag(tag: &str) -> Option<(Option<Component>, semver::Version)> {
    let (component, version) = match tag.split_once("-v") {
        Some(("desktop", v)) => (Some(Component::Desktop), v),
        Some(("server", v)) => (Some(Component::Server), v),
        Some(("cli", v)) => (Some(Component::Cli), v),
        Some(("android", v)) => (Some(Component::Android), v),
        Some(("ios", v)) => (Some(Component::Ios), v),
        _ => (None, tag.strip_prefix('v')?),
    };
    Some((component, semver::Version::parse(version).ok()?))
}

/// Latest release of each component and the files that can be downloaded.
struct Published {
    latest: HashMap<Component, Chosen>,
    /// `latest.json` of the latest desktop release.
    manifest: Result<Value, ApiError>,
    /// File name → GitHub asset and the component it belongs to.
    assets: HashMap<String, (GhAsset, Component)>,
    /// Files from an older desktop version (file → version).
    older: HashMap<String, String>,
}

struct Chosen {
    tag: String,
    version: semver::Version,
}

#[derive(Deserialize)]
struct GhRelease {
    #[serde(default)]
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<GhAsset>,
}

#[derive(Deserialize, Clone)]
struct GhAsset {
    id: u64,
    name: String,
    #[serde(default)]
    size: u64,
}

/// OS and kind of a release file, by its name.
fn classify(name: &str) -> (&'static str, &'static str) {
    let n = name.to_lowercase();
    let os = if n.ends_with(".apk") || n.contains("android") {
        "android"
    } else if n.ends_with(".ipa") {
        "ios"
    } else if n.contains("windows") {
        "windows"
    } else if n.contains("macos") {
        "macos"
    } else if n.contains("linux") {
        "linux"
    } else {
        "any"
    };
    let kind = if n == MANIFEST {
        "manifest"
    } else if n.ends_with(".dmg")
        || n.ends_with(".appimage")
        || n.ends_with(".exe")
        || n.ends_with(".apk")
        || n.ends_with(".ipa")
    {
        "app"
    } else if n.ends_with(".app.tar.gz") {
        "update"
    } else if n.starts_with("termoak-desktop-") {
        "app-archive"
    } else if n.starts_with("termoak-cli-") {
        "cli"
    } else if n.starts_with("termoak-") {
        // `termoak-server-v…` or, in old releases, `termoak-v…`
        // (server and CLI together).
        "server"
    } else {
        "other"
    };
    (os, kind)
}

/// Does this release file belong to this component?
/// `release` is the tag's component (`None` in the old `vX.Y.Z`).
fn belongs(name: &str, component: Component, release: Option<Component>) -> bool {
    match (classify(name), component) {
        (("android", _), c) => c == Component::Android,
        (("ios", _), c) => c == Component::Ios,
        ((_, "manifest" | "app" | "update" | "app-archive"), c) => c == Component::Desktop,
        ((_, "cli"), c) => c == Component::Cli,
        // In old releases the same archive carries the server and the CLI.
        ((_, "server"), c) => c == Component::Server || (release.is_none() && c == Component::Cli),
        (_, c) => c == release.unwrap_or(Component::Desktop),
    }
}

impl UpdateProxy {
    /// Creates the proxy if the config enables it.
    pub fn from_config(cfg: &UpdatesSection) -> Option<Arc<Self>> {
        let repo = cfg.github_repo.as_deref().map(str::trim).filter(|r| {
            let valid = r.split('/').count() == 2 && !r.starts_with('/') && !r.ends_with('/');
            if !valid && !r.is_empty() {
                tracing::warn!(repo = r, "updates.github_repo must be owner/repository");
            }
            valid
        })?;
        let token = std::env::var(&cfg.github_token_env)
            .ok()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty());
        if token.is_none() {
            tracing::warn!(
                var = %cfg.github_token_env,
                "updates: no GitHub token; this only works if the repository is public"
            );
        }
        let http = reqwest::Client::builder()
            .user_agent(concat!("termoak-server/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(15))
            .build()
            .ok()?;
        Some(Arc::new(Self {
            http,
            api: cfg.github_api.trim_end_matches('/').to_string(),
            repo: repo.to_string(),
            token,
            cache: Mutex::new(None),
        }))
    }

    fn request(&self, url: &str, accept: &str) -> reqwest::RequestBuilder {
        let mut req = self
            .http
            .get(url)
            .header(header::ACCEPT, accept)
            .header("X-GitHub-Api-Version", "2022-11-28");
        if let Some(token) = &self.token {
            // reqwest drops this header if GitHub redirects to another domain
            // (the actual download goes to its storage with a signed URL).
            req = req.bearer_auth(token);
        }
        req
    }

    /// Published releases (cached).
    async fn published(&self) -> ApiResult<Arc<Published>> {
        let mut cache = self.cache.lock().await;
        if let Some((at, published)) = cache.as_ref()
            && at.elapsed() < CACHE_FOR
        {
            return Ok(published.clone());
        }
        let published = Arc::new(self.fetch_published().await?);
        *cache = Some((Instant::now(), published.clone()));
        Ok(published)
    }

    async fn fetch_published(&self) -> ApiResult<Published> {
        // Newest first; 100 is more than enough to find the latest one of
        // each component.
        let url = format!("{}/repos/{}/releases?per_page=100", self.api, self.repo);
        let resp = self
            .request(&url, "application/vnd.github+json")
            .send()
            .await
            .map_err(|e| upstream(format!("could not query GitHub: {e}")))?;
        match resp.status() {
            s if s.is_success() => {}
            StatusCode::NOT_FOUND => {
                return Err(ApiError::not_found(
                    "repository not found (or the token has no access)",
                ));
            }
            s => {
                return Err(upstream(format!(
                    "GitHub answered {s} when listing the releases"
                )));
            }
        }
        let releases: Vec<GhRelease> = resp
            .json()
            .await
            .map_err(|e| upstream(format!("invalid GitHub response: {e}")))?;
        let published = choose(releases);
        if published.latest.is_empty() {
            return Err(ApiError::not_found("there is no published release"));
        }
        let manifest = match published.manifest_id {
            Some(id) => self.manifest(id, &published.assets).await,
            None => Err(ApiError::not_found("there is no published desktop version")),
        };
        Ok(Published {
            latest: published.latest,
            manifest,
            assets: published.assets,
            older: published.older,
        })
    }

    /// Downloads `latest.json` and checks that its files can be served.
    async fn manifest(
        &self,
        id: u64,
        assets: &HashMap<String, (GhAsset, Component)>,
    ) -> ApiResult<Value> {
        let manifest: Value = self
            .asset(id)
            .await?
            .json()
            .await
            .map_err(|e| upstream(format!("invalid latest.json: {e}")))?;
        for name in manifest_files(&manifest)? {
            if !matches!(assets.get(&name), Some((_, Component::Desktop))) {
                return Err(upstream(format!(
                    "latest.json lists {name}, but it is not in the release"
                )));
            }
        }
        Ok(manifest)
    }

    /// Downloads an asset (follows the GitHub redirect).
    async fn asset(&self, id: u64) -> ApiResult<reqwest::Response> {
        let url = format!("{}/repos/{}/releases/assets/{id}", self.api, self.repo);
        let resp = self
            .request(&url, "application/octet-stream")
            .send()
            .await
            .map_err(|e| upstream(format!("could not download from GitHub: {e}")))?;
        if !resp.status().is_success() {
            return Err(upstream(format!(
                "GitHub answered {} when downloading a file",
                resp.status()
            )));
        }
        Ok(resp)
    }
}

fn upstream(message: String) -> ApiError {
    tracing::warn!(%message, "updates");
    ApiError::new(StatusCode::BAD_GATEWAY, "updates_upstream", message)
}

/// Result of choosing releases, before downloading `latest.json`.
struct Choice {
    latest: HashMap<Component, Chosen>,
    manifest_id: Option<u64>,
    assets: HashMap<String, (GhAsset, Component)>,
    /// Desktop files from an older version (file → version): those for an
    /// OS the latest version does not include yet.
    older: HashMap<String, String>,
}

/// Picks the newest release of each component (no drafts or
/// pre-releases). At the same version, the component's own tag wins over an
/// old `vX.Y.Z`.
fn choose(releases: Vec<GhRelease>) -> Choice {
    let mut best: HashMap<Component, (semver::Version, bool, usize)> = HashMap::new();
    for (i, r) in releases.iter().enumerate() {
        if r.draft || r.prerelease {
            continue;
        }
        let Some((own, version)) = parse_tag(&r.tag_name) else {
            continue;
        };
        for c in Component::ALL {
            // The old `vX.Y.Z` did not carry the mobile apps.
            if own.map_or(c.mobile(), |o| o != c) {
                continue;
            }
            let candidate = (version.clone(), own.is_some(), i);
            let better = match best.get(&c) {
                None => true,
                Some((v, specific, _)) => (&candidate.0, candidate.1) > (v, *specific),
            };
            if better {
                best.insert(c, candidate);
            }
        }
    }
    let mut latest = HashMap::new();
    let mut assets = HashMap::new();
    let mut manifest_id = None;
    // In a fixed order: if an old release is the latest for both the server
    // and the CLI, its combined archive is assigned to the server.
    for c in Component::ALL {
        let Some((version, _, i)) = best.remove(&c) else {
            continue;
        };
        let release = &releases[i];
        let own = parse_tag(&release.tag_name).and_then(|(own, _)| own);
        for a in &release.assets {
            if !belongs(&a.name, c, own) {
                continue;
            }
            if c == Component::Desktop && a.name == MANIFEST {
                manifest_id = Some(a.id);
            }
            assets
                .entry(a.name.clone())
                .or_insert_with(|| (a.clone(), c));
        }
        latest.insert(
            c,
            Chosen {
                tag: release.tag_name.clone(),
                version,
            },
        );
    }
    let older = fill_missing_desktop_systems(&releases, &mut assets);
    Choice {
        latest,
        manifest_id,
        assets,
        older,
    }
}

/// If the latest desktop version lacks an OS (e.g. macOS is not built yet),
/// the web offers the one from the most recent older version that has it.
/// `latest.json` does not change: automatic updates only go to the latest
/// version.
fn fill_missing_desktop_systems(
    releases: &[GhRelease],
    assets: &mut HashMap<String, (GhAsset, Component)>,
) -> HashMap<String, String> {
    let desktop_file = |name: &str| matches!(classify(name).1, "app" | "update" | "app-archive");
    let mut has: std::collections::HashSet<&'static str> = assets
        .iter()
        .filter(|(n, (_, c))| *c == Component::Desktop && desktop_file(n))
        .map(|(n, _)| classify(n).0)
        .collect();
    let mut candidates: Vec<(semver::Version, &GhRelease)> = releases
        .iter()
        .filter(|r| !r.draft && !r.prerelease)
        .filter_map(|r| match parse_tag(&r.tag_name) {
            Some((None | Some(Component::Desktop), v)) => Some((v, r)),
            _ => None,
        })
        .collect();
    candidates.sort_by(|a, b| b.0.cmp(&a.0));
    let mut older = HashMap::new();
    for os in ["macos", "windows", "linux"] {
        if has.contains(os) {
            continue;
        }
        let found = candidates.iter().find(|(_, r)| {
            r.assets
                .iter()
                .any(|a| desktop_file(&a.name) && classify(&a.name).0 == os)
        });
        if let Some((version, r)) = found {
            for a in r
                .assets
                .iter()
                .filter(|a| desktop_file(&a.name) && classify(&a.name).0 == os)
            {
                if !assets.contains_key(&a.name) {
                    assets.insert(a.name.clone(), (a.clone(), Component::Desktop));
                    older.insert(a.name.clone(), version.to_string());
                }
            }
            has.insert(os);
        }
    }
    older
}

/// File name of each platform in the manifest (last segment of its URL).
fn manifest_files(manifest: &Value) -> ApiResult<Vec<String>> {
    let platforms = manifest
        .get("platforms")
        .and_then(Value::as_object)
        .ok_or_else(|| upstream("latest.json has no \"platforms\"".into()))?;
    platforms
        .values()
        .map(|asset| {
            asset
                .get("url")
                .and_then(Value::as_str)
                .and_then(|u| u.rsplit('/').next())
                .filter(|n| !n.is_empty())
                .map(str::to_string)
                .ok_or_else(|| upstream("latest.json has a platform without a URL".into()))
        })
        .collect()
}

/// Manifest with the URLs pointing to `base/updates/download/`.
fn rewrite(manifest: &Value, base: &str) -> Value {
    let mut out = manifest.clone();
    if let Some(platforms) = out.get_mut("platforms").and_then(Value::as_object_mut) {
        let names: BTreeMap<String, String> = platforms
            .iter()
            .filter_map(|(k, v)| {
                let name = v.get("url")?.as_str()?.rsplit('/').next()?.to_string();
                Some((k.clone(), name))
            })
            .collect();
        for (platform, name) in names {
            if let Some(asset) = platforms.get_mut(&platform) {
                asset["url"] = Value::String(format!("{base}/updates/download/{name}"));
            }
        }
    }
    out
}

/// Public URL of this server: `public_url` or, if unset, the request's.
fn base_url(st: &AppState, headers: &HeaderMap) -> String {
    if let Some(url) = st.config.server.public_url.as_deref() {
        return url.trim_end_matches('/').to_string();
    }
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|h| h.to_str().ok());
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or(if st.config.server.tls_cert.is_some() {
            "https"
        } else {
            "http"
        });
    match host {
        Some(host) => format!("{proto}://{host}"),
        None => st.config.base_url(),
    }
}

fn proxy(st: &AppState) -> ApiResult<&Arc<UpdateProxy>> {
    st.updates.as_ref().ok_or_else(|| {
        ApiError::not_found("this server does not serve updates").with_code("updates_disabled")
    })
}

async fn latest(State(st): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    let published = proxy(&st)?.published().await?;
    let manifest = published
        .manifest
        .as_ref()
        .map_err(|e| ApiError::new(e.status, e.code, e.message.clone()))?;
    let body = rewrite(manifest, &base_url(&st, &headers));
    Ok((
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body.to_string(),
    )
        .into_response())
}

/// Files of the latest version of each component for the downloads page.
/// `version` and `tag` are the desktop ones.
async fn downloads(State(st): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    let published = proxy(&st)?.published().await?;
    let base = base_url(&st, &headers);
    let mut files: Vec<Value> = published
        .assets
        .values()
        .map(|(a, c)| {
            let (os, kind) = classify(&a.name);
            serde_json::json!({
                "name": a.name,
                "size": a.size,
                "os": os,
                "kind": kind,
                "component": c.id(),
                "url": format!("{base}/updates/download/{}", a.name),
                // Only on files from an older desktop version.
                "version": published.older.get(&a.name),
            })
        })
        .collect();
    files.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    let components: serde_json::Map<String, Value> = Component::ALL
        .iter()
        .filter_map(|c| {
            let chosen = published.latest.get(c)?;
            Some((
                c.id().to_string(),
                serde_json::json!({"version": chosen.version.to_string(), "tag": chosen.tag}),
            ))
        })
        .collect();
    let desktop = published.latest.get(&Component::Desktop);
    Ok((
        [(header::CACHE_CONTROL, "public, max-age=300")],
        axum::Json(serde_json::json!({
            "version": desktop.map(|d| d.version.to_string()),
            "tag": desktop.map(|d| d.tag.clone()),
            "components": components,
            "files": files,
        })),
    )
        .into_response())
}

async fn download(State(st): State<AppState>, Path(name): Path<String>) -> ApiResult<Response> {
    let proxy = proxy(&st)?;
    let published = proxy.published().await?;
    let id = published
        .assets
        .get(&name)
        .ok_or_else(|| ApiError::not_found("that file is not part of the latest version"))?
        .0
        .id;
    let resp = proxy.asset(id).await?;
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{name}\""),
        );
    if let Some(len) = resp.content_length() {
        builder = builder.header(header::CONTENT_LENGTH, len);
    }
    builder
        .body(Body::from_stream(resp.bytes_stream()))
        .map_err(|e| ApiError::internal(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_release_files() {
        assert_eq!(
            classify("Termoak-v0.1.2-macos-universal.dmg"),
            ("macos", "app")
        );
        assert_eq!(classify("Termoak-linux-x86_64.AppImage"), ("linux", "app"));
        assert_eq!(classify("Termoak-windows-x86_64.exe"), ("windows", "app"));
        assert_eq!(
            classify("Termoak-macos-universal.app.tar.gz"),
            ("macos", "update")
        );
        assert_eq!(
            classify("termoak-desktop-v0.1.2-linux-x86_64.tar.gz"),
            ("linux", "app-archive")
        );
        assert_eq!(
            classify("termoak-v0.1.2-linux-aarch64.tar.gz"),
            ("linux", "server")
        );
        assert_eq!(
            classify("termoak-server-v0.2.0-linux-x86_64.tar.gz"),
            ("linux", "server")
        );
        assert_eq!(
            classify("termoak-cli-v0.2.0-windows-x86_64.zip"),
            ("windows", "cli")
        );
        assert_eq!(classify("latest.json"), ("any", "manifest"));
        assert_eq!(classify("Termoak-android-v0.1.0.apk"), ("android", "app"));
    }

    #[test]
    fn parses_component_tags() {
        let v = |s| semver::Version::parse(s).unwrap();
        assert_eq!(
            parse_tag("desktop-v0.2.0"),
            Some((Some(Component::Desktop), v("0.2.0")))
        );
        assert_eq!(
            parse_tag("server-v1.0.0-rc.1"),
            Some((Some(Component::Server), v("1.0.0-rc.1")))
        );
        assert_eq!(
            parse_tag("cli-v0.3.1"),
            Some((Some(Component::Cli), v("0.3.1")))
        );
        assert_eq!(parse_tag("v0.1.2"), Some((None, v("0.1.2"))));
        assert_eq!(
            parse_tag("android-v0.1.0"),
            Some((Some(Component::Android), v("0.1.0")))
        );
        assert_eq!(parse_tag("mobile-v0.1.0"), None);
        assert_eq!(parse_tag("desktop-vX"), None);
        assert_eq!(parse_tag("latest"), None);
    }

    fn release(tag: &str, names: &[&str]) -> GhRelease {
        GhRelease {
            tag_name: tag.into(),
            draft: false,
            prerelease: false,
            assets: names
                .iter()
                .enumerate()
                .map(|(i, n)| GhAsset {
                    id: i as u64,
                    name: n.to_string(),
                    size: 0,
                })
                .collect(),
        }
    }

    #[test]
    fn chooses_latest_release_of_each_component() {
        let legacy = [
            "latest.json",
            "Termoak-linux-x86_64.AppImage",
            "termoak-v0.1.2-linux-x86_64.tar.gz",
        ];
        let mut draft = release("desktop-v9.0.0", &["latest.json"]);
        draft.draft = true;
        let releases = vec![
            draft,
            release(
                "server-v0.3.0",
                &["termoak-server-v0.3.0-linux-x86_64.tar.gz"],
            ),
            release(
                "desktop-v0.2.0",
                &["latest.json", "Termoak-linux-x86_64.AppImage"],
            ),
            release("v0.1.2", &legacy),
            release("desktop-v0.1.9", &["latest.json"]),
        ];
        let choice = choose(releases);
        let tag = |c| choice.latest.get(&c).map(|x: &Chosen| x.tag.as_str());
        assert_eq!(tag(Component::Desktop), Some("desktop-v0.2.0"));
        assert_eq!(tag(Component::Server), Some("server-v0.3.0"));
        // The CLI has no release of its own yet: it stays on the old one.
        assert_eq!(tag(Component::Cli), Some("v0.1.2"));
        // latest.json is the one from desktop-v0.2.0 (index 0 in that release).
        assert_eq!(choice.manifest_id, Some(0));
        let owner = |n: &str| choice.assets.get(n).map(|(_, c)| *c);
        assert_eq!(
            owner("Termoak-linux-x86_64.AppImage"),
            Some(Component::Desktop)
        );
        assert_eq!(
            choice.assets["Termoak-linux-x86_64.AppImage"].0.id, 1,
            "the AppImage is the desktop-v0.2.0 one, not the v0.1.2 one"
        );
        assert_eq!(
            owner("termoak-server-v0.3.0-linux-x86_64.tar.gz"),
            Some(Component::Server)
        );
        // Server and CLI together from v0.1.2: only for the CLI.
        assert_eq!(
            owner("termoak-v0.1.2-linux-x86_64.tar.gz"),
            Some(Component::Cli)
        );
    }

    #[test]
    fn own_tag_wins_over_legacy_at_same_version() {
        let choice = choose(vec![
            release("v0.2.0", &["latest.json"]),
            release("desktop-v0.2.0", &["x", "latest.json"]),
        ]);
        assert_eq!(choice.latest[&Component::Desktop].tag, "desktop-v0.2.0");
        assert_eq!(choice.manifest_id, Some(1));
    }

    #[test]
    fn legacy_combined_archive_belongs_to_server() {
        // Always the same, even if HashMap iterates in another order.
        for _ in 0..20 {
            let choice = choose(vec![release(
                "v0.1.2",
                &["latest.json", "termoak-v0.1.2-linux-x86_64.tar.gz"],
            )]);
            assert_eq!(choice.latest.len(), 3);
            assert_eq!(
                choice.assets["termoak-v0.1.2-linux-x86_64.tar.gz"].1,
                Component::Server
            );
        }
    }

    #[test]
    fn android_has_its_own_releases() {
        let choice = choose(vec![
            release("android-v0.1.0", &["Termoak-android-v0.1.0.apk"]),
            release("v0.2.0", &["latest.json", "Termoak-linux-x86_64.AppImage"]),
        ]);
        assert_eq!(choice.latest[&Component::Android].tag, "android-v0.1.0");
        assert_eq!(choice.latest[&Component::Desktop].tag, "v0.2.0");
        assert_eq!(
            choice.assets["Termoak-android-v0.1.0.apk"].1,
            Component::Android
        );
        // An old release alone gives no Android version.
        let legacy = choose(vec![release("v0.2.0", &["latest.json"])]);
        assert!(!legacy.latest.contains_key(&Component::Android));
    }

    #[test]
    fn ios_has_its_own_releases() {
        assert_eq!(classify("Termoak-0.3.0-unsigned.ipa"), ("ios", "app"));
        let choice = choose(vec![
            // Just created, still without the .ipa: its version already counts.
            release("ios-v0.3.1", &[]),
            release("ios-v0.3.0", &["Termoak-0.3.0-unsigned.ipa"]),
            release("v0.2.0", &["latest.json"]),
        ]);
        assert_eq!(choice.latest[&Component::Ios].tag, "ios-v0.3.1");
        assert!(!choice.assets.contains_key("Termoak-0.3.0-unsigned.ipa"));
        let legacy = choose(vec![release("v0.2.0", &["latest.json"])]);
        assert!(!legacy.latest.contains_key(&Component::Ios));
    }

    #[test]
    fn missing_desktop_system_comes_from_an_older_release() {
        let choice = choose(vec![
            release(
                "desktop-v0.1.5",
                &[
                    "latest.json",
                    "Termoak-linux-x86_64.AppImage",
                    "Termoak-windows-x86_64.exe",
                ],
            ),
            release(
                "desktop-v0.1.4",
                &["latest.json", "Termoak-windows-x86_64.exe"],
            ),
            release(
                "desktop-v0.1.3",
                &[
                    "Termoak-v0.1.3-macos-universal.dmg",
                    "Termoak-macos-universal.app.tar.gz",
                ],
            ),
            release("desktop-v0.1.2", &["Termoak-v0.1.2-macos-universal.dmg"]),
        ]);
        assert_eq!(choice.latest[&Component::Desktop].tag, "desktop-v0.1.5");
        // macOS: from the most recent one that has it (0.1.3), not from 0.1.2.
        assert_eq!(
            choice
                .older
                .get("Termoak-v0.1.3-macos-universal.dmg")
                .map(String::as_str),
            Some("0.1.3")
        );
        assert!(
            !choice
                .assets
                .contains_key("Termoak-v0.1.2-macos-universal.dmg")
        );
        // Windows and Linux come from the latest: no separate version.
        assert!(!choice.older.contains_key("Termoak-windows-x86_64.exe"));
        assert_eq!(
            choice.assets["Termoak-windows-x86_64.exe"].0.id, 2,
            "the .exe from 0.1.5"
        );
    }

    #[test]
    fn nothing_published() {
        let choice = choose(vec![release("nightly", &["latest.json"])]);
        assert!(choice.latest.is_empty());
        assert!(choice.manifest_id.is_none());
    }

    #[test]
    fn rewrites_only_urls() {
        let m = serde_json::json!({
            "version": "0.2.0",
            "platforms": {
                "linux-x86_64": {
                    "url": "https://github.com/o/r/releases/download/v0.2.0/App.AppImage",
                    "sha256": "abc", "signature": "sig", "format": "appimage", "size": 3
                }
            }
        });
        assert_eq!(manifest_files(&m).unwrap(), vec!["App.AppImage"]);
        let out = rewrite(&m, "https://ssh.example.com");
        assert_eq!(
            out["platforms"]["linux-x86_64"]["url"],
            "https://ssh.example.com/updates/download/App.AppImage"
        );
        assert_eq!(out["platforms"]["linux-x86_64"]["sha256"], "abc");
        assert_eq!(out["platforms"]["linux-x86_64"]["signature"], "sig");
        assert_eq!(out["version"], "0.2.0");
    }
}
