//! Basic web app bundled with the server: sign in and sign up, sessions
//! (with a terminal in the browser), teams and account settings. It is a
//! single-page application without a build step (HTML, CSS and JavaScript in
//! `web/`, embedded in the binary) that uses the same API as the apps.
//!
//! Translations live in `web/locales/<lang>.json`; `/assets/locales.json`
//! lists the available ones (see docs/I18N.md), so adding a language only
//! takes a new file.
//!
//! Security: strict CSP (own resources only, no inline scripts),
//! `Referrer-Policy: no-referrer` (email links carry tokens) and no frames.
//!
//! Besides `/assets/`, a few well-known files are served at the root when the
//! web has them: `/robots.txt`, `/sitemap.xml`, the favicons, the web app
//! manifest and `/.well-known/*` (see [`ROOT_FILES`]). The embedded web only
//! has a `robots.txt` that disallows everything: a self-hosted server is not
//! indexed by search engines by default.
//!
//! A front-end served from a directory may also ship prerendered pages:
//! `prerendered/<path>.html` (or `prerendered/<path>/index.html`) is served
//! for `GET /<path>` instead of `index.html`, so search engines and visitors
//! get the content in the HTML before the JavaScript runs.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::state::AppState;

include!(concat!(env!("OUT_DIR"), "/web_files.rs"));

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; \
                   img-src 'self' data:; connect-src 'self'; font-src 'self'; \
                   object-src 'none'; base-uri 'none'; form-action 'self'; \
                   frame-ancestors 'none'";

/// Application routes that return `index.html`.
const PAGES: &[&str] = &[
    "/",
    "/login",
    "/signup",
    "/forgot-password",
    "/reset-password",
    "/verify-email",
    "/check-email",
    "/confirm-email",
    "/invite/{token}",
    "/join/{token}",
    "/app",
    "/app/{*rest}",
];

/// Well-known files served at the root of the site (from the root of the web
/// directory, or of the embedded web) when they exist, besides
/// `/.well-known/*`.
const ROOT_FILES: &[&str] = &[
    "robots.txt",
    "sitemap.xml",
    "favicon.ico",
    "favicon.svg",
    "apple-touch-icon.png",
    "apple-touch-icon-precomposed.png",
    "site.webmanifest",
    "manifest.webmanifest",
];

/// Folder of the prerendered pages inside the web directory.
const PRERENDERED: &str = "prerendered";

pub fn routes(state: &AppState) -> Router<AppState> {
    if !state.config.web.enabled {
        return Router::new();
    }
    let mut r = Router::new()
        .route("/assets/{*file}", get(asset))
        .route("/.well-known/{*file}", get(well_known));
    for name in ROOT_FILES {
        r = r.route(&format!("/{name}"), get(root_file));
    }
    for p in PAGES {
        r = r.route(p, get(index));
    }
    if state.config.web.dir.is_some() || std::env::var_os("TERMOAK_WEB_DIR").is_some() {
        // A custom front-end has its own pages: every other GET outside the
        // API gets its index.html (or its prerendered page).
        r = r.fallback(custom_page);
    }
    r
}

/// Where the web files come from.
enum Source {
    /// The basic web app embedded in the binary.
    Embedded,
    /// A directory (`[web] dir`, or `TERMOAK_WEB_DIR` while developing, which
    /// also disables caching).
    Dir { path: std::path::PathBuf, dev: bool },
}

fn source(st: &AppState) -> Source {
    if let Some(path) = std::env::var_os("TERMOAK_WEB_DIR") {
        return Source::Dir {
            path: path.into(),
            dev: true,
        };
    }
    match &st.config.web.dir {
        Some(path) => Source::Dir {
            path: path.clone(),
            dev: false,
        },
        None => Source::Embedded,
    }
}

/// Embedded file: MIME type, ETag and content.
fn embedded(name: &str) -> Option<(&'static str, &'static str, &'static [u8])> {
    WEB_FILES
        .iter()
        .find(|(n, _, _, _)| *n == name)
        .map(|(_, mime, etag, body)| (*mime, *etag, *body))
}

fn mime_of(name: &str) -> &'static str {
    let file_name = name.rsplit('/').next().unwrap_or(name);
    match file_name.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "webmanifest" => "application/manifest+json",
        "apple-app-site-association" => "application/json",
        _ => "application/octet-stream",
    }
}

/// Is `name` a safe relative path inside the web? (no empty, `.` or `..`
/// segments, no backslashes or NUL).
fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && !name
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
        && !name.contains(['\\', '\0'])
}

/// A file of the web: MIME type, ETag and content.
fn file(
    src: &Source,
    name: &str,
) -> Option<(&'static str, String, std::borrow::Cow<'static, [u8]>)> {
    match src {
        Source::Embedded => embedded(name).map(|(m, e, b)| (m, e.to_string(), b.into())),
        Source::Dir { path, dev } => {
            if !safe_name(name) {
                return None;
            }
            let full = path.join(name);
            if !full.is_file() {
                return None;
            }
            let body = std::fs::read(full).ok()?;
            let etag = if *dev {
                "\"dev\"".to_string()
            } else {
                fingerprint(&body)
            };
            Some((mime_of(name), etag, body.into()))
        }
    }
}

/// Content fingerprint (64-bit FNV-1a) for the ETag, as in build.rs.
fn fingerprint(data: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in data {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("\"{h:016x}\"")
}

/// Generated list of the available translations.
const LOCALES_INDEX: &str = "locales.json";

/// Translation files (`locales/<lang>.json`): `(code, content)`.
fn locale_files(src: &Source) -> Vec<(String, Vec<u8>)> {
    let code_of = |name: &str| -> Option<String> {
        let code = name.strip_prefix("locales/")?.strip_suffix(".json")?;
        let valid = !code.is_empty()
            && code.len() <= 16
            && code.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        valid.then(|| code.to_string())
    };
    if let Source::Dir { path, .. } = src {
        let Ok(entries) = std::fs::read_dir(path.join("locales")) else {
            return Vec::new();
        };
        return entries
            .flatten()
            .filter_map(|e| {
                let name = format!("locales/{}", e.file_name().to_string_lossy());
                let code = code_of(&name)?;
                Some((code, std::fs::read(e.path()).ok()?))
            })
            .collect();
    }
    WEB_FILES
        .iter()
        .filter_map(|(n, _, _, body)| Some((code_of(n)?, body.to_vec())))
        .collect()
}

/// `[{"code": "en", "name": "English"}, ...]`: every translation file with
/// its `language.name`, English first and then by code.
fn locales_index(src: &Source) -> serde_json::Value {
    let mut list: Vec<(String, String)> = locale_files(src)
        .into_iter()
        .filter_map(|(code, body)| {
            let json: serde_json::Value = serde_json::from_slice(&body).ok()?;
            let name = json
                .get("language.name")
                .and_then(|v| v.as_str())
                .unwrap_or(&code)
                .to_string();
            Some((code, name))
        })
        .collect();
    list.sort_by(|a, b| (a.0 != "en", &a.0).cmp(&(b.0 != "en", &b.0)));
    serde_json::Value::Array(
        list.into_iter()
            .map(|(code, name)| serde_json::json!({"code": code, "name": name}))
            .collect(),
    )
}

fn secure(mut headers: HeaderMap) -> HeaderMap {
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers
}

/// The prerendered page for a request path, if the web directory has one:
/// `/` → `prerendered/index.html`, `/es/pricing/` →
/// `prerendered/es/pricing.html` or `prerendered/es/pricing/index.html`.
/// Only plain path segments (letters, digits, `-`, `_` and `.`, not starting
/// with a dot) are looked up.
fn prerendered(src: &Source, path: &str) -> Option<std::borrow::Cow<'static, [u8]>> {
    let Source::Dir { .. } = src else {
        return None;
    };
    let rel = path.strip_prefix('/')?;
    let rel = rel.strip_suffix('/').unwrap_or(rel);
    if rel.is_empty() {
        return file(src, &format!("{PRERENDERED}/index.html")).map(|(_, _, b)| b);
    }
    let plain = rel.split('/').all(|seg| {
        !seg.is_empty()
            && !seg.starts_with('.')
            && seg
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    });
    if !plain {
        return None;
    }
    [
        format!("{PRERENDERED}/{rel}.html"),
        format!("{PRERENDERED}/{rel}/index.html"),
    ]
    .iter()
    .find_map(|name| file(src, name))
    .map(|(_, _, b)| b)
}

/// The page for a path: its prerendered HTML if there is one, else
/// `index.html` (the front-end renders it).
async fn index(State(st): State<AppState>, uri: Uri) -> Response {
    let src = source(&st);
    let page =
        prerendered(&src, uri.path()).or_else(|| file(&src, "index.html").map(|(_, _, b)| b));
    let Some(body) = page else {
        return (StatusCode::NOT_FOUND, "web not available").into_response();
    };
    let mime = "text/html; charset=utf-8";
    // The version in the asset URLs invalidates the cache on upgrades.
    let html = String::from_utf8_lossy(&body).replace("{{VERSION}}", env!("CARGO_PKG_VERSION"));
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    (secure(headers), html).into_response()
}

/// Assets with ETag: the browser always revalidates them (`no-cache`) and,
/// if they have not changed, gets a 304 without a body.
async fn asset(
    State(st): State<AppState>,
    Path(name): Path<String>,
    req_headers: HeaderMap,
) -> Response {
    let src = source(&st);
    // Pages are served at their own paths (with the version filled in).
    if name == "index.html" || name.starts_with(&format!("{PRERENDERED}/")) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if name == LOCALES_INDEX {
        let mut headers = HeaderMap::new();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return (secure(headers), locales_index(&src).to_string()).into_response();
    }
    let Some((mime, etag, body)) = file(&src, &name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&etag) {
        headers.insert(header::ETAG, v);
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    let fresh = !matches!(src, Source::Dir { dev: true, .. })
        && req_headers
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(',').any(|t| t.trim() == etag));
    if fresh {
        return (StatusCode::NOT_MODIFIED, secure(headers)).into_response();
    }
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
    (secure(headers), body.into_owned()).into_response()
}

/// Fallback with a custom front-end (`[web] dir`): its pages for any `GET`
/// outside the API, a plain 404 otherwise.
async fn custom_page(State(st): State<AppState>, method: Method, uri: Uri) -> Response {
    let path = uri.path();
    let api = ["/api/", "/assets/", "/healthz"]
        .iter()
        .any(|p| path.starts_with(p));
    if !(method == Method::GET || method == Method::HEAD) || api {
        return StatusCode::NOT_FOUND.into_response();
    }
    index(State(st), uri).await
}

/// `/robots.txt`, `/favicon.ico`... from the root of the web (404 if it does
/// not have the file).
async fn root_file(State(st): State<AppState>, uri: Uri, req_headers: HeaderMap) -> Response {
    let name = uri.path().trim_start_matches('/');
    static_file(&source(&st), name, &req_headers)
}

/// `/.well-known/<file>` from the web's `.well-known/` folder.
async fn well_known(
    State(st): State<AppState>,
    Path(name): Path<String>,
    req_headers: HeaderMap,
) -> Response {
    static_file(&source(&st), &format!(".well-known/{name}"), &req_headers)
}

/// A file served at the root: ETag and a short public cache (an hour; a day
/// for the icons), none while developing (`TERMOAK_WEB_DIR`).
fn static_file(src: &Source, name: &str, req_headers: &HeaderMap) -> Response {
    let Some((mime, etag, body)) = file(src, name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let dev = matches!(src, Source::Dir { dev: true, .. });
    let cache = if dev {
        "no-cache"
    } else if mime.starts_with("image/") {
        "public, max-age=86400"
    } else {
        "public, max-age=3600"
    };
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&etag) {
        headers.insert(header::ETAG, v);
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    let fresh = !dev
        && req_headers
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(',').any(|t| t.trim() == etag));
    if fresh {
        return (StatusCode::NOT_MODIFIED, secure(headers)).into_response();
    }
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
    (secure(headers), body.into_owned()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_is_embedded() {
        assert!(
            embedded("index.html").is_some(),
            "web/index.html is missing"
        );
        let (mime, etag, _) = embedded("icon.svg").unwrap();
        assert_eq!(mime, "image/svg+xml");
        assert!(etag.starts_with('"') && etag.len() == 18);
        assert!(embedded("../Cargo.toml").is_none());
        assert_eq!(mime_of("app.js"), "text/javascript; charset=utf-8");
    }

    #[test]
    fn root_file_types() {
        assert_eq!(mime_of("sitemap.xml"), "application/xml; charset=utf-8");
        assert_eq!(mime_of("site.webmanifest"), "application/manifest+json");
        assert_eq!(
            mime_of(".well-known/security.txt"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            mime_of(".well-known/apple-app-site-association"),
            "application/json"
        );
        assert_eq!(mime_of(".well-known/other"), "application/octet-stream");
        assert!(safe_name(".well-known/security.txt"));
        for bad in ["", "../x", "a//b", "a/./b", "a\\b", "a\0b", "/etc/passwd"] {
            assert!(!safe_name(bad), "{bad}");
        }
        let (mime, _, body) = embedded("robots.txt").unwrap();
        assert_eq!(mime, "text/plain; charset=utf-8");
        assert!(String::from_utf8_lossy(body).contains("Disallow: /\n"));
    }

    #[test]
    fn prerendered_pages_are_looked_up_safely() {
        let dir = std::env::temp_dir().join(format!("termoak-web-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for name in [
            "index.html",
            "pricing.html",
            "es/index.html",
            "es/pricing.html",
        ] {
            let path = dir.join(PRERENDERED).join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, name).unwrap();
        }
        let src = Source::Dir {
            path: dir.clone(),
            dev: true,
        };
        let page = |p: &str| prerendered(&src, p).map(|b| String::from_utf8_lossy(&b).to_string());
        assert_eq!(page("/").as_deref(), Some("index.html"));
        assert_eq!(page("/pricing").as_deref(), Some("pricing.html"));
        assert_eq!(page("/pricing/").as_deref(), Some("pricing.html"));
        assert_eq!(page("/es").as_deref(), Some("es/index.html"));
        assert_eq!(page("/es/").as_deref(), Some("es/index.html"));
        assert_eq!(page("/es/pricing").as_deref(), Some("es/pricing.html"));
        for p in [
            "/login",
            "/es/..",
            "/es/../pricing",
            "/es//pricing",
            "/%2e%2e/x",
            "/.x",
            "/es\\pricing",
            "/pricing//",
        ] {
            assert_eq!(page(p), None, "{p}");
        }
        assert!(prerendered(&Source::Embedded, "/").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn locales_are_listed() {
        let list = locales_index(&Source::Embedded);
        let list = list.as_array().unwrap();
        assert_eq!(list[0]["code"], "en");
        assert_eq!(list[0]["name"], "English");
        assert!(
            list.iter()
                .any(|l| l["code"] == "es" && l["name"] == "Español")
        );
        assert!(embedded("locales/en.json").is_some());
    }
}
