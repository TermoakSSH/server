//! A front-end served from a directory (`[web] dir`): its pages, the
//! well-known files at the root and the prerendered pages.

use reqwest::StatusCode;
use reqwest::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH};
use termoak_server::config::ServerConfig;
use termoak_server::{build_state, routes};

struct Srv {
    base: String,
    http: reqwest::Client,
    _data: tempfile::TempDir,
    _web: tempfile::TempDir,
}

fn write(dir: &std::path::Path, name: &str, body: &str) {
    let path = dir.join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
}

async fn start(embedded: bool) -> Srv {
    let data = tempfile::tempdir().unwrap();
    let web = tempfile::tempdir().unwrap();
    let w = web.path();
    write(w, "index.html", "<html>shell {{VERSION}}</html>");
    write(w, "app.js", "console.log(1)");
    write(w, "robots.txt", "User-agent: *\nAllow: /\n");
    write(w, "sitemap.xml", "<?xml version=\"1.0\"?><urlset/>");
    write(w, "favicon.ico", "ico");
    write(w, "site.webmanifest", "{}");
    write(
        w,
        ".well-known/security.txt",
        "Contact: mailto:x@example.test\n",
    );
    write(w, "prerendered/index.html", "<html>home {{VERSION}}</html>");
    write(w, "prerendered/pricing.html", "<html>pricing</html>");
    write(w, "prerendered/es/index.html", "<html>inicio</html>");
    write(w, "prerendered/es/pricing.html", "<html>precios</html>");
    // Outside the web directory: must never be reachable.
    write(data.path(), "secret.txt", "secret");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut config = ServerConfig::default();
    config.server.listen = addr;
    config.server.data_dir = data.path().to_path_buf();
    if !embedded {
        config.web.dir = Some(w.to_path_buf());
    }
    let state = build_state(config).await.unwrap();
    let app = routes::router(state);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Srv {
        base: format!("http://{addr}"),
        http: reqwest::Client::new(),
        _data: data,
        _web: web,
    }
}

impl Srv {
    async fn get(&self, path: &str) -> reqwest::Response {
        self.http
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .unwrap()
    }

    /// Status of a request with the path sent as it is (an HTTP client would
    /// normalize `..` and `%2e%2e`).
    async fn raw_status(&self, path: &str) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let addr = self.base.trim_start_matches("http://");
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        conn.write_all(req.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        conn.read_to_end(&mut out).await.unwrap();
        let out = String::from_utf8_lossy(&out).to_string();
        let status = out[9..12].parse().unwrap();
        (status, out)
    }

    async fn text(&self, path: &str) -> (StatusCode, String, String) {
        let resp = self.get(path).await;
        let status = resp.status();
        let mime = resp
            .headers()
            .get(CONTENT_TYPE)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        (status, mime, resp.text().await.unwrap())
    }
}

#[tokio::test]
async fn web_dir_root_files() {
    let srv = start(false).await;
    for (path, mime, body) in [
        ("/robots.txt", "text/plain; charset=utf-8", "Allow: /"),
        ("/sitemap.xml", "application/xml; charset=utf-8", "urlset"),
        ("/favicon.ico", "image/x-icon", "ico"),
        ("/site.webmanifest", "application/manifest+json", "{}"),
        (
            "/.well-known/security.txt",
            "text/plain; charset=utf-8",
            "Contact:",
        ),
    ] {
        let resp = srv.get(path).await;
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        let h = resp.headers().clone();
        assert_eq!(h[CONTENT_TYPE], mime, "{path}");
        assert!(h[CACHE_CONTROL].to_str().unwrap().contains("max-age"));
        assert_eq!(h["x-content-type-options"], "nosniff");
        assert!(h.contains_key("content-security-policy"));
        assert!(resp.text().await.unwrap().contains(body), "{path}");
        // Revalidation with the ETag.
        let again = srv
            .http
            .get(format!("{}{path}", srv.base))
            .header(IF_NONE_MATCH, h[ETAG].clone())
            .send()
            .await
            .unwrap();
        assert_eq!(again.status(), StatusCode::NOT_MODIFIED, "{path}");
    }
    // Missing root files are a 404, not the front-end's page.
    for path in [
        "/favicon.svg",
        "/apple-touch-icon.png",
        "/.well-known/missing.txt",
    ] {
        assert_eq!(
            srv.get(path).await.status(),
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    // Paths that try to leave the folder: a 404, or the shell when the router
    // does not see a file name; never another file.
    for path in [
        "/.well-known/../index.html",
        "/.well-known/%2e%2e/index.html",
        "/.well-known/..%2f..%2fsecret.txt",
        "/.well-known/..%5c..%5csecret.txt",
        "/.well-known//etc/passwd",
        "/robots.txt/../../secret.txt",
    ] {
        let (status, out) = srv.raw_status(path).await;
        let shell = status == 200 && out.contains("shell");
        assert!(status == 404 || shell, "{path}: {out}");
        assert!(
            !out.ends_with("secret") && !out.contains("Contact:"),
            "{path}: {out}"
        );
    }
    // HEAD works too.
    let head = srv
        .http
        .head(format!("{}/robots.txt", srv.base))
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), StatusCode::OK);
}

#[tokio::test]
async fn web_dir_prerendered_pages() {
    let srv = start(false).await;
    let version = env!("CARGO_PKG_VERSION");
    for (path, body) in [
        ("/", format!("home {version}")),
        ("/pricing", "pricing".into()),
        ("/pricing/", "pricing".into()),
        ("/es", "inicio".into()),
        ("/es/", "inicio".into()),
        ("/es/pricing", "precios".into()),
        // Not prerendered: the shell.
        ("/login", format!("shell {version}")),
        ("/app/teams/1", format!("shell {version}")),
        ("/es/unknown", format!("shell {version}")),
        ("/.hidden", format!("shell {version}")),
        ("/prerendered/index", format!("shell {version}")),
    ] {
        let (status, mime, text) = srv.text(path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(mime, "text/html; charset=utf-8", "{path}");
        assert!(text.contains(&body), "{path}: {text}");
    }
    // Paths that try to leave the folder get the shell, never another file.
    for path in [
        "/es/../pricing",
        "/es/%2e%2e/pricing",
        "/..%2fsecret.txt",
        "/es/..%2f..%2fsecret",
        "/es//pricing",
    ] {
        let (status, out) = srv.raw_status(path).await;
        assert_eq!(status, 200, "{path}");
        assert!(
            out.contains("shell") && !out.ends_with("secret"),
            "{path}: {out}"
        );
    }
    let resp = srv.get("/es/pricing").await;
    assert_eq!(resp.headers()[CACHE_CONTROL], "no-cache");
    assert_eq!(resp.headers()["referrer-policy"], "no-referrer");
    // The files themselves are not served raw under /assets/.
    for path in [
        "/assets/prerendered/pricing.html",
        "/assets/index.html",
        "/api/v1/nothing",
    ] {
        assert_eq!(
            srv.get(path).await.status(),
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    assert_eq!(srv.get("/assets/app.js").await.status(), StatusCode::OK);
    // Only GET and HEAD get pages.
    let post = srv
        .http
        .post(format!("{}/pricing", srv.base))
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn embedded_web_is_not_indexed() {
    let srv = start(true).await;
    let (status, mime, text) = srv.text("/robots.txt").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mime, "text/plain; charset=utf-8");
    assert!(text.contains("Disallow: /\n"), "{text}");
    // The embedded web has no prerendered pages or other root files.
    assert_eq!(
        srv.get("/sitemap.xml").await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        srv.get("/.well-known/security.txt").await.status(),
        StatusCode::NOT_FOUND
    );
    let (status, _, text) = srv.text("/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(text.contains("noindex"));
}
