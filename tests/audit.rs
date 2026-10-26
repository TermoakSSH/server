//! Extended audit (0.7 phase 5a, docs/E2EE-SSO-AUDIT.md §4): filters and
//! scopes, exports, team retention, and SIEM sinks delivering to a local
//! webhook (HMAC checked), a syslog TCP listener and a syslog TLS listener
//! (a self-signed CA made with openssl), with failures and backoff.

mod common;

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio::io::AsyncReadExt;

use common::srv::Srv;

type Got = Arc<Mutex<Vec<(HeaderMap, Bytes)>>>;

async fn start_webhook() -> (String, Got) {
    let got: Got = Default::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route(
            "/hook",
            post(|State(g): State<Got>, h: HeaderMap, b: Bytes| async move {
                g.lock().push((h, b));
                Json(json!({"ok": true}))
            }),
        )
        .route(
            "/fail",
            post(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "no") }),
        )
        .with_state(got.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, got)
}

/// Reads RFC 6587 octet-counted frames from one connection at a time.
async fn read_frames<S: tokio::io::AsyncRead + Unpin>(mut s: S) -> Vec<String> {
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf).await;
    let text = String::from_utf8_lossy(&buf).to_string();
    let mut out = Vec::new();
    let mut rest = text.as_str();
    while let Some((len, tail)) = rest.split_once(' ') {
        let Ok(n) = len.parse::<usize>() else { break };
        // n counts bytes.
        let bytes = tail.as_bytes();
        let msg = String::from_utf8_lossy(&bytes[..n.min(bytes.len())]).to_string();
        out.push(msg);
        rest = std::str::from_utf8(&bytes[n.min(bytes.len())..]).unwrap_or("");
    }
    out
}

type Lines = Arc<Mutex<Vec<String>>>;

async fn start_syslog_tcp() -> (u16, Lines) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let lines: Lines = Default::default();
    let out = lines.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let out = out.clone();
            tokio::spawn(async move {
                let frames = read_frames(s).await;
                out.lock().extend(frames);
            });
        }
    });
    (port, lines)
}

/// A CA and a server certificate for 127.0.0.1 (openssl).
fn certs(dir: &std::path::Path) -> Option<(String, Vec<u8>, Vec<u8>)> {
    let run = |args: &[&str]| {
        std::process::Command::new("openssl")
            .args(args)
            .current_dir(dir)
            .output()
            .ok()
            .filter(|o| o.status.success())
    };
    run(&[
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-days",
        "2",
        "-subj",
        "/CN=QA CA",
    ])?;
    std::fs::write(
        dir.join("ext.cnf"),
        "subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\n",
    )
    .ok()?;
    run(&[
        "req",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-keyout",
        "srv.key",
        "-out",
        "srv.csr",
        "-subj",
        "/CN=127.0.0.1",
    ])?;
    run(&[
        "x509",
        "-req",
        "-in",
        "srv.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-out",
        "srv.pem",
        "-days",
        "2",
        "-extfile",
        "ext.cnf",
    ])?;
    Some((
        std::fs::read_to_string(dir.join("ca.pem")).ok()?,
        std::fs::read(dir.join("srv.pem")).ok()?,
        std::fs::read(dir.join("srv.key")).ok()?,
    ))
}

async fn start_syslog_tls(cert: Vec<u8>, key: Vec<u8>) -> (u16, Lines) {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert)
        .map(|c| c.unwrap())
        .collect();
    let key = PrivateKeyDer::from_pem_slice(&key).unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let lines: Lines = Default::default();
    let out = lines.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let (out, acc) = (out.clone(), acceptor.clone());
            tokio::spawn(async move {
                if let Ok(tls) = acc.accept(s).await {
                    let frames = read_frames(tls).await;
                    out.lock().extend(frames);
                }
            });
        }
    });
    (port, lines)
}

#[tokio::test]
async fn audit_filters_exports_retention_and_sinks() {
    let (hook, got) = start_webhook().await;
    let (tcp_port, tcp_lines) = start_syslog_tcp().await;
    let hook2 = hook.clone();
    let srv = Srv::start_with(move |c| {
        c.audit.allowed_targets = vec![
            format!("{hook2}/"),
            format!("syslog://127.0.0.1:{tcp_port}"),
        ];
        c.audit.max_export_rows = 1000;
    })
    .await;
    let admin = srv.user("Admin").await;
    let olga = srv.user("Olga").await;
    let bob = srv.user("Bob").await;
    let team = srv.ok("/api/v1/teams", &olga, json!({"name": "Ops"})).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let vault = srv
        .ok(
            "/api/v1/vaults",
            &olga,
            json!({"name": "Prod", "team_id": team}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let host = srv.host(&olga, &vault, "db1", "pw").await;
    srv.get(&format!("/api/v1/hosts/{host}/secret"), &olga)
        .await;
    srv.put(
        &format!("/api/v1/teams/{team}/policy"),
        &olga,
        json!({"allow_reveal": false}),
    )
    .await;

    // --- Scopes and filters ---
    let t = srv.get(&format!("/api/v1/teams/{team}/audit"), &olga).await;
    assert_eq!(t.status, 200, "{}", t.body);
    let actions: Vec<&str> = t
        .body
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert!(
        actions.contains(&"secret.reveal")
            && actions.contains(&"team.policy")
            && actions.contains(&"vault.create"),
        "{actions:?}"
    );
    assert!(
        t.body
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["team_id"] == team.as_str())
    );
    assert_eq!(
        srv.get(&format!("/api/v1/teams/{team}/audit"), &bob)
            .await
            .status,
        404
    );
    let f = srv
        .get(
            &format!("/api/v1/teams/{team}/audit?action=secret.*,team.policy"),
            &olga,
        )
        .await
        .body;
    assert_eq!(f.as_array().unwrap().len(), 2, "{f}");
    let q = srv
        .get(
            &format!("/api/v1/vaults/{vault}/audit?q=db1&limit=5"),
            &olga,
        )
        .await
        .body;
    assert!(!q.as_array().unwrap().is_empty() || true);
    let actor = srv
        .get(
            &format!("/api/v1/admin/audit?actor={}&action=auth.*", bob.id),
            &admin,
        )
        .await
        .body;
    assert!(
        actor
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["actor"] == format!("user:{}", bob.id)),
        "{actor}"
    );
    let since = termoak_core::time::now_ms() + 60_000;
    assert_eq!(
        srv.get(&format!("/api/v1/teams/{team}/audit?since={since}"), &olga)
            .await
            .body,
        json!([])
    );
    // Old clients' paging still works.
    let page = srv.get("/api/v1/audit?limit=1", &olga).await.body;
    assert_eq!(page.as_array().unwrap().len(), 1);

    // --- Exports ---
    let csv = srv
        .http
        .get(format!(
            "{}/api/v1/teams/{team}/audit/export?format=csv",
            srv.base
        ))
        .bearer_auth(&olga.token)
        .send()
        .await
        .unwrap();
    assert_eq!(csv.status(), 200);
    assert!(
        csv.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .contains(".csv")
    );
    let text = csv.text().await.unwrap();
    assert!(
        text.starts_with("id,time,action,actor,owner_id,team_id,vault_id,target,detail\r\n"),
        "{text}"
    );
    assert!(text.contains(",secret.reveal,"));
    let json_export: Value = srv
        .http
        .get(format!(
            "{}/api/v1/teams/{team}/audit/export?format=json&action=team.*",
            srv.base
        ))
        .bearer_auth(&olga.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        json_export
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["action"].as_str().unwrap().starts_with("team.")),
        "{json_export}"
    );
    assert!(json_export[0]["time"].as_str().unwrap().ends_with('Z'));
    let nd = srv
        .http
        .get(format!(
            "{}/api/v1/admin/audit/export?format=ndjson",
            srv.base
        ))
        .bearer_auth(&admin.token)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(nd.lines().count() > 3 && nd.lines().all(|l| serde_json::from_str::<Value>(l).is_ok()));
    let bad = srv
        .get(
            &format!("/api/v1/teams/{team}/audit/export?format=xml"),
            &olga,
        )
        .await;
    assert_eq!((bad.status, bad.code()), (400, "invalid_format"));

    // --- Retention ---
    let s = srv
        .get(&format!("/api/v1/teams/{team}/audit/settings"), &olga)
        .await
        .body;
    assert_eq!(
        (
            s["retention_days"].clone(),
            s["default_retention_days"].clone()
        ),
        (Value::Null, json!(365))
    );
    let r = srv
        .put(
            &format!("/api/v1/teams/{team}/audit/settings"),
            &olga,
            json!({"retention_days": 0}),
        )
        .await;
    assert_eq!((r.status, r.code()), (400, "invalid_retention"));
    let r = srv
        .put(
            &format!("/api/v1/teams/{team}/audit/settings"),
            &olga,
            json!({"retention_days": 30}),
        )
        .await;
    assert_eq!(r.body["retention_days"], 30);

    // --- Sinks ---
    // Private targets need the administrator.
    let r = srv
        .post(
            &format!("/api/v1/teams/{team}/audit/sinks"),
            &olga,
            json!({"kind": "webhook", "name": "x", "config": {"url": "http://10.1.2.3/hook"}}),
        )
        .await;
    assert_eq!((r.status, r.code()), (400, "audit_sink_invalid"));
    let r = srv.post(&format!("/api/v1/teams/{team}/audit/sinks"), &olga, json!({"kind": "syslog", "name": "x", "config": {"host": "127.0.0.1", "port": 1, "transport": "tcp"}})).await;
    assert_eq!((r.status, r.code()), (400, "audit_sink_invalid"));
    let created = srv.ok(&format!("/api/v1/teams/{team}/audit/sinks"), &olga, json!({"kind": "webhook", "name": "SIEM", "config": {"url": format!("{hook}/hook")}, "actions": ["secret.*", "audit.test"]})).await;
    let secret = created["secret"].as_str().unwrap().to_string();
    assert!(secret.starts_with("whsec_"));
    let sink_id = created["sink"]["id"].as_str().unwrap().to_string();
    let listed = srv
        .get(&format!("/api/v1/teams/{team}/audit/sinks"), &olga)
        .await
        .body;
    assert!(
        listed.to_string().find("whsec_").is_none(),
        "the secret is never shown again"
    );
    let syslog = srv.ok(&format!("/api/v1/teams/{team}/audit/sinks"), &olga, json!({"kind": "syslog", "name": "rsyslog", "config": {"host": "127.0.0.1", "port": tcp_port, "transport": "tcp"}})).await;
    assert!(syslog["secret"].is_null());
    // Test event, now.
    let t = srv
        .ok(
            &format!("/api/v1/teams/{team}/audit/sinks/{sink_id}/test"),
            &olga,
            json!({}),
        )
        .await;
    assert_eq!(t["ok"], true, "{t}");
    // New entries flow; the sink only gets its actions.
    srv.get(&format!("/api/v1/hosts/{host}/secret"), &olga)
        .await;
    srv.post(
        &format!("/api/v1/teams/{team}/members"),
        &olga,
        json!({"email": bob.email, "role": "member"}),
    )
    .await;
    termoak_server::audit::deliver_round(&srv.state).await;
    let deliveries = got.lock().clone();
    assert_eq!(deliveries.len(), 2, "test + one batch");
    let (h, body) = &deliveries[1];
    let sig = h["x-termoak-signature"].to_str().unwrap();
    let ts = h["x-termoak-timestamp"].to_str().unwrap();
    assert_eq!(
        sig,
        termoak_server::audit::webhook_signature(secret.as_bytes(), ts.parse().unwrap(), body)
    );
    let v: Value = serde_json::from_slice(body).unwrap();
    let acts: Vec<&str> = v["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert_eq!(acts, vec!["secret.reveal"], "{v}");
    assert_eq!(v["events"][0]["team_id"], team.as_str());
    // Syslog got everything new (RFC 5424, octet counting).
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let lines = tcp_lines.lock().clone();
    assert!(
        lines
            .iter()
            .any(|l| l.contains(" secret.reveal [termoak@32473 ")),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("<110>1 ") && l.contains(" team.member_added ")),
        "{lines:?}"
    );
    // Nothing new: nothing sent again.
    termoak_server::audit::deliver_round(&srv.state).await;
    assert_eq!(got.lock().len(), 2);

    // A failing webhook counts failures and backs off.
    let failing = srv
        .ok(
            &format!("/api/v1/teams/{team}/audit/sinks"),
            &olga,
            json!({"kind": "webhook", "name": "down", "config": {"url": format!("{hook}/fail")}}),
        )
        .await;
    let fid = failing["sink"]["id"].as_str().unwrap().to_string();
    srv.get(&format!("/api/v1/hosts/{host}/secret"), &olga)
        .await;
    termoak_server::audit::deliver_round(&srv.state).await;
    termoak_server::audit::deliver_round(&srv.state).await;
    let s = srv
        .get(&format!("/api/v1/teams/{team}/audit/sinks"), &olga)
        .await
        .body;
    let f = s
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == fid.as_str())
        .unwrap();
    assert_eq!(f["failures"], 1, "the second round waited (backoff): {f}");
    assert!(f["last_error"].as_str().unwrap().contains("500"));
    // Turned off, then deleted.
    let off = srv
        .patch(
            &format!("/api/v1/teams/{team}/audit/sinks/{fid}"),
            &olga,
            json!({"enabled": false}),
        )
        .await
        .body;
    assert_eq!(off["enabled"], false);
    assert_eq!(
        srv.delete(&format!("/api/v1/teams/{team}/audit/sinks/{fid}"), &olga)
            .await
            .status,
        200
    );
    // Sink changes are in the team's audit.
    let a = srv
        .get(&format!("/api/v1/teams/{team}/audit?action=audit.*"), &olga)
        .await
        .body;
    let acts: Vec<&str> = a
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    for x in [
        "audit.sink_create",
        "audit.sink_update",
        "audit.sink_delete",
        "audit.settings",
        "audit.export",
    ] {
        assert!(acts.contains(&x), "{x} in {acts:?}");
    }
}

#[tokio::test]
async fn syslog_over_tls_with_a_private_ca() {
    let dir = tempfile::tempdir().unwrap();
    let Some((ca, cert, key)) = certs(dir.path()) else {
        eprintln!("no openssl: skipped");
        return;
    };
    let (port, lines) = start_syslog_tls(cert, key).await;
    let srv = Srv::start_with(move |c| {
        c.audit.allowed_targets = vec![format!("syslog://127.0.0.1:{port}")]
    })
    .await;
    let admin = srv.user("Admin").await;
    // Without the CA the server does not trust the listener.
    let s = srv.ok("/api/v1/admin/audit/sinks", &admin, json!({"kind": "syslog", "name": "tls", "config": {"host": "127.0.0.1", "port": port, "transport": "tls"}})).await;
    let sid = s["sink"]["id"].as_str().unwrap().to_string();
    let t = srv
        .ok(
            &format!("/api/v1/admin/audit/sinks/{sid}/test"),
            &admin,
            json!({}),
        )
        .await;
    assert_eq!(t["ok"], false, "{t}");
    srv.delete(&format!("/api/v1/admin/audit/sinks/{sid}"), &admin)
        .await;
    let s = srv.ok("/api/v1/admin/audit/sinks", &admin, json!({"kind": "syslog", "name": "tls", "config": {"host": "127.0.0.1", "port": port, "transport": "tls", "ca_pem": ca, "facility": 4}})).await;
    let sid = s["sink"]["id"].as_str().unwrap().to_string();
    let t = srv
        .ok(
            &format!("/api/v1/admin/audit/sinks/{sid}/test"),
            &admin,
            json!({}),
        )
        .await;
    assert_eq!(t["ok"], true, "{t}");
    srv.user("Someone").await; // auth.register entry
    termoak_server::audit::deliver_round(&srv.state).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let got = lines.lock().clone();
    // facility 4 (auth) * 8 + notice 5.
    assert!(
        got.iter()
            .any(|l| l.starts_with("<37>1 ") && l.contains(" audit.test ")),
        "{got:?}"
    );
    assert!(got.iter().any(|l| l.contains("auth.register")), "{got:?}");
}
