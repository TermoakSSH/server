//! Session holder: an open session stays alive (with its history) when
//! another server takes over, as when the server restarts.
//! Skipped if `sshd` is not installed.

mod common;

use std::time::Duration;

use common::{start_sshd, ws_connect, ws_wait_json, ws_wait_output};
use futures::SinkExt;
use serde_json::{Value, json};
use termoak_server::config::ServerConfig;
use termoak_server::{build_state, routes, start_sessions};
use tokio_tungstenite::tungstenite::Message as WsMsg;

/// Starts a server with `config` and returns its URL and the task serving it.
async fn start_server(config: &ServerConfig) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut config = config.clone();
    config.server.listen = addr;
    let state = build_state(config).await.unwrap();
    start_sessions(&state).await.unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, routes::router(state)).await.unwrap();
    });
    (format!("http://{addr}"), task)
}

async fn call(
    http: &reqwest::Client,
    method: reqwest::Method,
    url: String,
    token: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let mut r = http.request(method, url).bearer_auth(token);
    if let Some(b) = body {
        r = r.json(&b);
    }
    let resp = r.send().await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sessions_survive_a_server_restart() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let Some(sshd) = start_sshd() else {
        eprintln!("sshd not available: test skipped");
        return;
    };
    let data = tempfile::tempdir().unwrap();
    let socket = data.path().join("holder").join("sessions.sock");
    let stop = tokio_util::sync::CancellationToken::new();
    let holder = tokio::spawn({
        let socket = socket.clone();
        let stop = stop.clone();
        async move { termoak_server::holder::daemon::run(&socket, stop).await }
    });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let mut config = ServerConfig::default();
    config.server.data_dir = data.path().join("data");
    config.sessions.host_key_policy = termoak_ssh::HostKeyPolicy::AcceptNew;
    config.sessions.holder_socket = Some(socket.clone());
    let http = reqwest::Client::new();

    // --- First server: account, host and a session ---
    let (base, first) = start_server(&config).await;
    let reg: Value = http
        .post(format!("{base}/api/v1/auth/register"))
        .json(&json!({"email": "ana@termoak.test", "name": "Ana", "password": "secure-password", "device_name": "Laptop", "platform": "desktop-linux"}))
        .send().await.unwrap().json().await.unwrap();
    let token = reg["tokens"]["access_token"].as_str().unwrap().to_string();
    let post = |base: &str, path: &str, body: Value| {
        call(
            &http,
            reqwest::Method::POST,
            format!("{base}{path}"),
            &token,
            Some(body),
        )
    };
    let (_, key) = post(
        &base,
        "/api/v1/keys/import",
        json!({"label": "k", "private_key": sshd.private_key}),
    )
    .await;
    let (_, ident) = post(
        &base,
        "/api/v1/identities",
        json!({"label": "me", "username": sshd.user, "key_id": key["id"]}),
    )
    .await;
    let (_, host) = post(
        &base,
        "/api/v1/hosts",
        json!({"label": "local", "address": "127.0.0.1", "settings": {"port": sshd.port, "identity_id": ident["id"]}}),
    )
    .await;
    let (s, session) = post(
        &base,
        "/api/v1/sessions",
        json!({"host_id": host["id"], "cols": 100, "rows": 30, "title": "kept"}),
    )
    .await;
    assert!(s < 300, "{s} {session}");
    let sid = session["id"].as_str().unwrap().to_string();
    let mut ws = ws_connect(&base, &format!("/api/v1/sessions/{sid}/ws"), Some(&token)).await;
    ws_wait_json(&mut ws, "hello").await;
    // What is typed while connecting waits in the holder.
    ws.send(WsMsg::Binary(
        "cd /tmp && echo before-$((1+1))\n"
            .as_bytes()
            .to_vec()
            .into(),
    ))
    .await
    .unwrap();
    ws_wait_output(&mut ws, "before-2").await;

    // --- "Restart": another server takes over ---
    let (base2, _second) = start_server(&config).await;
    // The first one stops using the holder as soon as it notices.
    let mut refused = 0;
    for _ in 0..50 {
        let (s, _) = post(
            &base,
            "/api/v1/sessions",
            json!({"host_id": host["id"], "cols": 80, "rows": 24}),
        )
        .await;
        refused = s;
        if s == 503 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(refused, 503, "the old server kept opening sessions");
    first.abort();
    drop(ws);

    let (_, listed) = call(
        &http,
        reqwest::Method::GET,
        format!("{base2}/api/v1/sessions"),
        &token,
        None,
    )
    .await;
    assert_eq!(listed["active"][0]["id"], sid.as_str(), "{listed}");
    assert_eq!(listed["active"][0]["state"]["state"], "running");
    assert_eq!(listed["active"][0]["title"], "kept");

    // The history is still there, and so is the shell (with its current directory).
    let mut ws = ws_connect(&base2, &format!("/api/v1/sessions/{sid}/ws"), Some(&token)).await;
    ws_wait_json(&mut ws, "hello").await;
    ws_wait_output(&mut ws, "before-2").await;
    ws.send(WsMsg::Binary(
        "echo after-$((2+3)) in $(pwd)\n".as_bytes().to_vec().into(),
    ))
    .await
    .unwrap();
    ws_wait_output(&mut ws, "after-5 in /tmp").await;

    // Closing it from the new server closes the one in the holder.
    ws.send(WsMsg::Text(
        json!({"type": "close_session"}).to_string().into(),
    ))
    .await
    .unwrap();
    let status = ws_wait_json(&mut ws, "status").await;
    assert_eq!(status["status"]["state"], "closed", "{status}");

    stop.cancel();
    holder.await.unwrap().unwrap();
}
