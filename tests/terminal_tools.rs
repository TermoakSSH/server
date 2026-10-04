//! The AI types into a user's terminal and collects the output (copilot).
//! Skipped if `sshd` is not installed.

mod common;

use std::time::Duration;

use common::start_sshd;
use serde_json::{Value, json};
use termoak_ai::SessionAccess;
use termoak_server::config::ServerConfig;
use termoak_server::{build_state, routes, start_sessions};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn typing_waits_for_the_output() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let Some(sshd) = start_sshd() else {
        eprintln!("sshd not available: test skipped");
        return;
    };
    let data = tempfile::tempdir().unwrap();
    let mut config = ServerConfig::default();
    config.server.data_dir = data.path().to_path_buf();
    config.sessions.host_key_policy = termoak_ssh::HostKeyPolicy::AcceptNew;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let state = build_state(config).await.unwrap();
    start_sessions(&state).await.unwrap();
    let sessions = state.sessions.clone();
    tokio::spawn(async move { axum::serve(listener, routes::router(state)).await.unwrap() });

    let http = reqwest::Client::new();
    let reg: Value = http
        .post(format!("{base}/api/v1/auth/register"))
        .json(&json!({"email": "ana@termoak.test", "password": "secure-password", "device_name": "x", "platform": "desktop-linux"}))
        .send().await.unwrap().json().await.unwrap();
    let token = reg["tokens"]["access_token"].as_str().unwrap().to_string();
    let owner = reg["user"]["id"].as_str().unwrap().parse().unwrap();
    let post = |path: &str, body: Value| {
        http.post(format!("{base}{path}"))
            .bearer_auth(&token)
            .json(&body)
            .send()
    };
    let key: Value = post(
        "/api/v1/keys/import",
        json!({"label": "k", "private_key": sshd.private_key}),
    )
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let ident: Value = post(
        "/api/v1/identities",
        json!({"label": "me", "username": sshd.user, "key_id": key["id"]}),
    )
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let host: Value = post("/api/v1/hosts", json!({"label": "local", "address": "127.0.0.1", "settings": {"port": sshd.port, "identity_id": ident["id"]}}))
        .await.unwrap().json().await.unwrap();
    let session: Value = post(
        "/api/v1/sessions",
        json!({"host_id": host["id"], "cols": 100, "rows": 30}),
    )
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let sid = session["id"].as_str().unwrap().parse().unwrap();
    // Wait until the shell is ready.
    for _ in 0..100 {
        if sessions
            .read(owner, sid, 2000)
            .await
            .is_ok_and(|s| !s.is_empty())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let cmd = "echo one-$((2+2)); sleep 3; echo end-$((1+1))\r";
    // With 1 s of silence, it returns before the end...
    let out = sessions
        .send_and_collect(
            owner,
            sid,
            cmd,
            Duration::from_secs(1),
            Duration::from_secs(20),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(out.text.contains("one-4"), "{out:?}");
    assert!(!out.text.contains("end-2"), "{out:?}");
    assert!(
        !out.text.contains('\x1b'),
        "the output has no ANSI: {out:?}"
    );
    // ...and the rest arrives later.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        sessions
            .read(owner, sid, 2000)
            .await
            .unwrap()
            .contains("end-2")
    );

    // Waiting for more silence, everything arrives.
    let out = sessions
        .send_and_collect(
            owner,
            sid,
            cmd,
            Duration::from_secs(4),
            Duration::from_secs(20),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(
        out.text.contains("one-4") && out.text.contains("end-2"),
        "{out:?}"
    );
    assert!(!out.still_running);

    // If time runs out while the command is still writing, it says so.
    let out = sessions
        .send_and_collect(
            owner,
            sid,
            "for i in 1 2 3 4 5 6; do echo step-$i; sleep 0.5; done\r",
            Duration::from_secs(2),
            Duration::from_secs(1),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(out.still_running, "{out:?}");
}
