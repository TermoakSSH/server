//! End-to-end test: server + real sshd + mock AI provider.
//! Skipped if `sshd` is not installed.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

mod common;

use common::{start_sshd, ws_connect, ws_wait_json, ws_wait_output};
use futures::SinkExt;
use serde_json::{Value, json};
use termoak_ai::{AiConfig, Driver, ProviderConfig};
use termoak_server::config::ServerConfig;
use termoak_server::{build_state, routes};
use tokio_tungstenite::tungstenite::Message as WsMsg;

/// Mock AI provider (Chat Completions with SSE).
/// - First turn: asks to run a command (read-only, or a write if the prompt contains "CREATE").
/// - Second turn: replies with final text including the tool output.
async fn mock_ai() -> (String, Arc<AtomicUsize>) {
    use axum::routing::post;
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let app = axum::Router::new().route(
        "/v1/chat/completions",
        post(move |axum::Json(body): axum::Json<Value>| {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                let msgs = body["messages"].as_array().cloned().unwrap_or_default();
                let tool_result = msgs.iter().rev().find(|m| m["role"] == "tool").map(|m| m["content"].as_str().unwrap_or("").to_string());
                let user_text: String = msgs.iter().filter(|m| m["role"] == "user").map(|m| m["content"].as_str().unwrap_or("").to_string()).collect();
                let chunks: Vec<Value> = match tool_result {
                    None => {
                        let cmd = if user_text.contains("CREATE") { "touch /tmp/termoak-e2e-created && echo created" } else { "echo olive-42" };
                        vec![
                            json!({"choices":[{"delta":{"reasoning_content":"I will look at the host."}}]}),
                            json!({"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"run_command","arguments":""}}]}}]}),
                            json!({"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":format!("{{\"host\":\"local\",\"command\":\"{cmd}\"}}")}}]}}]}),
                            json!({"choices":[{"delta":{},"finish_reason":"tool_calls"}]}),
                            json!({"choices":[],"usage":{"prompt_tokens":100,"completion_tokens":20,"cost":0.001}}),
                        ]
                    }
                    Some(result) => vec![
                        json!({"choices":[{"delta":{"content":"Result: "}}]}),
                        json!({"choices":[{"delta":{"content":result.lines().filter(|l| l.contains("olive") || l.contains("created") || l.contains("did NOT approve")).collect::<Vec<_>>().join(" ")}}]}),
                        json!({"choices":[{"delta":{},"finish_reason":"stop"}]}),
                        json!({"choices":[],"usage":{"prompt_tokens":150,"completion_tokens":10}}),
                    ],
                };
                let mut sse = String::new();
                for ch in chunks {
                    sse.push_str(&format!("data: {ch}\n\n"));
                }
                sse.push_str("data: [DONE]\n\n");
                ([("content-type", "text/event-stream")], sse)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/v1"), calls)
}

struct Api {
    base: String,
    http: reqwest::Client,
    token: String,
}

impl Api {
    async fn call(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut r = self
            .http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(&self.token);
        if let Some(b) = body {
            r = r.json(&b);
        }
        let resp = r.send().await.unwrap();
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap();
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }
    async fn get(&self, p: &str) -> Value {
        let (s, v) = self.call(reqwest::Method::GET, p, None).await;
        assert!(s < 300, "GET {p} → {s} {v}");
        v
    }
    async fn post(&self, p: &str, b: Value) -> Value {
        let (s, v) = self.call(reqwest::Method::POST, p, Some(b)).await;
        assert!(s < 300, "POST {p} → {s} {v}");
        v
    }
}

async fn wait_task(api: &Api, id: &str, pred: impl Fn(&Value) -> bool) -> Value {
    let mut last = Value::Null;
    for _ in 0..300 {
        last = api.get(&format!("/api/v1/ai/tasks/{id}")).await;
        if pred(&last) {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let events = api.get(&format!("/api/v1/ai/tasks/{id}/events")).await;
    panic!("task {id} did not reach the expected state: {last}\nevents: {events}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn end_to_end() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let Some(sshd) = start_sshd() else {
        eprintln!("sshd not available: test skipped");
        return;
    };
    let (mock_url, mock_calls) = mock_ai().await;
    let data = tempfile::tempdir().unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut ai = AiConfig {
        default: "mock".into(),
        fallback: vec![],
        ..Default::default()
    };
    ai.providers.insert(
        "mock".into(),
        ProviderConfig {
            driver: Driver::OpenaiChat,
            base_url: Some(mock_url),
            api_key: Some("x".into()),
            model: Some("mock-1".into()),
            subscription: false,
            ..Default::default()
        },
    );
    let mut config = ServerConfig {
        ai,
        ..Default::default()
    };
    config.server.listen = addr;
    config.server.data_dir = data.path().to_path_buf();
    config.sessions.host_key_policy = termoak_ssh::HostKeyPolicy::AcceptNew;
    config.sessions.record = true;
    let state = build_state(config).await.unwrap();
    tokio::spawn(async move { axum::serve(listener, routes::router(state)).await.unwrap() });
    let base = format!("http://{addr}");
    let http = reqwest::Client::new();

    // --- Accounts ---
    let info: Value = http
        .get(format!("{base}/api/v1/info"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["needs_setup"], true);
    let reg: Value = http
        .post(format!("{base}/api/v1/auth/register"))
        .json(&json!({"email": "ana@termoak.test", "name": "Ana", "password": "secure-password", "device_name": "Laptop", "platform": "desktop-linux"}))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(reg["user"]["is_admin"], true);
    let ana = Api {
        base: base.clone(),
        http: http.clone(),
        token: reg["tokens"]["access_token"].as_str().unwrap().into(),
    };
    // Registration is closed for the second user; the admin creates Bea.
    let (s, _) = Api {
        token: String::new(),
        ..Api {
            base: base.clone(),
            http: http.clone(),
            token: String::new(),
        }
    }
    .call(
        reqwest::Method::POST,
        "/api/v1/auth/register",
        Some(json!({"email": "x@y.z", "password": "secure-password"})),
    )
    .await;
    assert_eq!(s, 403);
    ana.post(
        "/api/v1/admin/users",
        json!({"email": "bea@termoak.test", "name": "Bea", "password": "another-password"}),
    )
    .await;
    let login: Value = http
        .post(format!("{base}/api/v1/auth/login"))
        .json(&json!({"email": "bea@termoak.test", "password": "another-password", "device_name": "iPhone", "platform": "ios"}))
        .send().await.unwrap().json().await.unwrap();
    let bea = Api {
        base: base.clone(),
        http: http.clone(),
        token: login["tokens"]["access_token"].as_str().unwrap().into(),
    };
    let refreshed: Value = http
        .post(format!("{base}/api/v1/auth/refresh"))
        .json(&json!({"refresh_token": login["tokens"]["refresh_token"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        refreshed["access_token"]
            .as_str()
            .unwrap()
            .starts_with("aks_at_")
    );
    let bea = Api {
        token: refreshed["access_token"].as_str().unwrap().into(),
        ..bea
    };

    // --- Keychain, identity and host ---
    let key = ana
        .post(
            "/api/v1/keys/import",
            json!({"label": "e2e", "private_key": sshd.private_key}),
        )
        .await;
    assert!(key["fingerprint"].as_str().unwrap().starts_with("SHA256:"));
    assert_eq!(key["has_secret"], true);
    assert!(
        key.get("private_key").is_none(),
        "listings must not include secrets"
    );
    let ident = ana
        .post(
            "/api/v1/identities",
            json!({"label": "me", "username": sshd.user, "key_id": key["id"]}),
        )
        .await;
    let group = ana
        .post(
            "/api/v1/groups",
            json!({"name": "local", "settings": {"port": sshd.port, "identity_id": ident["id"]}}),
        )
        .await;
    let host = ana.post("/api/v1/hosts", json!({"label": "local", "address": "127.0.0.1", "group_id": group["id"], "tags": ["test"]})).await;
    let host_id = host["id"].as_str().unwrap().to_string();
    let eff = ana.get(&format!("/api/v1/hosts/{host_id}/effective")).await;
    assert_eq!(eff["port"], sshd.port);

    // Test connection: without trust the host is unknown; with trust=true it is saved.
    let t = ana
        .post(&format!("/api/v1/hosts/{host_id}/test"), json!({}))
        .await;
    assert_eq!(t["ok"], false);
    assert_eq!(t["error_code"], "host_key_unknown");
    let t = ana
        .post(
            &format!("/api/v1/hosts/{host_id}/test?trust=true"),
            json!({}),
        )
        .await;
    assert_eq!(t["ok"], true, "{t}");
    assert!(t["os"].is_string());
    assert_eq!(
        ana.get("/api/v1/known-hosts")
            .await
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // Bea does not see Ana's data.
    assert!(
        bea.get("/api/v1/hosts")
            .await
            .as_array()
            .unwrap()
            .is_empty()
    );
    let (s, _) = bea
        .call(
            reqwest::Method::GET,
            &format!("/api/v1/hosts/{host_id}"),
            None,
        )
        .await;
    assert_eq!(s, 404);

    // --- Running on several hosts ---
    let snippet = ana
        .post(
            "/api/v1/snippets",
            json!({"name": "greeting", "script": "echo hello-{{name}}"}),
        )
        .await;
    let res = ana.post("/api/v1/exec", json!({"host_ids": [host_id], "snippet_id": snippet["id"], "variables": {"name": "world"}})).await;
    assert_eq!(res[0]["stdout"], "hello-world\n");
    assert_eq!(res[0]["ok"], true);

    // --- SFTP through the server ---
    let dir = format!("/tmp/termoak-e2e-{}", std::process::id());
    ana.post(
        &format!("/api/v1/hosts/{host_id}/sftp/mkdir"),
        json!({"path": dir, "parents": true}),
    )
    .await;
    let up = http
        .post(format!(
            "{base}/api/v1/hosts/{host_id}/sftp/upload?path={dir}/f.txt"
        ))
        .bearer_auth(&ana.token)
        .body("uploaded content")
        .send()
        .await
        .unwrap();
    assert!(up.status().is_success());
    let list = ana
        .get(&format!("/api/v1/hosts/{host_id}/sftp/list?path={dir}"))
        .await;
    assert_eq!(list[0]["name"], "f.txt");
    let down = http
        .get(format!(
            "{base}/api/v1/hosts/{host_id}/sftp/download?path={dir}/f.txt"
        ))
        .bearer_auth(&ana.token)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(down, "uploaded content");
    ana.post(
        &format!("/api/v1/hosts/{host_id}/sftp/delete"),
        json!({"path": dir, "recursive": true}),
    )
    .await;

    // --- Persistent session on the server ---
    let session = ana
        .post(
            "/api/v1/sessions",
            json!({"host_id": host_id, "cols": 100, "rows": 30}),
        )
        .await;
    let sid = session["id"].as_str().unwrap().to_string();
    let mut ws = ws_connect(
        &base,
        &format!("/api/v1/sessions/{sid}/ws"),
        Some(&ana.token),
    )
    .await;
    let hello = ws_wait_json(&mut ws, "hello").await;
    assert_eq!(hello["you"]["access"], "owner");
    ws.send(WsMsg::Binary(
        "echo persistent-$((1+1))\n".as_bytes().to_vec().into(),
    ))
    .await
    .unwrap();
    ws_wait_output(&mut ws, "persistent-2").await;
    // Disconnect (as if closing the mobile app)...
    drop(ws);
    tokio::time::sleep(Duration::from_millis(300)).await;
    // ...the session stays alive and the history is there on return.
    let listed = ana.get("/api/v1/sessions").await;
    assert_eq!(listed["active"][0]["state"]["state"], "running");
    let mut ws = ws_connect(
        &base,
        &format!("/api/v1/sessions/{sid}/ws"),
        Some(&ana.token),
    )
    .await;
    ws_wait_json(&mut ws, "hello").await;
    ws_wait_output(&mut ws, "persistent-2").await;

    // Share by link (view only): the guest sees but cannot type.
    let share = ana
        .post(
            &format!("/api/v1/sessions/{sid}/shares"),
            json!({"link": true, "permission": "view"}),
        )
        .await;
    let token = share["token"].as_str().unwrap().to_string();
    let join: Value = http
        .get(format!("{base}/api/v1/join/{token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(join["permission"], "view");
    // Links wait in the waiting room; the link page says nothing about who is in.
    assert_eq!(join["require_approval"], true);
    assert!(join["session"].get("viewers").is_none() && join["session"].get("owner_id").is_none());
    let mut guest = ws_connect(&base, join["ws_path"].as_str().unwrap(), None).await;
    ws_wait_json(&mut guest, "waiting").await;
    let request = ws_wait_json(&mut ws, "join_request").await;
    assert_eq!(request["participant"]["name"], "Guest 1");
    ws.send(WsMsg::Text(
        json!({"type": "join_allow", "participant": request["participant"]["id"]})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let gh = ws_wait_json(&mut guest, "hello").await;
    assert_eq!(gh["you"]["access"], "view");
    guest
        .send(WsMsg::Binary(
            "echo MUST-NOT-APPEAR\n".as_bytes().to_vec().into(),
        ))
        .await
        .unwrap();
    ws.send(WsMsg::Binary(
        "echo seen-by-guest\n".as_bytes().to_vec().into(),
    ))
    .await
    .unwrap();
    let seen = ws_wait_output(&mut guest, "seen-by-guest").await;
    assert!(!seen.contains("MUST-NOT-APPEAR"));

    // Share with Bea (control): she can type.
    ana.post(
        &format!("/api/v1/sessions/{sid}/shares"),
        json!({"email": "bea@termoak.test", "permission": "control"}),
    )
    .await;
    let bea_sessions = bea.get("/api/v1/sessions").await;
    assert_eq!(bea_sessions["shared"][0]["id"], sid.as_str());
    let mut bws = ws_connect(
        &base,
        &format!("/api/v1/sessions/{sid}/ws"),
        Some(&bea.token),
    )
    .await;
    ws_wait_json(&mut bws, "hello").await;
    bws.send(WsMsg::Binary(
        "echo typed-by-bea\n".as_bytes().to_vec().into(),
    ))
    .await
    .unwrap();
    ws_wait_output(&mut ws, "typed-by-bea").await;

    // Revoking the link kicks the guest out.
    let shares = ana.get(&format!("/api/v1/sessions/{sid}/shares")).await;
    let link_share = shares
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["is_link"] == true)
        .unwrap();
    let (s, _) = ana
        .call(
            reqwest::Method::DELETE,
            &format!(
                "/api/v1/sessions/{sid}/shares/{}",
                link_share["id"].as_str().unwrap()
            ),
            None,
        )
        .await;
    assert_eq!(s, 200);
    let kicked = ws_wait_json(&mut guest, "error").await;
    assert!(kicked["message"].as_str().unwrap().contains("revoked"));
    assert_eq!(kicked["code"], "revoked");

    // --- AI: read-only task (runs without asking) ---
    let task = ana
        .post(
            "/api/v1/ai/tasks",
            json!({"prompt": "What does the local host say?", "provider": "mock"}),
        )
        .await;
    let tid = task["id"].as_str().unwrap().to_string();
    let done = wait_task(&ana, &tid, |t| {
        t["status"] == "completed" || t["status"] == "failed"
    })
    .await;
    assert_eq!(done["status"], "completed", "{done}");
    assert!(
        done["result"].as_str().unwrap().contains("olive-42"),
        "{done}"
    );
    assert_eq!(done["cost_micros"], 1000, "cost reported by the provider");
    let events = ana.get(&format!("/api/v1/ai/tasks/{tid}/events")).await;
    let kinds: Vec<&str> = events
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    assert!(
        kinds.contains(&"tool_call")
            && kinds.contains(&"tool_result")
            && kinds.contains(&"finished"),
        "{kinds:?}"
    );

    // --- AI: task that modifies → needs approval (from another device) ---
    let mut events_ws = ws_connect(&base, "/api/v1/events/ws", Some(&ana.token)).await;
    ws_wait_json(&mut events_ws, "hello").await;
    let task = ana
        .post(
            "/api/v1/ai/tasks",
            json!({"prompt": "CREATE a file on local", "provider": "mock", "mode": "ask"}),
        )
        .await;
    let tid = task["id"].as_str().unwrap().to_string();
    let waiting = wait_task(&ana, &tid, |t| t["status"] == "waiting_approval").await;
    let approval = &waiting["pending_approvals"][0];
    assert!(approval["summary"].as_str().unwrap().contains("touch"));
    // The notice arrives through the events WebSocket (used by the mobile app).
    let ev = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let v = ws_wait_json(&mut events_ws, "ai").await;
            if v["event"]["type"] == "approval_requested" {
                return v;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(ev["task_id"], tid.as_str());
    ana.post(
        &format!(
            "/api/v1/ai/tasks/{tid}/approvals/{}",
            approval["id"].as_str().unwrap()
        ),
        json!({"approve": true}),
    )
    .await;
    let done = wait_task(&ana, &tid, |t| {
        t["status"] == "completed" || t["status"] == "failed"
    })
    .await;
    assert!(
        done["result"].as_str().unwrap().contains("created"),
        "{done}"
    );
    let _ = std::fs::remove_file("/tmp/termoak-e2e-created");

    // Deny: the AI does not run it.
    let task = ana
        .post(
            "/api/v1/ai/tasks",
            json!({"prompt": "CREATE again", "provider": "mock"}),
        )
        .await;
    let tid = task["id"].as_str().unwrap().to_string();
    let waiting = wait_task(&ana, &tid, |t| t["status"] == "waiting_approval").await;
    ana.post(
        &format!(
            "/api/v1/ai/tasks/{tid}/approvals/{}",
            waiting["pending_approvals"][0]["id"].as_str().unwrap()
        ),
        json!({"approve": false}),
    )
    .await;
    let done = wait_task(&ana, &tid, |t| {
        t["status"] == "completed" || t["status"] == "failed"
    })
    .await;
    assert!(
        done["result"].as_str().unwrap().contains("did NOT approve"),
        "{done}"
    );
    assert!(!std::path::Path::new("/tmp/termoak-e2e-created").exists());
    assert!(mock_calls.load(Ordering::SeqCst) >= 6);

    // The AI can read the open terminal.
    let sessions = ana.get("/api/v1/sessions").await;
    assert_eq!(sessions["active"].as_array().unwrap().len(), 1);

    // --- MCP with a user token (read-only) ---
    let tools = ana
        .post(
            "/api/v1/mcp",
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        )
        .await;
    assert!(
        tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "run_command")
    );
    let call = ana.post("/api/v1/mcp", json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "run_command", "arguments": {"host": "local", "command": "echo mcp-ok"}}})).await;
    assert!(
        call["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("mcp-ok"),
        "{call}"
    );
    let denied = ana.post("/api/v1/mcp", json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "run_command", "arguments": {"host": "local", "command": "rm -rf /tmp/nothing"}}})).await;
    assert_eq!(denied["result"]["isError"], true);

    // --- Sync between devices ---
    let sync = ana
        .post("/api/v1/sync", json!({"since": 0, "changes": []}))
        .await;
    let kinds: Vec<&str> = sync["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"host") && kinds.contains(&"key"));
    let key_rec = sync["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["kind"] == "key")
        .unwrap();
    assert!(
        key_rec["secret"]["private_key"]
            .as_str()
            .unwrap()
            .contains("PRIVATE KEY"),
        "the user gets their own synced secrets"
    );
    let rev = sync["rev"].as_i64().unwrap();
    let pushed = ana.post("/api/v1/sync", json!({"since": rev, "changes": [{
        "id": termoak_core::new_id(), "kind": "snippet", "data": {"name": "from-mobile", "script": "uptime"},
        "sync_mode": "synced", "updated_at": termoak_core::time::now_ms(), "deleted": false
    }]})).await;
    assert_eq!(pushed["accepted"].as_array().unwrap().len(), 1);
    assert!(
        ana.get("/api/v1/snippets")
            .await
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["name"] == "from-mobile")
    );

    // --- Relay: share a local terminal through the server ---
    let relay = ana
        .post(
            "/api/v1/relay",
            json!({"title": "My laptop", "cols": 80, "rows": 24}),
        )
        .await;
    let rid = relay["session"]["id"].as_str().unwrap().to_string();
    let mut host_ws = ws_connect(
        &base,
        relay["host_ws_path"].as_str().unwrap(),
        Some(&ana.token),
    )
    .await;
    ws_wait_json(&mut host_ws, "hello").await;
    ana.post(
        &format!("/api/v1/sessions/{rid}/shares"),
        json!({"email": "bea@termoak.test", "permission": "control"}),
    )
    .await;
    let mut bea_relay = ws_connect(
        &base,
        &format!("/api/v1/sessions/{rid}/ws"),
        Some(&bea.token),
    )
    .await;
    ws_wait_json(&mut bea_relay, "hello").await;
    host_ws
        .send(WsMsg::Binary("local-output\r\n".as_bytes().to_vec().into()))
        .await
        .unwrap();
    ws_wait_output(&mut bea_relay, "local-output").await;
    bea_relay
        .send(WsMsg::Binary("ls\r".as_bytes().to_vec().into()))
        .await
        .unwrap();
    ws_wait_output(&mut host_ws, "ls").await;

    // --- Close, recording and audit ---
    let (s, _) = ana
        .call(
            reqwest::Method::DELETE,
            &format!("/api/v1/sessions/{sid}"),
            None,
        )
        .await;
    assert_eq!(s, 200);
    for _ in 0..50 {
        let (_, v) = ana
            .call(
                reqwest::Method::GET,
                &format!("/api/v1/sessions/{sid}"),
                None,
            )
            .await;
        if v["state"]["state"] == "closed" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let closed = ws_wait_json(&mut ws, "status").await;
    assert_eq!(closed["status"]["state"], "closed");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let rec = http
        .get(format!("{base}/api/v1/sessions/{sid}/recording"))
        .bearer_auth(&ana.token)
        .send()
        .await
        .unwrap();
    assert!(rec.status().is_success());
    let cast = rec.text().await.unwrap();
    assert!(cast.starts_with("{\"") && cast.contains("persistent-2"));
    let audit = ana.get("/api/v1/audit?limit=200").await;
    let actions: Vec<&str> = audit
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["action"].as_str().unwrap())
        .collect();
    for expected in [
        "session.open",
        "session.share",
        "ai.tool.run_command",
        "exec.batch",
        "sftp.upload",
    ] {
        assert!(
            actions.contains(&expected),
            "{expected} missing from {actions:?}"
        );
    }

    // --- OpenAPI ---
    let doc: Value = http
        .get(format!("{base}/api/openapi.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(doc["paths"]["/api/v1/sessions/{id}/ws"].is_object());
}
