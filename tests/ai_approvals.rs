//! AI tasks against a scripted mock provider (OpenAI-compatible): approvals
//! with a preview, edited and approved or denied with a reason (what the
//! model is told, events and audit), runbooks saved to a vault you can edit,
//! and multi-host tasks that only notify (push) when the parent finishes.

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use parking_lot::Mutex;
use serde_json::{Value, json};
use termoak_ai::{Driver, ProviderConfig};
use termoak_server::config::FcmSection;

use common::srv::{Srv, User};

/// What the mocks received.
#[derive(Default)]
struct Seen {
    /// Request bodies sent to the AI provider.
    ai: Mutex<Vec<Value>>,
    /// FCM messages.
    fcm: Mutex<Vec<Value>>,
}

/// Text of a Chat Completions message (a string or text parts).
fn text_of(m: &Value) -> String {
    match &m["content"] {
        Value::String(s) => s.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|p| p["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn sse(chunks: &[Value]) -> ([(&'static str, &'static str); 1], String) {
    let mut body = String::new();
    for c in chunks {
        body.push_str(&format!("data: {c}\n\n"));
    }
    body.push_str("data: [DONE]\n\n");
    ([("content-type", "text/event-stream")], body)
}

/// The scripted model: a user message with `RUN: <command>` gets a
/// `run_command` call on the host `web` (until a tool result comes back);
/// anything else gets a short answer.
async fn chat(
    State(seen): State<Arc<Seen>>,
    Json(body): Json<Value>,
) -> ([(&'static str, &'static str); 1], String) {
    seen.ai.lock().push(body.clone());
    let messages = body["messages"].as_array().cloned().unwrap_or_default();
    let usage = json!({"choices": [], "usage": {"prompt_tokens": 10, "completion_tokens": 2}});
    let last_is_tool = messages.last().is_some_and(|m| m["role"] == "tool");
    let command = messages
        .iter()
        .filter(|m| m["role"] == "user")
        .find_map(|m| {
            let t = text_of(m);
            t.find("RUN: ")
                .map(|i| t[i + 5..].lines().next().unwrap_or_default().to_string())
        });
    match command {
        Some(cmd) if !last_is_tool => {
            let args = json!({"host": "web", "command": cmd, "reason": "Clean the cache"});
            sse(&[
                json!({"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "call_1", "type": "function",
                    "function": {"name": "run_command", "arguments": args.to_string()}}]}}]}),
                json!({"choices": [{"delta": {}, "finish_reason": "tool_calls"}]}),
                usage,
            ])
        }
        _ => sse(&[
            json!({"choices": [{"delta": {"content": "done"}}]}),
            json!({"choices": [{"delta": {}, "finish_reason": "stop"}]}),
            usage,
        ]),
    }
}

async fn fcm_token() -> Json<Value> {
    Json(json!({"access_token": "ya29.test", "expires_in": 3600}))
}

async fn fcm_send(
    State(seen): State<Arc<Seen>>,
    _h: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    seen.fcm.lock().push(body);
    Json(json!({"name": "projects/demo/messages/1"}))
}

/// Mock AI provider and FCM; returns their base URL.
async fn start_mocks() -> (String, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let app = axum::Router::new()
        .route("/v1/chat/completions", post(chat))
        .route("/token", post(fcm_token))
        .route("/v1/projects/demo/messages:send", post(fcm_send))
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), seen)
}

async fn start(dir: &tempfile::TempDir) -> (Srv, Arc<Seen>) {
    let (mock, seen) = start_mocks().await;
    let account = json!({
        "type": "service_account",
        "project_id": "demo",
        "private_key_id": "key-1",
        "private_key": include_str!("data/fcm-test-key.pem"),
        "client_email": "push@demo.iam.gserviceaccount.com",
        "token_uri": format!("{mock}/token"),
    });
    let account_path = dir.path().join("firebase.json");
    std::fs::write(&account_path, account.to_string()).unwrap();
    let srv = Srv::start_with(|c| {
        c.ai.default = "opencode-api".into();
        c.ai.fallback = vec![];
        c.ai.providers.insert(
            "opencode-api".into(),
            ProviderConfig {
                driver: Driver::OpenaiChat,
                label: Some("Mock".into()),
                base_url: Some(format!("{mock}/v1")),
                api_key: Some("server-key".into()),
                model: Some("mock-1".into()),
                ..Default::default()
            },
        );
        c.push.fcm = Some(FcmSection {
            service_account_path: Some(account_path),
            endpoint: Some(mock.clone()),
        });
    })
    .await;
    (srv, seen)
}

/// Polls a task until `pred` holds (20 s).
async fn wait_task(srv: &Srv, u: &User, id: &str, pred: impl Fn(&Value) -> bool) -> Value {
    for _ in 0..400 {
        let r = srv.get(&format!("/api/v1/ai/tasks/{id}"), u).await;
        assert_eq!(r.status, 200, "{}", r.body);
        if pred(&r.body) {
            return r.body;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let r = srv.get(&format!("/api/v1/ai/tasks/{id}"), u).await;
    panic!("task {id} did not get there: {}", r.body);
}

fn finished(t: &Value) -> bool {
    matches!(
        t["status"].as_str(),
        Some("completed" | "failed" | "cancelled")
    )
}

/// Starts a task that wants to run `rm -rf …` and waits for its approval.
async fn task_with_approval(srv: &Srv, u: &User, host: &str) -> (String, Value) {
    let task = srv
        .ok(
            "/api/v1/ai/tasks",
            u,
            json!({"prompt": "RUN: rm -rf /tmp/termoak-ai-test", "mode": "ask", "host_ids": [host]}),
        )
        .await;
    let id = task["id"].as_str().unwrap().to_string();
    let t = wait_task(srv, u, &id, |t| {
        t["pending_approvals"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
            || finished(t)
    })
    .await;
    assert_eq!(t["status"], "waiting_approval", "{t}");
    (id, t["pending_approvals"][0].clone())
}

async fn events(srv: &Srv, u: &User, id: &str) -> Vec<Value> {
    let r = srv
        .get(&format!("/api/v1/ai/tasks/{id}/events?after=0"), u)
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    r.body.as_array().unwrap().clone()
}

async fn audit_entry(srv: &Srv, u: &User, action: &str, target: &str) -> Value {
    let r = srv.get("/api/v1/audit?limit=200", u).await;
    r.body
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["action"] == action && e["target"] == target)
        .unwrap_or_else(|| panic!("no {action} for {target}: {}", r.body))
        .clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn approvals_preview_edit_and_deny_with_reason() {
    let dir = tempfile::tempdir().unwrap();
    let (srv, seen) = start(&dir).await;
    // The first account (administrator: the server's AI without a plan limit).
    let ana = srv.user("Ana").await;
    let bea = srv.user("Bea").await;
    let sshd = common::start_sshd();
    let host = match &sshd {
        Some(sshd) => {
            let key = srv
                .ok(
                    "/api/v1/keys/import",
                    &ana,
                    json!({"label": "ai", "private_key": sshd.private_key}),
                )
                .await;
            srv.ok(
                "/api/v1/hosts",
                &ana,
                json!({"label": "web", "address": "127.0.0.1",
                       "settings": {"port": sshd.port, "username": sshd.user, "key_id": key["id"]}}),
            )
            .await
        }
        None => {
            eprintln!("no sshd: the edited command fails to connect and no runbook is saved");
            srv.ok(
                "/api/v1/hosts",
                &ana,
                json!({"label": "web", "address": "127.0.0.1", "settings": {"port": 1}}),
            )
            .await
        }
    };
    let host = host["id"].as_str().unwrap().to_string();

    // --- Deny with a reason ---------------------------------------------------
    let (task, approval) = task_with_approval(&srv, &ana, &host).await;
    let preview = &approval["preview"];
    assert_eq!(preview["kind"], "command", "{approval}");
    assert_eq!(preview["command"], "rm -rf /tmp/termoak-ai-test");
    assert_eq!(preview["host"], "web");
    assert_eq!(preview["risk"], "high");
    assert_eq!(preview["editable"], true);
    assert_eq!(preview["explanation"], "Clean the cache");
    assert!(
        preview["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["code"] == "rm_rf"),
        "{preview}"
    );
    let approval_id = approval["id"].as_str().unwrap().to_string();
    // Also in the list of pending approvals.
    let r = srv.get("/api/v1/ai/approvals", &ana).await;
    let pending = r
        .body
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == approval_id.as_str())
        .unwrap()
        .clone();
    assert_eq!(pending["preview"]["command"], "rm -rf /tmp/termoak-ai-test");
    // Someone else cannot answer it.
    let decide = format!("/api/v1/ai/tasks/{task}/approvals/{approval_id}");
    let r = srv
        .post(&decide, &bea, json!({"approve": true, "edited": "id"}))
        .await;
    assert_eq!(r.status, 404, "{}", r.body);

    let r = srv
        .post(
            &decide,
            &ana,
            json!({"approve": false, "reason": "  not on this server  "}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let t = wait_task(&srv, &ana, &task, finished).await;
    assert_eq!(t["status"], "completed", "{t}");
    assert!(t["pending_approvals"].as_array().unwrap().is_empty());
    // The model was told why.
    let told =
        seen.ai.lock().iter().any(|b| {
            b["messages"].as_array().unwrap().iter().any(|m| {
                m["role"] == "tool" && text_of(m).contains("Their reason: not on this server")
            })
        });
    assert!(told, "the reason did not reach the model");
    let decided = events(&srv, &ana, &task)
        .await
        .into_iter()
        .find(|e| e["kind"] == "approval_decided")
        .expect("approval_decided event");
    assert_eq!(decided["data"]["approved"], false, "{decided}");
    assert_eq!(decided["data"]["reason"], "not on this server");
    assert!(decided["data"].get("edited").is_none());
    let requested = events(&srv, &ana, &task)
        .await
        .into_iter()
        .find(|e| e["kind"] == "approval_requested")
        .unwrap();
    assert_eq!(requested["data"]["preview"]["risk"], "high");
    let entry = audit_entry(&srv, &ana, "ai.approval.denied", &approval_id).await;
    assert_eq!(entry["detail"]["reason"], "not on this server", "{entry}");
    assert_eq!(entry["detail"]["task"], task.as_str());
    assert!(entry["detail"].get("edited").is_none());

    // --- Edit and approve -----------------------------------------------------
    let (task, approval) = task_with_approval(&srv, &ana, &host).await;
    let approval_id = approval["id"].as_str().unwrap().to_string();
    let r = srv
        .post(
            &format!("/api/v1/ai/tasks/{task}/approvals/{approval_id}"),
            &ana,
            json!({"approve": true, "edited": " echo edited-by-user "}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let t = wait_task(&srv, &ana, &task, finished).await;
    assert_eq!(t["status"], "completed", "{t}");
    let decided = events(&srv, &ana, &task)
        .await
        .into_iter()
        .find(|e| e["kind"] == "approval_decided")
        .unwrap();
    assert_eq!(decided["data"]["approved"], true);
    assert_eq!(decided["data"]["edited"], "echo edited-by-user");
    let entry = audit_entry(&srv, &ana, "ai.approval.approved", &approval_id).await;
    assert_eq!(entry["detail"]["edited"], "echo edited-by-user", "{entry}");
    // Answering it again: it is no longer pending.
    let r = srv
        .post(
            &format!("/api/v1/ai/tasks/{task}/approvals/{approval_id}"),
            &ana,
            json!({"approve": true}),
        )
        .await;
    assert_eq!(r.status, 404);

    // --- Runbook ----------------------------------------------------------------
    let runbook = format!("/api/v1/ai/tasks/{task}/runbook");
    let r = srv.get(&runbook, &bea).await;
    assert_eq!(r.status, 404, "someone else's task: {}", r.body);
    let rb = srv.get(&runbook, &ana).await;
    assert_eq!(rb.status, 200, "{}", rb.body);
    // A shared vault where Ana is Editor and one where she is Use-only.
    let ops = srv.vault(&bea, "Ops").await;
    srv.share(&bea, &ops, &ana, "editor").await;
    let ro = srv.vault(&bea, "Read").await;
    srv.share(&bea, &ro, &ana, "use_only").await;
    let r = srv.post(&runbook, &ana, json!({"vault_id": ro})).await;
    assert_eq!(r.status, 403, "Use-only vault: {}", r.body);
    if sshd.is_some() {
        // The edited command ran, and the model was told.
        let steps = t["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 1, "{t}");
        assert_eq!(steps[0]["command"], "echo edited-by-user");
        assert_eq!(steps[0]["edited"], true);
        assert_eq!(steps[0]["ok"], true);
        let output_seen = seen.ai.lock().iter().any(|b| {
            b["messages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m["role"] == "tool" && text_of(m).contains("edited-by-user"))
        });
        assert!(output_seen);
        assert_eq!(rb.body["steps"], 1, "{}", rb.body);
        assert!(
            rb.body["script"]
                .as_str()
                .unwrap()
                .contains("echo edited-by-user"),
            "{}",
            rb.body
        );
        let saved = srv
            .post(
                &runbook,
                &ana,
                json!({"name": "Cache cleanup", "vault_id": ops}),
            )
            .await;
        assert_eq!(saved.status, 200, "{}", saved.body);
        assert_eq!(saved.body["name"], "Cache cleanup");
        assert_eq!(saved.body["vault_id"], ops.as_str());
        assert_eq!(saved.body["tags"], json!(["ai", "runbook"]));
        // Bea (the vault's owner) sees it.
        let id = saved.body["id"].as_str().unwrap();
        let r = srv.get(&format!("/api/v1/snippets/{id}"), &bea).await;
        assert_eq!(r.status, 200);
        // Without a body: the personal vault, named after the task.
        let r = srv
            .req(reqwest::Method::POST, &runbook, &ana.token, None)
            .await;
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(r.body["vault_id"], ana.id.as_str());
        let r = srv.get(&format!("/api/v1/vaults/{ops}/audit"), &bea).await;
        assert!(
            r.body
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["action"] == "ai.task.runbook"),
            "{}",
            r.body
        );
    } else {
        assert_eq!(rb.body["steps"], 0, "{}", rb.body);
        let r = srv.post(&runbook, &ana, json!({"vault_id": ops})).await;
        assert_eq!((r.status, r.code()), (400, "runbook_empty"), "{}", r.body);
    }

    // Apps that only send `{approve}` keep working.
    let (task, approval) = task_with_approval(&srv, &ana, &host).await;
    let r = srv
        .post(
            &format!(
                "/api/v1/ai/tasks/{task}/approvals/{}",
                approval["id"].as_str().unwrap()
            ),
            &ana,
            json!({"approve": false}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    wait_task(&srv, &ana, &task, finished).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_host_tasks_notify_only_when_the_parent_finishes() {
    let dir = tempfile::tempdir().unwrap();
    let (srv, seen) = start(&dir).await;
    let ana = srv.user("Ana").await;
    let r = srv
        .post(
            "/api/v1/push/register",
            &ana,
            json!({"platform": "fcm", "token": "tok-android"}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    for label in ["fleet-1", "fleet-2", "other"] {
        let tags = if label.starts_with("fleet") {
            json!(["fleet"])
        } else {
            json!([])
        };
        srv.ok(
            "/api/v1/hosts",
            &ana,
            json!({"label": label, "address": format!("{label}.example.com"), "tags": tags}),
        )
        .await;
    }
    let task = srv
        .ok(
            "/api/v1/ai/tasks",
            &ana,
            json!({"prompt": "Say hello", "tag": "fleet", "fan_out": true, "mode": "read_only"}),
        )
        .await;
    let id = task["id"].as_str().unwrap().to_string();
    let t = wait_task(&srv, &ana, &id, finished).await;
    assert_eq!(t["status"], "completed", "{t}");
    assert_eq!(t["fan_out"], true);
    assert_eq!(t["tag"], "fleet");
    let hosts = t["hosts"].as_array().unwrap();
    assert_eq!(hosts.len(), 2, "{t}");
    for h in hosts {
        let child = h["task_id"].as_str().unwrap();
        let c = srv.get(&format!("/api/v1/ai/tasks/{child}"), &ana).await;
        assert_eq!(c.body["parent_id"], id.as_str(), "{}", c.body);
    }
    // One "finished" notification: the parent's.
    let finished_pushes = || -> Vec<Value> {
        seen.fcm
            .lock()
            .iter()
            .filter(|m| m["message"]["data"]["type"] == "ai_finished")
            .cloned()
            .collect()
    };
    for _ in 0..100 {
        if !finished_pushes().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let pushes = finished_pushes();
    assert_eq!(pushes.len(), 1, "{pushes:?}");
    assert_eq!(pushes[0]["message"]["data"]["task_id"], id.as_str());
}
