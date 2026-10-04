//! AI access per plan: the users' own API keys (Free) and the server's AI
//! within a monthly credit (Pro), against a mock OpenAI-compatible provider.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use termoak_ai::{AiConfig, Driver, ProviderConfig};
use termoak_server::config::{Registration, ServerConfig};
use termoak_server::state::AppState;
use termoak_server::{build_state, routes};

const SERVER_KEY: &str = "server-secret-key";
const USER_KEY: &str = "user-good-key-0042";

/// Calls seen by the mock: (bearer token, model).
type Seen = Arc<Mutex<Vec<(String, String)>>>;

/// Mock provider (Chat Completions with SSE): answers "hello" and reports a
/// cost of $0.001 per call. `GET /models` only accepts the known keys.
async fn mock_ai() -> (String, Seen) {
    use axum::http::HeaderMap;
    use axum::routing::{get, post};
    let seen: Seen = Arc::default();
    let s = seen.clone();
    let bearer = |h: &HeaderMap| {
        h.get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or_default()
            .to_string()
    };
    let app = axum::Router::new()
        .route(
            "/v1/chat/completions",
            post(move |h: HeaderMap, axum::Json(body): axum::Json<Value>| {
                let s = s.clone();
                async move {
                    s.lock().push((
                        bearer(&h),
                        body["model"].as_str().unwrap_or_default().to_string(),
                    ));
                    let chunks = [
                        json!({"choices":[{"delta":{"content":"hello"}}]}),
                        json!({"choices":[{"delta":{},"finish_reason":"stop"}]}),
                        json!({"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":2,"cost":0.001}}),
                    ];
                    let mut sse = String::new();
                    for c in chunks {
                        sse.push_str(&format!("data: {c}\n\n"));
                    }
                    sse.push_str("data: [DONE]\n\n");
                    ([("content-type", "text/event-stream")], sse)
                }
            }),
        )
        .route(
            "/v1/models",
            get(move |h: HeaderMap| async move {
                let key = bearer(&h);
                if key == USER_KEY || key == SERVER_KEY {
                    (StatusCode::OK, axum::Json(json!({"data": [{"id": "mock-1"}]})))
                } else {
                    (
                        StatusCode::UNAUTHORIZED,
                        axum::Json(json!({"error": {"message": "invalid API key"}})),
                    )
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/v1"), seen)
}

struct Srv {
    base: String,
    http: reqwest::Client,
    state: AppState,
    _data: tempfile::TempDir,
}

impl Srv {
    async fn start(mock_url: &str) -> Self {
        // The server's AI is OpenCode Go (a provider that also accepts the
        // users' own keys), pointed at the mock.
        let mut ai = AiConfig {
            default: "opencode-api".into(),
            fallback: vec![],
            // Fallback credit: does not apply to admins nor to plans with
            // their own credit.
            monthly_budget_usd: Some(0.0),
            ..Default::default()
        };
        ai.providers.insert(
            "opencode-api".into(),
            ProviderConfig {
                driver: Driver::OpenaiChat,
                label: Some("OpenCode Go".into()),
                base_url: Some(mock_url.to_string()),
                api_key: Some(SERVER_KEY.into()),
                model: Some("mock-1".into()),
                subscription: false,
                ..Default::default()
            },
        );
        // A server provider that cannot run (its binary does not exist).
        ai.providers.insert(
            "broken".into(),
            ProviderConfig {
                driver: Driver::CodexCli,
                command: Some("/nonexistent/termoak-test/codex".into()),
                subscription: true,
                ..Default::default()
            },
        );
        // Pro: two calls of the mock ($0.001 each) spend the credit.
        Self::start_with(ai, 0.002).await
    }

    async fn start_with(ai: AiConfig, pro_credit_usd: f64) -> Self {
        let data = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = ServerConfig {
            ai,
            ..Default::default()
        };
        config.server.listen = addr;
        config.server.data_dir = data.path().to_path_buf();
        config.server.registration = Registration::Open;
        let pro = config
            .plans
            .catalog
            .iter_mut()
            .find(|p| p.id == "pro")
            .unwrap();
        pro.limits.ai_credit_usd = Some(pro_credit_usd);
        let state = build_state(config).await.unwrap();
        let app = routes::router(state.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Srv {
            base: format!("http://{addr}"),
            http: reqwest::Client::new(),
            state,
            _data: data,
        }
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut req = self
            .http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(token);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status();
        let text = resp.text().await.unwrap();
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }

    async fn ok(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> Value {
        let (s, v) = self.call(method.clone(), path, token, body).await;
        assert!(s.is_success(), "{method} {path} → {s} {v}");
        v
    }

    async fn register(&self, email: &str) -> (String, Value) {
        let resp = self
            .http
            .post(format!("{}/api/v1/auth/register", self.base))
            .json(&json!({"email": email, "name": "x", "password": "secure-password", "platform": "web"}))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let v: Value = resp.json().await.unwrap();
        (
            v["tokens"]["access_token"].as_str().unwrap().to_string(),
            v["user"].clone(),
        )
    }

    /// Runs a task to the end and returns it.
    async fn run_task(&self, token: &str) -> Value {
        self.run_task_with(token, None).await
    }

    /// Runs a task (with a provider, if given) to the end and returns it.
    async fn run_task_with(&self, token: &str, provider: Option<&str>) -> Value {
        let task = self
            .ok(
                Method::POST,
                "/api/v1/ai/tasks",
                token,
                Some(json!({"prompt": "Say hello", "provider": provider})),
            )
            .await;
        let id = task["id"].as_str().unwrap().to_string();
        for _ in 0..200 {
            let t = self
                .ok(Method::GET, &format!("/api/v1/ai/tasks/{id}"), token, None)
                .await;
            if t["status"] == "completed" || t["status"] == "failed" {
                return t;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the task did not finish");
    }

    /// One provider of `GET /api/v1/ai/providers`.
    async fn provider(&self, token: &str, key: &str) -> Value {
        let list = self
            .ok(Method::GET, "/api/v1/ai/providers", token, None)
            .await;
        list["providers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["key"] == key)
            .unwrap()
            .clone()
    }

    async fn access(&self, token: &str) -> Value {
        self.ok(Method::GET, "/api/v1/me/ai/access", token, None)
            .await
    }
}

fn last_call(seen: &Seen) -> (String, String) {
    seen.lock()
        .last()
        .cloned()
        .expect("the mock was not called")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn own_keys_and_ai_credit() {
    let (mock_url, seen) = mock_ai().await;
    let srv = Srv::start(&mock_url).await;
    let (admin, admin_user) = srv.register("admin@termoak.test").await;
    assert_eq!(admin_user["is_admin"], true);
    let (free, free_user) = srv.register("free@termoak.test").await;
    let (pro, pro_user) = srv.register("pro@termoak.test").await;
    srv.ok(
        Method::PATCH,
        &format!("/api/v1/admin/users/{}", pro_user["id"].as_str().unwrap()),
        &admin,
        Some(json!({"plan": "pro"})),
    )
    .await;

    // --- Free without a key: the server's AI is not included ---
    let (s, v) = srv
        .call(
            Method::POST,
            "/api/v1/ai/tasks",
            &free,
            Some(json!({"prompt": "hi"})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["error"]["code"], "ai_key_required");
    let (s, v) = srv
        .call(
            Method::POST,
            "/api/v1/ai/suggest",
            &free,
            Some(json!({"request": "disk usage"})),
        )
        .await;
    assert_eq!(
        (s, &v["error"]["code"]),
        (StatusCode::FORBIDDEN, &json!("ai_key_required"))
    );
    let access = srv.access(&free).await;
    assert_eq!(access["server_ai"], false);
    assert_eq!(access["own_keys"], json!([]));
    assert!(access["credit_usd"].is_null() && access["remaining_usd"].is_null());
    assert!(
        access["providers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["provider"] == "opencode-api")
    );
    let providers = srv
        .ok(Method::GET, "/api/v1/ai/providers", &free, None)
        .await;
    let oc = providers["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["key"] == "opencode-api")
        .unwrap()
        .clone();
    assert_eq!(
        (oc["available"].clone(), oc["accepts_own_key"].clone()),
        (json!(false), json!(true))
    );
    assert!(seen.lock().is_empty());

    // --- Saving a key: validated, stored encrypted, never returned ---
    let (s, v) = srv
        .call(
            Method::PUT,
            "/api/v1/me/ai/keys/codex",
            &free,
            Some(json!({"key": "abc"})),
        )
        .await;
    assert_eq!(
        (s, &v["error"]["code"]),
        (StatusCode::BAD_REQUEST, &json!("unknown_provider"))
    );
    let (s, _) = srv
        .call(
            Method::PUT,
            "/api/v1/me/ai/keys/opencode-api",
            &free,
            Some(json!({"key": "has spaces in it"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = srv
        .call(
            Method::PUT,
            "/api/v1/me/ai/keys/opencode-api",
            &free,
            Some(json!({"key": "x".repeat(600)})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let saved = srv
        .ok(
            Method::PUT,
            "/api/v1/me/ai/keys/opencode-api",
            &free,
            Some(json!({"key": format!("  {USER_KEY} "), "model": "mock-own"})),
        )
        .await;
    assert_eq!(saved["hint"], "0042");
    assert_eq!(saved["model"], "mock-own");
    assert_eq!(saved["label"], "OpenCode Go");
    let keys = srv.ok(Method::GET, "/api/v1/me/ai/keys", &free, None).await;
    assert_eq!(keys.as_array().unwrap().len(), 1);
    assert_eq!(keys[0]["provider"], "opencode-api");
    for body in [&saved, &keys] {
        assert!(
            !body.to_string().contains(USER_KEY),
            "the key leaked: {body}"
        );
    }

    // --- Without `key`: only the model of the saved key changes ---
    let changed = srv
        .ok(
            Method::PUT,
            "/api/v1/me/ai/keys/opencode-api",
            &free,
            Some(json!({"model": "mock-2"})),
        )
        .await;
    assert_eq!(
        (changed["hint"].clone(), changed["model"].clone()),
        (json!("0042"), json!("mock-2"))
    );
    assert_eq!(changed["created_at"], saved["created_at"]);
    srv.ok(
        Method::PUT,
        "/api/v1/me/ai/keys/opencode-api",
        &free,
        Some(json!({"model": "mock-own"})),
    )
    .await;
    let (s, v) = srv
        .call(
            Method::PUT,
            "/api/v1/me/ai/keys/openrouter",
            &free,
            Some(json!({"model": "x"})),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "no saved key for openrouter: {v}");

    // --- Checking keys (the saved one, or one in the body) ---
    let t = srv
        .ok(
            Method::POST,
            "/api/v1/me/ai/keys/opencode-api/test",
            &free,
            None,
        )
        .await;
    assert_eq!(t["ok"], true, "{t}");
    let t = srv
        .ok(
            Method::POST,
            "/api/v1/me/ai/keys/opencode-api/test",
            &free,
            Some(json!({"key": "wrong-key"})),
        )
        .await;
    assert_eq!(
        (t["ok"].clone(), t["status"].clone()),
        (json!(false), json!(401))
    );
    let (s, _) = srv
        .call(
            Method::POST,
            "/api/v1/me/ai/keys/gpt/test",
            &free,
            Some(json!({})),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "no saved key for gpt");

    // --- Free with their key: the task runs with it and spends no credit ---
    let done = srv.run_task(&free).await;
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(done["used_provider"], "opencode-api::mock-own");
    assert_eq!(
        last_call(&seen),
        (USER_KEY.to_string(), "mock-own".to_string())
    );
    let events = srv
        .ok(
            Method::GET,
            &format!("/api/v1/ai/tasks/{}/events", done["id"].as_str().unwrap()),
            &free,
            None,
        )
        .await;
    let usage = events
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "usage")
        .unwrap();
    assert_eq!(usage["data"]["own_key"], true);
    let access = srv.access(&free).await;
    assert_eq!(access["own_keys"], json!(["opencode-api"]));
    assert_eq!(access["spent_usd"], 0.0);
    let plan = srv.ok(Method::GET, "/api/v1/me/plan", &free, None).await;
    assert_eq!(plan["usage"]["ai_spent_usd"], 0.0);
    // The quick assistant follows the same rules (and uses the key).
    let explained = srv
        .ok(
            Method::POST,
            "/api/v1/ai/explain",
            &free,
            Some(json!({"text": "permission denied"})),
        )
        .await;
    assert_eq!(explained["answer"], "hello");
    assert_eq!(last_call(&seen).0, USER_KEY);
    let providers = srv
        .ok(Method::GET, "/api/v1/ai/providers", &free, None)
        .await;
    let oc = providers["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["key"] == "opencode-api")
        .unwrap()
        .clone();
    assert_eq!(
        (oc["available"].clone(), oc["uses_own_key"].clone()),
        (json!(true), json!(true))
    );

    // --- Pro without a key: the server's AI, within the credit ---
    let access = srv.access(&pro).await;
    assert_eq!(access["server_ai"], true);
    assert_eq!(access["credit_usd"], 0.002);
    assert_eq!(access["remaining_usd"], 0.002);
    for spent in [0.001, 0.002] {
        let done = srv.run_task(&pro).await;
        assert_eq!(done["status"], "completed", "{done}");
        assert_eq!(
            last_call(&seen),
            (SERVER_KEY.to_string(), "mock-1".to_string())
        );
        assert_eq!(srv.access(&pro).await["spent_usd"], spent);
    }
    let access = srv.access(&pro).await;
    assert_eq!(access["remaining_usd"], 0.0);
    let plan = srv.ok(Method::GET, "/api/v1/me/plan", &pro, None).await;
    assert_eq!(plan["usage"]["ai_spent_usd"], 0.002);
    assert_eq!(plan["usage"]["ai_credit_usd"], 0.002);
    let (s, v) = srv
        .call(
            Method::POST,
            "/api/v1/ai/tasks",
            &pro,
            Some(json!({"prompt": "again"})),
        )
        .await;
    assert_eq!(
        (s, &v["error"]["code"]),
        (StatusCode::FORBIDDEN, &json!("ai_budget_exceeded")),
        "{v}"
    );
    // Deleting the tasks does not give the credit back.
    let tasks = srv.ok(Method::GET, "/api/v1/ai/tasks", &pro, None).await;
    for t in tasks.as_array().unwrap() {
        srv.ok(
            Method::DELETE,
            &format!("/api/v1/ai/tasks/{}", t["id"].as_str().unwrap()),
            &pro,
            None,
        )
        .await;
    }
    assert_eq!(srv.access(&pro).await["spent_usd"], 0.002);
    // With their own key, Pro keeps going without spending credit.
    srv.ok(
        Method::PUT,
        "/api/v1/me/ai/keys/opencode-api",
        &pro,
        Some(json!({"key": USER_KEY})),
    )
    .await;
    let done = srv.run_task(&pro).await;
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(
        last_call(&seen),
        (USER_KEY.to_string(), "mock-1".to_string())
    );
    assert_eq!(srv.access(&pro).await["spent_usd"], 0.002);
    let deleted = srv
        .ok(
            Method::DELETE,
            "/api/v1/me/ai/keys/opencode-api",
            &pro,
            None,
        )
        .await;
    assert_eq!(deleted["deleted"], true);
    let (s, _) = srv
        .call(
            Method::POST,
            "/api/v1/ai/tasks",
            &pro,
            Some(json!({"prompt": "again"})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // --- Admins: no limits (the [ai] fallback credit of 0 does not apply) ---
    let access = srv.access(&admin).await;
    assert_eq!(access["server_ai"], true);
    assert!(access["credit_usd"].is_null());
    let done = srv.run_task(&admin).await;
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(last_call(&seen).0, SERVER_KEY);

    // --- Deleting the account deletes its keys ---
    let free_id: termoak_core::Id = free_user["id"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        srv.state.store.user_ai_keys(free_id).await.unwrap().len(),
        1
    );
    srv.ok(
        Method::DELETE,
        "/api/v1/me",
        &free,
        Some(json!({"password": "secure-password"})),
    )
    .await;
    assert!(
        srv.state
            .store
            .user_ai_keys(free_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        srv.state
            .store
            .user_ai_key_secrets(free_id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_reasons_are_generic_for_users() {
    let (mock_url, _seen) = mock_ai().await;
    let srv = Srv::start(&mock_url).await;
    let (admin, _) = srv.register("admin@termoak.test").await;
    let (free, _) = srv.register("free@termoak.test").await;
    let (pro, pro_user) = srv.register("pro@termoak.test").await;
    srv.ok(
        Method::PATCH,
        &format!("/api/v1/admin/users/{}", pro_user["id"].as_str().unwrap()),
        &admin,
        Some(json!({"plan": "pro"})),
    )
    .await;

    // Administrators see why it cannot run.
    let b = srv.provider(&admin, "broken").await;
    assert_eq!(b["available"], false);
    assert_eq!(b["reason_code"], "not_configured");
    assert!(
        b["reason"].as_str().unwrap().contains("/nonexistent/"),
        "{b}"
    );
    // Users get a generic text, without paths or variable names.
    let b = srv.provider(&pro, "broken").await;
    assert_eq!(
        (b["reason_code"].clone(), b["reason"].clone()),
        (
            json!("not_configured"),
            json!("not available on this server")
        )
    );
    // Without the server's AI in the plan: why, as a code.
    let b = srv.provider(&free, "broken").await;
    assert_eq!(b["reason_code"], "plan");
    let oc = srv.provider(&free, "opencode-api").await;
    assert_eq!(
        (oc["available"].clone(), oc["reason_code"].clone()),
        (json!(false), json!("own_key_required"))
    );
    let oc = srv.provider(&pro, "opencode-api").await;
    assert_eq!(
        (oc["available"].clone(), oc["reason_code"].clone()),
        (json!(true), Value::Null)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_checks_are_rate_limited() {
    let (mock_url, _seen) = mock_ai().await;
    let srv = Srv::start(&mock_url).await;
    let (_admin, _) = srv.register("admin@termoak.test").await;
    let (user, _) = srv.register("user@termoak.test").await;
    let mut limited = false;
    for _ in 0..12 {
        let (s, v) = srv
            .call(
                Method::POST,
                "/api/v1/me/ai/keys/opencode-api/test",
                &user,
                Some(json!({"key": "wrong-key"})),
            )
            .await;
        if s == StatusCode::TOO_MANY_REQUESTS {
            assert_eq!(v["error"]["code"], "too_many_attempts");
            limited = true;
            break;
        }
        assert_eq!(s, StatusCode::OK);
    }
    assert!(limited);
}

/// Fake `codex` CLI (ChatGPT subscription): answers "hello" and reports
/// 100,000 input and 10,000 output tokens per run.
fn fake_codex(dir: &std::path::Path, model: Option<&str>) -> ProviderConfig {
    use std::os::unix::fs::PermissionsExt;
    let bin = dir.join("codex");
    std::fs::write(
        &bin,
        r#"#!/bin/sh
cat > /dev/null
echo '{"type":"item.completed","item":{"type":"agent_message","text":"hello"}}'
echo '{"type":"turn.completed","usage":{"input_tokens":100000,"cached_input_tokens":0,"output_tokens":10000}}'
"#,
    )
    .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(dir.join("codex-code-mode-host"), "").unwrap();
    let home = dir.join("codex-home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("auth.json"), "{}").unwrap();
    ProviderConfig {
        driver: Driver::CodexCli,
        label: Some("Codex".into()),
        command: Some(bin.display().to_string()),
        codex_home: Some(home.display().to_string()),
        model: model.map(str::to_string),
        timeout_secs: Some(60),
        subscription: true,
        ..Default::default()
    }
}

/// Micro-USD of a `*_usd` field.
fn micros(v: &Value) -> i64 {
    (v.as_f64().unwrap() * 1_000_000.0).round() as i64
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscription_usage_spends_the_credit() {
    let (mock_url, seen) = mock_ai().await;
    let bin = tempfile::tempdir().unwrap();
    // As in production: the server's AI is Codex with the ChatGPT
    // subscription (real cost 0), plus OpenCode Go for the users' own keys.
    let mut ai = AiConfig {
        default: "codex".into(),
        fallback: vec![],
        ..Default::default()
    };
    ai.providers
        .insert("codex".into(), fake_codex(bin.path(), Some("gpt-5.6-sol")));
    // Without a model: charged at the Codex reference price.
    ai.providers
        .insert("codex-plain".into(), fake_codex(bin.path(), None));
    ai.providers.insert(
        "opencode-api".into(),
        ProviderConfig {
            driver: Driver::OpenaiChat,
            base_url: Some(mock_url.clone()),
            api_key: Some(SERVER_KEY.into()),
            model: Some("mock-1".into()),
            subscription: true,
            ..Default::default()
        },
    );
    // Codex with gpt-5.6-sol ($5 / $30 per million): $0.50 + $0.30 per run.
    let srv = Srv::start_with(ai, 1.0).await;
    let (admin, _) = srv.register("admin@termoak.test").await;
    let (pro, pro_user) = srv.register("pro@termoak.test").await;
    let (pro2, pro2_user) = srv.register("pro2@termoak.test").await;
    let (free, _) = srv.register("free@termoak.test").await;
    for u in [&pro_user, &pro2_user] {
        srv.ok(
            Method::PATCH,
            &format!("/api/v1/admin/users/{}", u["id"].as_str().unwrap()),
            &admin,
            Some(json!({"plan": "pro"})),
        )
        .await;
    }

    // --- Codex usage spends the Pro credit, though it costs the server $0 ---
    let t = srv.run_task(&pro).await;
    assert_eq!(t["status"], "completed", "{t}");
    assert_eq!(t["used_provider"], "codex::gpt-5.6-sol");
    assert_eq!(t["cost_micros"], 0, "the real cost of a subscription is 0");
    let access = srv.access(&pro).await;
    assert_eq!(micros(&access["spent_usd"]), 800_000);
    assert_eq!(micros(&access["remaining_usd"]), 200_000);
    let rows = srv
        .state
        .store
        .ai_credit_spent_since(pro_user["id"].as_str().unwrap().parse().unwrap(), 0)
        .await
        .unwrap();
    assert_eq!(rows, 800_000);
    // The credit is checked before each run: the second one still starts...
    assert_eq!(srv.run_task(&pro).await["status"], "completed");
    assert_eq!(micros(&srv.access(&pro).await["spent_usd"]), 1_600_000);
    // ...and then it is used up.
    let (s, v) = srv
        .call(
            Method::POST,
            "/api/v1/ai/tasks",
            &pro,
            Some(json!({"prompt": "hi"})),
        )
        .await;
    assert_eq!(
        (s, &v["error"]["code"]),
        (StatusCode::FORBIDDEN, &json!("ai_budget_exceeded")),
        "{v}"
    );
    assert_eq!(micros(&srv.access(&pro).await["remaining_usd"]), 0);

    // --- Codex without a model: GPT-5.3-codex reference ($1.75 / $14) ---
    let t = srv.run_task_with(&pro2, Some("codex-plain")).await;
    assert_eq!(t["status"], "completed", "{t}");
    assert_eq!(micros(&srv.access(&pro2).await["spent_usd"]), 315_000);

    // --- The user's own key still spends no credit ---
    srv.ok(
        Method::PUT,
        "/api/v1/me/ai/keys/opencode-api",
        &pro,
        Some(json!({"key": USER_KEY})),
    )
    .await;
    let t = srv.run_task(&pro).await;
    assert_eq!(t["status"], "completed", "{t}");
    assert_eq!(last_call(&seen).0, USER_KEY);
    assert_eq!(micros(&srv.access(&pro).await["spent_usd"]), 1_600_000);

    srv.ok(
        Method::PUT,
        "/api/v1/me/ai/keys/opencode-api",
        &free,
        Some(json!({"key": USER_KEY})),
    )
    .await;
    assert_eq!(srv.run_task(&free).await["status"], "completed");
    assert_eq!(micros(&srv.access(&free).await["spent_usd"]), 0);
}
