//! A test server with several users (vault tests).

use std::time::Duration;

use futures::StreamExt;
use reqwest::Method;
use serde_json::{Value, json};
use termoak_server::config::{Registration, ServerConfig};
use termoak_server::state::AppState;
use termoak_server::{build_state, routes};
use tokio_tungstenite::tungstenite::Message as WsMsg;

pub struct Srv {
    pub base: String,
    pub http: reqwest::Client,
    pub state: AppState,
    _data: tempfile::TempDir,
}

#[derive(Clone, Debug)]
pub struct User {
    pub token: String,
    pub id: String,
    pub email: String,
}

pub struct Resp {
    pub status: u16,
    pub body: Value,
    pub headers: reqwest::header::HeaderMap,
}

impl Resp {
    /// The error code (`error.code`).
    pub fn code(&self) -> &str {
        self.body["error"]["code"].as_str().unwrap_or("")
    }
}

impl Srv {
    pub async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    pub async fn start_with(configure: impl FnOnce(&mut ServerConfig)) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let data = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = ServerConfig::default();
        config.server.listen = addr;
        config.server.data_dir = data.path().to_path_buf();
        config.server.registration = Registration::Open;
        config.sessions.host_key_policy = termoak_ssh::HostKeyPolicy::AcceptNew;
        config.ai.host_key_policy = termoak_ssh::HostKeyPolicy::AcceptNew;
        configure(&mut config);
        let state = build_state(config).await.unwrap();
        let router = routes::router(state.clone());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Srv {
            base: format!("http://{addr}"),
            http: reqwest::Client::new(),
            state,
            _data: data,
        }
    }

    pub async fn req(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> Resp {
        let mut r = self
            .http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(token);
        if let Some(b) = body {
            r = r.json(&b);
        }
        let resp = r.send().await.unwrap();
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let text = resp.text().await.unwrap();
        Resp {
            status,
            body: serde_json::from_str(&text).unwrap_or(Value::String(text)),
            headers,
        }
    }

    pub async fn get(&self, path: &str, u: &User) -> Resp {
        self.req(Method::GET, path, &u.token, None).await
    }

    pub async fn post(&self, path: &str, u: &User, body: Value) -> Resp {
        self.req(Method::POST, path, &u.token, Some(body)).await
    }

    pub async fn put(&self, path: &str, u: &User, body: Value) -> Resp {
        self.req(Method::PUT, path, &u.token, Some(body)).await
    }

    pub async fn patch(&self, path: &str, u: &User, body: Value) -> Resp {
        self.req(Method::PATCH, path, &u.token, Some(body)).await
    }

    pub async fn delete(&self, path: &str, u: &User) -> Resp {
        self.req(Method::DELETE, path, &u.token, None).await
    }

    /// `POST` that must succeed.
    pub async fn ok(&self, path: &str, u: &User, body: Value) -> Value {
        let r = self.post(path, u, body).await;
        assert!(r.status < 300, "POST {path}: {} {}", r.status, r.body);
        r.body
    }

    /// Registers a user (the first one becomes an administrator).
    pub async fn user(&self, name: &str) -> User {
        let email = format!("{}@termoak.test", name.to_lowercase());
        let reg: Value = self
            .http
            .post(format!("{}/api/v1/auth/register", self.base))
            .json(
                &json!({"email": email, "name": name, "password": "secure-password",
                          "device_name": "Laptop", "platform": "desktop-linux"}),
            )
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        User {
            token: reg["tokens"]["access_token"]
                .as_str()
                .unwrap_or_else(|| panic!("register {name}: {reg}"))
                .into(),
            id: reg["user"]["id"].as_str().unwrap().into(),
            email,
        }
    }

    /// Creates a shared vault.
    pub async fn vault(&self, owner: &User, name: &str) -> String {
        let v = self
            .ok("/api/v1/vaults", owner, json!({"name": name}))
            .await;
        v["id"].as_str().unwrap().into()
    }

    /// Shares a vault with a user; returns the grant id.
    pub async fn share(&self, owner: &User, vault: &str, with: &User, role: &str) -> String {
        let m = self
            .ok(
                &format!("/api/v1/vaults/{vault}/members"),
                owner,
                json!({"email": with.email, "role": role}),
            )
            .await;
        m["id"].as_str().unwrap().into()
    }

    /// Creates a host with a password in a vault.
    pub async fn host(&self, u: &User, vault: &str, label: &str, password: &str) -> String {
        let h = self
            .ok(
                "/api/v1/hosts",
                u,
                json!({"label": label, "address": format!("{label}.example.com"),
                       "settings": {"username": "root"},
                       "vault_id": vault, "secret": {"password": password}}),
            )
            .await;
        h["id"].as_str().unwrap().into()
    }

    pub async fn events(&self, u: &User) -> Ws {
        let url = format!("{}/api/v1/events/ws", self.base.replace("http://", "ws://"));
        let mut req =
            tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(url)
                .unwrap();
        req.headers_mut().insert(
            "authorization",
            format!("Bearer {}", u.token).parse().unwrap(),
        );
        let (mut ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
        wait_event(&mut ws, |v| v["type"] == "hello").await;
        ws
    }
}

pub type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Waits for a JSON message matching `pred` (10 s).
pub async fn wait_event(ws: &mut Ws, pred: impl Fn(&Value) -> bool) -> Value {
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(Ok(msg)) = ws.next().await {
            if let WsMsg::Text(t) = msg {
                let v: Value = serde_json::from_str(&t).unwrap();
                if pred(&v) {
                    return v;
                }
            }
        }
        panic!("the WebSocket closed");
    })
    .await
    .expect("the expected event never arrived")
}
