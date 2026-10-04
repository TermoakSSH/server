//! Accounts: two-step verification, per-IP rate limit, invitations, user
//! administration and teams (with a session shared with a team). Does not
//! need sshd: uses relay sessions.

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use reqwest::StatusCode;
use serde_json::{Value, json};
use termoak_server::config::{Registration, ServerConfig};
use termoak_server::{build_state, routes};
use tokio_tungstenite::tungstenite::Message as WsMsg;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

struct Srv {
    base: String,
    http: reqwest::Client,
    _data: tempfile::TempDir,
}

impl Srv {
    async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    /// Starts a server with closed registration, after `configure`.
    async fn start_with(configure: impl FnOnce(&mut ServerConfig)) -> Self {
        let data = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = ServerConfig::default();
        config.server.listen = addr;
        config.server.data_dir = data.path().to_path_buf();
        config.server.registration = Registration::Closed;
        // The tests simulate different IPs with the header.
        config.server.trust_forwarded_for = true;
        configure(&mut config);
        let state = build_state(config).await.unwrap();
        tokio::spawn(async move { axum::serve(listener, routes::router(state)).await.unwrap() });
        Srv {
            base: format!("http://{addr}"),
            http: reqwest::Client::new(),
            _data: data,
        }
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
        ip: &str,
    ) -> (StatusCode, Value) {
        let mut req = self
            .http
            .request(method, format!("{}{path}", self.base))
            .header("x-forwarded-for", format!("10.0.0.1, {ip}"));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status();
        let v = resp.json().await.unwrap_or(Value::Null);
        (status, v)
    }

    async fn post(&self, path: &str, token: Option<&str>, body: Value) -> (StatusCode, Value) {
        self.call(reqwest::Method::POST, path, token, Some(body), "192.0.2.1")
            .await
    }

    async fn get(&self, path: &str, token: &str) -> Value {
        let (s, v) = self
            .call(reqwest::Method::GET, path, Some(token), None, "192.0.2.1")
            .await;
        assert!(s.is_success(), "GET {path}: {s} {v}");
        v
    }

    async fn login(&self, email: &str, password: &str, code: Option<&str>) -> (StatusCode, Value) {
        self.post(
            "/api/v1/auth/login",
            None,
            json!({"email": email, "password": password, "totp_code": code, "platform": "cli"}),
        )
        .await
    }
}

fn totp_now(secret_b32: &str, offset_steps: i64) -> String {
    let secret = data_encoding::BASE32_NOPAD
        .decode(secret_b32.as_bytes())
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let step = (termoak_core::totp::step_at(now) as i64 + offset_steps) as u64;
    format!("{:06}", termoak_core::totp::code_at(&secret, step))
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn ws_connect(base: &str, path: &str, token: &str) -> Ws {
    let url = format!("{}{path}", base.replace("http://", "ws://"));
    let mut req = url.into_client_request().unwrap();
    req.headers_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    tokio_tungstenite::connect_async(req).await.unwrap().0
}

async fn ws_wait_json(ws: &mut Ws, kind: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(Ok(msg)) = ws.next().await {
            if let WsMsg::Text(t) = msg {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v["type"] == kind {
                    return v;
                }
            }
        }
        panic!("WebSocket closed while waiting for {kind}");
    })
    .await
    .unwrap_or_else(|_| panic!("message {kind} never arrived"))
}

#[tokio::test]
async fn accounts_2fa_invites_admin_and_teams() {
    let srv = Srv::start().await;

    // --- First user (administrator) and closed registration ----------------
    let (s, ana) = srv
        .post(
            "/api/v1/auth/register",
            None,
            json!({"email": "ana@example.com", "name": "Ana", "password": "ana-password"}),
        )
        .await;
    assert!(s.is_success(), "{ana}");
    let ana_token = ana["tokens"]["access_token"].as_str().unwrap().to_string();
    assert_eq!(ana["user"]["is_admin"], true);
    let (s, _) = srv
        .post(
            "/api/v1/auth/register",
            None,
            json!({"email": "nobody@example.com", "password": "long-password"}),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let info = srv.get("/api/v1/info", &ana_token).await;
    assert_eq!(info["features"]["teams"], true);

    // --- Team and an invitation that joins it directly ----------------------
    let (s, team) = srv
        .post(
            "/api/v1/teams",
            Some(&ana_token),
            json!({"name": "Operations"}),
        )
        .await;
    assert!(s.is_success(), "{team}");
    let team_id = team["id"].as_str().unwrap().to_string();
    let (s, inv) = srv
        .post(
            "/api/v1/admin/invites",
            Some(&ana_token),
            json!({"email": "bea@example.com", "team_id": team_id}),
        )
        .await;
    assert!(s.is_success(), "{inv}");
    let inv_token = inv["token"].as_str().unwrap().to_string();
    assert!(
        inv["url"]
            .as_str()
            .unwrap()
            .starts_with("termoak://invite?server=")
    );
    let (s, pub_info) = srv
        .call(
            reqwest::Method::GET,
            &format!("/api/v1/invites/{inv_token}"),
            None,
            None,
            "192.0.2.1",
        )
        .await;
    assert!(s.is_success());
    assert_eq!(pub_info["team"], "Operations");
    // It does not work with another email.
    let (s, _) = srv
        .post(
            "/api/v1/auth/register",
            None,
            json!({"email": "other@example.com", "password": "long-password", "invite": inv_token}),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, bea) = srv
        .post(
            "/api/v1/auth/register",
            None,
            json!({"email": "bea@example.com", "name": "Bea", "password": "bea-password", "invite": inv_token}),
        )
        .await;
    assert!(s.is_success(), "{bea}");
    let bea_token = bea["tokens"]["access_token"].as_str().unwrap().to_string();
    let bea_id = bea["user"]["id"].as_str().unwrap().to_string();
    assert_eq!(bea["user"]["is_admin"], false);
    // The invitation cannot be reused.
    let (s, _) = srv
        .post(
            "/api/v1/auth/register",
            None,
            json!({"email": "bea@example.com", "password": "bea-password", "invite": inv_token}),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let teams = srv.get("/api/v1/teams", &bea_token).await;
    assert_eq!(teams[0]["name"], "Operations");
    assert_eq!(teams[0]["role"], "member");

    // --- Ana's relay session shared with the team ---------------------------
    let (s, relay) = srv
        .post(
            "/api/v1/relay",
            Some(&ana_token),
            json!({"title": "Laptop", "cols": 80, "rows": 24}),
        )
        .await;
    assert!(s.is_success(), "{relay}");
    let rid = relay["session"]["id"].as_str().unwrap().to_string();
    let mut host = ws_connect(
        &srv.base,
        relay["host_ws_path"].as_str().unwrap(),
        &ana_token,
    )
    .await;
    ws_wait_json(&mut host, "hello").await;
    let (s, share) = srv
        .post(
            &format!("/api/v1/sessions/{rid}/shares"),
            Some(&ana_token),
            json!({"team_id": team_id, "permission": "view"}),
        )
        .await;
    assert!(s.is_success(), "{share}");
    let list = srv.get("/api/v1/sessions", &bea_token).await;
    assert_eq!(list["shared"].as_array().unwrap().len(), 1, "{list}");
    let mut bea_ws = ws_connect(&srv.base, &format!("/api/v1/sessions/{rid}/ws"), &bea_token).await;
    let hello = ws_wait_json(&mut bea_ws, "hello").await;
    assert_eq!(hello["you"]["access"], "view");
    host.send(WsMsg::Binary(b"hello team\r\n".to_vec().into()))
        .await
        .unwrap();

    // Bea leaves the team: she is kicked out of the session.
    let (s, _) = srv
        .call(
            reqwest::Method::DELETE,
            &format!("/api/v1/teams/{team_id}/members/{bea_id}"),
            Some(&bea_token),
            None,
            "192.0.2.1",
        )
        .await;
    assert!(s.is_success());
    let err = ws_wait_json(&mut bea_ws, "error").await;
    assert!(err["message"].as_str().unwrap().contains("access"), "{err}");
    let list = srv.get("/api/v1/sessions", &bea_token).await;
    assert!(list["shared"].as_array().unwrap().is_empty());
    // The last owner cannot leave.
    let ana_id = ana["user"]["id"].as_str().unwrap();
    let (s, _) = srv
        .call(
            reqwest::Method::DELETE,
            &format!("/api/v1/teams/{team_id}/members/{ana_id}"),
            Some(&ana_token),
            None,
            "192.0.2.1",
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    // A regular member cannot manage the team.
    srv.post(
        &format!("/api/v1/teams/{team_id}/members"),
        Some(&ana_token),
        json!({"email": "bea@example.com"}),
    )
    .await;
    let (s, _) = srv
        .post(
            &format!("/api/v1/teams/{team_id}/members"),
            Some(&bea_token),
            json!({"email": "ana@example.com", "role": "member"}),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // --- Bea's two-step verification -----------------------------------------
    let (s, setup) = srv
        .post("/api/v1/me/2fa/setup", Some(&bea_token), json!({}))
        .await;
    assert!(s.is_success(), "{setup}");
    let secret = setup["secret"].as_str().unwrap().to_string();
    assert!(
        setup["otpauth_url"]
            .as_str()
            .unwrap()
            .contains("bea%40example.com")
    );
    let (s, enabled) = srv
        .post(
            "/api/v1/me/2fa/enable",
            Some(&bea_token),
            json!({"code": totp_now(&secret, -1)}),
        )
        .await;
    assert!(s.is_success(), "{enabled}");
    let recovery: Vec<String> = serde_json::from_value(enabled["recovery_codes"].clone()).unwrap();
    assert_eq!(recovery.len(), 10);

    // No code: 401 totp_required. Wrong code: 401 totp_invalid.
    let (s, v) = srv.login("bea@example.com", "bea-password", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["error"]["code"], "totp_required", "{v}");
    let (s, v) = srv
        .login("bea@example.com", "bea-password", Some("000000"))
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["error"]["code"], "totp_invalid");
    let (s, v) = srv
        .login(
            "bea@example.com",
            "bea-password",
            Some(&totp_now(&secret, 0)),
        )
        .await;
    assert!(s.is_success(), "{v}");
    assert_eq!(v["user"]["totp_enabled"], true);
    let (s, _) = srv
        .login("bea@example.com", "bea-password", Some(&recovery[0]))
        .await;
    assert!(s.is_success());
    let (s, _) = srv
        .login("bea@example.com", "bea-password", Some(&recovery[0]))
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "a recovery code is used up");

    // The administrator removes her 2FA and sets a new password.
    let (s, _) = srv
        .post(
            &format!("/api/v1/admin/users/{bea_id}/2fa/reset"),
            Some(&ana_token),
            json!({}),
        )
        .await;
    assert!(s.is_success());
    let devices = srv
        .get(&format!("/api/v1/admin/users/{bea_id}/devices"), &ana_token)
        .await;
    assert!(!devices.as_array().unwrap().is_empty());
    let (s, reset) = srv
        .post(
            &format!("/api/v1/admin/users/{bea_id}/password"),
            Some(&ana_token),
            json!({"password": "new-password"}),
        )
        .await;
    assert!(s.is_success(), "{reset}");
    // Her open sessions are closed.
    let (s, _) = srv
        .call(
            reqwest::Method::GET,
            "/api/v1/me",
            Some(&bea_token),
            None,
            "192.0.2.1",
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = srv.login("bea@example.com", "new-password", None).await;
    assert!(s.is_success(), "no 2FA after the reset");
    // Administrators only.
    let (s, _) = srv
        .call(
            reqwest::Method::GET,
            "/api/v1/admin/audit",
            Some(&bea_token),
            None,
            "192.0.2.1",
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED); // her token is no longer valid
    let audit = srv.get("/api/v1/admin/audit?limit=200", &ana_token).await;
    let actions: Vec<&str> = audit
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["action"].as_str())
        .collect();
    for a in [
        "admin.invite_created",
        "team.created",
        "session.share",
        "team.left",
        "auth.2fa_enabled",
        "admin.2fa_reset",
        "admin.password_reset",
    ] {
        assert!(actions.contains(&a), "missing {a} in {actions:?}");
    }

    // --- Per-IP limit ---------------------------------------------------------
    let attacker = "203.0.113.9";
    for i in 0..30 {
        let (s, _) = srv
            .call(
                reqwest::Method::POST,
                "/api/v1/auth/login",
                None,
                Some(json!({"email": format!("x{i}@example.com"), "password": "nope"})),
                attacker,
            )
            .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
    let (s, v) = srv
        .call(
            reqwest::Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({"email": "ana@example.com", "password": "ana-password"})),
            attacker,
        )
        .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{v}");
    // From another IP, Ana signs in without trouble.
    let (s, _) = srv.login("ana@example.com", "ana-password", None).await;
    assert!(s.is_success());
}

#[tokio::test]
async fn registration_records_terms_acceptance() {
    let srv = Srv::start_with(|c| {
        c.server.registration = Registration::Open;
        c.web.terms_url = Some("https://example.com/terms".into());
        c.web.privacy_url = Some("https://example.com/privacy".into());
    })
    .await;
    let register = |email: &str, extra: Value| {
        let mut body =
            json!({"email": email, "name": "Test", "password": "long-password", "platform": "web"});
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        srv.post("/api/v1/auth/register", None, body)
    };
    let terms_of = |audit: &Value| -> Value {
        audit
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["action"] == "auth.register")
            .map(|e| e["detail"]["terms"].clone())
            .expect("no auth.register entry")
    };

    let (s, info) = srv
        .call(
            reqwest::Method::GET,
            "/api/v1/info",
            None,
            None,
            "192.0.2.1",
        )
        .await;
    assert!(s.is_success());
    assert_eq!(info["terms_url"], "https://example.com/terms");
    assert_eq!(info["privacy_url"], "https://example.com/privacy");

    // Accepted: recorded with the version.
    let (s, ana) = register(
        "ana@example.com",
        json!({"accept_terms": true, "terms_version": "1.0"}),
    )
    .await;
    assert!(s.is_success(), "{ana}");
    let token = ana["tokens"]["access_token"].as_str().unwrap();
    let terms = terms_of(&srv.get("/api/v1/audit", token).await);
    assert_eq!(terms, json!({"accepted": true, "version": "1.0"}));

    // Older apps that do not send it can still sign up; nothing is recorded.
    let (s, bea) = register("bea@example.com", json!({})).await;
    assert!(s.is_success(), "{bea}");
    let token = bea["tokens"]["access_token"].as_str().unwrap();
    assert!(terms_of(&srv.get("/api/v1/audit", token).await).is_null());

    // An explicit refusal or an over-long version is rejected (no account).
    let (s, e) = register("carla@example.com", json!({"accept_terms": false})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(e["error"]["code"], "terms_not_accepted");
    let (s, e) = register(
        "carla@example.com",
        json!({"accept_terms": true, "terms_version": "12345678901234567"}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(e["error"]["code"], "invalid_terms_version");
    let (s, _) = srv.login("carla@example.com", "long-password", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn registration_without_terms_ignores_refusal() {
    // A server without terms has nothing to accept: `false` is not an error.
    let srv = Srv::start_with(|c| c.server.registration = Registration::Open).await;
    let (s, v) = srv
        .post(
            "/api/v1/auth/register",
            None,
            json!({"email": "ana@example.com", "password": "long-password", "accept_terms": false}),
        )
        .await;
    assert!(s.is_success(), "{v}");
}
