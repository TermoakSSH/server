//! Push notifications against mock APNs and FCM: token registration,
//! test notification, notices for teams and shared sessions, expired tokens
//! and signed JWTs.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use parking_lot::Mutex;
use reqwest::Method;
use serde_json::{Value, json};
use termoak_server::config::{ApnsSection, FcmSection, ServerConfig};
use termoak_server::{build_state, routes};

/// What the mock APNs/FCM receives.
#[derive(Default)]
struct Mock {
    apns: Mutex<Vec<(String, HeaderMap, Value)>>,
    fcm: Mutex<Vec<Value>>,
    oauth: Mutex<Vec<String>>,
}

async fn apns(
    State(m): State<Arc<Mock>>,
    Path(token): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    m.apns.lock().push((token.clone(), headers, body));
    if token == "expired" {
        return (StatusCode::GONE, Json(json!({"reason": "Unregistered"})));
    }
    (StatusCode::OK, Json(json!({})))
}

async fn oauth(State(m): State<Arc<Mock>>, body: String) -> Json<Value> {
    m.oauth.lock().push(body);
    Json(json!({"access_token": "ya29.test", "expires_in": 3600}))
}

async fn fcm(
    State(m): State<Arc<Mock>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    assert_eq!(headers["authorization"], "Bearer ya29.test");
    m.fcm.lock().push(body.clone());
    if body["message"]["token"] == "fcm-expired" {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": {"details": [{"errorCode": "UNREGISTERED"}]}})),
        );
    }
    (
        StatusCode::OK,
        Json(json!({"name": "projects/demo/messages/1"})),
    )
}

async fn start_mock() -> (String, Arc<Mock>) {
    let mock = Arc::new(Mock::default());
    let app = Router::new()
        .route("/3/device/{token}", post(apns))
        .route("/token", post(oauth))
        .route("/v1/projects/demo/messages:send", post(fcm))
        .with_state(mock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), mock)
}

fn pem(label: &str, der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

struct Srv {
    base: String,
    http: reqwest::Client,
    _dir: tempfile::TempDir,
}

impl Srv {
    async fn call(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut req = self.http.request(method, format!("{}{path}", self.base));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.unwrap();
        let s = resp.status();
        (
            StatusCode::from_u16(s.as_u16()).unwrap(),
            resp.json().await.unwrap_or(Value::Null),
        )
    }

    async fn login(&self, email: &str, device: &str) -> String {
        let (s, v) = self
            .call(
                Method::POST,
                "/api/v1/auth/login",
                None,
                Some(json!({"email": email, "password": "secure-password", "device_name": device, "platform": "ios"})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        v["tokens"]["access_token"].as_str().unwrap().to_string()
    }
}

/// Waits until a condition on what was received holds.
async fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..100 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("never arrived: {what}");
}

#[tokio::test]
async fn push_notifications() {
    let (mock_url, mock) = start_mock().await;
    let dir = tempfile::tempdir().unwrap();

    // APNs .p8 key (EC P-256) and Firebase service account.
    let rng = ring::rand::SystemRandom::new();
    let p8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &rng,
    )
    .unwrap();
    let key_path = dir.path().join("AuthKey.p8");
    std::fs::write(&key_path, pem("PRIVATE KEY", p8.as_ref())).unwrap();
    let apns_key = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        p8.as_ref(),
        &rng,
    )
    .unwrap();
    let account = json!({
        "type": "service_account",
        "project_id": "demo",
        "private_key_id": "key-1",
        "private_key": include_str!("data/fcm-test-key.pem"),
        "client_email": "push@demo.iam.gserviceaccount.com",
        "token_uri": format!("{mock_url}/token"),
    });
    let account_path = dir.path().join("firebase.json");
    std::fs::write(&account_path, account.to_string()).unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut config = ServerConfig::default();
    config.server.listen = addr;
    config.server.data_dir = dir.path().join("data");
    config.server.registration = termoak_server::config::Registration::Open;
    config.push.apns = Some(ApnsSection {
        key_path: Some(key_path),
        key_id: "KEYID12345".into(),
        team_id: "TEAM123456".into(),
        topic: "com.termoak".into(),
        endpoint: Some(mock_url.clone()),
        sandbox_endpoint: Some(mock_url.clone()),
    });
    config.push.fcm = Some(FcmSection {
        service_account_path: Some(account_path),
        endpoint: Some(mock_url.clone()),
    });
    let state = build_state(config).await.unwrap();
    let app = routes::router(state);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let srv = Srv {
        base: format!("http://{addr}"),
        http: reqwest::Client::new(),
        _dir: dir,
    };

    let (_, info) = srv.call(Method::GET, "/api/v1/info", None, None).await;
    assert_eq!(info["features"]["push"], json!({"apns": true, "fcm": true}));

    // Ana (iPhone and Android) and Beto.
    for email in ["ana@example.test", "beto@example.test"] {
        let (s, v) = srv
            .call(
                Method::POST,
                "/api/v1/auth/register",
                None,
                Some(json!({"email": email, "password": "secure-password", "platform": "web"})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }
    let ana_ios = srv.login("ana@example.test", "iPhone").await;
    let ana_android = srv.login("ana@example.test", "Pixel").await;
    let beto = srv.login("beto@example.test", "Laptop").await;

    // Without a registered token, the test reports an error.
    let (s, _) = srv
        .call(Method::POST, "/api/v1/push/test", Some(&ana_ios), None)
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, v) = srv
        .call(
            Method::POST,
            "/api/v1/push/register",
            Some(&ana_ios),
            Some(json!({"platform": "apns", "token": "tok-ios", "sandbox": true})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["server_enabled"], true);
    let (s, _) = srv
        .call(
            Method::POST,
            "/api/v1/push/register",
            Some(&ana_android),
            Some(json!({"platform": "fcm", "token": "tok-android"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = srv
        .call(
            Method::POST,
            "/api/v1/push/register",
            Some(&ana_android),
            Some(json!({"platform": "other", "token": "x"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Test notification to the iPhone: ES256 JWT with the key and the team.
    let (s, v) = srv
        .call(Method::POST, "/api/v1/push/test", Some(&ana_ios), None)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    {
        let got = mock.apns.lock();
        let (token, headers, body) = got.last().unwrap();
        assert_eq!(token, "tok-ios");
        assert_eq!(headers["apns-topic"], "com.termoak");
        assert_eq!(headers["apns-push-type"], "alert");
        assert_eq!(body["termoak"]["type"], "test");
        let jwt = headers["authorization"]
            .to_str()
            .unwrap()
            .strip_prefix("bearer ")
            .or_else(|| {
                headers["authorization"]
                    .to_str()
                    .unwrap()
                    .strip_prefix("Bearer ")
            })
            .unwrap()
            .to_string();
        let parts: Vec<&str> = jwt.split('.').collect();
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KEYID12345");
        assert_eq!(claims["iss"], "TEAM123456");
        use ring::signature::KeyPair;
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_FIXED,
            apns_key.public_key().as_ref(),
        )
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
        )
        .expect("valid ES256 signature");
    }

    // Beto adds Ana to a team: notice on both her devices.
    let (_, team) = srv
        .call(
            Method::POST,
            "/api/v1/teams",
            Some(&beto),
            Some(json!({"name": "Operations"})),
        )
        .await;
    let team_id = team["id"].as_str().unwrap().to_string();
    let (s, _) = srv
        .call(
            Method::POST,
            &format!("/api/v1/teams/{team_id}/members"),
            Some(&beto),
            Some(json!({"email": "ana@example.test"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    wait_for("team notice via APNs", || {
        mock.apns
            .lock()
            .iter()
            .any(|(_, _, b)| b["termoak"]["type"] == "team_added")
    })
    .await;
    wait_for("team notice via FCM", || {
        mock.fcm
            .lock()
            .iter()
            .any(|b| b["message"]["data"]["type"] == "team_added")
    })
    .await;
    {
        let fcm = mock.fcm.lock();
        let msg = &fcm.last().unwrap()["message"];
        assert_eq!(msg["token"], "tok-android");
        assert_eq!(msg["data"]["team_id"], team_id);
        assert_eq!(msg["android"]["priority"], "HIGH");
        // Generic text by default (no names or titles).
        assert_eq!(
            msg["notification"]["body"],
            "You have been added to a team."
        );
        // The OAuth token was requested with an RS256 JWT from the service account.
        let oauth = mock.oauth.lock();
        let form = oauth.first().expect("OAuth token request");
        assert!(form.contains("grant-type%3Ajwt-bearer"));
        let assertion = form.split("assertion=").nth(1).unwrap();
        let header: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(assertion.split('.').next().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["kid"], "key-1");
    }

    // Beto shares a session with Ana.
    let (s, relay) = srv
        .call(
            Method::POST,
            "/api/v1/relay",
            Some(&beto),
            Some(json!({"title": "Beto's laptop"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{relay}");
    let rid = relay["session"]["id"].as_str().unwrap().to_string();
    let (s, v) = srv
        .call(
            Method::POST,
            &format!("/api/v1/sessions/{rid}/shares"),
            Some(&beto),
            Some(json!({"email": "ana@example.test", "permission": "view"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    wait_for("shared session notice", || {
        mock.apns.lock().iter().any(|(_, _, b)| {
            b["termoak"]["type"] == "session_shared" && b["termoak"]["session_id"] == rid
        })
    })
    .await;

    // An expired token is forgotten.
    let ana_old = srv.login("ana@example.test", "Old iPad").await;
    let (s, _) = srv
        .call(
            Method::POST,
            "/api/v1/push/register",
            Some(&ana_old),
            Some(json!({"platform": "apns", "token": "expired"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = srv
        .call(Method::POST, "/api/v1/push/test", Some(&ana_old), None)
        .await;
    assert_eq!(s, StatusCode::BAD_GATEWAY);
    let (_, devices) = srv
        .call(Method::GET, "/api/v1/devices", Some(&ana_ios), None)
        .await;
    let find = |name: &str| -> Value {
        devices["devices"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["name"] == name)
            .unwrap()
            .clone()
    };
    assert_eq!(find("Old iPad")["push"], Value::Null);
    assert_eq!(find("iPhone")["push"], "apns");
    assert_eq!(find("Pixel")["push"], "fcm");

    // Turn off on one device.
    let (s, _) = srv
        .call(
            Method::DELETE,
            "/api/v1/push/register",
            Some(&ana_android),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (_, devices) = srv
        .call(Method::GET, "/api/v1/devices", Some(&ana_ios), None)
        .await;
    let pixel = devices["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "Pixel")
        .unwrap()
        .clone();
    assert_eq!(pixel["push"], Value::Null);
}
