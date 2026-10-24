//! Push without Firebase (docs-next/PUSH.md): Web Push to a mock push
//! service (like a UnifiedPush distributor's server, e.g. ntfy) that
//! decrypts every message with the device's keys. Registration and its
//! checks, VAPID, preferences, quiet while the events socket is open,
//! 404/410 cleanup, rate limits and the security key wake-up (a phone that
//! connects when the push arrives and signs the waiting request).

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::srv::{Srv, User};
use parking_lot::Mutex;
use serde_json::{Value, json};
use termoak_core::webpush::ReceiverKeys;

/// A message the mock push service got for one endpoint.
#[derive(Clone)]
struct Got {
    endpoint: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

type Hook = Arc<dyn Fn(&Got) + Send + Sync>;

#[derive(Default)]
struct PushService {
    got: Mutex<Vec<Got>>,
    /// Endpoints that answer 410 Gone (unsubscribed).
    gone: Mutex<Vec<String>>,
    /// Called for every message (the "phone").
    hook: Mutex<Option<Hook>>,
}

async fn receive(
    State(m): State<Arc<PushService>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> StatusCode {
    let got = Got {
        endpoint: id.clone(),
        headers,
        body: body.to_vec(),
    };
    m.got.lock().push(got.clone());
    let hook = m.hook.lock().clone();
    if let Some(h) = hook {
        h(&got);
    }
    if m.gone.lock().contains(&id) {
        StatusCode::GONE
    } else {
        StatusCode::CREATED
    }
}

async fn start_push_service() -> (String, Arc<PushService>) {
    let m = Arc::new(PushService::default());
    let app = Router::new()
        .route("/up/{id}", post(receive))
        .with_state(m.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), m)
}

/// Signs in another device of `u`.
async fn device(srv: &Srv, u: &User, name: &str) -> User {
    let v: Value = srv
        .http
        .post(format!("{}/api/v1/auth/login", srv.base))
        .json(&json!({"email": u.email, "password": "secure-password",
                      "device_name": name, "platform": "android"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    User {
        token: v["tokens"]["access_token"].as_str().unwrap().into(),
        ..u.clone()
    }
}

/// Registers a Web Push endpoint for the device; returns its keys.
async fn register(srv: &Srv, d: &User, push: &str, id: &str) -> ReceiverKeys {
    let keys = ReceiverKeys::generate();
    let r = srv
        .post(
            "/api/v1/push/register",
            d,
            json!({"platform": "webpush", "endpoint": format!("{push}/up/{id}"),
                   "keys": {"p256dh": keys.p256dh(), "auth": keys.auth()}}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["server_enabled"], true);
    keys
}

fn messages_for(m: &PushService, id: &str) -> Vec<Got> {
    m.got
        .lock()
        .iter()
        .filter(|g| g.endpoint == id)
        .cloned()
        .collect()
}

fn decrypt(keys: &ReceiverKeys, g: &Got) -> Value {
    assert_eq!(g.headers["content-encoding"], "aes128gcm");
    serde_json::from_slice(&keys.decrypt(&g.body).expect("decrypts")).unwrap()
}

async fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("never happened: {what}");
}

async fn add_to_team(srv: &Srv, owner: &User, member: &User, name: &str) {
    let team = srv.ok("/api/v1/teams", owner, json!({"name": name})).await;
    let id = team["id"].as_str().unwrap();
    srv.ok(
        &format!("/api/v1/teams/{id}/members"),
        owner,
        json!({"email": member.email}),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn web_push_end_to_end() {
    let (push, m) = start_push_service().await;
    let srv = Srv::start_with(|c| {
        c.push.webpush.allowed_endpoints = vec![format!("{push}/up/")];
        c.push.max_per_minute = 6;
    })
    .await;

    // /info: Web Push on, with the VAPID public key; APNs and FCM off.
    let info: Value = srv
        .http
        .get(format!("{}/api/v1/info", srv.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let features = &info["features"]["push"];
    assert_eq!(features["webpush"], true);
    assert_eq!(features["apns"], false);
    let vapid = features["vapid_public_key"].as_str().unwrap().to_string();
    assert_eq!(URL_SAFE_NO_PAD.decode(&vapid).unwrap().len(), 65);

    let ana = srv.user("Ana").await;
    let bob = srv.user("Bob").await;
    let phone = device(&srv, &ana, "Pixel").await;
    let tablet = device(&srv, &ana, "Tab").await;

    // Endpoints the server may not call, and broken keys.
    let k = ReceiverKeys::generate();
    for (endpoint, code) in [
        ("https://127.0.0.1/up/x", "push_endpoint_not_allowed"),
        ("http://ntfy.sh/up/x", "push_endpoint_not_allowed"),
        (
            "https://169.254.169.254/latest",
            "push_endpoint_not_allowed",
        ),
        (
            &format!("{push}/other/x") as &str,
            "push_endpoint_not_allowed",
        ),
    ] {
        let r = srv
            .post(
                "/api/v1/push/register",
                &phone,
                json!({"platform": "webpush", "endpoint": endpoint,
                       "keys": {"p256dh": k.p256dh(), "auth": k.auth()}}),
            )
            .await;
        assert_eq!((r.status, r.code()), (400, code), "{endpoint}: {}", r.body);
    }
    let r = srv
        .post(
            "/api/v1/push/register",
            &phone,
            json!({"platform": "webpush", "endpoint": format!("{push}/up/x"),
                   "keys": {"p256dh": k.auth(), "auth": k.auth()}}),
        )
        .await;
    assert_eq!(r.status, 400, "{}", r.body);
    let r = srv
        .post(
            "/api/v1/push/register",
            &phone,
            json!({"platform": "webpush", "endpoint": format!("{push}/up/x")}),
        )
        .await;
    assert_eq!(r.status, 400, "{}", r.body);

    // Status before and after registering.
    let s = srv.get("/api/v1/push", &phone).await.body;
    assert_eq!(s["registered"], false);
    assert_eq!(s["server"]["webpush"], true);
    assert_eq!(s["server"]["vapid_public_key"], vapid);
    assert!(
        s["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k == "security_key_request")
    );
    let phone_keys = register(&srv, &phone, &push, "phone").await;
    let tablet_keys = register(&srv, &tablet, &push, "tablet").await;
    let s = srv.get("/api/v1/push", &phone).await.body;
    assert_eq!(s["registered"], true);
    assert_eq!(s["platform"], "webpush");
    assert_eq!(s["endpoint"], format!("{push}/up/phone"));
    assert_eq!(s["preferences"]["kinds"]["ai_approval"], true);
    assert_eq!(s["preferences"]["when_online"], false);
    let devices = srv.get("/api/v1/devices", &ana).await.body;
    let pixel = devices["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "Pixel")
        .unwrap()
        .clone();
    assert_eq!(pixel["push"], "webpush");

    // Test notification: encrypted for the phone, VAPID for the service's origin.
    let r = srv.post("/api/v1/push/test", &phone, json!({})).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let got = messages_for(&m, "phone");
    assert_eq!(got.len(), 1);
    let g = &got[0];
    let msg = decrypt(&phone_keys, g);
    assert_eq!(msg["type"], "test");
    assert_eq!(msg["v"], 1);
    assert_eq!(msg["body"], "Notifications work on this device.");
    assert_eq!(msg["server"], info["instance_id"]);
    assert_eq!(msg["user"], phone.id);
    assert!(tablet_keys.decrypt(&g.body).is_err());
    assert_eq!(g.headers["ttl"], "300");
    assert_eq!(g.headers["urgency"], "high");
    assert_eq!(g.headers["topic"].len(), 32);
    let auth = g.headers["authorization"].to_str().unwrap();
    let rest = auth.strip_prefix("vapid t=").unwrap();
    let (jwt, k) = rest.split_once(", k=").unwrap();
    assert_eq!(k, vapid);
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["aud"], push);
    assert!(claims["sub"].as_str().unwrap().starts_with("mailto:"));
    {
        let parts: Vec<&str> = jwt.split('.').collect();
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_FIXED,
            URL_SAFE_NO_PAD.decode(k).unwrap(),
        )
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
        )
        .expect("VAPID signature");
    }

    // An event: both devices (generic text, ids only).
    add_to_team(&srv, &bob, &ana, "Ops").await;
    wait_for("team_added on both", || {
        messages_for(&m, "phone").len() == 2 && messages_for(&m, "tablet").len() == 1
    })
    .await;
    let msg = decrypt(&phone_keys, messages_for(&m, "phone").last().unwrap());
    assert_eq!(msg["type"], "team_added");
    assert_eq!(msg["body"], "You have been added to a team.");
    assert!(msg["data"]["team_id"].is_string());
    assert_eq!(msg["user"], ana.id);
    assert!(
        !msg.to_string().contains("Ops"),
        "no team name without detailed: {msg}"
    );

    // Preferences: the tablet turns team notices off; unknown kinds refused.
    let r = srv
        .put(
            "/api/v1/push/preferences",
            &tablet,
            json!({"kinds": {"team_added": false}}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["preferences"]["kinds"]["team_added"], false);
    assert_eq!(r.body["preferences"]["kinds"]["ai_approval"], true);
    let r = srv
        .put(
            "/api/v1/push/preferences",
            &tablet,
            json!({"kinds": {"nope": true}}),
        )
        .await;
    assert_eq!(r.status, 400);
    // The phone's app is open (events socket): quiet there.
    let ws = srv.events(&phone).await;
    add_to_team(&srv, &bob, &ana, "Dev").await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(messages_for(&m, "phone").len(), 2, "quiet while online");
    assert_eq!(messages_for(&m, "tablet").len(), 1, "turned off");
    // ...unless the device asks for notifications while online.
    let r = srv
        .put(
            "/api/v1/push/preferences",
            &phone,
            json!({"kinds": {}, "when_online": true}),
        )
        .await;
    assert_eq!(r.status, 200);
    add_to_team(&srv, &bob, &ana, "QA").await;
    wait_for("online but asked for it", || {
        messages_for(&m, "phone").len() == 3
    })
    .await;
    drop(ws);

    // Rate limit: at most 6 a minute per device (2 used: tests have their
    // own limit): 4 of these 5 arrive.
    for i in 0..5 {
        add_to_team(&srv, &bob, &ana, &format!("T{i}")).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(messages_for(&m, "phone").len(), 7);
    for _ in 0..4 {
        srv.post("/api/v1/push/test", &phone, json!({})).await;
    }
    let r = srv.post("/api/v1/push/test", &phone, json!({})).await;
    assert_eq!((r.status, r.code()), (429, "rate_limited"));

    // 410 Gone: the registration is forgotten.
    m.gone.lock().push("tablet".into());
    let r = srv.post("/api/v1/push/test", &tablet, json!({})).await;
    assert_eq!((r.status, r.code()), (502, "push_failed"));
    let s = srv.get("/api/v1/push", &tablet).await.body;
    assert_eq!(s["registered"], false);
    // ...but its preferences stay.
    assert_eq!(s["preferences"]["kinds"]["team_added"], false);
    let r = srv.post("/api/v1/push/test", &tablet, json!({})).await;
    assert_eq!((r.status, r.code()), (400, "push_not_registered"));

    // Old apps: APNs/FCM tokens still register (the server has neither).
    let r = srv
        .post(
            "/api/v1/push/register",
            &tablet,
            json!({"platform": "fcm", "token": "tok"}),
        )
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body["server_enabled"], false);
    let r = srv.post("/api/v1/push/test", &tablet, json!({})).await;
    assert_eq!((r.status, r.code()), (400, "push_disabled"));
    let r = srv.delete("/api/v1/push/register", &tablet).await;
    assert_eq!(r.status, 200);
}

/// The VAPID key survives restarts (same data dir) and `[push.webpush]
/// enabled = false` turns Web Push off.
#[tokio::test]
async fn vapid_key_and_disabled_web_push() {
    let srv = Srv::start_with(|c| c.push.webpush.enabled = false).await;
    let info: Value = srv
        .http
        .get(format!("{}/api/v1/info", srv.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["features"]["push"]["webpush"], false);
    assert_eq!(info["features"]["push"]["vapid_public_key"], Value::Null);
    let ana = srv.user("Ana").await;
    let k = ReceiverKeys::generate();
    let r = srv
        .post(
            "/api/v1/push/register",
            &ana,
            json!({"platform": "unifiedpush", "endpoint": "https://ntfy.sh/upX?up=1",
                   "keys": {"p256dh": k.p256dh(), "auth": k.auth()}}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["server_enabled"], false);
    let r = srv.post("/api/v1/push/test", &ana, json!({})).await;
    assert_eq!((r.status, r.code()), (400, "push_disabled"));
}

/// A server connection needs a security key and no device that can sign is
/// online: the phone gets a push, opens its events socket and signs the
/// waiting request; the notification is withdrawn after.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn security_key_wakes_the_phone() {
    use futures::{SinkExt, StreamExt};
    use termoak_ssh::sk::soft::SoftAuthenticator;
    use termoak_ssh::sk::{SecurityKeySigner, SkAlgorithm, SkKeyOptions, wire};
    use tokio_tungstenite::tungstenite::Message as WsMsg;

    let auth = Arc::new(SoftAuthenticator::new());
    let req = termoak_ssh::sk::make_credential_request(&SkKeyOptions {
        algorithm: SkAlgorithm::Ed25519,
        application: None,
        user: None,
        resident: false,
        verify_required: false,
        no_touch_required: false,
        device: Some("YubiKey".into()),
    })
    .unwrap();
    let key =
        termoak_ssh::sk::key_from_credential(&req, &auth.make_credential(&req).unwrap(), "sk")
            .unwrap();
    let Some(sshd) = common::start_sshd_with(std::slice::from_ref(&key.public_openssh)) else {
        eprintln!("sshd not available: test skipped");
        return;
    };
    let (push, m) = start_push_service().await;
    let srv = Srv::start_with(|c| {
        c.push.webpush.allowed_endpoints = vec![format!("{push}/up/")];
        c.sessions.security_key_timeout_secs = 8;
    })
    .await;
    let ana = srv.user("Ana").await;
    let k = srv
        .ok(
            "/api/v1/keys/import",
            &ana,
            json!({"label": "Yubi", "private_key": key.private_openssh}),
        )
        .await;
    let h = srv
        .ok(
            "/api/v1/hosts",
            &ana,
            json!({"label": "box", "address": "127.0.0.1",
                   "settings": {"port": sshd.port, "username": sshd.user, "key_id": k["id"]}}),
        )
        .await;
    let host = h["id"].as_str().unwrap().to_string();
    let test_path = format!("/api/v1/hosts/{host}/test?trust=true");
    let test = || srv.post(&test_path, &ana, json!({}));

    // No push registration: no device at once, as before.
    let r = test().await;
    assert_eq!(r.body["error_code"], "security_key_no_device", "{}", r.body);

    // The phone registers; when the push arrives it connects and signs.
    let phone = device(&srv, &ana, "Pixel").await;
    let keys = Arc::new(register(&srv, &phone, &push, "phone").await);
    let (base, token, a) = (srv.base.clone(), phone.token.clone(), auth.clone());
    let woke = Arc::new(Mutex::new(Vec::<Value>::new()));
    let (w, k2) = (woke.clone(), keys.clone());
    *m.hook.lock() = Some(Arc::new(move |g: &Got| {
        let msg: Value = serde_json::from_slice(&k2.decrypt(&g.body).unwrap()).unwrap();
        w.lock().push(msg.clone());
        if msg["type"] != "security_key_request" {
            return;
        }
        let (base, token, a) = (base.clone(), token.clone(), a.clone());
        tokio::spawn(async move {
            // The user opens the notification a moment later.
            tokio::time::sleep(Duration::from_millis(300)).await;
            let mut ws = common::ws_connect(
                &base,
                "/api/v1/events/ws?features=security_keys",
                Some(&token),
            )
            .await;
            while let Some(Ok(WsMsg::Text(t))) = ws.next().await {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v["type"] == wire::REQUEST {
                    let (id, req) = wire::parse_request(&v).unwrap();
                    assert_eq!(Some(id.as_str()), msg["data"]["request_id"].as_str());
                    let reply = wire::response(&id, &a.sign(req).await);
                    ws.send(WsMsg::Text(reply.to_string().into()))
                        .await
                        .unwrap();
                }
                if v["type"] == wire::DONE {
                    break;
                }
            }
        });
    }));
    let r = test().await;
    assert_eq!(r.body["ok"], true, "{}", r.body);
    wait_for("the withdrawal", || {
        woke.lock().iter().any(|v| v["type"] == "resolved")
    })
    .await;
    let seen = woke.lock().clone();
    let ask = seen
        .iter()
        .find(|v| v["type"] == "security_key_request")
        .unwrap();
    assert_eq!(
        ask["collapse"],
        format!("sk-{}", ask["data"]["request_id"].as_str().unwrap())
    );
    assert!(ask["expires_at"].as_i64().unwrap() > ask["sent_at"].as_i64().unwrap());
    assert!(
        !ask.to_string().contains("127.0.0.1"),
        "no host without detailed: {ask}"
    );
    let resolved = seen.iter().find(|v| v["type"] == "resolved").unwrap();
    assert_eq!(resolved["collapse"], ask["collapse"]);
    let urgent = messages_for(&m, "phone");
    assert_eq!(urgent[0].headers["urgency"], "high");
    assert_eq!(urgent[0].headers["ttl"], "8");

    // Nobody answers the push: a timeout, not "no device".
    *m.hook.lock() = None;
    let started = std::time::Instant::now();
    let r = test().await;
    assert_eq!(r.body["error_code"], "security_key_timeout", "{}", r.body);
    assert!(started.elapsed() >= Duration::from_secs(7));
    // The phone turned security key notifications off: no device at once.
    srv.put(
        "/api/v1/push/preferences",
        &phone,
        json!({"kinds": {"security_key_request": false}}),
    )
    .await;
    let r = test().await;
    assert_eq!(r.body["error_code"], "security_key_no_device", "{}", r.body);
}
