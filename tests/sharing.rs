//! Session sharing "multiplayer": waiting room, one driver at a time,
//! participants, kicks, live changes to shares, stop sharing, expiry,
//! re-checking access, relay host (with the client library and a connection
//! that drops), and the owner's notices (events WebSocket and push).
//!
//! Relay sessions need no SSH server; the prompt test uses the system's
//! `sshd` and is skipped without it.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use futures::{SinkExt, StreamExt};
use parking_lot::Mutex;
use reqwest::Method;
use serde_json::{Value, json};
use termoak_server::config::{ApnsSection, Registration, ServerConfig};
use termoak_server::{build_state, routes};
use tokio_tungstenite::tungstenite::Message as WsMsg;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

mod common;
use common::{Ws, ws_wait_json, ws_wait_output};

struct Srv {
    base: String,
    http: reqwest::Client,
    _dir: tempfile::TempDir,
}

impl Srv {
    async fn start(f: impl FnOnce(&mut ServerConfig, &std::path::Path)) -> Srv {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = ServerConfig::default();
        config.server.listen = addr;
        config.server.data_dir = dir.path().join("data");
        config.server.registration = Registration::Open;
        f(&mut config, dir.path());
        let state = build_state(config).await.unwrap();
        tokio::spawn(async move { axum::serve(listener, routes::router(state)).await.unwrap() });
        Srv {
            base: format!("http://{addr}"),
            http: reqwest::Client::new(),
            _dir: dir,
        }
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (u16, Value) {
        let mut req = self.http.request(method, format!("{}{path}", self.base));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.unwrap();
        let s = resp.status().as_u16();
        (s, resp.json().await.unwrap_or(Value::Null))
    }

    async fn ok(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> Value {
        let (s, v) = self.call(method.clone(), path, Some(token), body).await;
        assert!(s < 300, "{method} {path} → {s} {v}");
        v
    }

    /// Registers a user: (access token, user id).
    async fn user(&self, email: &str, name: &str) -> (String, String) {
        let (s, v) = self
            .call(
                Method::POST,
                "/api/v1/auth/register",
                None,
                Some(json!({"email": email, "name": name, "password": "secure-password", "device_name": "Laptop", "platform": "ios"})),
            )
            .await;
        assert_eq!(s, 200, "{v}");
        (
            v["tokens"]["access_token"].as_str().unwrap().to_string(),
            v["user"]["id"].as_str().unwrap().to_string(),
        )
    }

    async fn ws(&self, path: &str, token: Option<&str>) -> Ws {
        common::ws_connect(&self.base, path, token).await
    }

    /// The upgrade is refused: HTTP status.
    async fn ws_refused(&self, path: &str, token: Option<&str>) -> u16 {
        let url = format!("{}{path}", self.base.replace("http://", "ws://"));
        let mut req = url.into_client_request().unwrap();
        if let Some(t) = token {
            req.headers_mut()
                .insert("authorization", format!("Bearer {t}").parse().unwrap());
        }
        match tokio_tungstenite::connect_async(req).await {
            Ok(_) => panic!("the WebSocket of {path} was accepted"),
            Err(tokio_tungstenite::tungstenite::Error::Http(r)) => r.status().as_u16(),
            Err(e) => panic!("{e}"),
        }
    }

    /// A relay session with its host connected (protocol 2): (id, host).
    async fn relay(&self, token: &str, title: &str) -> (String, Ws) {
        let relay = self
            .ok(
                Method::POST,
                "/api/v1/relay",
                token,
                Some(json!({"title": title, "cols": 80, "rows": 24})),
            )
            .await;
        let rid = relay["session"]["id"].as_str().unwrap().to_string();
        let path = format!("{}&proto=2", relay["host_ws_path"].as_str().unwrap());
        let mut host = self.ws(&path, Some(token)).await;
        ws_wait_json(&mut host, "hello").await;
        host.send(WsMsg::Binary(b"host-screen\r\n".to_vec().into()))
            .await
            .unwrap();
        (rid, host)
    }

    async fn share(&self, token: &str, rid: &str, body: Value) -> Value {
        self.ok(
            Method::POST,
            &format!("/api/v1/sessions/{rid}/shares"),
            token,
            Some(body),
        )
        .await
    }

    async fn audit(&self, token: &str) -> Vec<Value> {
        self.ok(Method::GET, "/api/v1/audit?limit=500", token, None)
            .await
            .as_array()
            .unwrap()
            .clone()
    }
}

fn session_ws(rid: &str) -> String {
    format!("/api/v1/sessions/{rid}/ws?proto=2")
}

async fn send(ws: &mut Ws, v: Value) {
    ws.send(WsMsg::Text(v.to_string().into())).await.unwrap();
}

/// Everything that arrives for a while: (JSON messages, binary output).
async fn quiet(ws: &mut Ws, ms: u64) -> (Vec<Value>, String) {
    let mut texts = Vec::new();
    let mut out = String::new();
    let _ = tokio::time::timeout(Duration::from_millis(ms), async {
        while let Some(Ok(msg)) = ws.next().await {
            match msg {
                WsMsg::Text(t) => texts.push(serde_json::from_str(&t).unwrap()),
                WsMsg::Binary(b) => out.push_str(&String::from_utf8_lossy(&b)),
                _ => {}
            }
        }
    })
    .await;
    (texts, out)
}

/// No `error` and no `needle` in the output for a while.
async fn ignored(ws: &mut Ws, needle: &str) {
    let (texts, out) = quiet(ws, 500).await;
    assert!(
        !texts.iter().any(|t| t["type"] == "error"),
        "unexpected error: {texts:?}"
    );
    assert!(!out.contains(needle), "{needle:?} arrived: {out:?}");
}

/// The server sends the socket away with `code`: `error` with the code,
/// then a close frame with the code's number and name.
async fn expect_end(ws: &mut Ws, code: &str, close: u16) {
    let err = ws_wait_json(ws, "error").await;
    assert_eq!(err["code"], code, "{err}");
    let frame = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match ws.next().await {
                Some(Ok(WsMsg::Close(f))) => return f,
                Some(Ok(_)) => {}
                other => panic!("no close frame: {other:?}"),
            }
        }
    })
    .await
    .expect("no close frame");
    let f = frame.expect("close frame without a code");
    assert_eq!(u16::from(f.code), close);
    assert_eq!(f.reason.as_str(), code);
}

/// Waits for a `participants` list that satisfies `pred`.
async fn participants_until(ws: &mut Ws, pred: impl Fn(&[Value]) -> bool) -> Vec<Value> {
    loop {
        let p = ws_wait_json(ws, "participants").await;
        let list = p["participants"].as_array().unwrap().clone();
        if pred(&list) {
            return list;
        }
    }
}

fn url_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn actions(audit: &[Value]) -> Vec<String> {
    audit
        .iter()
        .map(|a| a["action"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn waiting_room_names_and_links() {
    let srv = Srv::start(|_, _| {}).await;
    let (ana, _) = srv.user("ana@t.test", "Ana").await;
    let (cid, _) = srv.user("cid@t.test", "Cid").await;
    let (rid, mut host) = srv.relay(&ana, "Laptop").await;
    let link = srv
        .share(&ana, &rid, json!({"link": true, "permission": "control"}))
        .await;
    // Links ask for approval by default.
    assert_eq!(link["share"]["require_approval"], true);
    assert_eq!(link["share"]["auto_grant"], false);
    let token = link["token"].as_str().unwrap();

    // The link page says nothing about who is inside.
    let (s, join) = srv
        .call(Method::GET, &format!("/api/v1/join/{token}"), None, None)
        .await;
    assert_eq!(s, 200);
    assert_eq!(join["owner"], "Ana");
    assert_eq!(join["require_approval"], true);
    assert_eq!(join["session"]["title"], "Laptop");
    assert_eq!(join["session"]["participants"], 1);
    for leak in ["viewers", "owner_id", "host_id"] {
        assert!(join["session"].get(leak).is_none(), "{leak} in {join}");
    }
    let path = format!("{}&proto=2", join["ws_path"].as_str().unwrap());

    // A guest with a name: cleaned (control characters, spaces) and shown
    // to the owner, who lets them in.
    let mut zoe = srv
        .ws(
            &format!(
                "{path}&guest=zoe-key-0001&name={}",
                url_encode("  Zoë\u{7}   the   tester ")
            ),
            None,
        )
        .await;
    let waiting = ws_wait_json(&mut zoe, "waiting").await;
    assert_eq!(waiting["name"], "Zoë the tester");
    assert_eq!(waiting["session"]["owner"], "Ana");
    let req = ws_wait_json(&mut host, "join_request").await;
    assert_eq!(req["participant"]["name"], "Zoë the tester");
    assert_eq!(req["participant"]["kind"], "guest");
    assert_eq!(req["participant"]["waiting"], true);
    let zoe_id = req["participant"]["id"].clone();
    send(
        &mut host,
        json!({"type": "join_allow", "participant": zoe_id}),
    )
    .await;
    let hello = ws_wait_json(&mut zoe, "hello").await;
    assert_eq!(hello["you"]["kind"], "guest");
    assert_eq!(hello["you"]["participant"], zoe_id);
    assert_eq!(hello["you"]["can_write"], false);
    ws_wait_output(&mut zoe, "host-screen").await;
    // Guests see neither user ids nor share ids.
    for p in hello["session"]["participants"].as_array().unwrap() {
        assert!(
            p.get("user_id").is_none() && p.get("share_id").is_none(),
            "{p}"
        );
    }
    for v in hello["session"]["viewers"].as_array().unwrap() {
        assert!(
            v.get("user_id").is_none() && v.get("share_id").is_none(),
            "{v}"
        );
    }

    // Without a name: "Guest 1"; the owner says no.
    let mut anon = srv.ws(&path, None).await;
    assert_eq!(ws_wait_json(&mut anon, "waiting").await["name"], "Guest 1");
    let req = loop {
        let r = ws_wait_json(&mut host, "join_request").await;
        if r["participant"]["name"] == "Guest 1" {
            break r;
        }
    };
    send(
        &mut host,
        json!({"type": "join_deny", "participant": req["participant"]["id"]}),
    )
    .await;
    expect_end(&mut anon, "join_denied", 4005).await;

    // A signed-in user can use the link too: they join with their name.
    let mut c = srv.ws(&path, Some(&cid)).await;
    assert_eq!(ws_wait_json(&mut c, "waiting").await["name"], "Cid");
    let req = loop {
        let r = ws_wait_json(&mut host, "join_request").await;
        if r["participant"]["name"] == "Cid" {
            break r;
        }
    };
    assert_eq!(req["participant"]["kind"], "user");
    assert!(
        req["participant"]["user_id"].is_string(),
        "the owner sees user ids"
    );
    send(
        &mut host,
        json!({"type": "join_allow", "participant": req["participant"]["id"]}),
    )
    .await;
    let hello = ws_wait_json(&mut c, "hello").await;
    assert_eq!(hello["you"]["kind"], "user");
    assert_eq!(hello["you"]["access"], "control");

    // A guest that reconnects with the same key is the same participant
    // and does not wait again.
    drop(zoe);
    let mut zoe = srv
        .ws(&format!("{path}&guest=zoe-key-0001&name=Zoe"), None)
        .await;
    let hello = ws_wait_json(&mut zoe, "hello").await;
    assert_eq!(hello["you"]["participant"], zoe_id);

    // The owner's view: three people, with user ids for users only.
    let view = srv
        .ok(Method::GET, &format!("/api/v1/sessions/{rid}"), &ana, None)
        .await;
    let names: Vec<&str> = view["participants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 3, "{view}");
    assert!(names.contains(&"Ana") && names.contains(&"Cid") && names.contains(&"Zoë the tester"));
    let (_, join) = srv
        .call(Method::GET, &format!("/api/v1/join/{token}"), None, None)
        .await;
    assert_eq!(join["session"]["participants"], 3);

    let audit = srv.audit(&ana).await;
    let acts = actions(&audit);
    for a in [
        "session.join_requested",
        "session.join_allowed",
        "session.join_denied",
        "session.join",
    ] {
        assert!(acts.contains(&a.to_string()), "{a} missing from {acts:?}");
    }
    // The guest's join is audited once with their name (the reconnect is not
    // a new join).
    let zoe_joins = audit
        .iter()
        .filter(|a| a["action"] == "session.join" && a["detail"]["name"] == "Zoë the tester")
        .count();
    assert_eq!(zoe_joins, 1, "{audit:?}");
    assert!(audit.iter().any(|a| a["action"] == "session.join_requested"
        && a["actor"].as_str().unwrap().starts_with("guest:")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_driver_at_a_time() {
    let srv = Srv::start(|_, _| {}).await;
    let (ana, _) = srv.user("ana@t.test", "Ana").await;
    let (bea, _) = srv.user("bea@t.test", "Bea").await;
    let (cid, _) = srv.user("cid@t.test", "Cid").await;
    let (dan, _) = srv.user("dan@t.test", "Dan").await;
    let (rid, mut host) = srv.relay(&ana, "Laptop").await;
    let bea_share = srv
        .share(
            &ana,
            &rid,
            json!({"email": "bea@t.test", "permission": "control"}),
        )
        .await;
    // Users and teams do not wait by default.
    assert_eq!(bea_share["share"]["require_approval"], false);
    let bea_share = bea_share["share"]["id"].as_str().unwrap().to_string();
    srv.share(
        &ana,
        &rid,
        json!({"email": "cid@t.test", "permission": "view"}),
    )
    .await;

    let mut b = srv.ws(&session_ws(&rid), Some(&bea)).await;
    let hello = ws_wait_json(&mut b, "hello").await;
    assert_eq!(hello["you"]["access"], "control");
    assert_eq!(hello["you"]["can_write"], false);
    assert_eq!(hello["session"]["driver"], Value::Null);
    let mut c = srv.ws(&session_ws(&rid), Some(&cid)).await;
    assert_eq!(ws_wait_json(&mut c, "hello").await["you"]["access"], "view");

    // Everyone joins read-only: input and resizes are dropped, without errors.
    b.send(WsMsg::Binary(b"bea-early".to_vec().into()))
        .await
        .unwrap();
    send(&mut b, json!({"type": "resize", "cols": 100, "rows": 30})).await;
    c.send(WsMsg::Binary(b"cid-typed".to_vec().into()))
        .await
        .unwrap();
    send(&mut c, json!({"type": "resize", "cols": 90, "rows": 20})).await;
    let (texts, out) = quiet(&mut host, 500).await;
    assert!(!out.contains("early") && !out.contains("cid"), "{out:?}");
    assert!(!texts.iter().any(|t| t["type"] == "resize"), "{texts:?}");
    ignored(&mut b, "nothing").await;
    ignored(&mut c, "nothing").await;

    // A view-only invitation cannot ask for the keyboard (the socket stays).
    send(&mut c, json!({"type": "control_request"})).await;
    assert_eq!(ws_wait_json(&mut c, "error").await["code"], "forbidden");
    send(&mut c, json!({"type": "ping"})).await;
    ws_wait_json(&mut c, "pong").await;

    // Bea asks; the owner grants it.
    send(&mut b, json!({"type": "control_request"})).await;
    let req = ws_wait_json(&mut host, "control_request").await;
    assert_eq!(req["participant"]["name"], "Bea");
    let bea_id = req["participant"]["id"].clone();
    send(
        &mut host,
        json!({"type": "control_grant", "participant": bea_id}),
    )
    .await;
    let ctl = ws_wait_json(&mut b, "control").await;
    assert_eq!(
        (ctl["can_write"].clone(), ctl["driver"].clone()),
        (json!(true), bea_id.clone())
    );
    assert_eq!(ctl["driver_name"], "Bea");
    let ctl = ws_wait_json(&mut c, "control").await;
    assert_eq!(ctl["can_write"], false);
    assert_eq!(ctl["driver"], bea_id);
    b.send(WsMsg::Binary(b"bea-typed".to_vec().into()))
        .await
        .unwrap();
    ws_wait_output(&mut host, "bea-typed").await;
    // The driver's resize goes to the host as a request; the host's size
    // goes to everyone.
    send(&mut b, json!({"type": "resize", "cols": 120, "rows": 40})).await;
    let r = ws_wait_json(&mut host, "resize").await;
    assert_eq!(
        (r["cols"].clone(), r["by"].clone()),
        (json!(120), bea_id.clone())
    );
    send(
        &mut host,
        json!({"type": "resize", "cols": 120, "rows": 40}),
    )
    .await;
    assert_eq!(ws_wait_json(&mut c, "resize").await["cols"], 120);

    // The owner takes it back.
    send(&mut host, json!({"type": "control_take"})).await;
    assert_eq!(ws_wait_json(&mut b, "control").await["can_write"], false);
    b.send(WsMsg::Binary(b"after-take".to_vec().into()))
        .await
        .unwrap();
    let (_, out) = quiet(&mut host, 400).await;
    assert!(!out.contains("after-take"));

    // Refused.
    send(&mut b, json!({"type": "control_request"})).await;
    ws_wait_json(&mut host, "control_request").await;
    send(
        &mut host,
        json!({"type": "control_deny", "participant": bea_id}),
    )
    .await;
    ws_wait_json(&mut b, "control_denied").await;

    // Granted and given back.
    send(&mut b, json!({"type": "control_request"})).await;
    ws_wait_json(&mut host, "control_request").await;
    send(
        &mut host,
        json!({"type": "control_grant", "participant": bea_id}),
    )
    .await;
    assert_eq!(ws_wait_json(&mut b, "control").await["can_write"], true);
    send(&mut b, json!({"type": "control_release"})).await;
    let ctl = ws_wait_json(&mut b, "control").await;
    assert_eq!(
        (ctl["can_write"].clone(), ctl["driver"].clone()),
        (json!(false), Value::Null)
    );

    // With auto_grant (changed live) the request is granted at once.
    let changed = srv
        .ok(
            Method::PATCH,
            &format!("/api/v1/sessions/{rid}/shares/{bea_share}"),
            &ana,
            Some(json!({"auto_grant": true})),
        )
        .await;
    assert_eq!(changed["auto_grant"], true);
    send(&mut b, json!({"type": "control_request"})).await;
    assert_eq!(ws_wait_json(&mut b, "control").await["can_write"], true);

    // Down to view only: the keyboard goes away at once.
    srv.ok(
        Method::PATCH,
        &format!("/api/v1/sessions/{rid}/shares/{bea_share}"),
        &ana,
        Some(json!({"permission": "view"})),
    )
    .await;
    assert_eq!(ws_wait_json(&mut b, "control").await["can_write"], false);
    participants_until(&mut b, |l| {
        l.iter().any(|p| p["you"] == true && p["access"] == "view")
    })
    .await;
    b.send(WsMsg::Binary(b"after-downgrade".to_vec().into()))
        .await
        .unwrap();
    let (_, out) = quiet(&mut host, 400).await;
    assert!(!out.contains("after-downgrade"));

    // An older client (no `proto=2`) with control: typing takes the free
    // keyboard, as before; it gets the old `presence` list.
    srv.share(
        &ana,
        &rid,
        json!({"email": "dan@t.test", "permission": "control"}),
    )
    .await;
    let mut d = srv
        .ws(&format!("/api/v1/sessions/{rid}/ws"), Some(&dan))
        .await;
    ws_wait_json(&mut d, "hello").await;
    d.send(WsMsg::Binary(b"legacy-typed".to_vec().into()))
        .await
        .unwrap();
    ws_wait_output(&mut host, "legacy-typed").await;
    ws_wait_json(&mut d, "presence").await;
    // Once the owner takes it back, typing does not take it again.
    send(&mut host, json!({"type": "control_take"})).await;
    while ws_wait_json(&mut d, "control").await["can_write"] != false {}
    d.send(WsMsg::Binary(b"legacy-again".to_vec().into()))
        .await
        .unwrap();
    let (texts, out) = quiet(&mut host, 500).await;
    assert!(!out.contains("legacy-again"));
    assert!(
        texts.iter().any(|t| t["type"] == "control_request"),
        "{texts:?}"
    );

    let acts = actions(&srv.audit(&ana).await);
    for a in [
        "session.control_requested",
        "session.control_granted",
        "session.control_taken",
        "session.control_denied",
        "session.control_released",
        "session.share_changed",
    ] {
        assert!(acts.contains(&a.to_string()), "{a} missing from {acts:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kicks_expiry_and_stop_sharing() {
    let srv = Srv::start(|_, _| {}).await;
    let (ana, _) = srv.user("ana@t.test", "Ana").await;
    let (bea, _) = srv.user("bea@t.test", "Bea").await;
    let (cid, _) = srv.user("cid@t.test", "Cid").await;
    let (dan, _) = srv.user("dan@t.test", "Dan").await;
    let (rid, mut host) = srv.relay(&ana, "Laptop").await;
    let link = srv
        .share(
            &ana,
            &rid,
            json!({"link": true, "permission": "view", "require_approval": false}),
        )
        .await;
    let gus_path = format!(
        "/api/v1/sessions/{rid}/ws?share_token={}&proto=2&name=Gus",
        link["token"].as_str().unwrap()
    );
    let mut g = srv.ws(&gus_path, None).await;
    let gus_id = ws_wait_json(&mut g, "hello").await["you"]["participant"].clone();
    srv.share(
        &ana,
        &rid,
        json!({"email": "bea@t.test", "permission": "control"}),
    )
    .await;
    let mut b = srv.ws(&session_ws(&rid), Some(&bea)).await;
    let bea_id = ws_wait_json(&mut b, "hello").await["you"]["participant"].clone();

    // Kicked: an error with the code, then the socket closes.
    send(&mut host, json!({"type": "kick", "participant": gus_id})).await;
    expect_end(&mut g, "kicked", 4002).await;
    // Kicked and blocked: the share is revoked, she cannot come back.
    send(
        &mut host,
        json!({"type": "kick", "participant": bea_id, "revoke_share": true}),
    )
    .await;
    expect_end(&mut b, "kicked", 4002).await;
    let shares = srv
        .ok(
            Method::GET,
            &format!("/api/v1/sessions/{rid}/shares"),
            &ana,
            None,
        )
        .await;
    let bea_share = shares
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["user_email"] == "bea@t.test")
        .unwrap()
        .clone();
    assert_eq!(bea_share["revoked"], true);
    assert_eq!(bea_share["active"], false);
    assert_eq!(srv.ws_refused(&session_ws(&rid), Some(&bea)).await, 404);
    // A kicked guest can come back with the link (not revoked).
    let mut g = srv.ws(&gus_path, None).await;
    ws_wait_json(&mut g, "hello").await;

    // An expired share sends away whoever is inside.
    let cid_share = srv
        .share(
            &ana,
            &rid,
            json!({"email": "cid@t.test", "permission": "control"}),
        )
        .await;
    let mut c = srv.ws(&session_ws(&rid), Some(&cid)).await;
    ws_wait_json(&mut c, "hello").await;
    let soon = termoak_core::time::now_ms() + 1500;
    srv.ok(
        Method::PATCH,
        &format!(
            "/api/v1/sessions/{rid}/shares/{}",
            cid_share["share"]["id"].as_str().unwrap()
        ),
        &ana,
        Some(json!({"expires_at": soon})),
    )
    .await;
    expect_end(&mut c, "expired", 4003).await;

    // Stop sharing: every share is revoked and everyone else leaves.
    srv.share(
        &ana,
        &rid,
        json!({"email": "dan@t.test", "permission": "view"}),
    )
    .await;
    let mut d = srv.ws(&session_ws(&rid), Some(&dan)).await;
    ws_wait_json(&mut d, "hello").await;
    let stopped = srv
        .ok(
            Method::DELETE,
            &format!("/api/v1/sessions/{rid}/shares"),
            &ana,
            None,
        )
        .await;
    assert!(stopped["revoked"].as_u64().unwrap() >= 2, "{stopped}");
    expect_end(&mut d, "revoked", 4001).await;
    expect_end(&mut g, "revoked", 4001).await;
    let (s, _) = srv
        .call(
            Method::GET,
            &format!("/api/v1/join/{}", link["token"].as_str().unwrap()),
            None,
            None,
        )
        .await;
    assert_eq!(s, 404);
    // The owner stays.
    send(&mut host, json!({"type": "ping"})).await;
    ws_wait_json(&mut host, "pong").await;

    // Revoked shares cannot be changed; closed sessions cannot be shared.
    let (s, v) = srv
        .call(
            Method::PATCH,
            &format!(
                "/api/v1/sessions/{rid}/shares/{}",
                bea_share["id"].as_str().unwrap()
            ),
            Some(&ana),
            Some(json!({"permission": "control"})),
        )
        .await;
    assert_eq!(
        (s, v["error"]["code"].clone()),
        (409, json!("share_revoked"))
    );
    send(&mut host, json!({"type": "host_closed"})).await;
    let mut closed = false;
    for _ in 0..50 {
        let v = srv
            .ok(Method::GET, &format!("/api/v1/sessions/{rid}"), &ana, None)
            .await;
        if v["state"]["state"] == "closed" {
            closed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(closed);
    let (s, v) = srv
        .call(
            Method::POST,
            &format!("/api/v1/sessions/{rid}/shares"),
            Some(&ana),
            Some(json!({"link": true})),
        )
        .await;
    assert_eq!(
        (s, v["error"]["code"].clone()),
        (404, json!("session_ended"))
    );

    let audit = srv.audit(&ana).await;
    let acts = actions(&audit);
    for a in ["session.kicked", "session.sharing_stopped"] {
        assert!(acts.contains(&a.to_string()), "{a} missing from {acts:?}");
    }
    assert!(
        audit
            .iter()
            .any(|a| a["action"] == "session.kicked" && a["detail"]["reason"] == "expired")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn access_is_checked_again() {
    let srv = Srv::start(|_, _| {}).await;
    let (ana, _) = srv.user("ana@t.test", "Ana").await;
    let (bea, _) = srv.user("bea@t.test", "Bea").await;
    let (cid, _) = srv.user("cid@t.test", "Cid").await;
    let team = srv
        .ok(
            Method::POST,
            "/api/v1/teams",
            &ana,
            Some(json!({"name": "Ops"})),
        )
        .await;
    let team_id = team["id"].as_str().unwrap();
    for email in ["bea@t.test", "cid@t.test"] {
        srv.ok(
            Method::POST,
            &format!("/api/v1/teams/{team_id}/members"),
            &ana,
            Some(json!({"email": email})),
        )
        .await;
    }
    let (rid, _host) = srv.relay(&ana, "Laptop").await;
    let team_share = srv
        .share(
            &ana,
            &rid,
            json!({"team_id": team_id, "permission": "view"}),
        )
        .await;
    srv.share(
        &ana,
        &rid,
        json!({"email": "bea@t.test", "permission": "control"}),
    )
    .await;
    // The best share wins (`control` over `view`, not alphabetical).
    let mut b = srv.ws(&session_ws(&rid), Some(&bea)).await;
    assert_eq!(
        ws_wait_json(&mut b, "hello").await["you"]["access"],
        "control"
    );
    let list = srv.ok(Method::GET, "/api/v1/sessions", &bea, None).await;
    assert_eq!(list["shared"][0]["access"], "control");
    let mut c = srv.ws(&session_ws(&rid), Some(&cid)).await;
    assert_eq!(ws_wait_json(&mut c, "hello").await["you"]["access"], "view");

    // Revoking the team share: Cid leaves; Bea stays with her own share.
    srv.ok(
        Method::DELETE,
        &format!(
            "/api/v1/sessions/{rid}/shares/{}",
            team_share["share"]["id"].as_str().unwrap()
        ),
        &ana,
        None,
    )
    .await;
    expect_end(&mut c, "revoked", 4001).await;
    ignored(&mut b, "nothing").await;
    send(&mut b, json!({"type": "ping"})).await;
    ws_wait_json(&mut b, "pong").await;

    // A deleted account leaves at once.
    srv.ok(
        Method::DELETE,
        "/api/v1/me",
        &bea,
        Some(json!({"password": "secure-password"})),
    )
    .await;
    expect_end(&mut b, "revoked", 4001).await;
}

/// TCP proxy that can cut every connection (to drop the relay host).
struct Proxy {
    addr: std::net::SocketAddr,
    cut: tokio::sync::watch::Sender<u64>,
}

impl Proxy {
    async fn start(target: String) -> Proxy {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (cut, _) = tokio::sync::watch::channel(0u64);
        let rx = cut.subscribe();
        tokio::spawn(async move {
            loop {
                let (mut inbound, _) = listener.accept().await.unwrap();
                let target = target.clone();
                let mut rx = rx.clone();
                rx.borrow_and_update();
                tokio::spawn(async move {
                    let Ok(mut outbound) = tokio::net::TcpStream::connect(&target).await else {
                        return;
                    };
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound) => {}
                        _ = rx.changed() => {}
                    }
                });
            }
        });
        Proxy { addr, cut }
    }

    fn cut(&self) {
        self.cut.send_modify(|n| *n += 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_host_with_the_client_library() {
    use termoak_client::relay::{LocalTerm, RelayEvent, RelayShare};
    use termoak_ssh::terminal::OutputHub;

    let srv = Srv::start(|_, _| {}).await;
    let (_, _) = srv.user("ana@t.test", "Ana").await;
    let (bea, _) = srv.user("bea@t.test", "Bea").await;
    let proxy = Proxy::start(srv.base.trim_start_matches("http://").to_string()).await;
    let api = termoak_client::ApiClient::new(&format!("http://{}", proxy.addr)).unwrap();
    api.login("ana@t.test", "secure-password", "Laptop", "desktop-linux")
        .await
        .unwrap();

    // A local terminal: whatever is pushed to the hub is its output.
    let hub = Arc::new(OutputHub::new(64 * 1024));
    hub.push("local-prompt$ ".into());
    let (input_tx, mut input_rx) = tokio::sync::mpsc::unbounded_channel();
    let (_closed_tx, closed_rx) = tokio::sync::watch::channel(false);
    let share = RelayShare::start_local(
        &api,
        LocalTerm {
            hub: hub.clone(),
            input: input_tx,
            size: (80, 24),
            closed: closed_rx,
        },
        "Local shell",
    )
    .await
    .unwrap();
    let mut events = share.subscribe();
    let rid = share.session_id.to_string();
    let invite = share.invite_user("bea@t.test", true).await.unwrap();
    assert_eq!(invite["share"]["permission"], "control");

    async fn wait_for<T>(
        events: &mut tokio::sync::broadcast::Receiver<RelayEvent>,
        mut f: impl FnMut(RelayEvent) -> Option<T>,
    ) -> T {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(t) = f(events.recv().await.unwrap()) {
                    return t;
                }
            }
        })
        .await
        .expect("relay event never arrived")
    }

    let mut b = srv.ws(&session_ws(&rid), Some(&bea)).await;
    ws_wait_json(&mut b, "hello").await;
    ws_wait_output(&mut b, "local-prompt$").await;
    // The host hears who joins and who asks for the keyboard.
    wait_for(&mut events, |e| match e {
        RelayEvent::Participants { participants, .. }
            if participants.iter().any(|p| p.name == "Bea") =>
        {
            Some(())
        }
        _ => None,
    })
    .await;
    send(&mut b, json!({"type": "control_request"})).await;
    let bea_id = wait_for(&mut events, |e| match e {
        RelayEvent::ControlRequest(p) => Some(p.id),
        _ => None,
    })
    .await;
    share.grant_control(bea_id).await;
    wait_for(&mut events, |e| match e {
        RelayEvent::Control { driver, .. } if driver == Some(bea_id) => Some(()),
        _ => None,
    })
    .await;
    ws_wait_json(&mut b, "control").await;
    b.send(WsMsg::Binary(b"whoami\r".to_vec().into()))
        .await
        .unwrap();
    let typed = tokio::time::timeout(Duration::from_secs(10), input_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&typed[..], b"whoami\r");
    // The driver's size reaches the host as a request.
    send(&mut b, json!({"type": "resize", "cols": 132, "rows": 43})).await;
    let (cols, rows) = wait_for(&mut events, |e| match e {
        RelayEvent::ResizeRequest { cols, rows } => Some((cols, rows)),
        _ => None,
    })
    .await;
    assert_eq!((cols, rows), (132, 43));
    share.resize(132, 43).await;
    assert_eq!(ws_wait_json(&mut b, "resize").await["cols"], 132);

    // The host's connection drops: guests see it offline, it comes back
    // by itself and the history is not duplicated.
    proxy.cut();
    wait_for(&mut events, |e| {
        matches!(e, RelayEvent::Reconnecting).then_some(())
    })
    .await;
    let offline = ws_wait_json(&mut b, "status").await;
    assert_eq!(offline["status"]["state"], "host_offline");
    wait_for(&mut events, |e| {
        matches!(e, RelayEvent::Reconnected).then_some(())
    })
    .await;
    loop {
        let s = ws_wait_json(&mut b, "status").await;
        if s["status"]["state"] == "running" {
            break;
        }
    }
    hub.push("after-reconnect".into());
    ws_wait_output(&mut b, "after-reconnect").await;
    let mut fresh = srv.ws(&session_ws(&rid), Some(&bea)).await;
    ws_wait_json(&mut fresh, "hello").await;
    let screen = ws_wait_output(&mut fresh, "after-reconnect").await;
    assert_eq!(screen.matches("local-prompt$").count(), 1, "{screen:?}");

    share.stop().await;
    let closed = ws_wait_json(&mut b, "status").await;
    assert_eq!(closed["status"]["state"], "closed");
}

// --- Notices for the owner: events WebSocket and push ----------------------

#[derive(Default)]
struct Mock {
    apns: Mutex<Vec<Value>>,
}

async fn apns(
    State(m): State<Arc<Mock>>,
    Path(_token): Path<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    m.apns.lock().push(body);
    (StatusCode::OK, Json(json!({})))
}

async fn wait_push(mock: &Mock, kind: &str) -> Value {
    for _ in 0..200 {
        if let Some(b) = mock
            .apns
            .lock()
            .iter()
            .find(|b| b["termoak"]["type"] == kind)
        {
            return b.clone();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no {kind} push: {:?}", mock.apns.lock());
}

async fn wait_notice(events: &mut Ws, kind: &str) -> Value {
    loop {
        let v = ws_wait_json(events, "session").await;
        if v["notice"]["type"] == kind {
            return v["notice"].clone();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_notices_and_push() {
    let mock = Arc::new(Mock::default());
    let app = Router::new()
        .route("/3/device/{token}", post(apns))
        .with_state(mock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let rng = ring::rand::SystemRandom::new();
    let p8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &rng,
    )
    .unwrap();
    let pem = {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(p8.as_ref());
        format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n")
    };
    let sshd = common::start_sshd();
    let srv = Srv::start(|c, dir| {
        let key = dir.join("AuthKey.p8");
        std::fs::write(&key, &pem).unwrap();
        c.push.apns = Some(ApnsSection {
            key_path: Some(key),
            key_id: "KEYID12345".into(),
            team_id: "TEAM123456".into(),
            topic: "com.termoak".into(),
            endpoint: Some(mock_url.clone()),
            sandbox_endpoint: Some(mock_url.clone()),
        });
    })
    .await;
    let (ana, _) = srv.user("ana@t.test", "Ana").await;
    let (bea, _) = srv.user("bea@t.test", "Bea").await;
    srv.ok(
        Method::POST,
        "/api/v1/push/register",
        &ana,
        Some(json!({"platform": "apns", "token": "ana-phone"})),
    )
    .await;
    let mut events = srv.ws("/api/v1/events/ws", Some(&ana)).await;
    ws_wait_json(&mut events, "hello").await;

    // A relay whose host is not connected: nobody of Ana is watching.
    let relay = srv
        .ok(
            Method::POST,
            "/api/v1/relay",
            &ana,
            Some(json!({"title": "Laptop"})),
        )
        .await;
    let rid = relay["session"]["id"].as_str().unwrap().to_string();
    let link = srv
        .share(&ana, &rid, json!({"link": true, "permission": "control"}))
        .await;
    let mut g = srv
        .ws(
            &format!(
                "/api/v1/sessions/{rid}/ws?share_token={}&proto=2&name=Zoe",
                link["token"].as_str().unwrap()
            ),
            None,
        )
        .await;
    ws_wait_json(&mut g, "waiting").await;
    let notice = wait_notice(&mut events, "join_request").await;
    assert_eq!(notice["session_id"], rid.as_str());
    assert_eq!(notice["participant"]["name"], "Zoe");
    let push = wait_push(&mock, "join_request").await;
    assert_eq!(push["termoak"]["session_id"], rid.as_str());
    // Generic text: no names or titles.
    assert_eq!(
        push["aps"]["alert"]["body"],
        "Someone is waiting to join a session you share."
    );

    // A request for the keyboard while Ana is not watching.
    srv.share(
        &ana,
        &rid,
        json!({"email": "bea@t.test", "permission": "control"}),
    )
    .await;
    let mut b = srv.ws(&session_ws(&rid), Some(&bea)).await;
    ws_wait_json(&mut b, "hello").await;
    let mut bea_events = srv.ws("/api/v1/events/ws", Some(&bea)).await;
    ws_wait_json(&mut bea_events, "hello").await;
    send(&mut b, json!({"type": "control_request"})).await;
    let notice = wait_notice(&mut events, "control_request").await;
    assert_eq!(notice["participant"]["name"], "Bea");
    wait_push(&mock, "control_request").await;
    // Ana grants it from her phone (attached as owner): Bea is told.
    let mut owner = srv.ws(&session_ws(&rid), Some(&ana)).await;
    ws_wait_json(&mut owner, "hello").await;
    let req = ws_wait_json(&mut owner, "control_request").await;
    send(
        &mut owner,
        json!({"type": "control_grant", "participant": req["participant"]["id"]}),
    )
    .await;
    wait_notice(&mut bea_events, "control_granted").await;
    send(&mut owner, json!({"type": "control_take"})).await;
    wait_notice(&mut bea_events, "control_revoked").await;

    // A server session waiting for an answer (unknown host key) while
    // nobody watches: notice and push.
    let Some(sshd) = sshd else {
        eprintln!("sshd not available: prompt part skipped");
        return;
    };
    let host = srv
        .ok(
            Method::POST,
            "/api/v1/hosts",
            &ana,
            Some(json!({"label": "local", "address": "127.0.0.1", "settings": {"port": sshd.port, "username": sshd.user}})),
        )
        .await;
    let opened = srv
        .ok(
            Method::POST,
            "/api/v1/sessions",
            &ana,
            Some(json!({"host_id": host["id"]})),
        )
        .await;
    let notice = wait_notice(&mut events, "prompt_pending").await;
    assert_eq!(notice["session_id"], opened["id"]);
    assert_eq!(notice["prompt"]["kind"], "hostkey");
    let push = wait_push(&mock, "session_prompt").await;
    assert_eq!(push["termoak"]["session_id"], opened["id"]);
}
