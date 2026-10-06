//! Sessions and devices: signing a device out stops its token and closes its
//! WebSockets at once, signing out every other device (or all of them), and
//! the last IP and client of each device.

mod common;

use std::time::Duration;

use common::srv::{Srv, User};
use futures::{SinkExt, StreamExt};
use reqwest::Method;
use serde_json::{Value, json};
use termoak_core::Id;
use tokio_tungstenite::tungstenite::Message as WsMsg;

const FIREFOX: &str =
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0";

/// Signs in again (a new device) with a `User-Agent` and maybe an
/// `X-Forwarded-For`.
async fn sign_in(srv: &Srv, u: &User, device: &str, ua: &str, forwarded: Option<&str>) -> User {
    let mut req = srv
        .http
        .post(format!("{}/api/v1/auth/login", srv.base))
        .header("user-agent", ua)
        .json(&json!({"email": u.email, "password": "secure-password",
                      "device_name": device, "platform": "web"}));
    if let Some(ip) = forwarded {
        req = req.header("x-forwarded-for", ip);
    }
    let r: Value = req.send().await.unwrap().json().await.unwrap();
    User {
        token: r["tokens"]["access_token"]
            .as_str()
            .unwrap_or_else(|| panic!("login: {r}"))
            .into(),
        id: r["user"]["id"].as_str().unwrap().into(),
        email: u.email.clone(),
    }
}

async fn device_id(srv: &Srv, u: &User) -> String {
    let me = srv.get("/api/v1/me", u).await;
    assert_eq!(me.status, 200, "{}", me.body);
    me.body["device"]["id"].as_str().unwrap().into()
}

async fn devices(srv: &Srv, u: &User) -> Value {
    let r = srv.get("/api/v1/devices", u).await;
    assert_eq!(r.status, 200, "{}", r.body);
    r.body
}

/// Waits for the server to close the WebSocket; returns the close code and
/// the JSON messages seen before.
async fn wait_closed(ws: &mut common::srv::Ws) -> (Option<u16>, Vec<Value>) {
    let mut seen = Vec::new();
    let code = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(msg) = ws.next().await {
            match msg {
                Ok(WsMsg::Text(t)) => seen.push(serde_json::from_str(&t).unwrap()),
                Ok(WsMsg::Close(frame)) => return frame.map(|f| u16::from(f.code)),
                Ok(_) => {}
                Err(_) => return None,
            }
        }
        None
    })
    .await
    .expect("the WebSocket was not closed");
    (code, seen)
}

async fn audit(srv: &Srv, u: &User, action: &str) -> Vec<Value> {
    let r = srv.get("/api/v1/audit?limit=500", u).await;
    assert_eq!(r.status, 200, "{}", r.body);
    r.body
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == action)
        .cloned()
        .collect()
}

#[tokio::test]
async fn a_signed_out_device_loses_its_token_sockets_and_notifications_at_once() {
    let srv = Srv::start().await;
    let ana = srv.user("Ana").await;
    let phone = sign_in(&srv, &ana, "Phone", "Termoak/0.4.0", None).await;
    let phone_id = device_id(&srv, &phone).await;
    let user_id: Id = ana.id.parse().unwrap();

    // The phone has notifications, the events socket and a relay session
    // (terminal) with its host connected.
    srv.state
        .store
        .set_push_token(phone_id.parse().unwrap(), "fcm", "phone-token", false)
        .await
        .unwrap();
    assert_eq!(
        srv.state.store.push_targets(user_id).await.unwrap().len(),
        1
    );
    let mut events = srv.events(&phone).await;
    let relay = srv
        .ok(
            "/api/v1/relay",
            &phone,
            json!({"title": "t", "cols": 80, "rows": 24}),
        )
        .await;
    let path = format!("{}&proto=2", relay["host_ws_path"].as_str().unwrap());
    let mut host = common::ws_connect(&srv.base, &path, Some(&phone.token)).await;
    common::ws_wait_json(&mut host, "hello").await;
    host.send(WsMsg::Binary(b"screen\r\n".to_vec().into()))
        .await
        .unwrap();
    // A viewer on the laptop (another device of the owner) stays.
    let rid = relay["session"]["id"].as_str().unwrap();
    let mut viewer = common::ws_connect(
        &srv.base,
        &format!("/api/v1/sessions/{rid}/ws?proto=2"),
        Some(&ana.token),
    )
    .await;
    common::ws_wait_json(&mut viewer, "hello").await;
    assert_eq!(
        srv.state
            .sockets
            .count_for_device(phone_id.parse().unwrap()),
        2
    );

    let r = srv
        .delete(&format!("/api/v1/devices/{phone_id}"), &ana)
        .await;
    assert_eq!(r.status, 200, "{}", r.body);

    // The access token stops working right away (not at its expiry).
    let me = srv.get("/api/v1/me", &phone).await;
    assert_eq!(me.status, 401, "{}", me.body);
    // Its sockets close with `signed_out` (4007).
    let (code, seen) = wait_closed(&mut events).await;
    assert_eq!(code, Some(4007));
    assert!(seen.iter().any(|v| v["type"] == "signed_out"), "{seen:?}");
    let (code, seen) = wait_closed(&mut host).await;
    assert_eq!(code, Some(4007));
    assert!(
        seen.iter()
            .any(|v| v["type"] == "error" && v["code"] == "signed_out"),
        "{seen:?}"
    );
    // No more notifications for it.
    assert!(
        srv.state
            .store
            .push_targets(user_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        srv.state
            .sockets
            .count_for_device(phone_id.parse().unwrap()),
        0
    );
    // The laptop is still in.
    assert_eq!(srv.get("/api/v1/me", &ana).await.status, 200);
    viewer
        .send(WsMsg::Text(r#"{"type":"ping"}"#.into()))
        .await
        .unwrap();
    common::ws_wait_json(&mut viewer, "pong").await;
    let list = devices(&srv, &ana).await;
    assert_eq!(list["devices"].as_array().unwrap().len(), 1);
    let entry = audit(&srv, &ana, "auth.device_revoked").await;
    assert_eq!(entry.len(), 1);
    assert_eq!(entry[0]["target"], phone_id.as_str());

    // Someone else's device: not found.
    let bea = srv.user("Bea").await;
    let bea_id = device_id(&srv, &bea).await;
    let r = srv.delete(&format!("/api/v1/devices/{bea_id}"), &ana).await;
    assert_eq!(r.status, 404, "{}", r.body);
    assert_eq!(srv.get("/api/v1/me", &bea).await.status, 200);

    // Signing out (logout) closes the sockets of the device too.
    let mut events = srv.events(&bea).await;
    let r = srv.post("/api/v1/auth/logout", &bea, json!({})).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(wait_closed(&mut events).await.0, Some(4007));
}

#[tokio::test]
async fn sign_out_all_with_and_without_the_current_device() {
    let srv = Srv::start().await;
    let ana = srv.user("Ana").await;
    let phone = sign_in(&srv, &ana, "Phone", "Termoak/0.4.0", None).await;
    let tablet = sign_in(&srv, &ana, "Tablet", FIREFOX, None).await;
    let other = srv.user("Bea").await;
    let mut phone_events = srv.events(&phone).await;
    let mut ana_events = srv.events(&ana).await;

    // Without a body: the others only.
    let r = srv
        .req(
            Method::POST,
            "/api/v1/devices/sign-out-all",
            &ana.token,
            None,
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["revoked"], 2);
    assert_eq!(srv.get("/api/v1/me", &phone).await.status, 401);
    assert_eq!(srv.get("/api/v1/me", &tablet).await.status, 401);
    assert_eq!(srv.get("/api/v1/me", &ana).await.status, 200);
    assert_eq!(srv.get("/api/v1/me", &other).await.status, 200);
    assert_eq!(wait_closed(&mut phone_events).await.0, Some(4007));
    let list = devices(&srv, &ana).await;
    let list = list["devices"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["id"], device_id(&srv, &ana).await.as_str());
    // The current device's socket is still open.
    if let Ok(msg) = tokio::time::timeout(Duration::from_millis(300), ana_events.next()).await {
        match msg {
            Some(Ok(WsMsg::Close(_))) | None | Some(Err(_)) => panic!("closed: {msg:?}"),
            Some(Ok(WsMsg::Text(t))) => assert!(!t.contains("signed_out"), "{t}"),
            Some(Ok(_)) => {}
        }
    }
    let entries = audit(&srv, &ana, "auth.devices_revoked").await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["detail"]["count"], 2);
    assert_eq!(entries[0]["detail"]["include_current"], false);

    // Nothing else to sign out.
    let r = srv
        .post(
            "/api/v1/devices/sign-out-all",
            &ana,
            json!({"include_current": false}),
        )
        .await;
    assert_eq!(r.body["revoked"], 0);

    // Everywhere, this one included.
    let phone = sign_in(&srv, &ana, "Phone", "Termoak/0.4.0", None).await;
    let r = srv
        .post(
            "/api/v1/devices/sign-out-all",
            &ana,
            json!({"include_current": true}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["revoked"], 2);
    assert_eq!(srv.get("/api/v1/me", &ana).await.status, 401);
    assert_eq!(srv.get("/api/v1/me", &phone).await.status, 401);
    assert_eq!(wait_closed(&mut ana_events).await.0, Some(4007));
    assert_eq!(srv.get("/api/v1/me", &other).await.status, 200);
    let left = srv
        .state
        .store
        .list_devices(ana.id.parse().unwrap())
        .await
        .unwrap();
    assert!(left.is_empty());

    // A bad body is rejected.
    let r = srv
        .post(
            "/api/v1/devices/sign-out-all",
            &other,
            json!({"include_current": "yes"}),
        )
        .await;
    assert!(
        r.status == 400 || r.status == 422,
        "{} {}",
        r.status,
        r.body
    );
    assert_eq!(srv.get("/api/v1/me", &other).await.status, 200);
}

#[tokio::test]
async fn devices_show_their_last_ip_and_client() {
    let srv = Srv::start_with_client_ip(|_| {}).await;
    let ana = srv.user("Ana").await;
    let web = sign_in(&srv, &ana, "Firefox", FIREFOX, None).await;
    let list = devices(&srv, &web).await;
    let current = list["current"].as_str().unwrap();
    let rows = list["devices"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    let me = rows.iter().find(|d| d["id"] == current).unwrap();
    assert_eq!(me["last_ip"], "127.0.0.1");
    assert_eq!(me["user_agent"], "Firefox 131 on Linux");
    assert_eq!(me["name"], "Firefox");
    assert!(me["created_at"].is_i64() && me["last_seen_at"].is_i64());
    // reqwest sends no User-Agent by default: the registration has the IP only.
    let first = rows.iter().find(|d| d["id"] != current).unwrap();
    assert_eq!(first["last_ip"], "127.0.0.1");
    assert!(first["user_agent"].is_null());

    // The administrator's listing has them too.
    let admin = srv
        .get(&format!("/api/v1/admin/users/{}/devices", ana.id), &ana)
        .await;
    assert_eq!(admin.status, 200, "{}", admin.body);
    assert!(
        admin
            .body
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["user_agent"] == "Firefox 131 on Linux" && d["last_ip"] == "127.0.0.1")
    );

    // Behind a trusted proxy: the forwarded address (as for the limits).
    let srv = Srv::start_with_client_ip(|c| c.server.trust_forwarded_for = true).await;
    let bea = srv.user("Bea").await;
    let phone = sign_in(
        &srv,
        &bea,
        "Phone",
        "Termoak/0.4.0",
        Some("10.0.0.1, 203.0.113.9"),
    )
    .await;
    let list = devices(&srv, &phone).await;
    let current = list["current"].as_str().unwrap();
    let me = list["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["id"] == current)
        .unwrap()
        .clone();
    assert_eq!(me["last_ip"], "203.0.113.9");
    assert_eq!(me["user_agent"], "Termoak 0.4.0");
    // Not trusted: the header is ignored.
    let srv = Srv::start_with_client_ip(|_| {}).await;
    let cai = srv.user("Cai").await;
    let phone = sign_in(&srv, &cai, "Phone", "Termoak/0.4.0", Some("203.0.113.9")).await;
    let list = devices(&srv, &phone).await;
    let current = list["current"].as_str().unwrap();
    assert!(
        list["devices"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["id"] == current && d["last_ip"] == "127.0.0.1")
    );
}

/// A device signed in on the production schema (v6) keeps working after the
/// migrations, without an IP until it is used again.
#[tokio::test]
async fn devices_from_schema_v6_survive_the_migrations() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("termoak.db");
    termoak_core::store::create_at_version(&path, 6).unwrap();
    let user = termoak_core::new_id();
    let device = termoak_core::new_id();
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute(
            "INSERT INTO users (id, email, name, password_hash, created_at) VALUES (?1, 'a@b.c', 'A', 'x', 1)",
            [user.to_string()],
        )
        .unwrap();
        c.execute(
            "INSERT INTO devices (id, user_id, name, platform, access_hash, access_expires_at,
                                  refresh_hash, refresh_expires_at, created_at, last_seen_at)
             VALUES (?1, ?2, 'Laptop', 'desktop-linux', 'ah', 9999999999999, 'rh', 9999999999999, 1, 1)",
            [device.to_string(), user.to_string()],
        )
        .unwrap();
    }
    let store =
        termoak_core::Store::open(&path, termoak_core::crypto::MasterKey::generate()).unwrap();
    let list = store.list_devices(user).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, device);
    assert_eq!(list[0].last_ip, None);
    assert_eq!(list[0].user_agent, None);
}
