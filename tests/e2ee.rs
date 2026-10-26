//! End-to-end encrypted vaults (0.7 phase 5a, docs/E2EE-SSO-AUDIT.md §2)
//! through the HTTP API, with the core's crypto playing the client: user
//! keys, turning a vault's E2EE on, sealed secrets in sync v2 and REST,
//! what the server refuses (plaintext, reveal, just-in-time credentials,
//! stale keys), clients without `e2ee`, per-session unlock against a real
//! sshd, key rotation after a member loses access, adding wraps, pairing
//! and turning E2EE off.

mod common;

use base64::Engine as _;
use reqwest::Method;
use serde_json::{Value, json};
use termoak_core::e2ee::{self, KeySeal, PairingKey, RecoveryKey, UserKeyPair, VaultKey};
use termoak_core::model::EntityKind;
use termoak_core::{Id, new_id};

use common::srv::{Resp, Srv, User, wait_event};

const FEATURES: &str = "roles_v2,policies,e2ee";

/// A request as a client that declares `e2ee`.
async fn freq(srv: &Srv, method: Method, path: &str, u: &User, body: Option<Value>) -> Resp {
    let mut r = srv
        .http
        .request(method, format!("{}{path}", srv.base))
        .bearer_auth(&u.token)
        .header("x-termoak-features", FEATURES);
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

async fn fok(srv: &Srv, method: Method, path: &str, u: &User, body: Option<Value>) -> Value {
    let r = freq(srv, method.clone(), path, u, body).await;
    assert!(r.status < 300, "{method} {path}: {} {}", r.status, r.body);
    r.body
}

fn id(u: &User) -> Id {
    u.id.parse().unwrap()
}

/// Publishes a user key with a recovery seal.
async fn setup(srv: &Srv, u: &User) -> (UserKeyPair, RecoveryKey) {
    let key = UserKeyPair::generate();
    let rk = RecoveryKey::generate();
    let seal = e2ee::seal_with_recovery(id(u), &key, &rk).unwrap();
    let info = fok(
        srv,
        Method::PUT,
        "/api/v1/me/e2ee",
        u,
        Some(json!({"key_id": key.id, "public_key": key.public_b64(), "seals": [seal]})),
    )
    .await;
    assert_eq!(info["fingerprint"], key.fingerprint());
    (key, rk)
}

fn wrap(vk: &VaultKey, vault: Id, version: u32, u: &User, key: &UserKeyPair) -> Value {
    json!({"user_id": u.id, "key_id": key.id,
           "wrapped": e2ee::wrap_vault_key(vk, vault, version, id(u), key.id, key.public()).unwrap()})
}

fn sealed(vk: &VaultKey, vault: Id, version: u32, host: Id, password: &str) -> String {
    e2ee::encrypt_secret(
        vk,
        vault,
        version,
        EntityKind::Host,
        host,
        json!({"password": password}).to_string().as_bytes(),
    )
    .unwrap()
}

async fn sync(srv: &Srv, u: &User, features: bool, changes: Value) -> Value {
    let body = json!({"vaults": [], "changes": changes, "kinds": ["group", "host", "identity", "key", "snippet", "forward", "known_host", "memory", "network"]});
    let r = if features {
        freq(srv, Method::POST, "/api/v1/vaults/sync", u, Some(body)).await
    } else {
        srv.post("/api/v1/vaults/sync", u, body).await
    };
    assert_eq!(r.status, 200, "{}", r.body);
    r.body
}

fn change_of<'a>(resp: &'a Value, host: &str) -> Option<&'a Value> {
    resp["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == host)
}

#[tokio::test]
async fn e2ee_vault_lifecycle() {
    let srv = Srv::start().await;
    let ana = srv.user("Ana").await;
    let bob = srv.user("Bob").await;
    let carl = srv.user("Carl").await;
    let vault_s = srv.vault(&ana, "Ops").await;
    let vault: Id = vault_s.parse().unwrap();
    let bob_grant = srv.share(&ana, &vault_s, &bob, "editor").await;
    srv.share(&ana, &vault_s, &carl, "use_only").await;
    let host_s = srv.host(&ana, &vault_s, "web", "server-pw").await;
    let host: Id = host_s.parse().unwrap();

    // Nobody has a key yet: enabling needs one.
    let st = fok(
        &srv,
        Method::GET,
        &format!("/api/v1/vaults/{vault}/e2ee"),
        &ana,
        None,
    )
    .await;
    assert_eq!(st["crypto"], "server");
    assert_eq!(st["without_key"].as_array().unwrap().len(), 2, "{st}");
    let (ka, rka) = setup(&srv, &ana).await;
    let (kb, _) = setup(&srv, &bob).await;
    let again = freq(&srv, Method::PUT, "/api/v1/me/e2ee", &ana, Some(json!({"key_id": new_id(), "public_key": ka.public_b64(), "seals": [e2ee::seal_with_recovery(id(&ana), &ka, &rka).unwrap()]}))).await;
    assert_eq!((again.status, again.code()), (409, "e2ee_key_exists"));
    // The status shows the key and the sealed copy (which only the
    // recovery key opens).
    let me = fok(&srv, Method::GET, "/api/v1/me/e2ee", &ana, None).await;
    let seal: KeySeal = serde_json::from_value(me["seals"][0].clone()).unwrap();
    let opened = e2ee::open_with_recovery(id(&ana), ka.id, &seal, &rka, Some(ka.public())).unwrap();
    assert_eq!(opened.public(), ka.public());

    let st = fok(
        &srv,
        Method::GET,
        &format!("/api/v1/vaults/{vault}/e2ee"),
        &ana,
        None,
    )
    .await;
    assert_eq!(st["recipients"].as_array().unwrap().len(), 2, "{st}");
    assert_eq!(st["items"].as_array().unwrap().len(), 1);
    let version = st["next_version"].as_u64().unwrap() as u32;
    // Carl (Use) may not hold the key: he cannot read the state.
    let r = freq(
        &srv,
        Method::GET,
        &format!("/api/v1/vaults/{vault}/e2ee"),
        &carl,
        None,
    )
    .await;
    assert_eq!(r.status, 403);

    // --- Turn it on: a client without `e2ee` cannot ---
    let vk = VaultKey::generate();
    let body = json!({"version": version, "wraps": [wrap(&vk, vault, version, &ana, &ka), wrap(&vk, vault, version, &bob, &kb)],
                      "items": [{"id": host, "kind": "host", "blob_b64": sealed(&vk, vault, version, host, "server-pw")}]});
    let r = srv
        .post(
            &format!("/api/v1/vaults/{vault}/e2ee/enable"),
            &ana,
            body.clone(),
        )
        .await;
    assert_eq!(
        (r.status, r.code()),
        (409, "e2ee_client_required"),
        "{}",
        r.body
    );
    // A wrap for Carl is refused.
    let mut bad = body.clone();
    let w = bad["wraps"][1]["wrapped"].clone();
    bad["wraps"]
        .as_array_mut()
        .unwrap()
        .push(json!({"user_id": carl.id, "key_id": kb.id, "wrapped": w}));
    let r = freq(
        &srv,
        Method::POST,
        &format!("/api/v1/vaults/{vault}/e2ee/enable"),
        &ana,
        Some(bad),
    )
    .await;
    assert_eq!((r.status, r.code()), (400, "e2ee_wrap_invalid"));
    // Missing the item: refused.
    let mut bad = body.clone();
    bad["items"] = json!([]);
    let r = freq(
        &srv,
        Method::POST,
        &format!("/api/v1/vaults/{vault}/e2ee/enable"),
        &ana,
        Some(bad),
    )
    .await;
    assert_eq!((r.status, r.code()), (409, "e2ee_incomplete"));
    let r = fok(
        &srv,
        Method::POST,
        &format!("/api/v1/vaults/{vault}/e2ee/enable"),
        &ana,
        Some(body),
    )
    .await;
    assert_eq!(r["key_version"], version);

    // --- The server cannot open it ---
    let r = freq(
        &srv,
        Method::GET,
        &format!("/api/v1/hosts/{host}/secret"),
        &ana,
        None,
    )
    .await;
    assert_eq!((r.status, r.code()), (409, "e2ee_locked"));
    let r = freq(
        &srv,
        Method::POST,
        &format!("/api/v1/hosts/{host}/credentials"),
        &carl,
        Some(json!({})),
    )
    .await;
    assert_eq!((r.status, r.code()), (409, "e2ee_vault"), "{}", r.body);
    let h = fok(
        &srv,
        Method::GET,
        &format!("/api/v1/hosts/{host}"),
        &ana,
        None,
    )
    .await;
    assert_eq!(h["e2ee_locked"], true);
    assert_eq!(h["has_secret"], true);

    // --- Clients without `e2ee` never see the vault ---
    let vaults = srv.get("/api/v1/vaults", &ana).await.body;
    assert!(
        !vaults
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["id"] == vault_s)
    );
    let hosts = srv.get("/api/v1/hosts", &ana).await.body;
    assert!(!hosts.as_array().unwrap().iter().any(|h| h["id"] == host_s));
    assert_eq!(
        srv.get(&format!("/api/v1/hosts/{host}"), &ana).await.status,
        404
    );
    let old = sync(&srv, &bob, false, json!([])).await;
    assert!(
        !old["vaults"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["id"] == vault_s)
    );
    assert!(change_of(&old, &host_s).is_none());
    // An old client pushing to it: refused, nothing changes.
    let push = json!([{"id": host, "kind": "host", "vault_id": vault, "data": {"label": "web", "address": "x", "settings": {"username": "root"}},
                        "secret": {"password": "plain"}, "sync_mode": "synced", "updated_at": termoak_core::time::now_ms(), "deleted": false}]);
    let old = sync(&srv, &bob, false, push.clone()).await;
    assert_eq!(old["rejected"][0]["code"], "vault_not_found", "{old}");

    // --- Members with `e2ee`: the wrap and the sealed secret ---
    let new = sync(&srv, &bob, true, json!([])).await;
    let v = new["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == vault_s)
        .unwrap();
    assert_eq!(v["crypto"], "e2ee");
    let wrapped = v["e2ee"]["wrap"].as_str().unwrap();
    let bvk = e2ee::unwrap_vault_key(wrapped, vault, version, id(&bob), &kb).unwrap();
    let rec = change_of(&new, &host_s).unwrap();
    assert!(rec["secret"].is_null());
    let blob = rec["sealed"]["blob_b64"].as_str().unwrap();
    let plain = e2ee::decrypt_secret(&bvk, vault, version, EntityKind::Host, host, blob).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&plain).unwrap()["password"],
        "server-pw"
    );
    let cnew = sync(&srv, &carl, true, json!([])).await;
    let crec = change_of(&cnew, &host_s).unwrap();
    assert!(
        crec["sealed"].is_null() && crec["has_secret"] == true,
        "{crec}"
    );
    let cv = cnew["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == vault_s)
        .unwrap();
    assert_eq!(cv["e2ee"]["may_hold_key"], false);
    assert!(cv["e2ee"]["wrap"].is_null());

    // --- Pushes: plaintext refused, a stale key refused, sealed accepted ---
    let now = termoak_core::time::now_ms();
    let rec_with = |extra: Value| {
        let mut r = json!({"id": host, "kind": "host", "vault_id": vault, "data": {"label": "web", "address": "web.example.com", "settings": {"username": "root"}},
                           "sync_mode": "synced", "updated_at": now, "deleted": false});
        r.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        r
    };
    let r = sync(
        &srv,
        &bob,
        true,
        json!([rec_with(json!({"secret": {"password": "plain"}}))]),
    )
    .await;
    assert_eq!(r["rejected"][0]["code"], "e2ee_plaintext_rejected", "{r}");
    let r = sync(&srv, &bob, true, json!([rec_with(json!({"sealed": {"key_version": version + 7, "blob_b64": sealed(&bvk, vault, version, host, "x")}}))])).await;
    assert_eq!(r["rejected"][0]["code"], "e2ee_key_outdated", "{r}");
    let r = sync(&srv, &bob, true, json!([rec_with(json!({"sealed": {"key_version": version, "blob_b64": sealed(&bvk, vault, version, host, "bob-pw")}}))])).await;
    assert_eq!(r["accepted"][0], host_s, "{r}");
    // REST: plaintext refused, sealed accepted, metadata alone keeps it.
    let r = freq(&srv, Method::PUT, &format!("/api/v1/hosts/{host}"), &ana, Some(json!({"label": "web", "address": "web.example.com", "settings": {"username": "root"}, "secret": {"password": "p"}}))).await;
    assert_eq!((r.status, r.code()), (409, "e2ee_plaintext_rejected"));
    fok(&srv, Method::PUT, &format!("/api/v1/hosts/{host}"), &ana, Some(json!({"label": "web", "address": "web.example.com", "settings": {"username": "root"},
        "sealed": {"key_version": version, "blob_b64": sealed(&vk, vault, version, host, "ana-pw")}}))).await;
    fok(&srv, Method::PUT, &format!("/api/v1/hosts/{host}"), &ana, Some(json!({"label": "web2", "address": "web.example.com", "settings": {"username": "root"}}))).await;
    let rec = change_of(&sync(&srv, &ana, true, json!([])).await, &host_s)
        .unwrap()
        .clone();
    let plain = e2ee::decrypt_secret(
        &vk,
        vault,
        version,
        EntityKind::Host,
        host,
        rec["sealed"]["blob_b64"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&plain).unwrap()["password"],
        "ana-pw"
    );
    // A server-side move out of the vault would need the secret.
    let other = srv.vault(&ana, "Other").await;
    let r = freq(
        &srv,
        Method::POST,
        &format!("/api/v1/vaults/{other}/transfer"),
        &ana,
        Some(json!({"mode": "move", "items": [{"kind": "host", "id": host}]})),
    )
    .await;
    assert_eq!((r.status, r.code()), (409, "e2ee_vault"), "{}", r.body);

    // --- Bob is no longer an Editor: rotate ---
    fok(
        &srv,
        Method::PATCH,
        &format!("/api/v1/vaults/{vault}/members/{bob_grant}"),
        &ana,
        Some(json!({"role": "use_only"})),
    )
    .await;
    let v = fok(
        &srv,
        Method::GET,
        &format!("/api/v1/vaults/{vault}"),
        &ana,
        None,
    )
    .await;
    assert_eq!(v["e2ee"]["rekey_needed"], true, "{v}");
    let v2 = version + 1;
    let vk2 = VaultKey::generate();
    let r = freq(&srv, Method::POST, &format!("/api/v1/vaults/{vault}/e2ee/rotate"), &ana, Some(json!({"from_version": version,
        "wraps": [wrap(&vk2, vault, v2, &ana, &ka), wrap(&vk2, vault, v2, &bob, &kb)],
        "items": [{"id": host, "kind": "host", "blob_b64": sealed(&vk2, vault, v2, host, "ana-pw")}]}))).await;
    assert_eq!((r.status, r.code()), (400, "e2ee_wrap_invalid"));
    fok(&srv, Method::POST, &format!("/api/v1/vaults/{vault}/e2ee/rotate"), &ana, Some(json!({"from_version": version,
        "wraps": [wrap(&vk2, vault, v2, &ana, &ka)],
        "items": [{"id": host, "kind": "host", "blob_b64": sealed(&vk2, vault, v2, host, "ana-pw")}]}))).await;
    let v = fok(
        &srv,
        Method::GET,
        &format!("/api/v1/vaults/{vault}"),
        &ana,
        None,
    )
    .await;
    assert_eq!(
        (v["e2ee"]["rekey_needed"].clone(), v["key_version"].clone()),
        (json!(false), json!(v2))
    );
    // Bob is an Editor again: he waits for a wrap; Ana gives it.
    fok(
        &srv,
        Method::PATCH,
        &format!("/api/v1/vaults/{vault}/members/{bob_grant}"),
        &ana,
        Some(json!({"role": "editor"})),
    )
    .await;
    let v = fok(
        &srv,
        Method::GET,
        &format!("/api/v1/vaults/{vault}"),
        &ana,
        None,
    )
    .await;
    assert_eq!(v["e2ee"]["pending"][0]["user_id"], bob.id, "{v}");
    assert_eq!(v["e2ee"]["pending"][0]["fingerprint"], kb.fingerprint());
    fok(
        &srv,
        Method::POST,
        &format!("/api/v1/vaults/{vault}/e2ee/wraps"),
        &ana,
        Some(json!({"version": v2, "wraps": [wrap(&vk2, vault, v2, &bob, &kb)]})),
    )
    .await;
    let v = fok(
        &srv,
        Method::GET,
        &format!("/api/v1/vaults/{vault}"),
        &bob,
        None,
    )
    .await;
    assert!(v["e2ee"]["wrap"].is_string());

    // --- Off again: the server reads the secret ---
    fok(
        &srv,
        Method::POST,
        &format!("/api/v1/vaults/{vault}/e2ee/disable"),
        &ana,
        Some(json!({"items": [{"id": host, "kind": "host", "secret": {"password": "back"}}]})),
    )
    .await;
    let s = fok(
        &srv,
        Method::GET,
        &format!("/api/v1/hosts/{host}/secret"),
        &ana,
        None,
    )
    .await;
    assert_eq!(s["password"], "back");
    let vaults = srv.get("/api/v1/vaults", &ana).await.body;
    assert!(
        vaults
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["id"] == vault_s),
        "visible to every client again"
    );

    // --- Audited ---
    let audit = fok(
        &srv,
        Method::GET,
        &format!("/api/v1/vaults/{vault}/audit?action=e2ee.*"),
        &ana,
        None,
    )
    .await;
    let actions: Vec<&str> = audit
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    for a in [
        "e2ee.enable",
        "e2ee.rotate",
        "e2ee.wraps_add",
        "e2ee.disable",
    ] {
        assert!(actions.contains(&a), "{a} in {actions:?}");
    }
}

#[tokio::test]
async fn per_session_unlock_reaches_a_real_sshd() {
    let Some(sshd) = common::start_sshd() else {
        eprintln!("no sshd: skipped");
        return;
    };
    let srv = Srv::start().await;
    let ana = srv.user("Ana").await;
    let vault_s = srv.vault(&ana, "Ops").await;
    let vault: Id = vault_s.parse().unwrap();
    // The key goes in the host's own secret (sealed).
    let h = srv
        .ok(
            "/api/v1/hosts",
            &ana,
            json!({"label": "box", "address": "127.0.0.1", "settings": {"username": sshd.user, "port": sshd.port},
                   "vault_id": vault_s, "secret": {"password": "unused"}}),
        )
        .await;
    let host: Id = h["id"].as_str().unwrap().parse().unwrap();
    let (ka, _) = setup(&srv, &ana).await;
    let st = fok(
        &srv,
        Method::GET,
        &format!("/api/v1/vaults/{vault}/e2ee"),
        &ana,
        None,
    )
    .await;
    let version = st["next_version"].as_u64().unwrap() as u32;
    let vk = VaultKey::generate();
    fok(&srv, Method::POST, &format!("/api/v1/vaults/{vault}/e2ee/enable"), &ana, Some(json!({"version": version,
        "wraps": [wrap(&vk, vault, version, &ana, &ka)],
        "items": [{"id": host, "kind": "host", "blob_b64": sealed(&vk, vault, version, host, "unused")}]}))).await;

    // Without an unlock the server has nothing to sign in with.
    let r = freq(
        &srv,
        Method::POST,
        &format!("/api/v1/hosts/{host}/test?trust=true"),
        &ana,
        Some(json!({})),
    )
    .await;
    assert_eq!(
        (r.status, r.code()),
        (409, "e2ee_unlock_required"),
        "{}",
        r.body
    );
    let r = freq(
        &srv,
        Method::POST,
        "/api/v1/sessions",
        &ana,
        Some(json!({"host_id": host})),
    )
    .await;
    assert_eq!(
        (r.status, r.code()),
        (409, "e2ee_unlock_required"),
        "{}",
        r.body
    );
    // The device sends the key for this test only.
    let unlock = json!({"hops": [{"host_id": host, "key": {"private_key": sshd.private_key}}]});
    let t = fok(
        &srv,
        Method::POST,
        &format!("/api/v1/hosts/{host}/test?trust=true"),
        &ana,
        Some(json!({"unlock": unlock})),
    )
    .await;
    assert_eq!(t["ok"], true, "{t}");
    // And for a server session.
    let s = fok(
        &srv,
        Method::POST,
        "/api/v1/sessions",
        &ana,
        Some(json!({"host_id": host, "unlock": unlock})),
    )
    .await;
    let sid = s["id"].as_str().unwrap().to_string();
    let mut ws = common::ws_connect(
        &srv.base,
        &format!("/api/v1/sessions/{sid}/ws"),
        Some(&ana.token),
    )
    .await;
    {
        use futures::SinkExt;
        ws.send(tokio_tungstenite::tungstenite::Message::Binary(
            "echo e2ee-$((40+2))\n".as_bytes().to_vec().into(),
        ))
        .await
        .unwrap();
    }
    common::ws_wait_output(&mut ws, "e2ee-42").await;
    let audit = fok(
        &srv,
        Method::GET,
        &format!("/api/v1/vaults/{vault}/audit?action=e2ee.unlock"),
        &ana,
        None,
    )
    .await;
    assert_eq!(audit.as_array().unwrap().len(), 2, "{audit}");
}

#[tokio::test]
async fn pairing_hands_the_key_to_a_new_device() {
    let srv = Srv::start().await;
    let ana = srv.user("Ana").await;
    let (ka, _) = setup(&srv, &ana).await;
    // A second device of Ana's.
    let login: Value = srv
        .http
        .post(format!("{}/api/v1/auth/login", srv.base))
        .json(&json!({"email": ana.email, "password": "secure-password", "device_name": "Phone", "platform": "android"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let phone = User {
        token: login["tokens"]["access_token"].as_str().unwrap().into(),
        id: ana.id.clone(),
        email: ana.email.clone(),
    };
    let mut ws = srv.events(&ana).await;
    let pk = PairingKey::generate();
    let p = fok(
        &srv,
        Method::POST,
        "/api/v1/me/e2ee/pairings",
        &phone,
        Some(json!({"public_key": pk.public_b64()})),
    )
    .await;
    let pid: Id = p["id"].as_str().unwrap().parse().unwrap();
    assert_eq!(p["device_name"], "Phone");
    let ev = wait_event(&mut ws, |v| v["type"] == "e2ee").await;
    assert_eq!(ev["pairing"]["id"], p["id"]);
    // The laptop sees it with the same public key → the same code.
    let list = fok(&srv, Method::GET, "/api/v1/me/e2ee/pairings", &ana, None).await;
    let seen_pk = e2ee::parse_public_key(list[0]["public_key"].as_str().unwrap()).unwrap();
    assert_eq!(
        e2ee::pairing_code(pid, &seen_pk),
        e2ee::pairing_code(pid, pk.public())
    );
    // The phone cannot approve itself.
    let r = freq(
        &srv,
        Method::POST,
        &format!("/api/v1/me/e2ee/pairings/{pid}/decide"),
        &phone,
        Some(json!({"approve": false})),
    )
    .await;
    assert_eq!(r.status, 403);
    let s = e2ee::pairing_seal(id(&ana), pid, &seen_pk, &ka).unwrap();
    fok(
        &srv,
        Method::POST,
        &format!("/api/v1/me/e2ee/pairings/{pid}/decide"),
        &ana,
        Some(json!({"approve": true, "sealed": s})),
    )
    .await;
    // Only the phone gets the sealed key, once.
    let other = fok(
        &srv,
        Method::GET,
        &format!("/api/v1/me/e2ee/pairings/{pid}"),
        &ana,
        None,
    )
    .await;
    assert!(other["sealed"].is_null());
    let got = fok(
        &srv,
        Method::GET,
        &format!("/api/v1/me/e2ee/pairings/{pid}"),
        &phone,
        None,
    )
    .await;
    assert_eq!(got["status"], "approved");
    let key = pk
        .open(id(&ana), pid, got["sealed"].as_str().unwrap())
        .unwrap();
    assert_eq!(key.public(), ka.public());
    let again = fok(
        &srv,
        Method::GET,
        &format!("/api/v1/me/e2ee/pairings/{pid}"),
        &phone,
        None,
    )
    .await;
    assert!(again["sealed"].is_null());
    let audit = fok(
        &srv,
        Method::GET,
        "/api/v1/audit?action=e2ee.pairing_*",
        &ana,
        None,
    )
    .await;
    assert_eq!(audit.as_array().unwrap().len(), 2, "{audit}");
    // Everything lost: reset (a dry run first lists what nobody could open).
    let dry = fok(&srv, Method::DELETE, "/api/v1/me/e2ee", &ana, None).await;
    assert_eq!(
        (dry["reset"].clone(), dry["orphaned_vaults"].clone()),
        (json!(false), json!([]))
    );
    fok(
        &srv,
        Method::DELETE,
        "/api/v1/me/e2ee?confirm=reset",
        &ana,
        None,
    )
    .await;
    let me = fok(&srv, Method::GET, "/api/v1/me/e2ee", &ana, None).await;
    assert!(me["key"].is_null() && me["seals"] == json!([]), "{me}");
    let _ = base64::engine::general_purpose::STANDARD.encode([0u8]);
}

#[tokio::test]
async fn legacy_sync_refuses_an_e2ee_personal_vault() {
    let srv = Srv::start().await;
    let ana = srv.user("Ana").await;
    let host_s = srv.host(&ana, &ana.id, "web", "pw").await;
    let host: Id = host_s.parse().unwrap();
    let personal: Id = ana.id.parse().unwrap();
    let (ka, _) = setup(&srv, &ana).await;
    let st = fok(
        &srv,
        Method::GET,
        &format!("/api/v1/vaults/{personal}/e2ee"),
        &ana,
        None,
    )
    .await;
    let version = st["next_version"].as_u64().unwrap() as u32;
    let vk = VaultKey::generate();
    fok(&srv, Method::POST, &format!("/api/v1/vaults/{personal}/e2ee/enable"), &ana, Some(json!({"version": version,
        "wraps": [wrap(&vk, personal, version, &ana, &ka)],
        "items": [{"id": host, "kind": "host", "blob_b64": sealed(&vk, personal, version, host, "pw")}]}))).await;
    let r = srv
        .post("/api/v1/sync", &ana, json!({"since": 0, "changes": []}))
        .await;
    assert_eq!(
        (r.status, r.code()),
        (409, "e2ee_client_required"),
        "{}",
        r.body
    );
}
