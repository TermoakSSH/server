//! Private networks (0.7): the entity, its sync with old and new clients,
//! the compatibility of hosts edited by apps that do not know
//! `settings.network_id`, the `max_networks` limit, and the relay and
//! server sessions through a fake `termoak-netd`.

mod common;

use std::time::Duration;

use common::netd::{self, FakeNetd};
use common::srv::{Srv, User};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message as WsMsg;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

fn find<'a>(changes: &'a Value, id: &str) -> Option<&'a Value> {
    changes.as_array().unwrap().iter().find(|c| c["id"] == id)
}

fn wireguard(name: &str, vault: &str) -> Value {
    json!({
        "name": name, "kind": "wireguard", "vault_id": vault,
        "wireguard": {"addresses": ["10.9.0.2/32"], "peers": [{
            "public_key": "cGVlcg==", "endpoint": "vpn.example.com:51820",
            "allowed_ips": ["10.9.0.0/24"]}]},
        "secret": {"private_key": "cHJpdmF0ZQ=="}
    })
}

async fn network(srv: &Srv, u: &User, vault: &str, name: &str) -> String {
    srv.ok("/api/v1/networks", u, wireguard(name, vault)).await["id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// A host of `vault` at 127.0.0.1:`port` through `network`.
async fn net_host(srv: &Srv, u: &User, vault: &str, port: u16, network: Option<&str>) -> String {
    srv.ok(
        "/api/v1/hosts",
        u,
        json!({"label": "nas", "address": "127.0.0.1", "vault_id": vault,
               "settings": {"username": "root", "port": port, "network_id": network}}),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn with_netd(
    configure: impl FnOnce(&mut termoak_server::config::ServerConfig),
) -> (Srv, FakeNetd) {
    let fake = netd::start().await;
    let socket = fake.socket.clone();
    let srv = Srv::start_with(move |c| {
        c.networks.netd_socket = Some(socket);
        configure(c);
    })
    .await;
    // The first health check runs right away.
    for _ in 0..50 {
        let info: Value = reqwest::get(format!("{}/api/v1/info", srv.base))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if info["features"]["networks"] == true {
            return (srv, fake);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("features.networks never became true");
}

async fn echo_server() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = c.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Opens the relay; `Err((status, body))` when refused before the upgrade.
async fn relay(srv: &Srv, u: &User, host: &str) -> Result<Ws, (u16, Value)> {
    let url = format!(
        "{}/api/v1/hosts/{host}/relay",
        srv.base.replace("http://", "ws://")
    );
    let mut req = url.into_client_request().unwrap();
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {}", u.token).parse().unwrap(),
    );
    match tokio_tungstenite::connect_async(req).await {
        Ok((ws, _)) => Ok(ws),
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            let status = resp.status().as_u16();
            let body = resp
                .body()
                .as_deref()
                .and_then(|b| serde_json::from_slice(b).ok())
                .unwrap_or(Value::Null);
            Err((status, body))
        }
        Err(e) => panic!("relay: {e}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn networks_sync_only_to_clients_that_know_them_and_old_apps_keep_them() {
    let srv = Srv::start().await;
    let ana = srv.user("Ana").await;
    let info: Value = reqwest::get(format!("{}/api/v1/info", srv.base))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["features"]["networks"], false, "no netd: off");

    // CRUD with the secret apart.
    let net = network(&srv, &ana, &ana.id, "office").await;
    let got = srv.get(&format!("/api/v1/networks/{net}"), &ana).await;
    assert_eq!(got.body["kind"], "wireguard");
    assert_eq!(got.body["has_secret"], true);
    assert!(got.body.get("secret").is_none());
    let secret = srv
        .get(&format!("/api/v1/networks/{net}/secret"), &ana)
        .await;
    assert_eq!(secret.body["private_key"], "cHJpdmF0ZQ==");
    let bad = srv
        .post(
            "/api/v1/networks",
            &ana,
            json!({"name": "zt", "kind": "zerotier", "zerotier": {"network_id": "nope"}}),
        )
        .await;
    assert_eq!(bad.status, 400, "{}", bad.body);

    // A host in the network.
    let host = net_host(&srv, &ana, &ana.id, 22, Some(&net)).await;
    let h = srv.get(&format!("/api/v1/hosts/{host}"), &ana).await.body;
    assert_eq!(h["settings"]["network_id"], net);

    // REST: a client that does not know the field (the web, apps before
    // 0.7) leaves it out and it is kept; `null` clears it.
    let mut old = h.clone();
    old["settings"]
        .as_object_mut()
        .unwrap()
        .remove("network_id");
    old["label"] = json!("nas (renamed)");
    let r = srv.put(&format!("/api/v1/hosts/{host}"), &ana, old).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["label"], "nas (renamed)");
    assert_eq!(r.body["settings"]["network_id"], net);
    let mut bare = h.clone();
    bare.as_object_mut().unwrap().remove("settings");
    let r = srv.put(&format!("/api/v1/hosts/{host}"), &ana, bare).await;
    assert_eq!(r.body["settings"]["network_id"], net, "{}", r.body);

    // Legacy sync (apps before vaults, cores 0.2/0.3): no networks at all.
    let legacy = srv
        .ok("/api/v1/sync", &ana, json!({"since": 0, "changes": []}))
        .await;
    assert!(find(&legacy["changes"], &host).is_some());
    assert!(find(&legacy["changes"], &net).is_none(), "{legacy}");
    assert!(
        legacy["changes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["kind"] != "network")
    );
    // The old app edits the host without the field: kept.
    let mut data = find(&legacy["changes"], &host).unwrap()["data"].clone();
    data["settings"]
        .as_object_mut()
        .unwrap()
        .remove("network_id");
    data["label"] = json!("nas (old app)");
    let now = termoak_core::time::now_ms() + 1000;
    let rev = legacy["rev"].as_i64().unwrap();
    let r = srv
        .ok(
            "/api/v1/sync",
            &ana,
            json!({"since": rev, "changes": [
                {"id": host, "kind": "host", "data": data, "sync_mode": "synced",
                 "updated_at": now, "deleted": false},
                // A network pushed on this protocol is ignored.
                {"id": termoak_core::new_id(), "kind": "network",
                 "data": {"name": "x", "kind": "wireguard"}, "sync_mode": "synced",
                 "updated_at": now, "deleted": false}
            ]}),
        )
        .await;
    assert_eq!(r["accepted"], json!([host]));
    assert!(
        r["changes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["kind"] != "network")
    );
    let h = srv.get(&format!("/api/v1/hosts/{host}"), &ana).await.body;
    assert_eq!(h["label"], "nas (old app)");
    assert_eq!(h["settings"]["network_id"], net);
    assert_eq!(
        srv.get("/api/v1/networks", &ana)
            .await
            .body
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // Sync v2 without `kinds` (cores 0.4–0.6): no networks either.
    let v2 = srv
        .ok(
            "/api/v1/vaults/sync",
            &ana,
            json!({"vaults": [], "changes": []}),
        )
        .await;
    assert!(find(&v2["changes"], &host).is_some());
    assert!(find(&v2["changes"], &net).is_none(), "{v2}");
    // With `kinds` (0.7): the network, with its secret.
    let kinds = termoak_client::sync::known_kinds();
    let v2 = srv
        .ok(
            "/api/v1/vaults/sync",
            &ana,
            json!({"vaults": [], "changes": [], "kinds": kinds}),
        )
        .await;
    let rec = find(&v2["changes"], &net).expect("network for 0.7 clients");
    assert_eq!(rec["kind"], "network");
    assert_eq!(rec["secret"]["private_key"], "cHJpdmF0ZQ==");
    // Its deletion reaches only clients that know it too.
    let cursor = v2["cursors"].clone();
    srv.delete(&format!("/api/v1/hosts/{host}"), &ana).await;
    let r = srv.delete(&format!("/api/v1/networks/{net}"), &ana).await;
    assert_eq!(r.status, 200);
    let old = srv
        .ok(
            "/api/v1/vaults/sync",
            &ana,
            json!({"vaults": cursor, "changes": []}),
        )
        .await;
    assert!(find(&old["changes"], &net).is_none(), "{old}");
    assert!(find(&old["changes"], &host).is_some());
    let new = srv
        .ok(
            "/api/v1/vaults/sync",
            &ana,
            json!({"vaults": cursor, "changes": [], "kinds": kinds}),
        )
        .await;
    assert_eq!(find(&new["changes"], &net).unwrap()["deleted"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn network_hosts_never_connect_directly_without_netd() {
    let srv = Srv::start().await;
    let ana = srv.user("Ana").await;
    let port = echo_server().await;
    let net = network(&srv, &ana, &ana.id, "office").await;
    let host = net_host(&srv, &ana, &ana.id, port, Some(&net)).await;

    // Relay, server session and connection test: network_unavailable.
    let (status, body) = relay(&srv, &ana, &host).await.err().unwrap();
    assert_eq!(status, 503);
    assert_eq!(body["error"]["code"], "network_unavailable");
    let r = srv
        .post(
            "/api/v1/sessions",
            &ana,
            json!({"host_id": host, "cols": 80, "rows": 24}),
        )
        .await;
    assert_eq!(r.status, 503, "{}", r.body);
    assert_eq!(r.code(), "network_unavailable");
    let t = srv
        .post(&format!("/api/v1/hosts/{host}/test"), &ana, json!({}))
        .await;
    assert_eq!(t.body["ok"], false);
    assert_eq!(t.body["error_code"], "network_unavailable");
    let r = srv
        .get(&format!("/api/v1/networks/{net}/status"), &ana)
        .await;
    assert_eq!((r.status, r.code()), (503, "network_unavailable"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn max_networks_counts_for_the_vault_owner_and_the_team_owner() {
    let srv = Srv::start_with(|c| {
        for p in &mut c.plans.catalog {
            p.limits.max_networks = Some(2);
        }
    })
    .await;
    let _admin = srv.user("Admin").await; // the first user has no limits
    let ana = srv.user("Ana").await;
    let bea = srv.user("Bea").await;
    // The default plan says 10 when not configured.
    let plans: Value = reqwest::get(format!("{}/api/v1/plans", srv.base))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(plans["plans"][0]["limits"]["max_networks"], 2);
    assert_eq!(
        termoak_server::config::PlanLimits::default().max_networks,
        Some(10)
    );

    let ops = srv.vault(&ana, "Ops").await;
    network(&srv, &ana, &ana.id, "one").await;
    network(&srv, &ana, &ops, "two").await;
    let r = srv
        .post("/api/v1/networks", &ana, wireguard("three", &ana.id))
        .await;
    assert_eq!((r.status, r.code()), (403, "plan_limit"), "{}", r.body);
    assert_eq!(r.body["error"]["limit"], "max_networks");
    assert_eq!(r.body["error"]["max"], 2);
    let mine = srv.get("/api/v1/me/plan", &ana).await;
    assert_eq!(mine.body["usage"]["networks"], 2);

    // Sync v2 pushes over the limit come back rejected.
    let id = termoak_core::new_id().to_string();
    let r = srv
        .ok(
            "/api/v1/vaults/sync",
            &ana,
            json!({"vaults": [], "kinds": ["network"], "changes": [{
                "id": id, "kind": "network", "vault_id": ana.id,
                "data": {"name": "pushed", "kind": "tailscale"},
                "sync_mode": "synced", "updated_at": termoak_core::time::now_ms(),
                "deleted": false}]}),
        )
        .await;
    assert_eq!(r["rejected"][0]["id"], id);
    assert_eq!(r["rejected"][0]["code"], "plan_limit");
    assert!(
        srv.get(&format!("/api/v1/networks/{id}"), &ana)
            .await
            .status
            == 404
    );

    // Team vault: billed to the team owner (Bea), not to who creates it.
    let team = srv
        .ok("/api/v1/teams", &bea, json!({"name": "Infra"}))
        .await;
    let team_id = team["id"].as_str().unwrap();
    srv.ok(
        &format!("/api/v1/teams/{team_id}/members"),
        &bea,
        json!({"email": ana.email, "role": "admin"}),
    )
    .await;
    let tv = srv
        .ok(
            "/api/v1/vaults",
            &ana,
            json!({"name": "Team", "team_id": team_id}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    network(&srv, &ana, &tv, "team-1").await;
    network(&srv, &ana, &tv, "team-2").await;
    let r = srv
        .post("/api/v1/networks", &ana, wireguard("team-3", &tv))
        .await;
    assert_eq!(r.code(), "plan_limit");
    assert_eq!(
        srv.get("/api/v1/me/plan", &bea).await.body["usage"]["networks"],
        2
    );
    assert_eq!(
        srv.get("/api/v1/me/plan", &ana).await.body["usage"]["networks"],
        2
    );

    // Transfers: a host brings its network along. Into a vault billed to
    // the same user it is not new; a copy into the team vault (Bea is at
    // her limit) is.
    let one = srv.get("/api/v1/networks", &ana).await.body;
    let one = one
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["name"] == "one")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let host = net_host(&srv, &ana, &ana.id, 22, Some(&one)).await;
    let r = srv
        .post(
            &format!("/api/v1/vaults/{tv}/transfer"),
            &ana,
            json!({"mode": "copy", "items": [{"kind": "host", "id": host}]}),
        )
        .await;
    assert_eq!((r.status, r.code()), (403, "plan_limit"), "{}", r.body);
    let r = srv
        .post(
            &format!("/api/v1/vaults/{ops}/transfer"),
            &ana,
            json!({"mode": "move", "items": [{"kind": "host", "id": host}]}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let moved = srv.get(&format!("/api/v1/hosts/{host}"), &ana).await.body;
    assert_eq!(moved["vault_id"], ops);
    assert_eq!(moved["settings"]["network_id"], one);
    let net = srv.get(&format!("/api/v1/networks/{one}"), &ana).await.body;
    assert_eq!(net["vault_id"], ops, "the network moved with its host");
    assert_eq!(
        srv.get("/api/v1/me/plan", &ana).await.body["usage"]["networks"],
        2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_pipes_bytes_through_netd_and_only_for_who_may_use_the_host() {
    let (srv, fake) = with_netd(|c| c.networks.max_relays_per_user = 2).await;
    let ana = srv.user("Ana").await;
    let bea = srv.user("Bea").await;
    let port = echo_server().await;
    let ops = srv.vault(&ana, "Ops").await;
    let net = network(&srv, &ana, &ops, "office").await;
    let host = net_host(&srv, &ana, &ops, port, Some(&net)).await;

    let mut ws = relay(&srv, &ana, &host).await.unwrap();
    let data: Vec<u8> = (0..100_000u32).map(|i| (i % 253) as u8).collect();
    for chunk in data.chunks(10_000) {
        ws.send(WsMsg::Binary(chunk.to_vec().into())).await.unwrap();
    }
    let mut got = Vec::new();
    while got.len() < data.len() {
        match tokio::time::timeout(Duration::from_secs(10), ws.next()).await {
            Ok(Some(Ok(WsMsg::Binary(b)))) => got.extend_from_slice(&b),
            Ok(Some(Ok(_))) => {}
            other => panic!("relay ended: {other:?}"),
        }
    }
    assert_eq!(got, data);
    ws.close(None).await.unwrap();
    // netd dialed the host's address inside the host's network, with the
    // network's config and secret.
    let dial = fake.dials().last().cloned().unwrap();
    assert_eq!(
        (dial.network_id.as_str(), dial.kind.as_str()),
        (net.as_str(), "wireguard")
    );
    assert_eq!((dial.host.as_str(), dial.port), ("127.0.0.1", port));
    assert_eq!(dial.secret["private_key"], "cHJpdmF0ZQ==");
    assert_eq!(dial.revision.len(), 16);

    // Audited with the bytes.
    let mut closed = Value::Null;
    for _ in 0..50 {
        let audit = srv
            .get(&format!("/api/v1/vaults/{ops}/audit"), &ana)
            .await
            .body;
        if let Some(e) = audit
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["action"] == "relay.close")
        {
            closed = e.clone();
            assert!(
                audit
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|e| e["action"] == "relay.open")
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(closed["detail"]["bytes_up"], 100_000, "{closed}");
    assert_eq!(closed["detail"]["bytes_down"], 100_000);
    assert_eq!(closed["detail"]["network"], "office");

    // Someone without access to the vault: not found (no dial).
    let dials = fake.dials().len();
    let (status, _) = relay(&srv, &bea, &host).await.err().unwrap();
    assert_eq!(status, 404);
    // Bea cannot point her own host at Ana's network either.
    let r = srv
        .post(
            "/api/v1/hosts",
            &bea,
            json!({"label": "steal", "address": "127.0.0.1",
                   "settings": {"username": "x", "network_id": net}}),
        )
        .await;
    assert_eq!(r.code(), "cross_vault_reference", "{}", r.body);
    // Use-only in a Strict vault: only through the server.
    srv.share(&ana, &ops, &bea, "use_only").await;
    let s = srv
        .patch(
            &format!("/api/v1/vaults/{ops}"),
            &ana,
            json!({"settings": {"use_only_local": false}}),
        )
        .await;
    assert_eq!(s.status, 200, "{}", s.body);
    let (status, body) = relay(&srv, &bea, &host).await.err().unwrap();
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (403, Some("use_only_strict"))
    );
    // Not Strict: Use-only members may relay.
    srv.patch(
        &format!("/api/v1/vaults/{ops}"),
        &ana,
        json!({"settings": {"use_only_local": true}}),
    )
    .await;
    let mut ws = relay(&srv, &bea, &host).await.unwrap();
    ws.send(WsMsg::Binary(b"hi".to_vec().into())).await.unwrap();
    loop {
        match tokio::time::timeout(Duration::from_secs(10), ws.next()).await {
            Ok(Some(Ok(WsMsg::Binary(b)))) => {
                assert_eq!(&b[..], b"hi");
                break;
            }
            Ok(Some(Ok(_))) => {}
            other => panic!("relay ended: {other:?}"),
        }
    }
    assert_eq!(fake.dials().len(), dials + 1);

    // A host without a network: the relay is not for it.
    let direct = net_host(&srv, &ana, &ops, port, None).await;
    let (status, body) = relay(&srv, &ana, &direct).await.err().unwrap();
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (422, Some("not_in_network"))
    );
    // A host that cannot be reached: network_dial_failed.
    let down = net_host(&srv, &ana, &ops, 1, Some(&net)).await;
    let (status, body) = relay(&srv, &ana, &down).await.err().unwrap();
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (502, Some("network_dial_failed"))
    );
    assert_eq!(body["error"]["netd_code"], "dial_failed");

    // At most 2 relays per user.
    let _a = relay(&srv, &ana, &host).await.unwrap();
    let _b = relay(&srv, &ana, &host).await.unwrap();
    let (status, body) = relay(&srv, &ana, &host).await.err().unwrap();
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (429, Some("relay_limit"))
    );

    // netd state of the network.
    let up = srv
        .ok(&format!("/api/v1/networks/{net}/up"), &ana, json!({}))
        .await;
    assert_eq!(up["state"], "up");
    assert_eq!(up["node"]["public_key"], "ZmFrZQ==");
    let st = srv
        .get(&format!("/api/v1/networks/{net}/status"), &bea)
        .await;
    assert_eq!(st.body["state"], "up", "{}", st.body);
    let peers = srv
        .get(&format!("/api/v1/networks/{net}/peers"), &ana)
        .await;
    assert_eq!(peers.body[0]["name"], "nas");
    // Use-only members cannot bring networks up or list their devices.
    let r = srv
        .post(&format!("/api/v1/networks/{net}/up"), &bea, json!({}))
        .await;
    assert_eq!(r.code(), "vault_read_only");
    // A kind this netd cannot join.
    let zt = srv
        .ok(
            "/api/v1/networks",
            &ana,
            json!({"name": "zt", "kind": "zerotier", "vault_id": ops,
                   "zerotier": {"network_id": "8056c2e21c000001"}}),
        )
        .await;
    let r = srv
        .post(
            &format!("/api/v1/networks/{}/up", zt["id"].as_str().unwrap()),
            &ana,
            json!({}),
        )
        .await;
    assert_eq!(
        (r.status, r.code()),
        (503, "network_unavailable"),
        "{}",
        r.body
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_sessions_and_the_apps_reach_hosts_through_the_network() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let Some(sshd) = common::start_sshd() else {
        eprintln!("sshd not available: test skipped");
        return;
    };
    let (srv, fake) = with_netd(|_| {}).await;
    let ana = srv.user("Ana").await;
    let net = network(&srv, &ana, &ana.id, "office").await;
    let key = srv
        .ok(
            "/api/v1/keys/import",
            &ana,
            json!({"label": "k", "private_key": sshd.private_key}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    // The network comes from the group.
    let group = srv
        .ok(
            "/api/v1/groups",
            &ana,
            json!({"name": "lan", "settings": {"network_id": net}}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let host = srv
        .ok(
            "/api/v1/hosts",
            &ana,
            json!({"label": "local", "address": "127.0.0.1", "group_id": group,
                   "settings": {"username": sshd.user, "port": sshd.port, "key_id": key}}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Connection test and exec from the server go through netd.
    let t = srv
        .post(
            &format!("/api/v1/hosts/{host}/test?trust=true"),
            &ana,
            json!({}),
        )
        .await;
    assert_eq!(t.body["ok"], true, "{}", t.body);
    assert_eq!(fake.dials().last().unwrap().port, sshd.port);
    let out = srv
        .ok(
            "/api/v1/exec",
            &ana,
            json!({"host_ids": [host], "command": "echo via-$((6*7))"}),
        )
        .await;
    assert_eq!(out[0]["stdout"].as_str().unwrap().trim(), "via-42", "{out}");

    // A server session.
    let dials = fake.dials().len();
    let s = srv
        .ok(
            "/api/v1/sessions",
            &ana,
            json!({"host_id": host, "cols": 80, "rows": 24}),
        )
        .await;
    let id = s["id"].as_str().unwrap();
    let mut ws = common::ws_connect(
        &srv.base,
        &format!("/api/v1/sessions/{id}/ws"),
        Some(&ana.token),
    )
    .await;
    common::ws_wait_json(&mut ws, "hello").await;
    ws.send(WsMsg::Binary(b"echo net-$((5*5))\n".to_vec().into()))
        .await
        .unwrap();
    common::ws_wait_output(&mut ws, "net-25").await;
    assert_eq!(fake.dials().len(), dials + 1);
    assert_eq!(fake.dials().last().unwrap().network_id, net);

    // An app (the mobile engine): its SSH connection goes over the relay,
    // end to end with the host.
    let dials = fake.dials().len();
    let (base, email, h) = (srv.base.clone(), ana.email.clone(), host.clone());
    let stdout = tokio::task::spawn_blocking(move || {
        use futures::executor::block_on;
        struct Trust;
        impl termoak_ffi::AuthHandler for Trust {
            fn on_host_key(&self, _: String, _: u32, _: String, _: String) -> bool {
                true
            }
            fn on_prompt(&self, _: termoak_ffi::AuthRequest) -> Option<Vec<String>> {
                None
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let core = termoak_ffi::TermoakCore::new(
            dir.path().to_string_lossy().into_owned(),
            termoak_ffi::generate_vault_key(),
        )
        .unwrap();
        block_on(core.login(base, email, "secure-password".into(), None)).unwrap();
        block_on(core.sync_now()).unwrap();
        assert_eq!(core.list_networks(None).unwrap().len(), 1);
        let session = block_on(core.connect(h, std::sync::Arc::new(Trust), None, None)).unwrap();
        let out = block_on(session.exec("echo app-$((2*21))".into(), 30)).unwrap();
        out.stdout
    })
    .await
    .unwrap();
    assert_eq!(stdout.trim(), "app-42");
    assert_eq!(
        fake.dials().len(),
        dials + 1,
        "the app went through the relay"
    );
    let audit = srv.get("/api/v1/audit", &ana).await.body;
    assert!(
        audit
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "relay.open"),
        "{audit}"
    );

    // A raw relay carries SSH too (the SSH banner arrives).
    let mut ws = relay(&srv, &ana, &host).await.unwrap();
    let banner = loop {
        match tokio::time::timeout(Duration::from_secs(10), ws.next()).await {
            Ok(Some(Ok(WsMsg::Binary(b)))) => break b,
            Ok(Some(Ok(_))) => {}
            other => panic!("relay ended: {other:?}"),
        }
    };
    assert!(banner.starts_with(b"SSH-2.0-"), "{banner:?}");
}

/// RFC 7748 §6.1 (Alice): a private key and its public key.
const RFC_PRIVATE: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=";
const RFC_PUBLIC: &str = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wireguard_keys_and_netd_follow_the_vaults() {
    assert_eq!(
        termoak_server::routes::networks::wireguard_public_key(RFC_PRIVATE).as_deref(),
        Some(RFC_PUBLIC)
    );
    assert_eq!(
        termoak_server::routes::networks::wireguard_public_key("cHJpdmF0ZQ=="),
        None
    );
    let (srv, fake) = with_netd(|_| {}).await;
    let ana = srv.user("Ana").await;
    let bob = srv.user("Bob").await;

    // Generate the key on the server: the public key comes back and stays
    // in the network; the private key only in the secret.
    let net = srv
        .ok(
            "/api/v1/networks",
            &ana,
            json!({"name": "office", "kind": "wireguard",
                   "wireguard": {"addresses": ["10.9.0.2/32"], "peers": [{
                       "public_key": RFC_PUBLIC, "endpoint": "vpn.example.com:51820",
                       "allowed_ips": ["10.9.0.0/24"]}]}}),
        )
        .await;
    let id = net["id"].as_str().unwrap().to_string();
    assert!(net["wireguard"]["public_key"].is_null(), "{net}");
    let key_path = format!("/api/v1/networks/{id}/wireguard/key");
    let gen1 = srv.ok(&key_path, &ana, json!({})).await;
    let public = gen1["public_key"].as_str().unwrap().to_string();
    assert_eq!(public.len(), 44);
    assert_eq!(gen1["network"]["wireguard"]["public_key"], public);
    assert_eq!(gen1["network"]["has_secret"], true);
    let secret = srv
        .get(&format!("/api/v1/networks/{id}/secret"), &ana)
        .await;
    let private = secret.body["private_key"].as_str().unwrap();
    assert_eq!(
        termoak_server::routes::networks::wireguard_public_key(private).as_deref(),
        Some(public.as_str())
    );
    let got = srv.get(&format!("/api/v1/networks/{id}"), &ana).await;
    assert_eq!(got.body["wireguard"]["public_key"], public);
    // Again: refused unless replacing.
    let again = srv.post(&key_path, &ana, json!({})).await;
    assert_eq!(
        (again.status, again.body["error"]["code"].as_str()),
        (409, Some("key_exists"))
    );
    let gen2 = srv.ok(&key_path, &ana, json!({"replace": true})).await;
    assert_ne!(gen2["public_key"], public);
    // Others' networks: not found; other kinds: not WireGuard.
    assert_eq!(srv.post(&key_path, &bob, json!({})).await.status, 404);
    let ts = srv
        .ok(
            "/api/v1/networks",
            &ana,
            json!({"name": "tailnet", "kind": "tailscale"}),
        )
        .await;
    let r = srv
        .post(
            &format!(
                "/api/v1/networks/{}/wireguard/key",
                ts["id"].as_str().unwrap()
            ),
            &ana,
            json!({}),
        )
        .await;
    assert_eq!(
        (r.status, r.body["error"]["code"].as_str()),
        (422, Some("not_wireguard"))
    );
    // Audited.
    let audit = srv
        .get(&format!("/api/v1/vaults/{}/audit", ana.id), &ana)
        .await;
    assert!(
        audit
            .body
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "network.key_generated"),
        "{}",
        audit.body
    );

    // A pasted private key: its public key is filled in.
    let pasted = srv
        .ok(
            "/api/v1/networks",
            &ana,
            json!({"name": "pasted", "kind": "wireguard",
                   "wireguard": {"addresses": ["10.9.0.3/32"], "public_key": "bogus", "peers": [{
                       "public_key": RFC_PUBLIC, "allowed_ips": ["10.9.0.0/24"]}]},
                   "secret": {"private_key": RFC_PRIVATE}}),
        )
        .await;
    assert_eq!(pasted["wireguard"]["public_key"], RFC_PUBLIC);
    let pasted_id = pasted["id"].as_str().unwrap().to_string();

    // netd follows the vault: renaming keeps the running node; a new
    // configuration or a deletion takes it down.
    let up = srv
        .ok(&format!("/api/v1/networks/{pasted_id}/up"), &ana, json!({}))
        .await;
    assert_eq!(up["state"], "up");
    let rev = fake.running(&pasted_id).unwrap();
    let mut data = srv
        .get(&format!("/api/v1/networks/{pasted_id}"), &ana)
        .await
        .body;
    data["name"] = json!("pasted (renamed)");
    // The public key a client sends back does not change the revision.
    let r = srv
        .put(&format!("/api/v1/networks/{pasted_id}"), &ana, data.clone())
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["wireguard"]["public_key"], RFC_PUBLIC);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(fake.downs().is_empty(), "{:?}", fake.downs());
    assert_eq!(fake.running(&pasted_id), Some(rev.clone()));
    data["wireguard"]["peers"][0]["endpoint"] = json!("vpn2.example.com:51820");
    let r = srv
        .put(&format!("/api/v1/networks/{pasted_id}"), &ana, data)
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    fake.wait_downs(&pasted_id, 1).await;
    assert_eq!(fake.running(&pasted_id), None);
    srv.ok(&format!("/api/v1/networks/{pasted_id}/up"), &ana, json!({}))
        .await;
    assert_ne!(fake.running(&pasted_id), Some(rev));
    // The host test says through which network it went.
    let host = net_host(&srv, &ana, &ana.id, 1, Some(&pasted_id)).await;
    let test = srv
        .ok(&format!("/api/v1/hosts/{host}/test"), &ana, json!({}))
        .await;
    assert_eq!(test["ok"], false);
    assert_eq!(test["error_code"], "network_dial_failed");
    assert_eq!(test["network"]["id"], pasted_id);
    assert_eq!(test["network"]["kind"], "wireguard");
    srv.delete(&format!("/api/v1/hosts/{host}"), &ana).await;
    let r = srv
        .delete(&format!("/api/v1/networks/{pasted_id}"), &ana)
        .await;
    assert_eq!(r.status, 200);
    fake.wait_downs(&pasted_id, 2).await;

    // Sync v2: a network pushed with only the private key gets its public
    // key in the same answer; a later change takes the running node down.
    let kinds = termoak_client::sync::known_kinds();
    let pushed = termoak_core::new_id().to_string();
    let record = |endpoint: &str, at: i64| {
        json!({"id": pushed, "kind": "network", "vault_id": ana.id, "sync_mode": "synced",
               "updated_at": at, "deleted": false,
               "data": {"id": pushed, "name": "pushed", "kind": "wireguard",
                        "wireguard": {"addresses": ["10.9.0.4/32"], "peers": [{
                            "public_key": RFC_PUBLIC, "endpoint": endpoint,
                            "allowed_ips": ["10.9.0.0/24"]}]}},
               "secret": {"private_key": RFC_PRIVATE}})
    };
    let now = termoak_core::time::now_ms();
    let r = srv
        .ok(
            "/api/v1/vaults/sync",
            &ana,
            json!({"vaults": [], "changes": [record("a.example.com:1", now)], "kinds": kinds}),
        )
        .await;
    let rec = find(&r["changes"], &pushed).expect("pushed network");
    assert_eq!(rec["data"]["wireguard"]["public_key"], RFC_PUBLIC, "{rec}");
    srv.ok(&format!("/api/v1/networks/{pushed}/up"), &ana, json!({}))
        .await;
    srv.ok(
        "/api/v1/vaults/sync",
        &ana,
        json!({"vaults": r["cursors"], "changes": [record("b.example.com:1", now + 1000)],
               "kinds": kinds}),
    )
    .await;
    fake.wait_downs(&pushed, 1).await;

    // Deleting a vault takes its networks down.
    let shared = srv.vault(&ana, "Shared").await;
    let in_shared = network(&srv, &ana, &shared, "shared net").await;
    srv.ok(&format!("/api/v1/networks/{in_shared}/up"), &ana, json!({}))
        .await;
    let r = srv
        .delete(&format!("/api/v1/vaults/{shared}?confirm=Shared"), &ana)
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    fake.wait_downs(&in_shared, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tailscale_networks_are_validated_and_report_logins_and_tailnets() {
    let (srv, fake) = with_netd(|_| {}).await;
    let ana = srv.user("Ana").await;
    let bea = srv.user("Bea").await;
    let ops = srv.vault(&ana, "Ops").await;
    srv.share(&ana, &ops, &bea, "use_only").await;

    // The kinds netd can join.
    let info: Value = reqwest::get(format!("{}/api/v1/info", srv.base))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        info["features"]["network_kinds"],
        json!(["wireguard", "tailscale"])
    );

    // Validation (REST): control URL, hostname, tags, the key's shape (never echoed).
    let tail = |cfg: Value, secret: Value| {
        json!({"name": "tailnet", "kind": "tailscale", "vault_id": ops,
               "tailscale": cfg, "secret": secret})
    };
    for (cfg, secret) in [
        (json!({"control_url": "ftp://hs.example.com"}), json!({})),
        (
            json!({"control_url": "https://user:pw@hs.example.com"}),
            json!({}),
        ),
        (json!({"hostname": "my server"}), json!({})),
        (json!({"tags": ["termoak"]}), json!({})),
        (json!({}), json!({"auth_key": "hskey-auth SECRET"})),
    ] {
        let r = srv
            .post("/api/v1/networks", &ana, tail(cfg.clone(), secret))
            .await;
        assert_eq!(r.status, 400, "{cfg}: {}", r.body);
        assert!(!r.body.to_string().contains("SECRET"), "{}", r.body);
    }
    // With a pre-auth key: up in the tailnet; `ephemeral` is kept as null.
    let keyed = srv
        .ok(
            "/api/v1/networks",
            &ana,
            tail(
                json!({"control_url": "https://hs.example.com", "tags": []}),
                json!({"auth_key": "hskey-auth-ok"}),
            ),
        )
        .await;
    let keyed = keyed["id"].as_str().unwrap().to_string();
    let got = srv
        .get(&format!("/api/v1/networks/{keyed}"), &ana)
        .await
        .body;
    assert!(
        got["tailscale"]
            .as_object()
            .unwrap()
            .contains_key("ephemeral"),
        "{got}"
    );
    let st = srv
        .ok(&format!("/api/v1/networks/{keyed}/up"), &ana, json!({}))
        .await;
    assert_eq!(st["state"], "up", "{st}");
    assert_eq!(st["control_url"], "https://hs.example.com");
    assert_eq!(st["peer_count"], 2);
    assert_eq!(st["tailnet"], "qa");
    assert_eq!(st["node"]["dns_name"], "termoak-test.ts.qa.test");
    let peers = srv
        .get(&format!("/api/v1/networks/{keyed}/peers"), &ana)
        .await
        .body;
    assert_eq!(peers[0]["tags"], json!(["tag:server"]), "{peers}");
    assert_eq!(peers[0]["routes"], json!(["192.168.10.0/24"]));
    assert_eq!(peers[0]["dns_name"], "nas.tail.ts.net");

    // Without a key: needs a login. Editors see the login URL, Use-only
    // members only the state.
    let login = srv
        .ok("/api/v1/networks", &ana, tail(json!({}), json!({})))
        .await;
    let login = login["id"].as_str().unwrap().to_string();
    let st = srv
        .ok(&format!("/api/v1/networks/{login}/up"), &ana, json!({}))
        .await;
    assert_eq!(
        (st["state"].as_str(), st["auth"].as_str()),
        (Some("needs_auth"), Some("login"))
    );
    assert_eq!(
        st["node"]["auth_url"],
        "https://hs.example.com/register/abc"
    );
    let st = srv
        .get(&format!("/api/v1/networks/{login}/status"), &ana)
        .await
        .body;
    assert_eq!(
        st["node"]["auth_url"], "https://hs.example.com/register/abc",
        "{st}"
    );
    let st = srv
        .get(&format!("/api/v1/networks/{login}/status"), &bea)
        .await
        .body;
    assert_eq!(st["auth"], "login", "{st}");
    assert!(st["node"].get("auth_url").is_none(), "{st}");
    // Up is for Editors.
    assert_eq!(
        srv.post(&format!("/api/v1/networks/{login}/up"), &bea, json!({}))
            .await
            .status,
        403
    );
    // Connecting through it: network_dial_failed with netd_code needs_auth
    // and why.
    let host = net_host(&srv, &ana, &ops, 22, Some(&login)).await;
    let (status, body) = relay(&srv, &ana, &host).await.err().unwrap();
    assert_eq!(status, 502, "{body}");
    assert_eq!(body["error"]["code"], "network_dial_failed");
    assert_eq!(body["error"]["netd_code"], "needs_auth");
    assert_eq!(body["error"]["auth"], "login");
    let test = srv
        .ok(&format!("/api/v1/hosts/{host}/test"), &ana, json!({}))
        .await;
    assert_eq!(test["ok"], false, "{test}");
    assert_eq!(test["error_code"], "network_dial_failed");

    // Sync v2 pushes are validated the same way.
    let now = termoak_core::time::now_ms();
    let bad_push = json!({
        "id": uuid::Uuid::now_v7(), "kind": "network", "sync_mode": "synced",
        "updated_at": now, "deleted": false, "rev": 0, "vault_id": ops,
        "data": {"name": "pushed", "kind": "tailscale", "tailscale": {"tags": ["bad"]}},
    });
    let r = srv
        .ok(
            "/api/v1/vaults/sync",
            &ana,
            json!({"vaults": [], "changes": [bad_push], "kinds": ["network"]}),
        )
        .await;
    assert_eq!(r["rejected"][0]["code"], "invalid", "{r}");

    // Deleting a network makes netd forget it (a persistent node logs out),
    // even when it is not running.
    srv.ok(&format!("/api/v1/networks/{login}/down"), &ana, json!({}))
        .await;
    assert!(fake.forgets().is_empty());
    let r = srv.delete(&format!("/api/v1/networks/{login}"), &ana).await;
    assert_eq!(r.status, 200, "{}", r.body);
    for _ in 0..100 {
        if fake.forgets().contains(&login) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(fake.forgets().contains(&login), "{:?}", fake.forgets());
}
