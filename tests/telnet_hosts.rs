//! Hosts through the REST API keep their protocol and logo (`protocol`,
//! `icon`), and Telnet hosts on the server: no server sessions nor tests
//! (`telnet_not_supported`), just-in-time credentials with the Use-only rules
//! (the apps log in to Telnet hosts with the password).

mod common;

use common::srv::{Srv, User};
use serde_json::{Value, json};

async fn create(srv: &Srv, u: &User, body: Value) -> Value {
    let r = srv.post("/api/v1/hosts", u, body).await;
    assert_eq!(r.status, 200, "{}", r.body);
    r.body
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hosts_round_trip_protocol_and_icon() {
    let srv = Srv::start().await;
    let ana = srv.user("Ana").await;

    // Telnet with a logo: stored and returned as sent.
    let telnet = create(
        &srv,
        &ana,
        json!({"label": "switch", "address": "10.0.0.2", "protocol": "telnet",
               "icon": "router", "settings": {"port": 23, "username": "admin"},
               "secret": {"password": "pw-telnet"}}),
    )
    .await;
    assert_eq!(telnet["protocol"], "telnet");
    assert_eq!(telnet["icon"], "router");
    assert_eq!(telnet["settings"]["port"], 23);
    let id = telnet["id"].as_str().unwrap().to_string();

    let one = srv.get(&format!("/api/v1/hosts/{id}"), &ana).await;
    assert_eq!(one.status, 200);
    assert_eq!(
        (&one.body["protocol"], &one.body["icon"]),
        (&json!("telnet"), &json!("router"))
    );
    let list = srv.get("/api/v1/hosts", &ana).await;
    let listed = list
        .body
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["id"] == id.as_str())
        .unwrap()
        .clone();
    assert_eq!(
        (&listed["protocol"], &listed["icon"]),
        (&json!("telnet"), &json!("router"))
    );
    // Never the secret in the list.
    assert!(!list.body.to_string().contains("pw-telnet"));

    // Update: a new logo, still Telnet; the password is kept.
    let r = srv
        .put(
            &format!("/api/v1/hosts/{id}"),
            &ana,
            json!({"label": "switch", "address": "10.0.0.2", "protocol": "telnet",
                   "icon": "server", "settings": {"port": 23, "username": "admin"}}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(
        (&r.body["protocol"], &r.body["icon"]),
        (&json!("telnet"), &json!("server"))
    );
    let secret = srv.get(&format!("/api/v1/hosts/{id}/secret"), &ana).await;
    assert_eq!(secret.body["password"], "pw-telnet");

    // SSH hosts look as before: no `protocol`, no `icon` unless set.
    let ssh = create(
        &srv,
        &ana,
        json!({"label": "web", "address": "web.example.com"}),
    )
    .await;
    assert!(ssh.get("protocol").is_none(), "{ssh}");
    assert!(ssh.get("icon").is_none() || ssh["icon"].is_null(), "{ssh}");
    let ssh_icon = create(
        &srv,
        &ana,
        json!({"label": "db", "address": "db.example.com", "protocol": "ssh", "icon": "database"}),
    )
    .await;
    assert!(ssh_icon.get("protocol").is_none());
    assert_eq!(ssh_icon["icon"], "database");

    // A later version's protocol is kept as it is.
    let other = create(
        &srv,
        &ana,
        json!({"label": "future", "address": "f.example.com", "protocol": "Mosh"}),
    )
    .await;
    assert_eq!(other["protocol"], "mosh");
    let other_id = other["id"].as_str().unwrap();
    let r = srv.get(&format!("/api/v1/hosts/{other_id}"), &ana).await;
    assert_eq!(r.body["protocol"], "mosh");

    // Sync v2 carries them too.
    let r = srv
        .post(
            "/api/v1/vaults/sync",
            &ana,
            json!({"vaults": [], "changes": []}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let text = r.body.to_string();
    assert!(text.contains("\"protocol\":\"telnet\""), "{text}");
    assert!(text.contains("\"icon\":\"server\""), "{text}");

    // No server sessions to Telnet hosts (nor unknown protocols), and the
    // server does not test them.
    let r = srv
        .post(
            "/api/v1/sessions",
            &ana,
            json!({"host_id": id, "cols": 80, "rows": 24}),
        )
        .await;
    assert_eq!(
        (r.status, r.code()),
        (422, "telnet_not_supported"),
        "{}",
        r.body
    );
    let r = srv
        .post(
            "/api/v1/sessions",
            &ana,
            json!({"host_id": other_id, "cols": 80, "rows": 24}),
        )
        .await;
    assert_eq!(
        (r.status, r.code()),
        (422, "protocol_not_supported"),
        "{}",
        r.body
    );
    assert_eq!(r.body["error"]["protocol"], "mosh");
    let sessions = srv.get("/api/v1/sessions", &ana).await;
    assert_eq!(sessions.body["active"], json!([]), "{}", sessions.body);
    let r = srv
        .post(&format!("/api/v1/hosts/{id}/test"), &ana, json!({}))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body["ok"], false);
    assert_eq!(r.body["error_code"], "telnet_not_supported");
    // `/exec` reports it per host.
    let r = srv
        .post(
            "/api/v1/exec",
            &ana,
            json!({"host_ids": [id], "command": "uptime"}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body[0]["ok"], false);
    assert!(
        r.body[0]["error"].as_str().unwrap().contains("Telnet"),
        "{}",
        r.body
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn telnet_credentials_follow_the_use_only_rules() {
    let srv = Srv::start().await;
    srv.user("Root").await;
    let ana = srv.user("Ana").await;
    let carl = srv.user("Carl").await;
    let dan = srv.user("Dan").await;
    let ops = srv.vault(&ana, "Ops").await;
    srv.share(&ana, &ops, &carl, "use_only").await;
    let host = create(
        &srv,
        &ana,
        json!({"label": "switch", "address": "10.0.0.2", "protocol": "telnet",
               "settings": {"port": 23, "username": "admin"},
               "vault_id": ops, "secret": {"password": "pw-telnet"}}),
    )
    .await;
    let id = host["id"].as_str().unwrap().to_string();
    let path = format!("/api/v1/hosts/{id}/credentials");

    // Use-only members see the host (protocol included) but not the secret.
    let r = srv.get(&format!("/api/v1/hosts/{id}"), &carl).await;
    assert_eq!(r.body["protocol"], "telnet");
    let r = srv.get(&format!("/api/v1/hosts/{id}/secret"), &carl).await;
    assert_eq!((r.status, r.code()), (403, "secret_hidden"));

    // The owner and Use-only members (vault not Strict) get the password for
    // the automatic login, with `ssh` (what the apps send) or `telnet`.
    for (u, purpose) in [(&ana, "ssh"), (&carl, "ssh"), (&carl, "telnet")] {
        let r = srv.post(&path, u, json!({"purpose": purpose})).await;
        assert_eq!(r.status, 200, "{purpose}: {}", r.body);
        let hop = &r.body["hops"][0];
        assert_eq!(hop["password"], "pw-telnet");
        assert_eq!(hop["username"], "admin");
        assert_eq!(hop["port"], 23);
        assert!(hop.get("key").is_none());
        assert_eq!(r.headers["cache-control"], "no-store");
    }
    let r = srv.post(&path, &carl, json!({"purpose": "rdp"})).await;
    assert_eq!(r.status, 400);
    // No access: not found.
    let r = srv.post(&path, &dan, json!({})).await;
    assert_eq!(r.status, 404, "{}", r.body);
    assert!(!r.body.to_string().contains("pw-telnet"));

    // Strict: Use-only members lose them; the owner keeps them.
    let r = srv
        .patch(
            &format!("/api/v1/vaults/{ops}"),
            &ana,
            json!({"settings": {"use_only_local": false}}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let r = srv.post(&path, &carl, json!({"purpose": "telnet"})).await;
    assert_eq!((r.status, r.code()), (403, "use_only_strict"));
    assert!(!r.body.to_string().contains("pw-telnet"));
    let r = srv.post(&path, &ana, json!({})).await;
    assert_eq!(r.status, 200);

    // Every use is audited in the vault with its purpose.
    let audit = srv.get(&format!("/api/v1/vaults/{ops}/audit"), &ana).await;
    let uses: Vec<&Value> = audit
        .body
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "secret.use")
        .collect();
    assert_eq!(uses.len(), 4, "{}", audit.body);
    assert!(uses.iter().any(|e| e["detail"]["purpose"] == "telnet"));
}
