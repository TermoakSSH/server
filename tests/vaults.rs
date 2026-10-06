//! Vaults: permission matrix of every route per role (none / use only /
//! editor / manager / team admin), Use-only never sees secrets but can use
//! the server (sessions, exec, SFTP), just-in-time credentials and the
//! Strict switch, revocation (sessions and pool), teams and account
//! deletion, and `vault` events.

mod common;

use std::time::Duration;

use common::srv::{Srv, User, wait_event};
use common::{start_sshd, ws_connect, ws_wait_json, ws_wait_output};
use futures::SinkExt;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message as WsMsg;

/// Ana owns "Ops"; Bea is Editor, Carl Use-only, Dan has nothing.
struct World {
    srv: Srv,
    ana: User,
    bea: User,
    carl: User,
    dan: User,
    ops: String,
    host: String,
}

async fn world() -> World {
    let srv = Srv::start().await;
    // The first account is the administrator (it cannot delete itself).
    srv.user("Root").await;
    let ana = srv.user("Ana").await;
    let bea = srv.user("Bea").await;
    let carl = srv.user("Carl").await;
    let dan = srv.user("Dan").await;
    let ops = srv.vault(&ana, "Ops").await;
    srv.share(&ana, &ops, &bea, "editor").await;
    srv.share(&ana, &ops, &carl, "use_only").await;
    let host = srv.host(&ana, &ops, "web", "hunter2").await;
    World {
        srv,
        ana,
        bea,
        carl,
        dan,
        ops,
        host,
    }
}

fn no_secret(v: &Value) {
    let text = v.to_string();
    assert!(!text.contains("hunter2"), "a secret leaked: {text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn permission_matrix() {
    let w = world().await;
    let (srv, ops, host) = (&w.srv, w.ops.as_str(), w.host.as_str());
    // (user, role) for the routes below.
    let people = [
        (&w.ana, "manager"),
        (&w.bea, "editor"),
        (&w.carl, "use_only"),
        (&w.dan, "none"),
    ];

    for (u, role) in people {
        let member = role != "none";
        let editor = matches!(role, "manager" | "editor");
        let manager = role == "manager";
        // Without access: 404 (the vault's existence is not revealed).
        let expect = |ok: bool, denied: u16| {
            if !member {
                404
            } else if ok {
                200
            } else {
                denied
            }
        };

        // GET /vaults and /vaults/{id}
        let list = srv.get("/api/v1/vaults", u).await;
        assert_eq!(list.status, 200);
        let mine = list.body.as_array().unwrap();
        assert_eq!(mine[0]["kind"], "personal", "{role}: personal first");
        let seen = mine.iter().find(|v| v["id"] == ops);
        assert_eq!(seen.is_some(), member, "{role}");
        if let Some(v) = seen {
            assert_eq!(v["role"], role);
            assert_eq!(v["item_counts"]["host"], 1);
        }
        let r = srv.get(&format!("/api/v1/vaults/{ops}"), u).await;
        assert_eq!(r.status, expect(true, 0), "{role} GET vault");
        if !member {
            assert_eq!(r.code(), "vault_not_found");
        }

        // PATCH (managers)
        let r = srv
            .patch(
                &format!("/api/v1/vaults/{ops}"),
                u,
                json!({"description": role}),
            )
            .await;
        assert_eq!(r.status, expect(manager, 403), "{role} PATCH vault");
        if member && !manager {
            assert_eq!(r.code(), "vault_manager_only");
        }

        // Members: list (members), add (managers).
        let r = srv.get(&format!("/api/v1/vaults/{ops}/members"), u).await;
        assert_eq!(r.status, expect(true, 0), "{role} GET members");
        let r = srv
            .post(
                &format!("/api/v1/vaults/{ops}/members"),
                u,
                json!({"email": "nobody@termoak.test", "role": "editor"}),
            )
            .await;
        assert_eq!(
            r.status,
            if manager { 404 } else { expect(false, 403) },
            "{role} add member"
        );
        if manager {
            assert_eq!(r.code(), "user_not_found");
        }

        // Audit (managers).
        let r = srv.get(&format!("/api/v1/vaults/{ops}/audit"), u).await;
        assert_eq!(r.status, expect(manager, 403), "{role} audit");

        // Create in the vault (Editors).
        let r = srv
            .post(
                "/api/v1/snippets",
                u,
                json!({"name": format!("s-{role}"), "script": "uptime", "vault_id": ops}),
            )
            .await;
        assert_eq!(r.status, expect(editor, 403), "{role} create");
        if member && !editor {
            assert_eq!(r.code(), "vault_read_only");
        }
        if !member {
            assert_eq!(r.code(), "vault_not_found");
        }

        // List hosts: the vault's host for members, with secret_hidden for Use-only.
        let r = srv.get("/api/v1/hosts", u).await;
        assert_eq!(r.status, 200);
        no_secret(&r.body);
        let h = r
            .body
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["id"] == host)
            .cloned();
        assert_eq!(h.is_some(), member, "{role} list");
        if let Some(h) = h {
            assert_eq!(h["vault_id"], ops);
            assert_eq!(h["has_secret"], true);
            assert_eq!(h["secret_hidden"], role == "use_only", "{role}");
        }
        let r = srv.get(&format!("/api/v1/hosts?vault_id={ops}"), u).await;
        assert_eq!(r.status, expect(true, 0), "{role} list ?vault_id");

        // Get, effective settings.
        let r = srv.get(&format!("/api/v1/hosts/{host}"), u).await;
        assert_eq!(r.status, expect(true, 0), "{role} GET host");
        no_secret(&r.body);
        let r = srv.get(&format!("/api/v1/hosts/{host}/effective"), u).await;
        assert_eq!(r.status, expect(true, 0), "{role} effective");

        // Update (Editors), a different vault_id → use_transfer.
        let r = srv
            .put(
                &format!("/api/v1/hosts/{host}"),
                u,
                json!({"label": "web", "address": "web.example.com",
                       "settings": {"username": "root"}, "notes": role}),
            )
            .await;
        assert_eq!(r.status, expect(editor, 403), "{role} PUT host");
        if editor {
            assert_eq!(r.body["updated_by"], u.id.as_str());
            let r = srv
                .put(
                    &format!("/api/v1/hosts/{host}"),
                    u,
                    json!({"label": "web", "address": "web.example.com", "vault_id": u.id}),
                )
                .await;
            assert_eq!((r.status, r.code()), (409, "use_transfer"), "{role}");
        }

        // Reveal (Editors; Use-only: secret_hidden).
        let r = srv.get(&format!("/api/v1/hosts/{host}/secret"), u).await;
        assert_eq!(r.status, expect(editor, 403), "{role} reveal");
        if editor {
            assert_eq!(r.body["password"], "hunter2");
        } else {
            no_secret(&r.body);
        }
        if member && !editor {
            assert_eq!(r.code(), "secret_hidden");
        }

        // Just-in-time credentials (Editors, and Use-only while not Strict).
        let r = srv
            .post(
                &format!("/api/v1/hosts/{host}/credentials"),
                u,
                json!({"purpose": "ssh"}),
            )
            .await;
        assert_eq!(r.status, expect(true, 0), "{role} credentials");
        if member {
            assert_eq!(r.body["hops"][0]["password"], "hunter2");
            assert_eq!(r.headers["cache-control"], "no-store");
        }

        // Copy the host out (Editors only; Use-only cannot take secrets out).
        let r = srv
            .post(
                &format!("/api/v1/vaults/{}/transfer", u.id),
                u,
                json!({"mode": "copy", "items": [{"kind": "host", "id": host}], "dry_run": true}),
            )
            .await;
        assert_eq!(r.status, expect(editor, 403), "{role} transfer copy");
    }

    // Strict: Use-only members lose the just-in-time credentials.
    let r = srv
        .patch(
            &format!("/api/v1/vaults/{ops}"),
            &w.ana,
            json!({"settings": {"use_only_local": false}}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let r = srv
        .post(
            &format!("/api/v1/hosts/{host}/credentials"),
            &w.carl,
            json!({}),
        )
        .await;
    assert_eq!((r.status, r.code()), (403, "use_only_strict"));
    no_secret(&r.body);
    let r = srv
        .post(
            &format!("/api/v1/hosts/{host}/credentials"),
            &w.bea,
            json!({}),
        )
        .await;
    assert_eq!(r.status, 200);

    // The vault's audit has the reveals and the credential uses.
    let audit = srv
        .get(&format!("/api/v1/vaults/{ops}/audit"), &w.ana)
        .await;
    let actions: Vec<&str> = audit
        .body
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    for a in [
        "vault.create",
        "vault.member_add",
        "secret.reveal",
        "secret.use",
        "vault.update",
    ] {
        assert!(actions.contains(&a), "missing {a} in {actions:?}");
    }
    let uses = audit
        .body
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "secret.use")
        .count();
    assert_eq!(uses, 4, "three members + Bea after Strict");

    // Delete (Use-only and Editors cannot; it needs the name).
    let r = srv.delete(&format!("/api/v1/hosts/{host}"), &w.carl).await;
    assert_eq!((r.status, r.code()), (403, "vault_read_only"));
    let r = srv.delete(&format!("/api/v1/hosts/{host}"), &w.dan).await;
    assert_eq!(r.status, 404);
    let r = srv
        .delete(&format!("/api/v1/vaults/{ops}?confirm=Ops"), &w.bea)
        .await;
    assert_eq!(r.status, 403);
    let r = srv.delete(&format!("/api/v1/vaults/{ops}"), &w.ana).await;
    assert_eq!((r.status, r.code()), (400, "confirmation_required"));
    let r = srv
        .delete(&format!("/api/v1/vaults/{}", w.ana.id), &w.ana)
        .await;
    assert_eq!((r.status, r.code()), (409, "vault_personal"));
    let r = srv
        .post(
            &format!("/api/v1/vaults/{}/members", w.ana.id),
            &w.ana,
            json!({"email": w.bea.email, "role": "editor"}),
        )
        .await;
    assert_eq!((r.status, r.code()), (409, "vault_personal"));
    let r = srv
        .post(
            &format!("/api/v1/vaults/{ops}/members"),
            &w.ana,
            json!({"email": w.dan.email, "role": "manager"}),
        )
        .await;
    assert_eq!((r.status, r.code()), (400, "invalid_role"));
    let r = srv.delete(&format!("/api/v1/hosts/{host}"), &w.bea).await;
    assert_eq!(r.status, 200);
    let r = srv
        .delete(&format!("/api/v1/vaults/{ops}?confirm=Ops"), &w.ana)
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let r = srv.get(&format!("/api/v1/vaults/{ops}"), &w.bea).await;
    assert_eq!(r.status, 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_vault_references_and_transfers() {
    let w = world().await;
    let srv = &w.srv;
    // A key in Ana's personal vault cannot be used by an Ops host.
    let key = srv
        .ok(
            "/api/v1/keys/generate",
            &w.ana,
            json!({"label": "mine", "key_type": "ed25519"}),
        )
        .await;
    assert_eq!(key["vault_id"], w.ana.id);
    let r = srv
        .post(
            "/api/v1/hosts",
            &w.ana,
            json!({"label": "db", "address": "db", "vault_id": w.ops,
                   "settings": {"username": "root", "key_id": key["id"]}}),
        )
        .await;
    assert_eq!((r.status, r.code()), (422, "cross_vault_reference"));
    assert_eq!(r.body["error"]["field"], "settings.key_id");

    // A personal host using that key, moved to Ops: nothing else uses the
    // key, so it moves along (same ids).
    let h = srv
        .ok(
            "/api/v1/hosts",
            &w.ana,
            json!({"label": "db", "address": "db",
                   "settings": {"username": "root", "key_id": key["id"]}}),
        )
        .await;
    let plan = srv
        .ok(
            &format!("/api/v1/vaults/{}/transfer", w.ops),
            &w.ana,
            json!({"mode": "move", "items": [{"kind": "host", "id": h["id"]}], "dry_run": true}),
        )
        .await;
    assert_eq!(plan["dry_run"], true);
    assert_eq!(plan["moved"].as_array().unwrap().len(), 2, "{plan}");
    // Explicitly moving the key alone while the host uses it: refused.
    let r = srv
        .post(
            &format!("/api/v1/vaults/{}/transfer", w.ops),
            &w.ana,
            json!({"mode": "move", "items": [{"kind": "key", "id": key["id"]}]}),
        )
        .await;
    assert_eq!((r.status, r.code()), (409, "still_referenced"));
    let done = srv
        .ok(
            &format!("/api/v1/vaults/{}/transfer", w.ops),
            &w.ana,
            json!({"mode": "move", "items": [{"kind": "host", "id": h["id"]}]}),
        )
        .await;
    assert_eq!(done["moved"].as_array().unwrap().len(), 2);
    // Bea (Editor of Ops) now reveals the moved key; the ids are the same.
    let r = srv
        .get(
            &format!("/api/v1/keys/{}/secret", key["id"].as_str().unwrap()),
            &w.bea,
        )
        .await;
    assert_eq!(r.status, 200);
    assert!(
        r.body["private_key"]
            .as_str()
            .unwrap()
            .contains("PRIVATE KEY")
    );
    // Use-only cannot move anything.
    let r = srv
        .post(
            &format!("/api/v1/vaults/{}/transfer", w.carl.id),
            &w.carl,
            json!({"mode": "move", "items": [{"kind": "host", "id": h["id"]}]}),
        )
        .await;
    assert_eq!((r.status, r.code()), (403, "vault_read_only"));
    // Both vaults have the transfer in their audit.
    for v in [&w.ops, &w.ana.id] {
        let a = srv.get(&format!("/api/v1/vaults/{v}/audit"), &w.ana).await;
        assert!(
            a.body
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["action"] == "vault.transfer"),
            "{v}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn teams_own_vaults_and_take_them_away() {
    let srv = Srv::start().await;
    srv.user("Root").await;
    let ana = srv.user("Ana").await;
    let eve = srv.user("Eve").await;
    let fran = srv.user("Fran").await;
    let team = srv
        .ok("/api/v1/teams", &ana, json!({"name": "Infra"}))
        .await;
    let tid = team["id"].as_str().unwrap();
    for (u, role) in [(&eve, "admin"), (&fran, "member")] {
        srv.ok(
            &format!("/api/v1/teams/{tid}/members"),
            &ana,
            json!({"email": u.email, "role": role}),
        )
        .await;
    }
    // Only owners and admins create team vaults.
    let r = srv
        .post(
            "/api/v1/vaults",
            &fran,
            json!({"name": "x", "team_id": tid}),
        )
        .await;
    assert_eq!(r.status, 403);
    let mut fran_ws = srv.events(&fran).await;
    let tv = srv
        .ok(
            "/api/v1/vaults",
            &eve,
            json!({"name": "Prod", "team_id": tid, "team_member_role": "use_only"}),
        )
        .await;
    let tv = tv["id"].as_str().unwrap().to_string();
    let ev = wait_event(&mut fran_ws, |v| {
        v["type"] == "vault" && v["event"] == "access"
    })
    .await;
    assert_eq!(
        (ev["role"].as_str(), ev["reason"].as_str()),
        (Some("use_only"), Some("granted"))
    );
    srv.host(&eve, &tv, "prod1", "hunter2").await;

    // Team admin = manager; plain member = team_member_role.
    let roles = |list: &Value| -> Option<String> {
        list.as_array()?
            .iter()
            .find(|v| v["id"] == tv.as_str())
            .map(|v| v["role"].as_str().unwrap().to_string())
    };
    assert_eq!(
        roles(&srv.get("/api/v1/vaults", &eve).await.body).as_deref(),
        Some("manager")
    );
    assert_eq!(
        roles(&srv.get("/api/v1/vaults", &ana).await.body).as_deref(),
        Some("manager")
    );
    assert_eq!(
        roles(&srv.get("/api/v1/vaults", &fran).await.body).as_deref(),
        Some("use_only")
    );
    let r = srv
        .patch(
            &format!("/api/v1/vaults/{tv}"),
            &eve,
            json!({"name": "Production"}),
        )
        .await;
    assert_eq!(r.status, 200);
    let r = srv
        .patch(&format!("/api/v1/vaults/{tv}"), &fran, json!({"name": "x"}))
        .await;
    assert_eq!(r.status, 403);
    // A direct grant on top: the maximum wins.
    srv.share(&eve, &tv, &fran, "editor").await;
    assert_eq!(
        roles(&srv.get("/api/v1/vaults", &fran).await.body).as_deref(),
        Some("editor")
    );
    let ev = wait_event(&mut fran_ws, |v| {
        v["event"] == "access" && v["reason"] == "role_changed"
    })
    .await;
    assert_eq!(ev["role"], "editor");

    // Removing Fran from the team leaves the direct grant...
    let r = srv
        .delete(&format!("/api/v1/teams/{tid}/members/{}", fran.id), &ana)
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(
        roles(&srv.get("/api/v1/vaults", &fran).await.body).as_deref(),
        Some("editor")
    );
    // ...and leaving drops it.
    let r = srv
        .post(&format!("/api/v1/vaults/{tv}/leave"), &fran, json!({}))
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(roles(&srv.get("/api/v1/vaults", &fran).await.body), None);
    let ev = wait_event(&mut fran_ws, |v| {
        v["event"] == "access" && v["role"].is_null()
    })
    .await;
    assert_eq!(ev["reason"], "revoked");

    // Deleting the team deletes its vaults and their items.
    let mut eve_ws = srv.events(&eve).await;
    let r = srv.delete(&format!("/api/v1/teams/{tid}"), &ana).await;
    assert_eq!(r.status, 200);
    let ev = wait_event(&mut eve_ws, |v| v["event"] == "access").await;
    assert_eq!(
        (ev["role"].clone(), ev["reason"].as_str()),
        (Value::Null, Some("deleted"))
    );
    let r = srv.get(&format!("/api/v1/vaults/{tv}"), &eve).await;
    assert_eq!(r.status, 404);
    let hosts = srv.get("/api/v1/hosts", &eve).await;
    assert!(hosts.body.as_array().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn account_deletion_lists_shared_vaults() {
    let w = world().await;
    let srv = &w.srv;
    // With two-step on, the refusal must not spend the code: the same recovery
    // code confirms the deletion afterwards.
    let r = srv.post("/api/v1/me/2fa/setup", &w.ana, json!({})).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let secret =
        termoak_core::totp::secret_from_base32(r.body["secret"].as_str().unwrap()).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let code = format!(
        "{:06}",
        termoak_core::totp::code_at(&secret, termoak_core::totp::step_at(now))
    );
    let r = srv
        .post("/api/v1/me/2fa/enable", &w.ana, json!({"code": code}))
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let recovery = r.body["recovery_codes"][0].as_str().unwrap().to_string();
    let r = srv
        .req(
            reqwest::Method::DELETE,
            "/api/v1/me",
            &w.ana.token,
            Some(json!({"password": "secure-password", "totp_code": recovery})),
        )
        .await;
    assert_eq!((r.status, r.code()), (409, "shared_vaults"));
    assert_eq!(r.body["error"]["vaults"][0]["name"], "Ops");
    assert_eq!(r.body["error"]["vaults"][0]["member_count"], 2);
    let mut bea_ws = srv.events(&w.bea).await;
    let r = srv
        .req(
            reqwest::Method::DELETE,
            "/api/v1/me",
            &w.ana.token,
            Some(json!({
                "password": "secure-password",
                "totp_code": recovery,
                "delete_shared_vaults": true
            })),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let ev = wait_event(&mut bea_ws, |v| v["event"] == "access").await;
    assert_eq!(ev["vault_id"], w.ops);
    assert_eq!(ev["reason"], "deleted");
    let r = srv.get(&format!("/api/v1/hosts/{}", w.host), &w.bea).await;
    assert_eq!(r.status, 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn changes_are_announced_to_members() {
    let w = world().await;
    let mut bea = w.srv.events(&w.bea).await;
    let mut dan = w.srv.events(&w.dan).await;
    w.srv.host(&w.ana, &w.ops, "db", "x").await;
    let ev = wait_event(&mut bea, |v| {
        v["type"] == "vault" && v["event"] == "changed"
    })
    .await;
    assert_eq!(ev["vault_id"], w.ops);
    assert!(ev["rev"].as_i64().unwrap() > 0);
    // Dan is not a member: nothing for him.
    let quiet = tokio::time::timeout(
        Duration::from_millis(1200),
        wait_event(&mut dan, |v| v["type"] == "vault"),
    )
    .await;
    assert!(quiet.is_err());
}

/// Use-only members use the server (sessions, exec, SFTP, AI-free) without
/// ever getting the secret; revoking closes their sessions and connections.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn use_only_uses_the_server_and_revocation_closes_sessions() {
    let Some(sshd) = start_sshd() else {
        eprintln!("sshd not available: test skipped");
        return;
    };
    let srv = Srv::start().await;
    srv.user("Root").await;
    let ana = srv.user("Ana").await;
    let carl = srv.user("Carl").await;
    let ops = srv.vault(&ana, "Ops").await;
    let grant = srv.share(&ana, &ops, &carl, "use_only").await;
    let key = srv
        .ok(
            "/api/v1/keys/import",
            &ana,
            json!({"label": "k", "private_key": sshd.private_key, "vault_id": ops}),
        )
        .await;
    let host = srv
        .ok(
            "/api/v1/hosts",
            &ana,
            json!({"label": "local", "address": "127.0.0.1", "vault_id": ops,
                   "settings": {"port": sshd.port, "username": sshd.user, "key_id": key["id"]}}),
        )
        .await;
    let host = host["id"].as_str().unwrap();

    // Never the key itself.
    let r = srv
        .get(
            &format!("/api/v1/keys/{}/secret", key["id"].as_str().unwrap()),
            &carl,
        )
        .await;
    assert_eq!((r.status, r.code()), (403, "secret_hidden"));

    // Exec, SFTP and a server session work.
    let r = srv
        .post(
            "/api/v1/exec",
            &carl,
            json!({"host_ids": [host], "command": "echo used-$((40+2))"}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(
        r.body[0]["stdout"].as_str().unwrap().contains("used-42"),
        "{}",
        r.body
    );
    let r = srv
        .get(&format!("/api/v1/hosts/{host}/sftp/list?path=/tmp"), &carl)
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let r = srv
        .post(&format!("/api/v1/hosts/{host}/test"), &carl, json!({}))
        .await;
    assert_eq!(r.body["ok"], true, "{}", r.body);
    let session = srv
        .ok(
            "/api/v1/sessions",
            &carl,
            json!({"host_id": host, "cols": 80, "rows": 24}),
        )
        .await;
    let sid = session["id"].as_str().unwrap();
    let mut ws = ws_connect(
        &srv.base,
        &format!("/api/v1/sessions/{sid}/ws"),
        Some(&carl.token),
    )
    .await;
    ws_wait_json(&mut ws, "hello").await;
    ws.send(WsMsg::Binary(
        "echo carl-$((1+1))\n".as_bytes().to_vec().into(),
    ))
    .await
    .unwrap();
    ws_wait_output(&mut ws, "carl-2").await;
    assert!(srv.state.pool.open_count() >= 1);
    let mut events = srv.events(&carl).await;

    // Ana revokes Carl: the session closes and the pool forgets him.
    let r = srv
        .delete(&format!("/api/v1/vaults/{ops}/members/{grant}"), &ana)
        .await;
    assert_eq!(r.status, 200);
    let ev = wait_event(&mut events, |v| {
        v["type"] == "session" && v["notice"]["type"] == "session_closed"
    })
    .await;
    assert_eq!(ev["notice"]["reason"], "vault_access_revoked");
    let ev = wait_event(&mut events, |v| {
        v["type"] == "vault" && v["event"] == "access"
    })
    .await;
    assert_eq!(
        (ev["role"].clone(), ev["reason"].as_str()),
        (Value::Null, Some("revoked"))
    );
    let r = srv
        .post(
            "/api/v1/exec",
            &carl,
            json!({"host_ids": [host], "command": "true"}),
        )
        .await;
    assert!(
        r.body[0]["error"].as_str().unwrap().contains("not found"),
        "{}",
        r.body
    );
    let r = srv
        .get(&format!("/api/v1/hosts/{host}/sftp/list?path=/tmp"), &carl)
        .await;
    assert_eq!(r.status, 404);
    let r = srv
        .post(
            "/api/v1/sessions",
            &carl,
            json!({"host_id": host, "cols": 80, "rows": 24}),
        )
        .await;
    assert_eq!(r.status, 404);
    // Ana's own use is unaffected.
    let r = srv
        .post(
            "/api/v1/exec",
            &ana,
            json!({"host_ids": [host], "command": "echo ana-ok"}),
        )
        .await;
    assert!(
        r.body[0]["stdout"].as_str().unwrap().contains("ana-ok"),
        "{}",
        r.body
    );
}
