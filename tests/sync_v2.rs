//! Sync protocol v2 (`POST /api/v1/vaults/sync`): authoritative vault list,
//! per-vault cursors, Use-only never gets secrets, rejections, paging,
//! departures, resync on role changes and revocation.

mod common;

use common::srv::{Srv, User};
use serde_json::{Value, json};

/// Syncs until `more` is false, from `cursors`; returns every response.
async fn sync_all(srv: &Srv, u: &User, cursors: Value, limit: u32) -> Vec<Value> {
    let mut out = Vec::new();
    let mut vaults = cursors;
    loop {
        let r = srv
            .ok(
                "/api/v1/vaults/sync",
                u,
                json!({"vaults": vaults, "changes": [], "limit": limit}),
            )
            .await;
        vaults = r["cursors"].clone();
        let more = r["more"] == true;
        out.push(r);
        if !more || out.len() > 50 {
            break;
        }
    }
    out
}

fn ids_of(changes: &Value, vault: &str) -> Vec<String> {
    changes
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["vault_id"] == vault)
        .map(|c| c["id"].as_str().unwrap().to_string())
        .collect()
}

fn record(id: &str, label: &str, vault: Option<&str>, secret: Option<Value>) -> Value {
    let mut r = json!({
        "id": id, "kind": "host",
        "data": {"label": label, "address": format!("{label}.example.com")},
        "sync_mode": "synced", "updated_at": termoak_core::time::now_ms(), "deleted": false,
    });
    if let Some(v) = vault {
        r["vault_id"] = json!(v);
    }
    if let Some(s) = secret {
        r["secret"] = s;
    }
    r
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sync_v2_roles_paging_resync_and_revocation() {
    let srv = Srv::start().await;
    // Clients detect the features (and tell servers apart) with /info.
    let info: Value = srv
        .http
        .get(format!("{}/api/v1/info", srv.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["features"]["vaults"], true);
    assert_eq!(info["features"]["sync_v2"], true);
    assert_eq!(info["features"]["credentials"], true);
    assert_eq!(info["instance_id"].as_str().unwrap().len(), 36);
    let ana = srv.user("Ana").await;
    let bea = srv.user("Bea").await;
    let carl = srv.user("Carl").await;
    let ops = srv.vault(&ana, "Ops").await;
    srv.share(&ana, &ops, &bea, "editor").await;
    let carl_grant = srv.share(&ana, &ops, &carl, "use_only").await;
    for i in 0..5 {
        srv.host(&ana, &ops, &format!("h{i}"), "hunter2").await;
    }

    // Carl (Use-only): the vault list is authoritative and secrets never come.
    let first = srv
        .ok(
            "/api/v1/vaults/sync",
            &carl,
            json!({"vaults": [], "changes": []}),
        )
        .await;
    let vaults: Vec<(String, String)> = first["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            (
                v["id"].as_str().unwrap().into(),
                v["role"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert!(vaults.contains(&(carl.id.clone(), "manager".into())));
    assert!(vaults.contains(&(ops.clone(), "use_only".into())));
    assert_eq!(ids_of(&first["changes"], &ops).len(), 5);
    assert!(!first.to_string().contains("hunter2"), "{first}");
    for c in first["changes"].as_array().unwrap() {
        assert_eq!(c["has_secret"], true);
        assert!(c.get("secret").is_none());
    }
    assert_eq!(first["more"], false);

    // Bea (Editor) gets them.
    let b = srv
        .ok(
            "/api/v1/vaults/sync",
            &bea,
            json!({"vaults": [], "changes": []}),
        )
        .await;
    assert!(
        b["changes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["secret"]["password"] == "hunter2")
    );

    // Paging: 2 per response, every item exactly once.
    let pages = sync_all(&srv, &bea, json!([]), 2).await;
    assert!(pages.len() >= 3, "{}", pages.len());
    let mut all: Vec<String> = pages
        .iter()
        .flat_map(|p| ids_of(&p["changes"], &ops))
        .collect();
    all.sort();
    all.dedup();
    assert_eq!(all.len(), 5);
    let cursors = pages.last().unwrap()["cursors"].clone();

    // Nothing new: nothing comes back.
    let again = srv
        .ok(
            "/api/v1/vaults/sync",
            &bea,
            json!({"vaults": cursors, "changes": []}),
        )
        .await;
    assert!(again["changes"].as_array().unwrap().is_empty(), "{again}");

    // Pushes: Use-only → vault_read_only; unknown vault → vault_not_found;
    // someone else's id → id_in_use; a record without vault_id lands in the
    // personal vault.
    let new_id = || termoak_core::new_id().to_string();
    let theirs = ids_of(&first["changes"], &ops)[0].clone();
    let r = srv
        .ok(
            "/api/v1/vaults/sync",
            &carl,
            json!({"vaults": [], "changes": [
                record(&new_id(), "x", Some(&ops), None),
                record(&new_id(), "y", Some(&termoak_core::new_id().to_string()), None),
                record(&new_id(), "mine", None, Some(json!({"password": "pw"}))),
            ]}),
        )
        .await;
    let codes: Vec<&str> = r["rejected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["code"].as_str().unwrap())
        .collect();
    assert_eq!(codes, vec!["vault_read_only", "vault_not_found"]);
    assert_eq!(r["accepted"].as_array().unwrap().len(), 1);
    let mine = r["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["data"]["label"] == "mine")
        .expect("the pushed record comes back");
    assert_eq!(mine["vault_id"], carl.id);
    let r = srv
        .ok(
            "/api/v1/vaults/sync",
            &srv.user("Dan").await,
            json!({"changes": [record(&theirs, "stolen", None, None)]}),
        )
        .await;
    assert_eq!(r["rejected"][0]["code"], "id_in_use");

    // Role change: Use-only → Editor needs a resync (secrets must come).
    let carl_cursors =
        sync_all(&srv, &carl, json!([]), 100).await.pop().unwrap()["cursors"].clone();
    let r = srv
        .patch(
            &format!("/api/v1/vaults/{ops}/members/{carl_grant}"),
            &ana,
            json!({"role": "editor"}),
        )
        .await;
    assert_eq!(r.status, 200);
    let r = srv
        .ok(
            "/api/v1/vaults/sync",
            &carl,
            json!({"vaults": carl_cursors, "changes": []}),
        )
        .await;
    assert_eq!(r["resync"], json!([ops]));
    assert_eq!(ids_of(&r["changes"], &ops).len(), 5);
    assert!(r.to_string().contains("hunter2"));
    let editor_cursors = r["cursors"].clone();
    // And back to Use-only: drop the secrets.
    srv.patch(
        &format!("/api/v1/vaults/{ops}/members/{carl_grant}"),
        &ana,
        json!({"role": "use_only"}),
    )
    .await;
    let r = srv
        .ok(
            "/api/v1/vaults/sync",
            &carl,
            json!({"vaults": editor_cursors, "changes": []}),
        )
        .await;
    assert_eq!(r["resync"], json!([ops]));
    assert!(!r.to_string().contains("hunter2"));

    // A move shows up as a departure in the source vault.
    let bea_cursors = sync_all(&srv, &bea, json!([]), 100).await.pop().unwrap()["cursors"].clone();
    let moved = theirs.clone();
    srv.ok(
        &format!("/api/v1/vaults/{}/transfer", ana.id),
        &ana,
        json!({"mode": "move", "items": [{"kind": "host", "id": moved}]}),
    )
    .await;
    let r = srv
        .ok(
            "/api/v1/vaults/sync",
            &bea,
            json!({"vaults": bea_cursors, "changes": []}),
        )
        .await;
    assert_eq!(r["removed"][0]["id"], moved);
    assert_eq!(r["removed"][0]["vault_id"], ops);
    // An edit pushed to the old vault after the move: Bea cannot write
    // Ana's personal vault, so it is an id she can no longer use.
    let r = srv
        .ok(
            "/api/v1/vaults/sync",
            &bea,
            json!({"changes": [record(&moved, "late edit", Some(&ops), None)]}),
        )
        .await;
    assert_eq!(r["rejected"][0]["code"], "id_in_use");

    // Revocation: the vault disappears from the authoritative list.
    srv.delete(&format!("/api/v1/vaults/{ops}/members/{carl_grant}"), &ana)
        .await;
    let r = srv
        .ok(
            "/api/v1/vaults/sync",
            &carl,
            json!({"vaults": [], "changes": []}),
        )
        .await;
    assert!(
        r["vaults"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["id"] != ops.as_str()),
        "{r}"
    );
    assert!(
        r["cursors"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["vault_id"] != ops.as_str())
    );
}
