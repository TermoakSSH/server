//! The legacy sync (`POST /api/v1/sync`, apps before vaults) on a server
//! with vaults: only the personal vault, departures as deletions, old-format
//! pushes land in the personal vault (or where the item is now).

mod common;

use common::srv::Srv;
use serde_json::{Value, json};

fn find<'a>(changes: &'a Value, id: &str) -> Option<&'a Value> {
    changes.as_array().unwrap().iter().find(|c| c["id"] == id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_sync_sees_only_the_personal_vault() {
    let srv = Srv::start().await;
    let ana = srv.user("Ana").await;
    let bea = srv.user("Bea").await;
    let ops = srv.vault(&bea, "Ops").await;
    srv.share(&bea, &ops, &ana, "editor").await;
    let in_ops = srv.host(&bea, &ops, "team-host", "team-secret").await;
    let mine = srv.host(&ana, &ana.id, "mine", "my-secret").await;

    // Only personal items, with their secrets, in the old shape.
    let first = srv
        .ok("/api/v1/sync", &ana, json!({"since": 0, "changes": []}))
        .await;
    assert!(find(&first["changes"], &mine).is_some());
    assert!(find(&first["changes"], &in_ops).is_none(), "{first}");
    assert!(!first.to_string().contains("team-secret"));
    let rec = find(&first["changes"], &mine).unwrap();
    assert_eq!(rec["secret"]["password"], "my-secret");
    assert!(rec.get("vault_id").is_none(), "old shape: {rec}");
    let rev = first["rev"].as_i64().unwrap();

    // An old-format push (no vault_id) lands in the personal vault.
    let pushed_id = termoak_core::new_id().to_string();
    let r = srv
        .ok(
            "/api/v1/sync",
            &ana,
            json!({"since": rev, "changes": [{
                "id": pushed_id, "kind": "snippet", "data": {"name": "old-app", "script": "uptime"},
                "sync_mode": "synced", "updated_at": termoak_core::time::now_ms(), "deleted": false
            }]}),
        )
        .await;
    assert_eq!(r["accepted"], json!([pushed_id]));
    let snip = srv
        .get(&format!("/api/v1/snippets/{pushed_id}"), &ana)
        .await;
    assert_eq!(snip.body["vault_id"], ana.id);
    let rev = r["rev"].as_i64().unwrap();

    // Moving an item to Ops: the old app sees a deletion.
    srv.ok(
        &format!("/api/v1/vaults/{ops}/transfer"),
        &ana,
        json!({"mode": "move", "items": [{"kind": "host", "id": mine}]}),
    )
    .await;
    let r = srv
        .ok("/api/v1/sync", &ana, json!({"since": rev, "changes": []}))
        .await;
    let gone = find(&r["changes"], &mine).expect("a tombstone");
    assert_eq!(gone["deleted"], true);
    assert_eq!(gone["kind"], "host");
    assert!(r["rev"].as_i64().unwrap() > rev);
    let rev2 = r["rev"].as_i64().unwrap();

    // An old app that still has it pushes an edit: it is applied where the
    // item is now (Ana is Editor of Ops) and stays out of the personal vault.
    let r = srv
        .ok(
            "/api/v1/sync",
            &ana,
            json!({"since": rev2, "changes": [{
                "id": mine, "kind": "host",
                "data": {"label": "renamed by old app", "address": "mine.example.com"},
                "sync_mode": "synced", "updated_at": termoak_core::time::now_ms() + 1000,
                "deleted": false
            }]}),
        )
        .await;
    assert_eq!(r["accepted"], json!([mine]));
    assert!(find(&r["changes"], &mine).is_none(), "{r}");
    let h = srv.get(&format!("/api/v1/hosts/{mine}"), &bea).await;
    assert_eq!(h.body["label"], "renamed by old app");
    assert_eq!(h.body["vault_id"], ops);

    // The legacy sync never pulls other vaults, whatever `since` says.
    let all = srv
        .ok("/api/v1/sync", &ana, json!({"since": 0, "changes": []}))
        .await;
    assert!(find(&all["changes"], &in_ops).is_none());
    assert!(!all.to_string().contains("team-secret"));
}
