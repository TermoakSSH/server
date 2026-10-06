//! The client library (`termoak-client`) against a real server with
//! vaults: two accounts of the same server on one device sharing a vault
//! (independent rows and roles), sync v2, just-in-time credentials and the
//! Strict switch, role changes (Use-only wipes secrets, Editor resyncs),
//! revocation (local wipe and the discarded report), transfers and
//! sign-out.

mod common;

use common::srv::Srv;
use serde_json::json;
use termoak_client::{
    AccountView, ItemAccess, ItemFilter, ItemRef, LOCAL_OWNER, LocalTransfer, SaveTarget, Scope,
    ServerChoice, Workspace,
};
use termoak_core::Id;
use termoak_core::crypto::MasterKey;
use termoak_core::model::{Host, HostSecret, HostSettings, SecretUpdate};
use termoak_core::transfer::{Dependencies, TransferMode};

fn host(label: &str) -> Host {
    Host {
        id: Id::nil(),
        label: label.into(),
        address: format!("{label}.example.com"),
        group_id: None,
        tags: vec![],
        settings: HostSettings {
            username: Some("root".into()),
            ..Default::default()
        },
        notes: String::new(),
        color: None,
        os: None,
        os_version: None,
        favorite: false,
    }
}

fn code_of(e: &termoak_client::ClientError) -> Option<&'static str> {
    match e {
        termoak_client::ClientError::Core(c) => c.vault_code(),
        _ => None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_accounts_share_a_vault() {
    let srv = Srv::start().await;
    let ana = srv.user("Ana").await;
    let bea = srv.user("Bea").await;
    let carl = srv.user("Carl").await;
    let ops = srv.vault(&ana, "Ops").await;
    let bea_grant = srv.share(&ana, &ops, &bea, "editor").await;
    srv.share(&ana, &ops, &carl, "use_only").await;
    let web: Id = srv.host(&ana, &ops, "web", "web-pw").await.parse().unwrap();

    // One device, two accounts of the same server.
    let dir = tempfile::tempdir().unwrap();
    let ws = Workspace::open(dir.path(), MasterKey::generate()).unwrap();
    let b = ws
        .sign_in(
            ServerChoice::Custom(srv.base.clone()),
            &bea.email,
            "secure-password",
            None,
        )
        .await
        .unwrap();
    let c = ws
        .sign_in(
            ServerChoice::Custom(srv.base.clone()),
            &carl.email,
            "secure-password",
            None,
        )
        .await
        .unwrap();
    assert_ne!(b.id, c.id);
    assert_eq!(ws.accounts().len(), 2);
    assert!(b.info().vaults_supported());
    assert!(b.info().instance_id.is_some());
    assert_eq!(ws.current().unwrap().id, c.id);

    let rb = b.sync_once().await.unwrap();
    assert_eq!(rb.protocol, "v2");
    assert!(rb.pulled >= 1);
    c.sync_once().await.unwrap();

    // The same host, twice, with each account's role.
    ws.set_view(AccountView::All).await.unwrap();
    let all = ws.list_items::<Host>(&ws.default_filter()).await.unwrap();
    let copies: Vec<_> = all.iter().filter(|h| h.record.data.id == web).collect();
    assert_eq!(copies.len(), 2);
    let as_bea = copies
        .iter()
        .find(|h| h.scope == Scope::Account(b.id))
        .unwrap();
    let as_carl = copies
        .iter()
        .find(|h| h.scope == Scope::Account(c.id))
        .unwrap();
    assert_eq!(as_bea.access, ItemAccess::Editor);
    assert_eq!(as_carl.access, ItemAccess::UseOnly);
    assert!(as_carl.record.meta.secret_hidden);
    assert_eq!(as_carl.record.meta.vault_id, Some(ops.parse().unwrap()));
    // Vault filter.
    let only_ops = ws
        .list_items::<Host>(&ItemFilter {
            accounts: Some(vec![b.id]),
            vaults: Some(vec![ops.parse().unwrap()]),
            include_device: false,
        })
        .await
        .unwrap();
    assert_eq!(only_ops.len(), 1);

    // Secrets: Bea sees them; Carl never has them on the device.
    let bea_item = ItemRef {
        scope: Scope::Account(b.id),
        id: web,
    };
    let carl_item = ItemRef {
        scope: Scope::Account(c.id),
        id: web,
    };
    let s: HostSecret = ws.item_secret::<Host>(bea_item).await.unwrap();
    assert_eq!(s.password.as_deref(), Some("web-pw"));
    let e = ws.item_secret::<Host>(carl_item).await.unwrap_err();
    assert_eq!(code_of(&e), Some("secret_hidden"), "{e}");
    let raw: HostSecret = c.store.secret::<Host>(LOCAL_OWNER, web).await.unwrap();
    assert!(raw.password.is_none());
    // Carl cannot change it locally.
    let mut edited = as_carl.record.data.clone();
    edited.notes = "x".into();
    let e = ws
        .save_item(
            SaveTarget::Account {
                account: c.id,
                vault: None,
            },
            edited,
            SecretUpdate::Keep,
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(code_of(&e), Some("vault_read_only"), "{e}");

    // Just-in-time credentials for Carl (memory only).
    let r = ws.resolve_item(carl_item).await.unwrap();
    assert_eq!(r.password.as_deref(), Some("web-pw"));
    assert_eq!(r.username, "root");
    // Strict vault: only through the server.
    let resp = srv
        .patch(
            &format!("/api/v1/vaults/{ops}"),
            &ana,
            json!({"settings": {"use_only_local": false}}),
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.body);
    c.sync_once().await.unwrap();
    let e = ws.resolve_item(carl_item).await.unwrap_err();
    assert_eq!(code_of(&e), Some("use_only_strict"), "{e}");

    // Bea goes down to Use-only: her copy loses the secret.
    let resp = srv
        .patch(
            &format!("/api/v1/vaults/{ops}/members/{bea_grant}"),
            &ana,
            json!({"role": "use_only"}),
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.body);
    b.sync_once().await.unwrap();
    let rec = b.store.get::<Host>(LOCAL_OWNER, web).await.unwrap();
    assert!(rec.meta.secret_hidden);
    let raw: HostSecret = b.store.secret::<Host>(LOCAL_OWNER, web).await.unwrap();
    assert!(raw.password.is_none());
    // Back to Editor: a resync brings it back.
    srv.patch(
        &format!("/api/v1/vaults/{ops}/members/{bea_grant}"),
        &ana,
        json!({"role": "editor"}),
    )
    .await;
    b.sync_once().await.unwrap();
    let s: HostSecret = ws.item_secret::<Host>(bea_item).await.unwrap();
    assert_eq!(s.password.as_deref(), Some("web-pw"));

    // A This-device host moves into Ops (keeping its id), with its secret.
    let local = ws
        .save_item(
            SaveTarget::Device,
            host("local"),
            SecretUpdate::Set(HostSecret {
                password: Some("local-pw".into()),
                proxy_password: None,
            }),
            None,
        )
        .await
        .unwrap();
    let local_id = local.record.data.id;
    let plan = ws
        .transfer(LocalTransfer {
            items: vec![local.item()],
            to: Scope::Account(b.id),
            vault: Some(ops.parse().unwrap()),
            mode: TransferMode::Move,
            dependencies: Dependencies::Auto,
            dry_run: true,
            force: false,
        })
        .await
        .unwrap();
    assert_eq!(plan.moved.len(), 1);
    assert!(ws.store.locate_local(local_id).await.unwrap().is_some());
    ws.transfer(LocalTransfer {
        items: vec![local.item()],
        to: Scope::Account(b.id),
        vault: Some(ops.parse().unwrap()),
        mode: TransferMode::Move,
        dependencies: Dependencies::Auto,
        dry_run: false,
        force: false,
    })
    .await
    .unwrap();
    assert!(ws.store.locate_local(local_id).await.unwrap().is_none());
    b.sync_once().await.unwrap();
    let seen = srv
        .get(&format!("/api/v1/hosts/{local_id}/secret"), &ana)
        .await;
    assert_eq!(seen.status, 200, "{}", seen.body);
    assert_eq!(seen.body["password"], "local-pw");

    // An online move between Bea's vaults (personal → Ops).
    let mine = ws
        .save_item(
            SaveTarget::Account {
                account: b.id,
                vault: None,
            },
            host("mine"),
            SecretUpdate::Keep,
            None,
        )
        .await
        .unwrap();
    assert_eq!(mine.record.meta.vault_id, b.user_id());
    b.sync_once().await.unwrap();
    let moved = ws
        .transfer(LocalTransfer {
            items: vec![mine.item()],
            to: Scope::Account(b.id),
            vault: Some(ops.parse().unwrap()),
            mode: TransferMode::Move,
            dependencies: Dependencies::Auto,
            dry_run: false,
            force: false,
        })
        .await
        .unwrap();
    assert_eq!(moved.moved.len(), 1);
    let rec = b
        .store
        .get::<Host>(LOCAL_OWNER, mine.record.data.id)
        .await
        .unwrap();
    assert_eq!(rec.meta.vault_id, Some(ops.parse().unwrap()));

    // Revocation: an unsynced edit of Bea is lost and reported.
    let mut edited = b.store.get::<Host>(LOCAL_OWNER, web).await.unwrap().data;
    edited.notes = "Bea was here".into();
    ws.save_item(
        SaveTarget::Account {
            account: b.id,
            vault: None,
        },
        edited,
        SecretUpdate::Keep,
        None,
    )
    .await
    .unwrap();
    let resp = srv
        .delete(&format!("/api/v1/vaults/{ops}/members/{bea_grant}"), &ana)
        .await;
    assert_eq!(resp.status, 200, "{}", resp.body);
    let report = b.sync_once().await.unwrap();
    assert_eq!(report.vaults_lost.len(), 1, "{report:?}");
    assert_eq!(report.vaults_lost[0].name, "Ops");
    assert_eq!(report.discarded_total(), 1, "{report:?}");
    assert_eq!(report.discarded[0].vault_name, "Ops");
    assert!(b.store.locate_local(web).await.unwrap().is_none());
    // Carl's copy is untouched.
    assert!(c.store.locate_local(web).await.unwrap().is_some());

    // Sign-out deletes Bea's store only.
    let file = dir.path().join(format!("accounts/{}.db", b.id));
    assert!(file.exists());
    let bid = b.id;
    drop(b);
    let out = ws.sign_out(bid, false).await.unwrap();
    assert!(out.signed_out, "{out:?}");
    assert!(!file.exists());
    assert_eq!(ws.accounts().len(), 1);
    assert!(c.store.locate_local(web).await.unwrap().is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_v2_sync_adopts_local_rows_and_the_legacy_cursor() {
    let srv = Srv::start().await;
    let ana = srv.user("Ana").await;
    let dir = tempfile::tempdir().unwrap();
    let ws = Workspace::open(dir.path(), MasterKey::generate()).unwrap();
    let a = ws
        .sign_in(
            ServerChoice::Custom(srv.base.clone()),
            &ana.email,
            "secure-password",
            None,
        )
        .await
        .unwrap();
    // Rows as a 0.3 store had them: no vault, synced with the legacy route.
    let old = a
        .store
        .save(LOCAL_OWNER, host("old"), SecretUpdate::Keep, None)
        .await
        .unwrap();
    assert_eq!(old.meta.vault_id, None);
    let legacy = termoak_client::SyncEngine::legacy(a.store.clone(), a.api.clone());
    let r = legacy.sync_once().await.unwrap();
    assert_eq!(r.protocol, "legacy");
    let rev = a.store.meta_get("sync.rev").await.unwrap().unwrap();
    // Another device adds something in between.
    srv.host(&ana, &ana.id, "newer", "pw").await;
    // First v2 sync: the row joins the personal vault, the old revision is
    // its cursor (only what is newer comes down).
    let r = a.sync_once().await.unwrap();
    assert_eq!(r.protocol, "v2");
    assert_eq!(r.pulled, 1, "{r:?}");
    let personal: Id = ana.id.parse().unwrap();
    let rec = a.store.get::<Host>(LOCAL_OWNER, old.data.id).await.unwrap();
    assert_eq!(rec.meta.vault_id, Some(personal));
    let vaults = a.store.local_vaults().await.unwrap();
    assert_eq!(vaults.len(), 1);
    assert!(vaults[0].cursor >= rev.parse::<i64>().unwrap());
}
