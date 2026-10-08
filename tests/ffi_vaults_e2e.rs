//! Accounts and vaults from the FFI layer (the mobile apps' engine) against
//! a real in-process server: sign-up, vault management and members,
//! Use-only items (hidden secrets, read-only, Strict), role changes heard
//! through the events (with `account_id`), two accounts on one device,
//! transfers, leaving a vault and signing out.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::executor::block_on;
use parking_lot::{Condvar, Mutex};
use serde_json::Value;
use termoak_ffi::*;
use termoak_server::config::ServerConfig;
use termoak_server::{build_state, routes};

fn start_server(data: PathBuf) -> String {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let mut config = ServerConfig::default();
            config.server.listen = addr;
            config.server.data_dir = data;
            config.server.registration = termoak_server::config::Registration::Open;
            let state = build_state(config).await.unwrap();
            tx.send(format!("http://{addr}")).unwrap();
            axum::serve(
                listener,
                routes::router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
    });
    rx.recv_timeout(Duration::from_secs(30)).unwrap()
}

fn core(dir: &tempfile::TempDir, name: &str) -> Arc<TermoakCore> {
    TermoakCore::new(
        dir.path().join(name).to_string_lossy().into_owned(),
        generate_vault_key(),
    )
    .unwrap()
}

fn host(label: &str, account: Option<&str>, vault: Option<&str>) -> SshHost {
    SshHost {
        id: String::new(),
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
        protocol: "ssh".into(),
        icon: None,
        sync_mode: None,
        has_password: false,
        updated_at: 0,
        account_id: account.map(str::to_string),
        vault_id: vault.map(str::to_string),
        access: None,
        secret_hidden: false,
    }
}

#[derive(Default)]
struct Events {
    list: Mutex<Vec<Value>>,
    cv: Condvar,
}

impl ServerEventListener for Events {
    fn on_event(&self, event_json: String) {
        self.list
            .lock()
            .push(serde_json::from_str(&event_json).unwrap());
        self.cv.notify_all();
    }

    fn on_closed(&self, _reason: Option<String>) {}
}

impl Events {
    fn wait(&self, what: &str, pred: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut list = self.list.lock();
        loop {
            if let Some(v) = list.iter().find(|v| pred(v)) {
                return v.clone();
            }
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "timed out waiting for {what}: {list:?}");
            self.cv.wait_for(&mut list, left);
        }
    }
}

const PW: &str = "strong-password";

#[test]
fn vaults_from_mobile() {
    let tmp = tempfile::tempdir().unwrap();
    let base = start_server(tmp.path().join("server"));
    let server = ServerChoice::Custom { url: base.clone() };

    // --- Ana (first user) and Bea sign up from their phones ---
    let ana = core(&tmp, "ana");
    let ana_acc = block_on(ana.sign_up(
        server.clone(),
        "ana@termoak.test".into(),
        "Ana".into(),
        PW.into(),
        None,
        false,
        None,
    ))
    .unwrap();
    assert!(ana_acc.vaults_supported && ana_acc.is_current);
    assert_eq!(ana_acc.status, AccountStatus::Active);
    let ana_h = ana.account(ana_acc.id.clone()).unwrap();
    let bea = core(&tmp, "bea");
    let bea_acc = block_on(bea.sign_up(
        server.clone(),
        "bea@termoak.test".into(),
        "Bea".into(),
        PW.into(),
        None,
        false,
        None,
    ))
    .unwrap();
    let bea_h = bea.account(bea_acc.id.clone()).unwrap();

    // --- Ana makes a vault with a host and shares it Use-only ---
    let ops = block_on(ana_h.create_vault(NewVault {
        name: "Ops".into(),
        description: Some("servers".into()),
        color: None,
        icon: None,
        team_id: None,
        team_member_role: None,
        strict: false,
    }))
    .unwrap();
    assert_eq!(ops.kind, VaultKind::Shared);
    assert_eq!(ops.role, VaultRole::Manager);
    assert!(!ops.strict);
    let web = ana
        .save_host(
            host("web", Some(&ana_acc.id), Some(&ops.id)),
            SecretChange::Set {
                value: "web-pw".into(),
            },
        )
        .unwrap();
    assert_eq!(web.vault_id.as_deref(), Some(ops.id.as_str()));
    assert_eq!(web.access, Some(ItemAccess::Manager));
    block_on(ana_h.sync_now()).unwrap();
    let grant = block_on(ana_h.add_vault_member(
        ops.id.clone(),
        VaultMemberTarget::User {
            email: "bea@termoak.test".into(),
        },
        VaultRole::UseOnly,
    ))
    .unwrap();
    assert_eq!(grant.role, VaultRole::UseOnly);
    let members = block_on(ana_h.vault_members(ops.id.clone())).unwrap();
    assert!(
        members
            .iter()
            .any(|m| m.implicit && m.role == VaultRole::Manager)
    );
    assert!(
        members
            .iter()
            .any(|m| m.email.as_deref() == Some("bea@termoak.test"))
    );
    assert!(matches!(
        block_on(ana_h.add_vault_member(
            ops.id.clone(),
            VaultMemberTarget::User {
                email: "nobody@termoak.test".into()
            },
            VaultRole::Editor,
        )),
        Err(TermoakError::NotFound(_))
    ));

    // --- Bea sees it Use-only ---
    let sub = Arc::new(Events::default());
    let _subscription = block_on(bea_h.subscribe_events(sub.clone())).unwrap();
    let hello = sub.wait("hello", |v| v["type"] == "hello");
    assert_eq!(hello["account_id"], bea_acc.id);
    let report = block_on(bea.sync_now()).unwrap();
    assert_eq!(report.protocol, "v2");
    assert_eq!(report.account_id.as_deref(), Some(bea_acc.id.as_str()));
    let vaults = bea.vaults(None).unwrap();
    let seen = vaults.iter().find(|v| v.id == ops.id).unwrap();
    assert_eq!(seen.role, VaultRole::UseOnly);
    assert_eq!(seen.owner_name.as_deref(), Some("Ana"));
    assert!(vaults.iter().any(|v| v.kind == VaultKind::Personal));
    let mine = bea.get_host(web.id.clone(), None).unwrap();
    assert_eq!(mine.access, Some(ItemAccess::UseOnly));
    assert!(mine.secret_hidden && mine.has_password);
    assert_eq!(mine.account_id.as_deref(), Some(bea_acc.id.as_str()));
    assert!(matches!(
        bea.host_password(web.id.clone(), None),
        Err(TermoakError::SecretHidden(_))
    ));
    let mut edited = mine.clone();
    edited.notes = "mine now".into();
    assert!(matches!(
        bea.save_host(edited, SecretChange::Keep),
        Err(TermoakError::VaultReadOnly(_))
    ));
    assert!(matches!(
        bea.delete_host(web.id.clone(), None),
        Err(TermoakError::VaultReadOnly(_))
    ));
    // Only items of Ops.
    let only_ops = bea
        .list_hosts(Some(ItemFilter {
            account_ids: None,
            vault_ids: Some(vec![ops.id.clone()]),
            include_device: false,
        }))
        .unwrap();
    assert_eq!(only_ops.len(), 1);

    // --- Strict: only through the server ---
    block_on(ana_h.update_vault(
        ops.id.clone(),
        VaultChanges {
            name: None,
            description: None,
            color: Some("#ff8800".into()),
            clear_color: false,
            icon: None,
            clear_icon: false,
            strict: Some(true),
            team_member_role: None,
            no_team_access: false,
        },
    ))
    .unwrap();
    sub.wait("access updated", |v| {
        v["type"] == "vault" && v["event"] == "access" && v["reason"] == "updated"
    });
    block_on(bea.sync_now()).unwrap();
    assert!(
        bea.vaults(None)
            .unwrap()
            .iter()
            .any(|v| v.id == ops.id && v.strict)
    );
    struct NoAuth;
    impl AuthHandler for NoAuth {
        fn on_host_key(&self, _: String, _: u32, _: String, _: String) -> bool {
            false
        }
        fn on_prompt(&self, _request: AuthRequest) -> Option<Vec<String>> {
            None
        }
    }
    assert!(matches!(
        block_on(bea.connect(web.id.clone(), Arc::new(NoAuth), None)),
        Err(TermoakError::UseOnlyStrict(_))
    ));

    // --- Upgrade to Editor: heard through the events, secrets arrive ---
    block_on(ana_h.set_vault_member_role(ops.id.clone(), grant.id.clone(), VaultRole::Editor))
        .unwrap();
    let ev = sub.wait("role changed", |v| {
        v["type"] == "vault" && v["event"] == "access" && v["role"] == "editor"
    });
    assert_eq!(ev["account_id"], bea_acc.id);
    assert_eq!(ev["vault_id"], ops.id);
    block_on(bea.sync_now()).unwrap();
    assert_eq!(
        bea.host_password(web.id.clone(), None).unwrap().as_deref(),
        Some("web-pw")
    );
    assert_eq!(
        bea.get_host(web.id.clone(), None).unwrap().access,
        Some(ItemAccess::Editor)
    );

    // --- A second account on Bea's phone (same server) ---
    block_on(ana_h.create_vault(NewVault {
        name: "Spare".into(),
        description: None,
        color: None,
        icon: None,
        team_id: None,
        team_member_role: None,
        strict: false,
    }))
    .unwrap();
    let carl_acc = block_on(bea.sign_up(
        server.clone(),
        "carl@termoak.test".into(),
        "Carl".into(),
        PW.into(),
        None,
        false,
        None,
    ))
    .unwrap();
    assert_eq!(bea.accounts().len(), 2);
    assert_eq!(bea.current_account().unwrap().id, carl_acc.id);
    // Carl's view: none of Bea's items.
    assert!(bea.list_hosts(None).unwrap().is_empty());
    bea.set_account_view(None).unwrap();
    assert_eq!(bea.list_hosts(None).unwrap().len(), 1);
    // Carl copies Bea's host into his personal vault (across accounts:
    // new id, with its secret, since Bea is an Editor of Ops).
    let r = block_on(bea.transfer(
        vec![ItemRef {
            account_id: Some(bea_acc.id.clone()),
            id: web.id.clone(),
        }],
        Some(carl_acc.id.clone()),
        None,
        TransferMode::Copy,
        false,
    ))
    .unwrap();
    assert_eq!(r.copied.len(), 1);
    let copy_id = r.copied[0].to_id.clone();
    assert_ne!(copy_id, web.id);
    assert_eq!(
        bea.host_password(copy_id.clone(), Some(carl_acc.id.clone()))
            .unwrap()
            .as_deref(),
        Some("web-pw")
    );
    let carl_h = bea.account(carl_acc.id.clone()).unwrap();
    block_on(carl_h.sync_now()).unwrap();
    assert_eq!(bea.list_hosts(None).unwrap().len(), 2);

    // --- Audit, leaving and deleting ---
    let audit = block_on(ana_h.vault_audit(ops.id.clone(), 50, None)).unwrap();
    assert!(audit.iter().any(|e| e.action == "vault.create"));
    // Leaving syncs at once: the vault and its items are gone here.
    block_on(bea_h.leave_vault(ops.id.clone())).unwrap();
    assert!(!bea.vaults(None).unwrap().iter().any(|v| v.id == ops.id));
    assert!(
        bea.get_host(web.id.clone(), Some(bea_acc.id.clone()))
            .is_err()
    );
    assert!(matches!(
        block_on(ana_h.delete_vault(ops.id.clone(), "wrong".into())),
        Err(TermoakError::Invalid(_))
    ));
    block_on(ana_h.delete_vault(ops.id.clone(), "Ops".into())).unwrap();

    // --- Signing out of one account keeps the other ---
    let out = block_on(bea.sign_out_account(carl_acc.id.clone(), false)).unwrap();
    assert!(out.signed_out, "{out:?}");
    assert_eq!(bea.accounts().len(), 1);
    assert_eq!(bea.current_account().unwrap().id, bea_acc.id);
    assert!(block_on(bea.is_logged_in()).unwrap());
}
