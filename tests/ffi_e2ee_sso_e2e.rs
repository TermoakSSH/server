//! The apps' engine (FFI) against a real in-process server for 0.7 phase
//! 5a: an account sets up E2EE, turns a vault's E2EE on from its device,
//! edits a secret (sealed by the engine's sync), a second device of the same
//! person sees it locked, unlocks with the recovery key, a third one is
//! paired from the second, a server session opens with a per-session
//! unlock, E2EE goes off again; then a single sign-on from the desktop path
//! (loopback) against an in-process identity provider, and the audit read
//! through the engine.

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures::executor::block_on;
use serde_json::json;
use termoak_ffi::*;
use termoak_server::config::ServerConfig;
use termoak_server::{build_state, routes};

struct Started {
    base: String,
    idp: Arc<common::oidc::Idp>,
    txt: common::oidc::Txt,
}

fn start_server(data: PathBuf) -> Started {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let idp = common::oidc::start_idp().await;
            let (dns, txt) = common::oidc::start_dns().await;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let mut config = ServerConfig::default();
            config.server.listen = addr;
            config.server.data_dir = data;
            config.server.registration = termoak_server::config::Registration::Open;
            config.server.public_url = Some(format!("http://{addr}"));
            config.sessions.host_key_policy = termoak_ssh::HostKeyPolicy::AcceptNew;
            config.sso.allowed_issuers = vec![format!("{}/", idp.base)];
            config.sso.dns_servers = vec![dns];
            let state = build_state(config).await.unwrap();
            tx.send(Started {
                base: format!("http://{addr}"),
                idp,
                txt,
            })
            .unwrap();
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

fn host(label: &str, account: &str, vault: &str, user: &str, port: u16) -> SshHost {
    SshHost {
        id: String::new(),
        label: label.into(),
        address: "127.0.0.1".into(),
        group_id: None,
        tags: vec![],
        settings: HostSettings {
            username: Some(user.into()),
            port: Some(port as u32),
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
        account_id: Some(account.into()),
        vault_id: Some(vault.into()),
        access: None,
        secret_hidden: false,
        e2ee_locked: false,
    }
}

fn code(e: &TermoakError) -> String {
    api_error_info(e.to_string())
        .map(|i| i.code)
        .unwrap_or_default()
}

const PW: &str = "strong-password";

#[test]
fn e2ee_from_the_engine() {
    let tmp = tempfile::tempdir().unwrap();
    let s = start_server(tmp.path().join("server"));
    let server = ServerChoice::Custom {
        url: s.base.clone(),
    };

    // --- Laptop: account, vault with a host, E2EE on ---
    let laptop = core(&tmp, "laptop");
    let acc = block_on(laptop.sign_up(
        server.clone(),
        "ana@termoak.test".into(),
        "Ana".into(),
        PW.into(),
        None,
        false,
        None,
    ))
    .unwrap();
    let ana = laptop.account(acc.id.clone()).unwrap();
    let st = block_on(ana.e2ee_status()).unwrap();
    assert!(!st.set_up && !st.unlocked);
    let setup = block_on(ana.e2ee_setup(Some("correct horse battery".into()))).unwrap();
    assert!(e2ee_recovery_key_valid(setup.recovery_key.clone()));
    let st = block_on(ana.e2ee_status()).unwrap();
    assert!(st.set_up && st.unlocked && st.has_passphrase && st.has_recovery_key);
    let ops = block_on(ana.create_vault(NewVault {
        name: "Ops".into(),
        description: None,
        color: None,
        icon: None,
        team_id: None,
        team_member_role: None,
        strict: false,
    }))
    .unwrap();
    let sshd = common::start_sshd();
    let (user, port) = sshd
        .as_ref()
        .map(|d| (d.user.clone(), d.port))
        .unwrap_or(("root".into(), 22));
    let web = laptop
        .save_host(
            host("web", &acc.id, &ops.id, &user, port),
            SecretChange::Set {
                value: "first-pw".into(),
            },
        )
        .unwrap();
    block_on(ana.sync_now()).unwrap();
    let state = block_on(ana.e2ee_vault_state(ops.id.clone())).unwrap();
    assert!(!state.e2ee && state.items == 1 && state.recipients.len() == 1);
    block_on(ana.e2ee_enable_vault(ops.id.clone(), None)).unwrap();
    let v = laptop
        .vaults(None)
        .unwrap()
        .into_iter()
        .find(|v| v.id == ops.id)
        .unwrap();
    let e = v.e2ee.expect("an E2EE vault");
    assert!(e.has_wrap && e.may_hold_key && !e.rekey_needed);
    // The laptop still has the secret; a new one goes up sealed.
    assert_eq!(
        laptop
            .host_password(web.id.clone(), None)
            .unwrap()
            .as_deref(),
        Some("first-pw")
    );
    let mut h = laptop.get_host(web.id.clone(), None).unwrap();
    h.notes = "edited".into();
    laptop
        .save_host(
            h,
            SecretChange::Set {
                value: "second-pw".into(),
            },
        )
        .unwrap();
    let r = block_on(ana.sync_now()).unwrap();
    assert_eq!((r.e2ee_waiting, r.e2ee_locked), (0, 0));

    // --- Phone: same person, locked ---
    let phone = core(&tmp, "phone");
    let pacc = block_on(phone.sign_in(server.clone(), "ana@termoak.test".into(), PW.into(), None))
        .unwrap();
    let pana = phone.account(pacc.id.clone()).unwrap();
    let r = block_on(pana.sync_now()).unwrap();
    assert!(r.e2ee_locked >= 1, "{r:?}");
    let ph = phone.get_host(web.id.clone(), None).unwrap();
    assert!(ph.e2ee_locked && ph.has_password);
    let err = phone.host_password(web.id.clone(), None).unwrap_err();
    assert!(matches!(err, TermoakError::E2eeLocked(_)), "{err:?}");
    assert_eq!(code(&err), "e2ee_locked");
    // A wrong passphrase, then the recovery key.
    let err = block_on(pana.e2ee_unlock_with_passphrase("wrong horse".into())).unwrap_err();
    assert_eq!(code(&err), "e2ee_passphrase_invalid");
    let opened =
        block_on(pana.e2ee_unlock_with_recovery_key(setup.recovery_key.to_lowercase())).unwrap();
    assert!(opened >= 1);
    assert_eq!(
        phone
            .host_password(web.id.clone(), None)
            .unwrap()
            .as_deref(),
        Some("second-pw")
    );
    assert!(!phone.get_host(web.id.clone(), None).unwrap().e2ee_locked);

    // --- Tablet: paired from the phone ---
    let tablet = core(&tmp, "tablet");
    let tacc = block_on(tablet.sign_in(server.clone(), "ana@termoak.test".into(), PW.into(), None))
        .unwrap();
    let tana = tablet.account(tacc.id.clone()).unwrap();
    let start = block_on(tana.e2ee_pairing_start()).unwrap();
    assert_eq!(start.code.len(), 6);
    assert!(
        block_on(tana.e2ee_pairing_finish(start.id.clone()))
            .unwrap()
            .is_none()
    );
    let reqs = block_on(pana.e2ee_pairings()).unwrap();
    let req = reqs.iter().find(|r| r.id == start.id).unwrap();
    assert_eq!(req.code, start.code, "both devices show the same code");
    block_on(pana.e2ee_pairing_decide(start.id.clone(), true)).unwrap();
    assert!(
        block_on(tana.e2ee_pairing_finish(start.id.clone()))
            .unwrap()
            .is_some()
    );
    block_on(tana.sync_now()).unwrap();
    assert_eq!(
        tablet
            .host_password(web.id.clone(), None)
            .unwrap()
            .as_deref(),
        Some("second-pw")
    );

    // --- A server session with a per-session unlock ---
    if let Some(sshd) = &sshd {
        // A key of the vault (sealed by the engine) signs in to the sshd.
        let key = block_on(laptop.import_key(
            "box".into(),
            sshd.private_key.clone(),
            None,
            false,
            None,
            Some(acc.id.clone()),
            Some(ops.id.clone()),
        ))
        .unwrap();
        let mut hk = laptop.get_host(web.id.clone(), None).unwrap();
        hk.settings.key_id = Some(key.id.clone());
        laptop.save_host(hk, SecretChange::Clear).unwrap();
        block_on(ana.sync_now()).unwrap();
        let err =
            block_on(ana.open_server_session(web.id.clone(), 80, 24, None, None)).unwrap_err();
        assert_eq!(code(&err), "e2ee_unlock_required", "{err:?}");
        let sess =
            block_on(ana.open_server_session_unlocked(web.id.clone(), 80, 24, None, None)).unwrap();
        // The holder-less server connects in the background.
        let mut running = false;
        for _ in 0..50 {
            let st = block_on(ana.get_server_session(sess.id.clone())).unwrap();
            match st.state {
                ServerSessionState::Running => {
                    running = true;
                    break;
                }
                ServerSessionState::Closed { .. } => panic!("the session closed: {st:?}"),
                _ => {}
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        assert!(running, "the unlocked session runs");
        block_on(ana.close_server_session(sess.id.clone())).unwrap();
        // Put the password back for the rest.
        let hk = laptop.get_host(web.id.clone(), None).unwrap();
        laptop
            .save_host(
                hk,
                SecretChange::Set {
                    value: "second-pw".into(),
                },
            )
            .unwrap();
        block_on(ana.sync_now()).unwrap();
        block_on(pana.sync_now()).unwrap();
    }

    // --- 0.7 phase 5b: moves and copies with an E2EE vault (done by the device) ---
    let lab = block_on(ana.create_vault(NewVault {
        name: "Lab".into(),
        description: None,
        color: None,
        icon: None,
        team_id: None,
        team_member_role: None,
        strict: false,
    }))
    .unwrap();
    let db = laptop
        .save_host(
            host("db", &acc.id, &lab.id, "root", 22),
            SecretChange::Set {
                value: "lab-pw".into(),
            },
        )
        .unwrap();
    block_on(ana.sync_now()).unwrap();
    let in_vault = |core: &Arc<TermoakCore>, vault: &str, label: &str| {
        core.list_hosts(Some(ItemFilter {
            account_ids: None,
            vault_ids: Some(vec![vault.to_string()]),
            include_device: false,
        }))
        .unwrap()
        .into_iter()
        .find(|h| h.label == label)
    };
    // Into the E2EE vault: a sealed copy there, the original deleted.
    block_on(laptop.transfer(
        vec![ItemRef {
            account_id: Some(acc.id.clone()),
            id: db.id.clone(),
        }],
        Some(acc.id.clone()),
        Some(ops.id.clone()),
        TransferMode::Move,
        false,
    ))
    .unwrap();
    block_on(ana.sync_now()).unwrap();
    assert!(in_vault(&laptop, &lab.id, "db").is_none());
    let moved = in_vault(&laptop, &ops.id, "db").expect("db moved into Ops");
    block_on(pana.sync_now()).unwrap();
    assert_eq!(
        phone
            .host_password(moved.id.clone(), None)
            .unwrap()
            .as_deref(),
        Some("lab-pw"),
        "the phone (unlocked) opens the sealed copy"
    );
    // Out of it: a server-readable copy in Lab.
    block_on(laptop.transfer(
        vec![ItemRef {
            account_id: Some(acc.id.clone()),
            id: web.id.clone(),
        }],
        Some(acc.id.clone()),
        Some(lab.id.clone()),
        TransferMode::Copy,
        false,
    ))
    .unwrap();
    block_on(ana.sync_now()).unwrap();
    let copy = in_vault(&laptop, &lab.id, "web").expect("web copied into Lab");
    assert_eq!(
        laptop
            .host_password(copy.id.clone(), None)
            .unwrap()
            .as_deref(),
        Some("second-pw")
    );
    assert!(in_vault(&laptop, &ops.id, "web").is_some());

    // --- 0.7 phase 5b: passphrase removed, key replaced, reset preview ---
    assert!(block_on(ana.e2ee_remove_passphrase()).unwrap());
    let st = block_on(ana.e2ee_status()).unwrap();
    assert!(!st.has_passphrase && st.has_recovery_key);
    let err = block_on(tana.e2ee_unlock_with_passphrase("correct horse battery".into()));
    assert!(err.is_err());
    // Nobody else holds Ops' key: a reset would lose it.
    let orphaned = block_on(ana.e2ee_reset(false)).unwrap();
    assert_eq!(orphaned, vec![ops.id.clone()]);
    let old_fp = st.key.as_ref().unwrap().fingerprint.clone();
    let rotated = block_on(ana.e2ee_rotate_user_key(Some("new horse battery staple".into()))).unwrap();
    assert_ne!(rotated.key.fingerprint, old_fp);
    assert!(e2ee_recovery_key_valid(rotated.recovery_key.clone()));
    assert_eq!(rotated.recovery_key.split(' ').count(), 24);
    block_on(ana.sync_now()).unwrap();
    // The laptop holds the new key and still opens the vault.
    let v = laptop
        .vaults(None)
        .unwrap()
        .into_iter()
        .find(|v| v.id == ops.id)
        .unwrap();
    assert!(v.e2ee.as_ref().is_some_and(|e| e.has_wrap));
    // The phone's old key no longer matches: it unlocks again with the
    // new passphrase.
    block_on(pana.e2ee_lock()).unwrap();
    block_on(pana.e2ee_unlock_with_passphrase("new horse battery staple".into())).unwrap();
    block_on(pana.sync_now()).unwrap();
    assert_eq!(
        phone
            .host_password(web.id.clone(), None)
            .unwrap()
            .as_deref(),
        Some("second-pw")
    );

    // --- E2EE off: other devices get plaintext again ---
    block_on(ana.e2ee_disable_vault(ops.id.clone())).unwrap();
    block_on(pana.sync_now()).unwrap();
    let v = phone
        .vaults(None)
        .unwrap()
        .into_iter()
        .find(|v| v.id == ops.id)
        .unwrap();
    assert!(v.e2ee.is_none());
    assert_eq!(
        phone
            .host_password(web.id.clone(), None)
            .unwrap()
            .as_deref(),
        Some("second-pw")
    );

    // --- The audit through the engine ---
    let entries = block_on(ana.audit_search(
        AuditScope::Vault,
        AuditQuery {
            action: Some("e2ee.*".into()),
            ..Default::default()
        },
        Some(ops.id.clone()),
    ))
    .unwrap();
    let actions: Vec<&str> = entries.iter().map(|e| e.action.as_str()).collect();
    assert!(
        actions.contains(&"e2ee.enable") && actions.contains(&"e2ee.disable"),
        "{actions:?}"
    );
    assert!(
        entries
            .iter()
            .all(|e| e.vault_id.as_deref() == Some(ops.id.as_str()))
    );
    let path = tmp.path().join("audit.csv");
    let n = block_on(ana.audit_export(
        AuditScope::Me,
        AuditQuery::default(),
        "csv".into(),
        path.to_string_lossy().into_owned(),
        None,
    ))
    .unwrap();
    assert!(
        n > 0
            && std::fs::read_to_string(&path)
                .unwrap()
                .starts_with("id,time,action")
    );
}

#[test]
fn single_sign_on_from_the_engine() {
    let tmp = tempfile::tempdir().unwrap();
    let s = start_server(tmp.path().join("server"));
    let server = ServerChoice::Custom {
        url: s.base.clone(),
    };
    let owner = core(&tmp, "owner");
    // The first account is the administrator; the owner is the second.
    block_on(owner.sign_up(
        server.clone(),
        "root@termoak.test".into(),
        "Root".into(),
        PW.into(),
        None,
        false,
        None,
    ))
    .unwrap();
    let oacc = block_on(owner.sign_up(
        server.clone(),
        "olga@corp.test".into(),
        "Olga".into(),
        PW.into(),
        None,
        false,
        None,
    ))
    .unwrap();
    let olga = owner.account(oacc.id.clone()).unwrap();
    let team: serde_json::Value = serde_json::from_str(
        &block_on(olga.api_post(
            "/api/v1/teams".into(),
            Some(json!({"name": "Corp"}).to_string()),
        ))
        .unwrap(),
    )
    .unwrap();
    let team_id = team["id"].as_str().unwrap().to_string();

    // SSO settings and the domain through the engine.
    let settings = SsoSettings {
        enabled: true,
        preset: "keycloak".into(),
        issuer: s.idp.base.clone(),
        tenant: None,
        client_id: "termoak".into(),
        scopes: vec![],
        email_claim: None,
        require_email_verified: true,
        enforce: false,
        owner_password_allowed: true,
        auto_create: true,
        auto_join: true,
        satisfies_2fa: false,
        has_client_secret: false,
        redirect_uri: String::new(),
    };
    let saved =
        block_on(olga.set_team_sso(team_id.clone(), settings.clone(), Some("s3cret".into())))
            .unwrap();
    assert!(saved.has_client_secret && saved.redirect_uri.ends_with("/api/v1/auth/sso/callback"));
    let d = block_on(olga.add_team_domain(team_id.clone(), "corp.test".into())).unwrap();
    s.txt
        .lock()
        .insert(d.record_name.clone(), d.record_value.clone());
    let d = block_on(olga.verify_team_domain(team_id.clone(), "corp.test".into())).unwrap();
    assert!(d.verified, "{d:?}");
    block_on(olga.set_team_sso(
        team_id.clone(),
        SsoSettings {
            enforce: true,
            ..settings
        },
        None,
    ))
    .unwrap();

    // A new desktop: Kim discovers SSO and signs in through the loopback.
    let desk = core(&tmp, "desk");
    let hint = block_on(desk.sso_discover(server.clone(), "kim@corp.test".into())).unwrap();
    assert!(hint.sso && hint.enforced && hint.team_name.as_deref() == Some("Corp"));
    let err = block_on(desk.sign_in(server.clone(), "kim@corp.test".into(), PW.into(), None))
        .unwrap_err();
    assert!(matches!(err, TermoakError::SsoRequired(_)), "{err:?}");
    *s.idp.next.lock() = common::oidc::Person {
        sub: "kim".into(),
        email: "kim@corp.test".into(),
        verified: true,
    };
    let lb = block_on(desk.sso_start_loopback(server.clone(), Some("kim@corp.test".into()), None))
        .unwrap();
    let flow = lb.flow();
    assert!(flow.redirect_uri.starts_with("http://127.0.0.1:"));
    // The "browser": the provider, the server's callback, then the loopback.
    let browser = std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let http = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            let a = http.get(&flow.authorize_url).send().await.unwrap();
            let cb = a.headers()["location"].to_str().unwrap().to_string();
            let b = http.get(&cb).send().await.unwrap();
            let back = b.headers()["location"].to_str().unwrap().to_string();
            assert!(back.starts_with("http://127.0.0.1:"), "{back}");
            let page = http.get(&back).send().await.unwrap().text().await.unwrap();
            assert!(page.contains("close this window"));
        })
    });
    let callback = block_on(lb.wait_callback(20)).unwrap();
    browser.join().unwrap();
    let kim = block_on(desk.sso_complete(lb.flow(), callback, None)).unwrap();
    assert_eq!(kim.email, "kim@corp.test");
    assert!(kim.is_current);

    // The mobile path: termoak://sso, completed with the URL the browser
    // came back to.
    let phone = core(&tmp, "phone");
    let flow = block_on(phone.sso_start(server.clone(), Some("kim@corp.test".into()), None, None))
        .unwrap();
    assert_eq!(flow.redirect_uri, "termoak://sso");
    let callback = std::thread::spawn({
        let url = flow.authorize_url.clone();
        move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async move {
                    let http = reqwest::Client::builder()
                        .redirect(reqwest::redirect::Policy::none())
                        .build()
                        .unwrap();
                    let a = http.get(&url).send().await.unwrap();
                    let b = http
                        .get(a.headers()["location"].to_str().unwrap())
                        .send()
                        .await
                        .unwrap();
                    b.headers()["location"].to_str().unwrap().to_string()
                })
        }
    })
    .join()
    .unwrap();
    assert!(callback.starts_with("termoak://sso?code="));
    let again = block_on(phone.sso_complete(flow.clone(), callback.clone(), None)).unwrap();
    assert_eq!(again.email, "kim@corp.test");
    assert!(
        block_on(phone.sso_complete(flow, callback, None)).is_err(),
        "a code works once"
    );

    // The team's audit through the engine (owner).
    let entries = block_on(olga.audit_search(
        AuditScope::Team,
        AuditQuery {
            action: Some("sso.*".into()),
            ..Default::default()
        },
        Some(team_id.clone()),
    ))
    .unwrap();
    let actions: Vec<&str> = entries.iter().map(|e| e.action.as_str()).collect();
    assert!(
        actions.contains(&"sso.login") && actions.contains(&"sso.user_created"),
        "{actions:?}"
    );
    // A webhook sink is refused on a private address (no allowance here).
    let err = block_on(olga.create_audit_sink(
        AuditScope::Team,
        AuditSinkInput {
            kind: "webhook".into(),
            name: "x".into(),
            url: Some("http://127.0.0.1:1/x".into()),
            host: None,
            port: None,
            transport: None,
            ca_pem: None,
            actions: vec![],
        },
        Some(team_id),
    ))
    .unwrap_err();
    assert_eq!(code(&err), "audit_sink_invalid");
}
