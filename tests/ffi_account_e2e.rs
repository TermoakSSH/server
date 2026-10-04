//! Account features from the FFI layer against a real in-process server:
//! two-factor authentication, invites, teams and administration. No `sshd`
//! needed. Also covers `ssh_config` import, autocompletion and QR codes,
//! which are local.

use std::path::PathBuf;
use std::time::Duration;

use futures::executor::block_on;
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

fn core(dir: &tempfile::TempDir, name: &str) -> std::sync::Arc<TermoakCore> {
    TermoakCore::new(
        dir.path().join(name).to_string_lossy().into_owned(),
        generate_vault_key(),
    )
    .unwrap()
}

/// Current TOTP code for a base32 secret.
fn totp_now(secret_b32: &str) -> String {
    let secret = termoak_core::totp::secret_from_base32(secret_b32).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!(
        "{:06}",
        termoak_core::totp::code_at(&secret, termoak_core::totp::step_at(now))
    )
}

#[test]
fn accounts_from_mobile() {
    let tmp = tempfile::tempdir().unwrap();
    let base = start_server(tmp.path().join("server"));

    // --- Ana creates the server (first account = admin) ---
    let ana = core(&tmp, "ana");
    block_on(ana.register(
        base.clone(),
        "ana@termoak.test".into(),
        "Ana".into(),
        "strong-password".into(),
        None,
    ))
    .unwrap();

    // --- Language ---
    let locales = block_on(server_locales(base.clone())).unwrap();
    assert!(locales.iter().any(|l| l.code == "en"));
    assert!(
        locales
            .iter()
            .any(|l| l.code == "es" && l.name == "Español")
    );
    let me = block_on(ana.current_user()).unwrap();
    assert_eq!(
        (me.email.as_str(), me.locale.as_str()),
        ("ana@termoak.test", "en")
    );
    assert_eq!(block_on(ana.set_locale("es".into())).unwrap().locale, "es");
    assert_eq!(block_on(ana.current_user()).unwrap().locale, "es");
    assert!(block_on(ana.set_locale("xx".into())).is_err());
    assert_eq!(block_on(ana.current_user()).unwrap().locale, "es");

    // --- Two-factor authentication ---
    assert!(!block_on(ana.two_factor_status()).unwrap().enabled);
    let setup = block_on(ana.setup_two_factor()).unwrap();
    assert!(setup.otpauth_url.starts_with("otpauth://totp/"));
    let qr = qr_code(setup.otpauth_url.clone()).unwrap();
    assert_eq!(qr.modules.len(), (qr.size * qr.size) as usize);
    assert!(matches!(
        block_on(ana.enable_two_factor("000000".into())),
        Err(TermoakError::Invalid(_) | TermoakError::TotpInvalid(_))
    ));
    let recovery = block_on(ana.enable_two_factor(totp_now(&setup.secret))).unwrap();
    assert_eq!(recovery.len(), 10);
    let status = block_on(ana.two_factor_status()).unwrap();
    assert!(status.enabled);
    assert_eq!(status.recovery_codes_left, 10);

    // From another device: without a code it asks for one; a recovery code
    // gets in.
    let ana_phone = core(&tmp, "ana-phone");
    let login = |code: Option<String>| {
        block_on(ana_phone.login(
            base.clone(),
            "ana@termoak.test".into(),
            "strong-password".into(),
            code,
        ))
    };
    assert!(matches!(login(None), Err(TermoakError::TotpRequired(_))));
    assert!(matches!(
        login(Some("123456".into())),
        Err(TermoakError::TotpInvalid(_))
    ));
    login(Some(recovery[0].clone())).unwrap();
    assert_eq!(
        block_on(ana_phone.two_factor_status())
            .unwrap()
            .recovery_codes_left,
        9
    );

    // --- Push notifications (not configured on this server) ---
    assert!(
        !block_on(ana_phone.register_push_token(PushPlatform::Apns, "abcdef0123".into(), true))
            .unwrap()
    );
    let devices = block_on(ana_phone.api_get("/api/v1/devices".into())).unwrap();
    assert!(devices.contains("\"push\":\"apns\""), "{devices}");
    assert!(matches!(
        block_on(ana_phone.send_test_push()),
        Err(TermoakError::Invalid(_))
    ));
    block_on(ana_phone.unregister_push_token()).unwrap();
    let devices = block_on(ana_phone.api_get("/api/v1/devices".into())).unwrap();
    assert!(!devices.contains("\"push\":\"apns\""), "{devices}");

    // --- Teams and invites ---
    let team = block_on(ana.create_team("Operations".into())).unwrap();
    assert_eq!(team.role, Some(TeamRole::Owner));
    let created = block_on(ana.admin_create_invite(
        Some("beto@termoak.test".into()),
        Some(team.id.clone()),
        false,
        None,
    ))
    .unwrap();
    assert!(created.app_link.starts_with("termoak://invite"));
    let info = block_on(invite_info(base.clone(), created.token.clone())).unwrap();
    assert_eq!(info.email.as_deref(), Some("beto@termoak.test"));
    assert_eq!(info.team.as_deref(), Some("Operations"));

    // Without an invite, registration is closed.
    let beto = core(&tmp, "beto");
    assert!(
        block_on(beto.register(
            base.clone(),
            "beto@termoak.test".into(),
            "Beto".into(),
            "another-password".into(),
            None,
        ))
        .is_err()
    );
    block_on(beto.register(
        base.clone(),
        "beto@termoak.test".into(),
        "Beto".into(),
        "another-password".into(),
        Some(created.token.clone()),
    ))
    .unwrap();
    let teams = block_on(beto.list_teams()).unwrap();
    assert_eq!(teams.len(), 1);
    assert_eq!(teams[0].role, Some(TeamRole::Member));
    // A member cannot manage the team.
    assert!(matches!(
        block_on(beto.rename_team(team.id.clone(), "Mine".into())),
        Err(TermoakError::Forbidden(_))
    ));
    let beto_id = block_on(ana.list_team_members(team.id.clone()))
        .unwrap()
        .into_iter()
        .find(|m| m.email == "beto@termoak.test")
        .unwrap()
        .user_id;
    let members =
        block_on(ana.set_team_member_role(team.id.clone(), beto_id.clone(), TeamRole::Admin))
            .unwrap();
    assert!(
        members
            .iter()
            .any(|m| m.user_id == beto_id && m.role == TeamRole::Admin)
    );
    let renamed = block_on(beto.rename_team(team.id.clone(), "Ops".into())).unwrap();
    assert_eq!(renamed.name, "Ops");
    block_on(beto.leave_team(team.id.clone())).unwrap();
    assert!(block_on(beto.list_teams()).unwrap().is_empty());

    // --- Administration ---
    let invites = block_on(ana.admin_list_invites()).unwrap();
    assert!(invites[0].used_at.is_some());
    let users = block_on(ana.admin_list_users()).unwrap();
    assert_eq!(users.len(), 2);
    assert!(
        users
            .iter()
            .any(|u| u.email == "ana@termoak.test" && u.two_factor)
    );
    assert!(matches!(
        block_on(beto.admin_list_users()),
        Err(TermoakError::Forbidden(_))
    ));
    let disabled =
        block_on(ana.admin_update_user(beto_id.clone(), None, None, Some(true))).unwrap();
    assert!(disabled.disabled);
    block_on(ana.admin_reset_two_factor(users.iter().find(|u| u.is_admin).unwrap().id.clone()))
        .unwrap();
    assert!(!block_on(ana.two_factor_status()).unwrap().enabled);
    let audit = block_on(ana.admin_audit(None, 100)).unwrap();
    assert!(audit.iter().any(|e| e.action == "auth.2fa_enabled"));
}

#[test]
fn import_and_autocomplete() {
    let tmp = tempfile::tempdir().unwrap();
    let c = core(&tmp, "local");
    let config = "\
Host bastion
    HostName bastion.example.com
    User ops

Host web-*
    User deploy
    ProxyJump bastion

Host web-1
    HostName 10.0.0.11
    LocalForward 8080 localhost:80
";
    let preview = c
        .import_ssh_config(
            config.into(),
            SshConfigImportOptions {
                dry_run: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(preview.hosts_created, ["bastion", "web-1"]);
    assert!(
        c.list_hosts().unwrap().is_empty(),
        "the preview does not save"
    );
    let report = c
        .import_ssh_config(
            config.into(),
            SshConfigImportOptions {
                group: Some("Imported".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(report.forwards_created, 1);
    let hosts = c.list_hosts().unwrap();
    let web = hosts.iter().find(|h| h.label == "web-1").unwrap();
    assert_eq!(web.settings.username.as_deref(), Some("deploy"));
    // Repeating does not duplicate.
    let again = c
        .import_ssh_config(config.into(), SshConfigImportOptions::default())
        .unwrap();
    assert!(again.hosts_created.is_empty());
    assert_eq!(again.hosts_skipped.len(), 2);

    // Autocompletion: this host's history first, then the dictionary.
    assert!(
        c.record_command(web.id.clone(), "systemctl status nginx".into())
            .unwrap()
    );
    assert!(
        !c.record_command(web.id.clone(), " export TOKEN=secret".into())
            .unwrap()
    );
    let s = c
        .complete_command(
            Some(web.id.clone()),
            Some("ubuntu".into()),
            "systemctl st".into(),
            5,
        )
        .unwrap();
    assert_eq!(s[0].text, "systemctl status nginx");
    assert_eq!(s[0].insert, "atus nginx");
    assert_eq!(s[0].source, SuggestionSource::History);
    let apt = c
        .complete_command(None, Some("debian".into()), "apt ins".into(), 5)
        .unwrap();
    assert!(apt.iter().any(|x| x.text.starts_with("apt install")));
    let apk = c
        .complete_command(None, Some("alpine".into()), "apt ins".into(), 5)
        .unwrap();
    assert!(apk.is_empty(), "apt is not suggested on Alpine: {apk:?}");
    c.clear_command_history(None).unwrap();
    assert!(
        c.complete_command(Some(web.id.clone()), None, "systemctl status n".into(), 5)
            .unwrap()
            .is_empty()
    );
}
