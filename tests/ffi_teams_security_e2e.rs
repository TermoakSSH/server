//! Teams security from the apps' engine (0.7 phase 4b): a Connect-only
//! member connects from their device to a host that only trusts the team
//! CA (the engine gets a certificate for an ephemeral key by itself), the
//! access policy makes it ask for access first, the approval opens it, and
//! a mandatory recording of the local terminal is uploaded to the server.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::executor::block_on;
use parking_lot::{Condvar, Mutex};
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

struct CaSshd {
    child: Child,
    port: u16,
    _dir: tempfile::TempDir,
    user: String,
}

impl Drop for CaSshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn ca_sshd(ca_keys: &str) -> Option<CaSshd> {
    let sshd = ["/usr/sbin/sshd", "/usr/local/sbin/sshd"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())?;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let hk = d.join("hk");
    Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&hk)
        .status()
        .ok()?;
    std::fs::write(d.join("ca.pub"), ca_keys).unwrap();
    std::fs::write(d.join("ak"), "").unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::create_dir_all("/run/sshd").ok();
    let cfg = d.join("cfg");
    std::fs::write(
        &cfg,
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\nTrustedUserCAKeys {}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin yes\nLogLevel ERROR\n",
            hk.display(),
            d.join("pid").display(),
            d.join("ak").display(),
            d.join("ca.pub").display(),
        ),
    )
    .unwrap();
    let child = Command::new(sshd)
        .args(["-D", "-e", "-f"])
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            let user = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
                .unwrap()
                .trim()
                .to_string();
            return Some(CaSshd {
                child,
                port,
                _dir: dir,
                user,
            });
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

struct TrustAll;

impl AuthHandler for TrustAll {
    fn on_host_key(&self, _: String, _: u32, _: String, _: String) -> bool {
        true
    }

    fn on_prompt(&self, _: AuthRequest) -> Option<Vec<String>> {
        None
    }
}

#[derive(Default)]
struct Term {
    out: Mutex<String>,
    closed: Mutex<bool>,
    cv: Condvar,
}

impl TerminalListener for Term {
    fn on_output(&self, data: Vec<u8>) {
        self.out.lock().push_str(&String::from_utf8_lossy(&data));
        self.cv.notify_all();
    }

    fn on_status(&self, status: TerminalStatus) {
        if matches!(status, TerminalStatus::Closed { .. }) {
            *self.closed.lock() = true;
            self.cv.notify_all();
        }
    }
}

impl Term {
    fn wait_output(&self, needle: &str) {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut out = self.out.lock();
        while !out.contains(needle) {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "\"{needle}\" never showed up: {out:?}");
            self.cv.wait_for(&mut out, left);
        }
    }

    fn wait_closed(&self) {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut c = self.closed.lock();
        while !*c {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "the terminal did not close");
            self.cv.wait_for(&mut c, left);
        }
    }
}

const PW: &str = "strong-password";

fn code_of(e: &TermoakError) -> String {
    api_error_info(e.to_string())
        .map(|i| i.code)
        .unwrap_or_else(|| e.to_string())
}

#[test]
fn connect_only_member_uses_team_certificates_from_the_device() {
    let tmp = tempfile::tempdir().unwrap();
    let base = start_server(tmp.path().join("server"));
    let server = ServerChoice::Custom { url: base };
    let new_core = |name: &str| {
        TermoakCore::new(
            tmp.path().join(name).to_string_lossy().into_owned(),
            generate_vault_key(),
        )
        .unwrap()
    };
    let ana = new_core("ana");
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
    let ana_h = ana.account(ana_acc.id.clone()).unwrap();
    let bea = new_core("bea");
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

    // Team "Ops" with Bea; its vault "Prod" is Connect only for members.
    let team = block_on(ana_h.create_team("Ops".into())).unwrap();
    block_on(ana_h.add_team_member(team.id.clone(), "bea@termoak.test".into(), TeamRole::Member))
        .unwrap();
    let prod = block_on(ana_h.create_vault(NewVault {
        name: "Prod".into(),
        description: None,
        color: None,
        icon: None,
        team_id: Some(team.id.clone()),
        team_member_role: Some(VaultRole::ConnectOnly),
        strict: false,
    }))
    .unwrap();
    let ca = block_on(ana_h.create_ca(Some(team.id.clone()), None)).unwrap();
    assert!(ca.ca.is_some() && ca.can_manage);
    assert_eq!(
        ca.sshd_config,
        vec!["TrustedUserCAKeys /etc/ssh/termoak_user_ca.pub"]
    );
    let Some(sshd) = ca_sshd(&ca.keys_file) else {
        eprintln!("sshd not available: skipped");
        return;
    };
    let host = ana
        .save_host(
            SshHost {
                id: String::new(),
                label: "trusting".into(),
                address: "127.0.0.1".into(),
                group_id: None,
                tags: vec![],
                settings: HostSettings {
                    username: Some(sshd.user.clone()),
                    port: Some(u32::from(sshd.port)),
                    auth: Some("team_certificate".into()),
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
                account_id: Some(ana_acc.id.clone()),
                vault_id: Some(prod.id.clone()),
                access: None,
                secret_hidden: false,
                e2ee_locked: false,
            },
            SecretChange::Keep,
        )
        .unwrap();
    assert_eq!(host.settings.auth.as_deref(), Some("team_certificate"));
    block_on(ana_h.sync_now()).unwrap();

    // Bea sees Connect only and the policy flags.
    block_on(bea_h.sync_now()).unwrap();
    let vaults = bea.vaults(None).unwrap();
    let v = vaults.iter().find(|v| v.id == prod.id).unwrap();
    assert_eq!(v.role, VaultRole::ConnectOnly);
    let policy = v.policy.clone().expect("policy from a new server");
    assert!(policy.certificates && !policy.access_policies);
    let mine = bea.get_host(host.id.clone(), None).unwrap();
    assert_eq!(mine.access, Some(ItemAccess::ConnectOnly));

    // From her device: certificate for an ephemeral key, no secrets.
    let session = block_on(bea.connect(host.id.clone(), Arc::new(TrustAll), None, None)).unwrap();
    let out = block_on(session.exec("echo from-the-device".into(), 10)).unwrap();
    assert_eq!(out.stdout.trim(), "from-the-device");
    let _ = block_on(session.disconnect());
    let certs = block_on(bea_h.my_certificates()).unwrap();
    assert!(
        certs
            .iter()
            .any(|c| c.purpose == "device" && c.host_id.as_deref() == Some(host.id.as_str()))
    );

    // An access policy: ask first.
    block_on(ana_h.set_access_policy(
        prod.id.clone(),
        AccessTargetKind::Host,
        host.id.clone(),
        AccessPolicyInfo {
            mode: AccessMode::Approval,
            approvers: vec![],
            max_minutes: 30,
            request_ttl_minutes: 60,
            allow_self_approval: false,
            require_for_managers: false,
            principals: None,
            cert_ttl_minutes: None,
            extensions: None,
            source_address: None,
            force_command: None,
            record_sessions: true,
        },
    ))
    .unwrap();
    block_on(bea_h.sync_now()).unwrap();
    let err = block_on(bea.connect(host.id.clone(), Arc::new(TrustAll), None, None))
        .err()
        .expect("needs approval");
    assert_eq!(code_of(&err), "access_approval_required", "{err}");
    let access = block_on(bea_h.host_access(host.id.clone())).unwrap();
    assert!(access.can_request && !access.allowed && access.record_required);
    let req = block_on(bea_h.create_access_request(
        AccessTargetKind::Host,
        host.id.clone(),
        15,
        "deploy".into(),
    ))
    .unwrap();
    assert_eq!(req.status, AccessRequestStatus::Pending);
    let inbox = block_on(ana_h.access_requests(
        AccessRequestScope::Approvals,
        Some(AccessRequestStatus::Pending),
    ))
    .unwrap();
    assert!(inbox.iter().any(|r| r.id == req.id && r.can_decide));
    let approved =
        block_on(ana_h.approve_access_request(req.id.clone(), Some(10), Some("ok".into())))
            .unwrap();
    assert!(approved.active && approved.minutes == 10);

    // Approved: a terminal, recorded and uploaded when it closes.
    let term = Arc::new(Term::default());
    let handle = block_on(bea.connect_terminal(
        host.id.clone(),
        80,
        24,
        Arc::new(TrustAll),
        term.clone(),
        None,
        false,
        false,
        None,
    ))
    .unwrap();
    assert!(handle.recording_path().is_some(), "mandatory recording");
    handle
        .write_text("echo recorded-$((40+2)); exit\n".into())
        .unwrap();
    term.wait_output("recorded-42");
    term.wait_closed();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let recs = block_on(ana_h.vault_recordings(prod.id.clone())).unwrap();
        if recs
            .iter()
            .any(|r| r.kind == "device" && r.host_id.as_deref() == Some(host.id.as_str()))
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the recording was not uploaded: {recs:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // Revoked: asking again.
    block_on(ana_h.revoke_access_request(req.id.clone(), None)).unwrap();
    let err = block_on(bea.connect(host.id.clone(), Arc::new(TrustAll), None, None))
        .err()
        .expect("revoked");
    assert_eq!(code_of(&err), "access_approval_required", "{err}");
}
