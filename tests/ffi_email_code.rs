//! Email verification with a code from the FFI layer (the mobile apps)
//! against a real in-process server that requires a verified email.

use std::path::PathBuf;
use std::time::Duration;

use futures::executor::block_on;
use termoak_ffi::*;
use termoak_server::config::{Registration, ServerConfig};
use termoak_server::state::AppState;
use termoak_server::{build_state, routes};

fn start_server(data: PathBuf) -> (String, AppState) {
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
            config.server.registration = Registration::Open;
            config.email.smtp_url = Some("log://".into());
            config.email.require_verification = true;
            let state = build_state(config).await.unwrap();
            tx.send((format!("http://{addr}"), state.clone())).unwrap();
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

/// Code of the last email to `to` (it is in the subject).
fn last_code(state: &AppState, to: &str) -> String {
    let mail = state
        .mailer
        .sent()
        .into_iter()
        .rev()
        .find(|m| m.to == to)
        .expect("a verification email");
    mail.subject.chars().filter(char::is_ascii_digit).collect()
}

#[test]
fn verify_the_email_with_a_code() {
    let tmp = tempfile::tempdir().unwrap();
    let (base, state) = start_server(tmp.path().join("server"));

    // The first account (admin) needs no verification.
    let ana = core(&tmp, "ana");
    block_on(ana.register(
        base.clone(),
        "ana@termoak.test".into(),
        "Ana".into(),
        "strong-password".into(),
        None,
    ))
    .unwrap();
    assert!(!block_on(ana.verification_required()).unwrap());

    // Bea signs up on her phone: pending, and the server says so.
    let bea = core(&tmp, "bea");
    block_on(bea.register(
        base.clone(),
        "bea@termoak.test".into(),
        "Bea".into(),
        "strong-password".into(),
        None,
    ))
    .unwrap();
    assert!(block_on(bea.verification_required()).unwrap());
    assert!(matches!(
        block_on(bea.sync_now()),
        Err(TermoakError::EmailNotVerified(_))
    ));
    let code = last_code(&state, "bea@termoak.test");
    assert_eq!(code.len(), 6);

    // Wrong code; asking for another one right away is too soon.
    assert!(matches!(
        block_on(bea.verify_code(
            base.clone(),
            "bea@termoak.test".into(),
            "000000".into(),
            None
        )),
        Err(TermoakError::Invalid(_))
    ));
    assert!(matches!(
        block_on(bea.resend_code(base.clone(), "bea@termoak.test".into())),
        Err(TermoakError::Server(_))
    ));

    // The right one (pasted with a dash) signs her in.
    let pasted = format!("{}-{}", &code[..3], &code[3..]);
    block_on(bea.verify_code(base.clone(), "bea@termoak.test".into(), pasted, None)).unwrap();
    assert!(!block_on(bea.verification_required()).unwrap());
    block_on(bea.sync_now()).unwrap();
    assert_eq!(
        block_on(bea.server_user()).unwrap().as_deref(),
        Some("bea@termoak.test")
    );

    // Carla signs up on the web and verifies on a phone that never signed in.
    let carla_web = core(&tmp, "carla-web");
    block_on(carla_web.register(
        base.clone(),
        "carla@termoak.test".into(),
        "Carla".into(),
        "strong-password".into(),
        None,
    ))
    .unwrap();
    let code = last_code(&state, "carla@termoak.test");
    let phone = core(&tmp, "carla-phone");
    assert!(!block_on(phone.is_logged_in()).unwrap());
    block_on(phone.verify_code(base.clone(), "carla@termoak.test".into(), code, None)).unwrap();
    assert!(block_on(phone.is_logged_in()).unwrap());
    assert_eq!(
        block_on(phone.server_url()).unwrap().as_deref(),
        Some(base.as_str())
    );
    block_on(phone.sync_now()).unwrap();
    // Resending to an unknown address looks the same as to a real one.
    block_on(phone.resend_code(base, "nobody@termoak.test".into())).unwrap();
}
