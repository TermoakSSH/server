//! The user's own AI keys through the FFI layer (`termoak-ffi`, the engine of
//! the mobile apps) against a real in-process server.
//!
//! The exported `async` functions are awaited with `futures::executor`, an
//! executor unrelated to tokio, as Swift and Kotlin coroutines will do.

use std::sync::Arc;

use futures::executor::block_on;
use termoak_ffi::*;

fn new_core(dir: &std::path::Path, key: &str) -> Arc<TermoakCore> {
    TermoakCore::new(dir.to_string_lossy().into_owned(), key.to_string()).unwrap()
}

/// Starts a Termoak server with open registration on its own runtime.
fn start_server() -> (String, tempfile::TempDir) {
    let data = tempfile::tempdir().unwrap();
    let dir = data.path().to_path_buf();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let mut config = termoak_server::config::ServerConfig::default();
            config.server.listen = addr;
            config.server.data_dir = dir;
            config.server.registration = termoak_server::config::Registration::Open;
            let state = termoak_server::build_state(config).await.unwrap();
            tx.send(format!("http://{addr}")).unwrap();
            axum::serve(listener, termoak_server::routes::router(state))
                .await
                .unwrap();
        });
    });
    (rx.recv().unwrap(), data)
}

#[test]
fn own_ai_keys() {
    let (url, _data) = start_server();
    let dir = tempfile::tempdir().unwrap();
    let admin = new_core(&dir.path().join("admin"), &generate_vault_key());
    block_on(admin.register(
        url.clone(),
        "admin@termoak.test".into(),
        "Admin".into(),
        "secure-password".into(),
        None,
    ))
    .unwrap();
    let core = new_core(&dir.path().join("user"), &generate_vault_key());
    block_on(core.register(
        url,
        "user@termoak.test".into(),
        "User".into(),
        "secure-password".into(),
        None,
    ))
    .unwrap();

    // Free plan without a key: no server AI.
    let access = block_on(core.ai_access()).unwrap();
    assert!(!access.server_ai && access.own_keys.is_empty());
    assert!(access.providers.iter().any(|p| p.provider == "claude"));
    let task = AiTaskRequest {
        prompt: "hello".into(),
        title: None,
        mode: None,
        provider: None,
        host_ids: Vec::new(),
        session_id: None,
        effort: None,
    };
    assert!(matches!(
        block_on(core.create_ai_task(task)),
        Err(TermoakError::AiKeyRequired(_))
    ));

    assert!(matches!(
        block_on(core.set_ai_key("codex".into(), Some("key".into()), None)),
        Err(TermoakError::Invalid(_))
    ));
    assert!(matches!(
        block_on(core.set_ai_key("../me".into(), Some("key".into()), None)),
        Err(TermoakError::Invalid(_))
    ));
    // Changing only the model needs a saved key.
    assert!(matches!(
        block_on(core.set_ai_key("claude".into(), None, Some("claude-opus-5".into()))),
        Err(TermoakError::NotFound(_))
    ));
    block_on(core.set_ai_key("claude".into(), Some("sk-ant-test-1234".into()), None)).unwrap();
    let saved =
        block_on(core.set_ai_key("claude".into(), None, Some("claude-sonnet-5".into()))).unwrap();
    assert_eq!(
        (saved.hint.as_str(), saved.model.as_deref()),
        ("1234", Some("claude-sonnet-5"))
    );
    assert_eq!(block_on(core.list_ai_keys()).unwrap(), vec![saved]);
    assert_eq!(
        block_on(core.ai_access()).unwrap().own_keys,
        vec!["claude".to_string()]
    );
    assert!(block_on(core.delete_ai_key("claude".into())).unwrap());
    assert!(!block_on(core.delete_ai_key("claude".into())).unwrap());

    // Administrators: the server's AI without limits.
    let access = block_on(admin.ai_access()).unwrap();
    assert!(access.server_ai && access.credit_usd.is_none());
}
