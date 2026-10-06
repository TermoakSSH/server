//! End-to-end test of the FFI layer against a real in-process server, with a
//! temporary `sshd` and a mock AI provider. Skipped if `sshd` is not
//! installed.
//!
//! The exported `async` functions are awaited with `futures::executor`, an
//! executor unrelated to tokio, as Swift and Kotlin coroutines will do.

use std::net::TcpListener as StdListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::executor::block_on;
use parking_lot::{Condvar, Mutex};
use serde_json::{Value, json};
use termoak_ai::{AiConfig, Driver, ProviderConfig};
use termoak_ffi::*;
use termoak_server::config::ServerConfig;
use termoak_server::{build_state, routes};

// ---------------------------------------------------------------------------
// Environment: sshd, mock AI and server
// ---------------------------------------------------------------------------

struct Sshd {
    child: Child,
    port: u16,
    _dir: tempfile::TempDir,
    private_key: String,
    user: String,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start_sshd() -> Option<Sshd> {
    if !cfg!(target_os = "linux") {
        return None;
    }
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
    let key = termoak_ssh_key();
    std::fs::write(d.join("ak"), format!("{}\n", key.1)).unwrap();
    let port = free_port();
    std::fs::create_dir_all("/run/sshd").ok();
    let cfg = d.join("cfg");
    std::fs::write(
        &cfg,
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin yes\nAllowTcpForwarding yes\nSubsystem sftp internal-sftp\nLogLevel ERROR\n",
            hk.display(),
            d.join("pid").display(),
            d.join("ak").display()
        ),
    )
    .unwrap();
    let child = Command::new(sshd)
        .args(["-D", "-e", "-f"])
        .arg(&cfg)
        .stdout(Stdio::null())
        .spawn()
        .ok()?;
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            let user = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
                .unwrap()
                .trim()
                .to_string();
            return Some(Sshd {
                child,
                port,
                _dir: dir,
                private_key: key.0,
                user,
            });
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

/// Ed25519 key pair (private, public) generated with `ssh-keygen`.
fn termoak_ssh_key() -> (String, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("id");
    let ok = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "ffi-e2e", "-f"])
        .arg(&path)
        .status()
        .unwrap()
        .success();
    assert!(ok);
    (
        std::fs::read_to_string(&path).unwrap(),
        std::fs::read_to_string(path.with_extension("pub")).unwrap(),
    )
}

/// Mock AI provider (Chat Completions with SSE): asks to run a command (a
/// write one if the prompt contains "CREATE") and then answers with the
/// output.
async fn mock_ai(marker: String) -> String {
    use axum::routing::post;
    let app = axum::Router::new().route(
        "/v1/chat/completions",
        post(move |axum::Json(body): axum::Json<Value>| {
            let marker = marker.clone();
            async move {
                let msgs = body["messages"].as_array().cloned().unwrap_or_default();
                let tool_result = msgs
                    .iter()
                    .rev()
                    .find(|m| m["role"] == "tool")
                    .map(|m| m["content"].as_str().unwrap_or("").to_string());
                let user_text: String = msgs
                    .iter()
                    .filter(|m| m["role"] == "user")
                    .map(|m| m["content"].as_str().unwrap_or("").to_string())
                    .collect();
                let chunks: Vec<Value> = match tool_result {
                    None => {
                        let cmd = if user_text.contains("CREATE") {
                            format!("touch {marker} && echo created")
                        } else {
                            "echo termoak-42".to_string()
                        };
                        let args = json!({"host": "local", "command": cmd}).to_string();
                        vec![
                            json!({"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"run_command","arguments":""}}]}}]}),
                            json!({"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":args}}]}}]}),
                            json!({"choices":[{"delta":{},"finish_reason":"tool_calls"}]}),
                            json!({"choices":[],"usage":{"prompt_tokens":100,"completion_tokens":20,"cost":0.001}}),
                        ]
                    }
                    Some(result) => vec![
                        json!({"choices":[{"delta":{"content":"Result: "}}]}),
                        json!({"choices":[{"delta":{"content":result.lines().filter(|l| l.contains("termoak-42") || l.contains("created")).collect::<Vec<_>>().join(" ")}}]}),
                        json!({"choices":[{"delta":{},"finish_reason":"stop"}]}),
                    ],
                };
                let mut sse = String::new();
                for ch in chunks {
                    sse.push_str(&format!("data: {ch}\n\n"));
                }
                sse.push_str("data: [DONE]\n\n");
                ([("content-type", "text/event-stream")], sse)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}/v1")
}

/// Starts the server on its own runtime (in another thread) and returns its URL.
fn start_server(data: PathBuf, marker: String) -> String {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let mock = mock_ai(marker).await;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let mut ai = AiConfig {
                default: "mock".into(),
                fallback: vec![],
                ..Default::default()
            };
            ai.providers.insert(
                "mock".into(),
                ProviderConfig {
                    driver: Driver::OpenaiChat,
                    base_url: Some(mock),
                    api_key: Some("x".into()),
                    model: Some("mock-1".into()),
                    subscription: false,
                    ..Default::default()
                },
            );
            let mut config = ServerConfig {
                ai,
                ..Default::default()
            };
            config.server.listen = addr;
            config.server.data_dir = data;
            let state = build_state(config).await.unwrap();
            tx.send(format!("http://{addr}")).unwrap();
            axum::serve(listener, routes::router(state)).await.unwrap();
        });
    });
    rx.recv_timeout(Duration::from_secs(30)).unwrap()
}

// ---------------------------------------------------------------------------
// Test implementations of the callbacks
// ---------------------------------------------------------------------------

/// Waits until `pred` holds for what has been collected.
fn wait_until<T, F: FnMut(&T) -> bool>(m: &Mutex<T>, cv: &Condvar, what: &str, mut pred: F) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut guard = m.lock();
    while !pred(&guard) {
        if cv.wait_until(&mut guard, deadline).timed_out() {
            panic!("timed out waiting for {what}");
        }
    }
}

#[derive(Default)]
struct TermEvents {
    events: Mutex<Vec<ServerTerminalEvent>>,
    cv: Condvar,
}

impl ServerTerminalListener for TermEvents {
    fn on_event(&self, event: ServerTerminalEvent) {
        self.events.lock().push(event);
        self.cv.notify_all();
    }
}

impl TermEvents {
    fn wait<F: Fn(&ServerTerminalEvent) -> bool>(&self, what: &str, f: F) -> ServerTerminalEvent {
        wait_until(&self.events, &self.cv, what, |evs| evs.iter().any(&f));
        self.events.lock().iter().find(|e| f(e)).cloned().unwrap()
    }

    fn output(&self) -> String {
        let mut s = String::new();
        for e in self.events.lock().iter() {
            match e {
                ServerTerminalEvent::Output { data } => s.push_str(&String::from_utf8_lossy(data)),
                ServerTerminalEvent::Resync => s.clear(),
                _ => {}
            }
        }
        s
    }

    fn wait_output(&self, needle: &str) {
        wait_until(&self.events, &self.cv, needle, |evs| {
            evs.iter().any(|e| {
                matches!(e, ServerTerminalEvent::Output { data } if String::from_utf8_lossy(data).contains(needle))
            })
        });
    }
}

#[derive(Default)]
struct UserEvents {
    events: Mutex<Vec<Value>>,
    closed: Mutex<bool>,
    cv: Condvar,
}

impl ServerEventListener for UserEvents {
    fn on_event(&self, event_json: String) {
        self.events
            .lock()
            .push(serde_json::from_str(&event_json).unwrap());
        self.cv.notify_all();
    }

    fn on_closed(&self, _reason: Option<String>) {
        *self.closed.lock() = true;
        self.cv.notify_all();
    }
}

/// Transfer progress (last value received).
#[derive(Default)]
struct Progress(Mutex<u64>);

impl TransferListener for Progress {
    fn on_progress(&self, transferred: u64, _total: Option<u64>) {
        *self.0.lock() = transferred;
    }
}

#[derive(Default)]
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
struct SharedEvents {
    events: Mutex<Vec<SharedTerminalEvent>>,
    cv: Condvar,
}

impl SharedTerminalListener for SharedEvents {
    fn on_event(&self, event: SharedTerminalEvent) {
        self.events.lock().push(event);
        self.cv.notify_all();
    }
}

impl SharedEvents {
    fn wait<T, F: Fn(&SharedTerminalEvent) -> Option<T>>(&self, what: &str, f: F) -> T {
        wait_until(&self.events, &self.cv, what, |evs| {
            evs.iter().any(|e| f(e).is_some())
        });
        self.events.lock().iter().find_map(f).unwrap()
    }
}

#[derive(Default)]
struct LocalTerm {
    out: Mutex<Vec<u8>>,
    cv: Condvar,
}

impl TerminalListener for LocalTerm {
    fn on_output(&self, data: Vec<u8>) {
        self.out.lock().extend_from_slice(&data);
        self.cv.notify_all();
    }

    fn on_status(&self, _status: TerminalStatus) {
        self.cv.notify_all();
    }
}

fn wait_task<F: Fn(&AiTask) -> bool>(core: &TermoakCore, id: &str, pred: F) -> AiTask {
    let mut last = None;
    for _ in 0..300 {
        let t = block_on(core.get_ai_task(id.to_string())).unwrap();
        if pred(&t) {
            return t;
        }
        last = Some(t);
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("the task did not reach the expected state: {last:?}");
}

fn parse(s: String) -> Value {
    serde_json::from_str(&s).unwrap()
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[test]
fn server_end_to_end() {
    let Some(sshd) = start_sshd() else {
        eprintln!("sshd not available: test skipped");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let marker = format!("/tmp/termoak-ffi-e2e-{}", std::process::id());
    let base = start_server(tmp.path().join("server"), marker.clone());

    let core = TermoakCore::new(
        tmp.path().join("phone").to_string_lossy().into_owned(),
        generate_vault_key(),
    )
    .unwrap();

    // --- Account ---
    let info = parse(block_on(server_info(base.clone())).unwrap());
    assert_eq!(info["needs_setup"], true);
    assert!(!block_on(core.is_logged_in()).unwrap());
    core.set_device_name("Ana's iPhone".into()).unwrap();
    assert_eq!(core.device_name().unwrap(), "Ana's iPhone");
    block_on(core.register(
        base.clone(),
        "ana@termoak.test".into(),
        "Ana".into(),
        "strong-password".into(),
        None,
    ))
    .unwrap();
    assert!(block_on(core.is_logged_in()).unwrap());
    assert_eq!(block_on(core.server_url()).unwrap(), Some(base.clone()));
    assert_eq!(
        block_on(core.server_user()).unwrap().as_deref(),
        Some("ana@termoak.test")
    );
    let me = parse(block_on(core.api_get("/api/v1/me".into())).unwrap());
    assert_eq!(me["user"]["email"], "ana@termoak.test");
    let devices = block_on(core.api_get("/api/v1/devices".into())).unwrap();
    assert!(devices.contains("Ana's iPhone"), "{devices}");
    assert!(matches!(
        block_on(core.api_get("/api/v1/missing".into())),
        Err(TermoakError::NotFound(_))
    ));

    // --- Sync ---
    let key = block_on(core.import_key(
        "e2e".into(),
        sshd.private_key.clone(),
        None,
        false,
        None,
        None,
        None,
    ))
    .unwrap();
    let host = core
        .save_host(
            SshHost {
                id: String::new(),
                label: "local".into(),
                address: "127.0.0.1".into(),
                group_id: None,
                tags: vec![],
                settings: HostSettings {
                    port: Some(sshd.port.into()),
                    username: Some(sshd.user.clone()),
                    key_id: Some(key.id.clone()),
                    ..Default::default()
                },
                notes: String::new(),
                color: None,
                os: None,
                os_version: None,
                favorite: true,
                sync_mode: None,
                has_password: false,
                updated_at: 0,
                account_id: None,
                vault_id: None,
                access: None,
                secret_hidden: false,
            },
            SecretChange::Keep,
        )
        .unwrap();
    let mut private = host.clone();
    private.id = String::new();
    private.label = "only-here".into();
    private.sync_mode = Some(SyncMode::DeviceOnly);
    core.save_host(private, SecretChange::Set { value: "pw".into() })
        .unwrap();
    let report = block_on(core.sync_now()).unwrap();
    assert_eq!(report.pushed, 2, "{report:?}");
    assert!(report.rev > 0);
    let remote_hosts = parse(block_on(core.api_get("/api/v1/hosts".into())).unwrap());
    let labels: Vec<&str> = remote_hosts
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["label"].as_str().unwrap())
        .collect();
    assert_eq!(
        labels,
        vec!["local"],
        "DeviceOnly records stay on the device"
    );
    // A change made "on another device" arrives on sync.
    block_on(core.api_post(
        "/api/v1/snippets".into(),
        Some(json!({"name": "from-server", "script": "uptime"}).to_string()),
    ))
    .unwrap();
    let report = block_on(core.sync_now()).unwrap();
    assert!(report.pulled >= 1, "{report:?}");
    assert!(
        core.list_snippets(None)
            .unwrap()
            .iter()
            .any(|s| s.name == "from-server")
    );

    // --- Persistent server session, with the fingerprint confirmed from the phone ---
    let session = block_on(core.open_server_session(
        host.id.clone(),
        100,
        30,
        Some("test".into()),
        None,
        None,
    ))
    .unwrap();
    assert_eq!(session.access, SessionAccess::Owner);
    assert_eq!(session.title, "test");
    assert_eq!(session.host_id.as_deref(), Some(host.id.as_str()));
    let events = Arc::new(TermEvents::default());
    let term = block_on(core.attach_server_session(session.id.clone(), events.clone())).unwrap();
    assert_eq!(term.session_id(), session.id);
    match events.wait("hello", |e| matches!(e, ServerTerminalEvent::Hello { .. })) {
        ServerTerminalEvent::Hello { session: s } => assert_eq!(s.id, session.id),
        _ => unreachable!(),
    }
    let prompt = match events.wait("prompt", |e| {
        matches!(e, ServerTerminalEvent::Prompt { .. })
    }) {
        ServerTerminalEvent::Prompt { prompt } => prompt,
        _ => unreachable!(),
    };
    assert_eq!(prompt.kind, "hostkey");
    assert!(prompt.fingerprint.unwrap().starts_with("SHA256:"));
    term.answer_prompt(prompt.prompt_id, Some(true), None)
        .unwrap();
    events.wait("running", |e| {
        matches!(
            e,
            ServerTerminalEvent::Status {
                state: ServerSessionState::Running
            }
        )
    });
    term.write_text("echo remote-$((1+1))\n".into());
    events.wait_output("remote-2");
    term.resize(120, 40);

    let list = block_on(core.list_server_sessions()).unwrap();
    assert_eq!(list.active.len(), 1);
    assert_eq!(list.active[0].state, ServerSessionState::Running);
    assert!(!list.active[0].viewers.is_empty());
    let one = block_on(core.get_server_session(session.id.clone())).unwrap();
    assert_eq!(one.title, "test");

    // Guest without an account using a read-only link.
    let share = parse(
        block_on(core.api_post(
            format!("/api/v1/sessions/{}/shares", session.id),
            Some(json!({"link": true, "permission": "view"}).to_string()),
        ))
        .unwrap(),
    );
    let token = share["token"].as_str().unwrap().to_string();
    let invite = block_on(link_invite_info(base.clone(), token.clone())).unwrap();
    assert_eq!(invite.owner, "Ana");
    assert_eq!(invite.access, SessionAccess::View);
    assert!(invite.require_approval);
    let guest_events = Arc::new(TermEvents::default());
    let guest = block_on(join_shared_session_as(
        base.clone(),
        token,
        Some("Phone guest".into()),
        guest_events.clone(),
    ))
    .unwrap();
    assert_eq!(guest.session_id(), session.id);
    // Links wait until the owner lets them in.
    guest_events.wait("waiting room", |e| {
        matches!(e, ServerTerminalEvent::Waiting { .. })
    });
    assert!(guest.is_waiting() && !guest.can_write());
    let participant = match events.wait("join request", |e| {
        matches!(e, ServerTerminalEvent::JoinRequest { .. })
    }) {
        ServerTerminalEvent::JoinRequest { participant } => participant,
        _ => unreachable!(),
    };
    assert_eq!(participant.name, "Phone guest");
    assert_eq!(participant.kind, ParticipantKind::Guest);
    assert!(term.is_owner() && term.can_write() && term.is_driver());
    term.allow_join(participant.id.clone()).unwrap();
    match guest_events.wait("guest hello", |e| {
        matches!(e, ServerTerminalEvent::Hello { .. })
    }) {
        ServerTerminalEvent::Hello { session: s } => {
            assert_eq!(s.access, SessionAccess::View);
            assert!(
                s.participants
                    .iter()
                    .any(|p| p.you && p.name == "Phone guest")
            );
            assert!(s.participants.iter().all(|p| p.user_id.is_none()));
        }
        _ => unreachable!(),
    }
    assert_eq!(guest.participant_id(), Some(participant.id.clone()));
    guest.write_text("echo MUST-NOT-APPEAR\n".into());
    term.write_text("echo seen-by-guest\n".into());
    guest_events.wait_output("seen-by-guest");
    assert!(!guest_events.output().contains("MUST-NOT-APPEAR"));

    // The owner's shares, changed live: the guest may now take the keyboard.
    let shares = block_on(core.list_server_session_shares(session.id.clone())).unwrap();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].kind, ShareKind::Link);
    assert!(shares[0].require_approval && shares[0].active && !shares[0].control);
    assert_eq!(shares[0].participants, 1);
    let changed = block_on(core.update_server_session_share(
        session.id.clone(),
        shares[0].id.clone(),
        ShareChanges {
            control: Some(true),
            expires_in_minutes: Some(60),
            no_expiry: false,
            require_approval: None,
            auto_grant: Some(true),
            // Each automatic grant lasts 30 minutes at most.
            control_minutes: Some(30),
            no_control_limit: false,
        },
    ))
    .unwrap();
    assert!(changed.control && changed.auto_grant && changed.expires_at.is_some());
    assert_eq!(changed.control_minutes, Some(30));
    guest.request_control();
    let until = match guest_events.wait("keyboard", |e| {
        matches!(
            e,
            ServerTerminalEvent::Control {
                can_write: true,
                ..
            }
        )
    }) {
        ServerTerminalEvent::Control { until, .. } => until.expect("a timed grant"),
        _ => unreachable!(),
    };
    let left = until - termoak_core::time::now_ms();
    assert!(left > 29 * 60_000 && left <= 30 * 60_000, "{left}");
    assert_eq!(guest.control_until(), Some(until));
    assert!(guest.can_write() && guest.is_driver());
    guest.write_text("echo typed-by-$((40+2))\n".into());
    events.wait_output("typed-by-42");
    term.take_control();
    guest_events.wait("keyboard back", |e| {
        matches!(
            e,
            ServerTerminalEvent::Control {
                can_write: false,
                ..
            }
        )
    });
    // Stop sharing: the guest is sent away with a code.
    assert_eq!(
        block_on(core.stop_sharing_server_session(session.id.clone())).unwrap(),
        1
    );
    match guest_events.wait("ended", |e| matches!(e, ServerTerminalEvent::Ended { .. })) {
        ServerTerminalEvent::Ended { code, .. } => assert_eq!(code, "revoked"),
        _ => unreachable!(),
    }
    guest_events.wait("closed", |e| matches!(e, ServerTerminalEvent::Closed));
    guest.detach();

    // --- Account events ---
    let user_events = Arc::new(UserEvents::default());
    let sub = block_on(core.subscribe_events(user_events.clone())).unwrap();
    wait_until(
        &user_events.events,
        &user_events.cv,
        "events hello",
        |evs| evs.iter().any(|e| e["type"] == "hello"),
    );

    // --- AI: read-only task ---
    let task = block_on(core.create_ai_task(AiTaskRequest {
        prompt: "What does the local host say?".into(),
        title: None,
        mode: None,
        provider: Some("mock".into()),
        host_ids: vec![],
        session_id: None,
        effort: None,
    }))
    .unwrap();
    let done = wait_task(&core, &task.id, |t| {
        matches!(t.status, AiTaskStatus::Completed | AiTaskStatus::Failed)
    });
    assert_eq!(done.status, AiTaskStatus::Completed, "{done:?}");
    assert!(done.result.as_deref().unwrap_or("").contains("termoak-42"));
    assert_eq!(done.cost_micros, 1000);
    assert!(parse(done.raw_json.clone())["messages"].is_array());

    // --- AI: task that makes changes → approval from the phone ---
    let task = block_on(core.create_ai_task(AiTaskRequest {
        prompt: "CREATE a file on local".into(),
        title: Some("create".into()),
        mode: Some(AiPermissionMode::Ask),
        provider: Some("mock".into()),
        host_ids: vec![host.id.clone()],
        session_id: None,
        effort: None,
    }))
    .unwrap();
    assert_eq!(task.mode, AiPermissionMode::Ask);
    let waiting = wait_task(&core, &task.id, |t| {
        t.status == AiTaskStatus::WaitingApproval
    });
    assert_eq!(waiting.pending_approvals.len(), 1);
    let pending = block_on(core.list_pending_approvals()).unwrap();
    assert_eq!(pending.len(), 1);
    assert!(pending[0].summary.contains("touch"), "{pending:?}");
    assert_eq!(parse(pending[0].input_json.clone())["host"], "local");
    wait_until(
        &user_events.events,
        &user_events.cv,
        "approval notice",
        |evs| {
            evs.iter()
                .any(|e| e["type"] == "ai" && e["event"]["type"] == "approval_requested")
        },
    );
    block_on(core.decide_approval(task.id.clone(), pending[0].id.clone(), true, false)).unwrap();
    let done = wait_task(&core, &task.id, |t| {
        matches!(t.status, AiTaskStatus::Completed | AiTaskStatus::Failed)
    });
    assert!(
        done.result.as_deref().unwrap_or("").contains("created"),
        "{done:?}"
    );
    assert!(std::path::Path::new(&marker).exists());
    let _ = std::fs::remove_file(&marker);
    let tasks = block_on(core.list_ai_tasks(10)).unwrap();
    assert_eq!(tasks.len(), 2);

    // --- Sharing a local terminal (relay) ---
    let local_listener = Arc::new(LocalTerm::default());
    let local = block_on(core.connect_terminal(
        host.id.clone(),
        80,
        24,
        Arc::new(TrustAll),
        local_listener.clone(),
        None,
    ))
    .unwrap();
    let shared = block_on(core.share_terminal(local.clone(), "from the phone".into())).unwrap();
    let host_events = Arc::new(SharedEvents::default());
    block_on(shared.set_listener(host_events.clone())).unwrap();
    let invite = block_on(shared.invite_link(false, Some(30))).unwrap();
    assert_eq!(invite.permission, "view");
    assert!(invite.app_link.unwrap().starts_with("termoak://join?"));
    let relay_events = Arc::new(TermEvents::default());
    let relay_guest = block_on(join_shared_session(
        base.clone(),
        invite.token.unwrap(),
        relay_events.clone(),
    ))
    .unwrap();
    assert_eq!(relay_guest.session_id(), shared.session_id());
    // The phone that shares is asked to let the guest in.
    let id = host_events.wait("join request", |e| match e {
        SharedTerminalEvent::JoinRequest { participant } => Some(participant.id.clone()),
        _ => None,
    });
    block_on(shared.allow_join(id)).unwrap();
    relay_events.wait("hello relay", |e| {
        matches!(e, ServerTerminalEvent::Hello { .. })
    });
    local.write_text("echo shared-$((3*3))\n".into()).unwrap();
    relay_events.wait_output("shared-9");
    block_on(shared.resize(100, 30)).unwrap();
    block_on(shared.revoke_invite(invite.share_id)).unwrap();
    relay_events.wait(
        "kicked out",
        |e| matches!(e, ServerTerminalEvent::Ended { code, .. } if code == "revoked"),
    );
    assert!(
        block_on(shared.list_invites())
            .unwrap()
            .iter()
            .all(|i| i.revoked)
    );
    block_on(shared.stop()).unwrap();
    local.close_terminal();

    // --- Files through the server (SFTP of the synced host) ---
    let files = tempfile::tempdir().unwrap();
    let local_file = files.path().join("upload.txt");
    std::fs::write(&local_file, b"content-through-the-server").unwrap();
    let home = block_on(core.server_sftp_home(host.id.clone(), None)).unwrap();
    let remote = format!("{home}/termoak-ffi-{}.txt", std::process::id());
    let progress = Arc::new(Progress::default());
    let sent = block_on(core.server_sftp_upload(
        host.id.clone(),
        local_file.to_string_lossy().into_owned(),
        remote.clone(),
        Some(progress.clone()),
        None,
    ))
    .unwrap();
    assert_eq!(sent, 26);
    assert_eq!(*progress.0.lock(), 26);
    let listed = block_on(core.server_sftp_list(host.id.clone(), home.clone(), None)).unwrap();
    assert!(listed.iter().any(|f| f.path == remote), "{listed:?}");
    let back = files.path().join("download.txt");
    *progress.0.lock() = 0;
    let got = block_on(core.server_sftp_download(
        host.id.clone(),
        remote.clone(),
        back.to_string_lossy().into_owned(),
        Some(progress.clone()),
        None,
    ))
    .unwrap();
    assert_eq!(got, 26);
    assert_eq!(*progress.0.lock(), 26);
    assert_eq!(std::fs::read(&back).unwrap(), b"content-through-the-server");
    assert!(!files.path().join("download.txt.part").exists());
    block_on(core.server_sftp_delete(host.id.clone(), remote.clone(), false, None)).unwrap();
    // A file that does not exist: an error and no half-written file.
    let missing = files.path().join("no.txt");
    assert!(
        block_on(core.server_sftp_download(
            host.id.clone(),
            remote,
            missing.to_string_lossy().into_owned(),
            None,
            None,
        ))
        .is_err()
    );
    assert!(!missing.exists() && !files.path().join("no.txt.part").exists());
    // The session is not recorded: there is no recording to download.
    assert!(matches!(
        block_on(core.download_recording(
            session.id.clone(),
            files.path().join("s.cast").to_string_lossy().into_owned(),
            None,
        )),
        Err(TermoakError::NotFound(_))
    ));

    // A recorded session: its recording is downloaded to disk.
    let recorded = block_on(core.open_server_session(
        host.id.clone(),
        80,
        24,
        Some("recorded".into()),
        Some(true),
        None,
    ))
    .unwrap();
    for _ in 0..100 {
        let s = block_on(core.get_server_session(recorded.id.clone())).unwrap();
        if matches!(s.state, ServerSessionState::Running) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    block_on(core.close_server_session(recorded.id.clone())).unwrap();
    let cast = files.path().join("recorded.cast");
    let bytes = block_on(core.download_recording(
        recorded.id.clone(),
        cast.to_string_lossy().into_owned(),
        None,
    ))
    .unwrap();
    assert!(bytes > 0);
    let text = std::fs::read_to_string(&cast).unwrap();
    assert!(
        text.lines().next().unwrap().contains("\"version\""),
        "{text}"
    );

    // --- Closing the server session ---
    block_on(core.close_server_session(session.id.clone())).unwrap();
    events.wait("close", |e| {
        matches!(
            e,
            ServerTerminalEvent::Status {
                state: ServerSessionState::Closed { .. }
            } | ServerTerminalEvent::Closed
        )
    });
    // The server keeps closed sessions for a while so their end can be seen.
    let list = block_on(core.list_server_sessions()).unwrap();
    assert!(
        list.active
            .iter()
            .all(|s| matches!(s.state, ServerSessionState::Closed { .. })),
        "{:#?}",
        list.active
    );

    sub.unsubscribe();
    wait_until(&user_events.closed, &user_events.cv, "events close", |c| *c);

    // --- Log out ---
    block_on(core.logout()).unwrap();
    assert!(!block_on(core.is_logged_in()).unwrap());
    assert!(matches!(
        block_on(core.sync_now()),
        Err(TermoakError::NotLoggedIn(_))
    ));
}
