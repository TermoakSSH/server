//! FIDO2 security keys on server-side connections (docs/SSH-PRO.md §5):
//! the server asks the owner's devices to sign over the events WebSocket.
//! The "devices" are the software authenticator behind a raw socket and
//! behind the FFI (the mobile apps' engine). Also snippets with variables
//! through the API. Skipped without `sshd`.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::srv::{Srv, User};
use common::{start_sshd_with, ws_connect, ws_wait_json, ws_wait_output};
use futures::{SinkExt, StreamExt};
use parking_lot::Mutex;
use serde_json::{Value, json};
use termoak_ssh::keys::KeyMaterial;
use termoak_ssh::sk::soft::{Behavior, SoftAuthenticator};
use termoak_ssh::sk::{SecurityKeySigner, SkAlgorithm, SkKeyOptions, wire};
use tokio_tungstenite::tungstenite::Message as WsMsg;

fn sk_key(auth: &SoftAuthenticator, alg: SkAlgorithm) -> KeyMaterial {
    let req = termoak_ssh::sk::make_credential_request(&SkKeyOptions {
        algorithm: alg,
        application: None,
        user: None,
        resident: false,
        verify_required: false,
        no_touch_required: false,
        device: Some("YubiKey 5".into()),
    })
    .unwrap();
    termoak_ssh::sk::key_from_credential(&req, &auth.make_credential(&req).unwrap(), "sk").unwrap()
}

/// A device of `u` that answers with `auth`; what it got is recorded.
struct Device {
    seen: Arc<Mutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Device {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn device(srv: &Srv, u: &User, auth: Option<Arc<SoftAuthenticator>>) -> Device {
    let mut ws = ws_connect(
        &srv.base,
        "/api/v1/events/ws?features=security_keys,other",
        Some(&u.token),
    )
    .await;
    let hello = ws_wait_json(&mut ws, "hello").await;
    assert_eq!(hello["features"], json!(["security_keys"]));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let rec = seen.clone();
    let task = tokio::spawn(async move {
        while let Some(Ok(msg)) = ws.next().await {
            let WsMsg::Text(t) = msg else { continue };
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["type"] == wire::REQUEST || v["type"] == wire::DONE {
                rec.lock().push(v.clone());
            }
            if v["type"] != wire::REQUEST {
                continue;
            }
            let Some(auth) = &auth else { continue }; // a silent device
            let (id, req) = wire::parse_request(&v).unwrap();
            let result = auth.sign(req).await;
            let reply = wire::response(&id, &result);
            if ws
                .send(WsMsg::Text(reply.to_string().into()))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    // The registration happens right after the hello.
    tokio::time::sleep(Duration::from_millis(100)).await;
    Device { seen, task }
}

async fn session_state(srv: &Srv, u: &User, sid: &str) -> Value {
    srv.get(&format!("/api/v1/sessions/{sid}"), u).await.body["state"].clone()
}

/// The reason of a session that closed (it stays listed for a while).
async fn wait_closed(srv: &Srv, u: &User, sid: &str) -> String {
    for _ in 0..200 {
        let s = session_state(srv, u, sid).await;
        if s["state"] == "closed" {
            return s["reason"].as_str().unwrap_or_default().to_string();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "the session did not close: {}",
        session_state(srv, u, sid).await
    );
}

async fn open_session(srv: &Srv, u: &User, host: &str) -> String {
    let s = srv
        .ok(
            "/api/v1/sessions",
            u,
            json!({"host_id": host, "cols": 100, "rows": 30}),
        )
        .await;
    s["id"].as_str().unwrap().to_string()
}

async fn test_code(srv: &Srv, u: &User, host: &str) -> (bool, String) {
    let r = srv
        .post(
            &format!("/api/v1/hosts/{host}/test?trust=true"),
            u,
            json!({}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    (
        r.body["ok"].as_bool().unwrap(),
        r.body["error_code"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_sessions_are_signed_by_the_owners_devices() {
    let auth = Arc::new(SoftAuthenticator::new());
    let key = sk_key(&auth, SkAlgorithm::EcdsaP256);
    let Some(sshd) = start_sshd_with(std::slice::from_ref(&key.public_openssh)) else {
        eprintln!("sshd not available: test skipped");
        return;
    };
    let srv = Srv::start_with(|c| c.sessions.security_key_timeout_secs = 3).await;
    let ana = srv.user("Ana").await;
    let bob = srv.user("Bob").await;

    // The sk "private key" file is imported like any key.
    let k = srv
        .ok(
            "/api/v1/keys/import",
            &ana,
            json!({"label": "Yubi", "private_key": key.private_openssh}),
        )
        .await;
    assert_eq!(k["algorithm"], "sk-ecdsa-sha2-nistp256@openssh.com");
    assert_eq!(k["security_key"]["application"], "ssh:");
    assert_eq!(k["security_key"]["touch_required"], true);
    let h = srv
        .ok(
            "/api/v1/hosts",
            &ana,
            json!({"label": "local", "address": "127.0.0.1",
                   "settings": {"port": sshd.port, "username": sshd.user, "key_id": k["id"]}}),
        )
        .await;
    let host = h["id"].as_str().unwrap().to_string();

    // No device online: at once, with a clear error.
    assert_eq!(
        test_code(&srv, &ana, &host).await,
        (false, "security_key_no_device".into())
    );
    let sid = open_session(&srv, &ana, &host).await;
    let reason = wait_closed(&srv, &ana, &sid).await;
    assert!(reason.contains("none of your devices"), "{reason}");

    // Bob's device is online too: it never hears about Ana's requests.
    let bob_dev = device(&srv, &bob, Some(Arc::new(SoftAuthenticator::new()))).await;
    let ana_dev = device(&srv, &ana, Some(auth.clone())).await;
    assert_eq!(test_code(&srv, &ana, &host).await, (true, String::new()));
    let sid = open_session(&srv, &ana, &host).await;
    let mut ws = ws_connect(
        &srv.base,
        &format!("/api/v1/sessions/{sid}/ws"),
        Some(&ana.token),
    )
    .await;
    ws_wait_json(&mut ws, "hello").await;
    ws.send(WsMsg::Binary(
        "echo sk-$((40+2))\n".as_bytes().to_vec().into(),
    ))
    .await
    .unwrap();
    ws_wait_output(&mut ws, "sk-42").await;
    assert!(bob_dev.seen.lock().is_empty());
    {
        let seen = ana_dev.seen.lock();
        let req = seen
            .iter()
            .find(|v| v["type"] == wire::REQUEST && v["purpose"] == "server_session")
            .expect("a request for the session");
        assert_eq!(req["session_id"], sid);
        assert_eq!(req["host"], "local");
        assert_eq!(req["key"]["label"], "Yubi");
        assert_eq!(req["key"]["fingerprint"], key.fingerprint);
        assert_eq!(req["require_presence"], true);
        let id = &req["request_id"];
        assert!(
            seen.iter().any(|v| v["type"] == wire::DONE
                && v["request_id"] == *id
                && v["result"] == "signed")
        );
    }
    // Audited in the vault.
    let audit = srv.get("/api/v1/audit", &ana).await.body;
    let signs: Vec<&Value> = audit
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "security_key.sign")
        .collect();
    assert!(signs.iter().any(|e| e["detail"]["result"] == "signed"
        && e["detail"]["purpose"] == "server_session"
        && e["detail"]["session"] == sid
        && e["detail"]["device"].is_string()));
    assert!(
        signs
            .iter()
            .any(|e| e["detail"]["code"] == "security_key_no_device")
    );

    // While it waits for the touch, the session says so.
    auth.set_delay(Duration::from_millis(1500));
    let sid2 = open_session(&srv, &ana, &host).await;
    let mut said = false;
    for _ in 0..40 {
        let s = session_state(&srv, &ana, &sid2).await;
        if s["message"]
            .as_str()
            .is_some_and(|m| m.contains("Touch your security key (Yubi)"))
        {
            said = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(said, "no touch message");
    auth.set_delay(Duration::ZERO);

    // Errors from the device keep their code.
    auth.set_behavior(Behavior::Fail(termoak_ssh::sk::SkErrorCode::Cancelled));
    assert_eq!(
        test_code(&srv, &ana, &host).await,
        (false, "security_key_cancelled".into())
    );
    auth.set_behavior(Behavior::WrongKey);
    assert_eq!(
        test_code(&srv, &ana, &host).await,
        (false, "security_key_wrong_key".into())
    );
    auth.set_behavior(Behavior::Sign);
    drop(ana_dev);
    // A device that never answers: the timeout (3 s here).
    let _silent = device(&srv, &ana, None).await;
    assert_eq!(
        test_code(&srv, &ana, &host).await,
        (false, "security_key_timeout".into())
    );
    drop(bob_dev);
}

/// The FFI engine as "the phone": its events subscription answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_ffi_answers_as_the_users_phone() {
    use termoak_ffi::*;

    struct Handler(Arc<SoftAuthenticator>);
    impl SecurityKeyHandler for Handler {
        fn sign(
            &self,
            r: SecurityKeySignRequest,
        ) -> Result<SecurityKeyAssertion, SecurityKeyError> {
            assert_eq!(r.purpose, "test");
            let req = termoak_ssh::sk::SkSignRequest {
                algorithm: r.algorithm.into(),
                application: r.application,
                key_handle: r.key_handle,
                public_key: r.public_key,
                fingerprint: r.fingerprint,
                client_data_hash: r.client_data_hash.try_into().unwrap(),
                message: r.message,
                require_presence: r.require_presence,
                require_verification: r.require_verification,
                context: Default::default(),
            };
            let a = self
                .0
                .sign_now(&req)
                .map_err(|e| SecurityKeyError::Failed { message: e.message })?;
            Ok(SecurityKeyAssertion {
                flags: a.flags,
                counter: a.counter,
                signature: a.signature,
                authenticator_data: None,
            })
        }
        fn make_credential(
            &self,
            r: SecurityKeyCredentialRequest,
        ) -> Result<SecurityKeyCredential, SecurityKeyError> {
            let req: termoak_ssh::sk::SkMakeCredentialRequest = r.try_into().unwrap();
            let c = self.0.make_credential(&req).unwrap();
            Ok(SecurityKeyCredential {
                authenticator_data: c.authenticator_data,
                attestation_object: vec![],
            })
        }
        fn list_resident(
            &self,
            _: SecurityKeyResidentRequest,
        ) -> Result<Vec<SecurityKeyResident>, SecurityKeyError> {
            Err(SecurityKeyError::Unsupported {
                message: String::new(),
            })
        }
    }
    struct Events;
    impl ServerEventListener for Events {
        fn on_event(&self, _: String) {}
        fn on_closed(&self, _: Option<String>) {}
    }

    let srv = Srv::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let core = TermoakCore::new(
        tmp.path().join("phone").to_string_lossy().into_owned(),
        generate_vault_key(),
    )
    .unwrap();
    let base = srv.base.clone();
    let c = core.clone();
    tokio::task::spawn_blocking(move || {
        futures::executor::block_on(c.register(
            base,
            "carla@termoak.test".into(),
            "Carla".into(),
            "secure-password".into(),
            None,
        ))
    })
    .await
    .unwrap()
    .unwrap();
    let auth = Arc::new(SoftAuthenticator::new());
    let handler = Arc::new(Handler(auth.clone()));
    // The key is created on "the phone" through the FFI and synced.
    let c = core.clone();
    let h2 = handler.clone();
    let key = tokio::task::spawn_blocking(move || {
        let key = futures::executor::block_on(c.create_security_key(
            "Phone key".into(),
            SecurityKeyOptions {
                algorithm: SecurityKeyAlgorithm::Ed25519,
                application: None,
                user: None,
                resident: false,
                verify_required: false,
                no_touch_required: false,
                device: Some("NFC key".into()),
            },
            "carla".into(),
            None,
            None,
            None,
            h2,
        ))
        .unwrap();
        futures::executor::block_on(c.sync_now()).unwrap();
        key
    })
    .await
    .unwrap();
    let Some(sshd) = start_sshd_with(std::slice::from_ref(&key.public_key)) else {
        eprintln!("sshd not available: test skipped");
        return;
    };
    let c = core.clone();
    let body = json!({"label": "local", "address": "127.0.0.1",
        "settings": {"port": sshd.port, "username": sshd.user, "key_id": key.id}})
    .to_string();
    let host: Value = serde_json::from_str(
        &tokio::task::spawn_blocking(move || {
            futures::executor::block_on(c.api_post("/api/v1/hosts".into(), Some(body)))
        })
        .await
        .unwrap()
        .unwrap(),
    )
    .unwrap();
    let hid = host["id"].as_str().unwrap().to_string();
    let test = |core: Arc<TermoakCore>, hid: String| async move {
        let v = tokio::task::spawn_blocking(move || {
            futures::executor::block_on(
                core.api_post(format!("/api/v1/hosts/{hid}/test?trust=true"), None),
            )
        })
        .await
        .unwrap()
        .unwrap();
        serde_json::from_str::<Value>(&v).unwrap()
    };
    // Subscribed without a handler: the server has nobody to ask.
    let sub = {
        let c = core.clone();
        tokio::task::spawn_blocking(move || {
            futures::executor::block_on(c.subscribe_events(Arc::new(Events)))
        })
        .await
        .unwrap()
        .unwrap()
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        test(core.clone(), hid.clone()).await["error_code"],
        "security_key_no_device"
    );
    sub.unsubscribe();
    drop(sub);
    // With the handler set, a new subscription signs.
    core.set_security_key_handler(Some(handler.clone()));
    let sub = {
        let c = core.clone();
        tokio::task::spawn_blocking(move || {
            futures::executor::block_on(c.subscribe_events(Arc::new(Events)))
        })
        .await
        .unwrap()
        .unwrap()
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    let r = test(core.clone(), hid.clone()).await;
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(auth.seen.lock().len(), 1);
    sub.unsubscribe();
}

/// The session holder asks the server, which asks the device.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn held_sessions_forward_too() {
    let auth = Arc::new(SoftAuthenticator::new());
    let key = sk_key(&auth, SkAlgorithm::Ed25519);
    let Some(sshd) = start_sshd_with(std::slice::from_ref(&key.public_openssh)) else {
        eprintln!("sshd not available: test skipped");
        return;
    };
    let data = tempfile::tempdir().unwrap();
    let socket = data.path().join("holder").join("sessions.sock");
    let stop = tokio_util::sync::CancellationToken::new();
    tokio::spawn({
        let socket = socket.clone();
        let stop = stop.clone();
        async move { termoak_server::holder::daemon::run(&socket, stop).await }
    });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let srv = Srv::start_with(|c| c.sessions.holder_socket = Some(socket.clone())).await;
    termoak_server::start_sessions(&srv.state).await.unwrap();
    let ana = srv.user("Ana").await;
    let k = srv
        .ok(
            "/api/v1/keys/import",
            &ana,
            json!({"label": "Yubi", "private_key": key.private_openssh}),
        )
        .await;
    let h = srv
        .ok(
            "/api/v1/hosts",
            &ana,
            json!({"label": "held", "address": "127.0.0.1",
                   "settings": {"port": sshd.port, "username": sshd.user, "key_id": k["id"]}}),
        )
        .await;
    let host = h["id"].as_str().unwrap().to_string();
    // Held by the holder (it announces security keys).
    assert!(
        srv.state
            .sessions
            .holder()
            .is_some_and(|h| h.knows_security_keys())
    );
    let dev = device(&srv, &ana, Some(auth.clone())).await;
    let sid = open_session(&srv, &ana, &host).await;
    let mut ws = ws_connect(
        &srv.base,
        &format!("/api/v1/sessions/{sid}/ws"),
        Some(&ana.token),
    )
    .await;
    ws_wait_json(&mut ws, "hello").await;
    ws.send(WsMsg::Binary(
        "echo held-$((6*7))\n".as_bytes().to_vec().into(),
    ))
    .await
    .unwrap();
    ws_wait_output(&mut ws, "held-42").await;
    let req = dev
        .seen
        .lock()
        .iter()
        .find(|v| v["type"] == wire::REQUEST)
        .cloned()
        .unwrap();
    assert_eq!(req["session_id"], sid);
    assert_eq!(req["purpose"], "server_session");
    stop.cancel();
}

/// Snippets: the API refuses malformed templates and `/exec` renders per host.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snippets_with_variables() {
    let srv = Srv::start().await;
    let ana = srv.user("Ana").await;
    let r = srv
        .post(
            "/api/v1/snippets",
            &ana,
            json!({"name": "bad", "script": "deploy {{select:Env}}"}),
        )
        .await;
    assert_eq!(r.status, 400, "{}", r.body);
    assert_eq!(r.code(), "invalid_snippet");
    assert_eq!(r.body["error"]["issues"][0]["tag"], "{{select:Env}}");
    // Text that is not a tag is fine (old snippets keep working).
    let ok = srv
        .ok(
            "/api/v1/snippets",
            &ana,
            json!({"name": "go", "script": "docker inspect -f '{{.State}}' x"}),
        )
        .await;
    let r = srv
        .put(
            &format!("/api/v1/snippets/{}", ok["id"].as_str().unwrap()),
            &ana,
            json!({"name": "go", "script": "{{secret:T|x}}"}),
        )
        .await;
    assert_eq!(r.code(), "invalid_snippet");

    let Some(sshd) = start_sshd_with(&[]) else {
        eprintln!("sshd not available: exec part skipped");
        return;
    };
    let k = srv
        .ok(
            "/api/v1/keys/import",
            &ana,
            json!({"label": "k", "private_key": sshd.private_key}),
        )
        .await;
    let mut hosts = Vec::new();
    for label in ["alpha", "beta"] {
        let h = srv
            .ok(
                "/api/v1/hosts",
                &ana,
                json!({"label": label, "address": "127.0.0.1",
                       "settings": {"port": sshd.port, "username": sshd.user, "key_id": k["id"]}}),
            )
            .await;
        let id = h["id"].as_str().unwrap().to_string();
        assert!(test_code(&srv, &ana, &id).await.0);
        hosts.push(id);
    }
    let s = srv
        .ok(
            "/api/v1/snippets",
            &ana,
            json!({"name": "hello", "script": "echo {{label}}:{{port}}:{{prompt:Msg}}:{{select:Env|prod|dev}}:{{secret:Token}}"}),
        )
        .await;
    // Missing prompt values: refused before running anything.
    let r = srv
        .post(
            "/api/v1/exec",
            &ana,
            json!({"host_ids": hosts, "snippet_id": s["id"], "variables": {"Msg": "hi"}}),
        )
        .await;
    assert_eq!(r.status, 400, "{}", r.body);
    let out = srv
        .ok(
            "/api/v1/exec",
            &ana,
            json!({"host_ids": hosts, "snippet_id": s["id"], "variables": {"Msg": "hi", "Token": "s3cr3t"}}),
        )
        .await;
    let lines: Vec<String> = out
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["stdout"].as_str().unwrap().trim().to_string())
        .collect();
    assert_eq!(
        lines,
        [
            format!("alpha:{}:hi:prod:s3cr3t", sshd.port),
            format!("beta:{}:hi:prod:s3cr3t", sshd.port)
        ]
    );
    // The audit keeps the template, never the secret.
    let audit = srv.get("/api/v1/audit", &ana).await.body.to_string();
    assert!(audit.contains("exec.batch"));
    assert!(!audit.contains("s3cr3t"));
}
