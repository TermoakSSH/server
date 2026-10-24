//! FIDO2 security keys for connections made by the server (docs/SSH-PRO.md
//! §5): there is no physical key here, so the server asks the owner's
//! devices to sign over the events WebSocket (`security_key_request` →
//! `security_key_response`), and uses the answer only if it verifies over
//! the exact data it asked for.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::{Value, json};
use termoak_core::time::now_ms;
use termoak_core::{Id, Store, new_id};
use termoak_ssh::sk::{SecurityKeySigner, SkAssertion, SkError, SkErrorCode, SkSignRequest, wire};
use tokio::sync::{mpsc, oneshot};

/// Default wait for a device (`[sessions] security_key_timeout_secs`).
pub const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// A device's events socket that can sign.
struct SignerSocket {
    id: u64,
    device: Id,
    tx: mpsc::UnboundedSender<Value>,
}

type Outcome = Result<(SkAssertion, Id), SkError>;

struct Pending {
    owner: Id,
    /// Sockets asked (and the ones that answered with an error).
    targets: HashSet<u64>,
    failed: HashSet<u64>,
    errors: Vec<SkError>,
    done: Option<oneshot::Sender<Outcome>>,
}

/// The signature requests in flight and the sockets that can answer them.
pub struct SkBroker {
    store: Store,
    timeout: Duration,
    next: AtomicU64,
    signers: Mutex<HashMap<Id, Vec<SignerSocket>>>,
    pending: Mutex<HashMap<String, Pending>>,
}

/// Unregisters a signer socket when dropped.
pub struct SignerGuard {
    broker: Arc<SkBroker>,
    user: Id,
    id: u64,
}

impl SignerGuard {
    /// The socket's id (for [`SkBroker::on_message`]).
    pub fn id(&self) -> u64 {
        self.id
    }
}

impl Drop for SignerGuard {
    fn drop(&mut self) {
        let mut signers = self.broker.signers.lock();
        if let Some(list) = signers.get_mut(&self.user) {
            list.retain(|s| s.id != self.id);
            if list.is_empty() {
                signers.remove(&self.user);
            }
        }
        drop(signers);
        // Requests waiting for this socket: it will never answer.
        let ids: Vec<String> = self
            .broker
            .pending
            .lock()
            .iter()
            .filter(|(_, p)| p.owner == self.user && p.targets.contains(&self.id))
            .map(|(k, _)| k.clone())
            .collect();
        for id in ids {
            self.broker.fail(
                &id,
                self.id,
                SkError::new(SkErrorCode::NoDevice, "the device disconnected"),
            );
        }
    }
}

impl SkBroker {
    pub fn new(store: Store, timeout: Duration) -> Arc<Self> {
        Arc::new(Self {
            store,
            timeout: timeout.clamp(Duration::from_secs(1), Duration::from_secs(300)),
            next: AtomicU64::new(1),
            signers: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
        })
    }

    /// Registers an events socket of `user` that declared `security_keys`;
    /// the messages for it come out of the receiver.
    pub fn register(
        self: &Arc<Self>,
        user: Id,
        device: Id,
    ) -> (SignerGuard, mpsc::UnboundedReceiver<Value>) {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel();
        self.signers
            .lock()
            .entry(user)
            .or_default()
            .push(SignerSocket { id, device, tx });
        (
            SignerGuard {
                broker: self.clone(),
                user,
                id,
            },
            rx,
        )
    }

    /// How many sockets of `user` can sign now.
    pub fn signers_of(&self, user: Id) -> usize {
        self.signers.lock().get(&user).map_or(0, Vec::len)
    }

    /// A message from an events socket (`socket` of `user`): a
    /// `security_key_response` for one of that user's pending requests.
    /// Anything else is ignored.
    pub fn on_message(&self, user: Id, socket: u64, v: &Value) {
        let Some((id, result)) = wire::parse_response(v) else {
            return;
        };
        let device = {
            let signers = self.signers.lock();
            match signers
                .get(&user)
                .and_then(|l| l.iter().find(|s| s.id == socket))
            {
                Some(s) => s.device,
                None => return,
            }
        };
        match result {
            Ok(a) => {
                let mut pending = self.pending.lock();
                let Some(p) = pending.get_mut(&id) else {
                    return;
                };
                if p.owner != user || !p.targets.contains(&socket) {
                    return;
                }
                if let Some(done) = p.done.take() {
                    let _ = done.send(Ok((a, device)));
                }
            }
            Err(e) => self.fail(&id, socket, e),
        }
    }

    /// A device of the request answered with an error: final when it is a
    /// cancellation or when every device asked failed.
    fn fail(&self, id: &str, socket: u64, e: SkError) {
        let mut pending = self.pending.lock();
        let Some(p) = pending.get_mut(id) else { return };
        if !p.targets.contains(&socket) || !p.failed.insert(socket) {
            return;
        }
        p.errors.push(e.clone());
        if e.code == SkErrorCode::Cancelled || p.failed.len() >= p.targets.len() {
            let best = p
                .errors
                .iter()
                .max_by_key(|e| e.code.rank())
                .cloned()
                .unwrap_or(e);
            if let Some(done) = p.done.take() {
                let _ = done.send(Err(best));
            }
        }
    }

    /// Asks `owner`'s devices to sign `req` and waits for the first good
    /// answer (or the timeout). Returns the assertion and the device id.
    async fn request(&self, owner: Id, req: &SkSignRequest) -> Outcome {
        let id = new_id().to_string();
        let expires_at = now_ms() + self.timeout.as_millis() as i64;
        let msg = wire::request(&id, req, expires_at);
        let (tx, rx) = oneshot::channel();
        let targets: Vec<(u64, mpsc::UnboundedSender<Value>)> = {
            let signers = self.signers.lock();
            signers
                .get(&owner)
                .map(|l| l.iter().map(|s| (s.id, s.tx.clone())).collect())
                .unwrap_or_default()
        };
        if targets.is_empty() {
            return Err(SkError::new(
                SkErrorCode::NoDevice,
                "none of your devices that can use security keys is online: open Termoak on your phone or computer (signed in) and try again",
            ));
        }
        self.pending.lock().insert(
            id.clone(),
            Pending {
                owner,
                targets: targets.iter().map(|(s, _)| *s).collect(),
                failed: HashSet::new(),
                errors: Vec::new(),
                done: Some(tx),
            },
        );
        for (_, t) in &targets {
            let _ = t.send(msg.clone());
        }
        let outcome = match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(o)) => o,
            Ok(Err(_)) => Err(SkError::of(SkErrorCode::Failed)),
            Err(_) => Err(SkError::new(
                SkErrorCode::Timeout,
                format!(
                    "nobody confirmed the security key in {} seconds",
                    self.timeout.as_secs()
                ),
            )),
        };
        self.pending.lock().remove(&id);
        let result = match &outcome {
            Ok(_) => "signed",
            Err(e) if e.code == SkErrorCode::Timeout => "timeout",
            Err(e) if e.code == SkErrorCode::Cancelled => "cancelled",
            Err(_) => "failed",
        };
        let done = wire::done(&id, result);
        for (_, t) in &targets {
            let _ = t.send(done.clone());
        }
        outcome
    }

    /// The signer for connections of `owner` to hosts of `vault`.
    pub fn signer(
        self: &Arc<Self>,
        owner: Id,
        vault: Option<Id>,
        on_wait: Option<WaitHook>,
    ) -> Arc<dyn SecurityKeySigner> {
        Arc::new(ForwardSigner {
            broker: self.clone(),
            owner,
            vault,
            on_wait,
        })
    }
}

/// Called with a message while a device is asked (sessions show it).
pub type WaitHook = Arc<dyn Fn(Option<String>) + Send + Sync>;

/// Forwards signatures to the owner's devices, verifying and auditing them.
struct ForwardSigner {
    broker: Arc<SkBroker>,
    owner: Id,
    vault: Option<Id>,
    on_wait: Option<WaitHook>,
}

#[async_trait]
impl SecurityKeySigner for ForwardSigner {
    async fn sign(&self, req: SkSignRequest) -> Result<SkAssertion, SkError> {
        if let Some(hook) = &self.on_wait {
            let key = req
                .context
                .device
                .clone()
                .unwrap_or_else(|| req.context.key_label.clone());
            hook(Some(format!(
                "Touch your security key ({key}) on one of your devices…"
            )));
        }
        let outcome = self.broker.request(self.owner, &req).await;
        if let Some(hook) = &self.on_wait {
            hook(None);
        }
        // The engine verifies the signature; a wrong one is audited here too.
        let verified = outcome.and_then(|(a, device)| {
            let sk = termoak_ssh::sk::SkKey {
                algorithm: req.algorithm,
                public: termoak_ssh::keys::parse_public(&req.public_key)
                    .map_err(|e| SkError::invalid(e.to_string()))?,
                application: req.application.clone(),
                flags: (if req.require_presence { 0x01 } else { 0 })
                    | (if req.require_verification { 0x04 } else { 0 }),
                key_handle: req.key_handle.clone(),
            };
            sk.signature_blob(&req.message, &a)?;
            Ok((a, device))
        });
        let c = &req.context;
        let mut detail = json!({
            "purpose": c.purpose,
            "session": c.session_id,
            "host": c.host,
            "key": req.fingerprint,
            "result": if verified.is_ok() { "signed" } else { "failed" },
        });
        match &verified {
            Ok((_, device)) => detail["device"] = json!(device),
            Err(e) => detail["code"] = json!(e.code.api_code()),
        }
        let actor = format!("user:{}", self.owner);
        let target = c.key_id.clone();
        let audited = match self.vault {
            Some(v) => {
                self.broker
                    .store
                    .audit_vault(self.owner, &actor, "security_key.sign", target, detail, v)
                    .await
            }
            None => {
                self.broker
                    .store
                    .audit(self.owner, &actor, "security_key.sign", target, detail)
                    .await
            }
        };
        if let Err(e) = audited {
            tracing::warn!(error = %e, "could not audit a security key signature");
        }
        verified.map(|(a, _)| a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(app: &str) -> SkSignRequest {
        SkSignRequest {
            algorithm: termoak_ssh::sk::SkAlgorithm::Ed25519,
            application: app.into(),
            key_handle: vec![1],
            public_key: String::new(),
            fingerprint: "SHA256:x".into(),
            message: b"m".to_vec(),
            client_data_hash: [0; 32],
            require_presence: true,
            require_verification: false,
            context: Default::default(),
        }
    }

    #[tokio::test]
    async fn routing_rules() {
        let store = Store::open_in_memory(termoak_core::crypto::MasterKey::generate()).unwrap();
        let broker = SkBroker::new(store, Duration::from_secs(1));
        let (alice, bob) = (new_id(), new_id());
        // Nobody online.
        let e = broker.request(alice, &request("ssh:")).await.unwrap_err();
        assert_eq!(e.code, SkErrorCode::NoDevice);
        // Two devices of alice, one of bob.
        let (g1, mut r1) = broker.register(alice, new_id());
        let (g2, mut r2) = broker.register(alice, new_id());
        let (gb, mut rb) = broker.register(bob, new_id());
        assert_eq!(broker.signers_of(alice), 2);
        let b2 = broker.clone();
        let task = tokio::spawn(async move { b2.request(alice, &request("ssh:")).await });
        let m1 = r1.recv().await.unwrap();
        let m2 = r2.recv().await.unwrap();
        assert_eq!(m1["type"], "security_key_request");
        assert_eq!(m1["request_id"], m2["request_id"]);
        assert!(rb.try_recv().is_err());
        let id = m1["request_id"].as_str().unwrap().to_string();
        let ok = wire::response(
            &id,
            &Ok(SkAssertion {
                flags: 1,
                counter: 3,
                signature: vec![9; 64],
            }),
        );
        // Bob cannot answer alice's request; one device's error does not end it.
        broker.on_message(bob, gb.id(), &ok);
        broker.on_message(
            alice,
            g1.id(),
            &wire::response(&id, &Err(SkError::of(SkErrorCode::NotFound))),
        );
        broker.on_message(alice, g2.id(), &ok);
        let (a, _) = task.await.unwrap().unwrap();
        assert_eq!(a.counter, 3);
        assert_eq!(r1.recv().await.unwrap()["type"], "security_key_done");
        // Every device fails: the most specific error.
        let b2 = broker.clone();
        let task = tokio::spawn(async move { b2.request(alice, &request("ssh:")).await });
        let id = r1.recv().await.unwrap()["request_id"]
            .as_str()
            .unwrap()
            .to_string();
        r2.recv().await.unwrap();
        broker.on_message(
            alice,
            g1.id(),
            &wire::response(&id, &Err(SkError::of(SkErrorCode::NotFound))),
        );
        broker.on_message(
            alice,
            g2.id(),
            &wire::response(&id, &Err(SkError::of(SkErrorCode::PinRequired))),
        );
        assert_eq!(
            task.await.unwrap().unwrap_err().code,
            SkErrorCode::PinRequired
        );
        r1.recv().await.unwrap();
        r2.recv().await.unwrap();
        // A cancel ends it at once; then the timeout.
        let b2 = broker.clone();
        let task = tokio::spawn(async move { b2.request(alice, &request("ssh:")).await });
        let id = r1.recv().await.unwrap()["request_id"]
            .as_str()
            .unwrap()
            .to_string();
        broker.on_message(
            alice,
            g2.id(),
            &wire::response(&id, &Err(SkError::of(SkErrorCode::Cancelled))),
        );
        assert_eq!(
            task.await.unwrap().unwrap_err().code,
            SkErrorCode::Cancelled
        );
        let e = broker.request(alice, &request("ssh:")).await.unwrap_err();
        assert_eq!(e.code, SkErrorCode::Timeout);
        // A device that goes away while asked counts as failed.
        drop(g1);
        let b2 = broker.clone();
        let task = tokio::spawn(async move { b2.request(alice, &request("ssh:")).await });
        while r2.recv().await.unwrap()["type"] != "security_key_request" {}
        drop(g2);
        assert_eq!(task.await.unwrap().unwrap_err().code, SkErrorCode::NoDevice);
        drop(gb);
        assert_eq!(broker.signers_of(alice), 0);
    }
}
