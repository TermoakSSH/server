//! The holder: a separate process that keeps the SSH connections of the
//! server sessions. It does little and changes little, so it almost never
//! needs a restart: the server can be updated (and restarted) without cutting
//! the sessions, and when it comes back it recovers their scrollback and
//! carries on where it was.
//!
//! It serves one server at a time: if another one connects, the previous one
//! receives `Replaced` and is no longer talked to. What the server knows and
//! the holder does not (known hosts, passwords to ask the user for...) is
//! asked with `Ask`.

use std::collections::HashMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use serde_json::Value;
use termoak_core::Id;
use termoak_ssh::keys::public_openssh;
use termoak_ssh::prompt::{AuthPrompter, Prompt};
use termoak_ssh::recording::{InputAuthor, Recorder};
use termoak_ssh::{
    ConnectOptions, Connection, HostKeyVerifier, PtyOptions, PublicKey, SshError, TermStatus,
    TerminalSession,
};
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use super::proto::{
    Answer, FEATURES, Frame, HeldStatus, OpenSession, PROTOCOL, Question, ToHolder, ToServer,
    read_frame, write_frame,
};
use crate::error::ApiError;

/// File next to the socket with the running holder's protocol (so the
/// deployment knows whether it must be restarted).
pub fn protocol_file(socket: &Path) -> PathBuf {
    let mut name = socket.file_name().unwrap_or_default().to_os_string();
    name.push(".protocol");
    socket.with_file_name(name)
}

/// Listens on `socket` until `stop` is cancelled.
pub async fn run(socket: &Path, stop: CancellationToken) -> anyhow::Result<()> {
    if socket.exists() {
        if UnixStream::connect(socket).await.is_ok() {
            anyhow::bail!("there is already a session holder at {}", socket.display());
        }
        std::fs::remove_file(socket)
            .with_context(|| format!("could not delete {}", socket.display()))?;
    }
    if let Some(dir) = socket.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("could not create {}", dir.display()))?;
    }
    let listener = UnixListener::bind(socket)
        .with_context(|| format!("could not listen on {}", socket.display()))?;
    // Credentials go through the socket: only for this user.
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    let uid = std::fs::metadata(socket)?.uid();
    std::fs::write(protocol_file(socket), format!("{PROTOCOL}\n"))?;
    tracing::info!(
        socket = %socket.display(),
        protocol = PROTOCOL,
        "session holder {} listening",
        env!("CARGO_PKG_VERSION")
    );

    let holder = Arc::new(Holder::default());
    loop {
        let stream = tokio::select! {
            _ = stop.cancelled() => break,
            r = listener.accept() => match r {
                Ok((s, _)) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "could not accept a connection");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        match stream.peer_cred() {
            Ok(c) if c.uid() == uid => {}
            other => {
                tracing::warn!(peer = ?other, "rejected a connection from another user");
                continue;
            }
        }
        let h = holder.clone();
        tokio::spawn(async move { h.serve(stream).await });
    }
    let _ = std::fs::remove_file(socket);
    let _ = std::fs::remove_file(protocol_file(socket));
    Ok(())
}

#[derive(Default)]
struct Holder {
    sessions: Mutex<HashMap<Id, Arc<Held>>>,
    /// The server being served now.
    link: Mutex<Option<Arc<Link>>>,
    links: AtomicU64,
}

/// Connection to a server.
struct Link {
    n: u64,
    /// Control: unbounded (small messages) and written first.
    ctl: mpsc::UnboundedSender<Frame<ToServer>>,
    /// Terminal output: bounded, so nothing piles up forever if the server
    /// stalls (whoever falls behind gets the full scrollback).
    data: mpsc::Sender<Frame<ToServer>>,
    asks: Mutex<HashMap<u64, oneshot::Sender<Answer>>>,
    next_ask: AtomicU64,
    gone: CancellationToken,
}

impl Link {
    fn send(&self, msg: ToServer) {
        let _ = self.ctl.send(Frame::Msg(msg));
    }

    async fn ask(&self, id: Id, question: Question) -> Option<Answer> {
        let ask = self.next_ask.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.asks.lock().insert(ask, tx);
        self.send(ToServer::Ask { ask, id, question });
        // The server already applies its own limit to the user (3 minutes).
        let answer = tokio::select! {
            a = rx => a.ok(),
            _ = self.gone.cancelled() => None,
            _ = tokio::time::sleep(Duration::from_secs(240)) => None,
        };
        self.asks.lock().remove(&ask);
        answer
    }
}

enum Input {
    Data(Bytes),
    Resize(u16, u16),
    Author(InputAuthor),
}

/// A session kept by the holder.
struct Held {
    id: Id,
    meta: Mutex<Value>,
    status: Mutex<HeldStatus>,
    size: Mutex<(u16, u16)>,
    term: OnceLock<Arc<TerminalSession>>,
    /// Typed input and resizes, in order (they wait in the queue while the
    /// session connects).
    input: mpsc::UnboundedSender<Input>,
    /// Connection in progress (to cancel it if closed before it opens).
    connecting: Mutex<Option<tokio::task::AbortHandle>>,
    /// Last server connection the output is forwarded to.
    forwarded_to: Mutex<u64>,
}

impl Holder {
    fn current(&self) -> Option<Arc<Link>> {
        self.link.lock().clone()
    }

    /// Sends a status change to the current server.
    fn set_status(&self, held: &Held, status: HeldStatus) {
        // With the status lock held, so it does not race with the list a
        // server receives when it connects.
        let mut s = held.status.lock();
        *s = status.clone();
        if let Some(link) = self.current() {
            link.send(ToServer::Status {
                id: held.id,
                status,
            });
        }
    }

    async fn serve(self: Arc<Self>, stream: UnixStream) {
        let (mut rd, wr) = stream.into_split();
        let (ctl, ctl_rx) = mpsc::unbounded_channel();
        let (data, data_rx) = mpsc::channel(1024);
        let link = Arc::new(Link {
            n: self.links.fetch_add(1, Ordering::Relaxed) + 1,
            ctl,
            data,
            asks: Mutex::new(HashMap::new()),
            next_ask: AtomicU64::new(1),
            gone: CancellationToken::new(),
        });
        tokio::spawn(writer(wr, ctl_rx, data_rx, link.gone.clone()));
        link.send(ToServer::Hello {
            protocol: PROTOCOL,
            version: env!("CARGO_PKG_VERSION").into(),
            pid: std::process::id(),
            features: FEATURES.iter().map(|f| f.to_string()).collect(),
        });
        if let Some(old) = self.link.lock().replace(link.clone()) {
            tracing::info!("another server connected: dropping the previous one");
            old.send(ToServer::Replaced);
            old.gone.cancel();
        }
        tracing::info!(link = link.n, "server connected");

        // The existing sessions, with their scrollback.
        let held: Vec<Arc<Held>> = self.sessions.lock().values().cloned().collect();
        for h in held {
            let status = h.status.lock();
            if matches!(*status, HeldStatus::Closed { .. }) {
                continue;
            }
            let (cols, rows) = *h.size.lock();
            link.send(ToServer::Held {
                id: h.id,
                meta: h.meta.lock().clone(),
                status: status.clone(),
                cols,
                rows,
            });
            drop(status);
            self.start_forward(&h, &link);
        }
        link.send(ToServer::Synced);

        loop {
            let frame = tokio::select! {
                _ = link.gone.cancelled() => break,
                f = read_frame::<_, ToHolder>(&mut rd) => f,
            };
            match frame {
                Ok(Some(Frame::Msg(msg))) => self.handle(msg, &link),
                Ok(Some(Frame::Data(id, data))) => {
                    if let Some(h) = self.get(id) {
                        let _ = h.input.send(Input::Data(data));
                    }
                }
                Ok(Some(Frame::Snapshot(..))) => {}
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!(error = %e, "error reading from the server");
                    break;
                }
            }
        }
        link.gone.cancel();
        link.asks.lock().clear();
        let mut current = self.link.lock();
        if current.as_ref().is_some_and(|l| l.n == link.n) {
            *current = None;
            tracing::info!(link = link.n, "server disconnected; sessions stay open");
        }
    }

    fn get(&self, id: Id) -> Option<Arc<Held>> {
        self.sessions.lock().get(&id).cloned()
    }

    fn handle(self: &Arc<Self>, msg: ToHolder, link: &Arc<Link>) {
        match msg {
            ToHolder::Open(open) => self.open(*open),
            ToHolder::Resize { id, cols, rows } => {
                if let Some(h) = self.get(id) {
                    *h.size.lock() = (cols, rows);
                    let _ = h.input.send(Input::Resize(cols, rows));
                }
            }
            ToHolder::Close { id } => {
                if let Some(h) = self.get(id) {
                    self.close(h);
                }
            }
            ToHolder::Meta { id, meta } => {
                if let Some(h) = self.get(id) {
                    *h.meta.lock() = meta;
                }
            }
            ToHolder::Answer { ask, answer } => {
                if let Some(tx) = link.asks.lock().remove(&ask) {
                    let _ = tx.send(answer);
                }
            }
            // In the input queue, so it stays in order with the input.
            ToHolder::Author { id, author } => {
                if let Some(h) = self.get(id) {
                    let _ = h.input.send(Input::Author(author));
                }
            }
        }
    }

    fn close(self: &Arc<Self>, h: Arc<Held>) {
        match h.term.get() {
            Some(term) => {
                let term = term.clone();
                tokio::spawn(async move { term.close().await });
            }
            None => {
                if let Some(task) = h.connecting.lock().take() {
                    task.abort();
                }
                self.finish(
                    &h,
                    HeldStatus::Closed {
                        exit_code: None,
                        reason: Some("cancelled".into()),
                        failed: false,
                    },
                );
            }
        }
    }

    fn finish(&self, h: &Held, status: HeldStatus) {
        self.sessions.lock().remove(&h.id);
        self.set_status(h, status);
    }

    fn open(self: &Arc<Self>, o: OpenSession) {
        let (input, input_rx) = mpsc::unbounded_channel();
        let held = Arc::new(Held {
            id: o.id,
            meta: Mutex::new(o.meta.clone()),
            status: Mutex::new(HeldStatus::Connecting {
                message: format!("Connecting to {}…", o.host.host.label),
            }),
            size: Mutex::new((o.cols, o.rows)),
            term: OnceLock::new(),
            input,
            connecting: Mutex::new(None),
            forwarded_to: Mutex::new(0),
        });
        self.sessions.lock().insert(held.id, held.clone());
        let holder = self.clone();
        let h = held.clone();
        let task = tokio::spawn(async move {
            if let Err(e) = holder.connect(&h, o, input_rx).await {
                let reason = ApiError::from(e).message;
                tracing::info!(session = %h.id, %reason, "could not open the session");
                holder.finish(
                    &h,
                    HeldStatus::Closed {
                        exit_code: None,
                        reason: Some(reason),
                        failed: true,
                    },
                );
            }
        });
        *held.connecting.lock() = Some(task.abort_handle());
    }

    async fn connect(
        self: &Arc<Self>,
        held: &Arc<Held>,
        o: OpenSession,
        mut input: mpsc::UnboundedReceiver<Input>,
    ) -> Result<(), SshError> {
        let asker = Arc::new(Asker {
            holder: Arc::downgrade(self),
            id: held.id,
        });
        let opts = ConnectOptions::new(asker.clone()).with_prompter(asker);
        let conn = Connection::connect(&o.host, &opts).await?;
        self.set_status(
            held,
            HeldStatus::Connecting {
                message: "Opening terminal…".into(),
            },
        );
        let (cols, rows) = *held.size.lock();
        let recorder = match &o.recording {
            Some(r) => match Recorder::create(&r.path, cols, rows, &r.title, r.input).await {
                Ok(rec) => Some(rec),
                Err(e) => {
                    tracing::warn!(error = %e, "could not create the recording");
                    None
                }
            },
            None => None,
        };
        let pty = PtyOptions {
            term: o.term,
            cols: cols.clamp(10, 1000),
            rows: rows.clamp(2, 500),
            env: o.env,
            startup_script: o.startup_script,
            agent_forwarding: false,
        };
        let term = TerminalSession::open(conn.clone(), pty, o.scrollback, recorder).await?;
        held.connecting.lock().take();
        let _ = held.term.set(term.clone());
        self.set_status(held, HeldStatus::Running);
        if let Some(link) = self.current() {
            self.start_forward(held, &link);
        }

        // Typed input (and whatever was queued while connecting).
        let t = term.clone();
        tokio::spawn(async move {
            while let Some(i) = input.recv().await {
                let res = match i {
                    Input::Data(d) => t.write(d).await,
                    Input::Resize(c, r) => t.resize(c, r).await,
                    Input::Author(a) => t.set_input_author(a).await,
                };
                if res.is_err() {
                    break;
                }
            }
        });

        if o.detect_os {
            let holder = self.clone();
            let id = held.id;
            tokio::spawn(async move {
                if let Some(os) = termoak_ssh::detect::detect_os_info(&conn).await
                    && let Some(link) = holder.current()
                {
                    link.send(ToServer::Os {
                        id,
                        display: os.display(),
                        os: os.id,
                    });
                }
            });
        }

        // Close.
        let mut status = term.watch_status();
        loop {
            let now = status.borrow().clone();
            if let TermStatus::Closed { exit_code, reason } = now {
                // Grace period so the last output arrives before the close.
                tokio::time::sleep(Duration::from_millis(300)).await;
                self.sessions.lock().remove(&held.id);
                let closed = HeldStatus::Closed {
                    exit_code,
                    reason,
                    failed: false,
                };
                *held.status.lock() = closed.clone();
                if let Some(link) = self.current() {
                    // Through the data channel: after the last output.
                    let _ = link
                        .data
                        .send(Frame::Msg(ToServer::Status {
                            id: held.id,
                            status: closed,
                        }))
                        .await;
                }
                return Ok(());
            }
            if status.changed().await.is_err() {
                return Ok(());
            }
        }
    }

    /// Sends the scrollback and output of an open session to a server (once
    /// per connection).
    fn start_forward(&self, held: &Arc<Held>, link: &Arc<Link>) {
        let Some(term) = held.term.get().cloned() else {
            return;
        };
        {
            let mut to = held.forwarded_to.lock();
            if *to == link.n {
                return;
            }
            *to = link.n;
        }
        let id = held.id;
        let link = link.clone();
        tokio::spawn(async move {
            let (snapshot, mut rx) = term.attach();
            if link.data.send(Frame::Snapshot(id, snapshot)).await.is_err() {
                return;
            }
            loop {
                let chunk = tokio::select! {
                    _ = link.gone.cancelled() => return,
                    r = rx.recv() => r,
                };
                let frame = match chunk {
                    Ok(data) => Frame::Data(id, data),
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let (snapshot, fresh) = term.attach();
                        rx = fresh;
                        Frame::Snapshot(id, snapshot)
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                };
                if link.data.send(frame).await.is_err() {
                    return;
                }
            }
        });
    }
}

/// Writes to the server: control first, then output.
async fn writer(
    wr: OwnedWriteHalf,
    mut ctl: mpsc::UnboundedReceiver<Frame<ToServer>>,
    mut data: mpsc::Receiver<Frame<ToServer>>,
    gone: CancellationToken,
) {
    let mut w = BufWriter::with_capacity(64 * 1024, wr);
    loop {
        let frame = tokio::select! {
            biased;
            Some(f) = ctl.recv() => f,
            Some(f) = data.recv() => f,
            _ = gone.cancelled() => break,
        };
        if write_frame(&mut w, &frame).await.is_err() {
            break;
        }
        // Flush when nothing else is queued (several frames, one write).
        if ctl.is_empty() && data.is_empty() && w.flush().await.is_err() {
            break;
        }
    }
    // Any remaining control frames (e.g. `Replaced`) before closing.
    while let Ok(f) = ctl.try_recv() {
        if write_frame(&mut w, &f).await.is_err() {
            break;
        }
    }
    let _ = w.flush().await;
    let _ = w.shutdown().await;
}

/// What the holder cannot decide, it asks the server.
struct Asker {
    holder: std::sync::Weak<Holder>,
    id: Id,
}

impl Asker {
    async fn ask(&self, question: Question) -> Option<Answer> {
        let link = self.holder.upgrade()?.current()?;
        link.ask(self.id, question).await
    }
}

#[async_trait]
impl HostKeyVerifier for Asker {
    async fn verify(&self, host: &str, port: u16, key: &PublicKey) -> termoak_ssh::Result<()> {
        let question = Question::HostKey {
            host: host.to_string(),
            port,
            key: public_openssh(key),
        };
        match self.ask(question).await {
            Some(Answer::HostKey { error: None }) => Ok(()),
            Some(Answer::HostKey { error: Some(e) }) => Err(e.into_ssh()),
            _ => Err(SshError::Connect {
                target: format!("{host}:{port}"),
                reason: "the server did not answer the host key verification".into(),
            }),
        }
    }
}

#[async_trait]
impl AuthPrompter for Asker {
    async fn confirm_host_key(&self, _: &str, _: u16, _: &str, _: &str) -> bool {
        // The server verifies the host key (above).
        false
    }

    async fn keyboard_interactive(
        &self,
        host: &str,
        name: &str,
        instructions: &str,
        prompts: &[Prompt],
    ) -> Option<Vec<String>> {
        match self
            .ask(Question::KeyboardInteractive {
                host: host.to_string(),
                name: name.to_string(),
                instructions: instructions.to_string(),
                prompts: prompts.to_vec(),
            })
            .await?
        {
            Answer::Answers { answers } => answers,
            _ => None,
        }
    }

    async fn passphrase(&self, host: &str, key_label: &str) -> Option<String> {
        match self
            .ask(Question::Passphrase {
                host: host.to_string(),
                key_label: key_label.to_string(),
            })
            .await?
        {
            Answer::Text { text } => text,
            _ => None,
        }
    }

    async fn password(&self, host: &str, user: &str) -> Option<String> {
        match self
            .ask(Question::Password {
                host: host.to_string(),
                user: user.to_string(),
            })
            .await?
        {
            Answer::Text { text } => text,
            _ => None,
        }
    }
}
