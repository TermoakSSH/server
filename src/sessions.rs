//! Terminal sessions that live on the server.
//!
//! - **server**: the server opens the SSH connection and keeps the terminal
//!   alive even if the user closes the app or loses coverage. Any of the
//!   user's devices can reattach and see the scrollback.
//! - **relay**: a device's local session shared through the server. The
//!   device (the "host") uploads its terminal output and receives what guests
//!   with control permission type.
//!
//! Both can be shared with other users or through links, with view-only or
//! control permission.
//!
//! With a session holder (`[sessions] holder_socket`), the SSH connections of
//! server sessions are kept by that other process (see [`crate::holder`]) and
//! a copy of the scrollback stays here: restarting the server does not cut
//! them.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use termoak_ai::{SessionAccess, SessionSummary, TerminalOutput};
use termoak_core::model::{Host, SessionInfo, SessionShare, SessionStatus, SharePermission};
use termoak_core::time::now_ms;
use termoak_core::{Id, Store, new_id};
use termoak_ssh::prompt::{AuthPrompter, Prompt};
use termoak_ssh::recording::{InputAuthor, Recorder};
use termoak_ssh::terminal::OutputHub;
use termoak_ssh::{
    ConnectOptions, Connection, HostKeyVerifier, PtyOptions, StoreVerifier, TermStatus,
    TerminalSession,
};
use tokio::sync::{broadcast, oneshot, watch};

use crate::config::SessionsSection;
use crate::error::{ApiError, ApiResult};
use crate::holder::HolderClient;
use crate::holder::proto::{
    Answer, HeldStatus, HostKeyError, OpenSession, Question, RecordingOptions, ToHolder,
};
use crate::room::{EndCode, Grant, ParticipantKind, PersonInfo, Room};

/// Visible state of a session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SessionState {
    Connecting {
        message: String,
    },
    Running,
    /// Relay session whose host is offline (waiting for it to come back).
    HostOffline,
    Closed {
        exit_code: Option<u32>,
        reason: Option<String>,
    },
}

impl SessionState {
    pub fn is_closed(&self) -> bool {
        matches!(self, SessionState::Closed { .. })
    }
}

/// Effective permission of whoever is looking at a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Owner,
    Control,
    View,
}

impl Access {
    pub fn can_write(self) -> bool {
        matches!(self, Access::Owner | Access::Control)
    }
}

impl From<SharePermission> for Access {
    fn from(p: SharePermission) -> Self {
        match p {
            SharePermission::Control => Access::Control,
            SharePermission::View => Access::View,
        }
    }
}

/// A socket connected to a session (old `presence` list; see
/// [`crate::room`] for the participants).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Viewer {
    pub id: Id,
    pub name: String,
    /// Owner's view only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Id>,
    pub access: Access,
    /// `viewer` or `host` (host of a relay session).
    pub role: String,
    pub since: i64,
    /// Share they joined with (owner's view only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub share_id: Option<Id>,
    /// Participant (person) this socket belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub participant: Option<Id>,
}

impl Viewer {
    /// What someone who is not the owner may see: no user or share ids.
    pub fn public(mut self) -> Self {
        self.user_id = None;
        self.share_id = None;
        self
    }
}

/// Authentication question forwarded to the owner's devices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptRequest {
    pub prompt_id: Id,
    /// `hostkey`, `keyboard_interactive`, `password` or `passphrase`.
    pub kind: String,
    pub host: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub prompts: Vec<Prompt>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub key_type: Option<String>,
}

/// Answer to a question.
#[derive(Debug, Clone, Deserialize)]
pub struct PromptAnswer {
    #[serde(default)]
    pub accept: Option<bool>,
    #[serde(default)]
    pub answers: Option<Vec<String>>,
}

/// Who a [`Signal::End`] sends away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndTarget {
    Participant(Id),
    /// Everyone except the owner.
    Guests,
}

/// Session signals for its sockets (each one renders them for itself).
#[derive(Debug, Clone)]
pub enum Signal {
    Status {
        status: SessionState,
    },
    Prompt(PromptRequest),
    PromptDone {
        prompt_id: Id,
    },
    /// New size. `from`: socket that caused it (it does not need it back).
    Resize {
        cols: u16,
        rows: u16,
        from: Option<Id>,
    },
    /// Relay: the driver (or the owner on another device) asks the host
    /// for a size.
    ResizeRequest {
        cols: u16,
        rows: u16,
        by: Id,
    },
    Title {
        title: String,
    },
    /// Participants changed (joined, left, waiting, devices, requests...).
    Room,
    /// The keyboard changed hands.
    Control,
    /// A participant's timed grant ended (the keyboard went back to the
    /// owner; `Control` goes too).
    ControlExpired {
        participant: Id,
    },
    /// Someone is waiting to be let in (owner).
    JoinRequest {
        participant: Id,
    },
    /// Someone asks for the keyboard (owner).
    ControlRequest {
        participant: Id,
    },
    /// The owner said no to a request for the keyboard.
    ControlDenied {
        participant: Id,
    },
    /// The owner let someone in.
    Admitted {
        participant: Id,
    },
    /// Sends sockets away with a code.
    End {
        target: EndTarget,
        code: EndCode,
    },
}

/// Terminal of a server session: in this process or in the holder.
pub enum ServerTerm {
    Local(Arc<TerminalSession>),
    Held(HeldTerm),
}

/// Session kept by the holder; here, its scrollback and size.
pub struct HeldTerm {
    id: Id,
    hub: Arc<OutputHub>,
    size: Mutex<(u16, u16)>,
    holder: Arc<HolderClient>,
}

fn holder_down() -> ApiError {
    ApiError::new(
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "unavailable",
        "the session holder is not responding; try again in a few seconds",
    )
}

impl ServerTerm {
    fn hub(&self) -> Arc<OutputHub> {
        match self {
            ServerTerm::Local(t) => t.hub().clone(),
            ServerTerm::Held(h) => h.hub.clone(),
        }
    }

    fn size(&self) -> (u16, u16) {
        match self {
            ServerTerm::Local(t) => t.size(),
            ServerTerm::Held(h) => *h.size.lock(),
        }
    }

    async fn write(&self, data: Bytes) -> ApiResult<()> {
        match self {
            ServerTerm::Local(t) => t.write(data).await.map_err(ApiError::from),
            ServerTerm::Held(h) => {
                if h.holder.send_input(h.id, data) {
                    Ok(())
                } else {
                    Err(holder_down())
                }
            }
        }
    }

    /// Who types the input that follows (recording).
    async fn author(&self, author: InputAuthor) {
        match self {
            ServerTerm::Local(t) => {
                let _ = t.set_input_author(author).await;
            }
            // A holder older than this server does not know the message.
            ServerTerm::Held(h) if h.holder.records_authors() => {
                h.holder.send(ToHolder::Author { id: h.id, author });
            }
            ServerTerm::Held(_) => {}
        }
    }

    async fn resize(&self, cols: u16, rows: u16) {
        match self {
            ServerTerm::Local(t) => {
                let _ = t.resize(cols, rows).await;
            }
            ServerTerm::Held(h) => {
                let (cols, rows) = (cols.clamp(10, 1000), rows.clamp(2, 500));
                {
                    let mut size = h.size.lock();
                    if *size == (cols, rows) {
                        return;
                    }
                    *size = (cols, rows);
                }
                h.holder.send(ToHolder::Resize {
                    id: h.id,
                    cols,
                    rows,
                });
            }
        }
    }

    /// `false` if the close could not be requested (the holder is not responding).
    async fn close(&self) -> bool {
        match self {
            ServerTerm::Local(t) => {
                t.close().await;
                true
            }
            ServerTerm::Held(h) => h.holder.send(ToHolder::Close { id: h.id }),
        }
    }
}

/// Session data the holder keeps to hand back to the server (after a
/// restart, the server knows nothing about it).
#[derive(Serialize, Deserialize)]
struct HeldMeta {
    owner: Id,
    host_id: Option<Id>,
    /// Vault of the host (sessions from before vaults: none).
    #[serde(default)]
    vault_id: Option<Id>,
    created_at: i64,
    recording: bool,
    title: String,
}

/// Input typed while a session connects.
pub enum Pending {
    Data(Bytes),
    Author(InputAuthor),
}

pub enum Backing {
    Server {
        term: OnceLock<ServerTerm>,
        /// Input typed while the session connects (sent once it opens).
        pending: Mutex<Vec<Pending>>,
    },
    Relay {
        hub: Arc<OutputHub>,
        input: broadcast::Sender<Bytes>,
        host_online: AtomicBool,
        size: Mutex<(u16, u16)>,
    },
}

/// A live session.
pub struct LiveSession {
    pub id: Id,
    pub owner: Id,
    pub host_id: Option<Id>,
    /// Vault of the host (server sessions).
    pub vault_id: Option<Id>,
    pub created_at: i64,
    pub recording: bool,
    title: Mutex<String>,
    pub backing: Backing,
    state: watch::Sender<SessionState>,
    room: Mutex<Room>,
    signals: broadcast::Sender<Signal>,
    notices: broadcast::Sender<(Id, SessionNotice)>,
    prompts: Mutex<HashMap<Id, oneshot::Sender<PromptAnswer>>>,
    prompt_reqs: Mutex<HashMap<Id, PromptRequest>>,
    last_activity: AtomicI64,
    /// Serializes input and keeps who typed last (so the recording gets an
    /// author mark only when it changes, right before their input).
    input_author: tokio::sync::Mutex<Option<InputAuthor>>,
}

/// Public view of a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionView {
    pub id: Id,
    pub owner_id: Id,
    pub host_id: Option<Id>,
    pub title: String,
    pub kind: String,
    pub state: SessionState,
    pub created_at: i64,
    /// Sockets (user and share ids only in the owner's view).
    pub viewers: Vec<Viewer>,
    /// People in the session (see `docs/WEBSOCKET-PROTOCOL.md`).
    #[serde(default)]
    pub participants: Vec<crate::room::ParticipantView>,
    /// Participant with the keyboard (`null`: the owner).
    #[serde(default)]
    pub driver: Option<Id>,
    /// End of the driver's timed grant (ms), if it is timed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_until: Option<i64>,
    pub cols: u16,
    pub rows: u16,
    pub recording: bool,
    /// Permission of the caller.
    pub access: Access,
    /// Owner's name (in sessions shared with you).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_name: Option<String>,
}

impl LiveSession {
    pub fn kind(&self) -> &'static str {
        match self.backing {
            Backing::Server { .. } => "server",
            Backing::Relay { .. } => "relay",
        }
    }

    pub fn title(&self) -> String {
        self.title.lock().clone()
    }

    pub fn state(&self) -> SessionState {
        self.state.borrow().clone()
    }

    pub fn watch_state(&self) -> watch::Receiver<SessionState> {
        self.state.subscribe()
    }

    fn set_state(&self, s: SessionState) {
        self.state.send_replace(s.clone());
        let _ = self.signals.send(Signal::Status { status: s });
    }

    pub fn signals(&self) -> broadcast::Receiver<Signal> {
        self.signals.subscribe()
    }

    /// Scrollback + live output (if there is a terminal yet).
    pub fn hub(&self) -> Option<Arc<OutputHub>> {
        match &self.backing {
            Backing::Server { term, .. } => term.get().map(|t| t.hub()),
            Backing::Relay { hub, .. } => Some(hub.clone()),
        }
    }

    pub fn size(&self) -> (u16, u16) {
        match &self.backing {
            Backing::Server { term, .. } => term.get().map(|t| t.size()).unwrap_or((80, 24)),
            Backing::Relay { size, .. } => *size.lock(),
        }
    }

    pub fn touch(&self) {
        self.last_activity.store(now_ms(), Ordering::Relaxed);
    }

    /// Keyboard input from `author` (who may write: the owner, the driver
    /// or the AI on the owner's behalf). It counts in the driver's control
    /// period and, when recording, the recording gets an author mark each
    /// time the author changes.
    pub async fn write_by(&self, data: Bytes, author: InputAuthor) -> ApiResult<()> {
        let mut last = self.input_author.lock().await;
        if self.recording && last.as_ref() != Some(&author) {
            match &self.backing {
                Backing::Server { term, pending } => match term.get() {
                    Some(t) => t.author(author.clone()).await,
                    None => pending.lock().push(Pending::Author(author.clone())),
                },
                Backing::Relay { .. } => {}
            }
            *last = Some(author.clone());
        }
        let len = data.len();
        self.write(data).await?;
        if let Some(pid) = author.participant {
            self.room.lock().typed(pid, len);
        }
        Ok(())
    }

    /// Writes to the terminal (keyboard input).
    async fn write(&self, data: Bytes) -> ApiResult<()> {
        self.touch();
        match &self.backing {
            Backing::Server { term, pending } => match term.get() {
                Some(t) => t.write(data).await,
                None => {
                    let mut p = pending.lock();
                    let queued: usize = p
                        .iter()
                        .map(|i| match i {
                            Pending::Data(b) => b.len(),
                            Pending::Author(_) => 0,
                        })
                        .sum();
                    if queued + data.len() > 64 * 1024 {
                        return Err(ApiError::conflict("the session is still connecting")
                            .with_code("session_connecting"));
                    }
                    p.push(Pending::Data(data));
                    Ok(())
                }
            },
            Backing::Relay { input, .. } => {
                let _ = input.send(data);
                Ok(())
            }
        }
    }

    /// New size from a socket that may write (the owner or the driver).
    /// In a relay session the host's terminal decides: the request goes to
    /// the host, and the size changes when the host reports it.
    pub async fn resize(&self, cols: u16, rows: u16, from: Option<Id>) {
        match &self.backing {
            Backing::Server { term, .. } => {
                if let Some(t) = term.get() {
                    t.resize(cols, rows).await;
                    let _ = self.signals.send(Signal::Resize { cols, rows, from });
                }
            }
            Backing::Relay { .. } => {
                if let Some(by) = from.and_then(|s| self.room.lock().participant_of(s)) {
                    let _ = self.signals.send(Signal::ResizeRequest { cols, rows, by });
                }
            }
        }
    }

    /// Relay: the host reports the size of its terminal.
    pub fn host_resized(&self, cols: u16, rows: u16, host_socket: Id) {
        if let Backing::Relay { size, .. } = &self.backing {
            let (cols, rows) = (cols.clamp(10, 1000), rows.clamp(2, 500));
            *size.lock() = (cols, rows);
            let _ = self.signals.send(Signal::Resize {
                cols,
                rows,
                from: Some(host_socket),
            });
        }
    }

    /// Participants and keyboard (keep the lock short: no `.await` inside).
    pub fn room(&self) -> parking_lot::MutexGuard<'_, Room> {
        self.room.lock()
    }

    /// Sends a signal to the session's sockets.
    pub fn signal(&self, s: Signal) {
        let _ = self.signals.send(s);
    }

    /// Notice to a user (events WebSocket and push).
    pub fn notify(&self, user: Id, notice: SessionNotice) {
        let _ = self.notices.send((user, notice));
    }

    /// Admitted sockets, as `viewer` sees them.
    pub fn viewers(&self) -> Vec<Viewer> {
        self.room.lock().viewers()
    }

    /// A user has an admitted socket in the session.
    pub fn is_watching(&self, user: Id) -> bool {
        self.room.lock().is_watching(user)
    }

    /// Sends away participants (their sockets close with `code`).
    pub fn end(&self, target: EndTarget, code: EndCode) {
        let _ = self.signals.send(Signal::End { target, code });
    }

    /// Applies the best share someone has now (`None`: they are sent away
    /// with `code`). Tells everyone what changed.
    pub fn apply_grant(&self, participant: Id, grant: Option<Grant>, code: EndCode) {
        // Without a waiting room any more: whoever was waiting comes in.
        let let_in = grant.as_ref().is_some_and(|g| !g.require_approval);
        let (applied, admitted) = {
            let mut room = self.room.lock();
            let applied = room.apply(participant, grant);
            (applied, let_in && room.admit(participant, now_ms()))
        };
        if admitted {
            self.signal(Signal::Admitted { participant });
            self.signal(Signal::Room);
        }
        match applied {
            crate::room::Applied::Unchanged => {}
            crate::room::Applied::Removed => {
                self.end(EndTarget::Participant(participant), code);
                self.signal(Signal::Room);
            }
            crate::room::Applied::Changed { lost_drive } => {
                if lost_drive {
                    self.signal(Signal::Control);
                }
                self.signal(Signal::Room);
            }
        }
    }

    /// Answers a pending question (owner only).
    pub fn answer_prompt(&self, prompt_id: Id, answer: PromptAnswer) -> bool {
        match self.prompts.lock().remove(&prompt_id) {
            Some(tx) => {
                let _ = tx.send(answer);
                self.prompt_reqs.lock().remove(&prompt_id);
                let _ = self.signals.send(Signal::PromptDone { prompt_id });
                true
            }
            None => false,
        }
    }

    /// Pending questions (for late joiners).
    pub fn pending_prompts(&self) -> Vec<PromptRequest> {
        self.prompt_reqs.lock().values().cloned().collect()
    }

    pub fn set_title(&self, title: String) {
        *self.title.lock() = title.clone();
        if let Backing::Server { term, .. } = &self.backing
            && let Some(ServerTerm::Held(h)) = term.get()
        {
            h.holder.send(ToHolder::Meta {
                id: self.id,
                meta: self.held_meta(),
            });
        }
        let _ = self.signals.send(Signal::Title { title });
    }

    fn held_meta(&self) -> serde_json::Value {
        serde_json::to_value(HeldMeta {
            owner: self.owner,
            host_id: self.host_id,
            vault_id: self.vault_id,
            created_at: self.created_at,
            recording: self.recording,
            title: self.title(),
        })
        .unwrap_or_default()
    }

    /// The session as someone with `access` sees it (`me`: their
    /// participant, if they are in).
    pub fn view(&self, access: Access) -> SessionView {
        self.view_for(access, None)
    }

    pub fn view_for(&self, access: Access, me: Option<Id>) -> SessionView {
        let (cols, rows) = self.size();
        let owner = access == Access::Owner;
        let (viewers, participants, driver, driver_until) = {
            let room = self.room.lock();
            let viewers = room.viewers();
            (
                if owner {
                    viewers
                } else {
                    viewers.into_iter().map(Viewer::public).collect()
                },
                room.participants(owner, me),
                room.driver(),
                room.driver_until(),
            )
        };
        SessionView {
            id: self.id,
            owner_id: self.owner,
            host_id: self.host_id,
            title: self.title(),
            kind: self.kind().to_string(),
            state: self.state(),
            created_at: self.created_at,
            viewers,
            participants,
            driver,
            driver_until,
            cols,
            rows,
            recording: self.recording,
            access,
            owner_name: None,
        }
    }

    /// Relay: the host connects or disconnects.
    pub fn set_host_online(&self, online: bool) {
        if let Backing::Relay { host_online, .. } = &self.backing {
            host_online.store(online, Ordering::SeqCst);
            if !self.state().is_closed() {
                self.set_state(if online {
                    SessionState::Running
                } else {
                    SessionState::HostOffline
                });
            }
        }
    }
}

/// Forwards authentication questions to the owner's devices.
struct SessionPrompter {
    session: std::sync::Weak<LiveSession>,
    last_prompt: Mutex<Option<PromptRequest>>,
}

impl SessionPrompter {
    fn new(session: &Arc<LiveSession>) -> Self {
        Self {
            session: Arc::downgrade(session),
            last_prompt: Mutex::new(None),
        }
    }
}

impl SessionPrompter {
    async fn ask(&self, mut req: PromptRequest) -> Option<PromptAnswer> {
        let session = self.session.upgrade()?;
        let (tx, rx) = oneshot::channel();
        req.prompt_id = new_id();
        session.prompts.lock().insert(req.prompt_id, tx);
        session
            .prompt_reqs
            .lock()
            .insert(req.prompt_id, req.clone());
        *self.last_prompt.lock() = Some(req.clone());
        let _ = session.signals.send(Signal::Prompt(req.clone()));
        // The owner's devices (events WebSocket, and push if nobody is watching).
        session.notify(
            session.owner,
            SessionNotice::PromptPending {
                session_id: session.id,
                prompt: req.clone(),
            },
        );
        let answer = tokio::time::timeout(Duration::from_secs(180), rx)
            .await
            .ok()?
            .ok();
        session.prompts.lock().remove(&req.prompt_id);
        session.prompt_reqs.lock().remove(&req.prompt_id);
        answer
    }
}

#[async_trait]
impl AuthPrompter for SessionPrompter {
    async fn confirm_host_key(
        &self,
        host: &str,
        port: u16,
        key_type: &str,
        fingerprint: &str,
    ) -> bool {
        self.ask(PromptRequest {
            prompt_id: Id::nil(),
            kind: "hostkey".into(),
            host: format!("{host}:{port}"),
            message: format!("New host. {key_type} fingerprint {fingerprint}. Do you trust it?"),
            prompts: vec![],
            fingerprint: Some(fingerprint.to_string()),
            key_type: Some(key_type.to_string()),
        })
        .await
        .and_then(|a| a.accept)
        .unwrap_or(false)
    }

    async fn keyboard_interactive(
        &self,
        host: &str,
        name: &str,
        instructions: &str,
        prompts: &[Prompt],
    ) -> Option<Vec<String>> {
        self.ask(PromptRequest {
            prompt_id: Id::nil(),
            kind: "keyboard_interactive".into(),
            host: host.to_string(),
            message: [name, instructions]
                .iter()
                .filter(|s| !s.is_empty())
                .copied()
                .collect::<Vec<_>>()
                .join("\n"),
            prompts: prompts.to_vec(),
            fingerprint: None,
            key_type: None,
        })
        .await
        .and_then(|a| a.answers)
    }

    async fn passphrase(&self, host: &str, key_label: &str) -> Option<String> {
        self.ask(PromptRequest {
            prompt_id: Id::nil(),
            kind: "passphrase".into(),
            host: host.to_string(),
            message: format!("Passphrase for key \"{key_label}\""),
            prompts: vec![Prompt {
                text: "Passphrase".into(),
                echo: false,
            }],
            fingerprint: None,
            key_type: None,
        })
        .await
        .and_then(|a| a.answers)
        .and_then(|a| a.into_iter().next())
    }

    async fn password(&self, host: &str, user: &str) -> Option<String> {
        self.ask(PromptRequest {
            prompt_id: Id::nil(),
            kind: "password".into(),
            host: host.to_string(),
            message: format!("Password for {user}@{host}"),
            prompts: vec![Prompt {
                text: "Password".into(),
                echo: false,
            }],
            fingerprint: None,
            key_type: None,
        })
        .await
        .and_then(|a| a.answers)
        .and_then(|a| a.into_iter().next())
    }
}

/// Notice for a user (events WebSocket).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionNotice {
    SessionOpened {
        session: SessionView,
    },
    SessionClosed {
        session_id: Id,
        reason: Option<String>,
    },
    SessionShared {
        session: SessionView,
        /// Name of the user who shared it.
        by: String,
        /// Team it was shared through, if any.
        #[serde(skip_serializing_if = "Option::is_none")]
        team: Option<String>,
    },
    PromptPending {
        session_id: Id,
        prompt: PromptRequest,
    },
    /// Someone is waiting to be let into one of your sessions.
    JoinRequest {
        session_id: Id,
        title: String,
        participant: crate::room::ParticipantView,
    },
    /// Someone asks for the keyboard of one of your sessions.
    ControlRequest {
        session_id: Id,
        title: String,
        participant: crate::room::ParticipantView,
    },
    /// You got the keyboard of a session shared with you.
    ControlGranted {
        session_id: Id,
    },
    /// You lost the keyboard of a session shared with you.
    ControlRevoked {
        session_id: Id,
    },
}

/// Session manager.
pub struct SessionManager {
    store: Store,
    cfg: SessionsSection,
    data_dir: PathBuf,
    sessions: Arc<RwLock<HashMap<Id, Arc<LiveSession>>>>,
    notices: broadcast::Sender<(Id, SessionNotice)>,
    holder: OnceLock<Arc<HolderClient>>,
}

impl SessionManager {
    pub fn new(store: Store, cfg: SessionsSection, data_dir: PathBuf) -> Arc<Self> {
        let (notices, _) = broadcast::channel(1024);
        let mgr = Arc::new(Self {
            store,
            cfg,
            data_dir,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            notices,
            holder: OnceLock::new(),
        });
        let weak = Arc::downgrade(&mgr);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                let Some(m) = weak.upgrade() else { break };
                m.reap().await;
            }
        });
        // Expired shares also send away whoever is already inside.
        let weak = Arc::downgrade(&mgr);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(EXPIRY_CHECK);
            loop {
                tick.tick().await;
                let Some(m) = weak.upgrade() else { break };
                m.check_expiry(now_ms()).await;
            }
        });
        mgr
    }

    /// Per-user notices.
    pub fn notices(&self) -> broadcast::Receiver<(Id, SessionNotice)> {
        self.notices.subscribe()
    }

    pub fn notify(&self, user: Id, notice: SessionNotice) {
        let _ = self.notices.send((user, notice));
    }

    pub fn get(&self, id: Id) -> Option<Arc<LiveSession>> {
        self.sessions.read().get(&id).cloned()
    }

    pub fn owned_by(&self, owner: Id) -> Vec<Arc<LiveSession>> {
        let mut v: Vec<_> = self
            .sessions
            .read()
            .values()
            .filter(|s| s.owner == owner)
            .cloned()
            .collect();
        v.sort_by_key(|s| s.created_at);
        v
    }

    fn scrollback(&self) -> usize {
        self.cfg.scrollback_kb.max(64) * 1024
    }

    #[allow(clippy::too_many_arguments)]
    fn new_live(
        &self,
        id: Id,
        created_at: i64,
        owner: Id,
        (host_id, vault_id): (Option<Id>, Option<Id>),
        title: String,
        backing: Backing,
        recording: bool,
        initial: SessionState,
    ) -> Arc<LiveSession> {
        let (state, _) = watch::channel(initial);
        let (signals, _) = broadcast::channel(256);
        let live = Arc::new(LiveSession {
            id,
            owner,
            host_id,
            vault_id,
            created_at,
            recording,
            title: Mutex::new(title),
            backing,
            state,
            room: Mutex::new(Room::default()),
            signals,
            notices: self.notices.clone(),
            prompts: Mutex::new(HashMap::new()),
            prompt_reqs: Mutex::new(HashMap::new()),
            last_activity: AtomicI64::new(now_ms()),
            input_author: tokio::sync::Mutex::new(None),
        });
        // Control periods are audited as they end.
        let mut rx = live.signals();
        let weak = Arc::downgrade(&live);
        let store = self.store.clone();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(Signal::Control | Signal::Room | Signal::End { .. })
                    | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Ok(_) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
                let Some(live) = weak.upgrade() else { break };
                audit_periods(&store, &live).await;
            }
        });
        live
    }

    fn check_quota(&self, owner: Id) -> ApiResult<()> {
        let active = self
            .owned_by(owner)
            .iter()
            .filter(|s| !s.state().is_closed())
            .count();
        if active >= self.cfg.max_per_user {
            return Err(ApiError::conflict(format!(
                "you have reached the maximum of {} active sessions",
                self.cfg.max_per_user
            ))
            .with_code("session_limit"));
        }
        Ok(())
    }

    /// Opens an SSH session that lives on the server.
    pub async fn open_server(
        self: &Arc<Self>,
        owner: Id,
        host_id: Id,
        cols: u16,
        rows: u16,
        title: Option<String>,
        record: Option<bool>,
    ) -> ApiResult<Arc<LiveSession>> {
        self.check_quota(owner)?;
        let holder = self.holder.get().cloned();
        if holder.as_ref().is_some_and(|h| !h.connected()) {
            return Err(holder_down());
        }
        // At least Use-only access to the host's vault; everything is
        // resolved inside that vault. Session shares never grant the vault.
        let access = self.store.vault_access(owner).await?;
        let rec = self.store.get_in::<Host>(&access, host_id).await?;
        let vault = rec.meta.vault_id.unwrap_or(owner);
        let host = rec.data;
        let settings = self
            .store
            .effective_settings_in(&access, vault, &host)
            .await?;
        let record = record
            .or(settings.record_sessions)
            .unwrap_or(self.cfg.record);
        let id = new_id();
        let term = OnceLock::new();
        if let Some(h) = &holder {
            let _ = term.set(ServerTerm::Held(HeldTerm {
                id,
                hub: Arc::new(OutputHub::new(self.scrollback())),
                size: Mutex::new((cols.clamp(10, 1000), rows.clamp(2, 500))),
                holder: h.clone(),
            }));
        }
        let live = self.new_live(
            id,
            now_ms(),
            owner,
            (Some(host_id), Some(vault)),
            title
                .filter(|t| !t.trim().is_empty())
                .unwrap_or_else(|| host.label.clone()),
            Backing::Server {
                term,
                pending: Mutex::new(Vec::new()),
            },
            record,
            SessionState::Connecting {
                message: format!("Connecting to {}…", host.label),
            },
        );
        self.store
            .insert_session(SessionInfo {
                id: live.id,
                owner_id: owner,
                host_id: Some(host_id),
                title: live.title(),
                status: SessionStatus::Connecting,
                kind: "server".into(),
                created_at: live.created_at,
                ended_at: None,
                error: None,
                recording: record,
            })
            .await?;
        self.store.set_session_vault(live.id, Some(vault)).await?;
        self.sessions.write().insert(live.id, live.clone());
        self.store
            .audit_vault(
                owner,
                &format!("user:{owner}"),
                "session.open",
                Some(host_id.to_string()),
                serde_json::json!({"session": live.id, "kind": "server"}),
                vault,
            )
            .await?;

        let mgr = self.clone();
        let session = live.clone();
        // With a holder, the session is resolved and handed over before the
        // client gets its id: what it types right away reaches a session the
        // holder already knows.
        let held = match &holder {
            Some(h) => Some(mgr.open_held(&session, h, cols, rows).await),
            None => None,
        };
        tokio::spawn(async move {
            let opened = match held {
                Some(r) => r,
                None => mgr.connect_server(&session, cols, rows).await,
            };
            match opened {
                Ok(()) => {}
                Err(e) => {
                    let reason = e.message;
                    tracing::info!(session = %session.id, %reason, "could not open the session");
                    mgr.finish(&session, SessionStatus::Failed, None, Some(reason))
                        .await;
                }
            }
        });
        self.notify(
            owner,
            SessionNotice::SessionOpened {
                session: live.view(Access::Owner),
            },
        );
        Ok(live)
    }

    async fn connect_server(
        self: &Arc<Self>,
        live: &Arc<LiveSession>,
        cols: u16,
        rows: u16,
    ) -> ApiResult<()> {
        let host_id = live.host_id.expect("server session with a host");
        let (resolved, access, vault) = self.resolve_for(live, host_id).await?;
        let prompter = Arc::new(SessionPrompter::new(live));
        let opts = ConnectOptions::new(Arc::new(StoreVerifier::for_host(
            self.store.clone(),
            access,
            vault,
            self.cfg.host_key_policy,
            Some(prompter.clone()),
        )))
        .with_prompter(prompter);
        let conn = Connection::connect(&resolved, &opts).await?;
        live.set_state(SessionState::Connecting {
            message: "Opening terminal…".into(),
        });
        let recorder = if live.recording {
            let path = self.recording_path(live.owner, live.id);
            match Recorder::create(&path, cols, rows, &live.title(), self.cfg.record_input).await {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::warn!(error = %e, "could not create the recording");
                    None
                }
            }
        } else {
            None
        };
        let pty = PtyOptions {
            term: resolved
                .settings
                .term
                .clone()
                .unwrap_or_else(|| "xterm-256color".into()),
            cols: cols.clamp(10, 1000),
            rows: rows.clamp(2, 500),
            env: resolved.settings.env.clone(),
            startup_script: resolved.startup_script.clone(),
            agent_forwarding: false,
        };
        let term = TerminalSession::open(conn.clone(), pty, self.scrollback(), recorder).await?;
        if let Backing::Server {
            term: slot,
            pending,
        } = &live.backing
        {
            let _ = slot.set(ServerTerm::Local(term.clone()));
            let queued: Vec<Pending> = std::mem::take(&mut *pending.lock());
            for input in queued {
                let _ = match input {
                    Pending::Data(data) => term.write(data).await,
                    Pending::Author(author) => term.set_input_author(author).await,
                };
            }
        }
        live.set_state(SessionState::Running);
        self.store
            .set_session_status(live.id, SessionStatus::Running, None)
            .await?;

        // Detect the host's OS if unknown (saved only by Editors: it is
        // just metadata).
        let store = self.store.clone();
        let owner = live.owner;
        tokio::spawn(async move {
            if let Ok(access) = store.vault_access(owner).await
                && let Ok(rec) = store.get_in::<Host>(&access, host_id).await
                && (rec.data.os.is_none() || rec.data.os_version.is_none())
                && let Some(vault) = rec.meta.vault_id
                && access.role(vault).is_some_and(|r| r.can_write())
                && let Some(os) = termoak_ssh::detect::detect_os_info(&conn).await
            {
                let mut h = rec.data;
                h.os_version = Some(os.display());
                h.os = Some(os.id);
                let _ = store
                    .save_in(
                        &access,
                        vault,
                        h,
                        termoak_core::model::SecretUpdate::Keep,
                        None,
                    )
                    .await;
            }
        });

        // Activity and close.
        let mgr = self.clone();
        let session = live.clone();
        tokio::spawn(async move {
            let (_, mut rx) = term.attach();
            let mut status = term.watch_status();
            loop {
                tokio::select! {
                    r = rx.recv() => match r {
                        Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => session.touch(),
                        Err(broadcast::error::RecvError::Closed) => {}
                    },
                    changed = status.changed() => {
                        if changed.is_err() { break; }
                        let s = status.borrow().clone();
                        if let TermStatus::Closed { exit_code, reason } = s {
                            mgr.finish(&session, SessionStatus::Closed, exit_code, reason).await;
                            break;
                        }
                    }
                }
            }
        });
        Ok(())
    }

    /// Creates a relay session (the host is one of the user's devices).
    pub async fn open_relay(
        self: &Arc<Self>,
        owner: Id,
        title: String,
        cols: u16,
        rows: u16,
        host_id: Option<Id>,
    ) -> ApiResult<Arc<LiveSession>> {
        self.check_quota(owner)?;
        let (input, _) = broadcast::channel(256);
        let live = self.new_live(
            new_id(),
            now_ms(),
            owner,
            (host_id, None),
            if title.trim().is_empty() {
                "Shared session".into()
            } else {
                title
            },
            Backing::Relay {
                hub: Arc::new(OutputHub::new(self.scrollback())),
                input,
                host_online: AtomicBool::new(false),
                size: Mutex::new((cols.clamp(10, 1000), rows.clamp(2, 500))),
            },
            false,
            SessionState::HostOffline,
        );
        self.store
            .insert_session(SessionInfo {
                id: live.id,
                owner_id: owner,
                host_id,
                title: live.title(),
                status: SessionStatus::Running,
                kind: "relay".into(),
                created_at: live.created_at,
                ended_at: None,
                error: None,
                recording: false,
            })
            .await?;
        self.sessions.write().insert(live.id, live.clone());
        self.spawn_relay_grace(live.clone());
        Ok(live)
    }

    /// Closes a relay if its host does not come back in time.
    pub fn spawn_relay_grace(self: &Arc<Self>, live: Arc<LiveSession>) {
        let mgr = self.clone();
        let grace = Duration::from_secs(self.cfg.relay_grace_minutes.max(1) * 60);
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            if let Backing::Relay { host_online, .. } = &live.backing
                && !host_online.load(Ordering::SeqCst)
                && !live.state().is_closed()
            {
                mgr.finish(
                    &live,
                    SessionStatus::Closed,
                    None,
                    Some("the host did not reconnect".into()),
                )
                .await;
            }
        });
    }

    /// Relay: input channel from guests to the host.
    pub fn relay_input(&self, live: &LiveSession) -> Option<broadcast::Receiver<Bytes>> {
        match &live.backing {
            Backing::Relay { input, .. } => Some(input.subscribe()),
            _ => None,
        }
    }

    /// Closes a session.
    pub async fn close(self: &Arc<Self>, live: &Arc<LiveSession>, by: Id) -> ApiResult<()> {
        match &live.backing {
            Backing::Server { term, .. } => {
                let asked = match term.get() {
                    Some(t) => t.close().await,
                    None => false,
                };
                if !asked {
                    self.finish(live, SessionStatus::Closed, None, Some("cancelled".into()))
                        .await;
                }
            }
            Backing::Relay { .. } => {
                self.finish(
                    live,
                    SessionStatus::Closed,
                    None,
                    Some("closed by the host".into()),
                )
                .await;
            }
        }
        self.store
            .audit(
                live.owner,
                &format!("user:{by}"),
                "session.close",
                Some(live.id.to_string()),
                serde_json::json!({}),
            )
            .await?;
        Ok(())
    }

    async fn finish(
        &self,
        live: &Arc<LiveSession>,
        status: SessionStatus,
        exit_code: Option<u32>,
        reason: Option<String>,
    ) {
        if live.state().is_closed() {
            return;
        }
        live.set_state(SessionState::Closed {
            exit_code,
            reason: reason.clone(),
        });
        live.room().end_period();
        audit_periods(&self.store, live).await;
        // Unblock pending questions.
        live.prompts.lock().clear();
        live.prompt_reqs.lock().clear();
        let _ = self
            .store
            .set_session_status(live.id, status, reason.clone())
            .await;
        self.notify(
            live.owner,
            SessionNotice::SessionClosed {
                session_id: live.id,
                reason,
            },
        );
        // Kept in memory for a while so clients see the end.
        let map = self.sessions.clone();
        let id = live.id;
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(120)).await;
            map.write().remove(&id);
        });
    }

    // --- session holder ----------------------------------------------------

    /// Uses the holder at `socket` for server sessions. Returns the sessions
    /// it already had if it answers within `wait` (otherwise it keeps trying
    /// in the background).
    pub async fn use_holder(self: &Arc<Self>, socket: PathBuf, wait: Duration) -> Option<Vec<Id>> {
        let client = Arc::new(HolderClient::new(socket));
        if self.holder.set(client.clone()).is_err() {
            return None;
        }
        let (tx, rx) = oneshot::channel();
        tokio::spawn(crate::holder::client::run(
            Arc::downgrade(self),
            client,
            Some(tx),
        ));
        tokio::time::timeout(wait, rx).await.ok()?.ok()
    }

    pub fn holder(&self) -> Option<&Arc<HolderClient>> {
        self.holder.get()
    }

    /// Asks the holder to open the session.
    async fn open_held(
        self: &Arc<Self>,
        live: &Arc<LiveSession>,
        holder: &HolderClient,
        cols: u16,
        rows: u16,
    ) -> ApiResult<()> {
        let host_id = live.host_id.expect("server session with a host");
        let (resolved, _, _) = self.resolve_for(live, host_id).await?;
        let detect_os = resolved.host.os.is_none() || resolved.host.os_version.is_none();
        let open = OpenSession {
            id: live.id,
            meta: live.held_meta(),
            term: resolved
                .settings
                .term
                .clone()
                .unwrap_or_else(|| "xterm-256color".into()),
            cols: cols.clamp(10, 1000),
            rows: rows.clamp(2, 500),
            env: resolved.settings.env.clone(),
            startup_script: resolved.startup_script.clone(),
            scrollback: self.scrollback(),
            recording: live.recording.then(|| RecordingOptions {
                path: self.recording_path(live.owner, live.id),
                title: live.title(),
                input: self.cfg.record_input,
            }),
            detect_os,
            host: resolved,
        };
        if holder.send(ToHolder::Open(Box::new(open))) {
            Ok(())
        } else {
            Err(holder_down())
        }
    }

    /// A session the holder already had (e.g. after a server restart).
    pub(crate) async fn adopt(
        self: &Arc<Self>,
        id: Id,
        meta: serde_json::Value,
        status: HeldStatus,
        cols: u16,
        rows: u16,
    ) {
        if self.get(id).is_some() {
            self.held_status(id, status).await;
            return;
        }
        let Some(holder) = self.holder.get().cloned() else {
            return;
        };
        let meta: HeldMeta = match serde_json::from_value(meta) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(session = %id, error = %e, "holder session without valid data");
                return;
            }
        };
        let state = match status {
            HeldStatus::Connecting { message } => SessionState::Connecting { message },
            HeldStatus::Running => SessionState::Running,
            HeldStatus::Closed { .. } => return,
        };
        let term = OnceLock::new();
        let _ = term.set(ServerTerm::Held(HeldTerm {
            id,
            hub: Arc::new(OutputHub::new(self.scrollback())),
            size: Mutex::new((cols, rows)),
            holder,
        }));
        let live = self.new_live(
            id,
            meta.created_at,
            meta.owner,
            (meta.host_id, meta.vault_id),
            meta.title,
            Backing::Server {
                term,
                pending: Mutex::new(Vec::new()),
            },
            meta.recording,
            state,
        );
        self.sessions.write().insert(id, live);
        // If it was marked closed at startup (the holder was slow), it is alive again.
        let _ = self
            .store
            .set_session_status(id, SessionStatus::Running, None)
            .await;
        tracing::info!(session = %id, "session recovered from the holder");
    }

    /// End of the holder's list: its sessions it no longer has were closed
    /// while disconnected (or the holder restarted).
    pub(crate) async fn held_synced(self: &Arc<Self>, held: &[Id]) {
        let gone: Vec<Arc<LiveSession>> = self
            .sessions
            .read()
            .values()
            .filter(|s| {
                !held.contains(&s.id)
                    && !s.state().is_closed()
                    && matches!(&s.backing, Backing::Server { term, .. }
                        if matches!(term.get(), Some(ServerTerm::Held(_))))
            })
            .cloned()
            .collect();
        for s in gone {
            self.finish(
                &s,
                SessionStatus::Closed,
                None,
                Some("the session ended while the server was down".into()),
            )
            .await;
        }
    }

    pub(crate) async fn held_status(self: &Arc<Self>, id: Id, status: HeldStatus) {
        let Some(live) = self.get(id) else { return };
        match status {
            HeldStatus::Connecting { message } => {
                if !live.state().is_closed() {
                    live.set_state(SessionState::Connecting { message });
                }
            }
            HeldStatus::Running => {
                if live.state() != SessionState::Running && !live.state().is_closed() {
                    live.set_state(SessionState::Running);
                    let _ = self
                        .store
                        .set_session_status(id, SessionStatus::Running, None)
                        .await;
                }
            }
            HeldStatus::Closed {
                exit_code,
                reason,
                failed,
            } => {
                let status = if failed {
                    SessionStatus::Failed
                } else {
                    SessionStatus::Closed
                };
                self.finish(&live, status, exit_code, reason).await;
            }
        }
    }

    pub(crate) fn held_output(&self, id: Id, data: Bytes) {
        if let Some(live) = self.get(id)
            && let Some(hub) = live.hub()
        {
            hub.push(data);
            live.touch();
        }
    }

    pub(crate) fn held_snapshot(&self, id: Id, data: Bytes) {
        if let Some(hub) = self.get(id).and_then(|l| l.hub()) {
            hub.reset(data);
        }
    }

    /// Answers a holder question as if the session were local.
    pub(crate) async fn answer(&self, id: Id, question: Question) -> Answer {
        let live = self.get(id);
        let prompter = live.as_ref().map(|l| Arc::new(SessionPrompter::new(l)));
        match question {
            Question::HostKey { host, port, key } => {
                let target = format!("{host}:{port}");
                let error = match (&live, termoak_ssh::keys::parse_public(&key)) {
                    (None, _) => Some(HostKeyError::Other {
                        host: target,
                        message: "the session no longer exists".into(),
                    }),
                    (_, Err(e)) => Some(HostKeyError::from_ssh(e, &target)),
                    (Some(l), Ok(key)) => match self.verifier_for(l, prompter).await {
                        Ok(verifier) => verifier
                            .verify(&host, port, &key)
                            .await
                            .err()
                            .map(|e| HostKeyError::from_ssh(e, &target)),
                        Err(e) => Some(HostKeyError::Other {
                            host: target,
                            message: e.message,
                        }),
                    },
                };
                Answer::HostKey { error }
            }
            Question::KeyboardInteractive {
                host,
                name,
                instructions,
                prompts,
            } => Answer::Answers {
                answers: match prompter {
                    Some(p) => {
                        p.keyboard_interactive(&host, &name, &instructions, &prompts)
                            .await
                    }
                    None => None,
                },
            },
            Question::Passphrase { host, key_label } => Answer::Text {
                text: match prompter {
                    Some(p) => p.passphrase(&host, &key_label).await,
                    None => None,
                },
            },
            Question::Password { host, user } => Answer::Text {
                text: match prompter {
                    Some(p) => p.password(&host, &user).await,
                    None => None,
                },
            },
        }
    }

    /// Stores the OS detected on the session's host.
    pub(crate) async fn held_os(&self, id: Id, os: String, display: String) {
        let Some(live) = self.get(id) else { return };
        let Some(host_id) = live.host_id else { return };
        let Ok(access) = self.store.vault_access(live.owner).await else {
            return;
        };
        if let Ok(rec) = self.store.get_in::<Host>(&access, host_id).await
            && let Some(vault) = rec.meta.vault_id
            && access.role(vault).is_some_and(|r| r.can_write())
        {
            let mut h = rec.data;
            h.os_version = Some(display);
            h.os = Some(os);
            let _ = self
                .store
                .save_in(
                    &access,
                    vault,
                    h,
                    termoak_core::model::SecretUpdate::Keep,
                    None,
                )
                .await;
        }
    }

    /// Resolves the host of a server session with the owner's current
    /// access, inside the session's vault (the host must still be there).
    async fn resolve_for(
        &self,
        live: &LiveSession,
        host_id: Id,
    ) -> ApiResult<(
        termoak_core::resolve::ResolvedHost,
        Arc<termoak_core::store::VaultAccess>,
        Id,
    )> {
        let access = self.store.vault_access(live.owner).await?;
        let vault = self.store.vault_of::<Host>(&access, host_id).await?;
        if live.vault_id.is_some_and(|v| v != vault) {
            return Err(ApiError::not_found(format!("host {host_id}")));
        }
        let resolved = self
            .store
            .resolve_in(&access, host_id, termoak_core::store::SecretUse::Server)
            .await?;
        Ok((resolved, access, vault))
    }

    /// Host key verifier of a session (its host's vault, then personal).
    async fn verifier_for(
        &self,
        live: &LiveSession,
        prompter: Option<Arc<SessionPrompter>>,
    ) -> ApiResult<StoreVerifier> {
        let access = self.store.vault_access(live.owner).await?;
        let vault = live.vault_id.unwrap_or(live.owner);
        Ok(StoreVerifier::for_host(
            self.store.clone(),
            access,
            vault,
            self.cfg.host_key_policy,
            prompter.map(|p| p as Arc<dyn AuthPrompter>),
        ))
    }

    /// Closes the server sessions on hosts of `vault` (of one user, or of
    /// everyone): access was revoked or the vault is gone. Returns how many.
    pub async fn close_for_vault(self: &Arc<Self>, user: Option<Id>, vault: Id) -> usize {
        let affected: Vec<Arc<LiveSession>> = self
            .sessions
            .read()
            .values()
            .filter(|s| {
                s.vault_id == Some(vault)
                    && user.is_none_or(|u| s.owner == u)
                    && matches!(s.backing, Backing::Server { .. })
                    && !s.state().is_closed()
            })
            .cloned()
            .collect();
        for s in &affected {
            if let Backing::Server { term, .. } = &s.backing
                && let Some(t) = term.get()
            {
                t.close().await;
            }
            self.finish(
                s,
                SessionStatus::Closed,
                None,
                Some(termoak_core::error::codes::VAULT_ACCESS_REVOKED.into()),
            )
            .await;
            self.audit(
                s,
                "system",
                "session.close",
                serde_json::json!({"reason": termoak_core::error::codes::VAULT_ACCESS_REVOKED}),
            )
            .await;
        }
        affected.len()
    }

    pub fn recording_path(&self, owner: Id, id: Id) -> PathBuf {
        self.data_dir
            .join("recordings")
            .join(owner.to_string())
            .join(format!("{id}.cast"))
    }

    async fn reap(self: &Arc<Self>) {
        if self.cfg.idle_timeout_hours == 0 {
            return;
        }
        let limit = self.cfg.idle_timeout_hours as i64 * 3_600_000;
        let now = now_ms();
        let idle: Vec<_> = self
            .sessions
            .read()
            .values()
            .filter(|s| {
                !s.state().is_closed()
                    && s.room.lock().socket_count() == 0
                    && now - s.last_activity.load(Ordering::Relaxed) > limit
            })
            .cloned()
            .collect();
        for s in idle {
            tracing::info!(session = %s.id, "closing idle session");
            let _ = self.close(&s, s.owner).await;
        }
    }

    /// A user's permission on a session (owner or guest).
    pub async fn access_for_user(&self, live: &LiveSession, user: Id) -> ApiResult<Access> {
        if live.owner == user {
            return Ok(Access::Owner);
        }
        match self.store.share_for_user(live.id, user).await? {
            Some(share) => Ok(share.permission.into()),
            None => Err(ApiError::not_found(format!("session {}", live.id))),
        }
    }

    /// Audit entry in the owner's log about one of their sessions.
    pub async fn audit(&self, live: &LiveSession, actor: &str, action: &str, detail: Value) {
        let _ = self
            .store
            .audit(live.owner, actor, action, Some(live.id.to_string()), detail)
            .await;
    }

    /// Takes the keyboard back from timed grants that are over and sends
    /// away participants whose share expired, as of `now` (ms). It runs
    /// every second; tests call it with a later `now`.
    pub async fn check_expiry(&self, now: i64) {
        let live: Vec<Arc<LiveSession>> = self
            .sessions
            .read()
            .values()
            .filter(|s| !s.state().is_closed())
            .cloned()
            .collect();
        for s in live {
            let ended = s.room().control_expired(now);
            if let Some(pid) = ended {
                s.signal(Signal::Control);
                s.signal(Signal::ControlExpired { participant: pid });
                s.signal(Signal::Room);
                let info = s.room().info(pid);
                if let Some(info) = info {
                    if let Some(user) = info.user_id {
                        s.notify(user, SessionNotice::ControlRevoked { session_id: s.id });
                    }
                    self.audit(
                        &s,
                        &actor_of(&info),
                        "session.control_expired",
                        serde_json::json!({"participant": pid, "name": info.name}),
                    )
                    .await;
                }
            }
            let expired = s.room().expired(now);
            for pid in expired {
                let gone = s.room().kick(pid);
                if let Some(info) = gone {
                    s.end(EndTarget::Participant(pid), EndCode::Expired);
                    s.signal(Signal::Control);
                    s.signal(Signal::Room);
                    self.audit(
                        &s,
                        &actor_of(&info),
                        "session.kicked",
                        serde_json::json!({"participant": pid, "name": info.name, "reason": "expired", "share": info.share_id}),
                    )
                    .await;
                }
            }
        }
    }

    /// The best share a participant has now (after a revocation, a change
    /// or leaving a team).
    async fn current_grant(
        &self,
        live: &LiveSession,
        info: &crate::room::PersonInfo,
    ) -> ApiResult<Option<Grant>> {
        let now = now_ms();
        let mut best: Option<Grant> = None;
        if let Some(user) = info.user_id
            && let Some(share) = self.store.share_for_user(live.id, user).await?
        {
            best = Some(grant_of(&share));
        }
        // A link they joined with (guests, or users who used a link).
        if info.link
            && let Some(id) = info.share_id
            && let Some(share) = self.store.session_share(live.id, id).await?
            && share.is_valid(now)
        {
            let link = grant_of(&share);
            if best.as_ref().is_none_or(|b| crate::room::better(&link, b)) {
                best = Some(link);
            }
        }
        Ok(best)
    }

    /// Checks again the access of everyone in a session (a share was
    /// revoked or changed, someone left a team...). Whoever has no share
    /// left is sent away with `code`; the rest keep the best one they have.
    /// `only`: just those participants.
    pub async fn reevaluate(&self, live: &LiveSession, code: EndCode, only: Option<&[Id]>) {
        let now = now_ms();
        let guests = live.room().guests();
        for info in guests {
            if only.is_some_and(|o| !o.contains(&info.participant)) {
                continue;
            }
            let Ok(grant) = self.current_grant(live, &info).await else {
                continue;
            };
            // Expired rather than revoked, when that is the reason.
            let code = match (&grant, info.share_id) {
                (None, Some(id)) => match self.store.session_share(live.id, id).await {
                    Ok(Some(s)) if !s.revoked && !s.is_valid(now) => EndCode::Expired,
                    _ => code,
                },
                _ => code,
            };
            let removed = grant.is_none();
            live.apply_grant(info.participant, grant, code);
            if removed {
                self.audit(
                    live,
                    &actor_of(&info),
                    "session.kicked",
                    serde_json::json!({"participant": info.participant, "name": info.name, "reason": code.as_str(), "share": info.share_id}),
                )
                .await;
            }
        }
    }

    /// A user's account is gone (deleted or disabled): out of every session.
    pub async fn remove_user(&self, user: Id) {
        let live: Vec<Arc<LiveSession>> = self.sessions.read().values().cloned().collect();
        for s in live {
            let pid = s.room().of_user(user);
            if let Some(pid) = pid
                && s.owner != user
                && s.room().kick(pid).is_some()
            {
                s.end(EndTarget::Participant(pid), EndCode::Revoked);
                s.signal(Signal::Control);
                s.signal(Signal::Room);
            }
        }
    }

    /// Re-checks a user's access to every live session (they left a team).
    pub async fn reevaluate_user(&self, user: Id) {
        let live: Vec<Arc<LiveSession>> = self.sessions.read().values().cloned().collect();
        for s in live {
            let pid = s.room().of_user(user);
            if let Some(pid) = pid
                && s.owner != user
            {
                self.reevaluate(&s, EndCode::Revoked, Some(&[pid])).await;
            }
        }
    }
}

/// Interval of the expiry check.
const EXPIRY_CHECK: Duration = Duration::from_secs(1);

/// What a share gives.
pub fn grant_of(share: &SessionShare) -> Grant {
    Grant {
        share_id: share.id,
        access: share.permission.into(),
        expires_at: share.expires_at,
        require_approval: share.require_approval,
        auto_grant: share.auto_grant,
        control_minutes: share.control_minutes,
        link: share.is_link,
    }
}

/// Author of a participant's input (recordings).
pub fn author_of(info: &PersonInfo) -> InputAuthor {
    InputAuthor {
        participant: Some(info.participant),
        name: info.name.clone(),
        kind: info.kind.as_str().into(),
    }
}

/// Author of what the AI types in one of the owner's sessions.
fn ai_author() -> InputAuthor {
    InputAuthor {
        participant: None,
        name: "AI".into(),
        kind: "ai".into(),
    }
}

/// One `session.control_period` audit entry per control period that ended
/// (who drove, from when to when, how much they typed).
async fn audit_periods(store: &Store, live: &LiveSession) {
    let periods = live.room().take_periods();
    for p in periods {
        let actor = match p.user_id {
            Some(u) => format!("user:{u}"),
            None if p.kind == ParticipantKind::Owner => format!("user:{}", live.owner),
            None => format!("guest:{}", p.participant),
        };
        let _ = store
            .audit(
                live.owner,
                &actor,
                "session.control_period",
                Some(live.id.to_string()),
                serde_json::to_value(&p).unwrap_or_default(),
            )
            .await;
    }
}

/// Audit actor of a participant.
pub fn actor_of(info: &crate::room::PersonInfo) -> String {
    match info.user_id {
        Some(u) => format!("user:{u}"),
        None => format!("guest:{}", info.participant),
    }
}

#[async_trait]
impl SessionAccess for SessionManager {
    async fn list(&self, owner: Id) -> Vec<SessionSummary> {
        self.owned_by(owner)
            .into_iter()
            .filter(|s| !s.state().is_closed())
            .map(|s| SessionSummary {
                id: s.id,
                title: s.title(),
                host_id: s.host_id,
                status: match s.state() {
                    SessionState::Running => "running".into(),
                    SessionState::Connecting { .. } => "connecting".into(),
                    SessionState::HostOffline => "host_offline".into(),
                    SessionState::Closed { .. } => "closed".into(),
                },
                viewers: s.room.lock().viewers().len(),
            })
            .collect()
    }

    async fn read(&self, owner: Id, session: Id, max_chars: usize) -> Result<String, String> {
        let live = self
            .get(session)
            .filter(|s| s.owner == owner)
            .ok_or_else(|| format!("no such session {session}"))?;
        let hub = live.hub().ok_or("the session is still connecting")?;
        Ok(hub.text_tail(max_chars))
    }

    async fn send(&self, owner: Id, session: Id, input: &str) -> Result<(), String> {
        let live = self
            .get(session)
            .filter(|s| s.owner == owner)
            .ok_or_else(|| format!("no such session {session}"))?;
        live.write_by(Bytes::from(input.to_string()), ai_author())
            .await
            .map_err(|e| e.message)
    }

    async fn send_and_collect(
        &self,
        owner: Id,
        session: Id,
        input: &str,
        quiet: Duration,
        max: Duration,
    ) -> Result<Option<TerminalOutput>, String> {
        let live = self
            .get(session)
            .filter(|s| s.owner == owner)
            .ok_or_else(|| format!("no such session {session}"))?;
        let hub = live.hub().ok_or("the session is still connecting")?;
        // Subscribed before writing: no output is lost.
        let (_, mut rx) = hub.attach();
        live.write_by(Bytes::from(input.to_string()), ai_author())
            .await
            .map_err(|e| e.message)?;
        let deadline = tokio::time::Instant::now() + max;
        let mut out = Vec::new();
        let mut still_running = false;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                still_running = true;
                break;
            }
            match tokio::time::timeout(quiet.min(left), rx.recv()).await {
                Ok(Ok(chunk)) => out.extend_from_slice(&chunk),
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => {}
                Ok(Err(broadcast::error::RecvError::Closed)) => break,
                // Quiet for the requested time: it finished (or is waiting for input).
                Err(_) if left > quiet => break,
                Err(_) => {
                    still_running = true;
                    break;
                }
            }
        }
        let text = termoak_ssh::ansi::strip(&String::from_utf8_lossy(&out));
        Ok(Some(TerminalOutput {
            text: termoak_ssh::ansi::tail(&text, 8000).to_string(),
            still_running,
        }))
    }
}
