//! Server terminal sessions: REST, WebSocket, sharing and relay.
//!
//! WebSocket protocol (`/api/v1/sessions/{id}/ws`), see `docs/WEBSOCKET-PROTOCOL.md`:
//! - Server → client: **binary** frames with the terminal output (the first
//!   one is the full history) and **JSON text** control frames (`hello`,
//!   `status`, `presence`, `resize`, `prompt`, `resync`...).
//! - Client → server: **binary** frames with the keystrokes (only with
//!   control permission) and JSON (`resize`, `prompt_answer`, `ping`...).

use axum::body::Body;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use termoak_core::model::{Host, SessionInfo, SharePermission};
use termoak_core::store::sessions::ShareTarget;
use termoak_core::time::now_ms;
use termoak_core::{Id, new_id};
use tokio::sync::broadcast;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::{AuthUser, MaybeUser};
use crate::error::{ApiError, ApiResult};
use crate::sessions::{
    Access, LiveSession, PromptAnswer, SessionNotice, SessionState, SessionView, Signal, Viewer,
};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/sessions", get(list).post(open))
        .route(
            "/api/v1/sessions/{id}",
            get(one).patch(rename).delete(close),
        )
        .route("/api/v1/sessions/{id}/ws", get(ws))
        .route("/api/v1/sessions/{id}/recording", get(recording))
        .route(
            "/api/v1/sessions/{id}/shares",
            get(list_shares).post(create_share),
        )
        .route(
            "/api/v1/sessions/{id}/shares/{share_id}",
            delete(revoke_share),
        )
        .route("/api/v1/relay", post(open_relay))
        .route("/api/v1/join/{token}", get(join_info))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct OpenSession {
    pub host_id: Uuid,
    #[serde(default = "default_cols")]
    pub cols: u16,
    #[serde(default = "default_rows")]
    pub rows: u16,
    #[serde(default)]
    pub title: Option<String>,
    /// Record the session (otherwise, whatever the host or the config says).
    #[serde(default)]
    pub record: Option<bool>,
}

fn default_cols() -> u16 {
    80
}

fn default_rows() -> u16 {
    24
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SessionList {
    /// Own sessions open on the server.
    #[schema(value_type = Vec<Object>)]
    pub active: Vec<SessionView>,
    /// Other users' sessions shared with me.
    #[schema(value_type = Vec<Object>)]
    pub shared: Vec<SessionView>,
    /// Recent history (closed).
    pub recent: Vec<SessionInfo>,
}

async fn list(State(st): State<AppState>, u: AuthUser) -> ApiResult<Json<SessionList>> {
    let active = st
        .sessions
        .owned_by(u.id())
        .into_iter()
        .map(|s| s.view(Access::Owner))
        .collect();
    let mut shared: Vec<SessionView> = st
        .store
        .sessions_shared_with(u.id())
        .await?
        .into_iter()
        .filter_map(|(info, share)| {
            st.sessions
                .get(info.id)
                .map(|l| l.view(share.permission.into()))
        })
        .collect();
    // Who shares it.
    let mut names: std::collections::HashMap<Id, String> = std::collections::HashMap::new();
    for v in &mut shared {
        if !names.contains_key(&v.owner_id)
            && let Ok(owner) = st.store.user(v.owner_id).await
        {
            names.insert(v.owner_id, owner.name);
        }
        v.owner_name = names.get(&v.owner_id).cloned();
    }
    let recent = st
        .store
        .list_sessions(u.id(), false, 50)
        .await?
        .into_iter()
        .filter(|s| st.sessions.get(s.id).is_none())
        .collect();
    Ok(Json(SessionList {
        active,
        shared,
        recent,
    }))
}

async fn open(
    State(st): State<AppState>,
    u: AuthUser,
    Json(req): Json<OpenSession>,
) -> ApiResult<Json<SessionView>> {
    crate::account::check_new_session(&st, &u.user)?;
    let live = st
        .sessions
        .open_server(
            u.id(),
            req.host_id,
            req.cols,
            req.rows,
            req.title,
            req.record,
        )
        .await?;
    Ok(Json(live.view(Access::Owner)))
}

async fn live_for(
    st: &AppState,
    u: &AuthUser,
    id: Id,
) -> ApiResult<(std::sync::Arc<LiveSession>, Access)> {
    let live = st
        .sessions
        .get(id)
        .ok_or_else(|| ApiError::not_found(format!("active session {id}")))?;
    let access = st.sessions.access_for_user(&live, u.id()).await?;
    Ok((live, access))
}

async fn one(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<SessionView>> {
    let (live, access) = live_for(&st, &u, id).await?;
    Ok(Json(live.view(access)))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RenameSession {
    pub title: String,
}

async fn rename(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Json(req): Json<RenameSession>,
) -> ApiResult<Json<SessionView>> {
    let (live, access) = live_for(&st, &u, id).await?;
    if access != Access::Owner {
        return Err(ApiError::forbidden("only the owner can rename the session")
            .with_code("session_owner_only"));
    }
    let title = req.title.trim().to_string();
    if title.is_empty() {
        return Err(ApiError::bad_request("the title cannot be empty").with_code("title_required"));
    }
    live.set_title(title.clone());
    st.store.rename_session(id, &title).await?;
    Ok(Json(live.view(access)))
}

async fn close(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    let (live, access) = live_for(&st, &u, id).await?;
    if access != Access::Owner {
        return Err(ApiError::forbidden("only the owner can close the session")
            .with_code("session_owner_only"));
    }
    st.sessions.close(&live, u.id()).await?;
    Ok(Json(json!({"ok": true})))
}

async fn recording(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Response> {
    let info = st.store.session(id).await?;
    if info.owner_id != u.id() {
        return Err(ApiError::not_found(format!("session {id}")));
    }
    let path = st.sessions.recording_path(u.id(), id);
    let file = tokio::fs::File::open(&path).await.map_err(|_| {
        ApiError::not_found("this session has no recording").with_code("recording_not_found")
    })?;
    let stream = tokio_util::io::ReaderStream::new(file);
    Ok((
        [
            (header::CONTENT_TYPE, "application/x-asciicast".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{id}.cast\""),
            ),
        ],
        Body::from_stream(stream),
    )
        .into_response())
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateShare {
    /// Invite a user of this server by email...
    #[serde(default)]
    pub email: Option<String>,
    /// ...or every member of a team you belong to...
    #[serde(default)]
    pub team_id: Option<Uuid>,
    /// ...or create a link (anyone who has it can join without an account).
    #[serde(default)]
    pub link: bool,
    #[serde(default = "default_permission")]
    pub permission: SharePermission,
    /// Expiry in minutes (no expiry if not given).
    #[serde(default)]
    pub expires_in_minutes: Option<i64>,
}

fn default_permission() -> SharePermission {
    SharePermission::View
}

async fn create_share(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Json(req): Json<CreateShare>,
) -> ApiResult<Json<Value>> {
    let (live, access) = live_for(&st, &u, id).await?;
    if access != Access::Owner {
        return Err(ApiError::forbidden("only the owner can share the session")
            .with_code("session_owner_only"));
    }
    let expires_at = req
        .expires_in_minutes
        .filter(|m| *m > 0)
        .map(|m| now_ms() + m * 60_000);
    let (target, invitee, team) = match (
        req.email.as_deref().filter(|e| !e.trim().is_empty()),
        req.team_id,
        req.link,
    ) {
        (Some(email), None, false) => {
            let invitee = st.store.user_by_email(email).await?.ok_or_else(|| {
                ApiError::not_found("there is no user with that email on this server")
                    .with_code("user_not_found")
            })?;
            if invitee.id == u.id() {
                return Err(ApiError::bad_request("you cannot invite yourself")
                    .with_code("cannot_invite_self"));
            }
            (ShareTarget::User(invitee.id), Some(invitee), None)
        }
        (None, Some(team_id), false) => {
            if st.store.team_role(team_id, u.id()).await?.is_none() {
                return Err(ApiError::forbidden(
                    "you can only share with teams you are a member of",
                )
                .with_code("not_team_member"));
            }
            let team = st.store.team_for(team_id, u.id()).await?;
            (ShareTarget::Team(team_id), None, Some(team))
        }
        (None, None, true) => (ShareTarget::Link, None, None),
        _ => {
            return Err(ApiError::bad_request(
                "give `email`, `team_id` or `link: true` (only one)",
            ));
        }
    };
    let (share, token) = st
        .store
        .create_share(id, u.id(), target, req.permission, expires_at)
        .await?;
    st.store
        .audit(u.id(), &u.actor(), "session.share", Some(id.to_string()), json!({"share": share.id, "permission": req.permission.as_str(), "link": share.is_link, "invitee": invitee.as_ref().map(|i| &i.email), "team": team.as_ref().map(|t| t.id)}))
        .await?;
    let mut notify: Vec<Id> = invitee.iter().map(|i| i.id).collect();
    if let Some(team) = &team {
        notify.extend(st.store.team_member_ids(team.id).await?);
    }
    for user in notify.into_iter().filter(|m| *m != u.id()) {
        st.sessions.notify(
            user,
            SessionNotice::SessionShared {
                session: live.view(req.permission.into()),
                by: u.user.name.clone(),
                team: team.as_ref().map(|t| t.name.clone()),
            },
        );
    }
    // With the web app enabled, the link opens a page that explains how to join.
    let link = token.as_ref().map(|t| {
        if st.config.web.enabled {
            format!("{}/join/{t}", st.config.base_url())
        } else {
            format!("{}/api/v1/join/{t}", st.config.base_url())
        }
    });
    let app_link = token.as_ref().map(|t| {
        format!(
            "termoak://join?server={}&token={t}",
            url_encode(&st.config.base_url())
        )
    });
    Ok(Json(
        json!({"share": share, "token": token, "link": link, "app_link": app_link}),
    ))
}

fn url_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

async fn list_shares(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    let (_, access) = live_for(&st, &u, id).await?;
    if access != Access::Owner {
        return Err(
            ApiError::forbidden("only the owner can see the invitations")
                .with_code("session_owner_only"),
        );
    }
    // With the invitee's email and name, or the team name.
    let mut out = Vec::new();
    for share in st.store.list_shares(id).await? {
        let mut v = json!(share);
        if let Some(user) = share.user_id
            && let Ok(user) = st.store.user(user).await
        {
            v["user_email"] = json!(user.email);
            v["user_name"] = json!(user.name);
        }
        if let Some(team) = share.team_id
            && let Ok(team) = st.store.team_for(team, u.id()).await
        {
            v["team_name"] = json!(team.name);
        }
        out.push(v);
    }
    Ok(Json(Value::Array(out)))
}

async fn revoke_share(
    State(st): State<AppState>,
    u: AuthUser,
    Path((id, share_id)): Path<(Id, Id)>,
) -> ApiResult<Json<Value>> {
    let (live, access) = live_for(&st, &u, id).await?;
    if access != Access::Owner {
        return Err(ApiError::forbidden("only the owner can revoke invitations")
            .with_code("session_owner_only"));
    }
    st.store.revoke_share(id, share_id).await?;
    live.revoke(share_id);
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "session.share_revoked",
            Some(id.to_string()),
            json!({"share": share_id}),
        )
        .await?;
    Ok(Json(json!({"ok": true})))
}

/// Information about a link invitation (no account required).
async fn join_info(
    State(st): State<AppState>,
    Path(token): Path<String>,
) -> ApiResult<Json<Value>> {
    let share = st.store.share_by_token(&token).await?.ok_or_else(|| {
        ApiError::not_found("the link is invalid or has expired").with_code("invalid_link")
    })?;
    let live = st.sessions.get(share.session_id).ok_or_else(|| {
        ApiError::not_found("the session is no longer active").with_code("session_ended")
    })?;
    let owner = st.store.user(live.owner).await?;
    Ok(Json(json!({
        "session": live.view(share.permission.into()),
        "owner": owner.name,
        "permission": share.permission,
        "ws_path": format!("/api/v1/sessions/{}/ws?share_token={token}", live.id),
    })))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct OpenRelay {
    #[serde(default)]
    pub title: String,
    #[serde(default = "default_cols")]
    pub cols: u16,
    #[serde(default = "default_rows")]
    pub rows: u16,
    #[serde(default)]
    pub host_id: Option<Uuid>,
}

/// Creates a relay session to share a local terminal.
async fn open_relay(
    State(st): State<AppState>,
    u: AuthUser,
    Json(req): Json<OpenRelay>,
) -> ApiResult<Json<Value>> {
    crate::account::check_new_session(&st, &u.user)?;
    let live = st
        .sessions
        .open_relay(u.id(), req.title, req.cols, req.rows, req.host_id)
        .await?;
    Ok(Json(json!({
        "session": live.view(Access::Owner),
        "host_ws_path": format!("/api/v1/sessions/{}/ws?role=host", live.id),
    })))
}

#[derive(Debug, Deserialize)]
struct WsQuery {
    #[serde(default)]
    share_token: Option<String>,
    #[serde(default)]
    role: Option<String>,
}

async fn ws(
    State(st): State<AppState>,
    MaybeUser(user): MaybeUser,
    Path(id): Path<Id>,
    Query(q): Query<WsQuery>,
    upgrade: WebSocketUpgrade,
) -> ApiResult<Response> {
    let live = st
        .sessions
        .get(id)
        .ok_or_else(|| ApiError::not_found(format!("active session {id}")))?;
    let (access, name, user_id, share_id) = match (&user, &q.share_token) {
        (Some(u), _) => (
            st.sessions.access_for_user(&live, u.id()).await?,
            u.user.name.clone(),
            Some(u.id()),
            st.store.share_for_user(id, u.id()).await?.map(|s| s.id),
        ),
        (None, Some(token)) => {
            let share = st
                .store
                .share_by_token(token)
                .await?
                .filter(|s| s.session_id == id)
                .ok_or_else(|| {
                    ApiError::unauthorized("invalid or expired link").with_code("invalid_link")
                })?;
            (
                Access::from(share.permission),
                "Guest".to_string(),
                None,
                Some(share.id),
            )
        }
        (None, None) => return Err(ApiError::unauthorized("missing access token")),
    };
    let share_id = if access == Access::Owner {
        None
    } else {
        share_id
    };
    let is_host = q.role.as_deref() == Some("host");
    if is_host && (access != Access::Owner || live.kind() != "relay") {
        return Err(
            ApiError::forbidden("only the owner of a relay session can be the host")
                .with_code("session_owner_only"),
        );
    }
    let viewer = Viewer {
        id: new_id(),
        name,
        user_id,
        access,
        role: if is_host {
            "host".into()
        } else {
            "viewer".into()
        },
        since: now_ms(),
        share_id,
    };
    if let Some(uid) = user_id {
        let _ = st
            .store
            .audit(
                live.owner,
                &format!("user:{uid}"),
                "session.attach",
                Some(id.to_string()),
                json!({"access": access, "role": viewer.role}),
            )
            .await;
    }
    Ok(upgrade
        .max_message_size(1 << 20)
        .on_upgrade(move |socket| async move {
            if is_host {
                host_loop(st, live, socket, viewer).await
            } else {
                viewer_loop(st, live, socket, viewer).await
            }
        }))
}

fn text(v: Value) -> Message {
    Message::Text(v.to_string().into())
}

/// Pending output, batched: whatever has already arrived (up to 64 KiB) goes
/// in a single message. A full-screen program (htop, vim...) paints each
/// screen in many small chunks; sending them one by one multiplies the
/// messages and makes the client fall behind.
async fn recv_output(
    rx: &mut Option<broadcast::Receiver<Bytes>>,
) -> Result<Bytes, broadcast::error::RecvError> {
    const MAX_BATCH: usize = 64 * 1024;
    let Some(r) = rx else {
        return std::future::pending().await;
    };
    let first = r.recv().await?;
    // An empty chunk signals that the history was replaced: treat it as if
    // the client were slow (resend all of it).
    if first.is_empty() {
        return Err(broadcast::error::RecvError::Lagged(0));
    }
    let mut batch: Option<bytes::BytesMut> = None;
    loop {
        let len = batch.as_ref().map_or(first.len(), |b| b.len());
        if len >= MAX_BATCH {
            break;
        }
        match r.try_recv() {
            Ok(more) if more.is_empty() => return Err(broadcast::error::RecvError::Lagged(0)),
            Ok(more) => batch
                .get_or_insert_with(|| bytes::BytesMut::from(&first[..]))
                .extend_from_slice(&more),
            Err(broadcast::error::TryRecvError::Lagged(n)) => {
                return Err(broadcast::error::RecvError::Lagged(n));
            }
            Err(_) => break,
        }
    }
    Ok(batch.map_or(first, |b| b.freeze()))
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMsg {
    Resize {
        cols: u16,
        rows: u16,
    },
    PromptAnswer {
        prompt_id: Id,
        #[serde(default)]
        accept: Option<bool>,
        #[serde(default)]
        answers: Option<Vec<String>>,
    },
    Ping,
    CloseSession,
    /// Relay host only: the local terminal ended.
    HostClosed,
    /// Input as text (alternative to binary frames).
    Input {
        data: String,
    },
}

async fn viewer_loop(
    st: AppState,
    live: std::sync::Arc<LiveSession>,
    mut socket: WebSocket,
    viewer: Viewer,
) {
    let access = viewer.access;
    live.add_viewer(viewer.clone());
    let hello = json!({"type": "hello", "session": live.view(access), "you": viewer});
    if socket.send(text(hello)).await.is_err() {
        live.remove_viewer(viewer.id);
        return;
    }
    if access == Access::Owner {
        for p in live.pending_prompts() {
            let _ = socket
                .send(text(
                    serde_json::to_value(Signal::Prompt(p)).unwrap_or_default(),
                ))
                .await;
        }
    }
    let mut signals = live.signals();
    let mut state_rx = live.watch_state();
    let mut out: Option<broadcast::Receiver<Bytes>> = None;
    if let Some(hub) = live.hub() {
        let (snapshot, rx) = hub.attach();
        if socket.send(Message::Binary(snapshot)).await.is_err() {
            live.remove_viewer(viewer.id);
            return;
        }
        out = Some(rx);
    }
    loop {
        tokio::select! {
            msg = socket.recv() => match msg {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                Some(Ok(Message::Binary(data))) => {
                    if access.can_write() {
                        let _ = live.write(data).await;
                    }
                }
                Some(Ok(Message::Text(t))) => {
                    match serde_json::from_str::<ClientMsg>(t.as_str()) {
                        Ok(ClientMsg::Resize { cols, rows }) if access.can_write() => live.resize(cols, rows).await,
                        Ok(ClientMsg::Input { data }) if access.can_write() => { let _ = live.write(Bytes::from(data)).await; }
                        Ok(ClientMsg::PromptAnswer { prompt_id, accept, answers }) if access == Access::Owner => {
                            live.answer_prompt(prompt_id, PromptAnswer { accept, answers });
                        }
                        Ok(ClientMsg::Ping) => { let _ = socket.send(text(json!({"type": "pong", "ts": now_ms()}))).await; }
                        Ok(ClientMsg::CloseSession) if access == Access::Owner => {
                            let _ = st.sessions.close(&live, viewer.user_id.unwrap_or(live.owner)).await;
                        }
                        Ok(_) => { let _ = socket.send(text(json!({"type": "error", "message": "you do not have permission for that action"}))).await; }
                        Err(e) => { let _ = socket.send(text(json!({"type": "error", "message": format!("invalid message: {e}")}))).await; }
                    }
                }
                Some(Ok(_)) => {}
            },
            data = recv_output(&mut out) => match data {
                Ok(bytes) => {
                    if socket.send(Message::Binary(bytes)).await.is_err() { break; }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    // The client is slow: resend the full history.
                    if let Some(hub) = live.hub() {
                        let (snapshot, rx) = hub.attach();
                        let _ = socket.send(text(json!({"type": "resync"}))).await;
                        if socket.send(Message::Binary(snapshot)).await.is_err() { break; }
                        out = Some(rx);
                    }
                }
                Err(broadcast::error::RecvError::Closed) => out = None,
            },
            sig = signals.recv() => match sig {
                Ok(Signal::Prompt(p)) => {
                    if access == Access::Owner
                        && socket.send(text(serde_json::to_value(Signal::Prompt(p)).unwrap_or_default())).await.is_err()
                    {
                        break;
                    }
                }
                Ok(Signal::PromptDone { .. }) if access != Access::Owner => {}
                Ok(Signal::Revoked { share_id }) => {
                    if viewer.share_id == Some(share_id) {
                        let _ = socket.send(text(json!({"type": "error", "message": "your access to this session has been revoked"}))).await;
                        break;
                    }
                }
                Ok(Signal::Kicked { user_id, share_id }) => {
                    if viewer.share_id == Some(share_id) && viewer.user_id == Some(user_id) {
                        let _ = socket.send(text(json!({"type": "error", "message": "you no longer have access to this session"}))).await;
                        break;
                    }
                }
                Ok(other) => {
                    if socket.send(text(serde_json::to_value(&other).unwrap_or_default())).await.is_err() { break; }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            },
            changed = state_rx.changed() => {
                if changed.is_err() { break; }
                let state = state_rx.borrow().clone();
                if out.is_none() && matches!(state, SessionState::Running)
                    && let Some(hub) = live.hub()
                {
                    let (snapshot, rx) = hub.attach();
                    if socket.send(Message::Binary(snapshot)).await.is_err() { break; }
                    out = Some(rx);
                }
                if state.is_closed() {
                    // Let the last output through and close.
                    let _ = socket.send(text(json!({"type": "status", "status": state}))).await;
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    while let Some(Ok(bytes)) = out.as_mut().map(|r| r.try_recv()) {
                        let _ = socket.send(Message::Binary(bytes)).await;
                    }
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
            }
        }
    }
    live.remove_viewer(viewer.id);
}

async fn host_loop(
    st: AppState,
    live: std::sync::Arc<LiveSession>,
    mut socket: WebSocket,
    viewer: Viewer,
) {
    let Some(hub) = live.hub() else { return };
    let Some(mut input) = st.sessions.relay_input(&live) else {
        return;
    };
    live.add_viewer(viewer.clone());
    live.set_host_online(true);
    let _ = socket
        .send(text(
            json!({"type": "hello", "session": live.view(Access::Owner), "you": viewer}),
        ))
        .await;
    let mut state_rx = live.watch_state();
    let mut signals = live.signals();
    let mut host_closed = false;
    loop {
        tokio::select! {
            msg = socket.recv() => match msg {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                Some(Ok(Message::Binary(data))) => {
                    live.touch();
                    hub.push(data);
                }
                Some(Ok(Message::Text(t))) => match serde_json::from_str::<ClientMsg>(t.as_str()) {
                    Ok(ClientMsg::Resize { cols, rows }) => live.resize(cols, rows).await,
                    Ok(ClientMsg::HostClosed) | Ok(ClientMsg::CloseSession) => {
                        host_closed = true;
                        let _ = st.sessions.close(&live, live.owner).await;
                        break;
                    }
                    Ok(ClientMsg::Ping) => { let _ = socket.send(text(json!({"type": "pong", "ts": now_ms()}))).await; }
                    _ => {}
                },
                Some(Ok(_)) => {}
            },
            data = input.recv() => match data {
                Ok(bytes) => {
                    if socket.send(Message::Binary(bytes)).await.is_err() { break; }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            },
            sig = signals.recv() => {
                if let Ok(Signal::Presence { viewers }) = sig {
                    let _ = socket.send(text(json!({"type": "presence", "viewers": viewers}))).await;
                }
            },
            changed = state_rx.changed() => {
                if changed.is_err() || state_rx.borrow().is_closed() { break; }
            }
        }
    }
    live.remove_viewer(viewer.id);
    if !host_closed && !live.state().is_closed() {
        live.set_host_online(false);
        st.sessions.spawn_relay_grace(live.clone());
    }
}

/// Helper so routes in other modules can resolve host labels.
pub async fn host_label(st: &AppState, owner: Id, host_id: Option<Id>) -> Option<String> {
    let id = host_id?;
    st.store
        .get::<Host>(owner, id)
        .await
        .ok()
        .map(|h| h.data.label)
}

#[cfg(test)]
mod batch_tests {
    use super::*;

    #[tokio::test]
    async fn pending_output_goes_in_one_message() {
        let (tx, rx) = broadcast::channel::<Bytes>(16);
        let mut rx = Some(rx);
        for part in ["\x1b[H", "CPU ", "[||| 12%]"] {
            tx.send(Bytes::from_static(part.as_bytes())).unwrap();
        }
        let got = recv_output(&mut rx).await.unwrap();
        assert_eq!(&got[..], b"\x1b[HCPU [||| 12%]");
        // The next one waits again for something to arrive.
        tx.send(Bytes::from_static(b"mem")).unwrap();
        assert_eq!(&recv_output(&mut rx).await.unwrap()[..], b"mem");
    }

    #[tokio::test]
    async fn lagging_reader_still_gets_resync() {
        let (tx, rx) = broadcast::channel::<Bytes>(2);
        let mut rx = Some(rx);
        for _ in 0..5 {
            tx.send(Bytes::from_static(b"x")).unwrap();
        }
        assert!(matches!(
            recv_output(&mut rx).await,
            Err(broadcast::error::RecvError::Lagged(_))
        ));
    }
}
