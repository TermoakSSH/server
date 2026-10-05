//! Server terminal sessions: REST, WebSocket, sharing and relay.
//!
//! WebSocket protocol (`/api/v1/sessions/{id}/ws`), see `docs/WEBSOCKET-PROTOCOL.md`:
//! - Server → client: **binary** frames with the terminal output (the first
//!   one is the full history) and **JSON text** control frames (`hello`,
//!   `status`, `participants`, `control`, `resize`, `prompt`, `resync`...).
//! - Client → server: **binary** frames with the keystrokes (they reach the
//!   terminal only from the owner and from whoever has the keyboard) and
//!   JSON (`resize`, `control_request`, `prompt_answer`, `ping`...).
//!
//! Participants, the keyboard and the waiting room live in [`crate::room`].

use axum::body::Body;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

use termoak_core::model::{Host, SessionInfo, SessionShare, SharePermission};
use termoak_core::store::sessions::{ShareOptions, ShareTarget, ShareUpdate};
use termoak_core::time::now_ms;
use termoak_core::{Id, new_id};
use tokio::sync::broadcast;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::{AuthUser, MaybeUser};
use crate::error::{ApiError, ApiResult};
use crate::room::{
    EndCode, Joiner, MAX_CONTROL_MINUTES, ParticipantKind, Request, better, clean_guest_key,
};
use crate::sessions::{
    Access, EndTarget, LiveSession, PromptAnswer, SessionNotice, SessionState, SessionView, Signal,
    Viewer, actor_of, author_of, grant_of,
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
            "/api/v1/sessions/{id}/recording/authors",
            get(recording_authors),
        )
        .route(
            "/api/v1/sessions/{id}/shares",
            get(list_shares)
                .post(create_share)
                .delete(stop_sharing_route),
        )
        .route(
            "/api/v1/sessions/{id}/shares/{share_id}",
            delete(revoke_share).patch(update_share),
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

/// Who typed in a recording: the author marks (`a` events) of the `.cast`
/// file, in order. Each one applies to the input that follows it.
#[derive(Debug, Serialize, ToSchema)]
pub struct RecordingAuthors {
    /// When the recording started (ms; from the `.cast` header).
    pub started_at: Option<i64>,
    pub authors: Vec<RecordingAuthor>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RecordingAuthor {
    /// Seconds since the start of the recording.
    pub time: f64,
    /// Participant of the shared session (absent for the AI).
    pub participant: Option<Uuid>,
    pub name: String,
    /// `owner`, `user`, `guest` or `ai`.
    pub kind: String,
}

async fn recording_authors(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<RecordingAuthors>> {
    use tokio::io::AsyncBufReadExt;
    let info = st.store.session(id).await?;
    if info.owner_id != u.id() {
        return Err(ApiError::not_found(format!("session {id}")));
    }
    let path = st.sessions.recording_path(u.id(), id);
    let file = tokio::fs::File::open(&path).await.map_err(|_| {
        ApiError::not_found("this session has no recording").with_code("recording_not_found")
    })?;
    let mut lines = tokio::io::BufReader::new(file).lines();
    let started_at = match lines.next_line().await.ok().flatten() {
        Some(header) => serde_json::from_str::<Value>(&header)
            .ok()
            .and_then(|h| h["timestamp"].as_i64())
            .map(|t| t * 1000),
        None => None,
    };
    let mut authors = Vec::new();
    // A recording still being written may end in half a line: it stops there.
    while let Ok(Some(line)) = lines.next_line().await {
        if let Some(mark) = termoak_ssh::recording::parse_author_line(&line) {
            authors.push(RecordingAuthor {
                time: mark.time,
                participant: mark.author.participant,
                name: mark.author.name,
                kind: mark.author.kind,
            });
        }
    }
    Ok(Json(RecordingAuthors {
        started_at,
        authors,
    }))
}

/// A timed grant lasts 1-240 minutes.
fn check_control_minutes(minutes: Option<u32>) -> ApiResult<()> {
    match minutes {
        Some(m) if !(1..=MAX_CONTROL_MINUTES).contains(&m) => Err(ApiError::bad_request(
            "the keyboard can be handed over for 1 to 240 minutes",
        )
        .with_code("invalid_control_minutes")),
        _ => Ok(()),
    }
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
    /// The most you can hand over: `view` (only watch) or `control` (can
    /// ask for the keyboard). Everyone joins read-only.
    #[serde(default = "default_permission")]
    pub permission: SharePermission,
    /// Expiry in minutes (no expiry if not given).
    #[serde(default)]
    pub expires_in_minutes: Option<i64>,
    /// Whoever joins waits until you let them in. Default: yes for links,
    /// no for users and teams.
    #[serde(default)]
    pub require_approval: Option<bool>,
    /// Requests for the keyboard are granted without asking you.
    #[serde(default)]
    pub auto_grant: bool,
    /// With `auto_grant`: each automatic grant lasts at most this many
    /// minutes (1-240); then the keyboard goes back to you.
    #[serde(default)]
    pub control_minutes: Option<u32>,
}

fn default_permission() -> SharePermission {
    SharePermission::View
}

fn owner_only(access: Access, what: &str) -> ApiResult<()> {
    if access == Access::Owner {
        Ok(())
    } else {
        Err(ApiError::forbidden(format!("only the owner can {what}"))
            .with_code("session_owner_only"))
    }
}

fn session_ended() -> ApiError {
    ApiError::not_found("the session is no longer active").with_code("session_ended")
}

async fn create_share(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Json(req): Json<CreateShare>,
) -> ApiResult<Json<Value>> {
    let (live, access) = live_for(&st, &u, id).await?;
    owner_only(access, "share the session")?;
    if live.state().is_closed() {
        return Err(session_ended());
    }
    check_control_minutes(req.control_minutes)?;
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
    let opts = ShareOptions {
        require_approval: req.require_approval.unwrap_or(req.link),
        auto_grant: req.auto_grant,
        control_minutes: req.control_minutes,
    };
    let (share, token) = st
        .store
        .create_share(id, u.id(), target, req.permission, expires_at, opts)
        .await?;
    st.store
        .audit(u.id(), &u.actor(), "session.share", Some(id.to_string()), json!({"share": share.id, "permission": req.permission.as_str(), "link": share.is_link, "invitee": invitee.as_ref().map(|i| &i.email), "team": team.as_ref().map(|t| t.id), "require_approval": opts.require_approval, "auto_grant": opts.auto_grant, "control_minutes": opts.control_minutes, "expires_at": expires_at}))
        .await?;
    // Someone already inside may have a better share now.
    st.sessions.reevaluate(&live, EndCode::Revoked, None).await;
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

/// A share with the invitee's email and name, or the team name, and who is
/// using it now.
async fn share_json(st: &AppState, owner: Id, live: &LiveSession, share: &SessionShare) -> Value {
    let mut v = json!(share);
    if let Some(user) = share.user_id
        && let Ok(user) = st.store.user(user).await
    {
        v["user_email"] = json!(user.email);
        v["user_name"] = json!(user.name);
    }
    if let Some(team) = share.team_id
        && let Ok(team) = st.store.team_for(team, owner).await
    {
        v["team_name"] = json!(team.name);
    }
    v["active"] = json!(share.is_valid(now_ms()));
    v["participants"] = json!(live.room().with_share(share.id).len());
    v
}

async fn list_shares(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    let (live, access) = live_for(&st, &u, id).await?;
    owner_only(access, "see the invitations")?;
    let mut out = Vec::new();
    for share in st.store.list_shares(id).await? {
        out.push(share_json(&st, u.id(), &live, &share).await);
    }
    Ok(Json(Value::Array(out)))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateShare {
    /// New permission. Going down to `view` takes the keyboard away.
    #[serde(default)]
    pub permission: Option<SharePermission>,
    /// New expiry, in minutes from now.
    #[serde(default)]
    pub expires_in_minutes: Option<i64>,
    /// New expiry, as a timestamp in ms (a past one sends away whoever
    /// uses it).
    #[serde(default)]
    pub expires_at: Option<i64>,
    /// Remove the expiry.
    #[serde(default)]
    pub no_expiry: bool,
    #[serde(default)]
    pub require_approval: Option<bool>,
    #[serde(default)]
    pub auto_grant: Option<bool>,
    /// New time limit of automatic grants (1-240 minutes).
    #[serde(default)]
    pub control_minutes: Option<u32>,
    /// Remove the time limit of automatic grants.
    #[serde(default)]
    pub no_control_limit: bool,
}

/// Changes a share live: whoever uses it gets the new permission at once.
async fn update_share(
    State(st): State<AppState>,
    u: AuthUser,
    Path((id, share_id)): Path<(Id, Id)>,
    Json(req): Json<UpdateShare>,
) -> ApiResult<Json<Value>> {
    let (live, access) = live_for(&st, &u, id).await?;
    owner_only(access, "change invitations")?;
    let current = st
        .store
        .session_share(id, share_id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("share {share_id}")))?;
    if current.revoked {
        return Err(ApiError::conflict("the invitation was revoked").with_code("share_revoked"));
    }
    check_control_minutes(req.control_minutes)?;
    let expires_at = if req.no_expiry {
        Some(None)
    } else if let Some(at) = req.expires_at {
        Some(Some(at))
    } else {
        req.expires_in_minutes
            .filter(|m| *m > 0)
            .map(|m| Some(now_ms() + m * 60_000))
    };
    let update = ShareUpdate {
        permission: req.permission,
        expires_at,
        require_approval: req.require_approval,
        auto_grant: req.auto_grant,
        control_minutes: if req.no_control_limit {
            Some(None)
        } else {
            req.control_minutes.map(Some)
        },
    };
    let share = st.store.update_share(id, share_id, update).await?;
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "session.share_changed",
            Some(id.to_string()),
            json!({"share": share_id, "permission": share.permission.as_str(), "expires_at": share.expires_at, "require_approval": share.require_approval, "auto_grant": share.auto_grant, "control_minutes": share.control_minutes}),
        )
        .await?;
    st.sessions.reevaluate(&live, EndCode::Revoked, None).await;
    Ok(Json(share_json(&st, u.id(), &live, &share).await))
}

async fn revoke_share(
    State(st): State<AppState>,
    u: AuthUser,
    Path((id, share_id)): Path<(Id, Id)>,
) -> ApiResult<Json<Value>> {
    let (live, access) = live_for(&st, &u, id).await?;
    owner_only(access, "revoke invitations")?;
    st.store.revoke_share(id, share_id).await?;
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "session.share_revoked",
            Some(id.to_string()),
            json!({"share": share_id}),
        )
        .await?;
    // Whoever has another valid share stays (with that one).
    let using = live.room().with_share(share_id);
    st.sessions
        .reevaluate(&live, EndCode::Revoked, Some(&using))
        .await;
    Ok(Json(json!({"ok": true})))
}

/// Stops sharing: revokes every share and sends everyone but the owner away.
async fn stop_sharing_route(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    let (live, access) = live_for(&st, &u, id).await?;
    owner_only(access, "stop sharing the session")?;
    let revoked = stop_sharing(&st, &live, &u.actor()).await?;
    Ok(Json(json!({"ok": true, "revoked": revoked})))
}

async fn stop_sharing(st: &AppState, live: &LiveSession, actor: &str) -> ApiResult<usize> {
    let revoked = st.store.revoke_all_shares(live.id).await?;
    let gone = {
        let mut room = live.room();
        let guests = room.guests();
        guests
            .iter()
            .filter_map(|g| room.kick(g.participant))
            .count()
    };
    live.end(EndTarget::Guests, EndCode::Revoked);
    live.signal(Signal::Control);
    live.signal(Signal::Room);
    st.sessions
        .audit(
            live,
            actor,
            "session.sharing_stopped",
            json!({"shares": revoked.len(), "participants": gone}),
        )
        .await;
    Ok(revoked.len())
}

/// Information about a link invitation (no account required). It says
/// nothing about who is inside, only how many.
async fn join_info(
    State(st): State<AppState>,
    Path(token): Path<String>,
) -> ApiResult<Json<Value>> {
    let share = st.store.share_by_token(&token).await?.ok_or_else(|| {
        ApiError::not_found("the link is invalid or has expired").with_code("invalid_link")
    })?;
    let live = st
        .sessions
        .get(share.session_id)
        .filter(|l| !l.state().is_closed())
        .ok_or_else(session_ended)?;
    let owner = st.store.user(live.owner).await?;
    let (cols, rows) = live.size();
    Ok(Json(json!({
        "session": {
            "id": live.id,
            "title": live.title(),
            "kind": live.kind(),
            "state": live.state(),
            "created_at": live.created_at,
            "cols": cols,
            "rows": rows,
            "access": Access::from(share.permission),
            "participants": live.room().present_count(),
        },
        "owner": owner.name,
        "permission": share.permission,
        "require_approval": share.require_approval,
        "expires_at": share.expires_at,
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
    /// Protocol version of the client (2: participants and control; older
    /// clients do not send it).
    #[serde(default)]
    proto: Option<u32>,
    /// Link guests: display name.
    #[serde(default)]
    name: Option<String>,
    /// Link guests: key kept between reconnects (8-64 letters, digits, `-`, `_`).
    #[serde(default)]
    guest: Option<String>,
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
    let legacy = q.proto.unwrap_or(1) < 2;
    let is_host = q.role.as_deref() == Some("host");
    let invalid_link =
        || ApiError::unauthorized("invalid or expired link").with_code("invalid_link");
    // A link works with or without an account.
    let link = match q.share_token.as_deref() {
        Some(t) => st
            .store
            .share_by_token(t)
            .await?
            .filter(|s| s.session_id == id),
        None => None,
    };
    let joiner = match &user {
        Some(u) if u.id() == live.owner => Joiner {
            kind: ParticipantKind::Owner,
            name: u.user.name.clone(),
            user_id: Some(u.id()),
            grant: None,
            guest_key: None,
            legacy,
            host: is_host,
        },
        Some(u) => {
            let own = st
                .store
                .share_for_user(id, u.id())
                .await?
                .map(|s| grant_of(&s));
            let grant = match (own, link.as_ref().map(grant_of)) {
                (Some(a), Some(b)) => Some(if better(&b, &a) { b } else { a }),
                (a, b) => a.or(b),
            };
            let Some(grant) = grant else {
                return Err(if q.share_token.is_some() {
                    invalid_link()
                } else {
                    ApiError::not_found(format!("session {id}"))
                });
            };
            Joiner {
                kind: ParticipantKind::User,
                name: u.user.name.clone(),
                user_id: Some(u.id()),
                grant: Some(grant),
                guest_key: None,
                legacy,
                host: false,
            }
        }
        None => match &link {
            Some(share) => Joiner {
                kind: ParticipantKind::Guest,
                name: q.name.clone().unwrap_or_default(),
                user_id: None,
                grant: Some(grant_of(share)),
                guest_key: q.guest.as_deref().and_then(clean_guest_key),
                legacy,
                host: false,
            },
            None if q.share_token.is_some() => return Err(invalid_link()),
            None => return Err(ApiError::unauthorized("missing access token")),
        },
    };
    if is_host && (joiner.kind != ParticipantKind::Owner || live.kind() != "relay") {
        return Err(
            ApiError::forbidden("only the owner of a relay session can be the host")
                .with_code("session_owner_only"),
        );
    }
    Ok(upgrade
        .max_message_size(1 << 20)
        .on_upgrade(move |socket| async move {
            if is_host {
                host_loop(st, live, socket, joiner).await
            } else {
                viewer_loop(st, live, socket, joiner).await
            }
        }))
}

fn text(v: Value) -> Message {
    Message::Text(v.to_string().into())
}

/// `error` message with a stable code.
fn error_msg(code: &str, message: &str) -> Message {
    text(json!({"type": "error", "code": code, "message": message}))
}

/// Sends the reason and closes (close code `4000 + n`, reason = the code).
async fn send_end(socket: &mut WebSocket, code: EndCode) {
    let _ = socket.send(error_msg(code.as_str(), code.message())).await;
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code: code.close_code(),
            reason: code.as_str().into(),
        })))
        .await;
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
    /// Link guests: change the display name.
    SetName {
        name: String,
    },
    /// Ask for the keyboard (`control` shares).
    ControlRequest,
    /// Give the keyboard back (or withdraw a request).
    ControlRelease,
    // --- Owner only ---
    ControlGrant {
        participant: Id,
        /// Timed grant (1-240 minutes): the keyboard comes back by itself.
        #[serde(default)]
        minutes: Option<u32>,
    },
    ControlDeny {
        participant: Id,
    },
    ControlTake,
    JoinAllow {
        participant: Id,
    },
    JoinDeny {
        participant: Id,
    },
    Kick {
        participant: Id,
        #[serde(default)]
        revoke_share: bool,
    },
    StopSharing,
}

/// Who a socket is.
#[derive(Debug, Clone, Copy)]
struct Ctx {
    /// Socket.
    sid: Id,
    /// Participant.
    me: Id,
    owner: bool,
    legacy: bool,
    host: bool,
}

/// How long someone who drops has to come back before they "left" (and
/// lose the keyboard). Reconnects inside it are not new joins.
const LEAVE_GRACE: Duration = Duration::from_secs(10);

/// What a socket does with a signal.
enum Out {
    Send(Value),
    End(EndCode),
    Skip,
}

fn participant_json(live: &LiveSession, pid: Id) -> Value {
    json!(live.room().view_of(pid, true))
}

fn control_json(live: &LiveSession, ctx: &Ctx) -> Value {
    let room = live.room();
    let mut v = json!({
        "type": "control",
        "driver": room.driver(),
        "driver_name": room.name_of_driver(),
        "can_write": room.can_write(ctx.me),
    });
    if let Some(until) = room.driver_until() {
        v["until"] = json!(until);
    }
    v
}

fn render(live: &LiveSession, ctx: &Ctx, sig: Signal) -> Out {
    match sig {
        Signal::Status { status } if !status.is_closed() && !ctx.host => {
            Out::Send(json!({"type": "status", "status": status}))
        }
        Signal::Status { .. } => Out::Skip,
        Signal::Prompt(p) if ctx.owner && !ctx.host => {
            let mut v = serde_json::to_value(&p).unwrap_or_default();
            v["type"] = json!("prompt");
            Out::Send(v)
        }
        Signal::PromptDone { prompt_id } if ctx.owner && !ctx.host => {
            Out::Send(json!({"type": "prompt_done", "prompt_id": prompt_id}))
        }
        Signal::Prompt(_) | Signal::PromptDone { .. } => Out::Skip,
        Signal::Resize { from, .. } if from == Some(ctx.sid) => Out::Skip,
        Signal::Resize { cols, rows, .. } => {
            Out::Send(json!({"type": "resize", "cols": cols, "rows": rows}))
        }
        Signal::ResizeRequest { cols, rows, by } if ctx.host => {
            Out::Send(json!({"type": "resize", "cols": cols, "rows": rows, "by": by}))
        }
        Signal::ResizeRequest { .. } => Out::Skip,
        Signal::Title { title } => Out::Send(json!({"type": "title", "title": title})),
        Signal::Room if ctx.legacy => {
            let viewers: Vec<Viewer> = if ctx.owner {
                live.viewers()
            } else {
                live.viewers().into_iter().map(Viewer::public).collect()
            };
            Out::Send(json!({"type": "presence", "viewers": viewers}))
        }
        Signal::Room => {
            let room = live.room();
            Out::Send(json!({
                "type": "participants",
                "participants": room.participants(ctx.owner, Some(ctx.me)),
                "driver": room.driver(),
            }))
        }
        Signal::Control => Out::Send(control_json(live, ctx)),
        Signal::ControlExpired { participant } if participant == ctx.me || ctx.owner => {
            Out::Send(json!({"type": "control_expired", "participant": participant}))
        }
        Signal::ControlExpired { .. } => Out::Skip,
        Signal::JoinRequest { participant } if ctx.owner => Out::Send(
            json!({"type": "join_request", "participant": participant_json(live, participant)}),
        ),
        Signal::ControlRequest { participant } if ctx.owner => Out::Send(
            json!({"type": "control_request", "participant": participant_json(live, participant)}),
        ),
        Signal::JoinRequest { .. } | Signal::ControlRequest { .. } => Out::Skip,
        Signal::ControlDenied { participant } if participant == ctx.me => {
            Out::Send(json!({"type": "control_denied"}))
        }
        Signal::ControlDenied { .. } | Signal::Admitted { .. } => Out::Skip,
        Signal::End { target, code } => match target {
            EndTarget::Participant(p) if p == ctx.me => Out::End(code),
            EndTarget::Guests if !ctx.owner => Out::End(code),
            _ => Out::Skip,
        },
    }
}

/// Tells a participant user that they got or lost the keyboard (events
/// WebSocket).
fn notify_control(live: &LiveSession, pid: Option<Id>, granted: bool) {
    let Some(user) = pid
        .and_then(|p| live.room().info(p))
        .and_then(|i| i.user_id)
    else {
        return;
    };
    live.notify(
        user,
        if granted {
            SessionNotice::ControlGranted {
                session_id: live.id,
            }
        } else {
            SessionNotice::ControlRevoked {
                session_id: live.id,
            }
        },
    );
}

fn actor_for(live: &LiveSession, pid: Id) -> String {
    live.room()
        .info(pid)
        .map(|i| actor_of(&i))
        .unwrap_or_else(|| format!("guest:{pid}"))
}

/// A participant asks for the keyboard (an older client: by typing).
async fn ask_control(st: &AppState, live: &LiveSession, ctx: &Ctx) -> Request {
    let r = live.room().request_control(ctx.me, ctx.legacy);
    match &r {
        Request::Granted { previous } => {
            live.signal(Signal::Control);
            live.signal(Signal::Room);
            notify_control(live, *previous, false);
            notify_control(live, Some(ctx.me), true);
            let name = live.room().info(ctx.me).map(|i| i.name);
            st.sessions
                .audit(
                    live,
                    &actor_for(live, ctx.me),
                    "session.control_granted",
                    json!({"participant": ctx.me, "name": name, "automatic": true, "until": live.room().driver_until()}),
                )
                .await;
        }
        Request::Asked { new: true } => {
            live.signal(Signal::ControlRequest {
                participant: ctx.me,
            });
            live.signal(Signal::Room);
            let view = live.room().view_of(ctx.me, true);
            if let Some(participant) = view {
                st.sessions
                    .audit(
                        live,
                        &actor_for(live, ctx.me),
                        "session.control_requested",
                        json!({"participant": ctx.me, "name": participant.name}),
                    )
                    .await;
                live.notify(
                    live.owner,
                    SessionNotice::ControlRequest {
                        session_id: live.id,
                        title: live.title(),
                        participant,
                    },
                );
            }
        }
        _ => {}
    }
    r
}

/// Keyboard input from a socket: it reaches the terminal only from the
/// owner and the driver. Anything else is dropped without an error.
async fn input(st: &AppState, live: &LiveSession, ctx: &Ctx, data: Bytes) {
    let can = live.room().can_write(ctx.me);
    if can || (ctx.legacy && matches!(ask_control(st, live, ctx).await, Request::Granted { .. })) {
        let who = live.room().info(ctx.me);
        if let Some(who) = who {
            let _ = live.write_by(data, author_of(&who)).await;
        }
    }
}

/// Messages every socket can send about participants and the keyboard.
/// `Err((code, message))` for an error message (the socket stays open).
async fn room_msg(
    st: &AppState,
    live: &LiveSession,
    ctx: &Ctx,
    msg: ClientMsg,
) -> Result<(), (&'static str, String)> {
    let forbidden = || ("forbidden", "only the owner can do that".to_string());
    let owner_actor = format!("user:{}", live.owner);
    match msg {
        ClientMsg::SetName { name } => {
            let changed = live.room().set_name(ctx.me, &name);
            if changed {
                live.signal(Signal::Room);
            }
        }
        ClientMsg::ControlRequest => {
            if ask_control(st, live, ctx).await == Request::Forbidden {
                return Err((
                    "forbidden",
                    "your invitation does not allow taking the keyboard".into(),
                ));
            }
        }
        ClientMsg::ControlRelease => {
            let was_driver = live.room().driver() == Some(ctx.me);
            let changed = live.room().release_control(ctx.me);
            if changed {
                if was_driver {
                    live.signal(Signal::Control);
                    notify_control(live, Some(ctx.me), false);
                    st.sessions
                        .audit(
                            live,
                            &actor_for(live, ctx.me),
                            "session.control_released",
                            json!({"participant": ctx.me}),
                        )
                        .await;
                }
                live.signal(Signal::Room);
            }
        }
        _ if !ctx.owner => return Err(forbidden()),
        ClientMsg::ControlGrant {
            participant,
            minutes,
        } => {
            if minutes.is_some_and(|m| !(1..=MAX_CONTROL_MINUTES).contains(&m)) {
                return Err((
                    "invalid_control_minutes",
                    "the keyboard can be handed over for 1 to 240 minutes".into(),
                ));
            }
            let until = minutes.map(|m| now_ms() + i64::from(m) * 60_000);
            let r = live.room().grant(participant, until);
            match r {
                Ok(previous) => {
                    live.signal(Signal::Control);
                    live.signal(Signal::Room);
                    notify_control(live, previous, false);
                    notify_control(live, Some(participant), true);
                    let name = live.room().info(participant).map(|i| i.name);
                    st.sessions
                        .audit(
                            live,
                            &owner_actor,
                            "session.control_granted",
                            json!({"participant": participant, "name": name, "minutes": minutes}),
                        )
                        .await;
                }
                Err(code) => {
                    return Err((
                        code,
                        if code == "forbidden" {
                            "that participant's invitation does not allow the keyboard".into()
                        } else {
                            "no such participant".into()
                        },
                    ));
                }
            }
        }
        ClientMsg::ControlDeny { participant } => {
            let denied = live.room().deny_control(participant);
            if denied {
                live.signal(Signal::ControlDenied { participant });
                live.signal(Signal::Room);
                st.sessions
                    .audit(
                        live,
                        &owner_actor,
                        "session.control_denied",
                        json!({"participant": participant}),
                    )
                    .await;
            }
        }
        ClientMsg::ControlTake => {
            let previous = live.room().take();
            if previous.is_some() {
                live.signal(Signal::Control);
                live.signal(Signal::Room);
                notify_control(live, previous, false);
                st.sessions
                    .audit(
                        live,
                        &owner_actor,
                        "session.control_taken",
                        json!({"participant": previous}),
                    )
                    .await;
            }
        }
        ClientMsg::JoinAllow { participant } => {
            let admitted = live.room().admit(participant, now_ms());
            if !admitted {
                return Err((
                    "participant_not_found",
                    "nobody is waiting with that id".into(),
                ));
            }
            live.signal(Signal::Admitted { participant });
            live.signal(Signal::Room);
            let info = live.room().info(participant);
            if let Some(info) = info {
                st.sessions
                    .audit(
                        live,
                        &owner_actor,
                        "session.join_allowed",
                        json!({"participant": participant, "name": info.name}),
                    )
                    .await;
                st.sessions
                    .audit(
                        live,
                        &actor_of(&info),
                        "session.join",
                        json!({"participant": participant, "name": info.name, "kind": info.kind, "access": info.access, "share": info.share_id, "link": info.link}),
                    )
                    .await;
            }
        }
        ClientMsg::JoinDeny { participant } => {
            let denied = live.room().deny(participant);
            let Some(info) = denied else {
                return Err((
                    "participant_not_found",
                    "nobody is waiting with that id".into(),
                ));
            };
            live.end(EndTarget::Participant(participant), EndCode::JoinDenied);
            live.signal(Signal::Room);
            st.sessions
                .audit(
                    live,
                    &owner_actor,
                    "session.join_denied",
                    json!({"participant": participant, "name": info.name}),
                )
                .await;
        }
        ClientMsg::Kick {
            participant,
            revoke_share,
        } => {
            let kicked = live.room().kick(participant);
            let Some(info) = kicked else {
                return Err(("participant_not_found", "no such participant".into()));
            };
            // The share is revoked before they are told, so whatever they
            // (or the owner) do next already sees it revoked.
            let revoked = match info.share_id.filter(|_| revoke_share) {
                Some(share) => st.store.revoke_share(live.id, share).await.is_ok(),
                None => false,
            };
            live.end(EndTarget::Participant(participant), EndCode::Kicked);
            live.signal(Signal::Control);
            live.signal(Signal::Room);
            if revoked && let Some(share) = info.share_id {
                let using = live.room().with_share(share);
                st.sessions
                    .reevaluate(live, EndCode::Revoked, Some(&using))
                    .await;
            }
            st.sessions
                .audit(
                    live,
                    &owner_actor,
                    "session.kicked",
                    json!({"participant": participant, "name": info.name, "reason": "kicked", "share": info.share_id, "share_revoked": revoked}),
                )
                .await;
        }
        ClientMsg::StopSharing => {
            stop_sharing(st, live, &owner_actor)
                .await
                .map_err(|_| ("internal", "could not stop sharing".to_string()))?;
        }
        _ => {}
    }
    Ok(())
}

/// The socket is gone: after the grace period, the participant left.
fn leave(st: &AppState, live: &Arc<LiveSession>, sid: Id) {
    let left = live.room().leave(sid);
    live.signal(Signal::Room);
    let Some(left) = left.filter(|l| l.empty && !l.was_waiting) else {
        return;
    };
    let (st, live) = (st.clone(), live.clone());
    tokio::spawn(async move {
        tokio::time::sleep(LEAVE_GRACE).await;
        let gone = live.room().finish_leave(left.participant, left.epoch);
        if let Some(gone) = gone {
            if gone.was_driver {
                live.signal(Signal::Control);
            }
            live.signal(Signal::Room);
            let actor = match gone.user_id {
                Some(u) => format!("user:{u}"),
                None => format!("guest:{}", gone.participant),
            };
            st.sessions
                .audit(
                    &live,
                    &actor,
                    "session.leave",
                    json!({"participant": gone.participant, "name": gone.name, "kind": gone.kind}),
                )
                .await;
        }
    });
}

/// Audit of a join and the join request for the owner.
async fn joined(st: &AppState, live: &LiveSession, j: &crate::room::Joined, role: &str) {
    let Some(info) = live.room().info(j.participant) else {
        return;
    };
    if j.first {
        st.sessions
            .audit(
                live,
                &actor_of(&info),
                "session.join",
                json!({"participant": j.participant, "name": info.name, "kind": info.kind, "access": info.access, "share": info.share_id, "link": info.link, "role": role}),
            )
            .await;
    }
    if j.new_request {
        live.signal(Signal::JoinRequest {
            participant: j.participant,
        });
        let view = live.room().view_of(j.participant, true);
        if let Some(participant) = view {
            live.notify(
                live.owner,
                SessionNotice::JoinRequest {
                    session_id: live.id,
                    title: live.title(),
                    participant,
                },
            );
        }
        st.sessions
            .audit(
                live,
                &actor_of(&info),
                "session.join_requested",
                json!({"participant": j.participant, "name": info.name, "kind": info.kind, "share": info.share_id}),
            )
            .await;
    }
}

/// What the owner has pending when a socket of theirs arrives.
async fn send_pending(socket: &mut WebSocket, live: &LiveSession) -> bool {
    let (waiting, requests) = {
        let room = live.room();
        (room.waiting(), room.control_requests())
    };
    for p in waiting {
        if socket
            .send(text(json!({"type": "join_request", "participant": p})))
            .await
            .is_err()
        {
            return false;
        }
    }
    for p in requests {
        if socket
            .send(text(json!({"type": "control_request", "participant": p})))
            .await
            .is_err()
        {
            return false;
        }
    }
    true
}

fn you_json(live: &LiveSession, ctx: &Ctx, j: &Joiner) -> Value {
    let room = live.room();
    let info = room.info(ctx.me);
    json!({
        "id": ctx.sid,
        "participant": ctx.me,
        "name": info.as_ref().map(|i| i.name.clone()).unwrap_or_else(|| j.name.clone()),
        "user_id": j.user_id,
        "kind": j.kind,
        "access": info.as_ref().map(|i| i.access).unwrap_or(Access::View),
        "role": if j.host { "host" } else { "viewer" },
        "since": now_ms(),
        "can_write": room.can_write(ctx.me),
        "is_driver": room.driver() == Some(ctx.me) || (ctx.owner && room.driver().is_none()),
    })
}

/// Waiting room: until the owner lets them in. `false` if they leave or
/// are not let in.
async fn wait_for_owner(
    st: &AppState,
    live: &LiveSession,
    socket: &mut WebSocket,
    signals: &mut broadcast::Receiver<Signal>,
    ctx: &Ctx,
) -> bool {
    let owner = st
        .store
        .user(live.owner)
        .await
        .map(|u| u.name)
        .unwrap_or_default();
    let name = live.room().info(ctx.me).map(|i| i.name).unwrap_or_default();
    let waiting = json!({
        "type": "waiting",
        "participant": ctx.me,
        "name": name,
        "session": {"id": live.id, "title": live.title(), "owner": owner},
    });
    if socket.send(text(waiting)).await.is_err() {
        return false;
    }
    let mut state_rx = live.watch_state();
    loop {
        if live.room().is_admitted(ctx.me) {
            return true;
        }
        tokio::select! {
            msg = socket.recv() => match msg {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return false,
                Some(Ok(Message::Text(t))) => match serde_json::from_str::<ClientMsg>(t.as_str()) {
                    Ok(ClientMsg::Ping) => { let _ = socket.send(text(json!({"type": "pong", "ts": now_ms()}))).await; }
                    Ok(ClientMsg::SetName { name }) => {
                        let changed = live.room().set_name(ctx.me, &name);
                        if changed { live.signal(Signal::Room); }
                    }
                    _ => {}
                },
                Some(Ok(_)) => {}
            },
            sig = signals.recv() => match sig {
                Ok(Signal::Admitted { participant }) if participant == ctx.me => return true,
                Ok(Signal::End { target, code }) => {
                    let me = match target {
                        EndTarget::Participant(p) => p == ctx.me,
                        EndTarget::Guests => true,
                    };
                    if me {
                        send_end(socket, code).await;
                        return false;
                    }
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return false,
            },
            changed = state_rx.changed() => {
                if changed.is_err() || state_rx.borrow().is_closed() {
                    send_end(socket, EndCode::SessionEnded).await;
                    return false;
                }
            }
        }
    }
}

async fn viewer_loop(
    st: AppState,
    live: std::sync::Arc<LiveSession>,
    mut socket: WebSocket,
    joiner: Joiner,
) {
    let sid = new_id();
    // Subscribed before joining: nothing is missed.
    let mut signals = live.signals();
    let j = live.room().join(sid, joiner.clone(), now_ms());
    let ctx = Ctx {
        sid,
        me: j.participant,
        owner: joiner.kind == ParticipantKind::Owner,
        legacy: joiner.legacy,
        host: false,
    };
    live.touch();
    live.signal(Signal::Room);
    joined(&st, &live, &j, "viewer").await;
    if !j.admitted && !wait_for_owner(&st, &live, &mut socket, &mut signals, &ctx).await {
        leave(&st, &live, sid);
        return;
    }
    let access = live
        .room()
        .info(ctx.me)
        .map(|i| i.access)
        .unwrap_or(Access::View);
    let hello = json!({
        "type": "hello",
        "proto": 2,
        "session": live.view_for(access, Some(ctx.me)),
        "you": you_json(&live, &ctx, &joiner),
    });
    if socket.send(text(hello)).await.is_err() {
        leave(&st, &live, sid);
        return;
    }
    if ctx.owner {
        for p in live.pending_prompts() {
            let mut v = serde_json::to_value(&p).unwrap_or_default();
            v["type"] = json!("prompt");
            let _ = socket.send(text(v)).await;
        }
        if !send_pending(&mut socket, &live).await {
            leave(&st, &live, sid);
            return;
        }
    }
    let mut state_rx = live.watch_state();
    let mut out: Option<broadcast::Receiver<Bytes>> = None;
    if let Some(hub) = live.hub() {
        let (snapshot, rx) = hub.attach();
        if socket.send(Message::Binary(snapshot)).await.is_err() {
            leave(&st, &live, sid);
            return;
        }
        out = Some(rx);
    }
    loop {
        tokio::select! {
            msg = socket.recv() => match msg {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                Some(Ok(Message::Binary(data))) => input(&st, &live, &ctx, data).await,
                Some(Ok(Message::Text(t))) => {
                    match serde_json::from_str::<ClientMsg>(t.as_str()) {
                        Ok(ClientMsg::Resize { cols, rows }) => {
                            let can = live.room().can_write(ctx.me);
                            if can { live.resize(cols, rows, Some(sid)).await; }
                        }
                        Ok(ClientMsg::Input { data }) => input(&st, &live, &ctx, Bytes::from(data)).await,
                        Ok(ClientMsg::PromptAnswer { prompt_id, accept, answers }) => {
                            if ctx.owner {
                                live.answer_prompt(prompt_id, PromptAnswer { accept, answers });
                            } else {
                                let _ = socket.send(error_msg("forbidden", "only the owner can answer")).await;
                            }
                        }
                        Ok(ClientMsg::Ping) => { let _ = socket.send(text(json!({"type": "pong", "ts": now_ms()}))).await; }
                        Ok(ClientMsg::CloseSession) => {
                            if ctx.owner {
                                let _ = st.sessions.close(&live, live.owner).await;
                            } else {
                                let _ = socket.send(error_msg("forbidden", "only the owner can close the session")).await;
                            }
                        }
                        Ok(ClientMsg::HostClosed) => {}
                        Ok(other) => {
                            if let Err((code, message)) = room_msg(&st, &live, &ctx, other).await {
                                let _ = socket.send(error_msg(code, &message)).await;
                            }
                        }
                        Err(e) => { let _ = socket.send(error_msg("bad_request", &format!("invalid message: {e}"))).await; }
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
                Ok(sig) => match render(&live, &ctx, sig) {
                    Out::Send(v) => if socket.send(text(v)).await.is_err() { break },
                    Out::End(code) => { send_end(&mut socket, code).await; break; }
                    Out::Skip => {}
                },
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    // Signals were lost: if they were sent away meanwhile,
                    // they leave now; otherwise, the current picture.
                    let gone = live.room().info(ctx.me).is_none();
                    if gone {
                        send_end(&mut socket, EndCode::Forbidden).await;
                        break;
                    }
                    let _ = socket.send(text(control_json(&live, &ctx))).await;
                    if let Out::Send(v) = render(&live, &ctx, Signal::Room) {
                        let _ = socket.send(text(v)).await;
                    }
                }
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
                    let code = EndCode::SessionEnded;
                    let _ = socket
                        .send(Message::Close(Some(CloseFrame {
                            code: code.close_code(),
                            reason: code.as_str().into(),
                        })))
                        .await;
                    break;
                }
            }
        }
    }
    leave(&st, &live, sid);
}

async fn host_loop(
    st: AppState,
    live: std::sync::Arc<LiveSession>,
    mut socket: WebSocket,
    joiner: Joiner,
) {
    let Some(hub) = live.hub() else { return };
    let Some(mut input) = st.sessions.relay_input(&live) else {
        return;
    };
    let sid = new_id();
    let mut signals = live.signals();
    let j = live.room().join(sid, joiner.clone(), now_ms());
    let ctx = Ctx {
        sid,
        me: j.participant,
        owner: true,
        legacy: joiner.legacy,
        host: true,
    };
    live.signal(Signal::Room);
    joined(&st, &live, &j, "host").await;
    live.set_host_online(true);
    let hello = json!({
        "type": "hello",
        "proto": 2,
        "session": live.view_for(Access::Owner, Some(ctx.me)),
        "you": you_json(&live, &ctx, &joiner),
    });
    let _ = socket.send(text(hello)).await;
    send_pending(&mut socket, &live).await;
    let mut state_rx = live.watch_state();
    let mut host_closed = false;
    // The first frame of each connection is the whole screen: it replaces
    // the history (so a host that reconnects does not duplicate it).
    let mut first = true;
    loop {
        tokio::select! {
            msg = socket.recv() => match msg {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                Some(Ok(Message::Binary(data))) => {
                    live.touch();
                    if std::mem::take(&mut first) {
                        hub.reset(data);
                    } else {
                        hub.push(data);
                    }
                }
                Some(Ok(Message::Text(t))) => match serde_json::from_str::<ClientMsg>(t.as_str()) {
                    Ok(ClientMsg::Resize { cols, rows }) => live.host_resized(cols, rows, sid),
                    Ok(ClientMsg::HostClosed) | Ok(ClientMsg::CloseSession) => {
                        host_closed = true;
                        let _ = st.sessions.close(&live, live.owner).await;
                        break;
                    }
                    Ok(ClientMsg::Ping) => { let _ = socket.send(text(json!({"type": "pong", "ts": now_ms()}))).await; }
                    Ok(ClientMsg::Input { .. } | ClientMsg::PromptAnswer { .. }) => {}
                    Ok(other) => {
                        if let Err((code, message)) = room_msg(&st, &live, &ctx, other).await {
                            let _ = socket.send(error_msg(code, &message)).await;
                        }
                    }
                    Err(_) => {}
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
            sig = signals.recv() => match sig {
                Ok(sig) => {
                    // An older host gets the old `presence` too.
                    if ctx.legacy && matches!(sig, Signal::Room) {
                        let _ = socket.send(text(json!({"type": "presence", "viewers": live.viewers()}))).await;
                    } else if let Out::Send(v) = render(&live, &Ctx { legacy: false, ..ctx }, sig)
                        && socket.send(text(v)).await.is_err()
                    {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            },
            changed = state_rx.changed() => {
                if changed.is_err() || state_rx.borrow().is_closed() {
                    let code = EndCode::SessionEnded;
                    let _ = socket
                        .send(Message::Close(Some(CloseFrame {
                            code: code.close_code(),
                            reason: code.as_str().into(),
                        })))
                        .await;
                    break;
                }
            }
        }
    }
    leave(&st, &live, sid);
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
