//! User event WebSocket (`/api/v1/events/ws`): AI task progress, pending
//! approvals, opened/closed sessions and sessions shared with you. The mobile
//! app uses it for notifications.

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use axum::routing::get;
use serde_json::json;
use tokio::sync::broadcast::error::RecvError;

use crate::auth::AuthUser;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/api/v1/events/ws", get(ws))
}

async fn ws(State(st): State<AppState>, u: AuthUser, upgrade: WebSocketUpgrade) -> Response {
    upgrade.on_upgrade(move |socket| run(st, u, socket))
}

async fn run(st: AppState, u: AuthUser, mut socket: WebSocket) {
    let owner = u.id();
    let mut ai = st.ai.subscribe();
    let mut sessions = st.sessions.notices();
    // Initial state: pending approvals.
    let pending = st.ai.pending_approvals(owner).await.unwrap_or_default();
    let hello = json!({"type": "hello", "user": u.user, "pending_approvals": pending});
    if socket
        .send(Message::Text(hello.to_string().into()))
        .await
        .is_err()
    {
        return;
    }
    let mut ping = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        tokio::select! {
            msg = socket.recv() => match msg {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                _ => {}
            },
            ev = ai.recv() => match ev {
                Ok(ev) if ev.owner == owner => {
                    let v = json!({"type": "ai", "task_id": ev.task_id, "seq": ev.seq, "event": ev.event});
                    if socket.send(Message::Text(v.to_string().into())).await.is_err() { break; }
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => {
                    let v = json!({"type": "lagged", "missed": n});
                    let _ = socket.send(Message::Text(v.to_string().into())).await;
                }
                Err(RecvError::Closed) => break,
            },
            ev = sessions.recv() => match ev {
                Ok((user, notice)) if user == owner => {
                    let v = json!({"type": "session", "notice": notice});
                    if socket.send(Message::Text(v.to_string().into())).await.is_err() { break; }
                }
                Ok(_) | Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => break,
            },
            _ = ping.tick() => {
                if socket.send(Message::Ping(Default::default())).await.is_err() { break; }
            }
        }
    }
}
