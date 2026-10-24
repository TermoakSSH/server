//! User event WebSocket (`/api/v1/events/ws`): AI task progress, pending
//! approvals, opened/closed sessions, sessions shared with you and vault
//! changes (`{"type":"vault","event":"changed"|"access",...}`). The mobile
//! app uses it for notifications. When the device is signed out it gets
//! `{"type":"signed_out"}` and the socket closes (code 4007, `signed_out`).
//!
//! A device that connects with `?features=security_keys` also gets the
//! server's `security_key_request`s and answers them on the same socket
//! (`security_key_response`): docs/SSH-PRO.md §5. `roles_v2` (0.7 phase 4b):
//! roles as they are (`connect_only`); without it they are shown as older
//! clients understand them. Teams security events: `access_request`
//! (created, approved, denied, cancelled, expired, revoked, ended) and
//! `team` (`policy`), docs-next/TEAMS-SECURITY.md §5.6.

use std::collections::HashMap;

use axum::Router;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::Response;
use axum::routing::get;
use serde_json::json;
use tokio::sync::broadcast::error::RecvError;

use crate::auth::AuthUser;
use crate::devices::{SocketGuard, SocketKind};
use crate::room::EndCode;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/api/v1/events/ws", get(ws))
}

async fn ws(
    State(st): State<AppState>,
    u: AuthUser,
    Query(q): Query<HashMap<String, String>>,
    upgrade: WebSocketUpgrade,
) -> Response {
    // Closed as soon as this device is signed out.
    let guard = st.sockets.register(u.id(), u.device.id, SocketKind::Events);
    let features: Vec<String> = q
        .get("features")
        .map(|f| {
            f.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| {
                    x == termoak_ssh::sk::wire::FEATURE
                        || matches!(x.as_str(), "roles_v2" | "policies")
                })
                .collect()
        })
        .unwrap_or_default();
    upgrade.on_upgrade(move |socket| run(st, u, socket, guard, features))
}

async fn run(
    st: AppState,
    u: AuthUser,
    mut socket: WebSocket,
    guard: SocketGuard,
    features: Vec<String>,
) {
    let owner = u.id();
    // Roles as this client understands them (`connect_only` is `use_only`
    // for clients without `roles_v2`, 0.7 phase 4b).
    let roles_v2 = features.iter().any(|f| f == "roles_v2");
    let mut ai = st.ai.subscribe();
    let mut sessions = st.sessions.notices();
    let mut vaults = st.vault_events.subscribe();
    // A device that can sign with security keys (server forwarding).
    let mut signer = features
        .iter()
        .any(|f| f == termoak_ssh::sk::wire::FEATURE)
        .then(|| st.security_keys.register(owner, u.device.id));
    // Initial state: pending approvals.
    let pending = st.ai.pending_approvals(owner).await.unwrap_or_default();
    let hello = json!({"type": "hello", "user": u.user, "pending_approvals": pending, "features": features});
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
                Some(Ok(Message::Text(t))) => {
                    if let Some((g, _)) = &signer
                        && let Ok(v) = serde_json::from_str::<serde_json::Value>(&t)
                    {
                        st.security_keys.on_message(owner, g.id(), &v);
                    }
                }
                _ => {}
            },
            Some(v) = async {
                match signer.as_mut() {
                    Some((_, rx)) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if socket.send(Message::Text(v.to_string().into())).await.is_err() { break; }
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
            ev = vaults.recv() => match ev {
                Ok((user, mut v)) if user == owner => {
                    if !roles_v2 && v["type"] == "vault" && v["role"] == "connect_only" {
                        v["role"] = serde_json::json!("use_only");
                    }
                    if socket.send(Message::Text(v.to_string().into())).await.is_err() { break; }
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => {
                    let v = json!({"type": "lagged", "missed": n});
                    let _ = socket.send(Message::Text(v.to_string().into())).await;
                }
                Err(RecvError::Closed) => break,
            },
            _ = ping.tick() => {
                if socket.send(Message::Ping(Default::default())).await.is_err() { break; }
            }
            _ = guard.signed_out() => {
                let code = EndCode::SignedOut;
                let v = json!({"type": "signed_out", "message": code.message()});
                let _ = socket.send(Message::Text(v.to_string().into())).await;
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
