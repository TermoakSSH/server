//! Shared application state.

use std::ops::Deref;
use std::sync::Arc;

use termoak_ai::AiEngine;
use termoak_core::Store;
use termoak_core::store::users::TokenTtl;
use termoak_ssh::ConnectionPool;

use crate::config::ServerConfig;
use crate::sessions::SessionManager;

pub struct Inner {
    pub store: Store,
    pub config: ServerConfig,
    pub sessions: Arc<SessionManager>,
    pub ai: Arc<AiEngine>,
    pub pool: Arc<ConnectionPool>,
    pub ttl: TokenTtl,
    pub started_at: i64,
    /// Failed sign-in attempts (per email and per IP).
    pub limiter: crate::limiter::LoginLimiter,
    /// Checks of the users' own AI keys (each one calls the provider).
    pub ai_key_limiter: crate::limiter::RateLimiter,
    /// Desktop updates (if configured).
    pub updates: Option<Arc<crate::updates::UpdateProxy>>,
    /// Outgoing email (may be disabled).
    pub mailer: Arc<crate::email::Mailer>,
    /// Push notifications (if APNs or FCM is configured).
    pub push: Option<Arc<crate::push::Push>>,
}

#[derive(Clone)]
pub struct AppState(pub Arc<Inner>);

impl Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}
