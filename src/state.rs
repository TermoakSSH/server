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
    /// Emails with a verification code (per address and per IP).
    pub code_emails: crate::limiter::CodeEmailLimiter,
    /// Checks of the users' own AI keys (each one calls the provider).
    pub ai_key_limiter: crate::limiter::RateLimiter,
    /// Desktop updates (if configured).
    pub updates: Option<Arc<crate::updates::UpdateProxy>>,
    /// Outgoing email (may be disabled).
    pub mailer: Arc<crate::email::Mailer>,
    /// Push notifications (if APNs or FCM is configured).
    pub push: Option<Arc<crate::push::Push>>,
    /// `vault` events (changed, access) for the events WebSocket.
    pub vault_events: Arc<crate::vaults::VaultEvents>,
    /// Just-in-time credentials (`POST /hosts/{id}/credentials`) per user.
    pub credentials_limiter: crate::limiter::RateLimiter,
    /// Random id of this server's database (`/info`).
    pub instance_id: String,
    /// Open WebSockets per device (closed when the device is signed out).
    pub sockets: Arc<crate::devices::Sockets>,
    /// `termoak-netd` (private networks), when configured.
    pub netd: Option<Arc<crate::netd::Netd>>,
    /// Open network relays per user.
    pub relays: crate::routes::networks::RelayCounter,
    /// Security key signatures forwarded to the users' devices.
    pub security_keys: Arc<crate::security_keys::SkBroker>,
    /// Teams security: SSH CA, access policies (0.7 phase 4b).
    pub security: Arc<crate::security::Security>,
    /// Certificates per user (`POST /certificates`).
    pub cert_limiter: crate::limiter::RateLimiter,
    /// Access requests per user.
    pub request_limiter: crate::limiter::RateLimiter,
}

#[derive(Clone)]
pub struct AppState(pub Arc<Inner>);

impl Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}
