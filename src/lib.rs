//! Termoak server.
//!
//! Serves the REST + WebSocket API used by the desktop app, the CLI and the
//! iOS and Android apps: synced data, terminal sessions that live on the
//! server (and can be shared), SFTP, running commands on several hosts, the
//! background AI engine and an MCP server.

// Translations for emails and notifications: `locales/<lang>.json`.
rust_i18n::i18n!("locales", fallback = "en");

pub mod account;
pub mod audit;
pub mod auth;
pub mod config;
pub mod devices;
pub mod e2ee;
pub mod egress;
pub mod email;
pub mod error;
pub mod holder;
pub mod i18n;
pub mod limiter;
pub mod netd;
pub mod openapi;
pub mod push;
pub mod room;
pub mod routes;
pub mod security;
pub mod security_keys;
pub mod sessions;
pub mod sso;
pub mod state;
pub mod updates;
pub mod vaults;
pub mod web;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use termoak_ai::AiEngine;
use termoak_core::Store;
use termoak_core::crypto::MasterKey;
use termoak_core::store::users::TokenTtl;
use termoak_core::time::now_ms;
use termoak_ssh::ConnectionPool;

use crate::config::ServerConfig;
use crate::sessions::SessionManager;
use crate::state::{AppState, Inner};

/// Own AI key checks per user and minute (each one calls the provider).
const AI_KEY_CHECKS_PER_MINUTE: usize = 10;

/// Loads the master key: `TERMOAK_MASTER_KEY` (base64) or `<data_dir>/master.key`.
pub fn load_master_key(data_dir: &Path) -> anyhow::Result<MasterKey> {
    if let Ok(v) = std::env::var("TERMOAK_MASTER_KEY")
        && !v.trim().is_empty()
    {
        return MasterKey::from_base64(&v).context("invalid TERMOAK_MASTER_KEY");
    }
    let path = data_dir.join("master.key");
    let existed = path.exists();
    let key = MasterKey::load_or_create(&path)
        .with_context(|| format!("could not read or create {}", path.display()))?;
    if !existed {
        tracing::warn!(
            path = %path.display(),
            "created a new master key: back it up; without it the secrets cannot be decrypted"
        );
    }
    Ok(key)
}

/// Starts the sessions when the server boots: connects to the holder (if
/// any) to recover its sessions and marks the other ones that were still
/// open as closed.
pub async fn start_sessions(state: &AppState) -> anyhow::Result<()> {
    let keep = match &state.config.sessions.holder_socket {
        Some(socket) => {
            match state
                .sessions
                .use_holder(socket.clone(), Duration::from_secs(10))
                .await
            {
                Some(held) => {
                    tracing::info!(sessions = held.len(), "session holder connected");
                    held
                }
                None => {
                    tracing::warn!(
                        socket = %socket.display(),
                        "the session holder is not responding: still trying"
                    );
                    Vec::new()
                }
            }
        }
        None => Vec::new(),
    };
    // Teams security: expire access requests, end windows, retire CAs.
    routes::security::spawn_job(state.clone());
    // Audit sinks and retention (0.7 phase 5a).
    audit::spawn_jobs(state.clone());
    let closed = state.store.close_orphan_sessions(&keep).await?;
    if closed > 0 {
        tracing::info!(closed, "sessions marked as closed after the restart");
    }
    Ok(())
}

/// Builds the application state.
pub async fn build_state(config: ServerConfig) -> anyhow::Result<AppState> {
    std::fs::create_dir_all(&config.server.data_dir)
        .with_context(|| format!("could not create {}", config.server.data_dir.display()))?;
    let key = load_master_key(&config.server.data_dir)?;
    let store = Store::open(&config.server.data_dir.join("termoak.db"), key)?;
    // New secrets are sealed with per-vault keys; older ones are resealed
    // in the background.
    store.enable_vault_keys();
    vaults::spawn_reseal_job(store.clone());
    let vault_events = vaults::VaultEvents::new(store.clone());
    let instance_id = store.instance_id().await?;
    let pool = ConnectionPool::new(
        store.clone(),
        config.ai.host_key_policy,
        Duration::from_secs(10 * 60),
    );
    let sessions = SessionManager::new(
        store.clone(),
        config.sessions.clone(),
        config.server.data_dir.clone(),
    );
    // FIDO2 security keys: signatures forwarded to the users' devices for
    // everything that connects from the server.
    let security_keys = security_keys::SkBroker::new(
        store.clone(),
        Duration::from_secs(config.sessions.security_key_timeout_secs),
    );
    sessions.set_security_keys(security_keys.clone());
    {
        let sk = security_keys.clone();
        pool.set_security_keys(Some(Arc::new(move |user, vault| {
            Some(sk.signer(user, Some(vault), None))
        })));
    }
    // Private networks: everything that connects from the server (sessions,
    // tests, exec, SFTP, AI) dials hosts with a network through netd.
    let netd = config.networks.netd_socket.clone().map(|socket| {
        tracing::info!(socket = %socket.display(), "private networks through termoak-netd");
        let netd = netd::Netd::new(socket);
        netd.spawn_health();
        pool.set_dialer(Some(netd.dialer()));
        sessions.set_dialer(netd.dialer());
        netd
    });
    let ai = AiEngine::new(
        store.clone(),
        pool.clone(),
        Some(sessions.clone() as Arc<dyn termoak_ai::SessionAccess>),
        config.ai.clone(),
    )
    .await?;
    ai.set_mcp_url(config.local_mcp_url());
    ai.set_access_policy(Arc::new(account::PlanAiPolicy {
        store: store.clone(),
        plans: config.plans.clone(),
        fallback_credit_usd: config.ai.monthly_budget_usd,
    }));
    let ttl = TokenTtl {
        access_ms: config.server.access_token_minutes.max(5) * 60_000,
        refresh_ms: config.server.refresh_token_days.max(1) * 86_400_000,
    };
    let mailer = Arc::new(email::Mailer::from_config(&config.email)?);
    if mailer.enabled() && config.server.public_url.is_none() {
        tracing::warn!(
            "email is configured but public_url is not: email links will not work outside this machine"
        );
    }
    let sockets = devices::Sockets::new();
    let push = push::Push::from_config(
        &config.push,
        push::PushContext {
            store: store.clone(),
            sockets: sockets.clone(),
            data_dir: config.server.data_dir.clone(),
            instance_id: instance_id.clone(),
            support_email: config.web.support_email.clone(),
            public_url: config.server.public_url.clone(),
            sk_timeout_secs: config.sessions.security_key_timeout_secs,
        },
    )?;
    if let Some(p) = &push {
        let (apns, fcm) = p.platforms();
        tracing::info!(
            webpush = p.webpush(),
            apns,
            fcm,
            "push notifications enabled"
        );
        p.clone().spawn_dispatcher(ai.clone(), sessions.clone());
        security_keys.set_waker(Arc::new(push::SkWaker(p.clone())));
    }
    // Teams security (0.7 phase 4b): access policies and team certificates
    // on every server resolution.
    let security = security::Security::new(store.clone(), instance_id.clone());
    store.set_resolve_hook(Some(
        security.clone() as Arc<dyn termoak_core::store::ResolveHook>
    ));
    sessions.set_security(security.clone());
    let updates = updates::UpdateProxy::from_config(&config.updates);
    if let Some(updates) = &updates {
        tracing::info!(
            repos = %updates.repos().join(", "),
            "updates at /updates/latest.json, downloads at /api/v1/downloads"
        );
    }
    Ok(AppState(Arc::new(Inner {
        store,
        config,
        sessions,
        ai,
        pool,
        ttl,
        started_at: now_ms(),
        limiter: Default::default(),
        code_emails: Default::default(),
        ai_key_limiter: limiter::RateLimiter::new(AI_KEY_CHECKS_PER_MINUTE, 60_000),
        updates,
        mailer,
        push,
        vault_events,
        credentials_limiter: limiter::RateLimiter::new(
            routes::entities::CREDENTIALS_PER_MINUTE,
            60_000,
        ),
        instance_id,
        sockets,
        netd,
        relays: Default::default(),
        security_keys,
        security,
        cert_limiter: limiter::RateLimiter::new(routes::security::CERTS_PER_MINUTE, 60_000),
        request_limiter: limiter::RateLimiter::new(routes::security::REQUESTS_PER_MINUTE, 60_000),
        sso: sso::new_oidc(),
    })))
}
