//! Termoak server.
//!
//! Serves the REST + WebSocket API used by the desktop app, the CLI and the
//! iOS and Android apps: synced data, terminal sessions that live on the
//! server (and can be shared), SFTP, running commands on several hosts, the
//! background AI engine and an MCP server.

// Translations for emails and notifications: `locales/<lang>.json`.
rust_i18n::i18n!("locales", fallback = "en");

pub mod account;
pub mod auth;
pub mod config;
pub mod email;
pub mod error;
pub mod holder;
pub mod i18n;
pub mod limiter;
pub mod openapi;
pub mod push;
pub mod room;
pub mod routes;
pub mod sessions;
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
    let push = push::Push::from_config(&config.push, store.clone())?;
    if let Some(p) = &push {
        let (apns, fcm) = p.platforms();
        tracing::info!(apns, fcm, "push notifications enabled");
        p.clone().spawn_dispatcher(ai.clone(), sessions.clone());
    }
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
    })))
}
