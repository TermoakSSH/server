//! Vault access on the server: the `AccessCtx` extractor every route that
//! touches entities uses, the `vault` events (`changed`, `access`), the
//! revocation hooks and the background job that reseals legacy secrets.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Weak};
use std::time::Duration;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use parking_lot::Mutex;
use serde_json::{Value, json};
use termoak_core::model::VaultRole;
use termoak_core::store::VaultAccess;
use termoak_core::{Id, Store};
use tokio::sync::broadcast;

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::AppState;

/// Authenticated user plus what they can reach (cached in the store,
/// invalidated by every change to vaults, grants, teams or team members).
pub struct AccessCtx {
    pub user: AuthUser,
    pub access: Arc<VaultAccess>,
}

impl AccessCtx {
    pub fn id(&self) -> Id {
        self.user.id()
    }

    pub fn actor(&self) -> String {
        self.user.actor()
    }

    /// The personal vault (same id as the user).
    pub fn personal(&self) -> Id {
        self.access.personal()
    }
}

impl FromRequestParts<AppState> for AccessCtx {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        let access = state.store.vault_access(user.id()).await?;
        Ok(AccessCtx { user, access })
    }
}

/// Changes are announced at most every this often per vault.
const CHANGED_EVERY: Duration = Duration::from_millis(500);

/// `vault` events for the events WebSocket: `(user, message)`.
pub struct VaultEvents {
    store: Store,
    tx: broadcast::Sender<(Id, Value)>,
    pending: Mutex<HashSet<Id>>,
}

impl VaultEvents {
    pub fn new(store: Store) -> Arc<Self> {
        let (tx, _) = broadcast::channel(1024);
        let events = Arc::new(Self {
            store: store.clone(),
            tx,
            pending: Mutex::new(HashSet::new()),
        });
        // Every committed entity change of a vault (REST, sync, transfers,
        // AI memories, known hosts...) ends up here.
        let weak: Weak<Self> = Arc::downgrade(&events);
        store.set_change_listener(Some(Arc::new(move |vaults: &[Id]| {
            if let Some(ev) = weak.upgrade() {
                ev.changed(vaults);
            }
        })));
        events
    }

    pub fn subscribe(&self) -> broadcast::Receiver<(Id, Value)> {
        self.tx.subscribe()
    }

    /// Something changed in these vaults: every member online gets
    /// `{"type":"vault","event":"changed","vault_id","rev"}`, coalesced per
    /// vault (one every 500 ms at most).
    pub fn changed(self: &Arc<Self>, vaults: &[Id]) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        for &vault in vaults {
            if !self.pending.lock().insert(vault) {
                continue;
            }
            let me = self.clone();
            handle.spawn(async move {
                tokio::time::sleep(CHANGED_EVERY).await;
                me.pending.lock().remove(&vault);
                let rev = me.store.head_rev().await.unwrap_or(0);
                let users = me.store.vault_user_ids(vault).await.unwrap_or_default();
                for user in users {
                    let has = me
                        .store
                        .vault_access(user)
                        .await
                        .map(|a| a.role(vault).is_some())
                        .unwrap_or(false);
                    if has {
                        let _ = me.tx.send((
                            user,
                            json!({"type": "vault", "event": "changed", "vault_id": vault, "rev": rev}),
                        ));
                    }
                }
            });
        }
    }

    /// A user's access to a vault changed (`role: null`: lost).
    pub fn access(&self, user: Id, vault: Id, role: Option<VaultRole>, reason: &str) {
        let _ = self.tx.send((
            user,
            json!({
                "type": "vault",
                "event": "access",
                "vault_id": vault,
                "role": role,
                "reason": reason,
            }),
        ));
    }
}

/// Access of some users before a change (see [`apply_revocations`]).
pub struct AccessSnapshot(HashMap<Id, Arc<VaultAccess>>);

/// Takes the access of `users` before a change to vaults, grants or teams.
pub async fn snapshot(st: &AppState, users: impl IntoIterator<Item = Id>) -> AccessSnapshot {
    let mut map = HashMap::new();
    for u in users {
        if let Ok(a) = st.store.vault_access(u).await {
            map.insert(u, a);
        }
    }
    AccessSnapshot(map)
}

/// Users with possible access to these vaults.
pub async fn vault_users(st: &AppState, vaults: &[Id]) -> Vec<Id> {
    let mut out = BTreeSet::new();
    for v in vaults {
        out.extend(st.store.vault_user_ids(*v).await.unwrap_or_default());
    }
    out.into_iter().collect()
}

/// After a change: for every user of the snapshot and every vault whose
/// role changed, closes the server sessions and pool connections of lost
/// vaults (a downgrade to Use-only keeps them) and sends `vault/access`.
/// `deleted`: vaults that no longer exist (reason `deleted`).
pub async fn apply_revocations(st: &AppState, before: AccessSnapshot, deleted: &[Id]) {
    for (user, old) in before.0 {
        let new = st
            .store
            .vault_access(user)
            .await
            .unwrap_or_else(|_| Arc::new(VaultAccess::default()));
        let vaults: BTreeSet<Id> = old.roles.keys().chain(new.roles.keys()).copied().collect();
        for vault in vaults {
            let (was, now) = (old.role(vault), new.role(vault));
            if was == now {
                continue;
            }
            let reason = match (was, now) {
                (_, None) if deleted.contains(&vault) => "deleted",
                (_, None) => "revoked",
                (None, Some(_)) => "granted",
                _ => "role_changed",
            };
            if now.is_none() {
                revoke(st, user, vault).await;
            }
            st.vault_events.access(user, vault, now, reason);
        }
    }
}

/// Closes a user's server sessions on hosts of a vault and their pooled
/// connections to it.
pub async fn revoke(st: &AppState, user: Id, vault: Id) {
    let closed = st.sessions.close_for_vault(Some(user), vault).await;
    st.pool.invalidate_vault(vault, Some(user)).await;
    if closed > 0 {
        tracing::info!(%user, %vault, closed, "vault access revoked: sessions closed");
    }
}

/// A user lost everything (account disabled or deleted).
pub async fn revoke_all(st: &AppState, user: Id, access: &VaultAccess) {
    for vault in access.vault_ids() {
        revoke(st, user, vault).await;
    }
}

/// Reseals the secrets stored before vault keys (master key) with their
/// vault key, in batches, once at start-up.
pub fn spawn_reseal_job(store: Store) {
    tokio::spawn(async move {
        let mut total = 0usize;
        loop {
            match store.reseal_legacy(500).await {
                Ok(0) => break,
                Ok(n) => {
                    total += n;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "could not reseal legacy secrets");
                    break;
                }
            }
        }
        if total > 0 {
            tracing::info!(total, "legacy secrets resealed with vault keys");
        }
    });
}
