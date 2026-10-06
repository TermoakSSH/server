//! Vaults: the unit of ownership, sharing and sync of hosts, keys,
//! snippets... (`/api/v1/vaults`), their members, moving and copying items
//! between them, their audit and the sync protocol v2.

use std::collections::{BTreeSet, HashMap};

use axum::extract::{Path, Query, State};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use termoak_core::Id;
use termoak_core::model::{
    AuditEntry, EntityKind, SyncRecord, Vault, VaultMember, VaultRole, VaultSettings,
};
use termoak_core::store::{
    NewVault, SyncRejection, SyncWarning, VaultChange, VaultGrantee, VaultPatch,
};
use termoak_core::transfer::{TransferRequest, TransferResult};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::vaults::{AccessCtx, apply_revocations, snapshot, vault_users};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/vaults", get(list).post(create))
        .route("/api/v1/vaults/sync", post(sync_v2))
        .route("/api/v1/vaults/{id}", get(one).patch(update).delete(remove))
        .route("/api/v1/vaults/{id}/leave", post(leave))
        .route("/api/v1/vaults/{id}/members", get(members).post(add_member))
        .route(
            "/api/v1/vaults/{id}/members/{member_id}",
            patch(set_member_role).delete(remove_member),
        )
        .route("/api/v1/vaults/{id}/transfer", post(transfer))
        .route("/api/v1/vaults/{id}/audit", get(audit))
}

/// `absent` → `None`, `null` → `Some(None)`, value → `Some(Some(v))`.
fn double_option<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateVault {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
    /// Owned by this team (you must be a team owner or admin).
    #[serde(default)]
    pub team_id: Option<Uuid>,
    /// Team vaults: role of plain team members, `editor` (default) or
    /// `use_only`.
    #[serde(default)]
    pub team_member_role: Option<VaultRole>,
    #[serde(default)]
    pub settings: Option<VaultSettings>,
}

/// Changes (missing: unchanged; `null` clears `color`, `icon`, and
/// `team_member_role` = plain team members get no access).
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct UpdateVault {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>)]
    pub color: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>)]
    pub icon: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<VaultRole>)]
    pub team_member_role: Option<Option<VaultRole>>,
    #[serde(default)]
    pub settings: Option<VaultSettings>,
}

#[derive(Debug, Deserialize)]
struct DeleteQuery {
    confirm: Option<String>,
}

/// `{email, role}` or `{team_id, role}`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddVaultMember {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub team_id: Option<Uuid>,
    /// `editor` or `use_only`.
    pub role: VaultRole,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetVaultMemberRole {
    pub role: VaultRole,
}

#[derive(Debug, Deserialize)]
struct AuditQuery {
    before: Option<i64>,
    limit: Option<i64>,
}

async fn list(State(st): State<AppState>, ctx: AccessCtx) -> ApiResult<Json<Vec<Vault>>> {
    Ok(Json(st.store.vaults_for(ctx.id()).await?))
}

async fn one(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
) -> ApiResult<Json<Vault>> {
    Ok(Json(st.store.vault_for(id, ctx.id()).await?))
}

/// Creates a `shared` vault, or a `team` vault with `team_id`.
async fn create(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Json(req): Json<CreateVault>,
) -> ApiResult<Json<Vault>> {
    let before = match req.team_id {
        Some(team) => Some(snapshot(&st, st.store.team_member_ids(team).await?).await),
        None => None,
    };
    let vault = st
        .store
        .create_vault(
            ctx.id(),
            NewVault {
                name: req.name,
                description: req.description.unwrap_or_default(),
                color: req.color,
                icon: req.icon,
                team_id: req.team_id,
                team_member_role: req.team_member_role,
                settings: req.settings,
            },
        )
        .await?;
    if let Some(before) = before {
        apply_revocations(&st, before, &[]).await;
    }
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "vault.create",
            Some(vault.id.to_string()),
            json!({"name": vault.name, "kind": vault.kind, "team_id": vault.owner_team_id}),
            vault.id,
        )
        .await?;
    Ok(Json(vault))
}

/// Managers. Personal vault: only name, color and icon.
async fn update(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
    Json(req): Json<UpdateVault>,
) -> ApiResult<Json<Vault>> {
    ctx.access.require(id, VaultRole::Manager)?;
    let users = vault_users(&st, &[id]).await;
    let before = snapshot(&st, users.clone()).await;
    let settings_changed = req.settings.is_some();
    st.store
        .update_vault(
            id,
            VaultPatch {
                name: req.name,
                description: req.description,
                color: req.color,
                icon: req.icon,
                team_member_role: req.team_member_role,
                settings: req.settings,
            },
        )
        .await?;
    apply_revocations(&st, before, &[]).await;
    // Everyone still in hears about the new settings (Strict switch...).
    if settings_changed {
        for u in users {
            if let Ok(a) = st.store.vault_access(u).await
                && let Some(role) = a.role(id)
            {
                st.vault_events.access(u, id, Some(role), "updated");
            }
        }
    }
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "vault.update",
            Some(id.to_string()),
            json!({}),
            id,
        )
        .await?;
    Ok(Json(st.store.vault_for(id, ctx.id()).await?))
}

/// Managers, with `?confirm=<vault name>`. Deletes its items and keys.
async fn remove(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
    Query(q): Query<DeleteQuery>,
) -> ApiResult<Json<Value>> {
    ctx.access.require(id, VaultRole::Manager)?;
    let vault = st.store.vault(id).await?;
    if q.confirm.as_deref().map(str::trim) != Some(vault.name.trim()) {
        // The personal vault is refused whatever the confirmation says.
        if vault.kind == termoak_core::model::VaultKind::Personal {
            return Err(ApiError::conflict("the personal vault cannot be deleted")
                .with_code("vault_personal"));
        }
        return Err(
            ApiError::bad_request("confirm the deletion with ?confirm=<the vault's name>")
                .with_code("confirmation_required"),
        );
    }
    let before = snapshot(&st, vault_users(&st, &[id]).await).await;
    st.store.delete_vault(id).await?;
    st.sessions.close_for_vault(None, id).await;
    st.pool.invalidate_vault(id, None).await;
    apply_revocations(&st, before, &[id]).await;
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "vault.delete",
            Some(id.to_string()),
            json!({"name": vault.name}),
            id,
        )
        .await?;
    Ok(Json(json!({"ok": true})))
}

/// Gives up your own direct grant.
async fn leave(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    ctx.access.require(id, VaultRole::UseOnly)?;
    let before = snapshot(&st, [ctx.id()]).await;
    let m = st.store.leave_vault(id, ctx.id()).await?;
    apply_revocations(&st, before, &[]).await;
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "vault.member_removed",
            Some(m.id.to_string()),
            json!({"user": ctx.id(), "left": true}),
            id,
        )
        .await?;
    Ok(Json(json!({"ok": true})))
}

async fn members(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
) -> ApiResult<Json<Vec<VaultMember>>> {
    ctx.access.require(id, VaultRole::UseOnly)?;
    Ok(Json(st.store.vault_members(id).await?))
}

/// Users a grant reaches (a user, or the members of a team).
async fn grant_users(st: &AppState, m: &VaultMember) -> Vec<Id> {
    match &m.principal {
        termoak_core::model::VaultPrincipal::User { id, .. } => vec![*id],
        termoak_core::model::VaultPrincipal::Team { id, .. } => {
            st.store.team_member_ids(*id).await.unwrap_or_default()
        }
        termoak_core::model::VaultPrincipal::Unknown => Vec::new(),
    }
}

async fn add_member(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
    Json(req): Json<AddVaultMember>,
) -> ApiResult<Json<VaultMember>> {
    ctx.access.require(id, VaultRole::Manager)?;
    let (grantee, users) = match (req.email.as_deref(), req.team_id) {
        (Some(email), None) => {
            let user = st
                .store
                .user_by_email(email.trim())
                .await?
                .filter(|u| !u.disabled)
                .ok_or_else(|| {
                    ApiError::not_found("there is no user with that email")
                        .with_code("user_not_found")
                })?;
            (VaultGrantee::User(user.id), vec![user.id])
        }
        (None, Some(team)) => (
            VaultGrantee::Team(team),
            st.store.team_member_ids(team).await?,
        ),
        _ => {
            return Err(ApiError::bad_request(
                "give `email` or `team_id` (only one)",
            ));
        }
    };
    let before = snapshot(&st, users).await;
    let m = st
        .store
        .add_vault_member(id, ctx.id(), grantee, req.role)
        .await?;
    apply_revocations(&st, before, &[]).await;
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "vault.member_add",
            Some(m.id.to_string()),
            json!({"principal": m.principal, "role": m.role}),
            id,
        )
        .await?;
    Ok(Json(m))
}

async fn set_member_role(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path((id, member)): Path<(Id, Id)>,
    Json(req): Json<SetVaultMemberRole>,
) -> ApiResult<Json<VaultMember>> {
    ctx.access.require(id, VaultRole::Manager)?;
    let current = st.store.vault_member(id, member).await?;
    let before = snapshot(&st, grant_users(&st, &current).await).await;
    let m = st.store.set_vault_member_role(id, member, req.role).await?;
    apply_revocations(&st, before, &[]).await;
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "vault.role_changed",
            Some(m.id.to_string()),
            json!({"principal": m.principal, "from": current.role, "to": m.role}),
            id,
        )
        .await?;
    Ok(Json(m))
}

async fn remove_member(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path((id, member)): Path<(Id, Id)>,
) -> ApiResult<Json<Value>> {
    ctx.access.require(id, VaultRole::Manager)?;
    let current = st.store.vault_member(id, member).await?;
    let before = snapshot(&st, grant_users(&st, &current).await).await;
    let m = st.store.remove_vault_member(id, member).await?;
    apply_revocations(&st, before, &[]).await;
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "vault.member_removed",
            Some(m.id.to_string()),
            json!({"principal": m.principal}),
            id,
        )
        .await?;
    Ok(Json(json!({"ok": true})))
}

/// Moves or copies items into this vault (online). `dry_run` returns the
/// plan without writing.
async fn transfer(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(target): Path<Id>,
    Json(req): Json<TransferRequest>,
) -> ApiResult<Json<TransferResult>> {
    let mut sources = BTreeSet::new();
    for item in &req.items {
        if let Ok((_, v)) = st.store.locate_in(&ctx.access, item.id).await {
            sources.insert(v);
        }
    }
    let dry_run = req.dry_run;
    let mode = req.mode;
    let result = st.store.transfer(&ctx.access, target, req).await?;
    if !dry_run {
        sources.insert(target);
        for v in sources {
            st.store
                .audit_vault(
                    ctx.id(),
                    &ctx.actor(),
                    "vault.transfer",
                    Some(target.to_string()),
                    json!({
                        "mode": mode,
                        "target": target,
                        "moved": result.moved.len(),
                        "copied": result.copied.len(),
                    }),
                    v,
                )
                .await?;
        }
    }
    Ok(Json(result))
}

/// Audit of a vault (managers).
async fn audit(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<Vec<AuditEntry>>> {
    ctx.access.require(id, VaultRole::Manager)?;
    Ok(Json(
        st.store
            .vault_audit(id, q.before, q.limit.unwrap_or(100).clamp(1, 1000))
            .await?,
    ))
}

// --- Sync v2 -----------------------------------------------------------------

/// What a store has of a vault.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VaultCursor {
    pub vault_id: Uuid,
    /// Highest revision received for this vault (0: none).
    #[serde(default)]
    pub cursor: i64,
    /// The role the client last saw (to detect changes that need a resync).
    #[serde(default)]
    pub role: Option<VaultRole>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SyncV2Request {
    /// The vaults this store has, with their cursors.
    #[serde(default)]
    pub vaults: Vec<VaultCursor>,
    /// Dirty records, each with `vault_id` (missing: the personal vault).
    #[serde(default)]
    pub changes: Vec<SyncRecord>,
    /// Records per response (default 2000, max 5000).
    #[serde(default)]
    pub limit: Option<u32>,
}

/// An entity left a vault (moved, or the vault lost it).
#[derive(Debug, Serialize, ToSchema)]
pub struct RemovedRecord {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub kind: EntityKind,
    pub rev: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SyncV2Response {
    /// Every vault you can access, with your role (authoritative: a vault
    /// missing here was lost: wipe its local rows).
    pub vaults: Vec<Vault>,
    /// New cursor of every vault.
    pub cursors: Vec<VaultCursor>,
    /// Changes (always with `vault_id`; Use-only vaults: no `secret`, but
    /// `has_secret`).
    pub changes: Vec<SyncRecord>,
    /// Departures after the cursor: delete these rows where `vault_id`
    /// matches.
    pub removed: Vec<RemovedRecord>,
    pub accepted: Vec<Uuid>,
    pub rejected: Vec<SyncRejection>,
    pub warnings: Vec<SyncWarning>,
    /// Drop the local rows of these vaults and download them again (the
    /// role changed between Use-only and Editor). Their changes in this
    /// response already start from 0.
    pub resync: Vec<Uuid>,
    /// Call again: the limit cut the result.
    pub more: bool,
}

/// Sync protocol v2: per-vault cursors, the authoritative list of vaults,
/// departures and explicit rejections.
async fn sync_v2(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Json(req): Json<SyncV2Request>,
) -> ApiResult<Json<SyncV2Response>> {
    if req.changes.len() > 5000 {
        return Err(
            ApiError::bad_request("too many changes in a single request (max. 5000)")
                .with_code("too_many_changes"),
        );
    }
    let limit = req.limit.unwrap_or(2000).clamp(1, 5000) as usize;
    let access = ctx.access.clone();
    let report = st.store.apply_remote_v2(&access, req.changes).await?;
    let known: HashMap<Id, VaultCursor> = req.vaults.into_iter().map(|c| (c.vault_id, c)).collect();

    let mut resync = Vec::new();
    let mut cursors = Vec::new();
    let mut changes = Vec::new();
    let mut removed = Vec::new();
    let mut more = false;
    let mut remaining = limit;
    for (vault, role) in &access.roles {
        let (vault, role) = (*vault, *role);
        if !role.can_use() {
            continue;
        }
        let mut start = known.get(&vault).map_or(0, |c| c.cursor.max(0));
        if let Some(seen) = known.get(&vault).and_then(|c| c.role)
            && seen.can_read_secrets() != role.can_read_secrets()
        {
            resync.push(vault);
            start = 0;
        }
        if remaining == 0 {
            more = true;
            cursors.push(VaultCursor {
                vault_id: vault,
                cursor: start,
                role: Some(role),
            });
            continue;
        }
        let page = st
            .store
            .vault_changes(&access, vault, start, remaining)
            .await?;
        remaining -= page.items.len();
        more |= page.more;
        let cursor = page.cursor(start);
        for item in page.items {
            match item {
                VaultChange::Record(r) => changes.push(r),
                VaultChange::Departed { id, kind, rev, .. } => removed.push(RemovedRecord {
                    id,
                    vault_id: vault,
                    kind,
                    rev,
                }),
            }
        }
        cursors.push(VaultCursor {
            vault_id: vault,
            cursor,
            role: Some(role),
        });
    }
    // Stale pushes: the server's newer version goes back.
    if !report.stale.is_empty() {
        for r in st
            .store
            .sync_records_in(&access, report.stale.clone())
            .await?
        {
            if !changes.iter().any(|c: &SyncRecord| c.id == r.id) {
                changes.push(r);
            }
        }
    }
    Ok(Json(SyncV2Response {
        vaults: st.store.vaults_for(ctx.id()).await?,
        cursors,
        changes,
        removed,
        accepted: report.accepted,
        rejected: report.rejected,
        warnings: report.warnings,
        resync,
        more,
    }))
}
