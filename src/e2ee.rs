//! End-to-end encrypted vaults (0.7 phase 5a, docs/E2EE-SSO-AUDIT.md §2):
//! users' E2EE keys and their sealed copies, pairing of new devices, and
//! turning a vault's end-to-end encryption on, rotating its key, adding
//! members' wraps and turning it off. The server stores blobs it cannot
//! open; it checks shapes, roles and completeness.

use axum::extract::{Path, State};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use termoak_core::Id;
use termoak_core::e2ee::{self, KeySeal};
use termoak_core::model::{
    E2eePairing, E2eePlainItem, E2eeSealedItem, E2eeVaultState, E2eeWrap, UserKeyInfo, VaultRole,
};
use utoipa::ToSchema;

use crate::auth::AuthUser;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::vaults::AccessCtx;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/me/e2ee", get(status).put(setup).delete(reset))
        .route("/api/v1/me/e2ee/seals", put(set_seal))
        .route("/api/v1/me/e2ee/passphrase", delete(remove_passphrase))
        .route("/api/v1/me/e2ee/rotate", post(rotate_user_key))
        .route(
            "/api/v1/me/e2ee/pairings",
            get(pairings).post(pairing_create),
        )
        .route("/api/v1/me/e2ee/pairings/{id}", get(pairing_one))
        .route("/api/v1/me/e2ee/pairings/{id}/decide", post(pairing_decide))
        .route("/api/v1/vaults/{id}/e2ee", get(vault_state))
        .route("/api/v1/vaults/{id}/e2ee/enable", post(enable))
        .route("/api/v1/vaults/{id}/e2ee/rotate", post(rotate))
        .route("/api/v1/vaults/{id}/e2ee/disable", post(disable))
        .route("/api/v1/vaults/{id}/e2ee/wraps", post(add_wraps))
}

/// `GET /me/e2ee`.
#[derive(Debug, Serialize, ToSchema)]
pub struct E2eeStatus {
    /// Your published E2EE key (`null`: not set up).
    pub key: Option<UserKeyInfo>,
    /// The copies of your private key sealed with your passphrase and
    /// recovery key (opaque to the server).
    pub seals: Vec<KeySeal>,
    /// Your devices waiting for approval.
    pub pairings: Vec<E2eePairing>,
}

async fn status(State(st): State<AppState>, u: AuthUser) -> ApiResult<Json<E2eeStatus>> {
    Ok(Json(E2eeStatus {
        key: st.store.user_key(u.id()).await?,
        seals: st.store.user_key_seals(u.id()).await?,
        pairings: st.store.e2ee_pairings(u.id()).await?,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetupE2ee {
    /// Chosen by the client (it is in the seals' AAD).
    pub key_id: uuid::Uuid,
    /// X25519 public key, base64.
    pub public_key: String,
    /// At least the recovery seal; a passphrase seal is optional.
    pub seals: Vec<KeySeal>,
}

async fn setup(
    State(st): State<AppState>,
    u: AuthUser,
    Json(req): Json<SetupE2ee>,
) -> ApiResult<Json<UserKeyInfo>> {
    let pk = e2ee::parse_public_key(&req.public_key)?;
    let info = st
        .store
        .e2ee_setup(u.id(), req.key_id, pk, req.seals.clone())
        .await?;
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "e2ee.setup",
            Some(info.id.to_string()),
            json!({"fingerprint": info.fingerprint, "seals": req.seals.iter().map(|s| s.kind).collect::<Vec<_>>(), "device": u.device.name}),
        )
        .await?;
    Ok(Json(info))
}

#[derive(Debug, Deserialize)]
struct ResetQuery {
    #[serde(default)]
    confirm: Option<String>,
}

/// Forgets your E2EE key (every device and the recovery key lost).
/// Without `?confirm=reset` it only lists the vaults nobody else could
/// open any more.
async fn reset(
    State(st): State<AppState>,
    u: AuthUser,
    axum::extract::Query(q): axum::extract::Query<ResetQuery>,
) -> ApiResult<Json<Value>> {
    let confirmed = q.confirm.as_deref() == Some("reset");
    let orphaned = st.store.e2ee_reset(u.id(), !confirmed).await?;
    if confirmed {
        st.store
            .audit(
                u.id(),
                &u.actor(),
                "e2ee.reset",
                None,
                json!({"orphaned_vaults": orphaned, "device": u.device.name}),
            )
            .await?;
    }
    Ok(Json(
        json!({"reset": confirmed, "orphaned_vaults": orphaned}),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetSeal {
    pub key_id: uuid::Uuid,
    pub seal: KeySeal,
}

async fn set_seal(
    State(st): State<AppState>,
    u: AuthUser,
    Json(req): Json<SetSeal>,
) -> ApiResult<Json<Value>> {
    let kind = req.seal.kind;
    st.store.e2ee_set_seal(u.id(), req.key_id, req.seal).await?;
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "e2ee.seal",
            Some(req.key_id.to_string()),
            json!({"kind": kind, "device": u.device.name}),
        )
        .await?;
    Ok(Json(json!({"ok": true})))
}

async fn remove_passphrase(State(st): State<AppState>, u: AuthUser) -> ApiResult<Json<Value>> {
    let removed = st.store.e2ee_remove_passphrase(u.id()).await?;
    if removed {
        st.store
            .audit(
                u.id(),
                &u.actor(),
                "e2ee.passphrase_removed",
                None,
                json!({"device": u.device.name}),
            )
            .await?;
    }
    Ok(Json(json!({"ok": true, "removed": removed})))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VaultWrapIn {
    pub vault_id: uuid::Uuid,
    pub version: u32,
    pub wrapped: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RotateUserKey {
    pub old_key_id: uuid::Uuid,
    pub key_id: uuid::Uuid,
    pub public_key: String,
    pub seals: Vec<KeySeal>,
    /// A new wrap of every vault key the old key holds (current versions).
    pub wraps: Vec<VaultWrapIn>,
}

async fn rotate_user_key(
    State(st): State<AppState>,
    u: AuthUser,
    Json(req): Json<RotateUserKey>,
) -> ApiResult<Json<UserKeyInfo>> {
    let pk = e2ee::parse_public_key(&req.public_key)?;
    let (info, vaults) = st
        .store
        .e2ee_rotate_user_key(
            u.id(),
            req.old_key_id,
            req.key_id,
            pk,
            req.seals,
            req.wraps
                .into_iter()
                .map(|w| (w.vault_id, w.version, w.wrapped))
                .collect(),
        )
        .await?;
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "e2ee.key_rotate",
            Some(info.id.to_string()),
            json!({"old_key": req.old_key_id, "fingerprint": info.fingerprint, "vaults": vaults.len()}),
        )
        .await?;
    Ok(Json(info))
}

// ---- pairings ----

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePairing {
    /// The new device's ephemeral X25519 public key, base64.
    pub public_key: String,
    #[serde(default)]
    pub device_name: Option<String>,
}

async fn pairing_create(
    State(st): State<AppState>,
    u: AuthUser,
    Json(req): Json<CreatePairing>,
) -> ApiResult<Json<E2eePairing>> {
    let pk = e2ee::parse_public_key(&req.public_key)?;
    let name = req
        .device_name
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| u.device.name.clone());
    let p = st
        .store
        .e2ee_pairing_create(u.id(), u.device.id, name, pk)
        .await?;
    st.vault_events.send(
        u.id(),
        json!({"type": "e2ee", "event": "pairing", "pairing": {"id": p.id, "device_name": p.device_name, "status": p.status, "expires_at": p.expires_at}}),
    );
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "e2ee.pairing_request",
            Some(p.id.to_string()),
            json!({"device": p.device_name, "device_id": u.device.id}),
        )
        .await?;
    Ok(Json(p))
}

async fn pairings(State(st): State<AppState>, u: AuthUser) -> ApiResult<Json<Vec<E2eePairing>>> {
    Ok(Json(st.store.e2ee_pairings(u.id()).await?))
}

async fn pairing_one(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<E2eePairing>> {
    Ok(Json(st.store.e2ee_pairing(u.id(), id, u.device.id).await?))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DecidePairing {
    pub approve: bool,
    /// With `approve`: the user key sealed for the pairing key (HPKE).
    #[serde(default)]
    pub sealed: Option<String>,
}

async fn pairing_decide(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Json(req): Json<DecidePairing>,
) -> ApiResult<Json<E2eePairing>> {
    if req.approve && req.sealed.is_none() {
        return Err(ApiError::bad_request("approving needs `sealed`"));
    }
    let sealed = if req.approve { req.sealed } else { None };
    let p = st
        .store
        .e2ee_pairing_decide(u.id(), id, u.device.id, sealed)
        .await?;
    st.vault_events.send(
        u.id(),
        json!({"type": "e2ee", "event": "pairing", "pairing": {"id": p.id, "device_name": p.device_name, "status": p.status, "expires_at": p.expires_at}}),
    );
    st.store
        .audit(
            u.id(),
            &u.actor(),
            if req.approve {
                "e2ee.pairing_approve"
            } else {
                "e2ee.pairing_deny"
            },
            Some(p.id.to_string()),
            json!({"device": p.device_name, "by_device": u.device.name}),
        )
        .await?;
    Ok(Json(p))
}

// ---- vaults ----

/// Key holders (Editors who may reveal, Admins) see what a rotation must
/// cover; managers also before turning it on.
async fn vault_state(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
) -> ApiResult<Json<E2eeVaultState>> {
    ctx.access.require(id, VaultRole::Editor)?;
    if !ctx.access.can_reveal(id) {
        return Err(ApiError::forbidden("you may not hold this vault's key")
            .with_code(termoak_core::error::codes::SECRET_REVEAL_FORBIDDEN));
    }
    Ok(Json(st.store.vault_e2ee_state(id).await?))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct EnableE2ee {
    /// `next_version` of `GET /vaults/{id}/e2ee` (it is in the AAD).
    pub version: u32,
    /// Your wrap and the members' you give the key now.
    pub wraps: Vec<E2eeWrap>,
    /// Every item with a secret, sealed with the new key.
    pub items: Vec<E2eeSealedItem>,
}

async fn enable(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
    Json(req): Json<EnableE2ee>,
) -> ApiResult<Json<Value>> {
    if !ctx.user.features.e2ee {
        return Err(ApiError::conflict("this client does not declare `e2ee`")
            .with_code(termoak_core::error::codes::E2EE_CLIENT_REQUIRED));
    }
    let (wraps, items) = (req.wraps.len(), req.items.len());
    let version = st
        .store
        .e2ee_enable(&ctx.access, id, req.version, req.wraps, req.items)
        .await?;
    // Server sessions keep running; new ones need a per-session unlock.
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "e2ee.enable",
            Some(id.to_string()),
            json!({"key_version": version, "wraps": wraps, "items": items, "device": ctx.user.device.name}),
            id,
        )
        .await?;
    Ok(Json(json!({"key_version": version})))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RotateE2ee {
    pub from_version: u32,
    pub wraps: Vec<E2eeWrap>,
    pub items: Vec<E2eeSealedItem>,
}

async fn rotate(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
    Json(req): Json<RotateE2ee>,
) -> ApiResult<Json<Value>> {
    let (wraps, items) = (req.wraps.len(), req.items.len());
    let version = st
        .store
        .e2ee_rotate(&ctx.access, id, req.from_version, req.wraps, req.items)
        .await?;
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "e2ee.rotate",
            Some(id.to_string()),
            json!({"key_version": version, "wraps": wraps, "items": items, "device": ctx.user.device.name}),
            id,
        )
        .await?;
    Ok(Json(json!({"key_version": version})))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DisableE2ee {
    /// Every item's secret in plaintext (over TLS).
    pub items: Vec<E2eePlainItem>,
}

async fn disable(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
    Json(req): Json<DisableE2ee>,
) -> ApiResult<Json<Value>> {
    let items = req.items.len();
    let version = st.store.e2ee_disable(&ctx.access, id, req.items).await?;
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "e2ee.disable",
            Some(id.to_string()),
            json!({"items": items, "device": ctx.user.device.name}),
            id,
        )
        .await?;
    Ok(Json(json!({"key_version": version})))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AddWraps {
    pub version: u32,
    pub wraps: Vec<E2eeWrap>,
}

async fn add_wraps(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
    Json(req): Json<AddWraps>,
) -> ApiResult<Json<Value>> {
    let users: Vec<Id> = req.wraps.iter().map(|w| w.user_id).collect();
    let n = st
        .store
        .e2ee_add_wraps(&ctx.access, id, req.version, req.wraps)
        .await?;
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "e2ee.wraps_add",
            Some(id.to_string()),
            json!({"users": users, "key_version": req.version}),
            id,
        )
        .await?;
    for u in users {
        st.vault_events.send(
            u,
            json!({"type": "vault", "event": "changed", "vault_id": id}),
        );
    }
    Ok(Json(json!({"added": n})))
}
