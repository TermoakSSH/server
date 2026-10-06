//! Entity CRUD (hosts, groups, identities, keys, snippets, tunnels, known
//! hosts, memories), keychain, sync and audit.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use termoak_core::model::*;
use termoak_core::{Id, new_id};
use termoak_ssh::exec::ExecOptions;
use termoak_ssh::keys::{self, KeyType};
use termoak_ssh::{ConnectOptions, Connection, HostKeyPolicy, StoreVerifier};
use utoipa::ToSchema;

use axum::http::header;
use axum::response::IntoResponse;
use termoak_core::error::codes;
use termoak_core::store::{SecretUse, VaultChange};

use crate::auth::AuthUser;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::vaults::AccessCtx;

pub fn routes() -> Router<AppState> {
    let mut r = Router::new();
    r = crud::<Host>(r, "hosts");
    r = crud::<Group>(r, "groups");
    r = crud::<Identity>(r, "identities");
    r = crud::<SshKey>(r, "keys");
    r = crud::<Snippet>(r, "snippets");
    r = crud::<PortForward>(r, "forwards");
    r = crud::<KnownHost>(r, "known-hosts");
    r = crud::<Memory>(r, "memories");
    r.route("/api/v1/keys/generate", post(generate_key))
        .route("/api/v1/keys/import", post(import_key))
        .route("/api/v1/hosts/{id}/test", post(test_host))
        .route("/api/v1/hosts/{id}/effective", get(effective))
        .route("/api/v1/hosts/{id}/credentials", post(credentials))
        .route("/api/v1/sync", post(sync))
        .route("/api/v1/audit", get(audit))
        .route("/api/v1/exec", post(exec_many))
}

fn crud<T: Entity>(r: Router<AppState>, name: &str) -> Router<AppState> {
    r.route(&format!("/api/v1/{name}"), get(list::<T>).post(create::<T>))
        .route(
            &format!("/api/v1/{name}/{{id}}"),
            get(one::<T>).put(update::<T>).delete(remove::<T>),
        )
        .route(&format!("/api/v1/{name}/{{id}}/secret"), get(reveal::<T>))
}

/// Splits `secret` and `sync_mode` off the body. `secret` missing = keep,
/// `null` = clear, object = replace.
fn split_body<T: Entity>(mut body: Value) -> ApiResult<Split<T>> {
    let obj = body
        .as_object_mut()
        .ok_or_else(|| ApiError::bad_request("expected a JSON object"))?;
    let secret = match obj.remove("secret") {
        None => SecretUpdate::Keep,
        Some(Value::Null) => SecretUpdate::Clear,
        Some(v) => SecretUpdate::Set(
            serde_json::from_value(v)
                .map_err(|e| ApiError::bad_request(format!("invalid secret: {e}")))?,
        ),
    };
    let sync_mode = match obj.remove("sync_mode") {
        None | Some(Value::Null) => None,
        Some(v) => {
            Some(serde_json::from_value(v).map_err(|e| ApiError::bad_request(e.to_string()))?)
        }
    };
    let vault_id = match obj.remove("vault_id") {
        None | Some(Value::Null) => None,
        Some(v) => Some(
            serde_json::from_value::<Id>(v)
                .map_err(|e| ApiError::bad_request(format!("invalid vault_id: {e}")))?,
        ),
    };
    for meta in [
        "owner_id",
        "rev",
        "updated_at",
        "deleted",
        "has_secret",
        "updated_by",
        "secret_hidden",
    ] {
        obj.remove(meta);
    }
    let data: T = serde_json::from_value(body)
        .map_err(|e| ApiError::bad_request(format!("invalid data: {e}")))?;
    Ok(Split {
        data,
        secret,
        sync_mode,
        vault_id,
    })
}

/// A create/update body taken apart.
struct Split<T: Entity> {
    data: T,
    secret: SecretUpdate<T::Secret>,
    sync_mode: Option<SyncMode>,
    vault_id: Option<Id>,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    vault_id: Option<Id>,
}

/// Items of every vault you can use (or of `?vault_id=`), each with
/// `vault_id` and `secret_hidden`. Never secrets.
async fn list<T: Entity>(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Vec<Record<T>>>> {
    Ok(Json(st.store.list_in::<T>(&ctx.access, q.vault_id).await?))
}

async fn one<T: Entity>(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
) -> ApiResult<Json<Record<T>>> {
    Ok(Json(st.store.get_in::<T>(&ctx.access, id).await?))
}

/// Creates in `vault_id` (default: your personal vault); needs Editor.
async fn create<T: Entity>(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Json(body): Json<Value>,
) -> ApiResult<Json<Record<T>>> {
    let mut b = split_body::<T>(body)?;
    b.data.set_id(Id::nil());
    let vault = b.vault_id.unwrap_or(ctx.personal());
    let rec = st
        .store
        .save_in(&ctx.access, vault, b.data, b.secret, b.sync_mode)
        .await?;
    Ok(Json(rec))
}

/// Updates in place (Editor). Another `vault_id` → 409 `use_transfer`.
async fn update<T: Entity>(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Record<T>>> {
    let current = st.store.get_in::<T>(&ctx.access, id).await?;
    let vault = current.meta.vault_id.unwrap_or(ctx.personal());
    let mut b = split_body::<T>(body)?;
    if b.vault_id.is_some_and(|v| v != vault) {
        return Err(ApiError::conflict(
            "the item is in another vault: move it with POST /vaults/{target}/transfer",
        )
        .with_code("use_transfer"));
    }
    b.data.set_id(id);
    Ok(Json(
        st.store
            .save_in(&ctx.access, vault, b.data, b.secret, b.sync_mode)
            .await?,
    ))
}

async fn remove<T: Entity>(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    st.store.delete_in::<T>(&ctx.access, id).await?;
    Ok(Json(json!({"ok": true})))
}

/// Reveals the secret (Editors only; Use-only → 403 `secret_hidden`).
/// Audited with the vault.
async fn reveal<T: Entity>(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
) -> ApiResult<Json<T::Secret>> {
    let vault = st.store.vault_of::<T>(&ctx.access, id).await?;
    let secret = st
        .store
        .secret_in::<T>(&ctx.access, id, SecretUse::Reveal)
        .await?;
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "secret.reveal",
            Some(format!("{}:{id}", T::KIND.as_str())),
            json!({"device": ctx.user.device.name}),
            vault,
        )
        .await?;
    Ok(Json(secret))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct GenerateKey {
    pub label: String,
    /// `ed25519` (recommended), `rsa4096`, `rsa3072`, `rsa2048`, `ecdsa_p256`, `ecdsa_p384`, `ecdsa_p521`.
    #[serde(default = "default_key_type")]
    pub key_type: String,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub passphrase: Option<String>,
    /// Store the passphrase in the vault (to use it without prompting).
    #[serde(default)]
    pub store_passphrase: bool,
    #[serde(default)]
    pub sync_mode: Option<SyncMode>,
    /// Vault to store it in (default: your personal vault; Editor).
    #[serde(default)]
    pub vault_id: Option<Uuid>,
}

fn default_key_type() -> String {
    "ed25519".into()
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ImportKey {
    pub label: String,
    pub private_key: String,
    #[serde(default)]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub store_passphrase: bool,
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub sync_mode: Option<SyncMode>,
    /// Vault to store it in (default: your personal vault; Editor).
    #[serde(default)]
    pub vault_id: Option<Uuid>,
}

#[allow(clippy::too_many_arguments)]
async fn save_key(
    st: &AppState,
    ctx: &AccessCtx,
    vault: Option<Id>,
    label: String,
    material: keys::KeyMaterial,
    passphrase: Option<String>,
    store_passphrase: bool,
    certificate: Option<String>,
    sync_mode: Option<SyncMode>,
) -> ApiResult<Record<SshKey>> {
    let vault = vault.unwrap_or(ctx.personal());
    let rec = st
        .store
        .save_in(
            &ctx.access,
            vault,
            SshKey {
                id: Id::nil(),
                label,
                algorithm: material.algorithm.clone(),
                public_key: material.public_openssh.clone(),
                fingerprint: material.fingerprint.clone(),
                comment: material.comment.clone(),
                has_passphrase: material.encrypted,
                certificate,
            },
            SecretUpdate::Set(SshKeySecret {
                private_key: Some(material.private_openssh.clone()),
                passphrase: if store_passphrase { passphrase } else { None },
            }),
            sync_mode,
        )
        .await?;
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "key.create",
            Some(rec.data.id.to_string()),
            json!({"fingerprint": rec.data.fingerprint}),
            vault,
        )
        .await?;
    Ok(rec)
}

async fn generate_key(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Json(req): Json<GenerateKey>,
) -> ApiResult<Json<Record<SshKey>>> {
    let vault = req.vault_id.unwrap_or(ctx.personal());
    ctx.access.require(vault, VaultRole::Editor)?;
    let u = &ctx.user;
    let kind =
        KeyType::parse(&req.key_type).ok_or_else(|| ApiError::bad_request("invalid key type"))?;
    let comment = req
        .comment
        .clone()
        .unwrap_or_else(|| format!("{}@termoak", u.user.name));
    let pass = req.passphrase.clone().filter(|p| !p.is_empty());
    let pass2 = pass.clone();
    let material =
        tokio::task::spawn_blocking(move || keys::generate(kind, &comment, pass2.as_deref()))
            .await
            .map_err(|e| ApiError::internal(e.to_string()))??;
    Ok(Json(
        save_key(
            &st,
            &ctx,
            Some(vault),
            req.label,
            material,
            pass,
            req.store_passphrase,
            None,
            req.sync_mode,
        )
        .await?,
    ))
}

async fn import_key(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Json(req): Json<ImportKey>,
) -> ApiResult<Json<Record<SshKey>>> {
    let pass = req.passphrase.clone().filter(|p| !p.is_empty());
    let material = keys::import_private(&req.private_key, pass.as_deref())?;
    Ok(Json(
        save_key(
            &st,
            &ctx,
            req.vault_id,
            req.label,
            material,
            pass,
            req.store_passphrase,
            req.certificate,
            req.sync_mode,
        )
        .await?,
    ))
}

async fn effective(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
) -> ApiResult<Json<HostSettings>> {
    let rec = st.store.get_in::<Host>(&ctx.access, id).await?;
    let vault = rec.meta.vault_id.unwrap_or(ctx.personal());
    Ok(Json(
        st.store
            .effective_settings_in(&ctx.access, vault, &rec.data)
            .await?,
    ))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HostTest {
    pub ok: bool,
    pub latency_ms: u64,
    pub fingerprint: Option<String>,
    pub key_type: Option<String>,
    pub os: Option<String>,
    pub banner: Option<String>,
    pub error: Option<String>,
    pub error_code: Option<String>,
}

/// Tests the connection (from the server). With `?trust=true` it accepts a
/// new key (saved in the host's vault if you are Editor there, otherwise in
/// your personal vault). Use-only members can test.
async fn test_host(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
    Query(q): Query<BTreeMap<String, String>>,
) -> ApiResult<Json<HostTest>> {
    let vault = st.store.vault_of::<Host>(&ctx.access, id).await?;
    let resolved = st
        .store
        .resolve_in(&ctx.access, id, SecretUse::Server)
        .await?;
    let trust = q.get("trust").is_some_and(|v| v == "true" || v == "1");
    let opts = ConnectOptions::new(Arc::new(StoreVerifier::for_host(
        st.store.clone(),
        ctx.access.clone(),
        vault,
        if trust {
            HostKeyPolicy::AcceptNew
        } else {
            HostKeyPolicy::Strict
        },
        None,
    )));
    let started = Instant::now();
    match Connection::connect(&resolved, &opts).await {
        Ok(conn) => {
            let latency = started.elapsed().as_millis() as u64;
            let info_os = termoak_ssh::detect::detect_os_info(&conn).await;
            let os = info_os.as_ref().map(|i| i.id.clone());
            // The detected OS is saved only by Editors (it is just metadata).
            if let Some(i) = &info_os
                && ctx.access.role(vault).is_some_and(|r| r.can_write())
            {
                let mut host = resolved.host.clone();
                let version = Some(i.display());
                if host.os.as_deref() != Some(i.id.as_str()) || host.os_version != version {
                    host.os = Some(i.id.clone());
                    host.os_version = version;
                    st.store
                        .save_in(&ctx.access, vault, host, SecretUpdate::Keep, None)
                        .await?;
                }
            }
            let info = conn.info().clone();
            conn.disconnect().await;
            Ok(Json(HostTest {
                ok: true,
                latency_ms: latency,
                fingerprint: info.server_fingerprint,
                key_type: info.server_key_type,
                os,
                banner: info.banner,
                error: None,
                error_code: None,
            }))
        }
        Err(e) => {
            let (code, fingerprint, key_type) = match &e {
                termoak_ssh::SshError::HostKeyUnknown {
                    fingerprint,
                    key_type,
                    ..
                } => (
                    "host_key_unknown",
                    Some(fingerprint.clone()),
                    Some(key_type.clone()),
                ),
                termoak_ssh::SshError::HostKeyChanged { actual, .. } => {
                    ("host_key_changed", Some(actual.clone()), None)
                }
                termoak_ssh::SshError::Auth { .. } => ("auth_failed", None, None),
                termoak_ssh::SshError::Timeout(_) => ("timeout", None, None),
                _ => ("connect_failed", None, None),
            };
            Ok(Json(HostTest {
                ok: false,
                latency_ms: started.elapsed().as_millis() as u64,
                fingerprint,
                key_type,
                os: None,
                banner: None,
                error: Some(e.to_string()),
                error_code: Some(code.into()),
            }))
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SyncRequest {
    /// Last revision received from the server (0 the first time).
    #[serde(default)]
    pub since: i64,
    /// Pending local changes.
    #[serde(default)]
    pub changes: Vec<SyncRecord>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SyncResponse {
    /// Current revision (keep it for the next `since`).
    pub rev: i64,
    /// Server changes after `since` (includes the ones just applied).
    pub changes: Vec<SyncRecord>,
    /// Ids of the accepted local changes.
    pub accepted: Vec<Uuid>,
}

/// Legacy two-way sync (apps before vaults): only the personal vault.
/// Items that left it (moved to another vault) come as deletions, so old
/// apps drop them; pushes land in the personal vault, or where the item is
/// now if you are Editor there.
async fn sync(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Json(req): Json<SyncRequest>,
) -> ApiResult<Json<SyncResponse>> {
    if req.changes.len() > 5000 {
        return Err(
            ApiError::bad_request("too many changes in a single request (max. 5000)")
                .with_code("too_many_changes"),
        );
    }
    let mut pushed = req.changes;
    for c in &mut pushed {
        c.vault_id = None;
        c.has_secret = None;
    }
    // What the old app has: its copy of each pushed item (for the deletions
    // below, which must not be older than it).
    let sent: BTreeMap<Id, (EntityKind, i64)> = pushed
        .iter()
        .map(|c| (c.id, (c.kind, c.updated_at)))
        .collect();
    let report = st.store.apply_remote_v2(&ctx.access, pushed).await?;
    let personal = ctx.personal();
    let page = st
        .store
        .vault_changes(&ctx.access, personal, req.since, 1_000_000)
        .await?;
    let mut changes: Vec<SyncRecord> = page
        .items
        .into_iter()
        .map(|c| match c {
            VaultChange::Record(mut r) => {
                r.vault_id = None;
                r
            }
            VaultChange::Departed { id, kind, rev, at } => tombstone(id, kind, rev, at),
        })
        .collect();
    // Pushes of items that are not in the personal vault (an old app's
    // copy of an item moved to another vault since): an edit applies where
    // the item is now if the user may change it there, a stale or refused
    // one does not; either way the old app must drop its copy. Its store
    // keeps the newest `updated_at`, so the deletion it gets is at least as
    // new as what it sent (the departure alone may be older than its edit).
    let mut gone: BTreeMap<Id, SyncRecord> = BTreeMap::new();
    for a in &report.applied {
        if a.vault_id.is_some_and(|v| v != personal) {
            gone.insert(a.id, tombstone(a.id, a.kind, a.rev, a.updated_at));
        }
    }
    // Stale pushes: the server's newer version goes back (personal), or
    // the deletion (elsewhere).
    if !report.stale.is_empty() {
        for mut r in st
            .store
            .sync_records_in(&ctx.access, report.stale.clone())
            .await?
        {
            if r.vault_id == Some(personal) {
                if !changes.iter().any(|c| c.id == r.id) {
                    r.vault_id = None;
                    changes.push(r);
                }
            } else {
                let at = sent
                    .get(&r.id)
                    .map_or(r.updated_at, |s| s.1.max(r.updated_at));
                gone.insert(r.id, tombstone(r.id, r.kind, r.rev, at));
            }
        }
    }
    // Refused because the id lives in a vault where the user cannot change
    // it (Use only) or cannot see it (never for a personal item).
    let refused: Vec<Id> = report
        .rejected
        .iter()
        .filter(|r| matches!(r.code.as_str(), codes::VAULT_READ_ONLY | codes::ID_IN_USE))
        .map(|r| r.id)
        .collect();
    if !refused.is_empty() {
        let in_personal: Vec<Id> = st
            .store
            .sync_records_in(&ctx.access, refused.clone())
            .await?
            .into_iter()
            .filter(|r| r.vault_id == Some(personal))
            .map(|r| r.id)
            .collect();
        for id in refused {
            if let Some((kind, at)) = sent.get(&id)
                && !in_personal.contains(&id)
            {
                gone.entry(id)
                    .or_insert_with(|| tombstone(id, *kind, page.head, *at));
            }
        }
    }
    if !gone.is_empty() {
        changes.retain(|c| !gone.contains_key(&c.id));
        changes.extend(gone.into_values());
    }
    Ok(Json(SyncResponse {
        rev: page.head.max(req.since),
        accepted: report.accepted,
        changes,
    }))
}

/// A departure as an old app understands it: a deletion.
pub fn tombstone(id: Id, kind: EntityKind, rev: i64, at: i64) -> SyncRecord {
    SyncRecord {
        id,
        kind,
        data: json!({}),
        secret: None,
        sync_mode: SyncMode::Synced,
        updated_at: at,
        deleted: true,
        rev,
        vault_id: None,
        has_secret: None,
        sealed: None,
        base_rev: None,
    }
}

#[derive(Debug, Deserialize)]
struct AuditQuery {
    before: Option<i64>,
    limit: Option<i64>,
}

async fn audit(
    State(st): State<AppState>,
    u: AuthUser,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<Vec<AuditEntry>>> {
    Ok(Json(
        st.store
            .audit_list(u.id(), q.before, q.limit.unwrap_or(100).clamp(1, 1000))
            .await?,
    ))
}

/// Just-in-time credentials, for a connection from the user's device.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CredentialsRequest {
    /// `ssh`, `sftp` or `forward` (audited).
    #[serde(default = "default_purpose")]
    pub purpose: String,
}

fn default_purpose() -> String {
    "ssh".into()
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CredentialKey {
    pub private_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
}

/// Credentials of one hop (the jumps first, the host last).
#[derive(Debug, Serialize, ToSchema)]
pub struct CredentialHop {
    pub host_id: Uuid,
    pub address: String,
    pub port: u16,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<CredentialKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_password: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Credentials {
    pub vault_id: Uuid,
    /// Keep them in memory until this time (ms) at most.
    pub expires_at: i64,
    pub hops: Vec<CredentialHop>,
}

/// Uses per user and minute of `/credentials`.
pub const CREDENTIALS_PER_MINUTE: usize = 30;

fn hop(r: &termoak_core::resolve::ResolvedHost) -> CredentialHop {
    CredentialHop {
        host_id: r.host.id,
        address: r.host.address.clone(),
        port: r.port,
        username: r.username.clone(),
        password: r.password.clone(),
        key: r.key.as_ref().map(|k| CredentialKey {
            private_key: k.private_key.clone(),
            passphrase: k.passphrase.clone(),
            certificate: k.certificate.clone(),
        }),
        proxy_password: r.proxy.as_ref().and_then(|p| p.password.clone()),
    }
}

/// `POST /hosts/{id}/credentials`: the resolved credentials of a host and
/// its jumps, for a connection made by the app. Editors always; Use-only
/// members only when the vault is not Strict (`use_only_strict`).
/// `Cache-Control: no-store`, rate limited and audited (`secret.use`).
async fn credentials(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
    body: Option<Json<CredentialsRequest>>,
) -> ApiResult<axum::response::Response> {
    let purpose = body.map(|b| b.0.purpose).unwrap_or_else(default_purpose);
    if !matches!(purpose.as_str(), "ssh" | "sftp" | "forward") {
        return Err(ApiError::bad_request(
            "purpose must be ssh, sftp or forward",
        ));
    }
    let key = format!("credentials:{}", ctx.id());
    if !st.credentials_limiter.allow(&key) {
        return Err(ApiError::new(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many credential requests: try again in a minute",
        )
        .with_detail("retry_ms", st.credentials_limiter.wait_ms(&key)));
    }
    let vault = st.store.vault_of::<Host>(&ctx.access, id).await?;
    let resolved = st
        .store
        .resolve_in(&ctx.access, id, SecretUse::Credentials)
        .await?;
    let mut hops: Vec<CredentialHop> = resolved.jumps.iter().map(hop).collect();
    hops.push(hop(&resolved));
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "secret.use",
            Some(format!("host:{id}")),
            json!({"device": ctx.user.device.name, "purpose": purpose}),
            vault,
        )
        .await?;
    let body = Credentials {
        vault_id: vault,
        expires_at: termoak_core::time::now_ms() + 60_000,
        hops,
    };
    Ok((
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(body),
    )
        .into_response())
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ExecRequest {
    pub host_ids: Vec<Uuid>,
    /// A direct command...
    #[serde(default)]
    pub command: Option<String>,
    /// ...or a snippet with its variables.
    #[serde(default)]
    pub snippet_id: Option<Uuid>,
    #[serde(default)]
    pub variables: BTreeMap<String, String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ExecResult {
    pub host_id: Uuid,
    pub label: String,
    pub ok: bool,
    pub exit_code: Option<u32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub error: Option<String>,
}

/// Runs a command or snippet on several hosts at once (from the server).
/// Use-only members can run it; each host is checked on its own.
async fn exec_many(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Json(req): Json<ExecRequest>,
) -> ApiResult<Json<Vec<ExecResult>>> {
    if req.host_ids.is_empty() || req.host_ids.len() > 200 {
        return Err(ApiError::bad_request("give between 1 and 200 hosts"));
    }
    let command = match (&req.command, req.snippet_id) {
        (Some(c), None) if !c.trim().is_empty() => c.clone(),
        (None, Some(sid)) => st
            .store
            .get_in::<Snippet>(&ctx.access, sid)
            .await?
            .data
            .render(&req.variables)?,
        _ => {
            return Err(ApiError::bad_request(
                "give `command` or `snippet_id` (only one)",
            ));
        }
    };
    let timeout = Duration::from_secs(req.timeout_secs.unwrap_or(120).clamp(1, 3600));
    let batch_id = new_id();
    st.store
        .audit(
            ctx.id(),
            &ctx.actor(),
            "exec.batch",
            Some(batch_id.to_string()),
            json!({"hosts": req.host_ids, "command": command}),
        )
        .await?;
    let futures = req.host_ids.iter().map(|&host_id| {
        let st = st.clone();
        let command = command.clone();
        let owner = ctx.id();
        let access = ctx.access.clone();
        async move {
            let label = st
                .store
                .get_in::<Host>(&access, host_id)
                .await
                .map(|h| h.data.label)
                .unwrap_or_else(|_| host_id.to_string());
            let result = async {
                let conn = st.pool.get(owner, host_id).await?;
                conn.exec(
                    &command,
                    &ExecOptions {
                        timeout,
                        max_output: 512 * 1024,
                        ..Default::default()
                    },
                )
                .await
            }
            .await;
            match result {
                Ok(out) => ExecResult {
                    host_id,
                    label,
                    ok: out.success(),
                    exit_code: out.exit_code,
                    stdout: out.stdout_text(),
                    stderr: out.stderr_text(),
                    duration_ms: out.duration_ms,
                    timed_out: out.timed_out,
                    error: None,
                },
                Err(e) => {
                    st.pool.invalidate(owner, host_id).await;
                    ExecResult {
                        host_id,
                        label,
                        ok: false,
                        exit_code: None,
                        stdout: String::new(),
                        stderr: String::new(),
                        duration_ms: 0,
                        timed_out: false,
                        error: Some(e.to_string()),
                    }
                }
            }
        }
    });
    Ok(Json(futures::future::join_all(futures).await))
}
