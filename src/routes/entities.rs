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
use termoak_ssh::{ConnectOptions, Connection, StoreVerifier};
use utoipa::ToSchema;

use crate::auth::AuthUser;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

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
fn split_body<T: Entity>(
    mut body: Value,
) -> ApiResult<(T, SecretUpdate<T::Secret>, Option<SyncMode>)> {
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
    for meta in ["owner_id", "rev", "updated_at", "deleted", "has_secret"] {
        obj.remove(meta);
    }
    let data: T = serde_json::from_value(body)
        .map_err(|e| ApiError::bad_request(format!("invalid data: {e}")))?;
    Ok((data, secret, sync_mode))
}

async fn list<T: Entity>(
    State(st): State<AppState>,
    u: AuthUser,
) -> ApiResult<Json<Vec<Record<T>>>> {
    Ok(Json(st.store.list::<T>(u.id()).await?))
}

async fn one<T: Entity>(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<Record<T>>> {
    Ok(Json(st.store.get::<T>(u.id(), id).await?))
}

async fn create<T: Entity>(
    State(st): State<AppState>,
    u: AuthUser,
    Json(body): Json<Value>,
) -> ApiResult<Json<Record<T>>> {
    let (mut data, secret, mode) = split_body::<T>(body)?;
    data.set_id(Id::nil());
    let rec = st.store.save(u.id(), data, secret, mode).await?;
    Ok(Json(rec))
}

async fn update<T: Entity>(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Record<T>>> {
    st.store.get::<T>(u.id(), id).await?;
    let (mut data, secret, mode) = split_body::<T>(body)?;
    data.set_id(id);
    Ok(Json(st.store.save(u.id(), data, secret, mode).await?))
}

async fn remove<T: Entity>(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    st.store.delete::<T>(u.id(), id).await?;
    Ok(Json(json!({"ok": true})))
}

/// Reveals the secret (only the user's own; audited).
async fn reveal<T: Entity>(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<T::Secret>> {
    let secret = st.store.secret::<T>(u.id(), id).await?;
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "secret.reveal",
            Some(format!("{}:{id}", T::KIND.as_str())),
            json!({"device": u.device.name}),
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
}

#[allow(clippy::too_many_arguments)]
async fn save_key(
    st: &AppState,
    u: &AuthUser,
    label: String,
    material: keys::KeyMaterial,
    passphrase: Option<String>,
    store_passphrase: bool,
    certificate: Option<String>,
    sync_mode: Option<SyncMode>,
) -> ApiResult<Record<SshKey>> {
    let rec = st
        .store
        .save(
            u.id(),
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
        .audit(
            u.id(),
            &u.actor(),
            "key.create",
            Some(rec.data.id.to_string()),
            json!({"fingerprint": rec.data.fingerprint}),
        )
        .await?;
    Ok(rec)
}

async fn generate_key(
    State(st): State<AppState>,
    u: AuthUser,
    Json(req): Json<GenerateKey>,
) -> ApiResult<Json<Record<SshKey>>> {
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
            &u,
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
    u: AuthUser,
    Json(req): Json<ImportKey>,
) -> ApiResult<Json<Record<SshKey>>> {
    let pass = req.passphrase.clone().filter(|p| !p.is_empty());
    let material = keys::import_private(&req.private_key, pass.as_deref())?;
    Ok(Json(
        save_key(
            &st,
            &u,
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
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<HostSettings>> {
    let host = st.store.get::<Host>(u.id(), id).await?.data;
    Ok(Json(st.store.effective_settings(u.id(), &host).await?))
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

/// Tests the connection (from the server). With `?trust=true` it accepts a new key.
async fn test_host(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Query(q): Query<BTreeMap<String, String>>,
) -> ApiResult<Json<HostTest>> {
    let resolved = st.store.resolve_host(u.id(), id).await?;
    let trust = q.get("trust").is_some_and(|v| v == "true" || v == "1");
    let opts = ConnectOptions::new(Arc::new(StoreVerifier {
        store: st.store.clone(),
        owner: u.id(),
        policy: if trust {
            termoak_ssh::HostKeyPolicy::AcceptNew
        } else {
            termoak_ssh::HostKeyPolicy::Strict
        },
        prompter: None,
    }));
    let started = Instant::now();
    match Connection::connect(&resolved, &opts).await {
        Ok(conn) => {
            let latency = started.elapsed().as_millis() as u64;
            let info_os = termoak_ssh::detect::detect_os_info(&conn).await;
            let os = info_os.as_ref().map(|i| i.id.clone());
            if let Some(i) = &info_os {
                let mut host = resolved.host.clone();
                let version = Some(i.display());
                if host.os.as_deref() != Some(i.id.as_str()) || host.os_version != version {
                    host.os = Some(i.id.clone());
                    host.os_version = version;
                    st.store
                        .save(u.id(), host, SecretUpdate::Keep, None)
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

/// Two-way sync (last writer wins).
async fn sync(
    State(st): State<AppState>,
    u: AuthUser,
    Json(req): Json<SyncRequest>,
) -> ApiResult<Json<SyncResponse>> {
    if req.changes.len() > 5000 {
        return Err(
            ApiError::bad_request("too many changes in a single request (max. 5000)")
                .with_code("too_many_changes"),
        );
    }
    let applied = st.store.apply_remote(u.id(), req.changes).await?;
    let changes = st.store.changes_since(u.id(), req.since, true).await?;
    let rev = st.store.max_rev(u.id()).await?;
    Ok(Json(SyncResponse {
        rev,
        accepted: applied.iter().map(|r| r.id).collect(),
        changes,
    }))
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
async fn exec_many(
    State(st): State<AppState>,
    u: AuthUser,
    Json(req): Json<ExecRequest>,
) -> ApiResult<Json<Vec<ExecResult>>> {
    if req.host_ids.is_empty() || req.host_ids.len() > 200 {
        return Err(ApiError::bad_request("give between 1 and 200 hosts"));
    }
    let command = match (&req.command, req.snippet_id) {
        (Some(c), None) if !c.trim().is_empty() => c.clone(),
        (None, Some(sid)) => st
            .store
            .get::<Snippet>(u.id(), sid)
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
            u.id(),
            &u.actor(),
            "exec.batch",
            Some(batch_id.to_string()),
            json!({"hosts": req.host_ids, "command": command}),
        )
        .await?;
    let futures = req.host_ids.iter().map(|&host_id| {
        let st = st.clone();
        let command = command.clone();
        let owner = u.id();
        async move {
            let label = st
                .store
                .get::<Host>(owner, host_id)
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
