//! Teams security routes (0.7 phase 4b, docs-next/TEAMS-SECURITY.md §7):
//! the team and personal SSH CA, certificates, team policies and 2FA
//! compliance, access policies, temporary access requests, mandatory
//! recordings, plus the background job (expiring requests, ending windows,
//! retiring rotated CAs).

use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::Engine;
use serde::Deserialize;
use serde_json::{Value, json};
use termoak_core::access::{
    AccessMode, AccessPolicy, AccessPolicyRecord, AccessRequest, AccessRequestStatus,
    AccessTargetKind, TeamPolicy,
};
use termoak_core::error::codes;
use termoak_core::model::{
    Group, Host, Identity, SessionInfo, SessionStatus, SshKey, TeamRole, VaultKind, VaultRole,
};
use termoak_core::store::SecretUse;
use termoak_core::store::security::{CaOwner, CertFilter, CertSelector, RequestFilter};
use termoak_core::time::now_ms;
use termoak_core::{Id, new_id};
use termoak_ssh::ca;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{ApiError, ApiResult};
use crate::security::{CertPurpose, Security, covers};
use crate::state::AppState;
use crate::vaults::{AccessCtx, apply_revocations, snapshot};

/// Largest uploaded recording.
const MAX_RECORDING: usize = 64 * 1024 * 1024;
/// Certificates per user and minute.
pub const CERTS_PER_MINUTE: usize = 60;
/// Access requests per user and minute.
pub const REQUESTS_PER_MINUTE: usize = 10;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/teams/{id}/ca",
            get(team_ca).post(team_ca_create).delete(team_ca_disable),
        )
        .route("/api/v1/teams/{id}/ca/rotate", post(team_ca_rotate))
        .route("/api/v1/teams/{id}/ca/install.sh", get(team_ca_install))
        .route("/api/v1/teams/{id}/ca/krl", get(team_ca_krl))
        .route("/api/v1/teams/{id}/ca/certificates", get(team_ca_certs))
        .route("/api/v1/teams/{id}/ca/revoke", post(team_ca_revoke))
        .route(
            "/api/v1/me/ca",
            get(me_ca).post(me_ca_create).delete(me_ca_disable),
        )
        .route("/api/v1/me/ca/rotate", post(me_ca_rotate))
        .route("/api/v1/me/ca/install.sh", get(me_ca_install))
        .route("/api/v1/me/ca/krl", get(me_ca_krl))
        .route("/api/v1/me/ca/certificates", get(me_ca_certs))
        .route("/api/v1/me/ca/revoke", post(me_ca_revoke))
        .route("/api/v1/ssh-ca/{owner}/keys", get(public_keys))
        .route("/api/v1/ssh-ca/{owner}/krl", get(public_krl))
        .route(
            "/api/v1/teams/{id}/policy",
            get(team_policy).put(set_team_policy),
        )
        .route("/api/v1/teams/{id}/compliance", get(compliance))
        .route(
            "/api/v1/vaults/{id}/access-policies",
            get(access_policies).put(set_access_policy),
        )
        .route(
            "/api/v1/vaults/{id}/access-policies/{policy_id}",
            delete(delete_access_policy),
        )
        .route("/api/v1/hosts/{id}/access", get(host_access))
        .route(
            "/api/v1/access-requests",
            get(list_requests).post(create_request),
        )
        .route("/api/v1/access-requests/{id}", get(one_request))
        .route(
            "/api/v1/access-requests/{id}/approve",
            post(approve_request),
        )
        .route("/api/v1/access-requests/{id}/deny", post(deny_request))
        .route("/api/v1/access-requests/{id}/cancel", post(cancel_request))
        .route("/api/v1/access-requests/{id}/revoke", post(revoke_request))
        .route(
            "/api/v1/certificates",
            get(my_certificates).post(issue_certificate),
        )
        .route("/api/v1/vaults/{id}/recordings", get(vault_recordings))
        .route(
            "/api/v1/vaults/{id}/recordings/{session_id}",
            get(download_recording),
        )
}

/// `POST /recordings` (its own body limit).
pub fn upload_routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/recordings", post(upload_recording))
        .layer(DefaultBodyLimit::max(MAX_RECORDING))
}

// ---------------------------------------------------------------------------
// CA scope (a team or yourself)
// ---------------------------------------------------------------------------

/// Whose CA a route is about.
struct CaScope {
    owner: CaOwner,
    /// The team's name, or "personal".
    label: String,
    can_manage: bool,
    /// `/api/v1/teams/{id}/ca` or `/api/v1/me/ca`.
    base: String,
}

async fn team_scope(st: &AppState, u: &AuthUser, team: Id) -> ApiResult<CaScope> {
    let role = st.store.team_role(team, u.id()).await?;
    let role = if u.user.is_admin {
        Some(TeamRole::Owner)
    } else {
        role
    };
    let Some(role) = role else {
        return Err(ApiError::not_found("team not found"));
    };
    let label = match st.store.team_for(team, u.id()).await {
        Ok(t) => t.name,
        Err(_) => st
            .store
            .all_teams(u.id())
            .await?
            .into_iter()
            .find(|t| t.id == team)
            .map(|t| t.name)
            .ok_or_else(|| ApiError::not_found("team not found"))?,
    };
    Ok(CaScope {
        owner: CaOwner::Team(team),
        label,
        can_manage: role.can_manage(),
        base: format!("/api/v1/teams/{team}/ca"),
    })
}

fn me_scope(u: &AuthUser) -> CaScope {
    CaScope {
        owner: CaOwner::User(u.id()),
        label: "personal".into(),
        can_manage: true,
        base: "/api/v1/me/ca".into(),
    }
}

fn manage(scope: &CaScope) -> ApiResult<()> {
    if scope.can_manage {
        Ok(())
    } else {
        Err(
            ApiError::forbidden("only team owners and admins can do this")
                .with_code("team_admin_only"),
        )
    }
}

fn public_base(st: &AppState) -> String {
    st.config
        .server
        .public_url
        .clone()
        .unwrap_or_default()
        .trim_end_matches('/')
        .to_string()
}

const CA_FILE: &str = "/etc/ssh/termoak_user_ca.pub";
const KRL_FILE: &str = "/etc/ssh/termoak_revoked.krl";
const PRINCIPALS_DIR: &str = "/etc/ssh/termoak_principals";

async fn keys_file(st: &AppState, owner: CaOwner) -> ApiResult<String> {
    let cas = st.store.cas_of(owner).await?;
    Ok(cas
        .iter()
        .map(|c| format!("{}\n", c.public_key.trim()))
        .collect())
}

async fn ca_overview(st: &AppState, scope: &CaScope) -> ApiResult<Value> {
    let cas = st.store.cas_of(scope.owner).await?;
    let active = cas
        .iter()
        .find(|c| c.status == termoak_core::access::CaStatus::Active)
        .cloned();
    let previous: Vec<_> = cas
        .iter()
        .filter(|c| c.status != termoak_core::access::CaStatus::Active)
        .cloned()
        .collect();
    let base = public_base(st);
    let owner = scope.owner.id();
    Ok(json!({
        "ca": active,
        "previous": previous,
        "keys_file": keys_file(st, scope.owner).await?,
        "sshd_config": [format!("TrustedUserCAKeys {CA_FILE}")],
        "sshd_config_optional": [
            format!("RevokedKeys {KRL_FILE}"),
            format!("AuthorizedPrincipalsFile {PRINCIPALS_DIR}/%u"),
        ],
        "urls": {
            "keys": format!("{base}/api/v1/ssh-ca/{owner}/keys"),
            "krl": format!("{base}/api/v1/ssh-ca/{owner}/krl"),
            "install": format!("{base}{}/install.sh", scope.base),
        },
        "policy": st.security.ca_policy(scope.owner).await?,
        "can_manage": scope.can_manage,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCa {
    /// `ed25519` (default) or `ecdsa-p256`.
    #[serde(default)]
    pub algorithm: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RotateCa {
    /// Hours the old CA stays published (1-720, default 24).
    #[serde(default)]
    pub overlap_hours: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct ConfirmQuery {
    pub confirm: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct InstallQuery {
    #[serde(default)]
    pub krl: Option<String>,
    #[serde(default)]
    pub principals: Option<String>,
    #[serde(default)]
    pub refresh: Option<String>,
}

fn flag(v: &Option<String>) -> bool {
    v.as_deref()
        .is_some_and(|v| matches!(v, "1" | "true" | "yes" | "on"))
}

#[derive(Debug, Deserialize)]
pub struct CertListQuery {
    pub user_id: Option<Uuid>,
    pub active: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RevokeCerts {
    pub serial: Option<i64>,
    pub user_id: Option<Uuid>,
    pub public_key: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

async fn ca_audit(
    st: &AppState,
    u: &AuthUser,
    scope: &CaScope,
    action: &str,
    detail: Value,
) -> ApiResult<()> {
    st.store
        .audit(
            u.id(),
            &u.actor(),
            action,
            Some(scope.owner.id().to_string()),
            detail,
        )
        .await?;
    Ok(())
}

async fn do_ca(st: AppState, scope: CaScope) -> ApiResult<Json<Value>> {
    Ok(Json(ca_overview(&st, &scope).await?))
}

async fn do_ca_create(
    st: AppState,
    u: AuthUser,
    scope: CaScope,
    req: CreateCa,
) -> ApiResult<Json<Value>> {
    manage(&scope)?;
    let alg = ca::CaAlgorithm::parse(req.algorithm.as_deref().unwrap_or(""))
        .ok_or_else(|| ApiError::bad_request("algorithm must be ed25519 or ecdsa-p256"))?;
    let key = Security::new_ca_key(alg, &scope.label, u.id())?;
    let info = st.store.create_ca(scope.owner, key).await?;
    ca_audit(
        &st,
        &u,
        &scope,
        "ca.create",
        json!({"ca": info.id, "fingerprint": info.fingerprint, "algorithm": info.algorithm}),
    )
    .await?;
    changed_owner_vaults(&st, scope.owner).await;
    Ok(Json(ca_overview(&st, &scope).await?))
}

async fn do_ca_rotate(
    st: AppState,
    u: AuthUser,
    scope: CaScope,
    req: RotateCa,
) -> ApiResult<Json<Value>> {
    manage(&scope)?;
    let hours = req.overlap_hours.unwrap_or(24).clamp(1, 720);
    let old = st
        .store
        .cas_of(scope.owner)
        .await?
        .into_iter()
        .find(|c| c.status == termoak_core::access::CaStatus::Active)
        .ok_or_else(|| {
            ApiError::not_found("there is no certificate authority to rotate")
                .with_code(codes::CA_NOT_CONFIGURED)
        })?;
    let alg = ca::CaAlgorithm::parse(&old.algorithm).unwrap_or(ca::CaAlgorithm::Ed25519);
    let key = Security::new_ca_key(alg, &scope.label, u.id())?;
    let info = st
        .store
        .rotate_ca(scope.owner, key, now_ms() + i64::from(hours) * 3_600_000)
        .await?;
    ca_audit(&st, &u, &scope, "ca.rotate", json!({"ca": info.id, "fingerprint": info.fingerprint, "previous": old.fingerprint, "overlap_hours": hours})).await?;
    Ok(Json(ca_overview(&st, &scope).await?))
}

async fn do_ca_disable(
    st: AppState,
    u: AuthUser,
    scope: CaScope,
    q: ConfirmQuery,
) -> ApiResult<Json<Value>> {
    manage(&scope)?;
    if q.confirm.as_deref().map(str::trim) != Some(scope.label.trim()) {
        return Err(ApiError::bad_request(format!(
            "confirm with ?confirm={} (the team's name, or \"personal\")",
            scope.label
        ))
        .with_code("confirmation_required"));
    }
    let n = st.store.disable_ca(scope.owner).await?;
    ca_audit(&st, &u, &scope, "ca.disable", json!({"retired": n})).await?;
    changed_owner_vaults(&st, scope.owner).await;
    Ok(Json(json!({"ok": true, "retired": n})))
}

async fn do_ca_install(st: AppState, scope: CaScope, q: InstallQuery) -> ApiResult<Response> {
    manage(&scope)?;
    let keys = keys_file(&st, scope.owner).await?;
    if keys.trim().is_empty() {
        return Err(ApiError::not_found("there is no certificate authority yet")
            .with_code(codes::CA_NOT_CONFIGURED));
    }
    let krl = if flag(&q.krl) {
        Some(base64::engine::general_purpose::STANDARD.encode(st.security.krl(scope.owner).await?))
    } else {
        None
    };
    let base = public_base(&st);
    let refresh = (flag(&q.refresh) && base.starts_with("http")).then(|| {
        let o = scope.owner.id();
        (
            format!("{base}/api/v1/ssh-ca/{o}/keys"),
            format!("{base}/api/v1/ssh-ca/{o}/krl"),
        )
    });
    let script = install_script(
        &scope.label,
        &keys,
        krl.as_deref(),
        flag(&q.principals),
        refresh,
    );
    Ok((
        [
            (header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        script,
    )
        .into_response())
}

async fn do_ca_krl(st: AppState, scope: CaScope) -> ApiResult<Response> {
    manage(&scope)?;
    krl_response(&st, scope.owner).await
}

async fn krl_response(st: &AppState, owner: CaOwner) -> ApiResult<Response> {
    let krl = st.security.krl(owner).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        krl,
    )
        .into_response())
}

async fn do_ca_certs(st: AppState, scope: CaScope, q: CertListQuery) -> ApiResult<Json<Value>> {
    manage(&scope)?;
    let list = st
        .store
        .certificates(CertFilter {
            owner: Some(scope.owner),
            user: q.user_id,
            active_only: flag(&q.active),
            limit: q.limit.unwrap_or(200),
        })
        .await?;
    Ok(Json(json!(list)))
}

async fn do_ca_revoke(
    st: AppState,
    u: AuthUser,
    scope: CaScope,
    req: RevokeCerts,
) -> ApiResult<Json<Value>> {
    manage(&scope)?;
    let reason = req
        .reason
        .map(|r| r.trim().chars().take(500).collect::<String>())
        .filter(|r| !r.is_empty());
    let revoked = match (req.serial, req.user_id, req.public_key.as_deref()) {
        (Some(s), None, None) => {
            st.store
                .revoke_certificates(
                    Some(scope.owner),
                    CertSelector::Serial(s),
                    u.id(),
                    reason.clone(),
                )
                .await?
        }
        (None, Some(user), None) => {
            st.security.forget_user(user);
            st.store
                .revoke_certificates(
                    Some(scope.owner),
                    CertSelector::User(user),
                    u.id(),
                    reason.clone(),
                )
                .await?
        }
        (None, None, Some(pk)) => {
            let key = ca::parse_public_key(pk)
                .map_err(|e| ApiError::bad_request(format!("invalid public key: {e}")))?;
            let fp = ca::fingerprint(&key);
            let text = ca::public_key_text(&key).map_err(ApiError::from)?;
            st.store
                .revoke_key(scope.owner, &fp, &text, u.id(), reason.clone())
                .await?;
            let mut out = Vec::new();
            for c in st
                .store
                .certificates(CertFilter {
                    owner: Some(scope.owner),
                    active_only: true,
                    limit: 1000,
                    ..Default::default()
                })
                .await?
                .into_iter()
                .filter(|c| c.key_fingerprint == fp)
            {
                out.extend(
                    st.store
                        .revoke_certificates(
                            Some(scope.owner),
                            CertSelector::Serial(c.serial),
                            u.id(),
                            reason.clone(),
                        )
                        .await?,
                );
            }
            out
        }
        _ => {
            return Err(ApiError::bad_request(
                "give one of serial, user_id or public_key",
            ));
        }
    };
    ca_audit(&st, &u, &scope, "cert.revoke", json!({"serials": revoked, "user": req.user_id, "key": req.public_key.is_some(), "reason": reason})).await?;
    Ok(Json(json!({"revoked": revoked})))
}

/// Members re-read `Vault.policy` (`certificates` flag) of an owner's vaults.
async fn changed_owner_vaults(st: &AppState, owner: CaOwner) {
    let vaults: Vec<Id> = match owner {
        CaOwner::Team(t) => st
            .store
            .team_vaults(t)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|v| v.id)
            .collect(),
        CaOwner::User(u) => st
            .store
            .vaults_for(u)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|v| v.owner_user_id == Some(u))
            .map(|v| v.id)
            .collect(),
    };
    st.vault_events.changed(&vaults);
}

macro_rules! team_and_me {
    ($team:ident, $me:ident, $inner:ident $(, $extract:ident : $ty:ty)*) => {
        async fn $team(
            State(st): State<AppState>,
            u: AuthUser,
            Path(id): Path<Id>,
            $($extract: $ty,)*
        ) -> ApiResult<impl IntoResponse> {
            let scope = team_scope(&st, &u, id).await?;
            $inner(st, u, scope $(, team_and_me!(@unwrap $extract))*).await
        }
        async fn $me(
            State(st): State<AppState>,
            u: AuthUser,
            $($extract: $ty,)*
        ) -> ApiResult<impl IntoResponse> {
            let scope = me_scope(&u);
            $inner(st, u, scope $(, team_and_me!(@unwrap $extract))*).await
        }
    };
    (@unwrap $e:ident) => { $e.0 };
}

async fn ca_get(st: AppState, _u: AuthUser, scope: CaScope) -> ApiResult<Json<Value>> {
    do_ca(st, scope).await
}
async fn ca_create(
    st: AppState,
    u: AuthUser,
    scope: CaScope,
    req: CreateCa,
) -> ApiResult<Json<Value>> {
    do_ca_create(st, u, scope, req).await
}
async fn ca_rotate(
    st: AppState,
    u: AuthUser,
    scope: CaScope,
    req: RotateCa,
) -> ApiResult<Json<Value>> {
    do_ca_rotate(st, u, scope, req).await
}
async fn ca_disable(
    st: AppState,
    u: AuthUser,
    scope: CaScope,
    q: ConfirmQuery,
) -> ApiResult<Json<Value>> {
    do_ca_disable(st, u, scope, q).await
}
async fn ca_install(
    st: AppState,
    _u: AuthUser,
    scope: CaScope,
    q: InstallQuery,
) -> ApiResult<Response> {
    do_ca_install(st, scope, q).await
}
async fn ca_krl(st: AppState, _u: AuthUser, scope: CaScope) -> ApiResult<Response> {
    do_ca_krl(st, scope).await
}
async fn ca_certs(
    st: AppState,
    _u: AuthUser,
    scope: CaScope,
    q: CertListQuery,
) -> ApiResult<Json<Value>> {
    do_ca_certs(st, scope, q).await
}
async fn ca_revoke(
    st: AppState,
    u: AuthUser,
    scope: CaScope,
    req: RevokeCerts,
) -> ApiResult<Json<Value>> {
    do_ca_revoke(st, u, scope, req).await
}

team_and_me!(team_ca, me_ca, ca_get);
team_and_me!(team_ca_create, me_ca_create, ca_create, body: Json<CreateCa>);
team_and_me!(team_ca_rotate, me_ca_rotate, ca_rotate, body: Json<RotateCa>);
team_and_me!(team_ca_disable, me_ca_disable, ca_disable, q: Query<ConfirmQuery>);
team_and_me!(team_ca_install, me_ca_install, ca_install, q: Query<InstallQuery>);
team_and_me!(team_ca_krl, me_ca_krl, ca_krl);
team_and_me!(team_ca_certs, me_ca_certs, ca_certs, q: Query<CertListQuery>);
team_and_me!(team_ca_revoke, me_ca_revoke, ca_revoke, body: Json<RevokeCerts>);

/// The owner of a public CA URL (team first, then user).
async fn public_owner(st: &AppState, owner: Id) -> ApiResult<CaOwner> {
    for o in [CaOwner::Team(owner), CaOwner::User(owner)] {
        if !st.store.ca_history(o).await?.is_empty() {
            return Ok(o);
        }
    }
    Err(ApiError::not_found("unknown certificate authority"))
}

/// `TrustedUserCAKeys` file of an owner (public).
async fn public_keys(State(st): State<AppState>, Path(owner): Path<Id>) -> ApiResult<Response> {
    let owner = public_owner(&st, owner).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        keys_file(&st, owner).await?,
    )
        .into_response())
}

/// KRL of an owner (public).
async fn public_krl(State(st): State<AppState>, Path(owner): Path<Id>) -> ApiResult<Response> {
    let owner = public_owner(&st, owner).await?;
    krl_response(&st, owner).await
}

/// The host install script (POSIX sh, public data only).
fn install_script(
    label: &str,
    keys: &str,
    krl_b64: Option<&str>,
    principals: bool,
    refresh: Option<(String, String)>,
) -> String {
    let label: String = label.chars().filter(|c| !c.is_control()).take(80).collect();
    let mut lines = vec![format!("TrustedUserCAKeys {CA_FILE}")];
    if krl_b64.is_some() {
        lines.push(format!("RevokedKeys {KRL_FILE}"));
    }
    if principals {
        lines.push(format!("AuthorizedPrincipalsFile {PRINCIPALS_DIR}/%u"));
    }
    let mut s = format!(
        r#"#!/bin/sh
# Termoak: trust the SSH certificate authority "{label}".
# Generated {date}. Run as root on each host; safe to run again.
# It only contains public data (CA public keys{krl_note}).
set -eu
[ "$(id -u)" = 0 ] || {{ echo "termoak: run this as root" >&2; exit 1; }}
SSHD_CONFIG=/etc/ssh/sshd_config
CA_FILE={CA_FILE}
KRL_FILE={KRL_FILE}
SSHD=$(command -v sshd || echo /usr/sbin/sshd)
umask 022
cat > "$CA_FILE.new" <<'TERMOAK_CA_KEYS'
{keys}TERMOAK_CA_KEYS
mv "$CA_FILE.new" "$CA_FILE"
"#,
        date = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC"),
        krl_note = if krl_b64.is_some() {
            " and the revocation list"
        } else {
            ""
        },
        keys = keys,
    );
    if let Some(b64) = krl_b64 {
        s.push_str(&format!(
            "printf '%s' '{b64}' | base64 -d > \"$KRL_FILE.new\"\nmv \"$KRL_FILE.new\" \"$KRL_FILE\"\n"
        ));
    }
    if principals {
        s.push_str(&format!(
            "mkdir -p {PRINCIPALS_DIR}\nchmod 755 {PRINCIPALS_DIR}\n# One file per login user: {PRINCIPALS_DIR}/<user> with the principals allowed\n# to log in as that user, one per line (e.g. prod-admin).\n"
        ));
    }
    s.push_str(&format!(
        r##"BLOCK="# BEGIN termoak
{lines}
# END termoak"
if [ -d /etc/ssh/sshd_config.d ] && grep -Eqi '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_CONFIG"; then
  TARGET=/etc/ssh/sshd_config.d/10-termoak.conf
  [ -f "$TARGET" ] && cp -p "$TARGET" "$TARGET.termoak.bak"
  printf '%s\n' "$BLOCK" > "$TARGET"
else
  TARGET=$SSHD_CONFIG
  cp -p "$SSHD_CONFIG" "$SSHD_CONFIG.termoak.bak"
  # At the top: sshd keeps the first value, and nothing after a Match block
  # applies globally.
  sed '/^# BEGIN termoak$/,/^# END termoak$/d' "$SSHD_CONFIG.termoak.bak" > "$SSHD_CONFIG.termoak.tmp"
  {{ printf '%s\n' "$BLOCK"; cat "$SSHD_CONFIG.termoak.tmp"; }} > "$SSHD_CONFIG"
  rm -f "$SSHD_CONFIG.termoak.tmp"
fi
if ! "$SSHD" -t; then
  echo "termoak: sshd -t failed, restoring the previous configuration" >&2
  if [ "$TARGET" = "$SSHD_CONFIG" ]; then
    mv "$SSHD_CONFIG.termoak.bak" "$SSHD_CONFIG"
  elif [ -f "$TARGET.termoak.bak" ]; then
    mv "$TARGET.termoak.bak" "$TARGET"
  else
    rm -f "$TARGET"
  fi
  exit 1
fi
"##,
        lines = lines.join("\n"),
    ));
    if let Some((keys_url, krl_url)) = refresh {
        let krl_line = if krl_b64.is_some() {
            format!(" && curl -fsS {krl_url} -o {KRL_FILE}.tmp && mv {KRL_FILE}.tmp {KRL_FILE}")
        } else {
            String::new()
        };
        s.push_str(&format!(
            "if [ -d /etc/cron.d ] && command -v curl >/dev/null 2>&1; then\n  echo '*/15 * * * * root curl -fsS {keys_url} -o {CA_FILE}.tmp && mv {CA_FILE}.tmp {CA_FILE}{krl_line}' > /etc/cron.d/termoak-ca\n  chmod 644 /etc/cron.d/termoak-ca\nfi\n"
        ));
    }
    s.push_str(
        r#"if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ssh 2>/dev/null; then
  systemctl reload ssh
elif command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet sshd 2>/dev/null; then
  systemctl reload sshd
elif command -v service >/dev/null 2>&1; then
  service ssh reload 2>/dev/null || service sshd reload 2>/dev/null || true
elif [ -f /var/run/sshd.pid ]; then
  kill -HUP "$(cat /var/run/sshd.pid)"
fi
echo "termoak: this host now trusts the certificate authority."
"#,
    );
    s
}

// ---------------------------------------------------------------------------
// Team policy and compliance
// ---------------------------------------------------------------------------

async fn team_policy(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<TeamPolicy>> {
    team_scope(&st, &u, id).await?;
    Ok(Json(st.store.team_policy(id).await?))
}

/// Replaces a team's policy (owners and admins).
async fn set_team_policy(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Json(mut policy): Json<TeamPolicy>,
) -> ApiResult<Json<TeamPolicy>> {
    let scope = team_scope(&st, &u, id).await?;
    manage(&scope)?;
    policy
        .validate()
        .map_err(|e| ApiError::bad_request(e.to_string()).with_code("invalid_policy"))?;
    let old = st.store.team_policy(id).await?;
    if policy.require_2fa {
        if !u.user.totp_enabled {
            return Err(ApiError::conflict(
                "turn on two-step verification for yourself before requiring it",
            )
            .with_code(codes::POLICY_REQUIRES_2FA));
        }
        policy.require_2fa_since = if old.require_2fa {
            old.require_2fa_since.or(Some(now_ms()))
        } else {
            Some(now_ms())
        };
    } else {
        policy.require_2fa_since = None;
    }
    let members = st.store.team_member_ids(id).await?;
    let mut users = members.clone();
    for v in st.store.team_vaults(id).await? {
        users.extend(st.store.vault_user_ids(v.id).await.unwrap_or_default());
    }
    users.sort();
    users.dedup();
    let before = snapshot(&st, users.clone()).await;
    let vaults = st.store.set_team_policy(id, policy.clone()).await?;
    apply_revocations(&st, before, &[]).await;
    st.vault_events.changed(&vaults);
    for user in &users {
        st.security.forget_user(*user);
        st.vault_events.send(
            *user,
            json!({"type": "team", "event": "policy", "team_id": id}),
        );
    }
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "team.policy",
            Some(id.to_string()),
            json!({"before": old, "after": policy}),
        )
        .await?;
    Ok(Json(policy))
}

/// Members and their 2FA state (owners and admins).
async fn compliance(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    let scope = team_scope(&st, &u, id).await?;
    manage(&scope)?;
    let policy = st.store.team_policy(id).await?;
    let now = now_ms();
    let mut members = Vec::new();
    for m in st.store.team_compliance(id).await? {
        let deadline = (!m.totp_enabled)
            .then(|| policy.twofa_deadline(m.added_at))
            .flatten();
        members.push(json!({
            "user_id": m.user_id,
            "email": m.email,
            "name": m.name,
            "role": m.role.as_str(),
            "totp_enabled": m.totp_enabled,
            "deadline": deadline,
            "blocked": deadline.is_some_and(|d| d <= now),
            "principal": st.store.team_member_principal(id, m.user_id).await?,
        }));
    }
    Ok(Json(json!({
        "require_2fa": policy.require_2fa,
        "grace_days": policy.grace_days,
        "members": members,
    })))
}

/// Teams that require 2FA from a user without it (login and `/me`).
pub async fn team_2fa(
    st: &AppState,
    user: &termoak_core::model::User,
) -> Vec<termoak_core::access::Team2fa> {
    if user.totp_enabled {
        return Vec::new();
    }
    let now = now_ms();
    st.store
        .teams_with_policy(user.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(id, name, p, joined)| {
            p.twofa_deadline(joined)
                .map(|deadline| termoak_core::access::Team2fa {
                    team_id: id,
                    team_name: name,
                    deadline,
                    blocked: deadline <= now,
                })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Access policies
// ---------------------------------------------------------------------------

async fn access_policies(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
) -> ApiResult<Json<Vec<AccessPolicyRecord>>> {
    ctx.access.require(id, VaultRole::ConnectOnly)?;
    Ok(Json(st.store.access_policies(id).await?))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetAccessPolicy {
    pub target_kind: AccessTargetKind,
    pub target_id: Uuid,
    pub policy: AccessPolicy,
}

/// Creates or replaces the policy of a host, group or the vault (managers).
async fn set_access_policy(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
    Json(req): Json<SetAccessPolicy>,
) -> ApiResult<Json<AccessPolicyRecord>> {
    ctx.access.require(id, VaultRole::Manager)?;
    let vault = st.store.vault(id).await?;
    if vault.kind == VaultKind::Personal {
        return Err(
            ApiError::conflict("the personal vault has no access policies")
                .with_code("vault_personal"),
        );
    }
    match req.target_kind {
        AccessTargetKind::Host => {
            if st
                .store
                .vault_of::<Host>(&ctx.access, req.target_id)
                .await?
                != id
            {
                return Err(ApiError::not_found("host not found in this vault"));
            }
        }
        AccessTargetKind::Group => {
            if st
                .store
                .vault_of::<Group>(&ctx.access, req.target_id)
                .await?
                != id
            {
                return Err(ApiError::not_found("group not found in this vault"));
            }
        }
        AccessTargetKind::Vault if req.target_id == id => {}
        _ => {
            return Err(ApiError::bad_request(
                "target_kind must be host, group or vault (this vault)",
            ));
        }
    }
    req.policy
        .validate()
        .map_err(|e| ApiError::bad_request(e.to_string()).with_code("invalid_policy"))?;
    for a in &req.policy.approvers {
        if st.store.effective_role(id, *a).await?.is_none() {
            return Err(
                ApiError::bad_request(format!("approver {a} has no access to this vault"))
                    .with_code("invalid_approver"),
            );
        }
    }
    let rec = st
        .store
        .set_access_policy(id, req.target_kind, req.target_id, req.policy, ctx.id())
        .await?;
    st.security.forget_all();
    st.vault_events.changed(&[id]);
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "access_policy.set",
            Some(format!("{}:{}", rec.target_kind.as_str(), rec.target_id)),
            json!({"policy": rec.policy}),
            id,
        )
        .await?;
    Ok(Json(rec))
}

async fn delete_access_policy(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path((id, policy_id)): Path<(Id, Id)>,
) -> ApiResult<Json<Value>> {
    ctx.access.require(id, VaultRole::Manager)?;
    let rec = st.store.delete_access_policy(id, policy_id).await?;
    st.security.forget_all();
    st.vault_events.changed(&[id]);
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "access_policy.delete",
            Some(format!("{}:{}", rec.target_kind.as_str(), rec.target_id)),
            json!({}),
            id,
        )
        .await?;
    Ok(Json(json!({"ok": true})))
}

async fn host_access(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
) -> ApiResult<Json<termoak_core::access::HostAccess>> {
    Ok(Json(st.security.host_access(&ctx.access, id).await?))
}

// ---------------------------------------------------------------------------
// Access requests
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateAccessRequest {
    pub host_id: Option<Uuid>,
    pub group_id: Option<Uuid>,
    pub vault_id: Option<Uuid>,
    pub minutes: u32,
    pub reason: String,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct DecideRequest {
    /// Approve: a shorter window than asked (never longer).
    #[serde(default)]
    pub minutes: Option<u32>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RequestListQuery {
    /// `mine` (default), `approvals` or `vault` (with `vault_id`).
    pub scope: Option<String>,
    pub status: Option<String>,
    pub vault_id: Option<Uuid>,
    pub limit: Option<usize>,
}

/// The policy that applies to a request's target (`None`: none now).
async fn target_policy(
    st: &AppState,
    access: &termoak_core::store::VaultAccess,
    vault: Id,
    kind: AccessTargetKind,
    target: Id,
) -> ApiResult<Option<AccessPolicyRecord>> {
    match kind {
        AccessTargetKind::Host => {
            let host = st.store.get_in::<Host>(access, target).await?.data;
            let groups = st.security.host_groups(access, &host).await;
            st.security.effective_policy(vault, host.id, &groups).await
        }
        AccessTargetKind::Group => {
            let mut groups = vec![target];
            let mut next = st
                .store
                .get_in::<Group>(access, target)
                .await?
                .data
                .parent_id;
            while let Some(g) = next {
                if groups.contains(&g) || groups.len() >= 16 {
                    break;
                }
                groups.push(g);
                next = st
                    .store
                    .get_in::<Group>(access, g)
                    .await
                    .ok()
                    .and_then(|r| r.data.parent_id);
            }
            // No host: only group and vault policies apply.
            st.security
                .effective_policy(vault, Id::nil(), &groups)
                .await
        }
        AccessTargetKind::Vault => st.security.effective_policy(vault, Id::nil(), &[]).await,
        AccessTargetKind::Unknown => Ok(None),
    }
}

/// A policy to decide with when the target has none any more: its
/// managers decide.
fn fallback_policy(vault: Id) -> AccessPolicyRecord {
    AccessPolicyRecord {
        id: Id::nil(),
        vault_id: vault,
        target_kind: AccessTargetKind::Vault,
        target_id: vault,
        policy: AccessPolicy {
            mode: AccessMode::Approval,
            ..Default::default()
        },
        updated_by: Id::nil(),
        updated_at: 0,
    }
}

async fn request_json(st: &AppState, me: Id, req: &AccessRequest) -> Value {
    let mut v = json!(req);
    let can_decide = match st.store.vault_access(me).await {
        Ok(access) if access.role(req.vault_id).is_some() => {
            let policy = target_policy(st, &access, req.vault_id, req.target_kind, req.target_id)
                .await
                .ok()
                .flatten()
                .unwrap_or_else(|| fallback_policy(req.vault_id));
            let approver = st.security.is_approver(me, req.vault_id, &policy).await;
            match req.status {
                AccessRequestStatus::Pending => {
                    approver && (req.requester_id != me || policy.policy.allow_self_approval)
                }
                AccessRequestStatus::Approved if req.active => {
                    approver || access.role(req.vault_id) == Some(VaultRole::Manager)
                }
                _ => false,
            }
        }
        _ => false,
    };
    v["can_decide"] = json!(can_decide);
    v
}

/// Sends the event to the requester and the approvers, and the pushes.
async fn notify(st: &AppState, req: &AccessRequest, event: &str, approvers: &[Id]) {
    let v = json!({"type": "access_request", "event": event, "request": req});
    st.vault_events.send(req.requester_id, v.clone());
    for a in approvers {
        if *a != req.requester_id {
            st.vault_events.send(*a, v.clone());
        }
    }
    let Some(push) = &st.push else {
        return;
    };
    match event {
        "created" => {
            for a in approvers {
                if *a != req.requester_id {
                    let name = if req.requester_name.is_empty() {
                        req.requester_email.clone()
                    } else {
                        req.requester_name.clone()
                    };
                    push.access_request(*a, req.id, &name, &req.target_label, Some(req.expires_at));
                }
            }
        }
        _ => {
            for a in approvers {
                push.access_request_resolved(*a, req.id);
            }
            if matches!(event, "approved" | "denied" | "revoked" | "expired") {
                push.access_decided(req.requester_id, req.id, event, &req.target_label);
            }
        }
    }
}

async fn approvers_of(st: &AppState, req: &AccessRequest) -> Vec<Id> {
    let access = match st.store.vault_access(req.requester_id).await {
        Ok(a) => a,
        Err(_) => return Vec::new(),
    };
    // The requester may have lost access: use any manager's view then.
    let policy = target_policy(st, &access, req.vault_id, req.target_kind, req.target_id)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| fallback_policy(req.vault_id));
    st.security.approvers(req.vault_id, &policy).await
}

async fn create_request(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Json(req): Json<CreateAccessRequest>,
) -> ApiResult<Json<Value>> {
    let key = format!("access-request:{}", ctx.id());
    if !st.request_limiter.allow(&key) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many access requests: try again in a minute",
        )
        .with_detail("retry_ms", st.request_limiter.wait_ms(&key)));
    }
    let (kind, target, vault, label) = match (req.host_id, req.group_id, req.vault_id) {
        (Some(h), None, None) => {
            let rec = st.store.get_in::<Host>(&ctx.access, h).await?;
            let vault = rec.meta.vault_id.unwrap_or(ctx.personal());
            (AccessTargetKind::Host, h, vault, rec.data.label)
        }
        (None, Some(g), None) => {
            let rec = st.store.get_in::<Group>(&ctx.access, g).await?;
            let vault = rec.meta.vault_id.unwrap_or(ctx.personal());
            (AccessTargetKind::Group, g, vault, rec.data.name)
        }
        (None, None, Some(v)) => {
            ctx.access.require(v, VaultRole::ConnectOnly)?;
            let vault = st.store.vault(v).await?;
            (AccessTargetKind::Vault, v, v, vault.name)
        }
        _ => {
            return Err(ApiError::bad_request(
                "give one of host_id, group_id or vault_id",
            ));
        }
    };
    let reason = req.reason.trim().to_string();
    if reason.is_empty() || reason.chars().count() > 500 {
        return Err(
            ApiError::bad_request("give a reason (1-500 characters)").with_code("invalid_reason")
        );
    }
    let policy = target_policy(&st, &ctx.access, vault, kind, target).await?;
    let Some(policy) = policy.filter(|p| p.policy.mode.requires_approval()) else {
        return Err(
            ApiError::conflict("this does not need an approval: connect directly")
                .with_code(codes::ACCESS_REQUEST_NOT_NEEDED),
        );
    };
    if ctx.access.role(vault) == Some(VaultRole::Manager) && !policy.policy.require_for_managers {
        return Err(
            ApiError::conflict("vault managers do not need an approval here")
                .with_code(codes::ACCESS_REQUEST_NOT_NEEDED),
        );
    }
    if req.minutes == 0 || req.minutes > policy.policy.max_minutes {
        return Err(ApiError::bad_request(format!(
            "ask for 1-{} minutes",
            policy.policy.max_minutes
        ))
        .with_code(codes::ACCESS_DURATION_TOO_LONG)
        .with_detail("max_minutes", policy.policy.max_minutes));
    }
    let now = now_ms();
    let created = st
        .store
        .create_access_request(AccessRequest {
            id: new_id(),
            vault_id: vault,
            target_kind: kind,
            target_id: target,
            target_label: label.chars().take(200).collect(),
            requester_id: ctx.id(),
            requester_name: String::new(),
            requester_email: String::new(),
            reason,
            minutes: req.minutes,
            status: AccessRequestStatus::Pending,
            created_at: now,
            expires_at: now + i64::from(policy.policy.request_ttl_minutes) * 60_000,
            decided_by: None,
            decided_by_name: None,
            decided_at: None,
            decision_reason: None,
            starts_at: None,
            ends_at: None,
            self_approved: false,
            active: false,
        })
        .await?;
    let approvers = st.security.approvers(vault, &policy).await;
    notify(&st, &created, "created", &approvers).await;
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "access.request",
            Some(format!("{}:{}", kind.as_str(), target)),
            json!({"request": created.id, "minutes": created.minutes, "reason": created.reason, "approvers": approvers.len()}),
            vault,
        )
        .await?;
    Ok(Json(request_json(&st, ctx.id(), &created).await))
}

async fn list_requests(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Query(q): Query<RequestListQuery>,
) -> ApiResult<Json<Vec<Value>>> {
    let status = q
        .status
        .as_deref()
        .map(AccessRequestStatus::parse)
        .filter(|s| *s != AccessRequestStatus::Unknown);
    let limit = q.limit.unwrap_or(100);
    let list = match q.scope.as_deref().unwrap_or("mine") {
        "mine" => {
            st.store
                .access_requests(RequestFilter {
                    requester: Some(ctx.id()),
                    status,
                    limit,
                    ..Default::default()
                })
                .await?
        }
        "approvals" => {
            let all = st
                .store
                .access_requests(RequestFilter {
                    vaults: Some(ctx.access.vault_ids()),
                    status,
                    limit: 500,
                    ..Default::default()
                })
                .await?;
            let mut out = Vec::new();
            for r in all {
                if r.requester_id == ctx.id() && r.status != AccessRequestStatus::Pending {
                    continue;
                }
                let policy =
                    target_policy(&st, &ctx.access, r.vault_id, r.target_kind, r.target_id)
                        .await
                        .ok()
                        .flatten()
                        .unwrap_or_else(|| fallback_policy(r.vault_id));
                if st.security.is_approver(ctx.id(), r.vault_id, &policy).await {
                    out.push(r);
                }
                if out.len() >= limit {
                    break;
                }
            }
            out
        }
        "vault" => {
            let v = q
                .vault_id
                .ok_or_else(|| ApiError::bad_request("give vault_id"))?;
            ctx.access.require(v, VaultRole::Manager)?;
            st.store
                .access_requests(RequestFilter {
                    vaults: Some(vec![v]),
                    status,
                    limit,
                    ..Default::default()
                })
                .await?
        }
        _ => {
            return Err(ApiError::bad_request(
                "scope must be mine, approvals or vault",
            ));
        }
    };
    let mut out = Vec::with_capacity(list.len());
    for r in &list {
        out.push(request_json(&st, ctx.id(), r).await);
    }
    Ok(Json(out))
}

/// The request if the caller may see it (requester, approvers, managers).
async fn visible_request(st: &AppState, ctx: &AccessCtx, id: Id) -> ApiResult<AccessRequest> {
    let req = st.store.access_request(id).await?;
    if req.requester_id == ctx.id() {
        return Ok(req);
    }
    if ctx.access.role(req.vault_id).is_none() {
        return Err(ApiError::not_found("access request not found"));
    }
    if ctx.access.role(req.vault_id) == Some(VaultRole::Manager) {
        return Ok(req);
    }
    let policy = target_policy(
        st,
        &ctx.access,
        req.vault_id,
        req.target_kind,
        req.target_id,
    )
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| fallback_policy(req.vault_id));
    if st
        .security
        .is_approver(ctx.id(), req.vault_id, &policy)
        .await
    {
        return Ok(req);
    }
    Err(ApiError::not_found("access request not found"))
}

async fn one_request(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    let req = visible_request(&st, &ctx, id).await?;
    Ok(Json(request_json(&st, ctx.id(), &req).await))
}

fn clean_reason(r: Option<String>) -> Option<String> {
    r.map(|r| r.trim().chars().take(500).collect::<String>())
        .filter(|r| !r.is_empty())
}

async fn approve_request(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
    body: Option<Json<DecideRequest>>,
) -> ApiResult<Json<Value>> {
    let body = body.map(|b| b.0).unwrap_or_default();
    let req = visible_request(&st, &ctx, id).await?;
    let policy = target_policy(
        &st,
        &ctx.access,
        req.vault_id,
        req.target_kind,
        req.target_id,
    )
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| fallback_policy(req.vault_id));
    if !st
        .security
        .is_approver(ctx.id(), req.vault_id, &policy)
        .await
    {
        return Err(ApiError::forbidden("you cannot approve this request")
            .with_code(codes::NOT_AN_APPROVER));
    }
    let self_approved = req.requester_id == ctx.id();
    if self_approved && !policy.policy.allow_self_approval {
        return Err(ApiError::forbidden("you cannot approve your own request")
            .with_code(codes::SELF_APPROVAL_FORBIDDEN));
    }
    let minutes = body.minutes.unwrap_or(req.minutes);
    if minutes == 0 || minutes > req.minutes {
        return Err(ApiError::bad_request(format!(
            "approve 1-{} minutes (a window can only be shortened)",
            req.minutes
        ))
        .with_code(codes::ACCESS_DURATION_TOO_LONG));
    }
    let reason = clean_reason(body.reason);
    let approved = st
        .store
        .approve_access_request(id, ctx.id(), minutes, reason.clone(), self_approved)
        .await?;
    st.security.forget_user(approved.requester_id);
    let approvers = st.security.approvers(req.vault_id, &policy).await;
    notify(&st, &approved, "approved", &approvers).await;
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "access.approve",
            Some(format!(
                "{}:{}",
                approved.target_kind.as_str(),
                approved.target_id
            )),
            json!({
                "request": id, "requester": approved.requester_id, "minutes": minutes,
                "ends_at": approved.ends_at, "reason": reason, "self_approved": self_approved,
            }),
            approved.vault_id,
        )
        .await?;
    Ok(Json(request_json(&st, ctx.id(), &approved).await))
}

async fn deny_request(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
    body: Option<Json<DecideRequest>>,
) -> ApiResult<Json<Value>> {
    let body = body.map(|b| b.0).unwrap_or_default();
    let req = visible_request(&st, &ctx, id).await?;
    let policy = target_policy(
        &st,
        &ctx.access,
        req.vault_id,
        req.target_kind,
        req.target_id,
    )
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| fallback_policy(req.vault_id));
    if !st
        .security
        .is_approver(ctx.id(), req.vault_id, &policy)
        .await
    {
        return Err(
            ApiError::forbidden("you cannot decide this request").with_code(codes::NOT_AN_APPROVER)
        );
    }
    let reason = clean_reason(body.reason);
    let denied = st
        .store
        .deny_access_request(id, ctx.id(), reason.clone())
        .await?;
    let approvers = st.security.approvers(req.vault_id, &policy).await;
    notify(&st, &denied, "denied", &approvers).await;
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "access.deny",
            Some(format!(
                "{}:{}",
                denied.target_kind.as_str(),
                denied.target_id
            )),
            json!({"request": id, "requester": denied.requester_id, "reason": reason}),
            denied.vault_id,
        )
        .await?;
    Ok(Json(request_json(&st, ctx.id(), &denied).await))
}

async fn cancel_request(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    let req = st.store.access_request(id).await?;
    if req.requester_id != ctx.id() {
        return Err(ApiError::not_found("access request not found"));
    }
    let was_active = req.is_active(now_ms());
    let cancelled = st.store.cancel_access_request(id).await?;
    let approvers = approvers_of(&st, &cancelled).await;
    notify(&st, &cancelled, "cancelled", &approvers).await;
    if was_active {
        end_window(&st, &cancelled, codes::ACCESS_EXPIRED).await;
    }
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "access.cancel",
            Some(format!(
                "{}:{}",
                cancelled.target_kind.as_str(),
                cancelled.target_id
            )),
            json!({"request": id, "was_active": was_active}),
            cancelled.vault_id,
        )
        .await?;
    Ok(Json(request_json(&st, ctx.id(), &cancelled).await))
}

async fn revoke_request(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
    body: Option<Json<DecideRequest>>,
) -> ApiResult<Json<Value>> {
    let body = body.map(|b| b.0).unwrap_or_default();
    let req = visible_request(&st, &ctx, id).await?;
    let policy = target_policy(
        &st,
        &ctx.access,
        req.vault_id,
        req.target_kind,
        req.target_id,
    )
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| fallback_policy(req.vault_id));
    let manager = ctx.access.role(req.vault_id) == Some(VaultRole::Manager);
    if !manager
        && !st
            .security
            .is_approver(ctx.id(), req.vault_id, &policy)
            .await
    {
        return Err(
            ApiError::forbidden("you cannot revoke this access").with_code(codes::NOT_AN_APPROVER)
        );
    }
    let reason = clean_reason(body.reason);
    let revoked = st
        .store
        .revoke_access_request(id, ctx.id(), reason.clone())
        .await?;
    let serials = st
        .store
        .revoke_certificates(
            None,
            CertSelector::Request(id),
            ctx.id(),
            Some("access revoked".into()),
        )
        .await?;
    end_window(&st, &revoked, codes::ACCESS_REVOKED).await;
    let approvers = st.security.approvers(req.vault_id, &policy).await;
    notify(&st, &revoked, "revoked", &approvers).await;
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "access.revoke",
            Some(format!("{}:{}", revoked.target_kind.as_str(), revoked.target_id)),
            json!({"request": id, "requester": revoked.requester_id, "reason": reason, "certificates": serials}),
            revoked.vault_id,
        )
        .await?;
    Ok(Json(request_json(&st, ctx.id(), &revoked).await))
}

/// A window ended (expired, cancelled or revoked): the requester's server
/// sessions on hosts no longer allowed close, and pooled connections of the
/// vault are dropped.
pub async fn end_window(st: &AppState, req: &AccessRequest, reason: &str) {
    let user = req.requester_id;
    st.security.forget_user(user);
    st.pool.invalidate_vault(req.vault_id, Some(user)).await;
    let Ok(access) = st.store.vault_access(user).await else {
        return;
    };
    for (session, host) in st.sessions.server_sessions_in(user, req.vault_id) {
        let allowed = match host {
            Some(h) => match st.store.get_in::<Host>(&access, h).await {
                Ok(rec) => st
                    .security
                    .gate(&access, req.vault_id, &rec.data)
                    .await
                    .map(|g| g.allowed())
                    .unwrap_or(false),
                Err(_) => false,
            },
            None => true,
        };
        if !allowed {
            st.sessions.close_with_reason(session, reason).await;
        }
    }
}

/// Expires pending requests, ends windows and retires rotated CAs, every
/// 15 seconds.
pub fn spawn_job(st: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(15));
        loop {
            tick.tick().await;
            run_job(&st).await;
        }
    });
}

/// One pass of the job (also called by tests).
pub async fn run_job(st: &AppState) {
    let now = now_ms();
    match st.store.expire_access_requests(now).await {
        Ok(list) => {
            for r in list {
                let approvers = approvers_of(st, &r).await;
                notify(st, &r, "expired", &approvers).await;
                let _ = st
                    .store
                    .audit_vault(
                        r.requester_id,
                        "system",
                        "access.expire",
                        Some(format!("{}:{}", r.target_kind.as_str(), r.target_id)),
                        json!({"request": r.id}),
                        r.vault_id,
                    )
                    .await;
            }
        }
        Err(e) => tracing::warn!(error = %e, "could not expire access requests"),
    }
    match st.store.ended_access_requests(now).await {
        Ok(list) => {
            for r in list {
                end_window(st, &r, codes::ACCESS_EXPIRED).await;
                let v = json!({"type": "access_request", "event": "ended", "request": r});
                st.vault_events.send(r.requester_id, v);
                let _ = st
                    .store
                    .audit_vault(
                        r.requester_id,
                        "system",
                        "access.end",
                        Some(format!("{}:{}", r.target_kind.as_str(), r.target_id)),
                        json!({"request": r.id}),
                        r.vault_id,
                    )
                    .await;
            }
        }
        Err(e) => tracing::warn!(error = %e, "could not end access windows"),
    }
    if let Err(e) = st.store.retire_due_cas(now).await {
        tracing::warn!(error = %e, "could not retire certificate authorities");
    }
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CertificateRequest {
    /// The host to connect to (principals and policy come from it).
    pub host_id: Uuid,
    /// A key of your vaults (same vault as the host, or your personal one)
    /// that you may use…
    #[serde(default)]
    pub key_id: Option<Uuid>,
    /// …or any public key with a proof of possession.
    #[serde(default)]
    pub public_key: Option<String>,
    /// SSHSIG (namespace `termoak-cert@termoak.com`) over
    /// `termoak-cert-request\n<instance_id>\n<user id>\n<public key>\n<timestamp>`.
    #[serde(default)]
    pub proof: Option<String>,
    /// Milliseconds since the epoch (±5 minutes).
    #[serde(default)]
    pub timestamp: Option<i64>,
    #[serde(default)]
    pub ttl_minutes: Option<u32>,
}

fn not_owned(m: &str) -> ApiError {
    ApiError::forbidden(m.to_string()).with_code(codes::CERTIFICATE_KEY_NOT_OWNED)
}

/// `POST /certificates`: a short-lived certificate for one of your keys.
async fn issue_certificate(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Json(req): Json<CertificateRequest>,
) -> ApiResult<Json<crate::security::IssuedCert>> {
    let key = format!("certificates:{}", ctx.id());
    if !st.cert_limiter.allow(&key) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many certificate requests: try again in a minute",
        )
        .with_detail("retry_ms", st.cert_limiter.wait_ms(&key)));
    }
    let rec = st.store.get_in::<Host>(&ctx.access, req.host_id).await?;
    let vault = rec.meta.vault_id.unwrap_or(ctx.personal());
    let host = rec.data;
    if !host.protocol.is_ssh() {
        return Err(ApiError::bad_request("certificates are for SSH hosts"));
    }
    let settings = st
        .store
        .effective_settings_in(&ctx.access, vault, &host)
        .await?;
    let login = match settings.username.clone().filter(|u| !u.trim().is_empty()) {
        Some(u) => Some(u),
        None => match settings.identity_id {
            Some(iid) => st
                .store
                .get_in::<Identity>(&ctx.access, iid)
                .await
                .ok()
                .map(|r| r.data.username),
            None => None,
        },
    };
    // Whose key: a vault key the caller may use, or a proof of possession.
    let subject = match req.key_id {
        Some(kid) => {
            let k = st
                .store
                .get_in::<SshKey>(&ctx.access, kid)
                .await
                .map_err(|_| not_owned("key not found"))?;
            let kv = k.meta.vault_id.unwrap_or(ctx.personal());
            if kv != vault && kv != ctx.personal() {
                return Err(not_owned(
                    "the key must be in the host's vault or your personal vault",
                ));
            }
            ctx.access
                .authorize_secret(kv, SecretUse::Credentials)
                .map_err(|_| not_owned("you cannot use this key from your device"))?;
            let pk = ca::parse_public_key(&k.data.public_key).map_err(|e| {
                ApiError::bad_request(format!("the key's public key is invalid: {e}"))
            })?;
            if let Some(given) = &req.public_key {
                let g = ca::parse_public_key(given)
                    .map_err(|e| ApiError::bad_request(format!("invalid public key: {e}")))?;
                if ca::fingerprint(&g) != ca::fingerprint(&pk) {
                    return Err(not_owned("public_key does not match key_id"));
                }
            }
            pk
        }
        None => {
            let (Some(pk), Some(proof), Some(ts)) = (&req.public_key, &req.proof, req.timestamp)
            else {
                return Err(ApiError::bad_request(
                    "give key_id, or public_key with proof and timestamp",
                ));
            };
            let key = ca::parse_public_key(pk)
                .map_err(|e| ApiError::bad_request(format!("invalid public key: {e}")))?;
            if (now_ms() - ts).abs() > ca::PROOF_WINDOW_MS {
                return Err(
                    ApiError::forbidden("the proof is too old (check the device's clock)")
                        .with_code(codes::CERTIFICATE_PROOF_INVALID),
                );
            }
            let text = ca::public_key_text(&key).map_err(ApiError::from)?;
            let msg =
                ca::proof_message(st.security.instance_id(), &ctx.id().to_string(), &text, ts);
            ca::verify_proof(&key, proof, &msg).map_err(|_| {
                ApiError::forbidden("the proof of possession does not verify")
                    .with_code(codes::CERTIFICATE_PROOF_INVALID)
            })?;
            key
        }
    };
    let gate = st.security.gate(&ctx.access, vault, &host).await?;
    if !gate.allowed() {
        return Err(gate.error(&host).into());
    }
    if st.security.record_required(&ctx.access, vault, &host).await && !ctx.user.features.recording
    {
        return Err(ApiError::forbidden(
            "sessions on this host must be recorded: update the app or open a server session",
        )
        .with_code(codes::RECORDING_REQUIRED));
    }
    let issued = st
        .security
        .issue(
            &ctx.user.user,
            &ctx.access,
            vault,
            &host,
            login,
            &subject,
            &gate,
            CertPurpose::Device,
            Some(ctx.user.device.id),
            req.ttl_minutes,
        )
        .await?;
    Ok(Json(issued))
}

async fn my_certificates(State(st): State<AppState>, u: AuthUser) -> ApiResult<Json<Value>> {
    let list = st
        .store
        .certificates(CertFilter {
            user: Some(u.id()),
            limit: 100,
            ..Default::default()
        })
        .await?;
    Ok(Json(json!(list)))
}

// ---------------------------------------------------------------------------
// Recordings
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct UploadQuery {
    pub host_id: Uuid,
    pub started_at: Option<i64>,
    pub title: Option<String>,
}

/// `POST /recordings`: an app uploads the recording (asciicast) of a local
/// session on a host of a vault.
async fn upload_recording(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Query(q): Query<UploadQuery>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    if body.is_empty() {
        return Err(ApiError::bad_request("empty recording").with_code("invalid_recording"));
    }
    let header_ok = body
        .split(|b| *b == b'\n')
        .next()
        .and_then(|l| serde_json::from_slice::<Value>(l).ok())
        .is_some_and(|v| v.get("version").is_some());
    if !header_ok {
        return Err(
            ApiError::bad_request("not an asciicast recording").with_code("invalid_recording")
        );
    }
    let rec = st.store.get_in::<Host>(&ctx.access, q.host_id).await?;
    let vault = rec.meta.vault_id.unwrap_or(ctx.personal());
    let now = now_ms();
    let id = new_id();
    let path = st.sessions.recording_path(ctx.id(), id);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| ApiError::internal(format!("could not save the recording: {e}")))?;
    }
    tokio::fs::write(&path, &body)
        .await
        .map_err(|e| ApiError::internal(format!("could not save the recording: {e}")))?;
    let title: String = q
        .title
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| rec.data.label.clone())
        .chars()
        .take(200)
        .collect();
    st.store
        .insert_session(SessionInfo {
            id,
            owner_id: ctx.id(),
            host_id: Some(q.host_id),
            title,
            status: SessionStatus::Closed,
            kind: "device".into(),
            created_at: q.started_at.unwrap_or(now).min(now),
            ended_at: Some(now),
            error: None,
            recording: true,
        })
        .await?;
    st.store
        .set_session_status(id, SessionStatus::Closed, None)
        .await?;
    st.store.set_session_vault(id, Some(vault)).await?;
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "session.recording_upload",
            Some(format!("host:{}", q.host_id)),
            json!({"session": id, "bytes": body.len(), "device": ctx.user.device.name}),
            vault,
        )
        .await?;
    Ok(Json(json!({"id": id})))
}

async fn vault_recordings(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    ctx.access.require(id, VaultRole::Manager)?;
    let list = st.store.vault_recordings(id, 500).await?;
    Ok(Json(json!(
        list.into_iter()
            .map(|(s, email)| json!({
                "session_id": s.id, "owner_id": s.owner_id, "owner_email": email,
                "host_id": s.host_id, "title": s.title, "kind": s.kind,
                "created_at": s.created_at, "ended_at": s.ended_at,
            }))
            .collect::<Vec<_>>()
    )))
}

async fn download_recording(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path((id, session)): Path<(Id, Id)>,
) -> ApiResult<Response> {
    ctx.access.require(id, VaultRole::Manager)?;
    if st.store.session_vault(session).await? != Some(id) {
        return Err(ApiError::not_found(format!("session {session}")));
    }
    let info = st.store.session(session).await?;
    let path = st.sessions.recording_path(info.owner_id, session);
    let file = tokio::fs::File::open(&path).await.map_err(|_| {
        ApiError::not_found("this session has no recording").with_code("recording_not_found")
    })?;
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "recording.download",
            Some(session.to_string()),
            json!({"owner": info.owner_id}),
            id,
        )
        .await?;
    let stream = tokio_util::io::ReaderStream::new(file);
    Ok((
        [
            (header::CONTENT_TYPE, "application/x-asciicast".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{session}.cast\""),
            ),
        ],
        Body::from_stream(stream),
    )
        .into_response())
}

/// `covers` re-exported for tests.
pub fn request_covers(req: &AccessRequest, vault: Id, host: Id, groups: &[Id]) -> bool {
    covers(req, vault, host, groups)
}
