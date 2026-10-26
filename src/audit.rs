//! Extended audit (0.7 phase 5a, docs/E2EE-SSO-AUDIT.md §4): search with
//! filters, export (CSV, JSON, NDJSON), team retention, and delivery to
//! SIEMs through sinks: webhooks (JSON batches signed with HMAC-SHA256) and
//! syslog (RFC 5424 over TCP or TLS with RFC 6587 octet counting). Sinks
//! keep a cursor (the last entry id delivered): at-least-once, in order,
//! across restarts.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use termoak_core::Id;
use termoak_core::model::{AuditEntry, TeamRole, VaultRole};
use termoak_core::store::audit::{
    AuditFilter, AuditScope, AuditSettings, AuditSink, AuditSinkConfig, AuditSinkKind, AuditSinkRow,
};
use termoak_core::time::now_ms;
use tokio::io::AsyncWriteExt;
use utoipa::ToSchema;

use crate::auth::{AdminUser, AuthUser};
use crate::egress::Egress;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::vaults::AccessCtx;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/audit", get(mine))
        .route("/api/v1/audit/export", get(mine_export))
        .route("/api/v1/vaults/{id}/audit", get(vault))
        .route("/api/v1/vaults/{id}/audit/export", get(vault_export))
        .route("/api/v1/teams/{id}/audit", get(team))
        .route("/api/v1/teams/{id}/audit/export", get(team_export))
        .route(
            "/api/v1/teams/{id}/audit/settings",
            get(settings).put(set_settings),
        )
        .route(
            "/api/v1/teams/{id}/audit/sinks",
            get(team_sinks).post(team_sink_create),
        )
        .route(
            "/api/v1/teams/{id}/audit/sinks/{sink}",
            axum::routing::patch(team_sink_update).delete(team_sink_delete),
        )
        .route(
            "/api/v1/teams/{id}/audit/sinks/{sink}/test",
            post(team_sink_test),
        )
        .route("/api/v1/admin/audit", get(admin))
        .route("/api/v1/admin/audit/export", get(admin_export))
        .route(
            "/api/v1/admin/audit/sinks",
            get(admin_sinks).post(admin_sink_create),
        )
        .route(
            "/api/v1/admin/audit/sinks/{sink}",
            axum::routing::patch(admin_sink_update).delete(admin_sink_delete),
        )
        .route(
            "/api/v1/admin/audit/sinks/{sink}/test",
            post(admin_sink_test),
        )
}

// ---------------------------------------------------------------------------
// Search and export
// ---------------------------------------------------------------------------

async fn search(
    st: &AppState,
    scope: AuditScope,
    mut f: AuditFilter,
) -> ApiResult<Json<Vec<AuditEntry>>> {
    f.limit = Some(f.limit.unwrap_or(100).clamp(1, 1000));
    Ok(Json(st.store.audit_search(scope, f).await?))
}

async fn require_team_admin(st: &AppState, team: Id, u: &AuthUser) -> ApiResult<()> {
    match st.store.team_role(team, u.id()).await? {
        Some(TeamRole::Owner | TeamRole::Admin) => Ok(()),
        Some(_) => Err(
            ApiError::forbidden("only the team's owners and admins can do this")
                .with_code("team_admin_only"),
        ),
        None => Err(ApiError::not_found(format!("team {team}"))),
    }
}

/// Your own account's entries.
async fn mine(
    State(st): State<AppState>,
    u: AuthUser,
    Query(f): Query<AuditFilter>,
) -> ApiResult<Json<Vec<AuditEntry>>> {
    search(&st, AuditScope::Owner(u.id()), f).await
}

/// A vault's entries (managers).
async fn vault(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
    Query(f): Query<AuditFilter>,
) -> ApiResult<Json<Vec<AuditEntry>>> {
    ctx.access.require(id, VaultRole::Manager)?;
    search(&st, AuditScope::Vault(id), f).await
}

/// A team's entries: its vaults and the team's own actions (owners, admins).
async fn team(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Query(f): Query<AuditFilter>,
) -> ApiResult<Json<Vec<AuditEntry>>> {
    require_team_admin(&st, id, &u).await?;
    search(&st, AuditScope::Team(id), f).await
}

/// Every entry of the server (administrators).
async fn admin(
    State(st): State<AppState>,
    _a: AdminUser,
    Query(f): Query<AuditFilter>,
) -> ApiResult<Json<Vec<AuditEntry>>> {
    search(&st, AuditScope::All, f).await
}

#[derive(Debug, Deserialize)]
struct ExportQuery {
    #[serde(default)]
    format: Option<String>,
    #[serde(flatten)]
    filter: AuditFilter,
}

/// One entry as SIEMs and exports get it.
pub fn event_json(e: &AuditEntry, server: &str) -> Value {
    json!({
        "id": e.id,
        "time": chrono::DateTime::from_timestamp_millis(e.created_at)
            .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
            .unwrap_or_default(),
        "created_at": e.created_at,
        "action": e.action,
        "actor": e.actor,
        "owner_id": e.owner_id,
        "team_id": e.team_id,
        "vault_id": e.vault_id,
        "target": e.target,
        "detail": e.detail,
        "server": server,
    })
}

/// A CSV field (RFC 4180), neutralizing formulas for spreadsheets.
fn csv_field(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

fn csv_row(e: &AuditEntry) -> String {
    let time = chrono::DateTime::from_timestamp_millis(e.created_at)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_default();
    [
        e.id.to_string(),
        time,
        e.action.clone(),
        e.actor.clone(),
        e.owner_id.to_string(),
        e.team_id.map(|t| t.to_string()).unwrap_or_default(),
        e.vault_id.map(|v| v.to_string()).unwrap_or_default(),
        e.target.clone().unwrap_or_default(),
        e.detail.to_string(),
    ]
    .iter()
    .map(|f| csv_field(f))
    .collect::<Vec<_>>()
    .join(",")
        + "\r\n"
}

async fn export(
    st: AppState,
    u: &AuthUser,
    scope: AuditScope,
    label: &str,
    q: ExportQuery,
) -> ApiResult<Response> {
    let format = q.format.unwrap_or_else(|| "csv".into());
    let (ctype, ext) = match format.as_str() {
        "csv" => ("text/csv; charset=utf-8", "csv"),
        "json" => ("application/json", "json"),
        "ndjson" => ("application/x-ndjson", "ndjson"),
        _ => {
            return Err(ApiError::bad_request("format must be csv, json or ndjson")
                .with_code("invalid_format"));
        }
    };
    let max = st.config.audit.max_export_rows.max(1) as usize;
    let mut filter = q.filter;
    filter.before = None;
    filter.limit = Some(1000);
    let detail = json!({"format": format, "filter": {"action": filter.action, "actor": filter.actor, "since": filter.since, "until": filter.until, "q": filter.q}});
    // An export is audited where it was taken from.
    match scope {
        AuditScope::Team(t) => {
            st.store
                .audit_team(
                    t,
                    u.id(),
                    &u.actor(),
                    "audit.export",
                    Some(label.to_string()),
                    detail,
                )
                .await?
        }
        AuditScope::Vault(v) => {
            st.store
                .audit_vault(
                    u.id(),
                    &u.actor(),
                    "audit.export",
                    Some(label.to_string()),
                    detail,
                    v,
                )
                .await?
        }
        _ => {
            st.store
                .audit(
                    u.id(),
                    &u.actor(),
                    "audit.export",
                    Some(label.to_string()),
                    detail,
                )
                .await?
        }
    }
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(8);
    let server = st.instance_id.clone();
    let fmt = format.clone();
    tokio::spawn(async move {
        let send = |s: String| {
            let tx = tx.clone();
            async move { tx.send(Ok(bytes::Bytes::from(s))).await.is_ok() }
        };
        let head = match fmt.as_str() {
            "csv" => Some("id,time,action,actor,owner_id,team_id,vault_id,target,detail\r\n"),
            "json" => Some("["),
            _ => None,
        };
        if let Some(h) = head
            && !send(h.into()).await
        {
            return;
        }
        let mut after = 0i64;
        let mut sent = 0usize;
        loop {
            let mut f = filter.clone();
            f.after = Some(after);
            let page = match st.store.audit_search(scope, f).await {
                Ok(p) => p,
                Err(e) => {
                    let _ = tx.send(Err(std::io::Error::other(e.to_string()))).await;
                    return;
                }
            };
            if page.is_empty() {
                break;
            }
            let mut chunk = String::new();
            for e in &page {
                if sent >= max {
                    break;
                }
                match fmt.as_str() {
                    "csv" => chunk.push_str(&csv_row(e)),
                    "json" => {
                        if sent > 0 {
                            chunk.push(',');
                        }
                        chunk.push_str(&event_json(e, &server).to_string());
                    }
                    _ => {
                        chunk.push_str(&event_json(e, &server).to_string());
                        chunk.push('\n');
                    }
                }
                sent += 1;
            }
            after = page.last().map(|e| e.id).unwrap_or(after);
            if !send(chunk).await || sent >= max || page.len() < 1000 {
                break;
            }
        }
        if fmt == "json" {
            let _ = send("]".into()).await;
        }
    });
    let date = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, ctype)
        .header(header::CACHE_CONTROL, "no-store")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"termoak-audit-{label}-{date}.{ext}\""),
        )
        .body(Body::from_stream(tokio_stream_of(rx)))
        .map_err(|e| ApiError::internal(e.to_string()))
}

fn tokio_stream_of(
    mut rx: tokio::sync::mpsc::Receiver<Result<bytes::Bytes, std::io::Error>>,
) -> impl futures::Stream<Item = Result<bytes::Bytes, std::io::Error>> {
    futures::stream::poll_fn(move |cx| rx.poll_recv(cx))
}

async fn mine_export(
    State(st): State<AppState>,
    u: AuthUser,
    Query(q): Query<ExportQuery>,
) -> ApiResult<Response> {
    let id = u.id();
    export(st, &u, AuditScope::Owner(id), "account", q).await
}

async fn vault_export(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
    Query(q): Query<ExportQuery>,
) -> ApiResult<Response> {
    ctx.access.require(id, VaultRole::Manager)?;
    export(
        st,
        &ctx.user,
        AuditScope::Vault(id),
        &format!("vault-{id}"),
        q,
    )
    .await
}

async fn team_export(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Query(q): Query<ExportQuery>,
) -> ApiResult<Response> {
    require_team_admin(&st, id, &u).await?;
    export(st, &u, AuditScope::Team(id), &format!("team-{id}"), q).await
}

async fn admin_export(
    State(st): State<AppState>,
    AdminUser(u): AdminUser,
    Query(q): Query<ExportQuery>,
) -> ApiResult<Response> {
    export(st, &u, AuditScope::All, "server", q).await
}

// ---------------------------------------------------------------------------
// Team settings
// ---------------------------------------------------------------------------

/// `GET /teams/{id}/audit/settings`.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditSettingsView {
    /// Days the team keeps its entries (`null`: the server's default).
    pub retention_days: Option<u32>,
    pub default_retention_days: u32,
    pub max_retention_days: u32,
}

async fn settings_view(st: &AppState, team: Id) -> ApiResult<AuditSettingsView> {
    Ok(AuditSettingsView {
        retention_days: st.store.audit_settings(team).await?.retention_days,
        default_retention_days: st.config.audit.retention_days,
        max_retention_days: st.config.audit.max_team_retention_days,
    })
}

async fn settings(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<AuditSettingsView>> {
    require_team_admin(&st, id, &u).await?;
    Ok(Json(settings_view(&st, id).await?))
}

async fn set_settings(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Json(req): Json<AuditSettings>,
) -> ApiResult<Json<AuditSettingsView>> {
    require_team_admin(&st, id, &u).await?;
    if let Some(d) = req.retention_days {
        let max = st.config.audit.max_team_retention_days;
        if d < 1 || (max > 0 && d > max) {
            return Err(ApiError::bad_request(format!(
                "retention_days must be between 1 and {max}"
            ))
            .with_code("invalid_retention")
            .with_detail("max", max));
        }
    }
    st.store.set_audit_settings(id, req.clone()).await?;
    st.store
        .audit_team(
            id,
            u.id(),
            &u.actor(),
            "audit.settings",
            Some(id.to_string()),
            json!({"retention_days": req.retention_days}),
        )
        .await?;
    Ok(Json(settings_view(&st, id).await?))
}

// ---------------------------------------------------------------------------
// Sinks
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSink {
    pub kind: AuditSinkKind,
    pub name: String,
    pub config: AuditSinkConfig,
    /// Action patterns (`access.*`); empty: every entry.
    #[serde(default)]
    pub actions: Vec<String>,
}

/// A new sink and, for webhooks, its signing secret (shown once).
#[derive(Debug, Serialize, ToSchema)]
pub struct CreatedSink {
    pub sink: AuditSink,
    pub secret: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSink {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub config: Option<AuditSinkConfig>,
    #[serde(default)]
    pub actions: Option<Vec<String>>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

fn check_sink(
    st: &AppState,
    kind: AuditSinkKind,
    cfg: &mut AuditSinkConfig,
    name: &str,
    actions: &[String],
) -> ApiResult<()> {
    let bad = |m: String| ApiError::bad_request(m).with_code("audit_sink_invalid");
    if name.trim().is_empty() || name.chars().count() > 80 {
        return Err(bad("the name needs 1 to 80 characters".into()));
    }
    if actions.len() > 50
        || actions
            .iter()
            .any(|a| a.is_empty() || a.len() > 64 || a.contains(char::is_whitespace))
    {
        return Err(bad(
            "actions: up to 50 patterns like access.* or cert.issue".into(),
        ));
    }
    let egress = Egress::new(&st.config.audit.allowed_targets);
    match kind {
        AuditSinkKind::Webhook => {
            let url = cfg.url.clone().unwrap_or_default();
            egress
                .check_url(&url)
                .map_err(|e| bad(format!("the URL {e}")))?;
            *cfg = AuditSinkConfig {
                url: Some(url.trim().to_string()),
                ..Default::default()
            };
        }
        AuditSinkKind::Syslog => {
            let host = cfg.host.clone().unwrap_or_default();
            let transport = cfg.transport.clone().unwrap_or_else(|| "tls".into());
            if !matches!(transport.as_str(), "tls" | "tcp") {
                return Err(bad("transport must be tls or tcp".into()));
            }
            let tls = transport == "tls";
            let port = cfg.port.unwrap_or(if tls { 6514 } else { 514 });
            egress
                .check_syslog(&host, port, tls)
                .map_err(|e| bad(format!("the syslog target {e}")))?;
            if let Some(pem) = &cfg.ca_pem
                && tls_roots(Some(pem)).is_err()
            {
                return Err(bad("ca_pem is not a PEM certificate".into()));
            }
            if cfg.facility.is_some_and(|f| f > 23) {
                return Err(bad("facility is 0 to 23".into()));
            }
            cfg.host = Some(host.trim().to_string());
            cfg.port = Some(port);
            cfg.transport = Some(transport);
            cfg.url = None;
        }
    }
    Ok(())
}

fn sink_aad(id: Id) -> Vec<u8> {
    format!("termoak:audit-sink:{id}").into_bytes()
}

async fn create_sink(
    st: &AppState,
    u: &AuthUser,
    team: Option<Id>,
    mut req: CreateSink,
) -> ApiResult<CreatedSink> {
    check_sink(st, req.kind, &mut req.config, &req.name, &req.actions)?;
    if st.store.audit_sinks(team).await?.len() >= st.config.audit.max_sinks_per_team.max(1) as usize
    {
        return Err(ApiError::conflict("too many sinks").with_code("limit_reached"));
    }
    // Webhooks get a signing secret, sealed at rest; shown once.
    let secret = (req.kind == AuditSinkKind::Webhook)
        .then(|| format!("whsec_{}", termoak_core::sso::random_token()));
    let mut sink = st
        .store
        .create_audit_sink(
            team,
            req.kind,
            req.name.trim().to_string(),
            req.config,
            req.actions,
            None,
            u.id(),
        )
        .await?;
    if let Some(s) = &secret {
        let sealed = st
            .store
            .master_key()
            .seal(s.as_bytes(), &sink_aad(sink.id))?;
        st.store.set_audit_sink_secret(sink.id, sealed).await?;
        sink = st.store.audit_sink(sink.id).await?.sink;
    }
    let detail = json!({"kind": sink.kind, "name": sink.name, "url": sink.config.url, "host": sink.config.host, "actions": sink.actions});
    match team {
        Some(t) => {
            st.store
                .audit_team(
                    t,
                    u.id(),
                    &u.actor(),
                    "audit.sink_create",
                    Some(sink.id.to_string()),
                    detail,
                )
                .await?
        }
        None => {
            st.store
                .audit(
                    u.id(),
                    &u.actor(),
                    "audit.sink_create",
                    Some(sink.id.to_string()),
                    detail,
                )
                .await?
        }
    }
    Ok(CreatedSink { sink, secret })
}

async fn owned_sink(st: &AppState, team: Option<Id>, sink: Id) -> ApiResult<AuditSinkRow> {
    let row = st.store.audit_sink(sink).await?;
    if row.sink.team_id != team {
        return Err(ApiError::not_found(format!("audit sink {sink}")));
    }
    Ok(row)
}

async fn update_sink(
    st: &AppState,
    u: &AuthUser,
    team: Option<Id>,
    sink: Id,
    mut req: UpdateSink,
) -> ApiResult<AuditSink> {
    let row = owned_sink(st, team, sink).await?;
    if let Some(cfg) = req.config.as_mut() {
        let name = req.name.clone().unwrap_or(row.sink.name.clone());
        let actions = req.actions.clone().unwrap_or(row.sink.actions.clone());
        check_sink(st, row.sink.kind, cfg, &name, &actions)?;
    } else if req.name.is_some() || req.actions.is_some() {
        let mut cfg = row.sink.config.clone();
        let name = req.name.clone().unwrap_or(row.sink.name.clone());
        let actions = req.actions.clone().unwrap_or(row.sink.actions.clone());
        check_sink(st, row.sink.kind, &mut cfg, &name, &actions)?;
    }
    let s = st
        .store
        .update_audit_sink(
            sink,
            req.name.map(|n| n.trim().to_string()),
            req.config,
            req.actions,
            req.enabled,
        )
        .await?;
    let detail = json!({"name": s.name, "enabled": s.enabled, "actions": s.actions});
    match team {
        Some(t) => {
            st.store
                .audit_team(
                    t,
                    u.id(),
                    &u.actor(),
                    "audit.sink_update",
                    Some(sink.to_string()),
                    detail,
                )
                .await?
        }
        None => {
            st.store
                .audit(
                    u.id(),
                    &u.actor(),
                    "audit.sink_update",
                    Some(sink.to_string()),
                    detail,
                )
                .await?
        }
    }
    Ok(s)
}

async fn delete_sink(st: &AppState, u: &AuthUser, team: Option<Id>, sink: Id) -> ApiResult<Value> {
    owned_sink(st, team, sink).await?;
    st.store.delete_audit_sink(sink).await?;
    match team {
        Some(t) => {
            st.store
                .audit_team(
                    t,
                    u.id(),
                    &u.actor(),
                    "audit.sink_delete",
                    Some(sink.to_string()),
                    json!({}),
                )
                .await?
        }
        None => {
            st.store
                .audit(
                    u.id(),
                    &u.actor(),
                    "audit.sink_delete",
                    Some(sink.to_string()),
                    json!({}),
                )
                .await?
        }
    }
    Ok(json!({"ok": true}))
}

async fn test_sink(st: &AppState, u: &AuthUser, team: Option<Id>, sink: Id) -> ApiResult<Value> {
    let row = owned_sink(st, team, sink).await?;
    let e = AuditEntry {
        id: 0,
        owner_id: u.id(),
        actor: u.actor(),
        action: "audit.test".into(),
        target: Some(sink.to_string()),
        detail: json!({"message": "test event from Termoak"}),
        created_at: now_ms(),
        vault_id: None,
        team_id: team,
    };
    Ok(match deliver(st, &row, &[e]).await {
        Ok(()) => json!({"ok": true}),
        Err(err) => json!({"ok": false, "error": err}),
    })
}

async fn team_sinks(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<Vec<AuditSink>>> {
    require_team_admin(&st, id, &u).await?;
    Ok(Json(st.store.audit_sinks(Some(id)).await?))
}
async fn team_sink_create(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Json(req): Json<CreateSink>,
) -> ApiResult<Json<CreatedSink>> {
    require_team_admin(&st, id, &u).await?;
    Ok(Json(create_sink(&st, &u, Some(id), req).await?))
}
async fn team_sink_update(
    State(st): State<AppState>,
    u: AuthUser,
    Path((id, sink)): Path<(Id, Id)>,
    Json(req): Json<UpdateSink>,
) -> ApiResult<Json<AuditSink>> {
    require_team_admin(&st, id, &u).await?;
    Ok(Json(update_sink(&st, &u, Some(id), sink, req).await?))
}
async fn team_sink_delete(
    State(st): State<AppState>,
    u: AuthUser,
    Path((id, sink)): Path<(Id, Id)>,
) -> ApiResult<Json<Value>> {
    require_team_admin(&st, id, &u).await?;
    Ok(Json(delete_sink(&st, &u, Some(id), sink).await?))
}
async fn team_sink_test(
    State(st): State<AppState>,
    u: AuthUser,
    Path((id, sink)): Path<(Id, Id)>,
) -> ApiResult<Json<Value>> {
    require_team_admin(&st, id, &u).await?;
    Ok(Json(test_sink(&st, &u, Some(id), sink).await?))
}
async fn admin_sinks(State(st): State<AppState>, _a: AdminUser) -> ApiResult<Json<Vec<AuditSink>>> {
    Ok(Json(st.store.audit_sinks(None).await?))
}
async fn admin_sink_create(
    State(st): State<AppState>,
    AdminUser(u): AdminUser,
    Json(req): Json<CreateSink>,
) -> ApiResult<Json<CreatedSink>> {
    Ok(Json(create_sink(&st, &u, None, req).await?))
}
async fn admin_sink_update(
    State(st): State<AppState>,
    AdminUser(u): AdminUser,
    Path(sink): Path<Id>,
    Json(req): Json<UpdateSink>,
) -> ApiResult<Json<AuditSink>> {
    Ok(Json(update_sink(&st, &u, None, sink, req).await?))
}
async fn admin_sink_delete(
    State(st): State<AppState>,
    AdminUser(u): AdminUser,
    Path(sink): Path<Id>,
) -> ApiResult<Json<Value>> {
    Ok(Json(delete_sink(&st, &u, None, sink).await?))
}
async fn admin_sink_test(
    State(st): State<AppState>,
    AdminUser(u): AdminUser,
    Path(sink): Path<Id>,
) -> ApiResult<Json<Value>> {
    Ok(Json(test_sink(&st, &u, None, sink).await?))
}

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

/// `X-Termoak-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>`.
pub fn webhook_signature(secret: &[u8], t: i64, body: &[u8]) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    let mut ctx = ring::hmac::Context::with_key(&key);
    ctx.update(t.to_string().as_bytes());
    ctx.update(b".");
    ctx.update(body);
    format!("t={t},v1={}", hex::encode(ctx.sign().as_ref()))
}

/// RFC 5424 severity of an action.
fn severity(action: &str) -> u8 {
    if action.ends_with("_failed")
        || action.ends_with(".deny")
        || action.ends_with(".revoke")
        || action.contains("refused")
    {
        4 // warning
    } else if action.starts_with("sso.config")
        || action.starts_with("e2ee.")
        || action.starts_with("team.policy")
        || action.starts_with("ca.")
        || action.starts_with("audit.")
    {
        5 // notice
    } else {
        6 // informational
    }
}

fn sd_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(']', "\\]")
}

/// One RFC 5424 message (without framing).
pub fn syslog_message(
    e: &AuditEntry,
    cfg: &AuditSinkConfig,
    hostname: &str,
    server: &str,
) -> String {
    let facility = cfg.facility.unwrap_or(13) as u32;
    let pri = facility * 8 + severity(&e.action) as u32;
    let time = chrono::DateTime::from_timestamp_millis(e.created_at)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_else(|| "-".into());
    let app: String = cfg
        .app_name
        .clone()
        .unwrap_or_else(|| "termoak".into())
        .chars()
        .filter(|c| c.is_ascii_graphic())
        .take(48)
        .collect();
    let msgid: String = e
        .action
        .chars()
        .filter(|c| c.is_ascii_graphic())
        .take(32)
        .collect();
    let host: String = hostname
        .chars()
        .filter(|c| c.is_ascii_graphic())
        .take(255)
        .collect();
    let mut sd = format!(
        "[termoak@32473 id=\"{}\" actor=\"{}\"",
        e.id,
        sd_escape(&e.actor)
    );
    if let Some(t) = e.team_id {
        sd.push_str(&format!(" team=\"{t}\""));
    }
    if let Some(v) = e.vault_id {
        sd.push_str(&format!(" vault=\"{v}\""));
    }
    if let Some(t) = &e.target {
        sd.push_str(&format!(" target=\"{}\"", sd_escape(t)));
    }
    sd.push(']');
    format!(
        "<{pri}>1 {time} {host} {app} - {msgid} {sd} \u{feff}{}",
        event_json(e, server)
    )
}

fn tls_roots(ca_pem: Option<&str>) -> Result<rustls::RootCertStore, String> {
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    match ca_pem {
        Some(pem) => {
            let mut n = 0;
            for c in CertificateDer::pem_slice_iter(pem.as_bytes()) {
                let c = c.map_err(|e| e.to_string())?;
                roots.add(c).map_err(|e| e.to_string())?;
                n += 1;
            }
            if n == 0 {
                return Err("no certificate".into());
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    Ok(roots)
}

async fn send_syslog(
    st: &AppState,
    cfg: &AuditSinkConfig,
    entries: &[AuditEntry],
) -> Result<(), String> {
    let host = cfg.host.clone().unwrap_or_default();
    let tls = cfg.transport.as_deref() != Some("tcp");
    let port = cfg.port.unwrap_or(if tls { 6514 } else { 514 });
    let egress = Egress::new(&st.config.audit.allowed_targets);
    egress.check_syslog(&host, port, tls)?;
    let addrs = egress
        .resolve(&host, port)
        .await
        .map_err(|e| e.to_string())?;
    let hostname = st
        .config
        .server
        .public_url
        .as_deref()
        .and_then(|u| url::Url::parse(u).ok())
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| "termoak".into());
    let mut payload = Vec::new();
    for e in entries {
        let m = syslog_message(e, cfg, &hostname, &st.instance_id);
        payload.extend_from_slice(format!("{} ", m.len()).as_bytes());
        payload.extend_from_slice(m.as_bytes());
    }
    let timeout = Duration::from_secs(10);
    let tcp = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addrs[..]))
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|e| format!("connect: {e}"))?;
    if tls {
        let roots = tls_roots(cfg.ca_pem.as_deref())?;
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let name =
            rustls_pki_types::ServerName::try_from(host.clone()).map_err(|e| e.to_string())?;
        let mut s = tokio::time::timeout(
            timeout,
            tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp),
        )
        .await
        .map_err(|_| "TLS timed out".to_string())?
        .map_err(|e| format!("TLS: {e}"))?;
        tokio::time::timeout(timeout, async {
            s.write_all(&payload).await?;
            s.flush().await?;
            s.shutdown().await
        })
        .await
        .map_err(|_| "write timed out".to_string())?
        .map_err(|e| format!("write: {e}"))?;
    } else {
        let mut s = tcp;
        tokio::time::timeout(timeout, async {
            s.write_all(&payload).await?;
            s.flush().await?;
            s.shutdown().await
        })
        .await
        .map_err(|_| "write timed out".to_string())?
        .map_err(|e| format!("write: {e}"))?;
    }
    Ok(())
}

async fn send_webhook(
    st: &AppState,
    row: &AuditSinkRow,
    entries: &[AuditEntry],
) -> Result<(), String> {
    let url = row.sink.config.url.clone().unwrap_or_default();
    let egress = Egress::new(&st.config.audit.allowed_targets);
    egress.check_url(&url)?;
    let secret = match &row.secret {
        Some(sealed) => st
            .store
            .master_key()
            .open(sealed, &sink_aad(row.sink.id))
            .map_err(|_| "cannot open the signing secret".to_string())?
            .to_vec(),
        None => return Err("the sink has no signing secret".into()),
    };
    let body = json!({
        "sink_id": row.sink.id,
        "server": st.instance_id,
        "events": entries.iter().map(|e| event_json(e, &st.instance_id)).collect::<Vec<_>>(),
    })
    .to_string();
    let t = chrono::Utc::now().timestamp();
    let first = entries.first().map(|e| e.id).unwrap_or(0);
    let last = entries.last().map(|e| e.id).unwrap_or(0);
    let resp = egress
        .http_client(Duration::from_secs(10))
        .post(&url)
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-Termoak-Event-Id", format!("{first}-{last}"))
        .header("X-Termoak-Timestamp", t.to_string())
        .header(
            "X-Termoak-Signature",
            webhook_signature(&secret, t, body.as_bytes()),
        )
        .body(body)
        .send()
        .await
        .map_err(|e| format!("request: {e}"))?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("the webhook answered {}", resp.status()))
    }
}

async fn deliver(st: &AppState, row: &AuditSinkRow, entries: &[AuditEntry]) -> Result<(), String> {
    match row.sink.kind {
        AuditSinkKind::Webhook => send_webhook(st, row, entries).await,
        AuditSinkKind::Syslog => send_syslog(st, &row.sink.config, entries).await,
    }
}

/// Backoff of a failing sink: 5 s doubling to 10 min.
fn due(row: &AuditSinkRow, now: i64) -> bool {
    if row.sink.failures == 0 {
        return true;
    }
    let wait = (5_000i64 << row.sink.failures.min(7)).min(600_000);
    row.sink.last_attempt_at.is_none_or(|t| now >= t + wait)
}

/// One round of every enabled sink.
pub async fn deliver_round(st: &AppState) {
    let Ok(sinks) = st.store.audit_sinks_enabled().await else {
        return;
    };
    let now = now_ms();
    for row in sinks {
        if !due(&row, now) {
            continue;
        }
        let scope = match row.sink.team_id {
            Some(t) => AuditScope::Team(t),
            None => AuditScope::All,
        };
        let page = match st
            .store
            .audit_search(
                scope,
                AuditFilter {
                    after: Some(row.sink.cursor),
                    limit: Some(100),
                    ..Default::default()
                },
            )
            .await
        {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(sink = %row.sink.id, error = %e, "audit sink: could not read the log");
                continue;
            }
        };
        let Some(last) = page.last().map(|e| e.id) else {
            continue;
        };
        let patterns: Vec<String> = row.sink.actions.clone();
        let entries: Vec<AuditEntry> = page
            .into_iter()
            .filter(|e| AuditFilter::matches_action(&patterns, &e.action))
            // A sink never reports on its own deliveries.
            .filter(|e| {
                !(e.action == "audit.sink_failed"
                    && e.target.as_deref() == Some(row.sink.id.to_string().as_str()))
            })
            .collect();
        let result = if entries.is_empty() {
            Ok(())
        } else {
            deliver(st, &row, &entries).await
        };
        match result {
            Ok(()) => {
                let _ = st
                    .store
                    .audit_sink_attempt(row.sink.id, Some(last), None)
                    .await;
            }
            Err(e) => {
                tracing::info!(sink = %row.sink.id, error = %e, "audit sink delivery failed");
                let _ = st
                    .store
                    .audit_sink_attempt(row.sink.id, None, Some(e))
                    .await;
            }
        }
    }
}

/// Sinks every 5 seconds; retention every hour.
pub fn spawn_jobs(st: AppState) {
    let s = st.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            deliver_round(&s).await;
        }
    });
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3600));
        loop {
            tick.tick().await;
            let max = st.config.audit.max_team_retention_days;
            match st
                .store
                .audit_purge(st.config.audit.retention_days, (max > 0).then_some(max))
                .await
            {
                Ok(n) if n > 0 => {
                    tracing::info!(deleted = n, "audit entries past their retention deleted")
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "audit retention failed"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_signature_and_syslog() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("=cmd()"), "'=cmd()");
        let sig = webhook_signature(b"secret", 1_700_000_000, b"{}");
        let hexsig = sig.strip_prefix("t=1700000000,v1=").unwrap();
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"secret");
        ring::hmac::verify(&key, b"1700000000.{}", &hex::decode(hexsig).unwrap()).unwrap();
        let e = AuditEntry {
            id: 7,
            owner_id: Id::nil(),
            actor: "user:x".into(),
            action: "access.deny".into(),
            target: Some("r\"1]".into()),
            detail: json!({}),
            created_at: 1_700_000_000_000,
            vault_id: None,
            team_id: None,
        };
        let m = syslog_message(&e, &AuditSinkConfig::default(), "next.termoak.com", "srv");
        // facility 13 (log audit) * 8 + warning 4.
        assert!(m.starts_with("<108>1 2023-11-14T22:13:20.000Z next.termoak.com termoak - access.deny [termoak@32473 id=\"7\" actor=\"user:x\" target=\"r\\\"1\\]\"] \u{feff}{"), "{m}");
    }
}
