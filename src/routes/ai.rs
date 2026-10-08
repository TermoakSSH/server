//! AI engine routes: background tasks, approvals, quick assistant,
//! providers, the users' own API keys and the MCP endpoint.

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use termoak_ai::assist::{AssistContext, CommandSuggestion};
use termoak_ai::mcp::McpCaller;
use termoak_ai::{ApprovalDecision, CreateTask, PermissionMode, Runbook, TaskView};
use termoak_core::Id;
use termoak_core::model::{Record, SecretUpdate, Snippet};
use utoipa::ToSchema;

use crate::account::micros_to_usd;
use crate::auth::{AuthUser, bearer_from_headers};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::vaults::AccessCtx;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/ai/providers", get(providers))
        .route("/api/v1/ai/tasks", get(list).post(create))
        .route("/api/v1/ai/tasks/{id}", get(one).delete(remove))
        .route("/api/v1/ai/tasks/{id}/messages", post(message))
        .route("/api/v1/ai/tasks/{id}/cancel", post(cancel))
        .route("/api/v1/ai/tasks/{id}/mode", post(set_mode))
        .route("/api/v1/ai/tasks/{id}/events", get(events))
        .route(
            "/api/v1/ai/tasks/{id}/runbook",
            get(runbook).post(save_runbook),
        )
        .route(
            "/api/v1/ai/tasks/{id}/approvals/{approval_id}",
            post(decide),
        )
        .route("/api/v1/ai/approvals", get(pending))
        .route("/api/v1/ai/suggest", post(suggest))
        .route("/api/v1/ai/explain", post(explain))
        .route("/api/v1/mcp", post(mcp))
        .route("/api/v1/me/ai/keys", get(list_keys))
        .route(
            "/api/v1/me/ai/keys/{provider}",
            put(set_key).delete(delete_key),
        )
        .route("/api/v1/me/ai/keys/{provider}/test", post(test_key))
        .route("/api/v1/me/ai/access", get(access))
}

/// Providers for your picker: `available` takes your plan and your own API
/// keys into account. Only administrators see why a server provider cannot
/// run (paths, environment variables...); everybody else gets a generic text.
async fn providers(State(st): State<AppState>, u: AuthUser) -> ApiResult<Json<Value>> {
    let mut providers = st.ai.providers_for(u.id()).await?;
    if !u.user.is_admin {
        for p in &mut providers {
            if p.reason_code.as_deref() == Some(termoak_ai::provider::REASON_NOT_CONFIGURED) {
                p.reason = Some("not available on this server".into());
            }
        }
    }
    Ok(Json(json!({
        "default": st.ai.config().default,
        "fallback": st.ai.config().fallback,
        "default_mode": st.ai.config().default_mode,
        "providers": providers,
    })))
}

// --- Your own API keys -------------------------------------------------------

/// Longest API key accepted (provider keys are around 50-200 characters).
const MAX_KEY_LEN: usize = 512;
/// Longest model name accepted.
const MAX_MODEL_LEN: usize = 128;

/// `PUT /api/v1/me/ai/keys/{provider}`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetAiKey {
    /// The API key. It is stored encrypted and never returned. Optional when
    /// a key is already saved: then only the model changes.
    #[serde(default)]
    pub key: Option<String>,
    /// Model to use with it (the provider's default when absent or `null`).
    #[serde(default)]
    pub model: Option<String>,
}

/// `POST /api/v1/me/ai/keys/{provider}/test` (the body is optional).
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct TestAiKey {
    /// Key to check before saving it; the saved one otherwise.
    #[serde(default)]
    pub key: Option<String>,
}

/// One of your own API keys (never the key itself).
#[derive(Debug, Serialize, ToSchema)]
pub struct AiKeyView {
    /// `claude`, `gpt`, `openrouter` or `opencode-api`.
    pub provider: String,
    /// Display name of the provider.
    pub label: String,
    /// Model chosen for it (`null` = the provider's default).
    pub model: Option<String>,
    /// Last 4 characters of the key.
    pub hint: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Result of checking a key with its provider.
#[derive(Debug, Serialize, ToSchema)]
pub struct AiKeyTestResult {
    pub ok: bool,
    /// What the provider said, when it failed.
    pub error: Option<String>,
    /// HTTP status of the provider, when it answered with an error (401 or
    /// 403 usually mean a wrong key).
    pub status: Option<u16>,
}

/// A provider that accepts your own API key.
#[derive(Debug, Serialize, ToSchema)]
pub struct AiKeyProvider {
    pub provider: String,
    pub label: String,
    pub default_model: Option<String>,
    /// Suggested models (others can be typed).
    pub models: Vec<String>,
}

/// Your AI situation, so clients can explain it.
#[derive(Debug, Serialize, ToSchema)]
pub struct AiAccess {
    /// Providers with one of your own API keys (used first, no credit spent).
    pub own_keys: Vec<String>,
    /// Your plan can use this server's AI providers.
    pub server_ai: bool,
    /// Monthly credit (USD) for the server's providers (`null` = no cap, or
    /// `server_ai` is false).
    pub credit_usd: Option<f64>,
    /// Credit spent this month (UTC) on the server's providers (their credit
    /// cost: the server's subscriptions are charged at a reference price).
    pub spent_usd: f64,
    /// Credit left this month (`null` when there is no credit).
    pub remaining_usd: Option<f64>,
    /// Providers that accept your own API key.
    pub providers: Vec<AiKeyProvider>,
}

fn provider_label(st: &AppState, provider: &str) -> String {
    st.ai
        .registry()
        .provider_config(provider)
        .and_then(|c| c.label.clone())
        .unwrap_or_else(|| provider.to_string())
}

/// The provider must accept the user's own API key.
fn check_provider(st: &AppState, provider: &str) -> ApiResult<()> {
    if provider.len() <= 64 && st.ai.registry().own_key_supported(provider) {
        return Ok(());
    }
    let shown: String = provider.chars().take(64).collect();
    Err(ApiError::bad_request(format!(
        "\"{shown}\" does not accept your own API key (use one of: {})",
        own_key_providers(st)
            .iter()
            .map(|p| p.provider.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    ))
    .with_code("unknown_provider")
    .with_detail("provider", shown))
}

fn clean_key(key: &str) -> ApiResult<String> {
    let key = key.trim();
    if key.is_empty() {
        return Err(ApiError::bad_request("the API key is empty"));
    }
    if key.len() > MAX_KEY_LEN {
        return Err(ApiError::bad_request(format!(
            "the API key is too long (maximum {MAX_KEY_LEN} characters)"
        )));
    }
    if !key.chars().all(|c| c.is_ascii_graphic()) {
        return Err(ApiError::bad_request(
            "the API key has characters that are not allowed",
        ));
    }
    Ok(key.to_string())
}

fn clean_model(model: Option<&str>) -> ApiResult<Option<String>> {
    let Some(model) = model.map(str::trim).filter(|m| !m.is_empty()) else {
        return Ok(None);
    };
    if model.len() > MAX_MODEL_LEN || !model.chars().all(|c| c.is_ascii_graphic()) {
        return Err(ApiError::bad_request(format!(
            "invalid model name (at most {MAX_MODEL_LEN} characters, no spaces)"
        )));
    }
    Ok(Some(model.to_string()))
}

fn own_key_providers(st: &AppState) -> Vec<AiKeyProvider> {
    let registry = st.ai.registry();
    termoak_ai::OWN_KEY_PROVIDERS
        .iter()
        .filter(|p| registry.own_key_supported(p))
        .filter_map(|p| {
            let cfg = registry.provider_config(p)?;
            let mut models: Vec<String> = cfg.model.iter().cloned().collect();
            for m in &cfg.models {
                if !models.contains(m) {
                    models.push(m.clone());
                }
            }
            Some(AiKeyProvider {
                provider: p.to_string(),
                label: cfg.label.clone().unwrap_or_else(|| p.to_string()),
                default_model: cfg.model.clone(),
                models,
            })
        })
        .collect()
}

fn key_view(st: &AppState, k: termoak_core::store::ai_keys::UserAiKey) -> AiKeyView {
    AiKeyView {
        label: provider_label(st, &k.provider),
        provider: k.provider,
        model: k.model,
        hint: k.hint,
        created_at: k.created_at,
        updated_at: k.updated_at,
    }
}

async fn list_keys(State(st): State<AppState>, u: AuthUser) -> ApiResult<Json<Vec<AiKeyView>>> {
    let keys = st.store.user_ai_keys(u.id()).await?;
    Ok(Json(keys.into_iter().map(|k| key_view(&st, k)).collect()))
}

async fn set_key(
    State(st): State<AppState>,
    u: AuthUser,
    Path(provider): Path<String>,
    Json(req): Json<SetAiKey>,
) -> ApiResult<Json<AiKeyView>> {
    check_provider(&st, &provider)?;
    let key = req.key.as_deref().map(clean_key).transpose()?;
    let model = clean_model(req.model.as_deref())?;
    let saved = match &key {
        Some(key) => {
            st.store
                .set_user_ai_key(u.id(), &provider, key, model.as_deref())
                .await?
        }
        // Without a key, only the model of the saved one changes.
        None => st
            .store
            .set_user_ai_key_model(u.id(), &provider, model.as_deref())
            .await?
            .ok_or_else(|| {
                ApiError::not_found(format!(
                    "you have no API key for \"{provider}\": send `key`"
                ))
            })?,
    };
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "ai.key.set",
            Some(provider.clone()),
            json!({"model": model, "key_changed": key.is_some()}),
        )
        .await?;
    Ok(Json(key_view(&st, saved)))
}

async fn delete_key(
    State(st): State<AppState>,
    u: AuthUser,
    Path(provider): Path<String>,
) -> ApiResult<Json<Value>> {
    let shown: String = provider.chars().take(64).collect();
    let deleted = st.store.delete_user_ai_key(u.id(), &shown).await?;
    if deleted {
        st.store
            .audit(u.id(), &u.actor(), "ai.key.delete", Some(shown), json!({}))
            .await?;
    }
    Ok(Json(json!({"ok": true, "deleted": deleted})))
}

async fn test_key(
    State(st): State<AppState>,
    u: AuthUser,
    Path(provider): Path<String>,
    body: axum::body::Bytes,
) -> ApiResult<Json<AiKeyTestResult>> {
    check_provider(&st, &provider)?;
    let req: TestAiKey = if body.iter().all(u8::is_ascii_whitespace) {
        TestAiKey::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| ApiError::bad_request(format!("invalid body: {e}")))?
    };
    let key = match req.key.as_deref() {
        Some(k) => clean_key(k)?,
        None => st
            .store
            .user_ai_key_secret(u.id(), &provider)
            .await?
            .map(|s| s.key.to_string())
            .ok_or_else(|| {
                ApiError::not_found(format!("you have no API key for \"{provider}\""))
            })?,
    };
    if !st.ai_key_limiter.allow(&u.id().to_string()) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_attempts",
            "too many key checks; wait a minute",
        ));
    }
    Ok(Json(match st.ai.check_own_key(&provider, &key).await {
        Ok(()) => AiKeyTestResult {
            ok: true,
            error: None,
            status: None,
        },
        Err(e) => AiKeyTestResult {
            status: match &e {
                termoak_ai::AiError::Http { status, .. } => Some(*status),
                _ => None,
            },
            ok: false,
            error: Some(e.to_string()),
        },
    }))
}

async fn access(State(st): State<AppState>, u: AuthUser) -> ApiResult<Json<AiAccess>> {
    let info = st.ai.access_info(u.id()).await?;
    let credit = info.credit_micros.filter(|_| info.server_ai);
    Ok(Json(AiAccess {
        own_keys: info.own_keys,
        server_ai: info.server_ai,
        credit_usd: credit.map(micros_to_usd),
        spent_usd: micros_to_usd(info.spent_micros),
        remaining_usd: credit.map(|c| micros_to_usd((c - info.spent_micros).max(0))),
        providers: own_key_providers(&st),
    }))
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    limit: Option<i64>,
}

async fn list(
    State(st): State<AppState>,
    u: AuthUser,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Vec<TaskView>>> {
    Ok(Json(st.ai.list(u.id(), q.limit.unwrap_or(50)).await?))
}

async fn create(
    State(st): State<AppState>,
    u: AuthUser,
    Json(req): Json<CreateTask>,
) -> ApiResult<Json<TaskView>> {
    Ok(Json(st.ai.create_task(u.id(), req).await?))
}

#[derive(Debug, Deserialize)]
struct OneQuery {
    #[serde(default)]
    messages: Option<bool>,
}

async fn one(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Query(q): Query<OneQuery>,
) -> ApiResult<Json<TaskView>> {
    Ok(Json(
        st.ai.get(u.id(), id, q.messages.unwrap_or(true)).await?,
    ))
}

async fn remove(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    st.ai.delete(u.id(), id).await?;
    Ok(Json(json!({"ok": true})))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TaskMessage {
    pub text: String,
}

async fn message(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Json(req): Json<TaskMessage>,
) -> ApiResult<Json<TaskView>> {
    Ok(Json(st.ai.send_message(u.id(), id, &req.text).await?))
}

async fn cancel(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    st.ai.cancel(u.id(), id).await?;
    Ok(Json(json!({"ok": true})))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetMode {
    /// `read_only`, `ask`, `confirm` or `auto`.
    #[schema(value_type = String)]
    pub mode: PermissionMode,
}

async fn set_mode(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Json(req): Json<SetMode>,
) -> ApiResult<Json<Value>> {
    st.ai.set_mode(u.id(), id, req.mode).await?;
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "ai.task.mode",
            Some(id.to_string()),
            json!({"mode": req.mode}),
        )
        .await?;
    Ok(Json(json!({"ok": true})))
}

#[derive(Debug, Deserialize)]
struct EventsQuery {
    #[serde(default)]
    after: i64,
}

async fn events(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Query(q): Query<EventsQuery>,
) -> ApiResult<Json<Value>> {
    let rows = st.ai.events(u.id(), id, q.after).await?;
    Ok(Json(json!(rows)))
}

/// `POST /ai/tasks/{id}/approvals/{approval_id}`. Apps that only send
/// `{approve, always}` keep working.
#[derive(Debug, Deserialize, ToSchema)]
pub struct Decision {
    pub approve: bool,
    /// Approve this one and every later one in the task (switches to autonomous mode).
    #[serde(default)]
    pub always: bool,
    /// With `approve: true`: the command (`run_command`, `send_to_terminal`)
    /// or plan to use instead of the model's (approvals whose `preview` has
    /// `editable: true`). It is what runs, and the model is told.
    #[serde(default)]
    pub edited: Option<String>,
    /// Why it was denied (or a note with the approval): sent to the model.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Longest edited command or plan kept in the audit entry (characters).
const AUDIT_EDITED_CHARS: usize = 4000;

async fn decide(
    State(st): State<AppState>,
    u: AuthUser,
    Path((id, approval_id)): Path<(Id, Id)>,
    Json(req): Json<Decision>,
) -> ApiResult<Json<Value>> {
    let by = format!("{} ({})", u.user.name, u.device.name);
    let decision = ApprovalDecision {
        approve: req.approve,
        always: req.always,
        edited: req.edited,
        reason: req.reason,
    };
    // What the engine uses: the edit only when approving, trimmed; the
    // reason trimmed and capped.
    let edited = decision
        .edited_text()
        .filter(|_| decision.approve)
        .map(str::to_string);
    let reason = decision.reason_text();
    st.ai
        .decide_with(u.id(), id, approval_id, decision, &by)
        .await?;
    let mut detail = json!({"task": id, "always": req.always});
    if let Some(e) = &edited {
        let count = e.chars().count();
        detail["edited"] = json!(e.chars().take(AUDIT_EDITED_CHARS).collect::<String>());
        if count > AUDIT_EDITED_CHARS {
            detail["edited_truncated"] = json!(true);
        }
    }
    if let Some(r) = &reason {
        detail["reason"] = json!(r);
    }
    st.store
        .audit(
            u.id(),
            &u.actor(),
            if req.approve {
                "ai.approval.approved"
            } else {
                "ai.approval.denied"
            },
            Some(approval_id.to_string()),
            detail,
        )
        .await?;
    Ok(Json(json!({"ok": true})))
}

/// `GET /ai/tasks/{id}/runbook`: the commands the task ran, as a snippet to
/// review before saving it (`steps: 0` when it ran none).
async fn runbook(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<RunbookView>> {
    Ok(Json(st.ai.runbook(u.id(), id).await?.into()))
}

/// The runbook of a task: a snippet built from the commands (and file
/// writes) it ran successfully, in order.
#[derive(Debug, Serialize, ToSchema)]
pub struct RunbookView {
    /// Suggested snippet name (the task's title).
    pub name: String,
    pub description: String,
    /// The script (`{{host}}` where the host's name or address was).
    pub script: String,
    /// `{{variables}}` of the script.
    pub variables: Vec<String>,
    /// Commands and file writes in it (0: nothing to save).
    pub steps: usize,
}

impl From<Runbook> for RunbookView {
    fn from(r: Runbook) -> Self {
        Self {
            name: r.name,
            description: r.description,
            script: r.script,
            variables: r.variables,
            steps: r.steps,
        }
    }
}

/// `POST /ai/tasks/{id}/runbook`.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct SaveRunbook {
    /// Name of the snippet (the task's title otherwise).
    #[serde(default)]
    pub name: Option<String>,
    /// Vault to save it in (default: your personal vault). You must be an
    /// Editor there.
    #[serde(default)]
    pub vault_id: Option<uuid::Uuid>,
}

/// Longest snippet name accepted.
const MAX_RUNBOOK_NAME: usize = 200;

/// Saves the runbook of a task as a snippet (tags `ai`, `runbook`) in a
/// vault you can edit. The body is optional.
async fn save_runbook(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
    body: axum::body::Bytes,
) -> ApiResult<Json<Record<Snippet>>> {
    let req: SaveRunbook = if body.iter().all(u8::is_ascii_whitespace) {
        SaveRunbook::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| ApiError::bad_request(format!("invalid body: {e}")))?
    };
    let name = req
        .name
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty());
    if name
        .as_ref()
        .is_some_and(|n| n.chars().count() > MAX_RUNBOOK_NAME)
    {
        return Err(ApiError::bad_request(format!(
            "the name is too long (maximum {MAX_RUNBOOK_NAME} characters)"
        )));
    }
    let vault = req.vault_id.unwrap_or(ctx.personal());
    // Checked before building it: a vault you cannot edit is refused the
    // same way whether the task ran commands or not.
    ctx.access
        .require(vault, termoak_core::model::VaultRole::Editor)?;
    let rb = st.ai.runbook(ctx.id(), id).await?;
    if rb.steps == 0 {
        return Err(ApiError::bad_request("the task ran no commands").with_code("runbook_empty"));
    }
    let snippet = Snippet {
        id: Id::nil(),
        name: name.unwrap_or(rb.name),
        script: rb.script,
        description: rb.description,
        tags: vec!["ai".into(), "runbook".into()],
    };
    let saved = st
        .store
        .save_in(&ctx.access, vault, snippet, SecretUpdate::Keep, None)
        .await?;
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "ai.task.runbook",
            Some(id.to_string()),
            json!({"snippet": saved.data.id, "steps": rb.steps}),
            vault,
        )
        .await?;
    Ok(Json(saved))
}

async fn pending(State(st): State<AppState>, u: AuthUser) -> ApiResult<Json<Value>> {
    Ok(Json(json!(st.ai.pending_approvals(u.id()).await?)))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SuggestReq {
    /// What you want to do, in natural language.
    pub request: String,
    #[serde(default)]
    #[schema(value_type = Object)]
    pub context: Option<AssistContext>,
    #[serde(default)]
    pub provider: Option<String>,
}

async fn suggest(
    State(st): State<AppState>,
    u: AuthUser,
    Json(req): Json<SuggestReq>,
) -> ApiResult<Json<CommandSuggestion>> {
    if req.request.trim().is_empty() {
        return Err(ApiError::bad_request("the request is empty"));
    }
    Ok(Json(
        st.ai
            .suggest_command(
                u.id(),
                &req.request,
                req.context.unwrap_or_default(),
                req.provider.as_deref(),
            )
            .await?,
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ExplainReq {
    /// Output or error to explain.
    pub text: String,
    #[serde(default)]
    pub question: Option<String>,
    #[serde(default)]
    #[schema(value_type = Object)]
    pub context: Option<AssistContext>,
    #[serde(default)]
    pub provider: Option<String>,
}

async fn explain(
    State(st): State<AppState>,
    u: AuthUser,
    Json(req): Json<ExplainReq>,
) -> ApiResult<Json<Value>> {
    let (answer, provider) = st
        .ai
        .explain(
            u.id(),
            &req.text,
            req.question.as_deref(),
            req.context.unwrap_or_default(),
            req.provider.as_deref(),
        )
        .await?;
    Ok(Json(json!({"answer": answer, "provider": provider})))
}

/// MCP endpoint (JSON-RPC). Accepts task tokens (Codex) or user tokens.
async fn mcp(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult<Response> {
    let token =
        bearer_from_headers(&headers).ok_or_else(|| ApiError::unauthorized("missing token"))?;
    let caller = if st.ai.is_task_mcp_token(&token) {
        McpCaller::TaskToken(token)
    } else {
        match st.store.authenticate(&token).await? {
            Some((user, _)) => McpCaller::User {
                owner: user.id,
                mode: st.ai.config().mcp_user_mode,
            },
            None => return Err(ApiError::unauthorized("invalid token")),
        }
    };
    Ok(match st.ai.mcp_handle(&caller, body).await {
        Some(resp) => Json(resp).into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    })
}

// --- OpenAPI shapes ----------------------------------------------------------
//
// The task routes send and receive the engine's own types (`CreateTask`,
// `TaskView`, the approval rows); these mirror them for the documentation.

/// `POST /ai/tasks`.
#[allow(dead_code)]
#[derive(Debug, ToSchema)]
pub struct NewTask {
    pub prompt: String,
    pub title: Option<String>,
    /// `read_only`, `ask`, `confirm` or `auto` (the server's default otherwise).
    pub mode: Option<String>,
    /// `provider` or `provider::model` (the default one otherwise).
    pub provider: Option<String>,
    /// Limit the task to these hosts.
    pub host_ids: Option<Vec<uuid::Uuid>>,
    /// Terminal it was launched from (context).
    pub session_id: Option<uuid::Uuid>,
    pub effort: Option<String>,
    /// Run it on the hosts of this group (and its subgroups).
    pub group_id: Option<uuid::Uuid>,
    /// Run it on the hosts with this tag.
    pub tag: Option<String>,
    /// With several hosts: one conversation per host (the same request,
    /// `[ai] fan_out_concurrency` at a time, at most `max_fan_out_hosts`)
    /// under this task, which gets the per-host table (`hosts`).
    pub fan_out: Option<bool>,
    /// The model first writes a numbered plan (without tools) to approve or
    /// edit: an approval with `tool: "plan"`.
    pub plan_first: Option<bool>,
}

/// What an approval shows.
#[allow(dead_code)]
#[derive(Debug, ToSchema)]
pub struct ApprovalPreview {
    /// `command` (run_command), `terminal` (send_to_terminal), `file`
    /// (write_file), `plan` or `other`.
    pub kind: String,
    /// Host as the model named it, or the terminal's title.
    pub host: Option<String>,
    /// Exact command (or text typed into the terminal).
    pub command: Option<String>,
    /// File written.
    pub path: Option<String>,
    /// Unified diff of the file (size-capped).
    pub diff: Option<String>,
    pub diff_truncated: Option<bool>,
    pub added: Option<usize>,
    pub removed: Option<usize>,
    pub new_file: Option<bool>,
    /// Why there is no diff.
    pub diff_error: Option<String>,
    /// `low`, `medium` or `high`.
    pub risk: String,
    /// The classifier's reasons.
    pub reasons: Option<Vec<RiskReasonDoc>>,
    /// Why the model wants to do it.
    pub explanation: Option<String>,
    /// The plan to approve (`kind: plan`).
    pub plan: Option<String>,
    /// It can be edited before approving (`edited` in the decision).
    pub editable: Option<bool>,
}

/// Why an action is risky.
#[allow(dead_code)]
#[derive(Debug, ToSchema)]
#[schema(as = RiskReason)]
pub struct RiskReasonDoc {
    /// Stable code for translations: `pipe`, `chain`, `redirect`,
    /// `substitution`, `sudo`, `rm_rf`, `delete`, `disk`, `reboot`,
    /// `service`, `packages`, `firewall`, `permissions`, `kill`, `users`,
    /// `remote_script`, `containers`, `cron`, `git_history`, `system_path`,
    /// `redacted`, `changes`.
    pub code: String,
    /// English text.
    pub text: String,
}

/// An approval of a task (`pending_approvals`, `GET /ai/approvals`).
#[allow(dead_code)]
#[derive(Debug, ToSchema)]
pub struct PendingApproval {
    pub id: uuid::Uuid,
    pub task_id: uuid::Uuid,
    /// The tool, or `plan`.
    pub tool: String,
    #[schema(value_type = Object)]
    pub input: Value,
    pub summary: String,
    /// `pending`, `approved`, `denied` or `expired`.
    pub status: String,
    pub decided_by: Option<String>,
    pub created_at: i64,
    pub decided_at: Option<i64>,
    /// Absent on approvals from before server 0.6.
    pub preview: Option<ApprovalPreview>,
}

/// One host of a multi-host task.
#[allow(dead_code)]
#[derive(Debug, ToSchema)]
pub struct HostRun {
    pub host_id: uuid::Uuid,
    pub label: String,
    /// The host's own task (its conversation, with `parent_id`).
    pub task_id: uuid::Uuid,
    pub status: String,
    pub summary: Option<String>,
    pub error: Option<String>,
    pub duration_ms: Option<i64>,
    pub cost_micros: i64,
    pub pending_approvals: usize,
}

/// The plan of a "plan before acting" task.
#[allow(dead_code)]
#[derive(Debug, ToSchema)]
pub struct TaskPlan {
    pub text: String,
    pub approved: bool,
    pub edited: Option<bool>,
}

/// A command or file write a task ran.
#[allow(dead_code)]
#[derive(Debug, ToSchema)]
pub struct ExecutedStep {
    pub call_id: String,
    /// `run_command`, `send_to_terminal` or `write_file`.
    pub tool: String,
    pub host: Option<String>,
    /// What ran (the user's edit, if they edited it).
    pub command: Option<String>,
    pub path: Option<String>,
    pub content: Option<String>,
    pub ok: bool,
    pub edited: Option<bool>,
    pub explanation: Option<String>,
    pub at: i64,
}

/// A task. Fields that are empty or false are left out.
#[allow(dead_code)]
#[derive(Debug, ToSchema)]
#[schema(as = TaskView)]
pub struct TaskViewDoc {
    pub id: uuid::Uuid,
    pub title: String,
    pub prompt: String,
    /// `queued`, `running`, `waiting_approval`, `completed`, `failed` or
    /// `cancelled`.
    pub status: String,
    pub mode: String,
    pub provider: String,
    pub used_provider: Option<String>,
    pub host_ids: Option<Vec<uuid::Uuid>>,
    pub created_at: i64,
    pub updated_at: i64,
    pub finished_at: Option<i64>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub cost_micros: i64,
    #[schema(value_type = Object)]
    pub usage: Value,
    #[schema(value_type = Option<Vec<Object>>)]
    pub messages: Option<Vec<Value>>,
    pub pending_approvals: Vec<PendingApproval>,
    /// The multi-host task this host's conversation belongs to.
    pub parent_id: Option<uuid::Uuid>,
    /// A multi-host task (see `hosts`).
    pub fan_out: Option<bool>,
    /// Per-host table of a multi-host task (`GET` of one task).
    pub hosts: Option<Vec<HostRun>>,
    pub group_id: Option<uuid::Uuid>,
    pub tag: Option<String>,
    pub plan_first: Option<bool>,
    pub plan: Option<TaskPlan>,
    /// Commands and file writes it ran, in order.
    pub steps: Option<Vec<ExecutedStep>>,
}
