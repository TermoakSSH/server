//! Single sign-on for teams (0.7 phase 5a, docs/E2EE-SSO-AUDIT.md §3):
//! OpenID Connect authorization code flow with PKCE (both towards the
//! identity provider and between the app and this server), ID tokens
//! checked against the provider's keys (RS*, PS*, ES256/384, EdDSA with
//! ring), verified team domains (DNS TXT) and their enforcement.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use termoak_core::Id;
use termoak_core::model::{TeamRole, User};
use termoak_core::sso::{SsoConfig, TeamDomain, normalize_domain};
use termoak_core::store::sso::{NewSsoFlow, SsoFlow};
use termoak_core::store::users::SecondFactor;
use utoipa::ToSchema;

use crate::auth::{AuthResponse, AuthUser, ClientIp, UserAgent, client_info};
use crate::egress::Egress;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/auth/sso/discover", get(discover))
        .route("/api/v1/auth/sso/start", post(start))
        .route("/api/v1/auth/sso/callback", get(callback))
        .route("/api/v1/auth/sso/exchange", post(exchange))
        .route("/api/v1/me/sso", get(my_identities))
        .route("/api/v1/me/sso/link", post(link_start))
        .route("/api/v1/me/sso/{team_id}", axum::routing::delete(unlink))
        .route(
            "/api/v1/teams/{id}/sso",
            get(team_sso).put(set_team_sso).delete(delete_team_sso),
        )
        .route("/api/v1/teams/{id}/domains", get(domains).post(add_domain))
        .route(
            "/api/v1/teams/{id}/domains/{domain}",
            axum::routing::delete(remove_domain),
        )
        .route(
            "/api/v1/teams/{id}/domains/{domain}/verify",
            post(verify_domain),
        )
        .route(
            "/api/v1/admin/teams/{id}/domains/{domain}/verify",
            post(admin_verify_domain),
        )
}

const CALLBACK_PATH: &str = "/api/v1/auth/sso/callback";
const DISCOVERY_TTL: Duration = Duration::from_secs(3600);
const JWKS_TTL: Duration = Duration::from_secs(3600);
const LEEWAY_SECS: i64 = 120;

// ---------------------------------------------------------------------------
// OIDC client
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    #[serde(default)]
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

/// Discovery documents and key sets of identity providers (cached).
#[derive(Default)]
pub struct Oidc {
    discovery: Mutex<HashMap<String, (Discovery, Instant)>>,
    jwks: Mutex<HashMap<String, (Jwks, Instant)>>,
}

fn sso_err(code: &'static str, m: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, code, m)
}

impl Oidc {
    fn egress(st: &AppState) -> Egress {
        Egress::new(&st.config.sso.allowed_issuers)
    }

    fn http(st: &AppState) -> reqwest::Client {
        Self::egress(st).http_client(Duration::from_secs(st.config.sso.timeout_secs.max(2)))
    }

    async fn discovery(&self, st: &AppState, issuer: &str) -> ApiResult<Discovery> {
        if let Some((d, at)) = self.discovery.lock().get(issuer)
            && at.elapsed() < DISCOVERY_TTL
        {
            return Ok(d.clone());
        }
        let egress = Self::egress(st);
        egress
            .check_url(issuer)
            .map_err(|e| sso_err("sso_issuer_invalid", format!("the issuer {e}")))?;
        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let d: Discovery = Self::http(st)
            .get(&url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| {
                sso_err(
                    "sso_issuer_invalid",
                    format!("could not read the provider's discovery: {e}"),
                )
            })?
            .json()
            .await
            .map_err(|e| {
                sso_err(
                    "sso_issuer_invalid",
                    format!("the provider's discovery is not valid: {e}"),
                )
            })?;
        if d.issuer.trim_end_matches('/') != issuer.trim_end_matches('/') {
            return Err(sso_err(
                "sso_issuer_invalid",
                format!("the provider says its issuer is {}, not {issuer}", d.issuer),
            ));
        }
        for u in [&d.authorization_endpoint, &d.token_endpoint, &d.jwks_uri] {
            egress
                .check_url(u)
                .map_err(|e| sso_err("sso_issuer_invalid", format!("a provider endpoint {e}")))?;
        }
        self.discovery
            .lock()
            .insert(issuer.to_string(), (d.clone(), Instant::now()));
        Ok(d)
    }

    async fn jwks(&self, st: &AppState, uri: &str, refresh: bool) -> ApiResult<Jwks> {
        if !refresh
            && let Some((k, at)) = self.jwks.lock().get(uri)
            && at.elapsed() < JWKS_TTL
        {
            return Ok(k.clone());
        }
        let k: Jwks = Self::http(st)
            .get(uri)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| {
                sso_err(
                    "sso_failed",
                    format!("could not read the provider's keys: {e}"),
                )
            })?
            .json()
            .await
            .map_err(|e| {
                sso_err(
                    "sso_failed",
                    format!("the provider's keys are not valid: {e}"),
                )
            })?;
        self.jwks
            .lock()
            .insert(uri.to_string(), (k.clone(), Instant::now()));
        Ok(k)
    }
}

fn b64url(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
}

/// Verifies a JWS signature with a JWK (ring).
fn verify_jws(alg: &str, jwk: &Jwk, msg: &[u8], sig: &[u8]) -> bool {
    use ring::signature as s;
    if let Some(a) = &jwk.alg
        && a != alg
    {
        return false;
    }
    match (alg, jwk.kty.as_str()) {
        ("RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512", "RSA") => {
            let (Some(n), Some(e)) = (
                jwk.n.as_deref().and_then(b64url),
                jwk.e.as_deref().and_then(b64url),
            ) else {
                return false;
            };
            let params: &s::RsaParameters = match alg {
                "RS256" => &s::RSA_PKCS1_2048_8192_SHA256,
                "RS384" => &s::RSA_PKCS1_2048_8192_SHA384,
                "RS512" => &s::RSA_PKCS1_2048_8192_SHA512,
                "PS256" => &s::RSA_PSS_2048_8192_SHA256,
                "PS384" => &s::RSA_PSS_2048_8192_SHA384,
                _ => &s::RSA_PSS_2048_8192_SHA512,
            };
            s::RsaPublicKeyComponents { n: &n, e: &e }
                .verify(params, msg, sig)
                .is_ok()
        }
        ("ES256" | "ES384", "EC") => {
            let (Some(x), Some(y)) = (
                jwk.x.as_deref().and_then(b64url),
                jwk.y.as_deref().and_then(b64url),
            ) else {
                return false;
            };
            let (alg_ring, crv): (&s::EcdsaVerificationAlgorithm, &str) = if alg == "ES256" {
                (&s::ECDSA_P256_SHA256_FIXED, "P-256")
            } else {
                (&s::ECDSA_P384_SHA384_FIXED, "P-384")
            };
            if jwk.crv.as_deref() != Some(crv) {
                return false;
            }
            let mut point = vec![4u8];
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            s::UnparsedPublicKey::new(alg_ring, point)
                .verify(msg, sig)
                .is_ok()
        }
        ("EdDSA", "OKP") if jwk.crv.as_deref() == Some("Ed25519") => {
            let Some(x) = jwk.x.as_deref().and_then(b64url) else {
                return false;
            };
            s::UnparsedPublicKey::new(&s::ED25519, x)
                .verify(msg, sig)
                .is_ok()
        }
        _ => false,
    }
}

/// Checks an ID token: signature with the provider's keys (refreshed once
/// for an unknown key id), issuer, audience, expiry and nonce.
async fn verify_id_token(
    st: &AppState,
    d: &Discovery,
    cfg: &SsoConfig,
    token: &str,
    nonce: &str,
) -> ApiResult<serde_json::Map<String, Value>> {
    let bad = |m: &str| sso_err("sso_failed", format!("the ID token is not valid: {m}"));
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad("not a JWS"));
    };
    let header: Value = b64url(h)
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| bad("header"))?;
    let alg = header["alg"].as_str().unwrap_or_default().to_string();
    if alg.is_empty() || alg == "none" || alg.starts_with("HS") {
        return Err(bad("algorithm"));
    }
    let kid = header["kid"].as_str().map(str::to_string);
    let sig = b64url(sig).ok_or_else(|| bad("signature"))?;
    let msg = format!("{h}.{p}");
    let mut ok = false;
    for refresh in [false, true] {
        let keys = st.sso.jwks(st, &d.jwks_uri, refresh).await?;
        let candidates: Vec<&Jwk> = keys
            .keys
            .iter()
            .filter(|k| kid.is_none() || k.kid == kid)
            .collect();
        if candidates
            .iter()
            .any(|k| verify_jws(&alg, k, msg.as_bytes(), &sig))
        {
            ok = true;
            break;
        }
        if !candidates.is_empty() {
            break;
        }
    }
    if !ok {
        return Err(bad("signature"));
    }
    let claims: serde_json::Map<String, Value> = b64url(p)
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| bad("payload"))?;
    let now = chrono::Utc::now().timestamp();
    if claims
        .get("iss")
        .and_then(Value::as_str)
        .map(|i| i.trim_end_matches('/'))
        != Some(cfg.issuer.trim_end_matches('/'))
    {
        return Err(bad("issuer"));
    }
    let aud_ok = match claims.get("aud") {
        Some(Value::String(a)) => *a == cfg.client_id,
        Some(Value::Array(list)) => {
            list.iter()
                .any(|a| a.as_str() == Some(cfg.client_id.as_str()))
                && (list.len() == 1
                    || claims.get("azp").and_then(Value::as_str) == Some(cfg.client_id.as_str()))
        }
        _ => false,
    };
    if !aud_ok {
        return Err(bad("audience"));
    }
    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or_else(|| bad("exp"))?;
    if exp + LEEWAY_SECS < now {
        return Err(bad("expired"));
    }
    if let Some(iat) = claims.get("iat").and_then(Value::as_i64)
        && iat > now + LEEWAY_SECS
    {
        return Err(bad("issued in the future"));
    }
    if claims.get("nonce").and_then(Value::as_str) != Some(nonce) {
        return Err(bad("nonce"));
    }
    if claims
        .get("sub")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(bad("sub"));
    }
    Ok(claims)
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

/// Whether `_termoak-challenge.<domain>` has `termoak-verify=<token>`.
async fn dns_has_token(st: &AppState, domain: &str, token: &str) -> Result<(), String> {
    use hickory_resolver::config::{NameServerConfig, ResolverConfig};
    use hickory_resolver::name_server::TokioConnectionProvider;
    use hickory_resolver::proto::xfer::Protocol;
    let mut builder = if st.config.sso.dns_servers.is_empty() {
        hickory_resolver::Resolver::builder(TokioConnectionProvider::default())
            .map_err(|e| format!("no system DNS configuration: {e}"))?
    } else {
        let mut cfg = ResolverConfig::new();
        for s in &st.config.sso.dns_servers {
            let addr: std::net::SocketAddr =
                s.parse().map_err(|_| format!("bad DNS server {s}"))?;
            cfg.add_name_server(NameServerConfig::new(addr, Protocol::Udp));
            cfg.add_name_server(NameServerConfig::new(addr, Protocol::Tcp));
        }
        hickory_resolver::Resolver::builder_with_config(cfg, TokioConnectionProvider::default())
    };
    builder.options_mut().timeout = Duration::from_secs(st.config.sso.timeout_secs.max(2));
    builder.options_mut().cache_size = 0;
    let resolver = builder.build();
    let name = format!("{}.", termoak_core::sso::txt_record_name(domain));
    let want = termoak_core::sso::txt_record_value(token);
    let lookup = resolver.txt_lookup(name.as_str()).await.map_err(|e| {
        format!(
            "no TXT record at {}: {e}",
            termoak_core::sso::txt_record_name(domain)
        )
    })?;
    for txt in lookup.iter() {
        let value: String = txt
            .txt_data()
            .iter()
            .map(|d| String::from_utf8_lossy(d).into_owned())
            .collect();
        if value.trim() == want {
            return Ok(());
        }
    }
    Err(format!(
        "the TXT record at {} does not have {want}",
        termoak_core::sso::txt_record_name(domain)
    ))
}

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

/// The error for a password sign-in, sign-up or reset of an email whose team
/// enforces SSO (`None`: allowed). The team owner keeps password sign-in when
/// the team allows it (break glass); server administrators always do.
pub async fn sso_required(st: &AppState, email: &str, user: Option<&User>) -> Option<ApiError> {
    if !st.config.sso.enabled {
        return None;
    }
    let (team, name, cfg) = st.store.sso_team_for_email(email).await.ok().flatten()?;
    let cfg = cfg?;
    if !cfg.enabled || !cfg.enforce {
        return None;
    }
    if let Some(u) = user {
        if u.is_admin {
            return None;
        }
        if cfg.owner_password_allowed
            && st.store.team_role(team, u.id).await.ok().flatten() == Some(TeamRole::Owner)
        {
            return None;
        }
    }
    Some(
        ApiError::new(
            StatusCode::FORBIDDEN,
            "sso_required",
            format!("{name} signs in through single sign-on"),
        )
        .with_detail("team_id", team.to_string())
        .with_detail("team_name", name),
    )
}

// ---------------------------------------------------------------------------
// Sign-in routes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct DiscoverQuery {
    email: String,
}

/// `GET /auth/sso/discover`.
#[derive(Debug, Serialize, ToSchema)]
pub struct SsoDiscovery {
    pub sso: bool,
    pub enforced: bool,
    pub team_id: Option<uuid::Uuid>,
    pub team_name: Option<String>,
}

async fn discover(
    State(st): State<AppState>,
    Query(q): Query<DiscoverQuery>,
) -> ApiResult<Json<SsoDiscovery>> {
    let none = SsoDiscovery {
        sso: false,
        enforced: false,
        team_id: None,
        team_name: None,
    };
    if !st.config.sso.enabled {
        return Ok(Json(none));
    }
    Ok(Json(match st.store.sso_team_for_email(&q.email).await? {
        Some((team, name, Some(cfg))) if cfg.enabled => SsoDiscovery {
            sso: true,
            enforced: cfg.enforce,
            team_id: Some(team),
            team_name: Some(name),
        },
        _ => none,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SsoStart {
    /// Finds the team by the email's verified domain...
    #[serde(default)]
    pub email: Option<String>,
    /// ...or the team directly.
    #[serde(default)]
    pub team_id: Option<uuid::Uuid>,
    /// The app's callback: `http://127.0.0.1:<port>/...` (desktop, CLI),
    /// `termoak://sso` (mobile) or `<public_url>/app/sso...` (web).
    pub redirect_uri: String,
    /// Sent back to the callback as is.
    #[serde(default)]
    pub state: Option<String>,
    /// The app's PKCE challenge (S256) for `POST /auth/sso/exchange`.
    pub code_challenge: String,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub device_name: String,
    #[serde(default)]
    pub platform: String,
}

/// `POST /auth/sso/start`.
#[derive(Debug, Serialize, ToSchema)]
pub struct SsoStarted {
    /// Open it in the system browser.
    pub authorize_url: String,
    pub expires_at: i64,
}

fn public_url(st: &AppState) -> ApiResult<String> {
    st.config
        .server
        .public_url
        .as_deref()
        .map(|u| u.trim_end_matches('/').to_string())
        .filter(|u| !u.is_empty())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "sso_not_configured",
                "single sign-on needs the server's public_url",
            )
        })
}

async fn start_flow(st: &AppState, req: SsoStart, link_user: Option<Id>) -> ApiResult<SsoStarted> {
    if !st.config.sso.enabled {
        return Err(ApiError::not_found("single sign-on is off on this server")
            .with_code("sso_not_configured"));
    }
    let base = public_url(st)?;
    if req
        .code_challenge_method
        .as_deref()
        .is_some_and(|m| m != "S256")
        || req.code_challenge.len() != 43
    {
        return Err(sso_err(
            "sso_pkce_invalid",
            "code_challenge must be an S256 challenge",
        ));
    }
    if !termoak_core::sso::allowed_redirect(&req.redirect_uri, Some(&base)) {
        return Err(sso_err(
            "sso_redirect_invalid",
            "redirect_uri must be a loopback address, termoak://sso or this server's /app/sso",
        ));
    }
    let (team, cfg) = match (
        req.team_id,
        req.email.as_deref().filter(|e| !e.trim().is_empty()),
    ) {
        (Some(t), _) => (t, st.store.team_sso(t).await?),
        (None, Some(email)) => match st.store.sso_team_for_email(email).await? {
            Some((t, _, cfg)) => (t, cfg),
            None => {
                return Err(
                    ApiError::not_found("no team signs in through SSO with this email")
                        .with_code("sso_not_configured"),
                );
            }
        },
        (None, None) => return Err(ApiError::bad_request("give an email or a team_id")),
    };
    let cfg = cfg.filter(|c| c.enabled).ok_or_else(|| {
        ApiError::not_found("this team has no single sign-on").with_code("sso_not_configured")
    })?;
    let d = st.sso.discovery(st, &cfg.issuer).await?;
    let verifier = termoak_core::sso::pkce_verifier();
    let state = termoak_core::sso::random_token();
    let nonce = termoak_core::sso::random_token();
    let flow = st
        .store
        .create_sso_flow(NewSsoFlow {
            team_id: team,
            link_user,
            state: state.clone(),
            nonce: nonce.clone(),
            verifier: verifier.clone(),
            redirect_uri: req.redirect_uri.clone(),
            client_state: req.state.clone().map(|s| s.chars().take(512).collect()),
            client_challenge: req.code_challenge.clone(),
            device_name: req.device_name.chars().take(80).collect(),
            platform: req.platform.chars().take(40).collect(),
        })
        .await?;
    let mut u = url::Url::parse(&d.authorization_endpoint)
        .map_err(|_| sso_err("sso_issuer_invalid", "bad authorization endpoint"))?;
    {
        let mut q = u.query_pairs_mut();
        q.append_pair("response_type", "code")
            .append_pair("client_id", &cfg.client_id)
            .append_pair("redirect_uri", &format!("{base}{CALLBACK_PATH}"))
            .append_pair("scope", &cfg.scopes.join(" "))
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair(
                "code_challenge",
                &termoak_core::sso::pkce_challenge(&verifier),
            )
            .append_pair("code_challenge_method", "S256");
        if let Some(e) = req.email.as_deref().filter(|e| !e.trim().is_empty()) {
            q.append_pair("login_hint", e.trim());
            if cfg.preset == termoak_core::sso::SsoPreset::Google
                && let Some(d) = termoak_core::sso::email_domain(e)
            {
                q.append_pair("hd", &d);
            }
        }
    }
    Ok(SsoStarted {
        authorize_url: u.to_string(),
        expires_at: flow.expires_at,
    })
}

async fn start(
    State(st): State<AppState>,
    Json(req): Json<SsoStart>,
) -> ApiResult<Json<SsoStarted>> {
    Ok(Json(start_flow(&st, req, None).await?))
}

/// Linking a signed-in account to its identity at the team's provider.
async fn link_start(
    State(st): State<AppState>,
    u: AuthUser,
    Json(req): Json<SsoStart>,
) -> ApiResult<Json<SsoStarted>> {
    let team = req
        .team_id
        .ok_or_else(|| ApiError::bad_request("give the team_id"))?;
    if st.store.team_role(team, u.id()).await?.is_none() {
        return Err(ApiError::forbidden("you are not in this team").with_code("not_team_member"));
    }
    Ok(Json(start_flow(&st, req, Some(u.id())).await?))
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

fn redirect_to(uri: &str, params: &[(&str, &str)]) -> Response {
    match url::Url::parse(uri) {
        Ok(mut u) => {
            {
                let mut q = u.query_pairs_mut();
                for (k, v) in params {
                    q.append_pair(k, v);
                }
            }
            Redirect::to(u.as_str()).into_response()
        }
        Err(_) => error_page("sso_failed", "bad callback"),
    }
}

fn error_page(code: &str, message: &str) -> Response {
    let esc = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    (
        StatusCode::BAD_REQUEST,
        Html(format!(
            "<!doctype html><meta charset=utf-8><title>Termoak</title><h1>Single sign-on failed</h1><p>{}</p><p><code>{}</code></p>",
            esc(message),
            esc(code)
        )),
    )
        .into_response()
}

/// The identity provider's way back.
async fn callback(State(st): State<AppState>, Query(q): Query<CallbackQuery>) -> Response {
    let Some(state) = q.state.clone() else {
        return error_page("sso_state_invalid", "the sign-in has no state");
    };
    let flow = match st.store.take_sso_flow(state).await {
        Ok(Some(f)) => f,
        _ => {
            return error_page(
                "sso_state_invalid",
                "this sign-in expired or was already used: start again",
            );
        }
    };
    let fail = |code: &'static str, message: String| {
        let st = st.clone();
        let flow = flow.clone();
        async move {
            let _ = st
                .store
                .finish_sso_flow(flow.id, Err(format!("{code}: {message}")))
                .await;
            let _ = st
                .store
                .audit_team(
                    flow.team_id,
                    flow.link_user.unwrap_or(Id::nil()),
                    "sso",
                    "sso.login_failed",
                    None,
                    json!({"code": code, "reason": message, "platform": flow.platform}),
                )
                .await;
            let mut params = vec![("error", code), ("error_description", message.as_str())];
            if let Some(s) = &flow.client_state {
                params.push(("state", s.as_str()));
            }
            redirect_to(&flow.redirect_uri, &params)
        }
    };
    if let Some(e) = q.error {
        let msg = q.error_description.unwrap_or_else(|| e.clone());
        return fail(
            "sso_failed",
            format!("the identity provider said {e}: {msg}"),
        )
        .await;
    }
    let Some(code) = q.code else {
        return fail("sso_failed", "the identity provider sent no code".into()).await;
    };
    match finish(&st, &flow, &code).await {
        Ok(user) => {
            let one_time = termoak_core::sso::random_token();
            let hash = hex::encode(ring::digest::digest(
                &ring::digest::SHA256,
                one_time.as_bytes(),
            ));
            if st
                .store
                .finish_sso_flow(flow.id, Ok((user.id, hash)))
                .await
                .is_err()
            {
                return error_page("internal", "could not finish the sign-in");
            }
            let mut params = vec![("code", one_time.as_str())];
            if let Some(s) = &flow.client_state {
                params.push(("state", s.as_str()));
            }
            redirect_to(&flow.redirect_uri, &params)
        }
        Err(e) => fail(e.code, e.message).await,
    }
}

/// The code at the provider → the account (linked, found by verified
/// domain, or created).
async fn finish(st: &AppState, flow: &SsoFlow, code: &str) -> ApiResult<User> {
    let cfg = st
        .store
        .team_sso(flow.team_id)
        .await?
        .filter(|c| c.enabled)
        .ok_or_else(|| sso_err("sso_not_configured", "this team's single sign-on is off"))?;
    let d = st.sso.discovery(st, &cfg.issuer).await?;
    let base = public_url(st)?;
    let secret = match st.store.team_sso_secret(flow.team_id).await? {
        Some(sealed) => Some(
            String::from_utf8(
                st.store
                    .master_key()
                    .open(&sealed, format!("termoak:sso:{}", flow.team_id).as_bytes())
                    .map_err(|_| ApiError::internal("cannot open the client secret"))?
                    .to_vec(),
            )
            .unwrap_or_default(),
        ),
        None => None,
    };
    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("redirect_uri", format!("{base}{CALLBACK_PATH}")),
        ("code_verifier", flow.verifier.clone()),
    ];
    let basic = secret.is_some()
        && !d.token_endpoint_auth_methods_supported.is_empty()
        && !d
            .token_endpoint_auth_methods_supported
            .iter()
            .any(|m| m == "client_secret_post")
        && d.token_endpoint_auth_methods_supported
            .iter()
            .any(|m| m == "client_secret_basic");
    let mut req = Oidc::http(st).post(&d.token_endpoint);
    if basic {
        req = req.basic_auth(&cfg.client_id, secret.as_deref());
    } else {
        form.push(("client_id", cfg.client_id.clone()));
        if let Some(s) = &secret {
            form.push(("client_secret", s.clone()));
        }
    }
    let resp = req.form(&form).send().await.map_err(|e| {
        sso_err(
            "sso_failed",
            format!("the token endpoint did not answer: {e}"),
        )
    })?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(sso_err(
            "sso_failed",
            format!(
                "the identity provider refused the code: {}",
                body["error_description"]
                    .as_str()
                    .or(body["error"].as_str())
                    .unwrap_or("error")
            ),
        ));
    }
    let id_token = body["id_token"]
        .as_str()
        .ok_or_else(|| sso_err("sso_failed", "the identity provider sent no ID token"))?;
    let claims = verify_id_token(st, &d, &cfg, id_token, &flow.nonce).await?;
    let subject = claims["sub"].as_str().unwrap_or_default().to_string();
    let email = claims
        .get(cfg.email_claim())
        .and_then(Value::as_str)
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| e.contains('@'))
        .ok_or_else(|| sso_err("sso_email_missing", "the identity provider sent no email"))?;
    let verified = match claims.get("email_verified") {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "true",
        _ => false,
    };
    if cfg.require_email_verified && !verified {
        return Err(sso_err(
            "sso_email_unverified",
            "the identity provider says the email is not verified",
        ));
    }
    let name = claims
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let domain = termoak_core::sso::email_domain(&email).unwrap_or_default();
    let domain_ok = st
        .store
        .team_domain(domain.clone())
        .await?
        .is_some_and(|d| d.team_id == flow.team_id && d.verified_at.is_some());
    if cfg.preset == termoak_core::sso::SsoPreset::Google
        && domain_ok
        && claims.get("hd").and_then(Value::as_str) != Some(domain.as_str())
    {
        return Err(sso_err(
            "sso_failed",
            "the Google account is not in the team's Workspace domain",
        ));
    }
    let issuer = cfg.issuer.clone();
    let existing = st
        .store
        .sso_identity(issuer.clone(), subject.clone())
        .await?;
    let user = match (flow.link_user, existing) {
        (Some(me), Some(ident)) if ident.user_id != me => {
            return Err(sso_err(
                "sso_identity_taken",
                "this identity is linked to another account",
            ));
        }
        (Some(me), _) => {
            st.store
                .link_sso_identity(
                    issuer.clone(),
                    subject.clone(),
                    me,
                    flow.team_id,
                    email.clone(),
                )
                .await?;
            st.store
                .audit_team(
                    flow.team_id,
                    me,
                    &format!("user:{me}"),
                    "sso.link",
                    Some(me.to_string()),
                    json!({"email": email, "issuer": issuer}),
                )
                .await?;
            st.store.user(me).await?
        }
        (None, Some(ident)) => {
            st.store
                .link_sso_identity(
                    issuer.clone(),
                    subject.clone(),
                    ident.user_id,
                    flow.team_id,
                    email.clone(),
                )
                .await?;
            st.store.user(ident.user_id).await?
        }
        (None, None) if domain_ok => {
            let user = match st.store.user_by_email(&email).await? {
                Some(u) => u,
                None if cfg.auto_create => {
                    let u = st.store.create_sso_user(&email, &name).await?;
                    st.store
                        .audit_team(
                            flow.team_id,
                            u.id,
                            &format!("user:{}", u.id),
                            "sso.user_created",
                            Some(u.id.to_string()),
                            json!({"email": email}),
                        )
                        .await?;
                    u
                }
                None => {
                    return Err(sso_err(
                        "sso_account_not_found",
                        "there is no account with this email: ask for an invitation",
                    ));
                }
            };
            st.store
                .link_sso_identity(
                    issuer.clone(),
                    subject.clone(),
                    user.id,
                    flow.team_id,
                    email.clone(),
                )
                .await?;
            st.store
                .audit_team(
                    flow.team_id,
                    user.id,
                    &format!("user:{}", user.id),
                    "sso.link",
                    Some(user.id.to_string()),
                    json!({"email": email, "issuer": issuer, "by": "verified_domain"}),
                )
                .await?;
            user
        }
        (None, None) => {
            return Err(sso_err(
                "sso_account_not_linked",
                "this identity is not linked to an account: sign in and link it, or verify the team's domain",
            ));
        }
    };
    if user.disabled {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "account_disabled",
            "the account is disabled",
        ));
    }
    if cfg.auto_join && st.store.team_role(flow.team_id, user.id).await?.is_none() {
        st.store
            .set_team_member(flow.team_id, user.id, TeamRole::Member)
            .await?;
        st.store
            .audit_team(
                flow.team_id,
                user.id,
                "sso",
                "team.member_added",
                Some(flow.team_id.to_string()),
                json!({"user": user.id, "via": "sso"}),
            )
            .await?;
    }
    Ok(user)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SsoExchange {
    /// The one-time code of the callback.
    pub code: String,
    /// The PKCE verifier of the app's `code_challenge`.
    pub code_verifier: String,
    /// Two-step verification code, when the account has it and the team
    /// does not count its SSO as 2FA.
    #[serde(default)]
    pub totp_code: Option<String>,
}

async fn exchange(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    Json(req): Json<SsoExchange>,
) -> ApiResult<Json<AuthResponse>> {
    if !termoak_core::sso::valid_verifier(&req.code_verifier) {
        return Err(sso_err("sso_pkce_invalid", "invalid code_verifier"));
    }
    let hash = hex::encode(ring::digest::digest(
        &ring::digest::SHA256,
        req.code.trim().as_bytes(),
    ));
    let challenge = termoak_core::sso::pkce_challenge(&req.code_verifier);
    let flow = st
        .store
        .redeem_sso_code(hash, move |f| f.client_challenge == challenge)
        .await?
        .ok_or_else(|| {
            sso_err(
                "sso_code_invalid",
                "the code expired, was used or does not match: start again",
            )
        })?;
    let user_id = flow
        .user_id
        .ok_or_else(|| ApiError::internal("flow without a user"))?;
    let user = st.store.user(user_id).await?;
    let cfg = st.store.team_sso(flow.team_id).await?.unwrap_or_default();
    let mut via = "sso";
    if user.totp_enabled && !cfg.satisfies_2fa {
        let code = req
            .totp_code
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty());
        let Some(code) = code else {
            st.store.reopen_sso_code(flow.id).await?;
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "totp_required",
                "enter the two-step verification code",
            ));
        };
        if st.limiter.is_blocked(&user.email, ip) {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_attempts",
                "too many attempts: wait a few minutes",
            ));
        }
        match st
            .store
            .totp_check(user.id, code, chrono::Utc::now().timestamp() as u64)
            .await?
        {
            SecondFactor::Totp => via = "sso+totp",
            SecondFactor::RecoveryCode => via = "sso+recovery_code",
            SecondFactor::Invalid => {
                st.limiter.failure(&user.email, ip);
                st.store.reopen_sso_code(flow.id).await?;
                return Err(ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    "totp_invalid",
                    "the verification code is not correct",
                ));
            }
        }
    }
    let device = if flow.device_name.is_empty() {
        "SSO".to_string()
    } else {
        flow.device_name.clone()
    };
    let tokens = st
        .store
        .issue_device_from(
            user.id,
            &device,
            &flow.platform,
            st.ttl,
            Some(&client_info(ip, &ua)),
        )
        .await?;
    st.store
        .audit(
            user.id,
            &format!("user:{}", user.id),
            "auth.login",
            Some(tokens.device_id.to_string()),
            json!({"device": device, "platform": flow.platform, "via": via, "ip": ip, "team": flow.team_id}),
        )
        .await?;
    st.store
        .audit_team(
            flow.team_id,
            user.id,
            &format!("user:{}", user.id),
            "sso.login",
            Some(user.id.to_string()),
            json!({"email": user.email, "platform": flow.platform, "device": device, "ip": ip}),
        )
        .await?;
    let team_2fa = crate::routes::security::team_2fa(&st, &user).await;
    Ok(Json(AuthResponse {
        user,
        tokens,
        verification_required: false,
        team_2fa,
    }))
}

/// Your linked identities, each with its team's name (`team_name`).
async fn my_identities(State(st): State<AppState>, u: AuthUser) -> ApiResult<Json<Value>> {
    let teams = st.store.teams_of(u.id()).await?;
    let mut list = json!(st.store.sso_identities_of(u.id()).await?);
    if let Some(items) = list.as_array_mut() {
        for i in items {
            let name = i["team_id"]
                .as_str()
                .and_then(|t| teams.iter().find(|x| x.id.to_string() == t))
                .map(|t| t.name.clone());
            i["team_name"] = json!(name);
        }
    }
    Ok(Json(list))
}

async fn unlink(
    State(st): State<AppState>,
    u: AuthUser,
    Path(team): Path<Id>,
) -> ApiResult<Json<Value>> {
    if u.user.sso_only {
        return Err(
            ApiError::conflict("this account has no password: set one before unlinking")
                .with_code("sso_only_account"),
        );
    }
    let n = st.store.unlink_sso_identities(u.id(), team).await?;
    if n > 0 {
        st.store
            .audit_team(
                team,
                u.id(),
                &u.actor(),
                "sso.unlink",
                Some(u.id().to_string()),
                json!({}),
            )
            .await?;
    }
    Ok(Json(json!({"ok": true, "removed": n})))
}

// ---------------------------------------------------------------------------
// Team settings
// ---------------------------------------------------------------------------

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

/// `GET /teams/{id}/sso`.
#[derive(Debug, Serialize, ToSchema)]
pub struct TeamSso {
    /// `null`: not set up.
    pub config: Option<SsoConfig>,
    /// Register this redirect URI at the identity provider.
    pub redirect_uri: Option<String>,
    pub domains: Vec<TeamDomain>,
}

async fn team_sso_view(st: &AppState, team: Id) -> ApiResult<TeamSso> {
    Ok(TeamSso {
        config: st.store.team_sso(team).await?,
        redirect_uri: public_url(st).ok().map(|b| format!("{b}{CALLBACK_PATH}")),
        domains: st.store.team_domains(team).await?,
    })
}

async fn team_sso(
    State(st): State<AppState>,
    u: AuthUser,
    Path(team): Path<Id>,
) -> ApiResult<Json<TeamSso>> {
    if st.store.team_role(team, u.id()).await?.is_none() {
        return Err(ApiError::not_found(format!("team {team}")));
    }
    let mut v = team_sso_view(&st, team).await?;
    // Plain members see whether SSO exists, not its details.
    if !matches!(
        st.store.team_role(team, u.id()).await?,
        Some(TeamRole::Owner | TeamRole::Admin)
    ) {
        v.domains.retain(|d| d.verified_at.is_some());
        for d in &mut v.domains {
            d.token.clear();
            d.record_value.clear();
        }
    }
    Ok(Json(v))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetTeamSso {
    pub config: SsoConfig,
    /// `null`/missing keeps the stored secret, `""` removes it.
    #[serde(default)]
    pub client_secret: Option<String>,
}

async fn set_team_sso(
    State(st): State<AppState>,
    u: AuthUser,
    Path(team): Path<Id>,
    Json(req): Json<SetTeamSso>,
) -> ApiResult<Json<TeamSso>> {
    require_team_admin(&st, team, &u).await?;
    if !st.config.sso.enabled {
        return Err(ApiError::not_found("single sign-on is off on this server")
            .with_code("sso_not_configured"));
    }
    let cfg = req.config.normalized()?;
    if cfg.enabled {
        // Reachable and coherent before anyone depends on it.
        st.sso.discovery.lock().remove(&cfg.issuer);
        st.sso.discovery(&st, &cfg.issuer).await?;
    }
    if cfg.enforce
        && !st
            .store
            .team_domains(team)
            .await?
            .iter()
            .any(|d| d.verified_at.is_some())
    {
        return Err(ApiError::conflict("enforcing SSO needs a verified domain")
            .with_code("sso_domain_unverified"));
    }
    let secret = match req.client_secret {
        None => None,
        Some(s) if s.is_empty() => Some(None),
        Some(s) => Some(Some(
            st.store
                .master_key()
                .seal(s.as_bytes(), format!("termoak:sso:{team}").as_bytes())?,
        )),
    };
    let saved = st.store.set_team_sso(team, cfg, secret, u.id()).await?;
    st.store
        .audit_team(
            team,
            u.id(),
            &u.actor(),
            "sso.config",
            Some(team.to_string()),
            json!({"enabled": saved.enabled, "preset": saved.preset, "issuer": saved.issuer, "enforce": saved.enforce, "client_secret": saved.has_client_secret}),
        )
        .await?;
    Ok(Json(team_sso_view(&st, team).await?))
}

async fn delete_team_sso(
    State(st): State<AppState>,
    u: AuthUser,
    Path(team): Path<Id>,
) -> ApiResult<Json<Value>> {
    require_team_admin(&st, team, &u).await?;
    st.store.delete_team_sso(team).await?;
    st.store
        .audit_team(
            team,
            u.id(),
            &u.actor(),
            "sso.config",
            Some(team.to_string()),
            json!({"deleted": true}),
        )
        .await?;
    Ok(Json(json!({"ok": true})))
}

async fn domains(
    State(st): State<AppState>,
    u: AuthUser,
    Path(team): Path<Id>,
) -> ApiResult<Json<Vec<TeamDomain>>> {
    require_team_admin(&st, team, &u).await?;
    Ok(Json(st.store.team_domains(team).await?))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AddDomain {
    pub domain: String,
}

async fn add_domain(
    State(st): State<AppState>,
    u: AuthUser,
    Path(team): Path<Id>,
    Json(req): Json<AddDomain>,
) -> ApiResult<Json<TeamDomain>> {
    require_team_admin(&st, team, &u).await?;
    let domain = normalize_domain(&req.domain)?;
    if st.store.team_domains(team).await?.len() >= 20 {
        return Err(
            ApiError::conflict("a team can have at most 20 domains").with_code("limit_reached")
        );
    }
    let d = st
        .store
        .add_team_domain(team, domain.clone(), u.id())
        .await?;
    st.store
        .audit_team(
            team,
            u.id(),
            &u.actor(),
            "sso.domain_add",
            Some(domain),
            json!({}),
        )
        .await?;
    Ok(Json(d))
}

async fn verify_domain(
    State(st): State<AppState>,
    u: AuthUser,
    Path((team, domain)): Path<(Id, String)>,
) -> ApiResult<Json<TeamDomain>> {
    require_team_admin(&st, team, &u).await?;
    let domain = normalize_domain(&domain)?;
    let d = st
        .store
        .team_domain(domain.clone())
        .await?
        .filter(|d| d.team_id == team)
        .ok_or_else(|| ApiError::not_found(format!("domain {domain}")))?;
    let outcome = dns_has_token(&st, &domain, &d.token)
        .await
        .map(|_| "dns".to_string());
    let ok = outcome.is_ok();
    let d = st
        .store
        .record_domain_check(domain.clone(), outcome)
        .await?;
    st.store
        .audit_team(
            team,
            u.id(),
            &u.actor(),
            if ok {
                "sso.domain_verify"
            } else {
                "sso.domain_check_failed"
            },
            Some(domain),
            json!({"error": d.last_error}),
        )
        .await?;
    Ok(Json(d))
}

/// A server administrator vouches for a domain (internal domains without
/// public DNS).
async fn admin_verify_domain(
    State(st): State<AppState>,
    crate::auth::AdminUser(u): crate::auth::AdminUser,
    Path((team, domain)): Path<(Id, String)>,
) -> ApiResult<Json<TeamDomain>> {
    let domain = normalize_domain(&domain)?;
    st.store
        .team_domain(domain.clone())
        .await?
        .filter(|d| d.team_id == team)
        .ok_or_else(|| ApiError::not_found(format!("domain {domain}")))?;
    let d = st
        .store
        .record_domain_check(domain.clone(), Ok(format!("admin:{}", u.id())))
        .await?;
    st.store
        .audit_team(
            team,
            u.id(),
            &u.actor(),
            "sso.domain_verify",
            Some(domain),
            json!({"by": "admin"}),
        )
        .await?;
    Ok(Json(d))
}

async fn remove_domain(
    State(st): State<AppState>,
    u: AuthUser,
    Path((team, domain)): Path<(Id, String)>,
) -> ApiResult<Json<Value>> {
    require_team_admin(&st, team, &u).await?;
    let domain = normalize_domain(&domain)?;
    let removed = st.store.remove_team_domain(team, domain.clone()).await?;
    // Enforcement needs a verified domain.
    if let Some(mut cfg) = st.store.team_sso(team).await?
        && cfg.enforce
        && !st
            .store
            .team_domains(team)
            .await?
            .iter()
            .any(|d| d.verified_at.is_some())
    {
        cfg.enforce = false;
        st.store.set_team_sso(team, cfg, None, u.id()).await?;
    }
    st.store
        .audit_team(
            team,
            u.id(),
            &u.actor(),
            "sso.domain_remove",
            Some(domain),
            json!({"removed": removed}),
        )
        .await?;
    Ok(Json(json!({"ok": true})))
}

/// Kept for `Arc` sharing in the state.
pub fn new_oidc() -> Arc<Oidc> {
    Arc::new(Oidc::default())
}
