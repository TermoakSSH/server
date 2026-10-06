//! Authentication: accounts, per-device tokens and extractors.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts, Path, Query, State};
use axum::http::HeaderMap;
use axum::http::request::Parts;
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use termoak_core::Id;
use termoak_core::model::{Device, Invite, TeamRole, TokenPair, User};
use termoak_core::store::users::{ClientInfo, SecondFactor};
use utoipa::ToSchema;

use crate::config::Registration;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Authenticated user.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user: User,
    pub device: Device,
}

impl AuthUser {
    pub fn id(&self) -> Id {
        self.user.id
    }

    pub fn actor(&self) -> String {
        format!("user:{}", self.user.id)
    }
}

/// Token from the `Authorization: Bearer` header.
pub fn bearer_from_headers(headers: &axum::http::HeaderMap) -> Option<String> {
    let h = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    h.strip_prefix("Bearer ")
        .or_else(|| h.strip_prefix("bearer "))
        .map(|t| t.trim().to_string())
}

/// Token from the `Authorization: Bearer` header or, for WebSockets only, from `?access_token=`.
pub fn bearer_token(parts: &Parts) -> Option<String> {
    if let Some(t) = bearer_from_headers(&parts.headers) {
        return Some(t);
    }
    let is_ws = parts
        .headers
        .get(axum::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    if is_ws {
        return parts.uri.query().and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find(|(k, _)| k == "access_token")
                .map(|(_, v)| v.into_owned())
        });
    }
    None
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token =
            bearer_token(parts).ok_or_else(|| ApiError::unauthorized("missing access token"))?;
        let client = client_info(client_ip(parts, state), &user_agent(parts));
        match state.store.authenticate_from(&token, Some(&client)).await? {
            Some((user, device)) => {
                // Without a verified email (if the server requires it) the
                // user can only manage their own account.
                let path = parts.uri.path();
                let own_account = path == "/api/v1/me"
                    || path.starts_with("/api/v1/me/")
                    || path.starts_with("/api/v1/auth/")
                    || path.starts_with("/api/v1/devices");
                if !own_account && crate::account::verification_required(state, &user) {
                    return Err(crate::account::email_not_verified(&user));
                }
                Ok(AuthUser { user, device })
            }
            None => Err(ApiError::unauthorized("invalid or expired token")),
        }
    }
}

/// Optional authenticated user (for routes that accept guests with a link).
pub struct MaybeUser(pub Option<AuthUser>);

impl FromRequestParts<AppState> for MaybeUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        match bearer_token(parts) {
            None => Ok(MaybeUser(None)),
            Some(token) => Ok(MaybeUser(
                state
                    .store
                    .authenticate(&token)
                    .await?
                    .map(|(user, device)| AuthUser { user, device }),
            )),
        }
    }
}

/// Client IP: the connection's or, behind a trusted reverse proxy
/// (`trust_forwarded_for`), the last one in `X-Forwarded-For`.
pub struct ClientIp(pub Option<IpAddr>);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(ClientIp(client_ip(parts, state)))
    }
}

/// The client IP of a request (see [`ClientIp`]).
pub fn client_ip(parts: &Parts, state: &AppState) -> Option<IpAddr> {
    if state.config.server.trust_forwarded_for
        && let Some(ip) = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
    {
        return Some(ip);
    }
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
}

/// Short description of the client from `User-Agent` (`Firefox 131 on Linux`).
pub struct UserAgent(pub Option<String>);

impl FromRequestParts<AppState> for UserAgent {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(UserAgent(user_agent(parts)))
    }
}

fn user_agent(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .and_then(crate::devices::describe_user_agent)
}

/// Where a device is used from, for its "last seen".
pub fn client_info(ip: Option<IpAddr>, user_agent: &Option<String>) -> ClientInfo {
    ClientInfo {
        // IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`) as IPv4.
        ip: ip.map(|ip| ip.to_canonical().to_string()),
        user_agent: user_agent.clone(),
    }
}

/// Authenticated administrator.
pub struct AdminUser(pub AuthUser);

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let u = AuthUser::from_request_parts(parts, state).await?;
        if !u.user.is_admin {
            return Err(ApiError::forbidden("administrators only").with_code("admin_only"));
        }
        Ok(AdminUser(u))
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterRequest {
    pub email: String,
    #[serde(default)]
    pub name: String,
    pub password: String,
    #[serde(default)]
    pub device_name: String,
    #[serde(default)]
    pub platform: String,
    /// Invitation code (allows signing up when registration is closed).
    #[serde(default)]
    pub invite: Option<String>,
    /// Preferred language (`en`, `es`...). Without it (or if the server does
    /// not have it), the best match from `Accept-Language`, else `en`.
    #[serde(default)]
    pub locale: Option<String>,
    /// The person accepted the server's terms of use and privacy policy
    /// (`terms_url` and `privacy_url` in `GET /info`). Optional, so older
    /// apps can still sign up; when `true` it is recorded in the audit entry
    /// of the registration. If the server has terms (`terms_url`), `false`
    /// is rejected with `terms_not_accepted`.
    #[serde(default)]
    pub accept_terms: Option<bool>,
    /// Version of the terms that were accepted (`"1.0"`), at most 16
    /// characters. Recorded with `accept_terms`.
    #[serde(default)]
    #[schema(max_length = 16)]
    pub terms_version: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub device_name: String,
    /// `desktop-windows`, `desktop-macos`, `desktop-linux`, `ios`, `android`, `cli`...
    #[serde(default)]
    pub platform: String,
    /// Authenticator app code or recovery code, if the account has two-step
    /// verification. Without it, the server answers 401 with the error code
    /// `totp_required`.
    #[serde(default)]
    pub totp_code: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthResponse {
    pub user: User,
    pub tokens: TokenPair,
    /// The server requires a verified email and this account has not
    /// verified it yet. The tokens then only reach the account itself
    /// (`/me*`, `/auth/*`, `/devices*`; anything else answers
    /// `email_not_verified`) until the code from the email is entered
    /// (`POST /auth/verify-code`, which signs in with new tokens) or its link
    /// is opened.
    pub verification_required: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangePassword {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateMe {
    pub name: Option<String>,
    /// Preferred language for emails and notifications (`en`, `es`...; see
    /// `GET /api/v1/locales`). Unknown languages are rejected with
    /// `invalid_locale`.
    #[serde(default)]
    pub locale: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateUser {
    pub email: String,
    #[serde(default)]
    pub name: String,
    pub password: String,
    #[serde(default)]
    pub is_admin: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUser {
    pub name: Option<String>,
    pub is_admin: Option<bool>,
    pub disabled: Option<bool>,
    /// Plan (catalog id).
    #[serde(default)]
    pub plan: Option<String>,
    /// Mark the email as verified (or not).
    #[serde(default)]
    pub email_verified: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TotpSetup {
    /// Base32 secret (to type it by hand).
    pub secret: String,
    /// `otpauth://` URL for the QR code.
    pub otpauth_url: String,
    /// QR code of `otpauth_url` as SVG.
    pub qr_svg: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TotpCode {
    pub code: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TotpDisable {
    pub password: String,
    /// Current code or recovery code.
    pub code: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateInvite {
    /// Only this email can use it.
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub is_admin: bool,
    /// Team joined when signing up.
    #[serde(default)]
    pub team_id: Option<uuid::Uuid>,
    /// Role in that team (member by default).
    #[serde(default)]
    pub team_role: Option<TeamRole>,
    /// Expiry in hours (7 days by default; 0 = never expires).
    #[serde(default)]
    pub expires_in_hours: Option<i64>,
    /// Send the invitation by email (if it has an email and email is configured).
    #[serde(default = "yes")]
    pub send_email: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreatedInvite {
    pub invite: Invite,
    /// Code given to the invitee (only shown this time).
    pub token: String,
    /// Server to connect to.
    pub server: String,
    /// Link that opens the app directly.
    pub url: String,
    /// Website link to sign up (if the website is enabled).
    pub web_url: Option<String>,
    /// It was sent by email.
    pub emailed: bool,
}

/// Invitation links: server, app (`termoak://`) and website.
pub(crate) fn invite_links(st: &AppState, token: &str) -> (String, String, Option<String>) {
    let server = st.config.base_url();
    let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    let app = format!(
        "termoak://invite?server={}&token={}",
        enc(&server),
        enc(token)
    );
    let web = st
        .config
        .web
        .enabled
        .then(|| format!("{server}/invite/{}", enc(token)));
    (server, app, web)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ResetPassword {
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    #[serde(default)]
    pub before: Option<i64>,
    #[serde(default)]
    pub limit: Option<i64>,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/info", get(info))
        .route("/api/v1/locales", get(locales))
        .route("/api/v1/auth/register", post(register))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/refresh", post(refresh))
        .route("/api/v1/auth/logout", post(logout))
        .route(
            "/api/v1/me",
            get(me)
                .patch(update_me)
                .delete(crate::account::delete_account),
        )
        .route("/api/v1/me/password", post(change_password))
        .route("/api/v1/me/2fa", get(totp_status))
        .route("/api/v1/me/2fa/setup", post(totp_setup))
        .route("/api/v1/me/2fa/enable", post(totp_enable))
        .route("/api/v1/me/2fa/disable", post(totp_disable))
        .route("/api/v1/devices", get(devices))
        .route("/api/v1/devices/sign-out-all", post(sign_out_all))
        .route("/api/v1/devices/{id}", delete(revoke_device))
        .route("/api/v1/invites/{token}", get(invite_info))
        .route("/api/v1/admin/users", get(list_users).post(create_user))
        .route("/api/v1/admin/users/{id}", patch(update_user))
        .route(
            "/api/v1/admin/users/{id}/password",
            post(admin_reset_password),
        )
        .route("/api/v1/admin/users/{id}/2fa/reset", post(admin_reset_totp))
        .route("/api/v1/admin/users/{id}/devices", get(admin_user_devices))
        .route(
            "/api/v1/admin/users/{id}/devices/{device_id}",
            delete(admin_revoke_device),
        )
        .route(
            "/api/v1/admin/invites",
            get(list_invites).post(create_invite),
        )
        .route("/api/v1/admin/invites/{id}", delete(revoke_invite))
        .route("/api/v1/admin/audit", get(admin_audit))
}

/// Public server information.
async fn info(State(st): State<AppState>) -> ApiResult<Json<Value>> {
    let users = st.store.count_users().await?;
    Ok(Json(json!({
        "name": "Termoak",
        "version": env!("CARGO_PKG_VERSION"),
        "api": "v1",
        // Random id of this server's database: apps tell servers apart with it.
        "instance_id": st.instance_id,
        // Set on test servers ("preprod"...): the web apps show a banner.
        "environment": st.config.server.environment.as_deref().map(str::trim).filter(|e| !e.is_empty()),
        "needs_setup": users == 0,
        "registration": match st.config.server.registration {
            Registration::Open => "open",
            Registration::FirstUser => if users == 0 { "open" } else { "closed" },
            Registration::Closed => if users == 0 { "open" } else { "closed" },
        },
        "features": {
            "server_sessions": true,
            "relay_sessions": true,
            "session_sharing": true,
            "sftp": true,
            "ai": true,
            "mcp": true,
            "sync": true,
            "totp": true,
            "invites": true,
            "teams": true,
            // Vaults (`/vaults`), sync v2 (`POST /vaults/sync`) and just-in-time
            // credentials (`POST /hosts/{id}/credentials`).
            "vaults": true,
            "sync_v2": true,
            "credentials": true,
            "plans": true,
            "web": st.config.web.enabled,
            "email": st.mailer.enabled(),
            "email_verification": crate::account::verification_enforced(&st),
            // `POST /auth/verify-code` and `/auth/resend-code` exist.
            "email_verification_code": crate::account::verification_enforced(&st),
            "push": {
                "apns": st.push.as_ref().is_some_and(|p| p.platforms().0),
                "fcm": st.push.as_ref().is_some_and(|p| p.platforms().1),
            },
        },
        "support_email": st.config.web.support_email,
        "terms_url": st.config.web.terms_url,
        "privacy_url": st.config.web.privacy_url,
        "started_at": st.started_at,
    })))
}

/// Languages the server has for emails and notifications (public).
async fn locales() -> Json<Value> {
    let list: Vec<Value> = crate::i18n::available()
        .into_iter()
        .map(|code| json!({"code": code, "name": crate::i18n::language_name(code)}))
        .collect();
    Json(json!({"default": crate::i18n::DEFAULT, "locales": list}))
}

/// A requested locale that the server has, normalized (`es-ES` → `es`).
fn requested_locale(locale: &str) -> ApiResult<&'static str> {
    crate::i18n::supported(locale).ok_or_else(|| {
        ApiError::bad_request(format!(
            "unknown locale \"{locale}\"; available: {}",
            crate::i18n::available().join(", ")
        ))
        .with_code("invalid_locale")
    })
}

async fn register(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> ApiResult<Json<AuthResponse>> {
    let users = st.store.count_users().await?;
    let first = users == 0;
    // With an invitation, sign-up works even when registration is closed.
    let invite = match req
        .invite
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        Some(token) if !first => Some(
            st.store
                .invite_by_token(token)
                .await?
                .ok_or_else(|| invalid_invite(ApiError::forbidden))?,
        ),
        _ => None,
    };
    if let Some(inv) = &invite
        && let Some(email) = &inv.email
        && !email.eq_ignore_ascii_case(req.email.trim())
    {
        return Err(
            ApiError::forbidden("this invitation is for another email address")
                .with_code("invite_email_mismatch"),
        );
    }
    if !first && invite.is_none() && st.config.server.registration != Registration::Open {
        return Err(ApiError::forbidden(
            "registration is closed: ask an administrator for an invitation",
        )
        .with_code("registration_closed"));
    }
    let is_admin = first || invite.as_ref().is_some_and(|i| i.is_admin);
    // Verified when there is no email, for the first account, or when the
    // invitation was sent to that email.
    let verified =
        !st.mailer.enabled() || first || invite.as_ref().is_some_and(|i| i.email.is_some());
    let locale = req
        .locale
        .as_deref()
        .and_then(crate::i18n::supported)
        .or_else(|| crate::i18n::from_accept_language(&headers))
        .unwrap_or(crate::i18n::DEFAULT);
    check_new_account(&req.email, &req.password)?;
    let terms = terms_acceptance(&st, &req)?;
    let mut user = st
        .store
        .create_account(&req.email, &req.name, &req.password, is_admin, verified)
        .await
        .map_err(crate::account::map_email_taken)?;
    if user.locale != locale {
        user = st.store.set_locale(user.id, locale).await?;
    }
    if let Some(inv) = &invite {
        if let Err(e) = st.store.consume_invite(inv.id, user.id).await {
            // Someone else used it at the same time: the account cannot stay.
            let _ = st.store.update_user(user.id, None, None, Some(true)).await;
            return Err(e.into());
        }
        if let Some(team) = inv.team_id {
            // The team may have been deleted after the invitation: not an error.
            let _ = st
                .store
                .set_team_member(team, user.id, inv.team_role.unwrap_or(TeamRole::Member))
                .await;
        }
    }
    if !user.email_verified {
        // Counts against the limits on code emails (so asking for another
        // one right away waits), but is always sent: it is the first.
        let _ = st.code_emails.try_send(&user.email, ip);
        if let Err(e) = crate::account::send_verification_email(&st, &user).await {
            // The account is created: the user can ask for another email later.
            tracing::warn!(user = %user.id, error = %e.message, "no verification email");
        }
    }
    let tokens = st
        .store
        .issue_device_from(
            user.id,
            &req.device_name,
            &req.platform,
            st.ttl,
            Some(&client_info(ip, &ua)),
        )
        .await?;
    let mut detail = json!({"platform": req.platform, "invite": invite.as_ref().map(|i| i.id)});
    if let Some(terms) = terms {
        detail["terms"] = terms;
    }
    st.store
        .audit(
            user.id,
            &format!("user:{}", user.id),
            "auth.register",
            None,
            detail,
        )
        .await?;
    let verification_required = crate::account::verification_required(&st, &user);
    Ok(Json(AuthResponse {
        user,
        tokens,
        verification_required,
    }))
}

/// Maximum length of `terms_version`.
const TERMS_VERSION_MAX: usize = 16;

/// Acceptance of the terms in a registration, for its audit entry:
/// `{"accepted": true, "version": "1.0"}`, or `None` when the client did not
/// say (older apps). An explicit `false` is rejected when the server has
/// terms of use (`[web] terms_url`).
fn terms_acceptance(st: &AppState, req: &RegisterRequest) -> ApiResult<Option<Value>> {
    let version = req
        .terms_version
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    if let Some(v) = version
        && (v.chars().count() > TERMS_VERSION_MAX || v.chars().any(char::is_control))
    {
        return Err(ApiError::bad_request(format!(
            "terms_version must be at most {TERMS_VERSION_MAX} printable characters"
        ))
        .with_code("invalid_terms_version"));
    }
    match req.accept_terms {
        Some(true) => Ok(Some(json!({"accepted": true, "version": version}))),
        Some(false) if st.config.web.terms_url.is_some() => Err(ApiError::bad_request(
            "the terms of use and the privacy policy must be accepted to sign up",
        )
        .with_code("terms_not_accepted")),
        _ => Ok(None),
    }
}

/// The invitation code is invalid, used, revoked or expired.
fn invalid_invite(kind: fn(String) -> ApiError) -> ApiError {
    kind("the invitation is invalid or has expired".into()).with_code("invalid_invite")
}

/// Email format and password policy, checked here to answer with specific
/// codes (`invalid_email`, `password_too_short`).
fn check_new_account(email: &str, password: &str) -> ApiResult<()> {
    let email = email.trim();
    if email.len() < 3 || !email.contains('@') || email.chars().any(char::is_whitespace) {
        return Err(ApiError::bad_request("invalid email").with_code("invalid_email"));
    }
    crate::account::check_password_len(password)
}

pub(crate) fn too_many_attempts() -> ApiError {
    ApiError::new(
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        "too_many_attempts",
        "too many failed attempts; wait a few minutes",
    )
}

pub(crate) fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn login(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<AuthResponse>> {
    if st.limiter.is_blocked(&req.email, ip) {
        return Err(too_many_attempts());
    }
    let Some(user) = st.store.verify_login(&req.email, &req.password).await? else {
        st.limiter.failure(&req.email, ip);
        return Err(
            ApiError::unauthorized("wrong email or password").with_code("invalid_credentials")
        );
    };
    let mut via = "password";
    if user.totp_enabled {
        let code = req
            .totp_code
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty());
        let Some(code) = code else {
            return Err(ApiError::new(
                axum::http::StatusCode::UNAUTHORIZED,
                "totp_required",
                "enter the two-step verification code",
            ));
        };
        match st.store.totp_check(user.id, code, unix_secs()).await? {
            SecondFactor::Totp => via = "totp",
            SecondFactor::RecoveryCode => via = "recovery_code",
            SecondFactor::Invalid => {
                st.limiter.failure(&req.email, ip);
                return Err(ApiError::new(
                    axum::http::StatusCode::UNAUTHORIZED,
                    "totp_invalid",
                    "the verification code is not correct",
                ));
            }
        }
    }
    st.limiter.success(&req.email);
    let tokens = st
        .store
        .issue_device_from(
            user.id,
            &req.device_name,
            &req.platform,
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
            json!({"device": req.device_name, "platform": req.platform, "via": via, "ip": ip}),
        )
        .await?;
    // Unverified: the tokens only reach the account itself, and the user
    // needs a code that still works.
    let verification_required = crate::account::verification_required(&st, &user);
    if verification_required {
        crate::account::refresh_code_on_login(&st, &user, ip).await;
    }
    Ok(Json(AuthResponse {
        user,
        tokens,
        verification_required,
    }))
}

async fn refresh(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    UserAgent(ua): UserAgent,
    Json(req): Json<RefreshRequest>,
) -> ApiResult<Json<TokenPair>> {
    st.store
        .refresh_device_from(&req.refresh_token, st.ttl, Some(&client_info(ip, &ua)))
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::unauthorized("invalid or expired refresh token"))
}

async fn logout(State(st): State<AppState>, u: AuthUser) -> ApiResult<Json<Value>> {
    st.store.revoke_device(u.id(), u.device.id).await?;
    st.sockets.sign_out_device(u.device.id);
    Ok(Json(json!({"ok": true})))
}

async fn me(State(st): State<AppState>, u: AuthUser) -> Json<Value> {
    let plan = st.config.plans.get(&u.user.plan);
    let verification_required = crate::account::verification_required(&st, &u.user);
    Json(json!({
        "user": u.user,
        "device": u.device,
        "plan": plan,
        "verification_required": verification_required,
    }))
}

async fn update_me(
    State(st): State<AppState>,
    u: AuthUser,
    Json(req): Json<UpdateMe>,
) -> ApiResult<Json<User>> {
    let locale = req.locale.as_deref().map(requested_locale).transpose()?;
    let mut user = st.store.update_user(u.id(), req.name, None, None).await?;
    if let Some(locale) = locale
        && locale != user.locale
    {
        user = st.store.set_locale(u.id(), locale).await?;
    }
    Ok(Json(user))
}

async fn change_password(
    State(st): State<AppState>,
    u: AuthUser,
    Json(req): Json<ChangePassword>,
) -> ApiResult<Json<Value>> {
    if st
        .store
        .verify_login(&u.user.email, &req.current_password)
        .await?
        .is_none()
    {
        return Err(ApiError::invalid_password(
            "the current password is not correct",
        ));
    }
    crate::account::check_password_len(&req.new_password)?;
    st.store.set_password(u.id(), &req.new_password).await?;
    st.store
        .audit(u.id(), &u.actor(), "auth.password_changed", None, json!({}))
        .await?;
    Ok(Json(json!({"ok": true})))
}

async fn devices(State(st): State<AppState>, u: AuthUser) -> ApiResult<Json<Value>> {
    let list = st.store.list_devices(u.id()).await?;
    Ok(Json(json!({"current": u.device.id, "devices": list})))
}

async fn revoke_device(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    st.store.revoke_device(u.id(), id).await?;
    st.sockets.sign_out_device(id);
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "auth.device_revoked",
            Some(id.to_string()),
            json!({"current": id == u.device.id}),
        )
        .await?;
    Ok(Json(json!({"ok": true})))
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct SignOutAll {
    /// Sign this device out too (`false` by default: only the others).
    #[serde(default)]
    pub include_current: bool,
}

/// `POST /api/v1/devices/sign-out-all`: signs out every device of the user
/// but this one (or this one too with `include_current`) and closes their
/// WebSockets.
async fn sign_out_all(
    State(st): State<AppState>,
    u: AuthUser,
    req: Option<Json<SignOutAll>>,
) -> ApiResult<Json<Value>> {
    let include_current = req.is_some_and(|Json(r)| r.include_current);
    let keep = (!include_current).then_some(u.device.id);
    let revoked = st.store.revoke_devices_except(u.id(), keep).await?;
    st.sockets.sign_out_devices(&revoked);
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "auth.devices_revoked",
            None,
            json!({"count": revoked.len(), "include_current": include_current}),
        )
        .await?;
    Ok(Json(json!({"revoked": revoked.len()})))
}

async fn list_users(State(st): State<AppState>, _a: AdminUser) -> ApiResult<Json<Vec<User>>> {
    Ok(Json(st.store.list_users().await?))
}

async fn create_user(
    State(st): State<AppState>,
    AdminUser(a): AdminUser,
    Json(req): Json<CreateUser>,
) -> ApiResult<Json<User>> {
    check_new_account(&req.email, &req.password)?;
    let mut user = st
        .store
        .create_user(&req.email, &req.name, &req.password, req.is_admin)
        .await
        .map_err(crate::account::map_email_taken)?;
    // The admin's language is the best guess for the new account.
    if user.locale != a.user.locale {
        user = st.store.set_locale(user.id, &a.user.locale).await?;
    }
    st.store
        .audit(
            a.id(),
            &a.actor(),
            "admin.user_created",
            Some(user.id.to_string()),
            json!({"email": user.email}),
        )
        .await?;
    Ok(Json(user))
}

async fn update_user(
    State(st): State<AppState>,
    AdminUser(a): AdminUser,
    Path(id): Path<Id>,
    Json(req): Json<UpdateUser>,
) -> ApiResult<Json<User>> {
    if id == a.id() && (req.disabled == Some(true) || req.is_admin == Some(false)) {
        return Err(ApiError::bad_request(
            "you cannot disable yourself or remove your own administrator role",
        )
        .with_code("cannot_modify_self"));
    }
    if let Some(plan) = &req.plan
        && (!st.config.plans.exists(plan) || st.config.plans.get(plan).for_teams)
    {
        return Err(ApiError::bad_request(format!(
            "plan \"{plan}\" does not exist or is a team plan"
        ))
        .with_code("unknown_plan"));
    }
    let mut user = st
        .store
        .update_user(id, req.name, req.is_admin, req.disabled)
        .await?;
    if let Some(plan) = &req.plan {
        user = st.store.set_user_plan(id, plan).await?;
    }
    if let Some(v) = req.email_verified {
        user = st.store.set_email_verified(id, v).await?;
    }
    if req.disabled == Some(true) {
        // A disabled account leaves the sessions shared with it and loses
        // its server sessions and pooled connections on every vault.
        st.sessions.remove_user(id).await;
        st.sockets.sign_out_user_events(id);
        if let Ok(access) = st.store.vault_access(id).await {
            crate::vaults::revoke_all(&st, id, &access).await;
        }
    }
    st.store
        .audit(
            a.id(),
            &a.actor(),
            "admin.user_updated",
            Some(id.to_string()),
            json!({
                "name": user.name,
                "plan": req.plan,
                "is_admin": req.is_admin,
                "disabled": req.disabled,
                "email_verified": req.email_verified,
            }),
        )
        .await?;
    Ok(Json(user))
}

// --- Two-step verification -----------------------------------------------

async fn totp_status(State(st): State<AppState>, u: AuthUser) -> ApiResult<Json<Value>> {
    let enabled = st.store.user(u.id()).await?.totp_enabled;
    let left = if enabled {
        st.store.recovery_codes_left(u.id()).await?
    } else {
        0
    };
    Ok(Json(
        json!({"enabled": enabled, "recovery_codes_left": left}),
    ))
}

/// Generates the secret and the QR code. Nothing is enabled until a code is confirmed.
async fn totp_setup(State(st): State<AppState>, u: AuthUser) -> ApiResult<Json<TotpSetup>> {
    let secret = st.store.totp_begin(u.id()).await?;
    let otpauth_url = termoak_core::totp::otpauth_url("Termoak", &u.user.email, &secret);
    Ok(Json(TotpSetup {
        secret: termoak_core::totp::secret_to_base32(&secret),
        qr_svg: termoak_core::qr::svg(&otpauth_url).unwrap_or_default(),
        otpauth_url,
    }))
}

async fn totp_enable(
    State(st): State<AppState>,
    u: AuthUser,
    Json(req): Json<TotpCode>,
) -> ApiResult<Json<Value>> {
    let codes = st.store.totp_enable(u.id(), &req.code, unix_secs()).await?;
    st.store
        .audit(u.id(), &u.actor(), "auth.2fa_enabled", None, json!({}))
        .await?;
    Ok(Json(json!({"enabled": true, "recovery_codes": codes})))
}

async fn totp_disable(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    u: AuthUser,
    Json(req): Json<TotpDisable>,
) -> ApiResult<Json<Value>> {
    if st.limiter.is_blocked(&u.user.email, ip) {
        return Err(too_many_attempts());
    }
    let password_ok = st.store.check_password(u.id(), &req.password).await?;
    let code_ok = password_ok
        && st.store.totp_check(u.id(), &req.code, unix_secs()).await? != SecondFactor::Invalid;
    if !code_ok {
        st.limiter.failure(&u.user.email, ip);
        return Err(ApiError::invalid_password(
            "the password or the code is not correct",
        ));
    }
    st.store.totp_disable(u.id()).await?;
    st.store
        .audit(u.id(), &u.actor(), "auth.2fa_disabled", None, json!({}))
        .await?;
    Ok(Json(json!({"enabled": false})))
}

// --- Invitations ----------------------------------------------------------

/// Public data of an invitation (to show "you have been invited to...").
async fn invite_info(
    State(st): State<AppState>,
    Path(token): Path<String>,
) -> ApiResult<Json<Value>> {
    let inv = st
        .store
        .invite_by_token(&token)
        .await?
        .ok_or_else(|| invalid_invite(ApiError::not_found))?;
    let team = match inv.team_id {
        Some(t) => st
            .store
            .team_for(t, inv.created_by)
            .await
            .ok()
            .map(|t| t.name),
        None => None,
    };
    Ok(Json(json!({
        "email": inv.email,
        "team": team,
        "expires_at": inv.expires_at,
    })))
}

async fn list_invites(State(st): State<AppState>, _a: AdminUser) -> ApiResult<Json<Vec<Invite>>> {
    Ok(Json(st.store.list_invites().await?))
}

async fn create_invite(
    State(st): State<AppState>,
    AdminUser(a): AdminUser,
    Json(req): Json<CreateInvite>,
) -> ApiResult<Json<CreatedInvite>> {
    if let Some(team) = req.team_id {
        st.store.team_for(team, a.id()).await?;
    }
    let expires_at = match req.expires_in_hours {
        Some(0) => None,
        Some(h) if h > 0 => Some(termoak_core::time::now_ms() + h * 3_600_000),
        Some(_) => return Err(ApiError::bad_request("invalid expiry")),
        None => Some(termoak_core::time::now_ms() + 7 * 24 * 3_600_000),
    };
    let (invite, token) = st
        .store
        .create_invite(
            a.id(),
            termoak_core::store::invites::NewInvite {
                email: req.email,
                is_admin: req.is_admin,
                team_id: req.team_id,
                team_role: req.team_role,
                expires_at,
            },
        )
        .await?;
    st.store
        .audit(
            a.id(),
            &a.actor(),
            "admin.invite_created",
            Some(invite.id.to_string()),
            json!({"email": invite.email, "is_admin": invite.is_admin, "team": invite.team_id}),
        )
        .await?;
    let (server, url, web_url) = invite_links(&st, &token);
    let emailed = send_invite_email(
        &st,
        &a,
        &invite,
        web_url.as_deref().unwrap_or(&url),
        req.send_email,
    )
    .await;
    Ok(Json(CreatedInvite {
        invite,
        token,
        server,
        url,
        web_url,
        emailed,
    }))
}

/// Sends an invitation by email (if it has an email, email is configured
/// and it was requested). The invitee has no account yet, so the email uses
/// the inviter's language.
pub(crate) async fn send_invite_email(
    st: &AppState,
    from: &AuthUser,
    invite: &Invite,
    link: &str,
    wanted: bool,
) -> bool {
    let Some(to) = invite
        .email
        .as_deref()
        .filter(|_| wanted && st.mailer.enabled())
    else {
        return false;
    };
    let team = match invite.team_id {
        Some(t) => st.store.team_for(t, from.id()).await.ok().map(|t| t.name),
        None => None,
    };
    let inviter = if from.user.name.trim().is_empty() {
        from.user.email.clone()
    } else {
        from.user.name.clone()
    };
    match st
        .mailer
        .send(crate::email::account_invite(
            to,
            &from.user.locale,
            &inviter,
            team.as_deref(),
            link,
        ))
        .await
    {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(error = %e, "could not send the invitation");
            false
        }
    }
}

async fn revoke_invite(
    State(st): State<AppState>,
    AdminUser(a): AdminUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    st.store.revoke_invite(id).await?;
    st.store
        .audit(
            a.id(),
            &a.actor(),
            "admin.invite_revoked",
            Some(id.to_string()),
            json!({}),
        )
        .await?;
    Ok(Json(json!({"ok": true})))
}

// --- User administration --------------------------------------------------

/// Sets a new password and signs the user out on all their devices.
async fn admin_reset_password(
    State(st): State<AppState>,
    AdminUser(a): AdminUser,
    Path(id): Path<Id>,
    Json(req): Json<ResetPassword>,
) -> ApiResult<Json<Value>> {
    crate::account::check_password_len(&req.password)?;
    st.store.set_password(id, &req.password).await?;
    let signed_out = st.store.revoke_all_devices(id).await?;
    st.sockets.sign_out_user(id);
    st.store
        .audit(
            a.id(),
            &a.actor(),
            "admin.password_reset",
            Some(id.to_string()),
            json!({"devices_signed_out": signed_out}),
        )
        .await?;
    Ok(Json(json!({"ok": true, "devices_signed_out": signed_out})))
}

/// Removes two-step verification (the user lost their phone).
async fn admin_reset_totp(
    State(st): State<AppState>,
    AdminUser(a): AdminUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    st.store.totp_disable(id).await?;
    st.store
        .audit(
            a.id(),
            &a.actor(),
            "admin.2fa_reset",
            Some(id.to_string()),
            json!({}),
        )
        .await?;
    Ok(Json(json!({"ok": true})))
}

async fn admin_user_devices(
    State(st): State<AppState>,
    _a: AdminUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<Vec<Device>>> {
    st.store.user(id).await?;
    Ok(Json(st.store.list_devices(id).await?))
}

async fn admin_revoke_device(
    State(st): State<AppState>,
    AdminUser(a): AdminUser,
    Path((id, device_id)): Path<(Id, Id)>,
) -> ApiResult<Json<Value>> {
    st.store.revoke_device(id, device_id).await?;
    st.sockets.sign_out_device(device_id);
    st.store
        .audit(
            a.id(),
            &a.actor(),
            "admin.device_revoked",
            Some(device_id.to_string()),
            json!({"user": id}),
        )
        .await?;
    Ok(Json(json!({"ok": true})))
}

async fn admin_audit(
    State(st): State<AppState>,
    _a: AdminUser,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<Value>> {
    let rows = st
        .store
        .audit_list_all(q.before, q.limit.unwrap_or(100).clamp(1, 1000))
        .await?;
    Ok(Json(json!(rows)))
}
