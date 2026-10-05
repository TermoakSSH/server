//! Platform account: email verification, password reset, email change,
//! account deletion and plans.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use termoak_core::model::User;
use termoak_core::store::email_tokens::{EmailPurpose, is_email_code};
use termoak_core::store::users::SecondFactor;
use termoak_core::time::now_ms;
use utoipa::ToSchema;

use crate::auth::{AuthResponse, AuthUser, ClientIp};
use crate::config::{Plan, PlanLimits, PlansSection};
use crate::email;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Lifetime of verification links (48 h) and password reset links (1 h).
const VERIFY_TTL_MS: i64 = 48 * 3_600_000;
const RESET_TTL_MS: i64 = 3_600_000;
/// Minimum wait between two verification emails.
const RESEND_AFTER_MS: i64 = 60_000;
/// Lifetime of the six-digit verification codes (15 minutes).
pub const CODE_TTL_MS: i64 = 15 * 60_000;

#[derive(Debug, Deserialize, ToSchema)]
pub struct TokenRequest {
    pub token: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyCode {
    pub email: String,
    /// The six digits from the email (spaces and dashes are ignored).
    pub code: String,
    /// Name of this device (as in the login). `device` is accepted too.
    #[serde(default, alias = "device")]
    pub device_name: String,
    #[serde(default)]
    pub platform: String,
    /// Authenticator app code or recovery code, only if the account already
    /// has two-step verification (otherwise `totp_required`).
    #[serde(default)]
    pub totp_code: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ResendCode {
    pub email: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ForgotPassword {
    pub email: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ResetWithToken {
    pub token: String,
    pub password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangeEmail {
    pub email: String,
    /// Current password.
    pub password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DeleteAccount {
    pub password: String,
    /// 2FA code (or recovery code) if the account has it enabled.
    #[serde(default)]
    pub totp_code: Option<String>,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/plans", get(plans))
        .route("/api/v1/me/plan", get(my_plan))
        .route("/api/v1/me/verify-email", post(send_verification))
        .route("/api/v1/me/email", post(change_email))
        .route("/api/v1/auth/verify-email", post(verify_email))
        .route("/api/v1/auth/verify-code", post(verify_code))
        .route("/api/v1/auth/resend-code", post(resend_code))
        .route("/api/v1/auth/confirm-email", post(confirm_email))
        .route("/api/v1/auth/forgot-password", post(forgot_password))
        .route("/api/v1/auth/reset-password", post(reset_password))
}

/// The server requires a verified email (and can send emails).
pub fn verification_enforced(st: &AppState) -> bool {
    st.config.email.require_verification && st.mailer.enabled()
}

/// The user's email must be verified to use the account.
pub fn verification_required(st: &AppState, user: &User) -> bool {
    verification_enforced(st) && !user.email_verified
}

/// `403 email_not_verified`, with the address and the ways to verify it so
/// that clients can open the screen to enter the code.
pub fn email_not_verified(user: &User) -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "email_not_verified",
        "confirm your email to use the account (check your inbox)",
    )
    .with_detail("email", user.email.clone())
    .with_detail("verification", json!(["code", "link"]))
}

/// Website link (`/path?token=...`).
fn web_link(st: &AppState, path: &str, token: &str) -> String {
    let enc: String = url::form_urlencoded::byte_serialize(token.as_bytes()).collect();
    format!("{}{path}?token={enc}", st.config.base_url())
}

/// Sends the verification email for the current address. When the server
/// requires a verified email it carries a new six-digit code (valid for
/// [`CODE_TTL_MS`]) as well as the link, which older apps and the website
/// still use; otherwise only the link.
pub async fn send_verification_email(st: &AppState, user: &User) -> ApiResult<()> {
    let token = st
        .store
        .create_email_token(user.id, EmailPurpose::Verify, &user.email, VERIFY_TTL_MS)
        .await?;
    let link = web_link(st, "/verify-email", &token);
    let mail = if verification_enforced(st) {
        let code = st
            .store
            .create_email_code(user.id, &user.email, CODE_TTL_MS)
            .await?;
        email::verify_code(
            &user.email,
            &user.locale,
            &user.name,
            &code,
            CODE_TTL_MS / 60_000,
            &link,
        )
    } else {
        email::verify_email(&user.email, &user.locale, &user.name, &link)
    };
    st.mailer.send(mail).await.map_err(|e| mail_error(&e))
}

/// After signing in to an unverified account: emails a new code if the last
/// one can no longer be used (expired, used up or never sent), within the
/// limits on code emails. Failures are only logged.
pub async fn refresh_code_on_login(st: &AppState, user: &User, ip: Option<std::net::IpAddr>) {
    match st.store.has_email_code(user.id).await {
        Ok(false) => {}
        Ok(true) => return,
        Err(e) => {
            tracing::warn!(user = %user.id, error = %e, "could not check the email code");
            return;
        }
    }
    if st.code_emails.try_send(&user.email, ip).is_err() {
        return;
    }
    if let Err(e) = send_verification_email(st, user).await {
        tracing::warn!(user = %user.id, error = %e.message, "no verification email");
    }
}

fn mail_error(e: &anyhow::Error) -> ApiError {
    tracing::warn!(error = %e, "could not send an email");
    ApiError::new(
        StatusCode::BAD_GATEWAY,
        "email_failed",
        "could not send the email; try again later",
    )
}

fn no_email() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "email_disabled",
        "this server does not send emails: ask an administrator for help",
    )
}

/// The email link (verification, change or reset) is invalid or expired.
fn invalid_link() -> ApiError {
    ApiError::bad_request("the link is invalid or has expired").with_code("invalid_link")
}

/// Another account already uses that email.
pub fn email_taken() -> ApiError {
    ApiError::conflict("an account with that email already exists").with_code("email_taken")
}

/// Maps the store's unique-email conflict to `email_taken`.
pub fn map_email_taken(e: termoak_core::CoreError) -> ApiError {
    match e {
        termoak_core::CoreError::Conflict(_) => email_taken(),
        other => other.into(),
    }
}

/// Password policy, checked here to answer with `password_too_short`.
pub fn check_password_len(password: &str) -> ApiResult<()> {
    let min = termoak_core::store::users::MIN_PASSWORD_LEN;
    if password.chars().count() < min {
        return Err(ApiError::bad_request(format!(
            "the password must be at least {min} characters long"
        ))
        .with_code("password_too_short")
        .with_detail("min", min));
    }
    Ok(())
}

// --- Plans --------------------------------------------------------------------

/// Plan catalog (public).
async fn plans(State(st): State<AppState>) -> Json<Value> {
    Json(json!({
        "default": st.config.plans.default,
        "plans": st.config.plans.catalog,
    }))
}

/// Your plan, its limits and your usage.
async fn my_plan(State(st): State<AppState>, u: AuthUser) -> ApiResult<Json<Value>> {
    let plan = st.config.plans.get(&u.user.plan);
    let teams_owned = st.store.teams_owned(u.id()).await?;
    let sessions = st
        .sessions
        .owned_by(u.id())
        .iter()
        .filter(|s| !s.state().is_closed())
        .count();
    let access = server_ai_access(&st.config.plans, st.config.ai.monthly_budget_usd, &u.user);
    let ai_spent = st.ai.server_spend_this_month(u.id()).await?;
    Ok(Json(json!({
        "plan": plan,
        "usage": {
            "teams_owned": teams_owned,
            "server_sessions": sessions,
            "ai_spent_usd": micros_to_usd(ai_spent),
            "ai_credit_usd": access.credit_micros.filter(|_| access.allowed).map(micros_to_usd),
        },
    })))
}

/// Micro-USD to USD (rounded to 4 decimals).
pub fn micros_to_usd(micros: i64) -> f64 {
    (micros as f64 / 100.0).round() / 10_000.0
}

/// Access of a user to the server's AI providers, according to their plan:
/// administrators without limits; otherwise the plan's `server_ai` with its
/// `ai_credit_usd`, or `[ai] monthly_budget_usd` as the fallback credit.
pub fn server_ai_access(
    plans: &PlansSection,
    fallback_credit_usd: Option<f64>,
    user: &User,
) -> termoak_ai::ServerAccess {
    if user.is_admin {
        return termoak_ai::ServerAccess::UNRESTRICTED;
    }
    let limits = plans.get(&user.plan).limits;
    termoak_ai::ServerAccess {
        allowed: limits.server_ai,
        credit_micros: limits
            .ai_credit_usd
            .or(fallback_credit_usd)
            .map(termoak_ai::access::usd_to_micros),
    }
}

/// [`termoak_ai::AccessPolicy`] backed by the plans.
pub struct PlanAiPolicy {
    pub store: termoak_core::Store,
    pub plans: PlansSection,
    pub fallback_credit_usd: Option<f64>,
}

#[async_trait::async_trait]
impl termoak_ai::AccessPolicy for PlanAiPolicy {
    async fn server_access(
        &self,
        owner: termoak_core::Id,
    ) -> Result<termoak_ai::ServerAccess, termoak_ai::AiError> {
        let user = self.store.user(owner).await?;
        Ok(server_ai_access(
            &self.plans,
            self.fallback_credit_usd,
            &user,
        ))
    }
}

/// `limit` is the `PlanLimits` field that was reached (`max_teams`...).
fn limit_error(limit: &str, what: &str, max: u32) -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "plan_limit",
        format!("your plan allows at most {max} {what}"),
    )
    .with_detail("limit", limit)
    .with_detail("max", max)
}

/// Plan limits of a user (administrators have none).
fn limits_for(st: &AppState, user: &User) -> Option<PlanLimits> {
    (!user.is_admin).then(|| st.config.plans.get(&user.plan).limits)
}

/// Can the user create another team?
pub async fn check_new_team(st: &AppState, user: &User) -> ApiResult<()> {
    if let Some(max) = limits_for(st, user).and_then(|l| l.max_teams)
        && st.store.teams_owned(user.id).await? >= i64::from(max)
    {
        return Err(limit_error("max_teams", "teams", max));
    }
    Ok(())
}

/// Does another member fit in the team (according to the team's plan)?
pub fn check_team_size(st: &AppState, team_plan: &str, members: i64) -> ApiResult<()> {
    let plan: Plan = st.config.plans.get(team_plan);
    if let Some(max) = plan.limits.max_team_members
        && members >= i64::from(max)
    {
        return Err(limit_error("max_team_members", "members in this team", max));
    }
    Ok(())
}

/// Can the user open another server session?
pub fn check_new_session(st: &AppState, user: &User) -> ApiResult<()> {
    if let Some(max) = limits_for(st, user).and_then(|l| l.max_server_sessions) {
        let active = st
            .sessions
            .owned_by(user.id)
            .iter()
            .filter(|s| !s.state().is_closed())
            .count();
        if active >= max as usize {
            return Err(limit_error(
                "max_server_sessions",
                "open sessions at a time",
                max,
            ));
        }
    }
    Ok(())
}

// --- Email verification ---------------------------------------------------

async fn send_verification(State(st): State<AppState>, u: AuthUser) -> ApiResult<Json<Value>> {
    if u.user.email_verified {
        return Err(ApiError::bad_request("your email is already verified")
            .with_code("email_already_verified"));
    }
    if !st.mailer.enabled() {
        return Err(no_email());
    }
    let wait = match st
        .store
        .last_email_token_at(u.id(), EmailPurpose::Verify)
        .await?
    {
        Some(at) if now_ms() - at < RESEND_AFTER_MS => RESEND_AFTER_MS - (now_ms() - at),
        _ => 0,
    };
    // The email carries a code too: same limits as `/auth/resend-code`.
    let wait = if wait > 0 || !verification_enforced(&st) {
        wait
    } else {
        st.code_emails
            .try_send(&u.user.email, None)
            .err()
            .unwrap_or(0)
    };
    if wait > 0 {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_attempts",
            "wait a minute before asking for another email",
        )
        .with_detail("retry_after", (wait + 999) / 1000));
    }
    send_verification_email(&st, &u.user).await?;
    Ok(Json(json!({"sent": true, "email": u.user.email})))
}

async fn verify_email(
    State(st): State<AppState>,
    Json(req): Json<TokenRequest>,
) -> ApiResult<Json<Value>> {
    let t = st
        .store
        .consume_email_token(&req.token, EmailPurpose::Verify)
        .await?
        .ok_or_else(invalid_link)?;
    let user = st.store.user(t.user_id).await?;
    // If the email changed after asking for the link, the link is no longer valid.
    if !user.email.eq_ignore_ascii_case(&t.email) {
        return Err(invalid_link());
    }
    let user = st.store.set_email_verified(user.id, true).await?;
    // The code sent with the link is no longer needed.
    st.store.invalidate_email_codes(user.id).await?;
    st.store
        .audit(
            user.id,
            &format!("user:{}", user.id),
            "auth.email_verified",
            None,
            json!({"via": "link"}),
        )
        .await?;
    Ok(Json(json!({"ok": true, "email": user.email})))
}

/// The code is wrong, expired, used up or there is none (one answer for all,
/// whether or not the account exists).
fn invalid_code() -> ApiError {
    ApiError::bad_request("the code is wrong or has expired: check it or ask for a new one")
        .with_code("invalid_code")
}

/// The account of an email typed by someone signed out (`None` when there
/// is none, or the address is not valid).
async fn account_for(st: &AppState, email: &str) -> ApiResult<Option<User>> {
    match st.store.user_by_email(email).await {
        Ok(user) => Ok(user),
        Err(termoak_core::CoreError::Invalid(_)) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// `POST /auth/verify-code`: verifies the email with the six-digit code from
/// the verification email and signs in, like the login.
async fn verify_code(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<VerifyCode>,
) -> ApiResult<Json<AuthResponse>> {
    if st.limiter.is_blocked(&req.email, ip) {
        return Err(crate::auth::too_many_attempts());
    }
    let code: String = req
        .code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    let user = account_for(&st, &req.email)
        .await?
        .filter(|u| !u.disabled && verification_required(&st, u));
    // Checked without spending it: two-step verification may come next.
    let found = match &user {
        Some(u) if is_email_code(&code) => st
            .store
            .check_email_code(u.id, &code, false)
            .await?
            .filter(|t| t.email.eq_ignore_ascii_case(&u.email)),
        _ => None,
    };
    let (Some(user), Some(_)) = (user, found) else {
        st.limiter.failure(&req.email, ip);
        return Err(invalid_code());
    };
    if user.totp_enabled {
        let totp = req
            .totp_code
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty());
        let Some(totp) = totp else {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "totp_required",
                "enter the two-step verification code",
            ));
        };
        if st
            .store
            .totp_check(user.id, totp, crate::auth::unix_secs())
            .await?
            == SecondFactor::Invalid
        {
            st.limiter.failure(&req.email, ip);
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "totp_invalid",
                "the verification code is not correct",
            ));
        }
    }
    if st
        .store
        .check_email_code(user.id, &code, true)
        .await?
        .is_none()
    {
        // Spent by a parallel request.
        return Err(invalid_code());
    }
    st.limiter.success(&user.email);
    let user = st.store.set_email_verified(user.id, true).await?;
    let tokens = st
        .store
        .issue_device(user.id, &req.device_name, &req.platform, st.ttl)
        .await?;
    let actor = format!("user:{}", user.id);
    st.store
        .audit(
            user.id,
            &actor,
            "auth.email_verified",
            None,
            json!({"via": "code"}),
        )
        .await?;
    st.store
        .audit(
            user.id,
            &actor,
            "auth.login",
            Some(tokens.device_id.to_string()),
            json!({"device": req.device_name, "platform": req.platform, "via": "email_code", "ip": ip}),
        )
        .await?;
    Ok(Json(AuthResponse {
        user,
        tokens,
        verification_required: false,
    }))
}

/// `POST /auth/resend-code`: emails a new code. The same answer whether or
/// not there is an unverified account with that email; only the limits on
/// code emails (which count every request) can stop it.
async fn resend_code(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<ResendCode>,
) -> ApiResult<Json<Value>> {
    if !st.mailer.enabled() {
        return Err(no_email());
    }
    if let Err(wait_ms) = st.code_emails.try_send(&req.email, ip) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_attempts",
            "wait before asking for another code",
        )
        .with_detail("retry_after", (wait_ms + 999) / 1000));
    }
    if let Some(user) = account_for(&st, &req.email)
        .await?
        .filter(|u| !u.disabled && verification_required(&st, u))
    {
        // In the background, so the response time does not tell either.
        let st = st.clone();
        tokio::spawn(async move {
            if let Err(e) = send_verification_email(&st, &user).await {
                tracing::warn!(user = %user.id, error = %e.message, "no verification email");
            }
        });
    }
    Ok(Json(json!({
        "ok": true,
        "resend_after": RESEND_AFTER_MS / 1000,
    })))
}

// --- Email change ------------------------------------------------------------

async fn change_email(
    State(st): State<AppState>,
    u: AuthUser,
    Json(req): Json<ChangeEmail>,
) -> ApiResult<Json<Value>> {
    if !st.store.check_password(u.id(), &req.password).await? {
        return Err(ApiError::invalid_password("the password is not correct"));
    }
    let new = req.email.trim().to_lowercase();
    if new.eq_ignore_ascii_case(&u.user.email) {
        return Err(ApiError::bad_request("that is already your email").with_code("same_email"));
    }
    if !new.contains('@') || new.chars().any(char::is_whitespace) {
        return Err(ApiError::bad_request("invalid email").with_code("invalid_email"));
    }
    if st.store.user_by_email(&new).await?.is_some() {
        return Err(email_taken());
    }
    if st.mailer.enabled() {
        let token = st
            .store
            .create_email_token(u.id(), EmailPurpose::ChangeEmail, &new, VERIFY_TTL_MS)
            .await?;
        let link = web_link(&st, "/confirm-email", &token);
        st.mailer
            .send(email::change_email(
                &new,
                &u.user.locale,
                &u.user.name,
                &link,
            ))
            .await
            .map_err(|e| mail_error(&e))?;
        return Ok(Json(json!({"pending": true, "email": new})));
    }
    let user = st
        .store
        .set_email(u.id(), &new)
        .await
        .map_err(map_email_taken)?;
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "auth.email_changed",
            None,
            json!({"email": user.email}),
        )
        .await?;
    Ok(Json(json!({"pending": false, "user": user})))
}

async fn confirm_email(
    State(st): State<AppState>,
    Json(req): Json<TokenRequest>,
) -> ApiResult<Json<Value>> {
    let t = st
        .store
        .consume_email_token(&req.token, EmailPurpose::ChangeEmail)
        .await?
        .ok_or_else(invalid_link)?;
    let user = st
        .store
        .set_email(t.user_id, &t.email)
        .await
        .map_err(map_email_taken)?;
    st.store
        .audit(
            user.id,
            &format!("user:{}", user.id),
            "auth.email_changed",
            None,
            json!({"email": user.email}),
        )
        .await?;
    Ok(Json(json!({"ok": true, "email": user.email})))
}

// --- Password reset ------------------------------------------------------

async fn forgot_password(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<ForgotPassword>,
) -> ApiResult<Json<Value>> {
    if !st.mailer.enabled() {
        return Err(no_email());
    }
    // Counts as an attempt: prevents using this to flood a mailbox.
    if st.limiter.is_blocked(&req.email, ip) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_attempts",
            "too many attempts; wait a few minutes",
        ));
    }
    st.limiter.failure(&req.email, ip);
    // The answer is the same whether the account exists or not.
    if let Some(user) = st.store.user_by_email(&req.email).await?
        && !user.disabled
    {
        let token = st
            .store
            .create_email_token(
                user.id,
                EmailPurpose::ResetPassword,
                &user.email,
                RESET_TTL_MS,
            )
            .await?;
        let link = web_link(&st, "/reset-password", &token);
        st.mailer.send_later(email::reset_password(
            &user.email,
            &user.locale,
            &user.name,
            &link,
        ));
    }
    Ok(Json(json!({"ok": true})))
}

async fn reset_password(
    State(st): State<AppState>,
    Json(req): Json<ResetWithToken>,
) -> ApiResult<Json<Value>> {
    // Password policy first, so the link is not used up for nothing.
    check_password_len(&req.password)?;
    let t = st
        .store
        .consume_email_token(&req.token, EmailPurpose::ResetPassword)
        .await?
        .ok_or_else(invalid_link)?;
    st.store.set_password(t.user_id, &req.password).await?;
    let signed_out = st.store.revoke_all_devices(t.user_id).await?;
    let user = st.store.user(t.user_id).await?;
    if user.email.eq_ignore_ascii_case(&t.email) {
        st.store.set_email_verified(user.id, true).await?;
    }
    st.limiter.success(&user.email);
    st.store
        .audit(
            user.id,
            &format!("user:{}", user.id),
            "auth.password_reset",
            None,
            json!({"devices_signed_out": signed_out}),
        )
        .await?;
    Ok(Json(json!({"ok": true, "email": user.email})))
}

// --- Account deletion ----------------------------------------------------------

/// `DELETE /api/v1/me`: deletes the account and all its data.
pub async fn delete_account(
    State(st): State<AppState>,
    u: AuthUser,
    Json(req): Json<DeleteAccount>,
) -> ApiResult<Json<Value>> {
    if !st.store.check_password(u.id(), &req.password).await? {
        return Err(ApiError::invalid_password("the password is not correct"));
    }
    if u.user.totp_enabled {
        let code = req
            .totp_code
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    "totp_required",
                    "enter the two-step verification code",
                )
            })?;
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if st.store.totp_check(u.id(), code, secs).await? == SecondFactor::Invalid {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "totp_invalid",
                "the verification code is not correct",
            ));
        }
    }
    if u.user.is_admin {
        let admins = st
            .store
            .list_users()
            .await?
            .iter()
            .filter(|x| x.is_admin && !x.disabled)
            .count();
        if admins <= 1 {
            return Err(ApiError::conflict(
                "you are the only administrator: appoint another one before deleting your account",
            )
            .with_code("last_admin"));
        }
    }
    let blocking = st.store.teams_needing_owner(u.id()).await?;
    if !blocking.is_empty() {
        let names: Vec<String> = blocking.iter().map(|t| t.name.clone()).collect();
        let quoted: Vec<String> = names.iter().map(|n| format!("\"{n}\"")).collect();
        return Err(ApiError::conflict(format!(
            "you are the only owner of {}: appoint another owner or delete the team first",
            quoted.join(", ")
        ))
        .with_code("last_team_owner")
        .with_detail("teams", names));
    }
    for live in st.sessions.owned_by(u.id()) {
        let _ = st.sessions.close(&live, u.id()).await;
    }
    st.store.delete_user(u.id()).await?;
    // Out of the sessions others shared with them.
    st.sessions.remove_user(u.id()).await;
    let recordings = st
        .config
        .server
        .data_dir
        .join("recordings")
        .join(u.id().to_string());
    let _ = tokio::fs::remove_dir_all(recordings).await;
    tracing::info!(user = %u.id(), "account deleted by its owner");
    Ok(Json(json!({"ok": true})))
}
