//! Push notifications to the mobile apps: APNs (iOS) and FCM (Android).
//!
//! Each device registers its token (`POST /api/v1/push/register`) and the
//! server tells it what happens even when the app is closed:
//!
//! - an AI task is waiting for your approval, or has finished or failed;
//! - someone shared a session with you;
//! - one of your sessions is waiting for an answer (server fingerprint, 2FA
//!   code) and you are not watching it;
//! - you were added to a team.
//!
//! By default the text is generic (Apple and Google see it); with
//! `[push] detailed = true` it includes commands and titles. The texts are
//! translated to the recipient's language (`push.*` keys in
//! `locales/<lang>.json`). The notification data carries the ids so the app
//! opens the right screen.
//!
//! Signatures (ES256 for APNs, RS256 for the Firebase service account) are
//! made with `ring`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, RSA_PKCS1_SHA256, RsaKeyPair,
};
use rust_i18n::t;
use serde::Deserialize;
use serde_json::{Value, json};
use termoak_ai::{AiEngine, TaskEvent, TaskStatus};
use termoak_core::store::users::PushTarget;
use termoak_core::{Id, Store};
use tokio::sync::broadcast::error::RecvError;

use crate::auth::AuthUser;
use crate::config::PushSection;
use crate::error::{ApiError, ApiResult};
use crate::sessions::{SessionManager, SessionNotice};
use crate::state::AppState;

/// A notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub title: String,
    pub body: String,
    /// Data for the app (`type` and the relevant ids).
    pub data: BTreeMap<String, String>,
    /// Replaces another one with the same key (e.g. the same approval).
    pub collapse: Option<String>,
}

impl Notification {
    fn new(kind: &str, title: impl Into<String>, body: impl Into<String>) -> Self {
        let mut data = BTreeMap::new();
        data.insert("type".to_string(), kind.to_string());
        Self {
            title: title.into(),
            body: body.into(),
            data,
            collapse: None,
        }
    }

    fn with(mut self, key: &str, value: impl ToString) -> Self {
        self.data.insert(key.to_string(), value.to_string());
        self
    }
}

/// Result of a delivery.
#[derive(Debug, PartialEq, Eq)]
enum Sent {
    Ok,
    /// The token is no longer valid (app uninstalled...): it is forgotten.
    Unregistered,
    Failed(String),
}

// ---------------------------------------------------------------------------
// JWT
// ---------------------------------------------------------------------------

fn pem_to_der(pem: &str) -> anyhow::Result<Vec<u8>> {
    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect();
    Ok(STANDARD.decode(body)?)
}

fn jwt(
    header: &Value,
    claims: &Value,
    sign: impl FnOnce(&[u8]) -> anyhow::Result<Vec<u8>>,
) -> anyhow::Result<String> {
    let msg = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let sig = sign(msg.as_bytes())?;
    Ok(format!("{msg}.{}", URL_SAFE_NO_PAD.encode(sig)))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// APNs
// ---------------------------------------------------------------------------

struct Apns {
    key: EcdsaKeyPair,
    key_id: String,
    team_id: String,
    topic: String,
    endpoint: String,
    sandbox_endpoint: String,
    /// Current JWT (Apple asks to renew it at least once an hour).
    jwt: parking_lot::Mutex<Option<(Instant, String)>>,
}

impl Apns {
    fn token(&self) -> anyhow::Result<String> {
        let mut cached = self.jwt.lock();
        if let Some((at, t)) = cached.as_ref()
            && at.elapsed() < Duration::from_secs(45 * 60)
        {
            return Ok(t.clone());
        }
        let rng = SystemRandom::new();
        let t = jwt(
            &json!({"alg": "ES256", "kid": self.key_id}),
            &json!({"iss": self.team_id, "iat": unix_now()}),
            |msg| {
                Ok(self
                    .key
                    .sign(&rng, msg)
                    .map_err(|_| anyhow::anyhow!("could not sign the APNs JWT"))?
                    .as_ref()
                    .to_vec())
            },
        )?;
        *cached = Some((Instant::now(), t.clone()));
        Ok(t)
    }

    async fn send(&self, http: &reqwest::Client, t: &PushTarget, n: &Notification) -> Sent {
        let token = match self.token() {
            Ok(t) => t,
            Err(e) => return Sent::Failed(e.to_string()),
        };
        let base = if t.sandbox {
            &self.sandbox_endpoint
        } else {
            &self.endpoint
        };
        let mut custom = serde_json::Map::new();
        for (k, v) in &n.data {
            custom.insert(k.clone(), Value::String(v.clone()));
        }
        let body = json!({
            "aps": {
                "alert": {"title": n.title, "body": n.body},
                "sound": "default",
                "thread-id": n.data.get("type").cloned().unwrap_or_default(),
            },
            "termoak": custom,
        });
        let mut req = http
            .post(format!("{base}/3/device/{}", t.token))
            .bearer_auth(token)
            .header("apns-topic", &self.topic)
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .json(&body);
        if let Some(c) = &n.collapse {
            req = req.header("apns-collapse-id", c.chars().take(64).collect::<String>());
        }
        match req.send().await {
            Ok(r) if r.status().is_success() => Sent::Ok,
            Ok(r) => {
                let status = r.status().as_u16();
                let reason = r
                    .json::<Value>()
                    .await
                    .ok()
                    .and_then(|v| v["reason"].as_str().map(str::to_string))
                    .unwrap_or_default();
                if status == 410
                    || matches!(
                        reason.as_str(),
                        "BadDeviceToken" | "Unregistered" | "DeviceTokenNotForTopic"
                    )
                {
                    Sent::Unregistered
                } else {
                    Sent::Failed(format!("APNs answered {status} {reason}"))
                }
            }
            Err(e) => Sent::Failed(format!("APNs: {e}")),
        }
    }
}

// ---------------------------------------------------------------------------
// FCM
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ServiceAccount {
    project_id: String,
    client_email: String,
    private_key: String,
    #[serde(default)]
    private_key_id: Option<String>,
    #[serde(default = "default_token_uri")]
    token_uri: String,
}

fn default_token_uri() -> String {
    "https://oauth2.googleapis.com/token".into()
}

struct Fcm {
    key: RsaKeyPair,
    account: ServiceAccount,
    endpoint: String,
    /// Current OAuth token and when it expires.
    access: tokio::sync::Mutex<Option<(Instant, String)>>,
}

impl Fcm {
    async fn access_token(&self, http: &reqwest::Client) -> anyhow::Result<String> {
        let mut cached = self.access.lock().await;
        if let Some((until, t)) = cached.as_ref()
            && Instant::now() < *until
        {
            return Ok(t.clone());
        }
        let now = unix_now();
        let mut header = json!({"alg": "RS256", "typ": "JWT"});
        if let Some(kid) = &self.account.private_key_id {
            header["kid"] = json!(kid);
        }
        let rng = SystemRandom::new();
        let assertion = jwt(
            &header,
            &json!({
                "iss": self.account.client_email,
                "scope": "https://www.googleapis.com/auth/firebase.messaging",
                "aud": self.account.token_uri,
                "iat": now,
                "exp": now + 3600,
            }),
            |msg| {
                let mut sig = vec![0; self.key.public().modulus_len()];
                self.key
                    .sign(&RSA_PKCS1_SHA256, &rng, msg, &mut sig)
                    .map_err(|_| anyhow::anyhow!("could not sign the Firebase JWT"))?;
                Ok(sig)
            },
        )?;
        #[derive(Deserialize)]
        struct TokenResp {
            access_token: String,
            #[serde(default)]
            expires_in: Option<u64>,
        }
        let resp = http
            .post(&self.account.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "Google answered {} when asked for the FCM token",
                resp.status()
            );
        }
        let t: TokenResp = resp.json().await?;
        let life = t.expires_in.unwrap_or(3600).saturating_sub(120).max(60);
        *cached = Some((
            Instant::now() + Duration::from_secs(life),
            t.access_token.clone(),
        ));
        Ok(t.access_token)
    }

    async fn send(&self, http: &reqwest::Client, t: &PushTarget, n: &Notification) -> Sent {
        let token = match self.access_token(http).await {
            Ok(t) => t,
            Err(e) => return Sent::Failed(e.to_string()),
        };
        let mut android = json!({
            "priority": "HIGH",
            "notification": {"channel_id": "termoak"},
        });
        if let Some(c) = &n.collapse {
            android["collapse_key"] = json!(c);
        }
        let body = json!({
            "message": {
                "token": t.token,
                "notification": {"title": n.title, "body": n.body},
                "data": n.data,
                "android": android,
            }
        });
        let url = format!(
            "{}/v1/projects/{}/messages:send",
            self.endpoint, self.account.project_id
        );
        match http.post(url).bearer_auth(token).json(&body).send().await {
            Ok(r) if r.status().is_success() => Sent::Ok,
            Ok(r) => {
                let status = r.status().as_u16();
                let v: Value = r.json().await.unwrap_or(Value::Null);
                let unregistered = status == 404
                    || v["error"]["details"]
                        .as_array()
                        .is_some_and(|d| d.iter().any(|x| x["errorCode"] == "UNREGISTERED"));
                if unregistered {
                    Sent::Unregistered
                } else {
                    Sent::Failed(format!(
                        "FCM answered {status} {}",
                        v["error"]["message"].as_str().unwrap_or("")
                    ))
                }
            }
            Err(e) => Sent::Failed(format!("FCM: {e}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

pub struct Push {
    http: reqwest::Client,
    store: Store,
    apns: Option<Apns>,
    fcm: Option<Fcm>,
    detailed: bool,
}

impl Push {
    /// Creates the service if APNs or FCM is configured.
    pub fn from_config(cfg: &PushSection, store: Store) -> anyhow::Result<Option<Arc<Self>>> {
        let apns = match &cfg.apns {
            None => None,
            Some(a) => {
                let pem = match std::env::var("TERMOAK_APNS_KEY") {
                    Ok(v) if !v.trim().is_empty() => v,
                    _ => {
                        let path = a.key_path.as_ref().ok_or_else(|| {
                            anyhow::anyhow!("[push.apns] needs key_path or TERMOAK_APNS_KEY")
                        })?;
                        std::fs::read_to_string(path).map_err(|e| {
                            anyhow::anyhow!("no se pudo leer {}: {e}", path.display())
                        })?
                    }
                };
                let key = EcdsaKeyPair::from_pkcs8(
                    &ECDSA_P256_SHA256_FIXED_SIGNING,
                    &pem_to_der(&pem)?,
                    &SystemRandom::new(),
                )
                .map_err(|e| anyhow::anyhow!("the APNs key is not a valid .p8 key: {e}"))?;
                Some(Apns {
                    key,
                    key_id: a.key_id.trim().to_string(),
                    team_id: a.team_id.trim().to_string(),
                    topic: a.topic.trim().to_string(),
                    endpoint: a
                        .endpoint
                        .clone()
                        .unwrap_or_else(|| "https://api.push.apple.com".into())
                        .trim_end_matches('/')
                        .to_string(),
                    sandbox_endpoint: a
                        .sandbox_endpoint
                        .clone()
                        .unwrap_or_else(|| "https://api.sandbox.push.apple.com".into())
                        .trim_end_matches('/')
                        .to_string(),
                    jwt: parking_lot::Mutex::new(None),
                })
            }
        };
        let fcm = match &cfg.fcm {
            None => None,
            Some(f) => {
                let raw = match std::env::var("TERMOAK_FCM_CREDENTIALS") {
                    Ok(v) if !v.trim().is_empty() => v,
                    _ => {
                        let path = f.service_account_path.as_ref().ok_or_else(|| {
                            anyhow::anyhow!(
                                "[push.fcm] needs service_account_path or TERMOAK_FCM_CREDENTIALS"
                            )
                        })?;
                        std::fs::read_to_string(path).map_err(|e| {
                            anyhow::anyhow!("no se pudo leer {}: {e}", path.display())
                        })?
                    }
                };
                let account: ServiceAccount = serde_json::from_str(&raw)
                    .map_err(|e| anyhow::anyhow!("invalid Firebase service account: {e}"))?;
                let key = RsaKeyPair::from_pkcs8(&pem_to_der(&account.private_key)?)
                    .map_err(|e| anyhow::anyhow!("invalid service account key: {e}"))?;
                Some(Fcm {
                    key,
                    account,
                    endpoint: f
                        .endpoint
                        .clone()
                        .unwrap_or_else(|| "https://fcm.googleapis.com".into())
                        .trim_end_matches('/')
                        .to_string(),
                    access: tokio::sync::Mutex::new(None),
                })
            }
        };
        if apns.is_none() && fcm.is_none() {
            return Ok(None);
        }
        let http = reqwest::Client::builder()
            .user_agent(concat!("termoak-server/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Some(Arc::new(Self {
            http,
            store,
            apns,
            fcm,
            detailed: cfg.detailed,
        })))
    }

    /// Configured platforms.
    pub fn platforms(&self) -> (bool, bool) {
        (self.apns.is_some(), self.fcm.is_some())
    }

    /// Sends to one device.
    async fn send_to(&self, t: &PushTarget, n: &Notification) -> Sent {
        match t.platform.as_str() {
            "apns" => match &self.apns {
                Some(a) => a.send(&self.http, t, n).await,
                None => Sent::Failed("APNs is not configured on the server".into()),
            },
            "fcm" => match &self.fcm {
                Some(f) => f.send(&self.http, t, n).await,
                None => Sent::Failed("FCM is not configured on the server".into()),
            },
            other => Sent::Failed(format!("unknown platform: {other}")),
        }
    }

    async fn deliver(&self, t: &PushTarget, n: &Notification) -> Result<(), String> {
        match self.send_to(t, n).await {
            Sent::Ok => Ok(()),
            Sent::Unregistered => {
                let _ = self.store.forget_push_token(&t.token).await;
                Err("the device no longer accepts notifications".into())
            }
            Sent::Failed(e) => {
                tracing::warn!(device = %t.device_id, error = %e, "notification not sent");
                Err(e)
            }
        }
    }

    /// Sends to all the user's devices (in the background). `build` gets the
    /// user's language.
    pub fn notify(
        self: &Arc<Self>,
        user: Id,
        build: impl FnOnce(&'static str) -> Notification + Send + 'static,
    ) {
        let me = self.clone();
        tokio::spawn(async move {
            let targets = match me.store.push_targets(user).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(error = %e, "could not read the devices");
                    return;
                }
            };
            if targets.is_empty() {
                return;
            }
            let locale = match me.store.user(user).await {
                Ok(u) => crate::i18n::resolve(&u.locale),
                Err(_) => crate::i18n::DEFAULT,
            };
            let n = build(locale);
            for t in targets {
                let _ = me.deliver(&t, &n).await;
            }
        });
    }

    /// Test notification to one device (waits for the result).
    pub async fn test(&self, target: &PushTarget, locale: &str) -> Result<(), String> {
        let l = crate::i18n::resolve(locale);
        let n = Notification::new("test", "Termoak", t!("push.test.body", locale = l));
        self.deliver(target, &n).await
    }

    /// The detailed text if `[push] detailed` is on (and there is one), else
    /// the generic one.
    fn text(detailed: bool, text: String, generic: impl Into<String>) -> String {
        if detailed && !text.trim().is_empty() {
            text.chars().take(180).collect()
        } else {
            generic.into()
        }
    }

    /// You were added to a team.
    pub fn team_added(self: &Arc<Self>, user: Id, team_id: Id, team: &str, by: &str) {
        let (detailed, team, by) = (self.detailed, team.to_string(), by.to_string());
        self.notify(user, move |l| {
            let body = Self::text(
                detailed,
                t!(
                    "push.team_added.body",
                    locale = l,
                    inviter = by,
                    team = team
                )
                .into_owned(),
                t!("push.team_added.generic", locale = l),
            );
            Notification::new("team_added", t!("push.team_added.title", locale = l), body)
                .with("team_id", team_id)
        });
    }

    /// Listens to the AI and the sessions and notifies whoever is concerned.
    pub fn spawn_dispatcher(self: Arc<Self>, ai: Arc<AiEngine>, sessions: Arc<SessionManager>) {
        let mut ai_rx = ai.subscribe();
        let mut session_rx = sessions.notices();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    ev = ai_rx.recv() => match ev {
                        Ok(ev) => self.on_ai(ev.owner, ev.task_id, &ev.event).await,
                        Err(RecvError::Lagged(n)) => tracing::warn!(n, "push: AI events lost"),
                        Err(RecvError::Closed) => break,
                    },
                    ev = session_rx.recv() => match ev {
                        Ok((user, notice)) => self.on_session(&sessions, user, &notice),
                        Err(RecvError::Lagged(n)) => tracing::warn!(n, "push: session notices lost"),
                        Err(RecvError::Closed) => break,
                    },
                }
            }
        });
    }

    async fn on_ai(self: &Arc<Self>, owner: Id, task_id: Id, event: &TaskEvent) {
        let detailed = self.detailed;
        match event {
            TaskEvent::ApprovalRequested {
                approval_id,
                summary,
                ..
            } => {
                let (approval_id, summary) = (*approval_id, summary.clone());
                self.notify(owner, move |l| {
                    let mut n = Notification::new(
                        "ai_approval",
                        t!("push.ai_approval.title", locale = l),
                        Self::text(
                            detailed,
                            summary,
                            t!("push.ai_approval.generic", locale = l),
                        ),
                    )
                    .with("task_id", task_id)
                    .with("approval_id", approval_id);
                    n.collapse = Some(format!("approval-{approval_id}"));
                    n
                });
            }
            TaskEvent::Finished { status, .. } => {
                let (key, status) = match status {
                    TaskStatus::Completed => ("push.ai_finished.title_completed", "completed"),
                    TaskStatus::Failed => ("push.ai_finished.title_failed", "failed"),
                    _ => return,
                };
                let name = if detailed {
                    self.store
                        .ai_task(owner, task_id)
                        .await
                        .map(|t| t.title)
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                self.notify(owner, move |l| {
                    let mut n = Notification::new(
                        "ai_finished",
                        t!(key, locale = l),
                        Self::text(detailed, name, t!("push.ai_finished.generic", locale = l)),
                    )
                    .with("task_id", task_id)
                    .with("status", status);
                    n.collapse = Some(format!("task-{task_id}"));
                    n
                });
            }
            _ => {}
        }
    }

    fn on_session(self: &Arc<Self>, sessions: &SessionManager, user: Id, notice: &SessionNotice) {
        let detailed = self.detailed;
        match notice {
            SessionNotice::SessionShared { session, by, team } => {
                let (id, title) = (session.id, session.title.clone());
                let (by, team) = (by.clone(), team.clone());
                self.notify(user, move |l| {
                    let body = match &team {
                        Some(team) => t!(
                            "push.session_shared.body_team",
                            locale = l,
                            user = by,
                            team = team,
                            title = title
                        ),
                        None => t!(
                            "push.session_shared.body",
                            locale = l,
                            user = by,
                            title = title
                        ),
                    };
                    Notification::new(
                        "session_shared",
                        t!("push.session_shared.title", locale = l),
                        Self::text(
                            detailed,
                            body.into_owned(),
                            t!("push.session_shared.generic", locale = l),
                        ),
                    )
                    .with("session_id", id)
                });
            }
            SessionNotice::PromptPending { session_id, prompt } => {
                // If the user is watching it, they already see the question in the app.
                let watching = sessions
                    .get(*session_id)
                    .is_some_and(|s| s.viewers().iter().any(|v| v.user_id == Some(user)));
                if watching {
                    return;
                }
                let (session_id, prompt_id) = (*session_id, prompt.prompt_id);
                let (hostkey, host) = (prompt.kind == "hostkey", prompt.host.clone());
                self.notify(user, move |l| {
                    let detail = if hostkey {
                        t!("push.session_prompt.hostkey", locale = l, host = host)
                    } else {
                        t!("push.session_prompt.other", locale = l, host = host)
                    };
                    let mut n = Notification::new(
                        "session_prompt",
                        t!("push.session_prompt.title", locale = l),
                        Self::text(
                            detailed,
                            detail.into_owned(),
                            t!("push.session_prompt.generic", locale = l),
                        ),
                    )
                    .with("session_id", session_id)
                    .with("prompt_id", prompt_id);
                    n.collapse = Some(format!("prompt-{prompt_id}"));
                    n
                });
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RegisterPush {
    /// `apns` (iOS) or `fcm` (Android).
    pub platform: String,
    /// Device token given by the system.
    pub token: String,
    /// Sandbox APNs (app built in development mode).
    #[serde(default)]
    pub sandbox: bool,
}

pub fn routes() -> axum::Router<AppState> {
    use axum::routing::post;
    axum::Router::new()
        .route("/api/v1/push/register", post(register).delete(unregister))
        .route("/api/v1/push/test", post(test_push))
}

/// Enables notifications on the device of this session.
async fn register(
    axum::extract::State(st): axum::extract::State<AppState>,
    u: AuthUser,
    axum::Json(req): axum::Json<RegisterPush>,
) -> ApiResult<axum::Json<Value>> {
    st.store
        .set_push_token(u.device.id, req.platform.trim(), &req.token, req.sandbox)
        .await?;
    let (apns, fcm) = st.push.as_ref().map(|p| p.platforms()).unwrap_or_default();
    let enabled = match req.platform.trim() {
        "apns" => apns,
        _ => fcm,
    };
    Ok(axum::Json(json!({"ok": true, "server_enabled": enabled})))
}

/// Disables notifications on this device.
async fn unregister(
    axum::extract::State(st): axum::extract::State<AppState>,
    u: AuthUser,
) -> ApiResult<axum::Json<Value>> {
    st.store.clear_push_token(u.device.id).await?;
    Ok(axum::Json(json!({"ok": true})))
}

/// Sends a test notification to this device.
async fn test_push(
    axum::extract::State(st): axum::extract::State<AppState>,
    u: AuthUser,
) -> ApiResult<axum::Json<Value>> {
    let push = st.push.as_ref().ok_or_else(|| {
        ApiError::bad_request("this server has no push notifications configured")
            .with_code("push_disabled")
    })?;
    let target = st
        .store
        .push_targets(u.id())
        .await?
        .into_iter()
        .find(|t| t.device_id == u.device.id)
        .ok_or_else(|| {
            ApiError::bad_request("this device does not have notifications enabled")
                .with_code("push_not_registered")
        })?;
    push.test(&target, &u.user.locale)
        .await
        .map_err(|e| ApiError::new(axum::http::StatusCode::BAD_GATEWAY, "push_failed", e))?;
    Ok(axum::Json(json!({"ok": true})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn es256_jwt_verifies() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let t = jwt(
            &json!({"alg": "ES256", "kid": "K"}),
            &json!({"iss": "T"}),
            |m| Ok(key.sign(&rng, m).unwrap().as_ref().to_vec()),
        )
        .unwrap();
        let parts: Vec<&str> = t.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["kid"], "K");
        use ring::signature::KeyPair;
        let public = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_FIXED,
            key.public_key().as_ref(),
        );
        public
            .verify(
                format!("{}.{}", parts[0], parts[1]).as_bytes(),
                &URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn pem_decoding() {
        let der =
            pem_to_der("-----BEGIN PRIVATE KEY-----\nAQID\nBA==\n-----END PRIVATE KEY-----\n")
                .unwrap();
        assert_eq!(der, [1, 2, 3, 4]);
    }
}
