//! Push notifications: Web Push (UnifiedPush distributors and browsers,
//! with no third party), APNs (iOS) and, optionally, FCM (Android builds
//! with Firebase). Design: docs-next/PUSH.md.
//!
//! Each device registers once per account (`POST /api/v1/push/register`):
//! a Web Push endpoint with its keys, or an APNs/FCM token. The server tells
//! it what happens while the app is not looking:
//!
//! - an AI task is waiting for your approval (withdrawn when it is
//!   decided), or has finished or failed;
//! - someone shared a session with you;
//! - one of your sessions is waiting for an answer (server fingerprint, 2FA
//!   code) and you are not watching it;
//! - someone waits to join one of your shared sessions, or asks for its
//!   keyboard, and you are not watching it;
//! - a connection made by the server needs your security key and none of
//!   your devices that can sign is online (the phone wakes up, opens the
//!   events socket and answers the waiting request; withdrawn when done);
//! - you were added to a team;
//! - (0.7 phase 4b) someone asks for temporary access you can approve.
//!
//! Payloads are small (`termoak_core::push::Payload`): the kind, ids, a
//! generic title and body in the recipient's language (details only with
//! `[push] detailed = true`) and a collapse key. A device chooses the kinds
//! it wants and, by default, gets nothing while its events socket is open
//! (the app shows the event itself). Endpoints that answer 404/410 are
//! forgotten. Nothing about notifications is audited, and endpoints and
//! tokens are never logged.
//!
//! Signatures (ES256 for APNs, RS256 for the Firebase service account) are
//! made with `ring`; Web Push encryption and VAPID are in
//! `termoak_core::webpush`.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use futures::future::BoxFuture;
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, RSA_PKCS1_SHA256, RsaKeyPair,
};
use rust_i18n::t;
use serde::Deserialize;
use serde_json::{Value, json};
use termoak_ai::{AiEngine, TaskEvent, TaskStatus};
use termoak_core::push::{self as cp, Payload, Preferences};
use termoak_core::store::users::PushTarget;
use termoak_core::webpush::VapidKey;
use termoak_core::{Id, Store};
use tokio::sync::broadcast::error::RecvError;

use crate::auth::AuthUser;
use crate::config::{ApnsEnvironment, PushSection, WebPushSection};
use crate::devices::Sockets;
use crate::error::{ApiError, ApiResult};
use crate::limiter::RateLimiter;
use crate::sessions::{SessionManager, SessionNotice};
use crate::state::AppState;

/// Test notifications per device and minute.
const TESTS_PER_MINUTE: usize = 5;

/// Result of a delivery.
#[derive(Debug, PartialEq, Eq)]
enum Sent {
    Ok,
    /// The token or endpoint is no longer valid (app uninstalled,
    /// distributor unsubscribed...): it is forgotten.
    Unregistered,
    Failed(String),
}

/// How long a push service keeps a notification for an offline device, and
/// how urgent it is (RFC 8030 `TTL` and `Urgency`).
fn delivery(kind: &str, sk_timeout_secs: u64) -> (u64, &'static str) {
    match kind {
        "security_key_request" => (sk_timeout_secs.max(1), "high"),
        "test" => (300, "high"),
        "session_prompt" => (600, "high"),
        "resolved" => (600, "normal"),
        k if cp::APPROVALS.contains(&k) => (3600, "high"),
        _ => (86_400, "normal"),
    }
}

fn reqwest_error(e: reqwest::Error) -> String {
    // reqwest's text includes the URL: endpoints are never logged.
    e.without_url().to_string()
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
// Web Push
// ---------------------------------------------------------------------------

/// Whether an address is on the public internet (not loopback, private,
/// link-local, CGNAT, documentation, multicast...).
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || (s[0] == 0x64 && s[1] == 0xff9b))
        }
    }
}

/// Which endpoints the server may call: `https://` on a public address,
/// or a configured prefix (`[push.webpush] allowed_endpoints`).
#[derive(Debug, Clone, Default)]
pub struct EndpointPolicy {
    prefixes: Vec<String>,
    hosts: HashSet<String>,
}

impl EndpointPolicy {
    pub fn from_config(cfg: &WebPushSection) -> Self {
        let mut prefixes = Vec::new();
        let mut hosts = HashSet::new();
        for p in &cfg.allowed_endpoints {
            let p = p.trim();
            let Ok(u) = url::Url::parse(p) else {
                tracing::warn!(
                    prefix = p,
                    "push: ignoring an allowed endpoint that is not a URL"
                );
                continue;
            };
            if let Some(h) = u.host_str() {
                hosts.insert(h.trim_matches(['[', ']']).to_ascii_lowercase());
            }
            prefixes.push(u.to_string());
        }
        Self { prefixes, hosts }
    }

    fn allowed_prefix(&self, endpoint: &url::Url) -> bool {
        let s = endpoint.as_str();
        self.prefixes.iter().any(|p| s.starts_with(p.as_str()))
    }

    /// Checks an endpoint before registering it and before every call.
    pub fn check(&self, endpoint: &str) -> Result<(), String> {
        let u = url::Url::parse(endpoint.trim())
            .map_err(|_| "the push endpoint is not a URL".to_string())?;
        if !matches!(u.scheme(), "https" | "http") {
            return Err("the push endpoint must be an https URL".into());
        }
        if !u.username().is_empty() || u.password().is_some() {
            return Err("the push endpoint cannot carry a user or password".into());
        }
        let host = u
            .host()
            .ok_or_else(|| "the push endpoint has no host".to_string())?;
        if self.allowed_prefix(&u) {
            return Ok(());
        }
        if u.scheme() != "https" {
            return Err("the push endpoint must be an https URL".into());
        }
        let private = match host {
            url::Host::Ipv4(ip) => !is_public_ip(IpAddr::V4(ip)),
            url::Host::Ipv6(ip) => !is_public_ip(IpAddr::V6(ip)),
            url::Host::Domain(d) => {
                let d = d.to_ascii_lowercase();
                d == "localhost"
                    || d.ends_with(".localhost")
                    || d.ends_with(".local")
                    || d.ends_with(".internal")
                    || !d.contains('.')
            }
        };
        if private {
            return Err(
                "the push endpoint is on a private address (allow it in [push.webpush] allowed_endpoints)"
                    .into(),
            );
        }
        Ok(())
    }
}

/// Resolves push endpoints' names to public addresses only (except the
/// hosts of allowed endpoints), so a registered endpoint cannot make the
/// server call its own network.
struct PublicResolver {
    allowed_hosts: HashSet<String>,
}

impl reqwest::dns::Resolve for PublicResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_ascii_lowercase();
        let any = self.allowed_hosts.contains(&host);
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|a| any || is_public_ip(a.ip()))
                .collect();
            if addrs.is_empty() {
                return Err("the push endpoint has no public address".into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

struct WebPush {
    vapid: VapidKey,
    subject: String,
    policy: EndpointPolicy,
    http: reqwest::Client,
}

/// Loads the VAPID key (`TERMOAK_VAPID_KEY`, else the file), creating the
/// file (0600) on first start.
pub fn load_vapid_key(cfg: &WebPushSection, data_dir: &Path) -> anyhow::Result<VapidKey> {
    if let Ok(v) = std::env::var("TERMOAK_VAPID_KEY")
        && !v.trim().is_empty()
    {
        return VapidKey::from_base64url(v.trim())
            .map_err(|e| anyhow::anyhow!("invalid TERMOAK_VAPID_KEY: {e}"));
    }
    let path: PathBuf = cfg
        .key_path
        .clone()
        .unwrap_or_else(|| data_dir.join("vapid.key"));
    if path.exists() {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("could not read {}: {e}", path.display()))?;
        return VapidKey::from_base64url(text.trim())
            .map_err(|e| anyhow::anyhow!("invalid VAPID key in {}: {e}", path.display()));
    }
    let key = VapidKey::generate();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    write_secret(&path, key.to_base64url().as_bytes())
        .map_err(|e| anyhow::anyhow!("could not create {}: {e}", path.display()))?;
    tracing::warn!(
        path = %path.display(),
        "created the Web Push (VAPID) key: back it up with the master key"
    );
    Ok(key)
}

fn write_secret(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.write_all(b"\n")?;
    f.sync_all()
}

impl WebPush {
    async fn send(&self, t: &PushTarget, p: &Payload, ttl: u64, urgency: &str) -> Sent {
        let (Some(p256dh), Some(auth)) = (&t.p256dh, &t.auth) else {
            return Sent::Unregistered;
        };
        if let Err(e) = self.policy.check(&t.token) {
            return Sent::Failed(e);
        }
        let body = match termoak_core::webpush::encrypt(p256dh, auth, p.to_json().as_bytes()) {
            Ok(b) => b,
            // Keys that no longer parse: the registration is useless.
            Err(_) => return Sent::Unregistered,
        };
        let authorization = match self
            .vapid
            .authorization(&t.token, &self.subject, unix_now())
        {
            Ok(a) => a,
            Err(e) => return Sent::Failed(e.to_string()),
        };
        let mut req = self
            .http
            .post(&t.token)
            .header("TTL", ttl.to_string())
            .header("Urgency", urgency)
            .header("Content-Encoding", "aes128gcm")
            .header("Content-Type", "application/octet-stream")
            .header("Authorization", authorization)
            .body(body);
        if let Some(c) = &p.collapse {
            req = req.header("Topic", termoak_core::webpush::topic(c));
        }
        match req.send().await {
            Ok(r) if r.status().is_success() => Sent::Ok,
            Ok(r) => match r.status().as_u16() {
                404 | 410 => Sent::Unregistered,
                413 => Sent::Failed("the push service says the message is too large".into()),
                429 => Sent::Failed("the push service is rate limiting this server".into()),
                s => Sent::Failed(format!("the push service answered {s}")),
            },
            Err(e) => Sent::Failed(format!("push service: {}", reqwest_error(e))),
        }
    }
}

// ---------------------------------------------------------------------------
// APNs
// ---------------------------------------------------------------------------

struct Apns {
    key: EcdsaKeyPair,
    key_id: String,
    team_id: String,
    topic: String,
    environment: ApnsEnvironment,
    endpoint: String,
    sandbox_endpoint: String,
    /// Current JWT (Apple asks to renew it at least once an hour).
    jwt: parking_lot::Mutex<Option<(Instant, String)>>,
}

/// The APNs request body and headers for a payload.
fn apns_request(p: &Payload, ttl: u64) -> (Value, Vec<(&'static str, String)>) {
    let custom = p.to_flat();
    let mut headers = vec![("apns-expiration", (unix_now() + ttl).to_string())];
    if p.kind == "resolved" {
        // Silent: the app removes the delivered notification with that tag.
        headers.push(("apns-push-type", "background".into()));
        headers.push(("apns-priority", "5".into()));
        return (
            json!({"aps": {"content-available": 1}, "termoak": custom}),
            headers,
        );
    }
    let mut aps = json!({
        "alert": {"title": p.title, "body": p.body},
        "sound": "default",
        "thread-id": p.kind,
    });
    match p.category() {
        cp::Category::Approval => aps["category"] = json!("TERMOAK_APPROVAL"),
        cp::Category::SecurityKey => aps["category"] = json!("TERMOAK_SECURITY_KEY"),
        _ => {}
    }
    headers.push(("apns-push-type", "alert".into()));
    headers.push(("apns-priority", "10".into()));
    if let Some(c) = &p.collapse {
        headers.push(("apns-collapse-id", c.chars().take(64).collect()));
    }
    (json!({"aps": aps, "termoak": custom}), headers)
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

    async fn send(&self, http: &reqwest::Client, t: &PushTarget, p: &Payload, ttl: u64) -> Sent {
        let token = match self.token() {
            Ok(t) => t,
            Err(e) => return Sent::Failed(e.to_string()),
        };
        let sandbox = match self.environment {
            ApnsEnvironment::Auto => t.sandbox,
            ApnsEnvironment::Production => false,
            ApnsEnvironment::Sandbox => true,
        };
        let base = if sandbox {
            &self.sandbox_endpoint
        } else {
            &self.endpoint
        };
        let (body, headers) = apns_request(p, ttl);
        let mut req = http
            .post(format!("{base}/3/device/{}", t.token))
            .bearer_auth(token)
            .header("apns-topic", &self.topic)
            .json(&body);
        for (k, v) in headers {
            req = req.header(k, v);
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
            Err(e) => Sent::Failed(format!("APNs: {}", reqwest_error(e))),
        }
    }
}

// ---------------------------------------------------------------------------
// FCM (optional: only builds of the Android app with Firebase use it)
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

    async fn send(&self, http: &reqwest::Client, t: &PushTarget, p: &Payload, ttl: u64) -> Sent {
        let token = match self.access_token(http).await {
            Ok(t) => t,
            Err(e) => return Sent::Failed(e.to_string()),
        };
        let mut android = json!({"priority": "HIGH", "ttl": format!("{ttl}s")});
        let mut message = json!({"token": t.token, "data": p.to_flat()});
        if p.kind != "resolved" {
            android["notification"] = json!({"channel_id": "termoak"});
            message["notification"] = json!({"title": p.title, "body": p.body});
        }
        if let Some(c) = &p.collapse {
            android["collapse_key"] = json!(c);
        }
        message["android"] = android;
        let url = format!(
            "{}/v1/projects/{}/messages:send",
            self.endpoint, self.account.project_id
        );
        match http
            .post(url)
            .bearer_auth(token)
            .json(&json!({"message": message}))
            .send()
            .await
        {
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
            Err(e) => Sent::Failed(format!("FCM: {}", reqwest_error(e))),
        }
    }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

pub struct Push {
    http: reqwest::Client,
    store: Store,
    web: Option<WebPush>,
    apns: Option<Apns>,
    fcm: Option<Fcm>,
    detailed: bool,
    sockets: Arc<Sockets>,
    instance_id: String,
    limiter: RateLimiter,
    tests: RateLimiter,
    sk_timeout_secs: u64,
}

/// What `Push::from_config` needs besides the configuration.
pub struct PushContext {
    pub store: Store,
    pub sockets: Arc<Sockets>,
    pub data_dir: PathBuf,
    pub instance_id: String,
    /// `mailto:` contact when `[push.webpush] subject` is not set.
    pub support_email: Option<String>,
    pub public_url: Option<String>,
    pub sk_timeout_secs: u64,
}

impl Push {
    /// Creates the service if Web Push, APNs or FCM is enabled.
    pub fn from_config(cfg: &PushSection, ctx: PushContext) -> anyhow::Result<Option<Arc<Self>>> {
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
                            anyhow::anyhow!("could not read {}: {e}", path.display())
                        })?
                    }
                };
                let key = EcdsaKeyPair::from_pkcs8(
                    &ECDSA_P256_SHA256_FIXED_SIGNING,
                    &pem_to_der(&pem)?,
                    &SystemRandom::new(),
                )
                .map_err(|e| anyhow::anyhow!("the APNs key is not a valid .p8 key: {e}"))?;
                for (name, value) in [
                    ("key_id", &a.key_id),
                    ("team_id", &a.team_id),
                    ("bundle_id", &a.topic),
                ] {
                    if value.trim().is_empty() {
                        anyhow::bail!("[push.apns] needs {name}");
                    }
                }
                Some(Apns {
                    key,
                    key_id: a.key_id.trim().to_string(),
                    team_id: a.team_id.trim().to_string(),
                    topic: a.topic.trim().to_string(),
                    environment: a.environment,
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
                            anyhow::anyhow!("could not read {}: {e}", path.display())
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
        let web = if cfg.webpush.enabled {
            let vapid = load_vapid_key(&cfg.webpush, &ctx.data_dir)?;
            let policy = EndpointPolicy::from_config(&cfg.webpush);
            let subject = cfg
                .webpush
                .subject
                .clone()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    ctx.support_email
                        .as_deref()
                        .map(str::trim)
                        .filter(|e| e.contains('@'))
                        .map(|e| format!("mailto:{e}"))
                })
                .or_else(|| {
                    ctx.public_url
                        .as_deref()
                        .map(str::trim)
                        .filter(|u| u.starts_with("https://"))
                        .map(str::to_string)
                })
                .unwrap_or_else(|| "mailto:admin@localhost".into());
            let http = reqwest::Client::builder()
                .user_agent(concat!("termoak-server/", env!("CARGO_PKG_VERSION")))
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(20))
                .redirect(reqwest::redirect::Policy::none())
                .dns_resolver(Arc::new(PublicResolver {
                    allowed_hosts: policy.hosts.clone(),
                }))
                .build()?;
            Some(WebPush {
                vapid,
                subject,
                policy,
                http,
            })
        } else {
            None
        };
        if apns.is_none() && fcm.is_none() && web.is_none() {
            return Ok(None);
        }
        let http = reqwest::Client::builder()
            .user_agent(concat!("termoak-server/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Some(Arc::new(Self {
            http,
            store: ctx.store,
            web,
            apns,
            fcm,
            detailed: cfg.detailed,
            sockets: ctx.sockets,
            instance_id: ctx.instance_id,
            limiter: RateLimiter::new(cfg.max_per_minute.max(1), 60_000),
            tests: RateLimiter::new(TESTS_PER_MINUTE, 60_000),
            sk_timeout_secs: ctx.sk_timeout_secs,
        })))
    }

    /// Configured platforms: (APNs, FCM).
    pub fn platforms(&self) -> (bool, bool) {
        (self.apns.is_some(), self.fcm.is_some())
    }

    /// Web Push is on.
    pub fn webpush(&self) -> bool {
        self.web.is_some()
    }

    /// The VAPID public key (base64url), when Web Push is on.
    pub fn vapid_public_key(&self) -> Option<String> {
        self.web.as_ref().map(|w| w.vapid.public_key())
    }

    fn supports(&self, platform: &str) -> bool {
        match platform {
            "apns" => self.apns.is_some(),
            "fcm" => self.fcm.is_some(),
            "webpush" => self.web.is_some(),
            _ => false,
        }
    }

    /// Sends to one device.
    async fn send_to(&self, t: &PushTarget, p: &Payload) -> Sent {
        let (mut ttl, urgency) = delivery(&p.kind, self.sk_timeout_secs);
        // An access request lives until it expires (at most a day).
        if p.kind == "access_request"
            && let Some(exp) = p.expires_at
        {
            ttl = ((exp - termoak_core::time::now_ms()) / 1000).clamp(60, 86_400) as u64;
        }
        match t.platform.as_str() {
            "webpush" => match &self.web {
                Some(w) => w.send(t, p, ttl, urgency).await,
                None => Sent::Failed("Web Push is not enabled on the server".into()),
            },
            "apns" => match &self.apns {
                Some(a) => a.send(&self.http, t, p, ttl).await,
                None => Sent::Failed("APNs is not configured on the server".into()),
            },
            "fcm" => match &self.fcm {
                Some(f) => f.send(&self.http, t, p, ttl).await,
                None => Sent::Failed("FCM is not configured on the server".into()),
            },
            other => Sent::Failed(format!("unknown platform: {other}")),
        }
    }

    async fn deliver(&self, t: &PushTarget, p: &Payload) -> Result<(), String> {
        match self.send_to(t, p).await {
            Sent::Ok => Ok(()),
            Sent::Unregistered => {
                let _ = self.store.forget_push_token(&t.token).await;
                tracing::info!(device = %t.device_id, platform = %t.platform, "push registration expired: forgotten");
                Err("the device no longer accepts notifications".into())
            }
            Sent::Failed(e) => {
                tracing::warn!(device = %t.device_id, platform = %t.platform, error = %e, "notification not sent");
                Err(e)
            }
        }
    }

    /// The devices that get a notification of `kind` now: they want that
    /// kind, the server can reach their platform and, unless they asked
    /// otherwise, their app is not open (events socket). `resolved` goes to
    /// the devices that wanted the original kind, open or not.
    fn eligible(&self, targets: Vec<PushTarget>, kind: &str, original: &str) -> Vec<PushTarget> {
        targets
            .into_iter()
            .filter(|t| self.supports(&t.platform))
            .filter(|t| t.prefs.allows(original))
            .filter(|t| {
                kind == "resolved"
                    || kind == "test"
                    || t.prefs.when_online
                    || !self.sockets.has_events(t.device_id)
            })
            .collect()
    }

    /// Sends a notification of `kind` to the eligible devices of `user`;
    /// returns how many there were. `original`: for `resolved`, the kind it
    /// withdraws.
    async fn send_now(
        self: &Arc<Self>,
        user: Id,
        kind: &str,
        original: &str,
        build: impl FnOnce(&'static str) -> Payload,
    ) -> usize {
        let targets = match self.store.push_targets(user).await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(error = %e, "could not read the devices");
                return 0;
            }
        };
        let targets = self.eligible(targets, kind, original);
        if targets.is_empty() {
            return 0;
        }
        let locale = match self.store.user(user).await {
            Ok(u) => crate::i18n::resolve(&u.locale),
            Err(_) => crate::i18n::DEFAULT,
        };
        let mut p = build(locale);
        p.server = Some(self.instance_id.clone());
        p.user = Some(user.to_string());
        let mut sent = 0;
        let mut jobs = Vec::new();
        for t in targets {
            if kind != "resolved" && !self.limiter.allow(&t.device_id.to_string()) {
                tracing::warn!(device = %t.device_id, "push: too many notifications for this device, dropped");
                continue;
            }
            sent += 1;
            let (me, p) = (self.clone(), p.clone());
            jobs.push(tokio::spawn(async move {
                let _ = me.deliver(&t, &p).await;
            }));
        }
        drop(jobs);
        sent
    }

    /// Sends to the user's devices in the background. `build` gets the
    /// user's language.
    pub fn notify(
        self: &Arc<Self>,
        user: Id,
        kind: &'static str,
        build: impl FnOnce(&'static str) -> Payload + Send + 'static,
    ) {
        let me = self.clone();
        tokio::spawn(async move {
            me.send_now(user, kind, kind, build).await;
        });
    }

    /// Withdraws the notification `collapse` (of `kind`) from the user's
    /// devices: the request was answered or expired.
    pub fn resolve(self: &Arc<Self>, user: Id, kind: &'static str, collapse: String) {
        let me = self.clone();
        tokio::spawn(async move {
            me.send_now(user, "resolved", kind, move |_| {
                Payload::resolved(&collapse)
            })
            .await;
        });
    }

    /// Test notification to one device (waits for the result).
    pub async fn test(&self, target: &PushTarget, user: Id, locale: &str) -> Result<(), String> {
        let l = crate::i18n::resolve(locale);
        let mut p = Payload::new("test", "Termoak", &t!("push.test.body", locale = l));
        p.server = Some(self.instance_id.clone());
        p.user = Some(user.to_string());
        p.collapse = Some(format!("test-{}", target.device_id));
        self.deliver(target, &p).await
    }

    /// The detailed text if `[push] detailed` is on (and there is one), else
    /// the generic one.
    fn text(detailed: bool, text: String, generic: impl Into<String>) -> String {
        if detailed && !text.trim().is_empty() {
            text.chars().take(cp::MAX_BODY).collect()
        } else {
            generic.into()
        }
    }

    /// You were added to a team.
    pub fn team_added(self: &Arc<Self>, user: Id, team_id: Id, team: &str, by: &str) {
        let (detailed, team, by) = (self.detailed, team.to_string(), by.to_string());
        self.notify(user, "team_added", move |l| {
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
            Payload::new(
                "team_added",
                &t!("push.team_added.title", locale = l),
                &body,
            )
            .with("team_id", team_id)
        });
    }

    /// A connection made by the server needs a security key and no device
    /// that can sign is online: wakes the user's devices. Returns how many
    /// were notified (0: answer `no_device` at once).
    pub async fn security_key_request(
        self: &Arc<Self>,
        user: Id,
        request_id: &str,
        expires_at: i64,
        host: Option<String>,
    ) -> usize {
        let (detailed, id) = (self.detailed, request_id.to_string());
        self.send_now(
            user,
            "security_key_request",
            "security_key_request",
            move |l| {
                let detail = host
                    .map(|h| {
                        t!("push.security_key_request.body", locale = l, host = h).into_owned()
                    })
                    .unwrap_or_default();
                let mut p = Payload::new(
                    "security_key_request",
                    &t!("push.security_key_request.title", locale = l),
                    &Self::text(
                        detailed,
                        detail,
                        t!("push.security_key_request.generic", locale = l),
                    ),
                )
                .with("request_id", &id);
                p.collapse = Some(format!("sk-{id}"));
                p.expires_at = Some(expires_at);
                p
            },
        )
        .await
    }

    /// 0.7 phase 4b: `approver` can approve a request for temporary access
    /// (Approve / Deny open the app's confirmation). `requester` and
    /// `target` only show with `[push] detailed = true`.
    pub fn access_request(
        self: &Arc<Self>,
        approver: Id,
        request_id: Id,
        requester: &str,
        target: &str,
        expires_at: Option<i64>,
    ) {
        let (detailed, requester, target) =
            (self.detailed, requester.to_string(), target.to_string());
        self.notify(approver, "access_request", move |l| {
            let body = t!(
                "push.access_request.body",
                locale = l,
                name = requester,
                target = target
            )
            .into_owned();
            let mut p = Payload::new(
                "access_request",
                &t!("push.access_request.title", locale = l),
                &Self::text(
                    detailed,
                    body,
                    t!("push.access_request.generic", locale = l),
                ),
            )
            .with("request_id", request_id);
            p.collapse = Some(format!("access-{request_id}"));
            p.expires_at = expires_at;
            p
        });
    }

    /// 0.7 phase 4b: the access request was decided (or expired).
    pub fn access_request_resolved(self: &Arc<Self>, approver: Id, request_id: Id) {
        self.resolve(approver, "access_request", format!("access-{request_id}"));
    }

    /// 0.7 phase 4b: your access request was approved, denied, revoked or
    /// expired (`status`). `target` only shows with `[push] detailed`.
    pub fn access_decided(
        self: &Arc<Self>,
        requester: Id,
        request_id: Id,
        status: &str,
        target: &str,
    ) {
        let (detailed, status, target) = (self.detailed, status.to_string(), target.to_string());
        self.notify(requester, "access_decided", move |l| {
            let (full, generic) = match status.as_str() {
                "approved" => (
                    t!("push.access_decided.approved", locale = l, target = target),
                    t!("push.access_decided.approved_generic", locale = l),
                ),
                "denied" => (
                    t!("push.access_decided.denied", locale = l, target = target),
                    t!("push.access_decided.denied_generic", locale = l),
                ),
                "revoked" => (
                    t!("push.access_decided.revoked", locale = l, target = target),
                    t!("push.access_decided.revoked_generic", locale = l),
                ),
                _ => (
                    t!("push.access_decided.expired", locale = l, target = target),
                    t!("push.access_decided.expired_generic", locale = l),
                ),
            };
            let body = Self::text(detailed, full.into_owned(), generic);
            let mut p = Payload::new(
                "access_decided",
                &t!("push.access_decided.title", locale = l),
                &body,
            )
            .with("request_id", request_id)
            .with("status", status.as_str());
            p.collapse = Some(format!("access-decided-{request_id}"));
            p
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
                        Ok(ev) => self.on_ai(&ai, ev.owner, ev.task_id, &ev.event).await,
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

    async fn on_ai(self: &Arc<Self>, ai: &AiEngine, owner: Id, task_id: Id, event: &TaskEvent) {
        let detailed = self.detailed;
        match event {
            TaskEvent::ApprovalRequested {
                approval_id,
                summary,
                ..
            } => {
                let (approval_id, summary) = (*approval_id, summary.clone());
                self.notify(owner, "ai_approval", move |l| {
                    let mut p = Payload::new(
                        "ai_approval",
                        &t!("push.ai_approval.title", locale = l),
                        &Self::text(
                            detailed,
                            summary,
                            t!("push.ai_approval.generic", locale = l),
                        ),
                    )
                    .with("task_id", task_id)
                    .with("approval_id", approval_id);
                    p.collapse = Some(format!("approval-{approval_id}"));
                    p
                });
            }
            TaskEvent::ApprovalDecided { approval_id, .. } => {
                self.resolve(owner, "ai_approval", format!("approval-{approval_id}"));
            }
            TaskEvent::Finished { status, .. } => {
                let (key, status) = match status {
                    TaskStatus::Completed => ("push.ai_finished.title_completed", "completed"),
                    TaskStatus::Failed => ("push.ai_finished.title_failed", "failed"),
                    _ => return,
                };
                // A host's conversation of a multi-host task: only the task
                // itself (the parent) notifies when everything is done.
                let task = ai.get(owner, task_id, false).await.ok();
                if task.as_ref().is_some_and(|t| t.parent_id.is_some()) {
                    return;
                }
                let name = match task {
                    Some(t) if detailed => t.title,
                    _ => String::new(),
                };
                self.notify(owner, "ai_finished", move |l| {
                    let mut p = Payload::new(
                        "ai_finished",
                        &t!(key, locale = l),
                        &Self::text(detailed, name, t!("push.ai_finished.generic", locale = l)),
                    )
                    .with("task_id", task_id)
                    .with("status", status);
                    p.collapse = Some(format!("task-{task_id}"));
                    p
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
                self.notify(user, "session_shared", move |l| {
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
                    let mut p = Payload::new(
                        "session_shared",
                        &t!("push.session_shared.title", locale = l),
                        &Self::text(
                            detailed,
                            body.into_owned(),
                            t!("push.session_shared.generic", locale = l),
                        ),
                    )
                    .with("session_id", id);
                    p.collapse = Some(format!("shared-{id}"));
                    p
                });
            }
            SessionNotice::PromptPending { session_id, prompt } => {
                // If the user is watching it, they already see the question in the app.
                let watching = sessions
                    .get(*session_id)
                    .is_some_and(|s| s.is_watching(user));
                if watching {
                    return;
                }
                let (session_id, prompt_id) = (*session_id, prompt.prompt_id);
                let (hostkey, host) = (prompt.kind == "hostkey", prompt.host.clone());
                self.notify(user, "session_prompt", move |l| {
                    let detail = if hostkey {
                        t!("push.session_prompt.hostkey", locale = l, host = host)
                    } else {
                        t!("push.session_prompt.other", locale = l, host = host)
                    };
                    let mut p = Payload::new(
                        "session_prompt",
                        &t!("push.session_prompt.title", locale = l),
                        &Self::text(
                            detailed,
                            detail.into_owned(),
                            t!("push.session_prompt.generic", locale = l),
                        ),
                    )
                    .with("session_id", session_id)
                    .with("prompt_id", prompt_id);
                    p.collapse = Some(format!("prompt-{prompt_id}"));
                    p
                });
            }
            SessionNotice::JoinRequest {
                session_id,
                title,
                participant,
            }
            | SessionNotice::ControlRequest {
                session_id,
                title,
                participant,
            } => {
                // Whoever is watching sees it in the app.
                if sessions
                    .get(*session_id)
                    .is_some_and(|s| s.is_watching(user))
                {
                    return;
                }
                let join = matches!(notice, SessionNotice::JoinRequest { .. });
                let (kind, key) = if join {
                    ("join_request", "push.join_request")
                } else {
                    ("control_request", "push.control_request")
                };
                let (session_id, pid) = (*session_id, participant.id);
                let (name, title) = (participant.name.clone(), title.clone());
                self.notify(user, kind, move |l| {
                    let (k_title, k_body, k_generic) = (
                        format!("{key}.title"),
                        format!("{key}.body"),
                        format!("{key}.generic"),
                    );
                    let body = t!(&k_body, locale = l, name = name, title = title).into_owned();
                    let generic = t!(&k_generic, locale = l).into_owned();
                    let mut p = Payload::new(
                        kind,
                        &t!(&k_title, locale = l),
                        &Self::text(detailed, body, generic),
                    )
                    .with("session_id", session_id)
                    .with("participant", pid);
                    p.collapse = Some(format!("{kind}-{pid}"));
                    p
                });
            }
            _ => {}
        }
    }
}

/// Wakes a user's devices for a security key request (the broker calls it
/// when none of them is online to sign).
pub struct SkWaker(pub Arc<Push>);

impl crate::security_keys::Waker for SkWaker {
    fn wake(
        &self,
        owner: Id,
        request_id: String,
        expires_at: i64,
        host: Option<String>,
    ) -> BoxFuture<'static, usize> {
        let push = self.0.clone();
        Box::pin(async move {
            push.security_key_request(owner, &request_id, expires_at, host)
                .await
        })
    }

    fn resolved(&self, owner: Id, request_id: &str) {
        self.0
            .resolve(owner, "security_key_request", format!("sk-{request_id}"));
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// A Web Push subscription's keys (as in `PushSubscription.toJSON()`).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct WebPushKeys {
    /// The device's P-256 public key (65 bytes, base64url).
    pub p256dh: String,
    /// The auth secret (16 bytes, base64url).
    pub auth: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RegisterPush {
    /// `webpush` (UnifiedPush distributors and browsers; `unifiedpush` is
    /// the same), `apns` (iOS) or `fcm` (Android builds with Firebase).
    pub platform: String,
    /// APNs/FCM: the device token given by the system.
    #[serde(default)]
    pub token: Option<String>,
    /// APNs: sandbox (app built in development mode).
    #[serde(default)]
    pub sandbox: bool,
    /// Web Push: the endpoint URL the distributor or browser gave.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Web Push: the subscription's keys.
    #[serde(default)]
    pub keys: Option<WebPushKeys>,
    /// Optional: which notifications this device wants (as in `PUT
    /// /push/preferences`).
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub preferences: Option<Preferences>,
}

pub fn routes() -> axum::Router<AppState> {
    use axum::routing::{get, post, put};
    axum::Router::new()
        .route("/api/v1/push", get(status))
        .route("/api/v1/push/register", post(register).delete(unregister))
        .route("/api/v1/push/preferences", put(set_preferences))
        .route("/api/v1/push/test", post(test_push))
}

/// What the server can send (`/info` features.push and `GET /push`).
pub fn server_features(st: &AppState) -> Value {
    let p = st.push.as_ref();
    json!({
        "apns": p.is_some_and(|p| p.platforms().0),
        "fcm": p.is_some_and(|p| p.platforms().1),
        "webpush": p.is_some_and(|p| p.webpush()),
        "vapid_public_key": p.and_then(|p| p.vapid_public_key()),
    })
}

/// Enables notifications on the device of this session.
async fn register(
    axum::extract::State(st): axum::extract::State<AppState>,
    u: AuthUser,
    axum::Json(req): axum::Json<RegisterPush>,
) -> ApiResult<axum::Json<Value>> {
    let platform = req.platform.trim().to_ascii_lowercase();
    let enabled = match platform.as_str() {
        "webpush" | "unifiedpush" => {
            let endpoint = req
                .endpoint
                .as_deref()
                .or(req.token.as_deref())
                .map(str::trim)
                .unwrap_or_default();
            let keys = req.keys.as_ref().ok_or_else(|| {
                ApiError::bad_request("a Web Push registration needs keys.p256dh and keys.auth")
            })?;
            EndpointPolicy::from_config(&st.config.push.webpush)
                .check(endpoint)
                .map_err(|e| ApiError::bad_request(e).with_code("push_endpoint_not_allowed"))?;
            st.store
                .set_webpush(u.device.id, endpoint, &keys.p256dh, &keys.auth)
                .await?;
            st.push.as_ref().is_some_and(|p| p.webpush())
        }
        "apns" | "fcm" => {
            let token = req.token.as_deref().unwrap_or_default();
            st.store
                .set_push_token(u.device.id, &platform, token, req.sandbox)
                .await?;
            let (apns, fcm) = st.push.as_ref().map(|p| p.platforms()).unwrap_or_default();
            if platform == "apns" { apns } else { fcm }
        }
        _ => {
            return Err(ApiError::bad_request(
                "invalid notification platform (webpush, apns or fcm)",
            ));
        }
    };
    if let Some(prefs) = &req.preferences {
        st.store.set_push_prefs(u.device.id, prefs).await?;
    }
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

/// This device's registration, preferences and what the server can send.
async fn status(
    axum::extract::State(st): axum::extract::State<AppState>,
    u: AuthUser,
) -> ApiResult<axum::Json<Value>> {
    let reg = st.store.push_registration(u.device.id).await?;
    Ok(axum::Json(json!({
        "registered": reg.platform.is_some(),
        "platform": reg.platform,
        "endpoint": reg.endpoint,
        "sandbox": reg.sandbox,
        "preferences": reg.prefs,
        "server": server_features(&st),
        "kinds": cp::KINDS,
    })))
}

/// Chooses which notifications this device gets.
async fn set_preferences(
    axum::extract::State(st): axum::extract::State<AppState>,
    u: AuthUser,
    axum::Json(prefs): axum::Json<Preferences>,
) -> ApiResult<axum::Json<Value>> {
    let saved = st.store.set_push_prefs(u.device.id, &prefs).await?;
    Ok(axum::Json(json!({"ok": true, "preferences": saved})))
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
    if !push.supports(&target.platform) {
        return Err(ApiError::bad_request(format!(
            "this server cannot send {} notifications",
            target.platform
        ))
        .with_code("push_disabled"));
    }
    let key = target.device_id.to_string();
    if !push.tests.allow(&key) {
        return Err(ApiError::new(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many test notifications: try again in a minute",
        )
        .with_detail("retry_ms", push.tests.wait_ms(&key)));
    }
    push.test(&target, u.id(), &u.user.locale)
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

    #[test]
    fn endpoint_policy() {
        let open = EndpointPolicy::default();
        assert!(open.check("https://ntfy.sh/upAbc?up=1").is_ok());
        assert!(
            open.check("https://updates.push.services.mozilla.com/wpush/v2/x")
                .is_ok()
        );
        for bad in [
            "http://ntfy.sh/up",
            "https://127.0.0.1/x",
            "https://10.1.2.3/x",
            "https://[::1]/x",
            "https://[fd00::1]/x",
            "https://169.254.169.254/latest",
            "https://100.64.0.1/x",
            "https://localhost/x",
            "https://ntfy.local/x",
            "https://intranet/x",
            "https://u:p@ntfy.sh/x",
            "ftp://ntfy.sh/x",
            "not a url",
        ] {
            assert!(open.check(bad).is_err(), "{bad}");
        }
        let local = EndpointPolicy::from_config(&WebPushSection {
            allowed_endpoints: vec!["http://127.0.0.1:2586/".into()],
            ..Default::default()
        });
        assert!(local.check("http://127.0.0.1:2586/upX?up=1").is_ok());
        assert!(local.check("http://127.0.0.1:2587/upX").is_err());
        assert!(local.hosts.contains("127.0.0.1"));
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_public_ip("::ffff:192.168.1.1".parse().unwrap()));
        assert!(is_public_ip("2a01:4f8::1".parse().unwrap()));
    }

    #[test]
    fn delivery_and_apns_bodies() {
        assert_eq!(delivery("security_key_request", 60), (60, "high"));
        assert_eq!(delivery("ai_approval", 60).1, "high");
        assert_eq!(delivery("team_added", 60), (86_400, "normal"));
        let mut p = Payload::new("ai_approval", "Approval pending", "Waiting")
            .with("approval_id", "a1")
            .with("task_id", "t1");
        p.collapse = Some("approval-a1".into());
        let (body, headers) = apns_request(&p, 3600);
        assert_eq!(body["aps"]["category"], "TERMOAK_APPROVAL");
        assert_eq!(body["termoak"]["type"], "ai_approval");
        assert_eq!(body["termoak"]["approval_id"], "a1");
        assert_eq!(body["termoak"]["category"], "approval");
        assert!(headers.contains(&("apns-push-type", "alert".into())));
        assert!(headers.contains(&("apns-collapse-id", "approval-a1".into())));
        let (body, headers) = apns_request(&Payload::resolved("approval-a1"), 600);
        assert_eq!(body["aps"]["content-available"], 1);
        assert!(body["aps"].get("alert").is_none());
        assert!(headers.contains(&("apns-push-type", "background".into())));
        assert!(headers.contains(&("apns-priority", "5".into())));
    }

    #[test]
    fn vapid_key_is_created_once_with_private_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = WebPushSection::default();
        let a = load_vapid_key(&cfg, dir.path()).unwrap();
        let b = load_vapid_key(&cfg, dir.path()).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(dir.path().join("vapid.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
