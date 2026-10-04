//! Server configuration (TOML).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use termoak_ai::AiConfig;
use termoak_ssh::HostKeyPolicy;

/// Who can create accounts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Registration {
    /// Only the first user (who becomes an administrator); after that, only administrators.
    #[default]
    FirstUser,
    /// Anyone can sign up.
    Open,
    /// Nobody; administrators create the accounts.
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerSection {
    pub listen: SocketAddr,
    /// Public URL (share links and the MCP endpoint for Codex).
    pub public_url: Option<String>,
    pub data_dir: PathBuf,
    pub registration: Registration,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// Allowed CORS origins (empty = none).
    pub cors_origins: Vec<String>,
    /// Access token lifetime (minutes).
    pub access_token_minutes: i64,
    /// Refresh token lifetime (days).
    pub refresh_token_days: i64,
    /// Take the client IP from `X-Forwarded-For` (only behind a trusted
    /// reverse proxy such as Caddy or nginx; otherwise it can be spoofed).
    pub trust_forwarded_for: bool,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:7722".parse().expect("listen address"),
            public_url: None,
            data_dir: PathBuf::from("./data"),
            registration: Registration::FirstUser,
            tls_cert: None,
            tls_key: None,
            cors_origins: Vec::new(),
            access_token_minutes: 60,
            refresh_token_days: 90,
            trust_forwarded_for: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionsSection {
    /// Scrollback per session (KiB).
    pub scrollback_kb: usize,
    /// Close sessions with no viewers and no activity after this many hours (0 = never).
    pub idle_timeout_hours: u64,
    /// Record sessions by default (asciicast).
    pub record: bool,
    /// Also record what is typed (may include passwords).
    pub record_input: bool,
    /// Host key policy for server sessions.
    pub host_key_policy: HostKeyPolicy,
    /// Maximum active sessions per user.
    pub max_per_user: usize,
    /// Minutes a relay session waits for its host to come back.
    pub relay_grace_minutes: u64,
    /// Socket of the session holder (`termoak-server sessions-holder`): it
    /// keeps the SSH connections open so restarting the server does not cut
    /// the sessions. Without it, sessions live in the server process.
    pub holder_socket: Option<PathBuf>,
}

impl Default for SessionsSection {
    fn default() -> Self {
        Self {
            scrollback_kb: 2048,
            idle_timeout_hours: 0,
            record: false,
            record_input: false,
            host_key_policy: HostKeyPolicy::Ask,
            max_per_user: 50,
            relay_grace_minutes: 5,
            holder_socket: None,
        }
    }
}

/// Desktop updates served by this server (for private repositories; see
/// `updates.rs`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdatesSection {
    /// Repository with the releases (`owner/repo`). Disabled when unset.
    pub github_repo: Option<String>,
    /// Environment variable holding the GitHub token (read-only "Contents").
    pub github_token_env: String,
    /// GitHub API base (changed in tests or for GitHub Enterprise).
    pub github_api: String,
}

impl Default for UpdatesSection {
    fn default() -> Self {
        Self {
            github_repo: None,
            github_token_env: "TERMOAK_GITHUB_TOKEN".into(),
            github_api: "https://api.github.com".into(),
        }
    }
}

/// Plan limits (`None` = unlimited).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default)]
pub struct PlanLimits {
    /// Teams the user can own.
    pub max_teams: Option<u32>,
    /// Members per team (applied with the team's plan).
    pub max_team_members: Option<u32>,
    /// Persistent server sessions open at the same time.
    pub max_server_sessions: Option<u32>,
    /// Can use the server's own AI providers (its API keys, the Codex
    /// subscription...). Without it, the AI only runs with the user's own API
    /// keys. `true` when not set.
    pub server_ai: bool,
    /// Monthly credit (USD) for the server's AI providers. When not set,
    /// `[ai] monthly_budget_usd` applies (and without it, no cap). The
    /// user's own API keys never use it.
    pub ai_credit_usd: Option<f64>,
}

impl Default for PlanLimits {
    fn default() -> Self {
        Self {
            max_teams: None,
            max_team_members: None,
            max_server_sessions: None,
            server_ai: true,
            ai_credit_usd: None,
        }
    }
}

/// A catalog plan.
///
/// Clients translate the texts with the keys `plans.<id>.name`,
/// `plans.<id>.description` and `plans.feature.<feature>`, and fall back to
/// `name`, `description` and the raw feature id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Plan {
    /// Stable id (`free`, `pro`...).
    pub id: String,
    /// Display name (English; fallback when a client has no translation).
    pub name: String,
    /// Short description (English; fallback when a client has no translation).
    #[serde(default)]
    pub description: String,
    /// Monthly price in cents (`0` = free; none = not published yet).
    #[serde(default)]
    pub price_cents: Option<u32>,
    #[serde(default = "default_currency")]
    pub currency: String,
    /// Can be used now (`false` = "coming soon").
    #[serde(default = "default_true")]
    pub available: bool,
    /// Team plan (assigned to a team, not to an account).
    #[serde(default)]
    pub for_teams: bool,
    /// Highlight it on the pricing page.
    #[serde(default)]
    pub highlight: bool,
    /// Stable feature ids shown on the pricing page (`encrypted_sync`,
    /// `ai_credit`...); clients translate `plans.feature.<id>`.
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub limits: PlanLimits,
}

fn default_currency() -> String {
    "EUR".into()
}

fn default_true() -> bool {
    true
}

/// Monthly Termoak AI credit of the built-in Pro plan (USD).
pub const DEFAULT_PRO_AI_CREDIT_USD: f64 = 5.0;

/// Plans: they feed the pricing page and apply limits when needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PlansSection {
    /// Plan of new accounts and teams.
    pub default: String,
    /// Catalog (in TOML, `[[plans.catalog]]` blocks).
    pub catalog: Vec<Plan>,
}

impl Default for PlansSection {
    fn default() -> Self {
        let features = |ids: &[&str]| ids.iter().map(|s| s.to_string()).collect();
        let free = [
            "unlimited_entities",
            "encrypted_sync",
            "server_sessions",
            "session_sharing",
            "teams",
            "two_factor",
            "ai_own_keys",
            "desktop_mobile_apps",
        ];
        Self {
            default: "free".into(),
            catalog: vec![
                Plan {
                    id: "free".into(),
                    name: "Free".into(),
                    description: "Everything included. AI runs with your own API keys.".into(),
                    price_cents: Some(0),
                    currency: default_currency(),
                    available: true,
                    for_teams: false,
                    highlight: true,
                    features: features(&free),
                    limits: PlanLimits {
                        server_ai: false,
                        ..PlanLimits::default()
                    },
                },
                Plan {
                    id: "pro".into(),
                    name: "Pro".into(),
                    description: "Everything in Free, plus priority support and Termoak AI credit."
                        .into(),
                    price_cents: None,
                    currency: default_currency(),
                    available: false,
                    for_teams: false,
                    highlight: false,
                    features: features(&[&free[..], &["ai_credit", "priority_support"]].concat()),
                    limits: PlanLimits {
                        server_ai: true,
                        ai_credit_usd: Some(DEFAULT_PRO_AI_CREDIT_USD),
                        ..PlanLimits::default()
                    },
                },
            ],
        }
    }
}

impl PlansSection {
    /// A plan by id (or the default plan, or an unlimited one if the catalog
    /// has neither).
    pub fn get(&self, id: &str) -> Plan {
        self.catalog
            .iter()
            .find(|p| p.id == id)
            .or_else(|| self.catalog.iter().find(|p| p.id == self.default))
            .cloned()
            .unwrap_or_else(|| Plan {
                id: id.to_string(),
                name: id.to_string(),
                description: String::new(),
                price_cents: Some(0),
                currency: default_currency(),
                available: true,
                for_teams: false,
                highlight: false,
                features: Vec::new(),
                limits: PlanLimits::default(),
            })
    }

    pub fn exists(&self, id: &str) -> bool {
        self.catalog.iter().any(|p| p.id == id)
    }
}

/// Outgoing email (email verification, password reset and invitations).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EmailSection {
    /// `smtps://user:password@host:465` or
    /// `smtp://user:password@host:587?tls=required`. Better set through
    /// `TERMOAK_SMTP_URL`. `log://` writes the emails to the log (development
    /// only: they include the links with tokens).
    pub smtp_url: Option<String>,
    /// Sender.
    pub from: String,
    /// Require a verified email to use the account (only when email is
    /// configured).
    pub require_verification: bool,
}

impl Default for EmailSection {
    fn default() -> Self {
        Self {
            smtp_url: None,
            from: "Termoak <no-reply@localhost>".into(),
            require_verification: false,
        }
    }
}

/// Web app served at `/`: the basic one built into the server (sign-in,
/// sessions, teams and account) or your own front-end (`dir`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebSection {
    pub enabled: bool,
    /// Serve the web from this directory instead of the basic web app built
    /// into the server (e.g. your own front-end). It needs an `index.html`;
    /// any other file is served under `/assets/`, and every `GET` that is not
    /// an API route returns `index.html` so the front-end can do its routing.
    pub dir: Option<PathBuf>,
    /// Contact email shown on the website.
    pub support_email: Option<String>,
    /// Links to the terms and the privacy policy (if you have them).
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
}

impl Default for WebSection {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: None,
            support_email: None,
            terms_url: None,
            privacy_url: None,
        }
    }
}

/// Push notifications to the mobile apps.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PushSection {
    /// Include details in the text (the command the AI wants to run, the
    /// session title...). Apple and Google see that text; by default only
    /// generic notices are sent and the app fetches the details when opened.
    pub detailed: bool,
    pub apns: Option<ApnsSection>,
    pub fcm: Option<FcmSection>,
}

/// Apple Push Notification service (iOS), with a `.p8` authentication key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApnsSection {
    /// Path of the `.p8` key. Its content in `TERMOAK_APNS_KEY` also works.
    #[serde(default)]
    pub key_path: Option<PathBuf>,
    /// Key id (10 characters).
    pub key_id: String,
    /// Apple Developer team id.
    pub team_id: String,
    /// Bundle id of the iOS app.
    pub topic: String,
    /// Tests only: other endpoints.
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub sandbox_endpoint: Option<String>,
}

/// Firebase Cloud Messaging (Android), HTTP v1 API with a service account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FcmSection {
    /// Path of the service account JSON. Its content in
    /// `TERMOAK_FCM_CREDENTIALS` also works.
    #[serde(default)]
    pub service_account_path: Option<PathBuf>,
    /// Tests only: another FCM endpoint.
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// Full configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub server: ServerSection,
    pub sessions: SessionsSection,
    pub ai: AiConfig,
    pub updates: UpdatesSection,
    pub plans: PlansSection,
    pub email: EmailSection,
    pub web: WebSection,
    pub push: PushSection,
}

impl ServerConfig {
    /// Reads the file (if any) and applies the `TERMOAK_*` environment variables.
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let mut cfg: ServerConfig = match path {
            Some(p) if p.exists() => toml::from_str(&std::fs::read_to_string(p)?)
                .map_err(|e| anyhow::anyhow!("invalid configuration in {}: {e}", p.display()))?,
            Some(p) => anyhow::bail!("configuration file {} does not exist", p.display()),
            None => ServerConfig::default(),
        };
        if let Ok(v) = std::env::var("TERMOAK_LISTEN") {
            cfg.server.listen = v.parse()?;
        }
        if let Ok(v) = std::env::var("TERMOAK_DATA_DIR") {
            cfg.server.data_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("TERMOAK_PUBLIC_URL") {
            cfg.server.public_url = Some(v);
        }
        if let Ok(v) = std::env::var("TERMOAK_UPDATES_REPO") {
            cfg.updates.github_repo = Some(v);
        }
        if let Ok(v) = std::env::var("TERMOAK_SMTP_URL") {
            cfg.email.smtp_url = Some(v).filter(|v| !v.trim().is_empty());
        }
        if let Ok(v) = std::env::var("TERMOAK_EMAIL_FROM") {
            cfg.email.from = v;
        }
        if let Ok(v) = std::env::var("AI_PROVIDER") {
            cfg.ai.default = v;
        }
        if let Ok(v) = std::env::var("AI_FALLBACK") {
            cfg.ai.fallback = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        Ok(cfg)
    }

    /// Base URL to build links.
    pub fn base_url(&self) -> String {
        self.server
            .public_url
            .clone()
            .map(|u| u.trim_end_matches('/').to_string())
            .unwrap_or_else(|| {
                let scheme = if self.server.tls_cert.is_some() {
                    "https"
                } else {
                    "http"
                };
                let port = self.server.listen.port();
                format!("{scheme}://127.0.0.1:{port}")
            })
    }

    /// Internal URL of the MCP endpoint (Codex runs on the same machine).
    pub fn local_mcp_url(&self) -> String {
        let scheme = if self.server.tls_cert.is_some() {
            "https"
        } else {
            "http"
        };
        format!(
            "{scheme}://127.0.0.1:{}/api/v1/mcp",
            self.server.listen.port()
        )
    }
}

/// Commented example configuration.
pub const EXAMPLE: &str = r#"# Termoak server configuration

[server]
listen = "0.0.0.0:7722"
# Public URL (for shared session links and email links).
# public_url = "https://termoak.example.com"
data_dir = "/var/lib/termoak"
# first_user | open | closed
registration = "first_user"
# Direct TLS (or use a reverse proxy such as Caddy or nginx):
# tls_cert = "/etc/termoak/fullchain.pem"
# tls_key = "/etc/termoak/privkey.pem"
access_token_minutes = 60
refresh_token_days = 90
# Behind Caddy or nginx: use the IP from X-Forwarded-For to rate-limit sign-in
# attempts per IP. Do not enable it if the server is exposed directly.
trust_forwarded_for = false

[sessions]
scrollback_kb = 2048
# 0 = server sessions never expire for inactivity
idle_timeout_hours = 0
record = false
record_input = false
# ask | accept_new | strict
host_key_policy = "ask"
max_per_user = 50
# Session holder (termoak-sessions service): keeps the SSH connections open so
# updating or restarting the server does not cut the sessions. Without it,
# sessions live in the server and are closed when it restarts.
# holder_socket = "/run/termoak-sessions/sessions.sock"

[ai]
# Default provider and fallbacks (provider::model format).
default = "codex"
fallback = ["opencode-api::deepseek-v4-flash", "opencode-api::kimi-k2.6"]
# read_only | ask | auto
default_mode = "ask"
max_steps = 40
approval_timeout_secs = 1800
command_timeout_secs = 120
# Monthly credit per user in USD for the server's providers, for plans that
# allow the server's AI (`server_ai`) without their own `ai_credit_usd`.
# Comment out for no limit. The users' own API keys never count.
# monthly_budget_usd = 50.0
# Tool mode for external agents using MCP with a user token
mcp_user_mode = "read_only"

# The built-in providers (claude, gpt, codex, codex-api, opencode-api,
# openrouter, opencode, local) are configured with environment variables:
#   ANTHROPIC_API_KEY, OPENAI_API_KEY, CODEX_HOME, OPENCODE_GO_KEY,
#   OPENROUTER_API_KEY, LOCAL_AI_BASE_URL...
# Users can add their own API keys for claude, gpt, openrouter and
# opencode-api (Settings → AI): theirs replaces the server's key and does not
# use their plan's AI credit.
# The server's providers take from the plan's credit their real cost or, on
# a subscription or without a price, their tokens at the model's price (e.g.
# Codex with gpt-5.6-sol at OpenAI API prices) or a reference price (Codex:
# GPT-5.3-codex; others: $2 / $10 per million). `credit_price` (USD per
# million tokens) sets it per provider.
# or by overriding them here:
# [ai.providers.claude]
# driver = "anthropic"
# api_key_env = ["ANTHROPIC_API_KEY"]
# model = "claude-opus-5"
# effort = "high"
#
# [ai.providers.codex]
# driver = "codex_cli"
# command = "/usr/local/bin/codex"
# codex_home = "/var/lib/termoak/codex"
# subscription = true
# # Charged to the plans' credit instead of the model's price:
# credit_price = { input = 1.75, output = 14.0, cached_input = 0.175 }
#
# [ai.providers.opencode-api]
# driver = "openai_chat"
# base_url = "https://opencode.ai/zen/go/v1"
# api_key_env = ["OPENCODE_GO_KEY"]
# model = "deepseek-v4-flash"
# list_models = true
# subscription = true

# Desktop updates from GitHub releases. Needed when the repository is private:
# the app downloads them from /updates/latest.json on this server. The
# (read-only) token goes in the TERMOAK_GITHUB_TOKEN variable.
# [updates]
# github_repo = "owner/repo"

# Web app at /: the basic one built into the server (sign-in, sessions, teams
# and account), or your own front-end with `dir`.
[web]
enabled = true
# Serve your own front-end from a directory instead of the built-in basic web
# app (needs an index.html; other files are served under /assets/).
# dir = "/var/lib/termoak/web"
# support_email = "support@example.com"
# terms_url = "https://example.com/terms"
# privacy_url = "https://example.com/privacy"

# Outgoing email to verify addresses, reset passwords and send invitations.
# Better put the URL (with the password) in TERMOAK_SMTP_URL. public_url is
# needed for the links in the emails to work. Emails are sent in the
# recipient's language (the account's `locale`).
[email]
# smtp_url = "smtps://user:password@smtp.example.com:465"
from = "Termoak <no-reply@localhost>"
# Require a verified email to use the account
require_verification = false

# Push notifications to the iOS and Android apps (AI approvals, finished
# tasks, sessions shared with you...). By default the text is generic: Apple
# and Google never see commands or titles (detailed = true to include them).
[push]
detailed = false
# [push.apns]
# key_path = "/etc/termoak/AuthKey_ABC123DEFG.p8"   # or TERMOAK_APNS_KEY
# key_id = "ABC123DEFG"
# team_id = "TEAMID1234"
# topic = "com.termoak"
# [push.fcm]
# service_account_path = "/etc/termoak/firebase.json"   # or TERMOAK_FCM_CREDENTIALS

# Plans. The catalog feeds the pricing page and can set limits (unlimited when
# not set). Without a catalog the built-in one is used: "free" (everything
# included, AI with your own API keys: server_ai = false) and "pro" (coming
# soon: adds priority support and Termoak AI credit: server_ai = true,
# ai_credit_usd = 5.0). Administrators have no limits.
#
# AI limits: `server_ai` (default true) lets the plan use this server's AI
# providers; `ai_credit_usd` is their monthly credit (default: [ai]
# monthly_budget_usd, or no cap). To share the server's AI with every user,
# set server_ai = true on the plans they have.
#
# `features` are stable ids, not display text. Clients translate the keys
# `plans.<id>.name`, `plans.<id>.description` and `plans.feature.<feature>`,
# and fall back to `name`, `description` and the raw feature id. Known ids:
# unlimited_entities, encrypted_sync, server_sessions, session_sharing, teams,
# two_factor, ai_own_keys, ai_credit, priority_support, desktop_mobile_apps.
[plans]
default = "free"
# [[plans.catalog]]
# id = "free"
# name = "Free"
# description = "Everything included. AI runs with your own API keys."
# price_cents = 0
# features = ["unlimited_entities", "encrypted_sync", "teams"]
# [plans.catalog.limits]
# max_teams = 3
# max_team_members = 10
# max_server_sessions = 20
# server_ai = false
#
# [[plans.catalog]]
# id = "pro"
# name = "Pro"
# features = ["unlimited_entities", "encrypted_sync", "teams", "ai_credit"]
# [plans.catalog.limits]
# server_ai = true
# ai_credit_usd = 5.0
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credit_price_parses() {
        let cfg: ServerConfig = toml::from_str(
            "[ai.providers.codex]\ndriver = \"codex_cli\"\nsubscription = true\n\
             credit_price = { input = 1.75, output = 14.0, cached_input = 0.175 }\n",
        )
        .unwrap();
        let p = cfg.ai.providers["codex"].credit_price.unwrap();
        assert_eq!((p.input, p.output, p.cache_read), (1.75, 14.0, Some(0.175)));
    }

    #[test]
    fn example_parses() {
        let cfg: ServerConfig = toml::from_str(EXAMPLE).unwrap();
        assert_eq!(cfg.server.listen.port(), 7722);
        assert_eq!(cfg.ai.default, "codex");
        assert_eq!(cfg.sessions.host_key_policy, HostKeyPolicy::Ask);
        assert!(cfg.web.enabled);
        assert_eq!(cfg.plans.default, "free");
        assert_eq!(cfg.plans.catalog.len(), 2);
        assert!(cfg.plans.get("free").available);
        assert_eq!(cfg.plans.get("missing").id, "free");
    }

    #[test]
    fn default_plans_use_feature_ids() {
        let plans = PlansSection::default();
        let free = plans.get("free");
        assert_eq!((free.name.as_str(), free.price_cents), ("Free", Some(0)));
        assert!(free.features.contains(&"ai_own_keys".to_string()));
        assert!(!free.features.contains(&"ai_credit".to_string()));
        assert!(!free.limits.server_ai);
        let pro = plans.get("pro");
        assert!(!pro.available && pro.price_cents.is_none());
        assert!(pro.limits.server_ai);
        assert_eq!(pro.limits.ai_credit_usd, Some(DEFAULT_PRO_AI_CREDIT_USD));
        // Plans written without AI limits keep the server's AI.
        let custom: Plan = toml::from_str("id = \"x\"\nname = \"X\"").unwrap();
        assert!(custom.limits.server_ai && custom.limits.ai_credit_usd.is_none());
        assert!(pro.features.contains(&"ai_credit".to_string()));
        assert!(pro.features.contains(&"priority_support".to_string()));
        for f in plans.catalog.iter().flat_map(|p| &p.features) {
            assert!(
                f.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "feature {f} is not an id"
            );
        }
    }
}
