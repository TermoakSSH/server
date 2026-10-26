//! API errors with a uniform JSON body:
//! `{"error": {"code": "not_found", "message": "..."}}`.
//!
//! `code` is stable snake_case that clients translate (`error.<code>`);
//! `message` is English and only shown when a client has no translation.
//! Some errors add extra fields next to them for the translation
//! placeholders (`plan_limit` adds `limit` and `max`, for example).

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};
use termoak_ai::AiError;
use termoak_core::CoreError;
use termoak_core::error::codes;
use termoak_ssh::SshError;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    /// Extra fields of the error object (placeholders for translations).
    pub details: Map<String, Value>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            details: Map::new(),
        }
    }

    pub fn bad_request(m: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", m)
    }

    pub fn unauthorized(m: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", m)
    }

    /// The current password (or code) asked to confirm an action is wrong.
    /// Not a 401: the session is still valid.
    pub fn invalid_password(m: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "invalid_password", m)
    }

    pub fn forbidden(m: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", m)
    }

    pub fn not_found(m: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", m)
    }

    pub fn conflict(m: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", m)
    }

    pub fn internal(m: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", m)
    }

    /// Replaces the generic code with a more specific one, keeping the status:
    /// `ApiError::forbidden("...").with_code("session_owner_only")`.
    pub fn with_code(mut self, code: &'static str) -> Self {
        self.code = code;
        self
    }

    /// Adds an extra field to the error object.
    pub fn with_detail(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.details.insert(key.to_string(), value.into());
        self
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            tracing::error!(code = self.code, message = %self.message, "internal API error");
        }
        let mut error = self.details;
        error.insert("code".into(), self.code.into());
        error.insert("message".into(), self.message.into());
        (self.status, Json(json!({ "error": error }))).into_response()
    }
}

impl From<CoreError> for ApiError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::NotFound(m) => ApiError::not_found(m),
            CoreError::Conflict(m) => ApiError::conflict(m),
            CoreError::Invalid(m) => ApiError::bad_request(m),
            CoreError::Forbidden(m) => ApiError::forbidden(m),
            CoreError::Vault {
                code,
                message,
                detail,
            } => {
                let status = match code {
                    codes::VAULT_NOT_FOUND => StatusCode::NOT_FOUND,
                    codes::VAULT_PERSONAL
                    | codes::USE_TRANSFER
                    | codes::STILL_REFERENCED
                    | codes::MEMBER_EXISTS
                    | codes::ID_IN_USE
                    | codes::CA_EXISTS
                    | codes::ACCESS_REQUEST_EXISTS
                    | codes::ACCESS_REQUEST_NOT_NEEDED
                    | codes::ACCESS_REQUEST_CLOSED
                    | codes::TEAM_2FA_REQUIRED
                    | codes::POLICY_REQUIRES_2FA
                    | codes::E2EE_LOCKED
                    | codes::E2EE_NOT_SET_UP
                    | codes::E2EE_KEY_EXISTS
                    | codes::E2EE_PLAINTEXT_REJECTED
                    | codes::E2EE_KEY_OUTDATED
                    | codes::E2EE_VAULT
                    | codes::E2EE_UNLOCK_REQUIRED
                    | codes::E2EE_INCOMPLETE
                    | codes::E2EE_NOT_ENABLED
                    | codes::E2EE_ALREADY_ENABLED
                    | codes::E2EE_CLIENT_REQUIRED
                    | codes::E2EE_PAIRING_CLOSED
                    | codes::E2EE_STALE
                    | codes::E2EE_KEY_MISMATCH
                    | codes::SSO_DOMAIN_TAKEN => StatusCode::CONFLICT,
                    codes::E2EE_WRAP_INVALID
                    | codes::E2EE_PASSPHRASE_TOO_SHORT
                    | codes::E2EE_DECRYPT_FAILED
                    | codes::E2EE_RECOVERY_KEY_INVALID
                    | codes::E2EE_PASSPHRASE_INVALID => StatusCode::BAD_REQUEST,
                    codes::CA_NOT_CONFIGURED => StatusCode::NOT_FOUND,
                    codes::ACCESS_DURATION_TOO_LONG | codes::CERTIFICATE_NO_PRINCIPALS => {
                        StatusCode::BAD_REQUEST
                    }
                    codes::CROSS_VAULT_REFERENCE => StatusCode::UNPROCESSABLE_ENTITY,
                    codes::INVALID_ROLE | codes::INVALID_SNIPPET => StatusCode::BAD_REQUEST,
                    codes::NETWORK_NOT_FOUND => StatusCode::NOT_FOUND,
                    codes::NETWORK_UNAVAILABLE => StatusCode::SERVICE_UNAVAILABLE,
                    codes::NETWORK_DIAL_FAILED => StatusCode::BAD_GATEWAY,
                    _ => StatusCode::FORBIDDEN,
                };
                let mut e = ApiError::new(status, code, message);
                if let Some(Value::Object(map)) = detail {
                    e.details.extend(map);
                }
                e
            }
            other => ApiError::internal(other.to_string()),
        }
    }
}

impl From<SshError> for ApiError {
    fn from(e: SshError) -> Self {
        match e {
            SshError::Core(c) => c.into(),
            SshError::Auth { .. } => {
                ApiError::new(StatusCode::BAD_GATEWAY, "ssh_auth_failed", e.to_string())
            }
            SshError::HostKeyChanged { .. } => {
                ApiError::new(StatusCode::CONFLICT, "host_key_changed", e.to_string())
            }
            SshError::HostKeyUnknown { .. } => {
                ApiError::new(StatusCode::CONFLICT, "host_key_unknown", e.to_string())
            }
            SshError::HostKeyRejected { .. } => {
                ApiError::new(StatusCode::CONFLICT, "host_key_rejected", e.to_string())
            }
            SshError::Timeout(_) => {
                ApiError::new(StatusCode::GATEWAY_TIMEOUT, "ssh_timeout", e.to_string())
            }
            SshError::Key(m) => ApiError::bad_request(m),
            // SFTP, tunnels or jumps through a Telnet host (or a protocol
            // this version does not know).
            SshError::Unsupported(m) => {
                ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "not_supported", m)
            }
            // Private networks: `network_unavailable` (no netd, or it is
            // down), `network_not_found`, `network_dial_failed`.
            // FIDO2 security keys (docs/SSH-PRO.md §3.6).
            SshError::SecurityKey { code, message } => {
                ApiError::new(security_key_status(code), code, message)
            }
            SshError::Network { code, message } => {
                let status = match code {
                    codes::NETWORK_UNAVAILABLE => StatusCode::SERVICE_UNAVAILABLE,
                    codes::NETWORK_NOT_FOUND => StatusCode::NOT_FOUND,
                    _ => StatusCode::BAD_GATEWAY,
                };
                ApiError::new(status, code, message)
            }
            other => ApiError::new(StatusCode::BAD_GATEWAY, "ssh_error", other.to_string()),
        }
    }
}

/// HTTP status of a `security_key_*` code.
pub fn security_key_status(code: &str) -> StatusCode {
    match code {
        codes::SECURITY_KEY_TIMEOUT => StatusCode::GATEWAY_TIMEOUT,
        codes::SECURITY_KEY_UNSUPPORTED => StatusCode::UNPROCESSABLE_ENTITY,
        codes::SECURITY_KEY_INVALID => StatusCode::BAD_REQUEST,
        codes::SECURITY_KEY_FAILED => StatusCode::BAD_GATEWAY,
        _ => StatusCode::CONFLICT,
    }
}

impl From<AiError> for ApiError {
    fn from(e: AiError) -> Self {
        match e {
            AiError::Core(c) => c.into(),
            AiError::NotFound(m) => ApiError::not_found(m),
            AiError::Invalid(m) => ApiError::bad_request(m),
            AiError::Forbidden(m) => ApiError::forbidden(m),
            AiError::BudgetExceeded(m) => {
                ApiError::new(StatusCode::FORBIDDEN, "ai_budget_exceeded", m)
            }
            AiError::KeyRequired(m) => ApiError::new(StatusCode::FORBIDDEN, "ai_key_required", m),
            AiError::NotConfigured(m) => {
                ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "ai_not_configured", m)
            }
            other => ApiError::new(StatusCode::BAD_GATEWAY, "ai_error", other.to_string()),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::internal(e.to_string())
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
