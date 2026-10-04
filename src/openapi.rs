//! OpenAPI 3.1 contract of the API (`GET /api/openapi.json`).
//!
//! Built in code from a table of endpoints and the schemas derived from the
//! real types, so it cannot drift. The iOS (Swift) and Android (Kotlin)
//! clients are generated from it.

use std::collections::BTreeMap;

use termoak_core::model::*;
use utoipa::openapi::path::{
    HttpMethod, OperationBuilder, ParameterBuilder, ParameterIn, PathItemBuilder,
};
use utoipa::openapi::request_body::RequestBodyBuilder;
use utoipa::openapi::response::ResponseBuilder;
use utoipa::openapi::schema::{AllOfBuilder, ArrayBuilder, ComponentsBuilder, ObjectBuilder, Type};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityRequirement, SecurityScheme};
use utoipa::openapi::tag::TagBuilder;
use utoipa::openapi::{
    ContentBuilder, InfoBuilder, OpenApi, OpenApiBuilder, PathsBuilder, Ref, RefOr, Required,
    Schema,
};

use crate::auth::*;
use crate::routes::ai::{
    AiAccess, AiKeyProvider, AiKeyTestResult, AiKeyView, Decision, ExplainReq, SetAiKey, SetMode,
    SuggestReq, TaskMessage, TestAiKey,
};
use crate::routes::entities::{
    ExecRequest, ExecResult, GenerateKey, HostTest, ImportKey, SyncRequest, SyncResponse,
};
use crate::routes::sessions::{CreateShare, OpenRelay, OpenSession, RenameSession, SessionList};
use crate::routes::sftp::{ChmodReq, DeleteReq, MkdirReq, RenameReq};
use crate::routes::teams::{AddMember, CreateTeam, SetPlan, SetRole, TeamInviteRequest};

/// Shape of a request or response body.
#[derive(Clone, Copy)]
enum Body {
    None,
    Ref(&'static str),
    List(&'static str),
    /// Entity with metadata (`Record<T>`).
    Record(&'static str),
    RecordList(&'static str),
    Object,
    Binary,
}

struct Ep {
    method: HttpMethod,
    path: &'static str,
    tag: &'static str,
    summary: &'static str,
    req: Body,
    resp: Body,
    auth: bool,
    query: &'static [&'static str],
}

const fn ep(
    method: HttpMethod,
    path: &'static str,
    tag: &'static str,
    summary: &'static str,
    req: Body,
    resp: Body,
) -> Ep {
    Ep {
        method,
        path,
        tag,
        summary,
        req,
        resp,
        auth: true,
        query: &[],
    }
}

fn endpoints() -> Vec<Ep> {
    use Body::*;
    use HttpMethod::*;
    let mut v = vec![
        Ep {
            auth: false,
            ..ep(
                Get,
                "/api/v1/info",
                "system",
                "Server information",
                None,
                Object,
            )
        },
        Ep {
            auth: false,
            ..ep(
                Get,
                "/api/v1/locales",
                "system",
                "Languages the server has for emails and notifications: \
                 {\"default\": \"en\", \"locales\": [{\"code\", \"name\"}]}",
                None,
                Object,
            )
        },
        Ep {
            auth: false,
            ..ep(
                Post,
                "/api/v1/auth/register",
                "auth",
                "Create an account (the first user becomes an administrator). \
                 `locale` defaults to the best match of `Accept-Language`, else `en`. \
                 `accept_terms: true` (and `terms_version`) records the acceptance of the \
                 server's terms (`terms_url`, `privacy_url` in `/info`) in the audit log; \
                 `false` is rejected with `terms_not_accepted` when the server has terms",
                Ref("RegisterRequest"),
                Ref("AuthResponse"),
            )
        },
        Ep {
            auth: false,
            ..ep(
                Post,
                "/api/v1/auth/login",
                "auth",
                "Sign in (issues tokens for this device)",
                Ref("LoginRequest"),
                Ref("AuthResponse"),
            )
        },
        Ep {
            auth: false,
            ..ep(
                Post,
                "/api/v1/auth/refresh",
                "auth",
                "Renew tokens with the refresh token",
                Ref("RefreshRequest"),
                Ref("TokenPair"),
            )
        },
        ep(
            Post,
            "/api/v1/auth/logout",
            "auth",
            "Sign out this device",
            None,
            Object,
        ),
        ep(
            Get,
            "/api/v1/me",
            "auth",
            "Current user (including `locale`), device and plan",
            None,
            Object,
        ),
        ep(
            Patch,
            "/api/v1/me",
            "auth",
            "Update the profile: `name` and/or `locale` (unknown locale: 400 `invalid_locale`)",
            Ref("UpdateMe"),
            Ref("User"),
        ),
        ep(
            Post,
            "/api/v1/me/password",
            "auth",
            "Change the password",
            Ref("ChangePassword"),
            Object,
        ),
        ep(
            Get,
            "/api/v1/devices",
            "auth",
            "Signed-in devices",
            None,
            Object,
        ),
        ep(
            Delete,
            "/api/v1/devices/{id}",
            "auth",
            "Sign out a device",
            None,
            Object,
        ),
        ep(
            Get,
            "/api/v1/admin/users",
            "admin",
            "List users",
            None,
            List("User"),
        ),
        ep(
            Post,
            "/api/v1/admin/users",
            "admin",
            "Create a user",
            Ref("CreateUser"),
            Ref("User"),
        ),
        ep(
            Patch,
            "/api/v1/admin/users/{id}",
            "admin",
            "Update a user",
            Ref("UpdateUser"),
            Ref("User"),
        ),
        ep(
            Get,
            "/api/v1/me/2fa",
            "auth",
            "Two-factor authentication status",
            None,
            Object,
        ),
        ep(
            Post,
            "/api/v1/me/2fa/setup",
            "auth",
            "Generate the two-factor secret and QR code",
            None,
            Ref("TotpSetup"),
        ),
        ep(
            Post,
            "/api/v1/me/2fa/enable",
            "auth",
            "Enable two-factor authentication (returns the recovery codes)",
            Ref("TotpCode"),
            Object,
        ),
        ep(
            Post,
            "/api/v1/me/2fa/disable",
            "auth",
            "Disable two-factor authentication",
            Ref("TotpDisable"),
            Object,
        ),
        Ep {
            auth: false,
            ..ep(
                Get,
                "/api/v1/invites/{token}",
                "auth",
                "Public details of an invitation",
                None,
                Object,
            )
        },
        ep(
            Post,
            "/api/v1/admin/users/{id}/password",
            "admin",
            "Set a new password (signs out all their devices)",
            Ref("ResetPassword"),
            Object,
        ),
        ep(
            Post,
            "/api/v1/admin/users/{id}/2fa/reset",
            "admin",
            "Remove two-factor authentication from a user",
            None,
            Object,
        ),
        ep(
            Get,
            "/api/v1/admin/users/{id}/devices",
            "admin",
            "Devices of a user",
            None,
            List("Device"),
        ),
        ep(
            Delete,
            "/api/v1/admin/users/{id}/devices/{device_id}",
            "admin",
            "Sign out a device of a user",
            None,
            Object,
        ),
        ep(
            Get,
            "/api/v1/admin/invites",
            "admin",
            "List invitations",
            None,
            List("Invite"),
        ),
        ep(
            Post,
            "/api/v1/admin/invites",
            "admin",
            "Create an invitation (sign-up while registration is closed)",
            Ref("CreateInvite"),
            Ref("CreatedInvite"),
        ),
        ep(
            Delete,
            "/api/v1/admin/invites/{id}",
            "admin",
            "Revoke an invitation",
            None,
            Object,
        ),
        Ep {
            query: &["before", "limit"],
            ..ep(
                Get,
                "/api/v1/admin/audit",
                "admin",
                "Audit log of the whole server",
                None,
                List("AuditEntry"),
            )
        },
        ep(
            Get,
            "/api/v1/teams",
            "teams",
            "My teams",
            None,
            List("Team"),
        ),
        ep(
            Post,
            "/api/v1/teams",
            "teams",
            "Create a team",
            Ref("CreateTeam"),
            Ref("Team"),
        ),
        ep(
            Get,
            "/api/v1/teams/{id}",
            "teams",
            "Team with its members",
            None,
            Object,
        ),
        ep(
            Patch,
            "/api/v1/teams/{id}",
            "teams",
            "Rename a team",
            Ref("CreateTeam"),
            Ref("Team"),
        ),
        ep(
            Delete,
            "/api/v1/teams/{id}",
            "teams",
            "Delete a team",
            None,
            Object,
        ),
        ep(
            Get,
            "/api/v1/teams/{id}/members",
            "teams",
            "Members",
            None,
            List("TeamMember"),
        ),
        ep(
            Post,
            "/api/v1/teams/{id}/members",
            "teams",
            "Add a member",
            Ref("AddMember"),
            List("TeamMember"),
        ),
        ep(
            Patch,
            "/api/v1/teams/{id}/members/{user_id}",
            "teams",
            "Change the role of a member",
            Ref("SetRole"),
            List("TeamMember"),
        ),
        ep(
            Delete,
            "/api/v1/teams/{id}/members/{user_id}",
            "teams",
            "Remove a member or leave the team",
            None,
            Object,
        ),
        ep(
            Get,
            "/api/v1/teams/{id}/invites",
            "teams",
            "Pending invitations of the team",
            None,
            List("Invite"),
        ),
        ep(
            Post,
            "/api/v1/teams/{id}/invites",
            "teams",
            "Invite by email (joins directly if they already have an account)",
            Ref("TeamInviteRequest"),
            Object,
        ),
        ep(
            Delete,
            "/api/v1/teams/{id}/invites/{invite_id}",
            "teams",
            "Revoke a team invitation",
            None,
            Object,
        ),
        ep(
            Post,
            "/api/v1/admin/teams/{id}/plan",
            "admin",
            "Change the plan of a team",
            Ref("SetPlan"),
            Ref("Team"),
        ),
        ep(
            Delete,
            "/api/v1/me",
            "account",
            "Delete the account and all its data",
            Ref("DeleteAccount"),
            Object,
        ),
        Ep {
            auth: false,
            ..ep(
                Get,
                "/api/v1/plans",
                "account",
                "Plan catalog",
                None,
                Object,
            )
        },
        ep(
            Get,
            "/api/v1/me/plan",
            "account",
            "Your plan, its limits and your usage (`usage.ai_spent_usd`: this month's \
             spending on the server's AI providers; `usage.ai_credit_usd`: your credit)",
            None,
            Object,
        ),
        ep(
            Post,
            "/api/v1/me/verify-email",
            "account",
            "Resend the verification email",
            None,
            Object,
        ),
        ep(
            Post,
            "/api/v1/me/email",
            "account",
            "Change the email (confirmed from the new address)",
            Ref("ChangeEmail"),
            Object,
        ),
        Ep {
            auth: false,
            ..ep(
                Post,
                "/api/v1/auth/verify-email",
                "account",
                "Confirm the email with the token from the message",
                Ref("TokenRequest"),
                Object,
            )
        },
        Ep {
            auth: false,
            ..ep(
                Post,
                "/api/v1/auth/confirm-email",
                "account",
                "Confirm an email change",
                Ref("TokenRequest"),
                Object,
            )
        },
        Ep {
            auth: false,
            ..ep(
                Post,
                "/api/v1/auth/forgot-password",
                "account",
                "Request a link to set a new password",
                Ref("ForgotPassword"),
                Object,
            )
        },
        Ep {
            auth: false,
            ..ep(
                Post,
                "/api/v1/auth/reset-password",
                "account",
                "Set a new password with the token from the email",
                Ref("ResetWithToken"),
                Object,
            )
        },
        ep(
            Post,
            "/api/v1/push/register",
            "account",
            "Enable push notifications on this device",
            Ref("RegisterPush"),
            Object,
        ),
        ep(
            Delete,
            "/api/v1/push/register",
            "account",
            "Disable push notifications on this device",
            None,
            Object,
        ),
        ep(
            Post,
            "/api/v1/push/test",
            "account",
            "Send a test notification to this device",
            None,
            Object,
        ),
        Ep {
            auth: false,
            ..ep(
                Get,
                "/api/v1/downloads",
                "account",
                "Files of the latest release (apps and server)",
                None,
                Object,
            )
        },
        ep(
            Post,
            "/api/v1/keys/generate",
            "keychain",
            "Generate an SSH key",
            Ref("GenerateKey"),
            Record("SshKey"),
        ),
        ep(
            Post,
            "/api/v1/keys/import",
            "keychain",
            "Import an SSH key",
            Ref("ImportKey"),
            Record("SshKey"),
        ),
        Ep {
            query: &["trust"],
            ..ep(
                Post,
                "/api/v1/hosts/{id}/test",
                "hosts",
                "Test the connection from the server",
                None,
                Ref("HostTest"),
            )
        },
        ep(
            Get,
            "/api/v1/hosts/{id}/effective",
            "hosts",
            "Effective settings (with group inheritance)",
            None,
            Ref("HostSettings"),
        ),
        ep(
            Post,
            "/api/v1/sync",
            "sync",
            "Sync changes (last writer wins)",
            Ref("SyncRequest"),
            Ref("SyncResponse"),
        ),
        Ep {
            query: &["before", "limit"],
            ..ep(
                Get,
                "/api/v1/audit",
                "audit",
                "Audit log",
                None,
                List("AuditEntry"),
            )
        },
        ep(
            Post,
            "/api/v1/exec",
            "hosts",
            "Run a command or snippet on several hosts",
            Ref("ExecRequest"),
            List("ExecResult"),
        ),
        ep(
            Get,
            "/api/v1/sessions",
            "sessions",
            "Own sessions, sessions shared with me and history",
            None,
            Ref("SessionList"),
        ),
        ep(
            Post,
            "/api/v1/sessions",
            "sessions",
            "Open a persistent terminal on the server",
            Ref("OpenSession"),
            Object,
        ),
        ep(
            Get,
            "/api/v1/sessions/{id}",
            "sessions",
            "Status of a session",
            None,
            Object,
        ),
        ep(
            Patch,
            "/api/v1/sessions/{id}",
            "sessions",
            "Rename a session",
            Ref("RenameSession"),
            Object,
        ),
        ep(
            Delete,
            "/api/v1/sessions/{id}",
            "sessions",
            "Close a session",
            None,
            Object,
        ),
        Ep {
            query: &["access_token", "share_token", "role"],
            ..ep(
                Get,
                "/api/v1/sessions/{id}/ws",
                "sessions",
                "Terminal WebSocket (see docs/WEBSOCKET-PROTOCOL.md)",
                None,
                None,
            )
        },
        ep(
            Get,
            "/api/v1/sessions/{id}/recording",
            "sessions",
            "Download the recording (asciicast v2)",
            None,
            Binary,
        ),
        ep(
            Get,
            "/api/v1/sessions/{id}/shares",
            "sessions",
            "Invitations of a session",
            None,
            List("SessionShare"),
        ),
        ep(
            Post,
            "/api/v1/sessions/{id}/shares",
            "sessions",
            "Share with a user or with a link",
            Ref("CreateShare"),
            Object,
        ),
        ep(
            Delete,
            "/api/v1/sessions/{id}/shares/{share_id}",
            "sessions",
            "Revoke an invitation (kicks out whoever is using it)",
            None,
            Object,
        ),
        ep(
            Post,
            "/api/v1/relay",
            "sessions",
            "Create a relay session to share a local terminal",
            Ref("OpenRelay"),
            Object,
        ),
        Ep {
            auth: false,
            ..ep(
                Get,
                "/api/v1/join/{token}",
                "sessions",
                "Details of a link invitation",
                None,
                Object,
            )
        },
        ep(
            Get,
            "/api/v1/hosts/{id}/sftp/home",
            "sftp",
            "Home directory",
            None,
            Object,
        ),
        Ep {
            query: &["path"],
            ..ep(
                Get,
                "/api/v1/hosts/{id}/sftp/list",
                "sftp",
                "List a directory",
                None,
                Object,
            )
        },
        Ep {
            query: &["path"],
            ..ep(
                Get,
                "/api/v1/hosts/{id}/sftp/stat",
                "sftp",
                "File details",
                None,
                Object,
            )
        },
        Ep {
            query: &["path"],
            ..ep(
                Get,
                "/api/v1/hosts/{id}/sftp/download",
                "sftp",
                "Download (streaming)",
                None,
                Binary,
            )
        },
        Ep {
            query: &["path"],
            ..ep(
                Post,
                "/api/v1/hosts/{id}/sftp/upload",
                "sftp",
                "Upload (the body is the file)",
                Binary,
                Object,
            )
        },
        ep(
            Post,
            "/api/v1/hosts/{id}/sftp/mkdir",
            "sftp",
            "Create a directory",
            Ref("MkdirReq"),
            Object,
        ),
        ep(
            Post,
            "/api/v1/hosts/{id}/sftp/rename",
            "sftp",
            "Rename or move",
            Ref("RenameReq"),
            Object,
        ),
        ep(
            Post,
            "/api/v1/hosts/{id}/sftp/delete",
            "sftp",
            "Delete a file or directory",
            Ref("DeleteReq"),
            Object,
        ),
        ep(
            Post,
            "/api/v1/hosts/{id}/sftp/chmod",
            "sftp",
            "Change permissions",
            Ref("ChmodReq"),
            Object,
        ),
        ep(
            Get,
            "/api/v1/ai/providers",
            "ai",
            "AI providers and models, with `available` for you (your plan and own keys) and, \
             if not, `reason_code` (`not_configured`, `own_key_required`, `plan`) and `reason` \
             (detailed only for administrators)",
            None,
            Object,
        ),
        Ep {
            query: &["limit"],
            ..ep(Get, "/api/v1/ai/tasks", "ai", "AI tasks", None, Object)
        },
        ep(
            Post,
            "/api/v1/ai/tasks",
            "ai",
            "Create a background task",
            Object,
            Object,
        ),
        Ep {
            query: &["messages"],
            ..ep(
                Get,
                "/api/v1/ai/tasks/{id}",
                "ai",
                "Task (with the conversation)",
                None,
                Object,
            )
        },
        ep(
            Delete,
            "/api/v1/ai/tasks/{id}",
            "ai",
            "Delete a task",
            None,
            Object,
        ),
        ep(
            Post,
            "/api/v1/ai/tasks/{id}/messages",
            "ai",
            "Continue the conversation",
            Ref("TaskMessage"),
            Object,
        ),
        ep(
            Post,
            "/api/v1/ai/tasks/{id}/cancel",
            "ai",
            "Cancel",
            None,
            Object,
        ),
        ep(
            Post,
            "/api/v1/ai/tasks/{id}/mode",
            "ai",
            "Change the permission mode",
            Ref("SetMode"),
            Object,
        ),
        Ep {
            query: &["after"],
            ..ep(
                Get,
                "/api/v1/ai/tasks/{id}/events",
                "ai",
                "Stored events of a task",
                None,
                Object,
            )
        },
        ep(
            Post,
            "/api/v1/ai/tasks/{id}/approvals/{approval_id}",
            "ai",
            "Approve or deny an action",
            Ref("Decision"),
            Object,
        ),
        ep(
            Get,
            "/api/v1/ai/approvals",
            "ai",
            "Pending approvals",
            None,
            Object,
        ),
        ep(
            Post,
            "/api/v1/ai/suggest",
            "ai",
            "From natural language to a command",
            Ref("SuggestReq"),
            Object,
        ),
        ep(
            Post,
            "/api/v1/ai/explain",
            "ai",
            "Explain an output or an error",
            Ref("ExplainReq"),
            Object,
        ),
        ep(
            Post,
            "/api/v1/mcp",
            "ai",
            "MCP server (JSON-RPC 2.0)",
            Object,
            Object,
        ),
        ep(
            Get,
            "/api/v1/me/ai/keys",
            "ai",
            "Your own AI API keys (never the keys: provider, model, last 4 characters)",
            None,
            List("AiKeyView"),
        ),
        ep(
            Put,
            "/api/v1/me/ai/keys/{provider}",
            "ai",
            "Save your own API key for `claude`, `gpt`, `openrouter` or `opencode-api` \
             (`unknown_provider` otherwise). It replaces the server's key for that provider \
             and does not use your plan's AI credit. Without `key`, only the model of the \
             saved key changes (404 if there is none)",
            Ref("SetAiKey"),
            Ref("AiKeyView"),
        ),
        ep(
            Delete,
            "/api/v1/me/ai/keys/{provider}",
            "ai",
            "Delete one of your own API keys: {\"ok\": true, \"deleted\": bool}",
            None,
            Object,
        ),
        ep(
            Post,
            "/api/v1/me/ai/keys/{provider}/test",
            "ai",
            "Check a key with its provider (a call that spends nothing): the one in the \
             body, or the saved one. 10 checks per minute",
            Ref("TestAiKey"),
            Ref("AiKeyTestResult"),
        ),
        ep(
            Get,
            "/api/v1/me/ai/access",
            "ai",
            "Your AI situation: own keys, whether your plan includes the server's AI, \
             its credit and this month's spending",
            None,
            Ref("AiAccess"),
        ),
        Ep {
            query: &["access_token"],
            ..ep(
                Get,
                "/api/v1/events/ws",
                "events",
                "User events WebSocket",
                None,
                None,
            )
        },
    ];
    for (name, schema) in [
        ("hosts", "Host"),
        ("groups", "Group"),
        ("identities", "Identity"),
        ("keys", "SshKey"),
        ("snippets", "Snippet"),
        ("forwards", "PortForward"),
        ("known-hosts", "KnownHost"),
        ("memories", "Memory"),
    ] {
        let list: &'static str = Box::leak(format!("/api/v1/{name}").into_boxed_str());
        let item: &'static str = Box::leak(format!("/api/v1/{name}/{{id}}").into_boxed_str());
        let secret: &'static str =
            Box::leak(format!("/api/v1/{name}/{{id}}/secret").into_boxed_str());
        v.push(ep(
            Get,
            list,
            name_tag(name),
            "List",
            None,
            RecordList(schema),
        ));
        v.push(ep(
            Post,
            list,
            name_tag(name),
            "Create (fields + optional `secret` + `sync_mode`)",
            Ref(schema),
            Record(schema),
        ));
        v.push(ep(Get, item, name_tag(name), "Get", None, Record(schema)));
        v.push(ep(
            Put,
            item,
            name_tag(name),
            "Replace (`secret`: absent=keep, null=clear)",
            Ref(schema),
            Record(schema),
        ));
        v.push(ep(Delete, item, name_tag(name), "Delete", None, Object));
        v.push(ep(
            Get,
            secret,
            name_tag(name),
            "Reveal the secret (audited)",
            None,
            Object,
        ));
    }
    v
}

fn name_tag(name: &str) -> &'static str {
    match name {
        "hosts" => "hosts",
        "groups" => "groups",
        "identities" => "identities",
        "keys" => "keychain",
        "snippets" => "snippets",
        "forwards" => "tunnels",
        "known-hosts" => "known hosts",
        _ => "memories",
    }
}

fn method_name(m: &HttpMethod) -> &'static str {
    match m {
        HttpMethod::Get => "get",
        HttpMethod::Post => "post",
        HttpMethod::Put => "put",
        HttpMethod::Delete => "delete",
        HttpMethod::Patch => "patch",
        HttpMethod::Head => "head",
        HttpMethod::Options => "options",
        HttpMethod::Trace => "trace",
    }
}

fn schema_for(body: Body) -> Option<RefOr<Schema>> {
    let r = |n: &str| RefOr::Ref(Ref::from_schema_name(n));
    match body {
        Body::None | Body::Binary => None,
        Body::Ref(n) => Some(r(n)),
        Body::List(n) => Some(ArrayBuilder::new().items(r(n)).build().into()),
        Body::Record(n) => Some(RefOr::T(Schema::AllOf(
            AllOfBuilder::new().item(r(n)).item(r("RecordMeta")).build(),
        ))),
        Body::RecordList(n) => Some(
            ArrayBuilder::new()
                .items(RefOr::T(Schema::AllOf(
                    AllOfBuilder::new().item(r(n)).item(r("RecordMeta")).build(),
                )))
                .build()
                .into(),
        ),
        Body::Object => Some(
            ObjectBuilder::new()
                .schema_type(Type::Object)
                .build()
                .into(),
        ),
    }
}

/// Builds the OpenAPI document.
pub fn document() -> OpenApi {
    let mut items: BTreeMap<&'static str, PathItemBuilder> = BTreeMap::new();
    for e in endpoints() {
        let mut op = OperationBuilder::new()
            .tag(e.tag)
            .summary(Some(e.summary))
            .operation_id(Some(format!(
                "{}_{}",
                method_name(&e.method),
                e.path
                    .trim_start_matches("/api/v1/")
                    .replace(['/', '-'], "_")
                    .replace(['{', '}'], "")
            )));
        for segment in e.path.split('/') {
            if let Some(name) = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                op = op.parameter(
                    ParameterBuilder::new()
                        .name(name)
                        .parameter_in(ParameterIn::Path)
                        .required(Required::True)
                        .schema(Some(ObjectBuilder::new().schema_type(Type::String).build())),
                );
            }
        }
        for q in e.query {
            op = op.parameter(
                ParameterBuilder::new()
                    .name(*q)
                    .parameter_in(ParameterIn::Query)
                    .required(Required::False)
                    .schema(Some(ObjectBuilder::new().schema_type(Type::String).build())),
            );
        }
        match e.req {
            Body::None => {}
            Body::Binary => {
                op = op.request_body(Some(
                    RequestBodyBuilder::new()
                        .content("application/octet-stream", ContentBuilder::new().build())
                        .build(),
                ))
            }
            other => {
                op = op.request_body(Some(
                    RequestBodyBuilder::new()
                        .content(
                            "application/json",
                            ContentBuilder::new().schema(schema_for(other)).build(),
                        )
                        .required(Some(Required::True))
                        .build(),
                ))
            }
        }
        let ok = match e.resp {
            Body::None => ResponseBuilder::new()
                .description("Switch to WebSocket")
                .build(),
            Body::Binary => ResponseBuilder::new()
                .description("Binary content")
                .content("application/octet-stream", ContentBuilder::new().build())
                .build(),
            other => ResponseBuilder::new()
                .description("OK")
                .content(
                    "application/json",
                    ContentBuilder::new().schema(schema_for(other)).build(),
                )
                .build(),
        };
        op = op
            .response(
                if matches!(e.resp, Body::None) {
                    "101"
                } else {
                    "200"
                },
                ok,
            )
            .response(
                "default",
                ResponseBuilder::new()
                    .description(
                        "Error: {\"error\": {\"code\", \"message\", ...}}. `code` is stable \
                         (clients translate `error.<code>`); `message` is English.",
                    )
                    .build(),
            );
        if e.auth {
            op = op.security(SecurityRequirement::new("bearer", Vec::<String>::new()));
        }
        let entry = items.remove(e.path).unwrap_or_default();
        items.insert(e.path, entry.operation(e.method, op.build()));
    }
    let mut paths = PathsBuilder::new();
    for (path, item) in items {
        paths = paths.path(path, item.build());
    }

    let components = ComponentsBuilder::new()
        .security_scheme(
            "bearer",
            SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer).build()),
        )
        .schema_from::<Host>()
        .schema_from::<Group>()
        .schema_from::<Identity>()
        .schema_from::<SshKey>()
        .schema_from::<Snippet>()
        .schema_from::<PortForward>()
        .schema_from::<KnownHost>()
        .schema_from::<Memory>()
        .schema_from::<HostSettings>()
        .schema_from::<ProxySettings>()
        .schema_from::<ProxyKind>()
        .schema_from::<HostSecret>()
        .schema_from::<IdentitySecret>()
        .schema_from::<SshKeySecret>()
        .schema_from::<RecordMeta>()
        .schema_from::<SyncRecord>()
        .schema_from::<SyncMode>()
        .schema_from::<EntityKind>()
        .schema_from::<ForwardKind>()
        .schema_from::<User>()
        .schema_from::<Team>()
        .schema_from::<TeamMember>()
        .schema_from::<TeamRole>()
        .schema_from::<Invite>()
        .schema_from::<TotpSetup>()
        .schema_from::<TotpCode>()
        .schema_from::<TotpDisable>()
        .schema_from::<CreateInvite>()
        .schema_from::<CreatedInvite>()
        .schema_from::<ResetPassword>()
        .schema_from::<CreateTeam>()
        .schema_from::<AddMember>()
        .schema_from::<SetRole>()
        .schema_from::<TeamInviteRequest>()
        .schema_from::<SetPlan>()
        .schema_from::<crate::account::DeleteAccount>()
        .schema_from::<crate::account::ChangeEmail>()
        .schema_from::<crate::account::TokenRequest>()
        .schema_from::<crate::account::ForgotPassword>()
        .schema_from::<crate::account::ResetWithToken>()
        .schema_from::<crate::config::Plan>()
        .schema_from::<crate::config::PlanLimits>()
        .schema_from::<crate::push::RegisterPush>()
        .schema_from::<Device>()
        .schema_from::<TokenPair>()
        .schema_from::<SessionInfo>()
        .schema_from::<SessionStatus>()
        .schema_from::<SharePermission>()
        .schema_from::<SessionShare>()
        .schema_from::<AuditEntry>()
        .schema_from::<RegisterRequest>()
        .schema_from::<LoginRequest>()
        .schema_from::<AuthResponse>()
        .schema_from::<RefreshRequest>()
        .schema_from::<ChangePassword>()
        .schema_from::<UpdateMe>()
        .schema_from::<CreateUser>()
        .schema_from::<UpdateUser>()
        .schema_from::<GenerateKey>()
        .schema_from::<ImportKey>()
        .schema_from::<HostTest>()
        .schema_from::<SyncRequest>()
        .schema_from::<SyncResponse>()
        .schema_from::<ExecRequest>()
        .schema_from::<ExecResult>()
        .schema_from::<OpenSession>()
        .schema_from::<RenameSession>()
        .schema_from::<CreateShare>()
        .schema_from::<OpenRelay>()
        .schema_from::<SessionList>()
        .schema_from::<MkdirReq>()
        .schema_from::<RenameReq>()
        .schema_from::<DeleteReq>()
        .schema_from::<ChmodReq>()
        .schema_from::<TaskMessage>()
        .schema_from::<SetMode>()
        .schema_from::<Decision>()
        .schema_from::<SuggestReq>()
        .schema_from::<ExplainReq>()
        .schema_from::<SetAiKey>()
        .schema_from::<TestAiKey>()
        .schema_from::<AiKeyView>()
        .schema_from::<AiKeyTestResult>()
        .schema_from::<AiKeyProvider>()
        .schema_from::<AiAccess>()
        .build();

    let tags = [
        ("system", "Server status"),
        ("auth", "Accounts, sign-in and devices"),
        ("hosts", "SSH servers"),
        ("groups", "Host groups with inheritable settings"),
        ("identities", "Reusable user + password/key"),
        ("keychain", "SSH keys"),
        ("snippets", "Reusable scripts with variables"),
        ("tunnels", "Port forwarding rules"),
        ("known hosts", "Known host keys"),
        (
            "memories",
            "What the AI remembers about your infrastructure",
        ),
        ("sync", "Sync between devices"),
        ("sessions", "Persistent and shared terminals"),
        ("sftp", "Files over SFTP through the server"),
        ("ai", "AI engine: tasks, approvals, assistant, MCP"),
        ("events", "Real-time events"),
        ("audit", "Action log"),
        ("admin", "User administration"),
        ("teams", "Teams and sessions shared with teams"),
        (
            "account",
            "Platform: plans, email, password recovery and downloads",
        ),
    ];

    OpenApiBuilder::new()
        .info(
            InfoBuilder::new()
                .title("Termoak API")
                .version(env!("CARGO_PKG_VERSION"))
                .description(Some(
                    "Termoak API for native clients (desktop, iOS, Android). \
                     Authenticate with `Authorization: Bearer <access_token>`. \
                     WebSockets also accept `?access_token=`.",
                ))
                .build(),
        )
        .paths(paths.build())
        .components(Some(components))
        .tags(Some(tags.map(|(n, d)| {
            TagBuilder::new().name(n).description(Some(d)).build()
        })))
        .build()
}

#[cfg(test)]
mod tests {
    #[test]
    fn document_builds_and_references_exist() {
        let doc = super::document();
        let json = serde_json::to_value(&doc).unwrap();
        let schemas = json["components"]["schemas"].as_object().unwrap();
        // Every reference points to a declared schema.
        let text = json.to_string();
        for part in text.split("\"$ref\":\"#/components/schemas/").skip(1) {
            let name = &part[..part.find('"').unwrap()];
            assert!(schemas.contains_key(name), "missing schema {name}");
        }
        assert!(json["paths"]["/api/v1/hosts"]["get"].is_object());
        assert!(json["paths"]["/api/v1/hosts"]["post"].is_object());
        assert!(json["paths"]["/api/v1/me/ai/keys/{provider}"]["put"].is_object());
        assert!(json["paths"]["/api/v1/me/ai/access"]["get"].is_object());
        let register = &schemas["RegisterRequest"]["properties"];
        assert!(register["accept_terms"].is_object());
        assert_eq!(register["terms_version"]["maxLength"], 16);
    }
}
