//! Teams security on the server (0.7 phase 4b, docs-next/TEAMS-SECURITY.md):
//! the team SSH CA (issuing certificates for members and for the server's
//! own connections), access policies (who may reach a host now) and the
//! resolve hook that applies both to every server resolution.
//!
//! Routes live in `routes/security.rs`; the background job (expiring
//! requests, ending windows, retiring CAs) in `routes::security::spawn_job`.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use termoak_core::access::{
    AccessMode, AccessPolicyRecord, AccessRequest, AccessTargetKind, CaPolicy, HostAccess,
    PrincipalContext, VaultPolicy, expand_principals, member_principal,
};
use termoak_core::error::codes;
use termoak_core::model::{Group, Host, User, Vault, VaultKind, VaultRole};
use termoak_core::resolve::{ResolvedHost, ResolvedKey};
use termoak_core::store::security::{CaOwner, NewCert};
use termoak_core::store::{ResolveHook, SecretUse, VaultAccess};
use termoak_core::time::now_ms;
use termoak_core::{CoreError, Id, Store};
use termoak_ssh::ca;
use utoipa::ToSchema;
use zeroize::Zeroizing;

use crate::error::{ApiError, ApiResult};

/// A server-side certificate is reused while it has this much left (ms).
const SERVER_CERT_MARGIN_MS: i64 = 2 * 60_000;
/// The server's ephemeral key per user is renewed after this (ms).
const EPHEMERAL_MAX_AGE_MS: i64 = 30 * 60_000;
/// Clock skew allowed before a certificate starts (s).
const SKEW_SECS: u64 = 5 * 60;

/// What a certificate is for (its record).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertPurpose {
    /// Asked by an app (`POST /certificates`).
    Device,
    /// The server's own connection (sessions, exec, SFTP, AI...).
    Server,
    /// Added to just-in-time credentials.
    Credentials,
}

impl CertPurpose {
    fn as_str(self) -> &'static str {
        match self {
            CertPurpose::Device => "device",
            CertPurpose::Server => "server",
            CertPurpose::Credentials => "credentials",
        }
    }
}

/// `POST /api/v1/certificates` answer.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IssuedCert {
    /// OpenSSH certificate line.
    pub certificate: String,
    pub serial: i64,
    pub key_id: String,
    pub principals: Vec<String>,
    /// Milliseconds since the epoch.
    pub valid_after: i64,
    pub valid_before: i64,
    pub ca_fingerprint: String,
    pub request_id: Option<uuid::Uuid>,
    pub extensions: Vec<String>,
    /// Sessions on this host must be recorded (apps record and upload).
    pub record_required: bool,
}

/// Whether someone may reach a host now, and why.
#[derive(Debug, Clone, Default)]
pub struct Gate {
    /// The effective policy (`None`: direct, no policy).
    pub policy: Option<AccessPolicyRecord>,
    /// Allowed without a request.
    pub exempt: bool,
    /// The active window that allows it.
    pub grant: Option<AccessRequest>,
    /// The host's groups, nearest first.
    pub groups: Vec<Id>,
}

impl Gate {
    pub fn allowed(&self) -> bool {
        self.exempt || self.grant.is_some()
    }

    pub fn mode(&self) -> AccessMode {
        self.policy
            .as_ref()
            .map_or(AccessMode::Direct, |p| p.policy.mode)
    }

    /// `access_approval_required` with what the apps need to ask.
    pub fn error(&self, host: &Host) -> CoreError {
        let p = self.policy.as_ref();
        CoreError::vault_detail(
            codes::ACCESS_APPROVAL_REQUIRED,
            format!(
                "\"{}\" needs an approved access window: request access",
                host.label
            ),
            json!({
                "host_id": host.id,
                "policy_id": p.map(|p| p.id),
                "target_kind": p.map(|p| p.target_kind),
                "target_id": p.map(|p| p.target_id),
                "max_minutes": p.map(|p| p.policy.max_minutes),
            }),
        )
    }
}

/// Teams security service.
pub struct Security {
    store: Store,
    instance_id: String,
    ephemeral: Mutex<HashMap<Id, (Zeroizing<String>, termoak_ssh::PublicKey, i64)>>,
    /// `(user, host, key fingerprint)` → `(certificate, valid_before ms)`.
    certs: Mutex<HashMap<(Id, Id, String), (String, i64)>>,
}

/// Does a request's target cover this host?
pub fn covers(req: &AccessRequest, vault: Id, host: Id, groups: &[Id]) -> bool {
    req.vault_id == vault
        && match req.target_kind {
            AccessTargetKind::Host => req.target_id == host,
            AccessTargetKind::Group => groups.contains(&req.target_id),
            AccessTargetKind::Vault => req.target_id == vault,
            AccessTargetKind::Unknown => false,
        }
}

impl Security {
    pub fn new(store: Store, instance_id: String) -> Arc<Self> {
        Arc::new(Self {
            store,
            instance_id,
            ephemeral: Mutex::new(HashMap::new()),
            certs: Mutex::new(HashMap::new()),
        })
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Forgets every cached certificate (a policy changed).
    pub fn forget_all(&self) {
        self.certs.lock().clear();
    }

    /// Forgets the cached certificates of a user (access changed).
    pub fn forget_user(&self, user: Id) {
        self.certs.lock().retain(|(u, _, _), _| *u != user);
    }

    /// The CA owner of a vault: its team, or its owner user.
    pub fn owner_of(vault: &Vault) -> Option<CaOwner> {
        match (vault.owner_team_id, vault.owner_user_id) {
            (Some(t), _) => Some(CaOwner::Team(t)),
            (None, Some(u)) => Some(CaOwner::User(u)),
            _ => None,
        }
    }

    /// Certificate defaults of a CA owner (a team's policy; defaults for a
    /// user).
    pub async fn ca_policy(&self, owner: CaOwner) -> ApiResult<CaPolicy> {
        Ok(match owner {
            CaOwner::Team(t) => self.store.team_policy(t).await?.ca,
            CaOwner::User(_) => CaPolicy::default(),
        })
    }

    /// The groups of a host, nearest first (same vault).
    pub async fn host_groups(&self, access: &VaultAccess, host: &Host) -> Vec<Id> {
        let mut out = Vec::new();
        let mut next = host.group_id;
        while let Some(g) = next {
            if out.contains(&g) || out.len() >= 16 {
                break;
            }
            out.push(g);
            next = match self.store.get_in::<Group>(access, g).await {
                Ok(r) => r.data.parent_id,
                Err(_) => None,
            };
        }
        out
    }

    /// Whether `user` approves requests under `policy` in `vault`.
    pub async fn is_approver(&self, user: Id, vault: Id, policy: &AccessPolicyRecord) -> bool {
        let role = self.store.effective_role(vault, user).await.ok().flatten();
        if policy.policy.approvers.is_empty() {
            role == Some(VaultRole::Manager)
        } else {
            role.is_some() && policy.policy.approvers.contains(&user)
        }
    }

    /// Everyone who may approve under `policy`.
    pub async fn approvers(&self, vault: Id, policy: &AccessPolicyRecord) -> Vec<Id> {
        let candidates = if policy.policy.approvers.is_empty() {
            self.store.vault_user_ids(vault).await.unwrap_or_default()
        } else {
            policy.policy.approvers.clone()
        };
        let mut out = Vec::new();
        for u in candidates {
            if !out.contains(&u) && self.is_approver(u, vault, policy).await {
                out.push(u);
            }
        }
        out
    }

    /// The policy that applies to a host: its own, its nearest group's, or
    /// the vault's.
    pub async fn effective_policy(
        &self,
        vault: Id,
        host: Id,
        groups: &[Id],
    ) -> ApiResult<Option<AccessPolicyRecord>> {
        let all = self.store.access_policies(vault).await?;
        if all.is_empty() {
            return Ok(None);
        }
        let find = |kind: AccessTargetKind, id: Id| {
            all.iter()
                .find(|p| p.target_kind == kind && p.target_id == id)
                .cloned()
        };
        if let Some(p) = find(AccessTargetKind::Host, host) {
            return Ok(Some(p));
        }
        for g in groups {
            if let Some(p) = find(AccessTargetKind::Group, *g) {
                return Ok(Some(p));
            }
        }
        Ok(find(AccessTargetKind::Vault, vault))
    }

    /// Whether `access.user` may reach `host` (in `vault`) now.
    pub async fn gate(&self, access: &VaultAccess, vault: Id, host: &Host) -> ApiResult<Gate> {
        let groups = self.host_groups(access, host).await;
        let policy = self.effective_policy(vault, host.id, &groups).await?;
        let mut gate = Gate {
            policy,
            groups,
            ..Default::default()
        };
        let Some(p) = &gate.policy else {
            gate.exempt = true;
            return Ok(gate);
        };
        if !p.policy.mode.requires_approval() {
            gate.exempt = true;
            return Ok(gate);
        }
        if access.role(vault) == Some(VaultRole::Manager) && !p.policy.require_for_managers {
            gate.exempt = true;
            return Ok(gate);
        }
        gate.grant = self
            .store
            .active_grants(access.user, vault)
            .await?
            .into_iter()
            .find(|r| covers(r, vault, host.id, &gate.groups));
        Ok(gate)
    }

    /// Sessions on this host must be recorded (team or access policy).
    pub async fn record_required(&self, access: &VaultAccess, vault: Id, host: &Host) -> bool {
        if access.must_record(vault) {
            return true;
        }
        match self.gate(access, vault, host).await {
            Ok(g) => g.policy.is_some_and(|p| p.policy.record_sessions),
            Err(_) => false,
        }
    }

    /// The member principal of a user for a CA owner.
    async fn member_of(&self, owner: CaOwner, user: &User) -> String {
        if let CaOwner::Team(t) = owner
            && let Ok(Some(p)) = self.store.team_member_principal(t, user.id).await
        {
            return p;
        }
        member_principal(&user.email)
    }

    /// Signs a certificate for `subject` to reach `host` (checks done by the
    /// caller: access, ownership, gate).
    #[allow(clippy::too_many_arguments)]
    pub async fn issue(
        &self,
        user: &User,
        access: &VaultAccess,
        vault: Id,
        host: &Host,
        login: Option<String>,
        subject: &termoak_ssh::PublicKey,
        gate: &Gate,
        purpose: CertPurpose,
        device: Option<Id>,
        ttl_minutes: Option<u32>,
    ) -> ApiResult<IssuedCert> {
        let v = self.store.vault(vault).await?;
        let owner = Self::owner_of(&v).ok_or_else(ca_missing)?;
        let (ca_info, ca_key) = self.store.active_ca(owner).await?.ok_or_else(ca_missing)?;
        let fp = ca::fingerprint(subject);
        if self.store.is_key_revoked(owner, &fp).await? {
            return Err(
                ApiError::forbidden("this key was revoked by the certificate authority")
                    .with_code("certificate_key_revoked"),
            );
        }
        if self.store.ca_fingerprints().await?.contains(&fp) {
            return Err(ApiError::bad_request("a CA key cannot get a certificate")
                .with_code(codes::CERTIFICATE_KEY_NOT_OWNED));
        }
        let ca_policy = self.ca_policy(owner).await?;
        let policy = gate.policy.as_ref().map(|p| p.policy.clone());
        let templates = policy
            .as_ref()
            .and_then(|p| p.principals.clone())
            .unwrap_or_else(|| ca_policy.principals.clone());
        let principals = expand_principals(
            &templates,
            &PrincipalContext {
                login: login.filter(|l| !l.is_empty()),
                member: self.member_of(owner, user).await,
                email: user.email.clone(),
                user_id: user.id,
            },
        );
        if principals.is_empty() {
            return Err(ApiError::bad_request(
                "no valid principal for this certificate (does the host have a username?)",
            )
            .with_code(codes::CERTIFICATE_NO_PRINCIPALS));
        }
        let cap = ca_policy.max_ttl_minutes.min(
            policy
                .as_ref()
                .and_then(|p| p.cert_ttl_minutes)
                .unwrap_or(u32::MAX),
        );
        let ttl = ttl_minutes
            .unwrap_or(ca_policy.default_ttl_minutes)
            .clamp(1, cap.max(1));
        let now = now_ms();
        let mut valid_before = now + i64::from(ttl) * 60_000;
        if let Some(g) = &gate.grant
            && let Some(end) = g.ends_at
        {
            valid_before = valid_before.min(end);
        }
        let valid_after = now - (SKEW_SECS as i64) * 1000;
        let extensions = policy
            .as_ref()
            .and_then(|p| p.extensions.clone())
            .unwrap_or_else(|| ca_policy.extensions.clone());
        let source_address = policy
            .as_ref()
            .and_then(|p| p.source_address.clone())
            .or_else(|| ca_policy.source_address.clone());
        let force_command = policy.as_ref().and_then(|p| p.force_command.clone());
        let request_id = gate.grant.as_ref().map(|g| g.id);
        let serial = self
            .store
            .reserve_certificate(NewCert {
                ca_id: ca_info.id,
                user_id: user.id,
                vault_id: Some(vault),
                host_id: Some(host.id),
                request_id,
                device_id: device,
                purpose: purpose.as_str().into(),
                key_fingerprint: fp.clone(),
                principals: principals.clone(),
                valid_after,
                valid_before,
            })
            .await?;
        let key_id = format!(
            "termoak:{}:{}:{}:{serial}",
            user.email,
            user.id,
            request_id.map_or("direct".to_string(), |r| r.to_string())
        );
        let signed = ca::sign_user_certificate(
            &ca_key,
            subject,
            &ca::UserCertificate {
                serial: serial as u64,
                key_id: key_id.clone(),
                principals: principals.clone(),
                valid_after: (valid_after / 1000) as u64,
                valid_before: (valid_before / 1000) as u64,
                extensions: extensions.clone(),
                source_address: source_address.clone(),
                force_command: force_command.clone(),
            },
        );
        let certificate = match signed {
            Ok(c) => c,
            Err(e) => {
                let _ = self.store.drop_certificate(serial).await;
                return Err(ApiError::internal(format!(
                    "could not sign the certificate: {e}"
                )));
            }
        };
        self.store.finish_certificate(serial, &key_id).await?;
        self.store
            .audit_vault(
                user.id,
                &format!("user:{}", user.id),
                "cert.issue",
                Some(format!("host:{}", host.id)),
                json!({
                    "serial": serial,
                    "key_fingerprint": fp,
                    "principals": principals,
                    "valid_before": valid_before,
                    "request_id": request_id,
                    "purpose": purpose.as_str(),
                    "device": device,
                    "ca": ca_info.fingerprint,
                }),
                vault,
            )
            .await?;
        let record_required = access.must_record(vault)
            || gate
                .policy
                .as_ref()
                .is_some_and(|p| p.policy.record_sessions);
        Ok(IssuedCert {
            certificate,
            serial,
            key_id,
            principals,
            valid_after,
            valid_before,
            ca_fingerprint: ca_info.fingerprint,
            request_id,
            extensions,
            record_required,
        })
    }

    /// The server's ephemeral key for a user (memory only).
    fn ephemeral(&self, user: Id) -> ApiResult<(Zeroizing<String>, termoak_ssh::PublicKey)> {
        let mut map = self.ephemeral.lock();
        if let Some((k, p, at)) = map.get(&user)
            && now_ms() - at < EPHEMERAL_MAX_AGE_MS
        {
            return Ok((k.clone(), p.clone()));
        }
        let (k, p) = ca::ephemeral_key("termoak-server").map_err(ApiError::from)?;
        let p = ca::parse_public_key(&p).map_err(ApiError::from)?;
        map.insert(user, (k.clone(), p.clone(), now_ms()));
        Ok((k, p))
    }

    /// A certificate for one hop of a server resolution (`auth =
    /// team_certificate`): for its key, or for the user's ephemeral key
    /// (server use only), cached until shortly before it expires.
    async fn certify_hop(
        &self,
        access: &VaultAccess,
        vault: Id,
        purpose: CertPurpose,
        hop: &mut ResolvedHost,
        gate: &Gate,
    ) -> ApiResult<()> {
        let v = self.store.vault(vault).await?;
        let Some(owner) = Self::owner_of(&v) else {
            return Ok(());
        };
        if self.store.active_ca(owner).await?.is_none() {
            // No CA: the host's own credentials, as always.
            return Ok(());
        }
        let user = self.store.user(access.user).await?;
        let own = hop
            .key
            .as_ref()
            .and_then(|k| ca::public_key_of_private(&k.private_key).ok());
        let (subject, ephemeral) = match own {
            Some(p) => (p, None),
            None if purpose == CertPurpose::Server => {
                let (k, p) = self.ephemeral(user.id)?;
                (p, Some(k))
            }
            None => return Ok(()),
        };
        let fp = ca::fingerprint(&subject);
        let key = (user.id, hop.host.id, fp);
        let cached = self
            .certs
            .lock()
            .get(&key)
            .filter(|(_, until)| *until - now_ms() > SERVER_CERT_MARGIN_MS)
            .map(|(c, _)| c.clone());
        let cert = match cached {
            Some(c) => c,
            None => {
                let issued = self
                    .issue(
                        &user,
                        access,
                        vault,
                        &hop.host,
                        Some(hop.username.clone()),
                        &subject,
                        gate,
                        purpose,
                        None,
                        None,
                    )
                    .await?;
                self.certs
                    .lock()
                    .insert(key, (issued.certificate.clone(), issued.valid_before));
                issued.certificate
            }
        };
        match ephemeral {
            Some(private) => {
                hop.key = Some(ResolvedKey {
                    id: Id::nil(),
                    label: "team certificate".into(),
                    private_key: private.to_string(),
                    passphrase: None,
                    certificate: Some(cert),
                    security_key: None,
                });
            }
            None => {
                if let Some(k) = hop.key.as_mut() {
                    k.certificate = Some(cert);
                }
            }
        }
        Ok(())
    }

    /// What a user can do with a host (`GET /hosts/{id}/access`).
    pub async fn host_access(&self, access: &VaultAccess, host_id: Id) -> ApiResult<HostAccess> {
        let rec = self.store.get_in::<Host>(access, host_id).await?;
        let vault = rec.meta.vault_id.unwrap_or(access.user);
        let host = rec.data;
        let settings = self
            .store
            .effective_settings_in(access, vault, &host)
            .await?;
        let gate = self.gate(access, vault, &host).await?;
        let pending = self
            .store
            .pending_requests(access.user, vault)
            .await?
            .into_iter()
            .find(|r| covers(r, vault, host.id, &gate.groups));
        let v = self.store.vault(vault).await?;
        let certificates = match Self::owner_of(&v) {
            Some(o) => self.store.active_ca(o).await?.is_some(),
            None => false,
        };
        let allowed = gate.allowed();
        let mode = gate.mode();
        Ok(HostAccess {
            host_id: host.id,
            vault_id: vault,
            mode,
            exempt: gate.exempt,
            can_request: mode.requires_approval() && !allowed && pending.is_none(),
            allowed,
            max_minutes: gate.policy.as_ref().map_or(0, |p| p.policy.max_minutes),
            record_required: access.must_record(vault)
                || gate
                    .policy
                    .as_ref()
                    .is_some_and(|p| p.policy.record_sessions),
            policy: gate.policy,
            grant: gate.grant,
            pending,
            certificates,
            team_certificate: settings
                .auth
                .as_ref()
                .is_some_and(|a| a.is_team_certificate()),
            ai_allowed: access.ai_allowed(vault),
            reveal_allowed: !access.no_reveal.contains(&vault),
        })
    }

    /// The effective policies of vaults for one user (`Vault.policy`).
    pub async fn vault_policies(
        &self,
        access: &VaultAccess,
        vaults: &[Vault],
    ) -> ApiResult<HashMap<Id, VaultPolicy>> {
        let with_policies = self
            .store
            .vaults_with_access_policies(vaults.iter().map(|v| v.id).collect())
            .await?;
        let mut ca_of: HashMap<Id, bool> = HashMap::new();
        let mut team_policies = HashMap::new();
        let mut out = HashMap::new();
        for v in vaults {
            let certificates = match Self::owner_of(v) {
                Some(o) => match ca_of.get(&o.id()) {
                    Some(b) => *b,
                    None => {
                        let b = self.store.active_ca(o).await?.is_some();
                        ca_of.insert(o.id(), b);
                        b
                    }
                },
                None => false,
            };
            let access_policies = with_policies.contains(&v.id);
            let mut p = VaultPolicy {
                access_policies,
                certificates,
                reveal_allowed: !access.no_reveal.contains(&v.id),
                ai_allowed: access.ai_allowed(v.id),
                networks_allowed: access.networks_allowed(v.id),
                record_sessions: access.must_record(v.id),
                ..Default::default()
            };
            if v.kind == VaultKind::Team
                && let Some(t) = v.owner_team_id
            {
                if !team_policies.contains_key(&t) {
                    team_policies.insert(t, self.store.team_policy(t).await.unwrap_or_default());
                }
                let tp = &team_policies[&t];
                p.team_id = Some(t);
                p.require_2fa = tp.require_2fa;
                p.ai_approval = tp.ai.approval;
            } else if !access_policies && !certificates {
                continue;
            }
            out.insert(v.id, p);
        }
        Ok(out)
    }

    /// Vaults as this client should see them: roles it understands and,
    /// for clients with `policies`, the effective policy.
    pub async fn present_vaults(
        &self,
        access: &VaultAccess,
        features: crate::auth::ClientFeatures,
        mut vaults: Vec<Vault>,
    ) -> ApiResult<Vec<Vault>> {
        let policies = if features.policies {
            self.vault_policies(access, &vaults).await?
        } else {
            HashMap::new()
        };
        for v in &mut vaults {
            v.role = v.role.map(|r| features.role(r));
            v.team_member_role = v.team_member_role.map(|r| features.role(r));
            v.policy = policies.get(&v.id).cloned();
        }
        Ok(vaults)
    }

    /// Creates a CA key for an owner (the store seals it).
    pub fn new_ca_key(
        alg: ca::CaAlgorithm,
        label: &str,
        by: Id,
    ) -> ApiResult<termoak_core::store::security::NewCa> {
        let comment = format!(
            "termoak-ca {} {}",
            label
                .chars()
                .filter(|c| !c.is_whitespace())
                .take(40)
                .collect::<String>(),
            chrono::Utc::now().format("%Y-%m-%d")
        );
        let k = ca::generate_ca(alg, &comment).map_err(ApiError::from)?;
        Ok(termoak_core::store::security::NewCa {
            algorithm: k.algorithm,
            public_key: k.public_key,
            fingerprint: k.fingerprint,
            private_key: k.private_key,
            created_by: by,
        })
    }

    /// The KRL of an owner (revoked serials of its published CAs and
    /// revoked keys).
    pub async fn krl(&self, owner: CaOwner) -> ApiResult<Vec<u8>> {
        let mut cas = Vec::new();
        for c in self.store.ca_history(owner).await? {
            let serials = self.store.revoked_serials(c.id).await?;
            if !serials.is_empty() {
                cas.push(ca::KrlCa {
                    ca_public_key: c.public_key,
                    serials,
                });
            }
        }
        let keys = self.store.revoked_keys(owner).await?;
        ca::build_krl(&cas, &keys, ca::unix_now(), "termoak").map_err(ApiError::from)
    }
}

fn ca_missing() -> ApiError {
    ApiError::not_found("there is no certificate authority for this vault")
        .with_code(codes::CA_NOT_CONFIGURED)
}

fn to_core(e: ApiError) -> CoreError {
    match e.code {
        codes::ACCESS_APPROVAL_REQUIRED
        | codes::CA_NOT_CONFIGURED
        | codes::CERTIFICATE_NO_PRINCIPALS
        | codes::CERTIFICATE_KEY_NOT_OWNED
        | codes::TEAM_2FA_REQUIRED => CoreError::vault(e.code, e.message),
        "not_found" => CoreError::NotFound(e.message),
        _ => CoreError::Vault {
            code: "certificate_failed",
            message: e.message,
            detail: None,
        },
    }
}

impl ResolveHook for Security {
    fn after_resolve<'a>(
        &'a self,
        access: &'a VaultAccess,
        vault: Id,
        purpose: SecretUse,
        resolved: &'a mut ResolvedHost,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = termoak_core::Result<()>> + Send + 'a>>
    {
        Box::pin(async move {
            let cert_purpose = match purpose {
                SecretUse::Server => CertPurpose::Server,
                SecretUse::Credentials => CertPurpose::Credentials,
                SecretUse::Reveal => return Ok(()),
            };
            // Every hop: the jumps, then the host.
            for i in 0..=resolved.jumps.len() {
                let hop: &mut ResolvedHost = if i < resolved.jumps.len() {
                    &mut resolved.jumps[i]
                } else {
                    &mut *resolved
                };
                let gate = match self.gate(access, vault, &hop.host).await {
                    Ok(g) => g,
                    Err(e) => return Err(to_core(e)),
                };
                if !gate.allowed() {
                    return Err(gate.error(&hop.host));
                }
                if hop
                    .settings
                    .auth
                    .as_ref()
                    .is_some_and(|a| a.is_team_certificate())
                    && let Err(e) = self
                        .certify_hop(access, vault, cert_purpose, hop, &gate)
                        .await
                {
                    return Err(to_core(e));
                }
            }
            Ok(())
        })
    }
}
