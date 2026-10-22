//! Private networks (0.7): the server relay for the apps, the state of a
//! network in `termoak-netd`, and the `max_networks` plan limit.
//!
//! Relay (`GET /api/v1/hosts/{id}/relay`, WebSocket): the server dials the
//! first hop of the host (its first jump host, or the host) through the
//! host's network with netd and pipes the bytes both ways as binary frames.
//! SSH runs inside it from the app, end to end. It is by host id, not by
//! address: the server decides where to dial (the host as its vault
//! defines it), so nobody reaches arbitrary addresses of a network, and a
//! Use-only member only reaches the hosts an Editor put in it. The server
//! never dials directly: without netd it answers `network_unavailable`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Json;
use axum::Router;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};
use futures::{SinkExt, StreamExt};
use parking_lot::Mutex;
use serde_json::{Value, json};
use termoak_core::Id;
use termoak_core::model::{
    EntityKind, Host, Network, NetworkKind, NetworkSecret, SecretUpdate, SyncRecord, VaultRole,
};
use termoak_core::resolve::ResolvedNetwork;
use termoak_core::store::{SecretUse, SyncRejection, VaultAccess};
use termoak_core::time::now_ms;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::devices::{SocketGuard, SocketKind};
use crate::error::{ApiError, ApiResult};
use crate::netd::{NetworkPeer, NetworkSpec, NetworkStatus, not_configured};
use crate::state::AppState;
use crate::vaults::AccessCtx;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/hosts/{id}/relay", get(relay))
        .route("/api/v1/networks/{id}/status", get(status))
        .route("/api/v1/networks/{id}/up", post(up))
        .route("/api/v1/networks/{id}/down", post(down))
        .route("/api/v1/networks/{id}/peers", get(peers))
        .route("/api/v1/networks/{id}/wireguard/key", post(generate_key))
}

// --- WireGuard keys ------------------------------------------------------------

/// The WireGuard public key of a base64 private key (`None` if it is not
/// a 32-byte key).
pub fn wireguard_public_key(private_key: &str) -> Option<String> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let raw = b64.decode(private_key.trim()).ok()?;
    let bytes: [u8; 32] = raw.as_slice().try_into().ok()?;
    let public = curve25519_dalek::MontgomeryPoint::mul_base_clamped(bytes);
    Some(b64.encode(public.to_bytes()))
}

/// A new WireGuard private key (base64).
fn new_wireguard_key() -> ApiResult<String> {
    use base64::Engine as _;
    use ring::rand::SecureRandom;
    let mut k = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut k)
        .map_err(|_| ApiError::internal("no randomness"))?;
    k[0] &= 248;
    k[31] = (k[31] & 127) | 64;
    Ok(base64::engine::general_purpose::STANDARD.encode(k))
}

/// Keeps `wireguard.public_key` of a WireGuard network equal to the public
/// key of its private key (what the other side adds as a peer). Without a
/// private key there is no public key; an unreadable one leaves it as is.
/// Returns whether it changed.
pub fn fill_public_key(net: &mut Network, secret: Option<&NetworkSecret>) -> bool {
    if net.kind != NetworkKind::Wireguard {
        return false;
    }
    let private = secret.and_then(|s| s.private_key.as_deref());
    let derived = match private {
        Some(k) => match wireguard_public_key(k) {
            Some(p) => Some(p),
            None => return false,
        },
        None => None,
    };
    let current = net.wireguard.as_ref().and_then(|w| w.public_key.clone());
    if current == derived {
        return false;
    }
    net.wireguard
        .get_or_insert_with(Default::default)
        .public_key = derived;
    true
}

/// `POST /networks/{id}/wireguard/key` body.
#[derive(Debug, Default, serde::Deserialize, utoipa::ToSchema)]
pub struct GenerateWireguardKey {
    /// Replace the private key the network already has (the other side
    /// must then be given the new public key).
    #[serde(default)]
    pub replace: bool,
}

/// Answer of `POST /networks/{id}/wireguard/key`.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct GeneratedWireguardKey {
    /// Add it as a peer on the other side of the tunnel.
    pub public_key: String,
    #[schema(value_type = Object)]
    pub network: termoak_core::model::Record<Network>,
}

/// Generates the server's WireGuard private key for a network (Editor):
/// stored as the network's secret (it never leaves the server), the public
/// key is returned and kept in `wireguard.public_key`. A network that
/// already has a private key needs `replace: true` (409 `key_exists`).
async fn generate_key(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
    body: Option<Json<GenerateWireguardKey>>,
) -> ApiResult<Json<GeneratedWireguardKey>> {
    let replace = body.map(|b| b.0.replace).unwrap_or(false);
    let rec = st.store.get_in::<Network>(&ctx.access, id).await?;
    let vault = rec.meta.vault_id.unwrap_or(ctx.personal());
    ctx.access.require(vault, VaultRole::Editor)?;
    if rec.data.kind != NetworkKind::Wireguard {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "not_wireguard",
            "only WireGuard networks have a key pair",
        ));
    }
    let mut secret = st
        .store
        .secret_in::<Network>(&ctx.access, id, SecretUse::Server)
        .await?;
    if secret
        .private_key
        .as_deref()
        .is_some_and(|k| !k.trim().is_empty())
        && !replace
    {
        secret.zeroize();
        return Err(ApiError::conflict(
            "the network already has a private key: generate a new one with replace = true",
        )
        .with_code("key_exists"));
    }
    secret.private_key = Some(new_wireguard_key()?);
    let mut net = rec.data;
    fill_public_key(&mut net, Some(&secret));
    let public_key = net
        .wireguard
        .as_ref()
        .and_then(|w| w.public_key.clone())
        .ok_or_else(|| ApiError::internal("no public key"))?;
    let saved = st
        .store
        .save_in(&ctx.access, vault, net, SecretUpdate::Set(secret), None)
        .await?;
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "network.key_generated",
            Some(format!("network:{id}")),
            json!({"name": saved.data.name, "public_key": public_key, "replaced": replace}),
            vault,
        )
        .await?;
    reconcile_later(&st, &ctx.access, vec![id]);
    Ok(Json(GeneratedWireguardKey {
        public_key,
        network: saved,
    }))
}

// --- Keeping netd in step with the vaults ------------------------------------

/// After networks changed (saved, pushed, deleted): fixes the WireGuard
/// public key of pushed ones (apps send the private key only) and tells
/// netd `down` for the networks that no longer exist or whose revision
/// differs from the running one (so an old key or config stops at once).
/// Runs in the background; errors are logged.
pub fn reconcile_later(st: &AppState, access: &Arc<VaultAccess>, ids: Vec<Id>) {
    if ids.is_empty() || st.netd.is_none() {
        return;
    }
    let (st, access) = (st.clone(), access.clone());
    tokio::spawn(async move {
        reconcile(&st, &access, &ids).await;
    });
}

/// See [`reconcile_later`].
pub async fn reconcile(st: &AppState, access: &VaultAccess, ids: &[Id]) {
    let Some(netd) = st.netd.clone() else { return };
    for id in ids {
        let expected = match st.store.get_in::<Network>(access, *id).await {
            Ok(rec) => {
                let vault = rec.meta.vault_id;
                match st
                    .store
                    .secret_in::<Network>(access, *id, SecretUse::Server)
                    .await
                {
                    Ok(secret) => {
                        let mut net = ResolvedNetwork {
                            network: rec.data,
                            secret,
                        };
                        let rev = NetworkSpec::new(&net, vault).revision;
                        net.secret.zeroize();
                        Some(rev)
                    }
                    Err(_) => continue,
                }
            }
            Err(termoak_core::CoreError::NotFound(_)) => None,
            Err(_) => continue,
        };
        // Deleted: netd forgets it, running or not (a persistent Tailscale
        // node keeps state while it is down).
        if expected.is_none() {
            match netd.forget(*id).await {
                Ok(()) => {
                    tracing::info!(network = %id, "deleted network forgotten in termoak-netd")
                }
                Err(e) => {
                    tracing::warn!(network = %id, error = %e, "could not take a network down")
                }
            }
            continue;
        }
        let status = match netd.status(*id).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(network = %id, error = %e, "netd status failed");
                continue;
            }
        };
        if !status.is_running() || status.revision == expected {
            continue;
        }
        let why = "changed";
        match netd.down(*id).await {
            Ok(()) => tracing::info!(network = %id, why, "network taken down in termoak-netd"),
            Err(e) => tracing::warn!(network = %id, error = %e, "could not take a network down"),
        }
    }
}

/// Fixes `wireguard.public_key` of networks pushed by a sync (their
/// private key may have changed), saving those that differ.
pub async fn fix_pushed_keys(st: &AppState, access: &VaultAccess, ids: &[Id]) {
    for id in ids {
        let Ok(rec) = st.store.get_in::<Network>(access, *id).await else {
            continue;
        };
        let Ok(mut secret) = st
            .store
            .secret_in::<Network>(access, *id, SecretUse::Server)
            .await
        else {
            continue;
        };
        let vault = rec.meta.vault_id.unwrap_or(access.personal());
        let mut net = rec.data;
        if fill_public_key(&mut net, Some(&secret))
            && let Err(e) = st
                .store
                .save_in(access, vault, net, SecretUpdate::Keep, None)
                .await
        {
            tracing::warn!(network = %id, error = %e, "could not save the network's public key");
        }
        secret.zeroize();
    }
}

/// The networks of some vaults (before deleting them: netd is told `down`
/// afterwards with [`down_later`]).
pub async fn networks_in(st: &AppState, access: &VaultAccess, vaults: &[Id]) -> Vec<Id> {
    if st.netd.is_none() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for v in vaults {
        if let Ok(list) = st.store.list_in::<Network>(access, Some(*v)).await {
            out.extend(list.into_iter().map(|r| r.data.id));
        }
    }
    out
}

/// Tells netd that these networks were deleted (in the background):
/// `down` with `forget`, so it also removes what it keeps of them (a
/// persistent Tailscale node logs out), whether they run or not.
pub fn down_later(st: &AppState, ids: Vec<Id>) {
    let Some(netd) = st.netd.clone() else { return };
    if ids.is_empty() {
        return;
    }
    tokio::spawn(async move {
        for id in ids {
            if let Err(e) = netd.forget(id).await {
                tracing::warn!(network = %id, error = %e, "could not take a network down");
            }
        }
    });
}

// --- Plan limit ----------------------------------------------------------------

/// `plan_limit` (`max_networks`) if `adding` more networks billed to the
/// owner of `vault` (see `Store::vault_billing_user`) would go over their
/// plan. Administrators have no limit.
pub async fn check_new_networks(st: &AppState, vault: Id, adding: i64) -> ApiResult<()> {
    if adding <= 0 {
        return Ok(());
    }
    let Some((max, current)) = network_room(st, vault).await? else {
        return Ok(());
    };
    if current + adding > i64::from(max) {
        return Err(crate::account::limit_error(
            "max_networks",
            "private networks",
            max,
        ));
    }
    Ok(())
}

/// `(max_networks, networks billed now)` of the owner of `vault`; `None`:
/// no limit.
async fn network_room(st: &AppState, vault: Id) -> ApiResult<Option<(u32, i64)>> {
    let Some(billed) = st.store.vault_billing_user(vault).await? else {
        return Ok(None);
    };
    let user = st.store.user(billed).await?;
    let Some(max) = crate::account::limits_for(st, &user).and_then(|l| l.max_networks) else {
        return Ok(None);
    };
    Ok(Some((max, st.store.networks_billed_to(billed).await?)))
}

/// Takes out of `changes` the new networks that would go over their
/// owner's plan, and returns their rejections (`plan_limit`). Networks that
/// already exist, deletions and other kinds pass.
pub async fn limit_network_pushes(
    st: &AppState,
    access: &VaultAccess,
    changes: &mut Vec<SyncRecord>,
) -> ApiResult<Vec<SyncRejection>> {
    let mut room: HashMap<Id, Option<(u32, i64)>> = HashMap::new();
    let mut rejected = Vec::new();
    let mut keep = Vec::with_capacity(changes.len());
    for rec in std::mem::take(changes) {
        if rec.kind != EntityKind::Network || rec.deleted {
            keep.push(rec);
            continue;
        }
        if st.store.locate_in(access, rec.id).await.is_ok() {
            keep.push(rec);
            continue;
        }
        let vault = rec.vault_id.unwrap_or(access.personal());
        let billed = st.store.vault_billing_user(vault).await?.unwrap_or(vault);
        if let std::collections::hash_map::Entry::Vacant(e) = room.entry(billed) {
            e.insert(network_room(st, vault).await?);
        }
        match room.get_mut(&billed).expect("inserted") {
            Some((max, current)) if *current >= i64::from(*max) => {
                rejected.push(SyncRejection {
                    id: rec.id,
                    code: "plan_limit".into(),
                    message: format!("your plan allows at most {max} private networks"),
                });
            }
            Some((_, current)) => {
                *current += 1;
                keep.push(rec);
            }
            None => keep.push(rec),
        }
    }
    *changes = keep;
    Ok(rejected)
}

// --- netd state ------------------------------------------------------------------

fn netd(st: &AppState) -> ApiResult<Arc<crate::netd::Netd>> {
    st.netd.clone().ok_or_else(not_configured)
}

/// A network with its secret (server use only), checking `min` in its vault.
async fn network_for(
    st: &AppState,
    ctx: &AccessCtx,
    id: Id,
    min: VaultRole,
) -> ApiResult<(ResolvedNetwork, Id)> {
    let rec = st.store.get_in::<Network>(&ctx.access, id).await?;
    let vault = rec.meta.vault_id.unwrap_or(ctx.personal());
    ctx.access.require(vault, min)?;
    let secret = st
        .store
        .secret_in::<Network>(&ctx.access, id, SecretUse::Server)
        .await?;
    Ok((
        ResolvedNetwork {
            network: rec.data,
            secret,
        },
        vault,
    ))
}

/// State of a network in netd (any member of its vault). The login URL of
/// a Tailscale node (`node.auth_url`) is for Editors only: whoever opens it
/// decides which tailnet the server's node joins.
async fn status(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
) -> ApiResult<Json<NetworkStatus>> {
    let netd = netd(&st)?;
    let rec = st.store.get_in::<Network>(&ctx.access, id).await?;
    let vault = rec.meta.vault_id.unwrap_or(ctx.personal());
    let mut status = netd.status(id).await?;
    if ctx.access.require(vault, VaultRole::Editor).is_err()
        && let Some(node) = status.node.as_mut()
    {
        node.auth_url = None;
    }
    Ok(Json(status))
}

/// Brings a network up now (Editor): to test it, or to see the server's
/// node (public key, node id, MagicDNS name, the login URL of a Tailscale
/// node that waits for one).
async fn up(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
) -> ApiResult<Json<NetworkStatus>> {
    let netd = netd(&st)?;
    let (net, vault) = network_for(&st, &ctx, id, VaultRole::Editor).await?;
    let status = netd.up(&NetworkSpec::new(&net, Some(vault))).await?;
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "network.up",
            Some(format!("network:{id}")),
            json!({"name": net.network.name, "kind": net.network.kind.as_str(), "state": status.state}),
            vault,
        )
        .await?;
    Ok(Json(status))
}

/// Takes a network down (Editor).
async fn down(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    let netd = netd(&st)?;
    let rec = st.store.get_in::<Network>(&ctx.access, id).await?;
    let vault = rec.meta.vault_id.unwrap_or(ctx.personal());
    ctx.access.require(vault, VaultRole::Editor)?;
    netd.down(id).await?;
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "network.down",
            Some(format!("network:{id}")),
            json!({"name": rec.data.name}),
            vault,
        )
        .await?;
    Ok(Json(json!({"ok": true})))
}

/// Devices of a network, to import them as hosts (Editor).
async fn peers(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(id): Path<Id>,
) -> ApiResult<Json<Vec<NetworkPeer>>> {
    let netd = netd(&st)?;
    let (net, vault) = network_for(&st, &ctx, id, VaultRole::Editor).await?;
    Ok(Json(
        netd.peers(&NetworkSpec::new(&net, Some(vault))).await?,
    ))
}

// --- Relay -------------------------------------------------------------------------

/// Open relays per user.
#[derive(Default, Clone)]
pub struct RelayCounter(Arc<Mutex<HashMap<Id, usize>>>);

/// One open relay; released when dropped.
pub struct RelaySlot {
    counter: RelayCounter,
    user: Id,
}

impl RelayCounter {
    /// Takes a slot, or `None` if the user already has `max` open.
    pub fn acquire(&self, user: Id, max: usize) -> Option<RelaySlot> {
        let mut open = self.0.lock();
        let n = open.entry(user).or_default();
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(RelaySlot {
            counter: self.clone(),
            user,
        })
    }

    /// Relays open by a user.
    pub fn open(&self, user: Id) -> usize {
        self.0.lock().get(&user).copied().unwrap_or(0)
    }
}

impl Drop for RelaySlot {
    fn drop(&mut self) {
        let mut open = self.counter.0.lock();
        if let Some(n) = open.get_mut(&self.user) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                open.remove(&self.user);
            }
        }
    }
}

/// What the relay audit entries say.
struct RelayAudit {
    owner: Id,
    actor: String,
    vault: Id,
    host_id: Id,
    detail: Value,
}

/// `GET /api/v1/hosts/{id}/relay` (WebSocket, `?access_token=` or the
/// `Authorization` header). Before upgrading it checks access (Editor, or
/// Use-only when the vault is not Strict: the same rule as just-in-time
/// credentials), that the host's first hop has a network, the per-user
/// limit, and dials through netd: every failure is a normal API error
/// (`network_unavailable`, `network_not_found`, `network_dial_failed`,
/// `not_in_network`, `relay_limit`, `use_only_strict`...). Then binary
/// frames carry the bytes both ways until either side closes, the device
/// is signed out (4007) or it is idle for `[networks] relay_idle_minutes`.
async fn relay(
    State(st): State<AppState>,
    ctx: AccessCtx,
    Path(host_id): Path<Id>,
    upgrade: WebSocketUpgrade,
) -> ApiResult<Response> {
    let netd = netd(&st)?;
    let vault = st.store.vault_of::<Host>(&ctx.access, host_id).await?;
    ctx.access.authorize_secret(vault, SecretUse::Credentials)?;
    let mut resolved = st
        .store
        .resolve_in(&ctx.access, host_id, SecretUse::Server)
        .await?;
    let Some(network) = resolved.first_hop_network() else {
        resolved.zeroize_secrets();
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "not_in_network",
            "this host is not reached through a private network: connect to it directly",
        ));
    };
    let spec = NetworkSpec::new(network, Some(vault));
    let (net_id, net_name, net_kind) = (
        network.network.id,
        network.network.name.clone(),
        network.network.kind.as_str().to_string(),
    );
    let hop = resolved.first_hop();
    let (address, port, hop_id) = (hop.host.address.clone(), hop.port, hop.host.id);
    resolved.zeroize_secrets();
    drop(resolved);

    let cfg = &st.config.networks;
    let Some(slot) = st.relays.acquire(ctx.id(), cfg.max_relays_per_user.max(1)) else {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "relay_limit",
            format!(
                "you have {} relays open: close some connections first",
                cfg.max_relays_per_user
            ),
        )
        .with_detail("max", cfg.max_relays_per_user));
    };
    let timeout = Duration::from_secs(cfg.dial_timeout_secs.clamp(1, 120));
    let stream = netd.dial(&spec, &address, port, timeout).await?;
    let detail = json!({
        "network_id": net_id,
        "network": net_name,
        "kind": net_kind,
        "address": address,
        "port": port,
        "hop_host_id": hop_id,
        "device": ctx.user.device.name,
    });
    st.store
        .audit_vault(
            ctx.id(),
            &ctx.actor(),
            "relay.open",
            Some(format!("host:{host_id}")),
            detail.clone(),
            vault,
        )
        .await?;
    tracing::info!(user = %ctx.id(), host = %host_id, network = %net_id, %address, port, "relay opened");
    let guard = st
        .sockets
        .register(ctx.id(), ctx.user.device.id, SocketKind::Relay);
    let idle = Duration::from_secs(cfg.relay_idle_minutes.max(1) * 60);
    let audit = RelayAudit {
        owner: ctx.id(),
        actor: ctx.actor(),
        vault,
        host_id,
        detail,
    };
    Ok(upgrade
        .max_message_size(1 << 20)
        .on_upgrade(move |socket| async move {
            pipe(st, socket, stream, idle, guard, slot, audit).await;
        }))
}

/// Copies bytes between the WebSocket and the netd connection.
async fn pipe<S>(
    st: AppState,
    socket: WebSocket,
    stream: S,
    idle: Duration,
    guard: SocketGuard,
    _slot: RelaySlot,
    audit: RelayAudit,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let started = Instant::now();
    let (mut rd, mut wr) = tokio::io::split(stream);
    let (mut sink, mut source) = socket.split();
    let mut buf = vec![0u8; 32 * 1024];
    let (mut up, mut down) = (0u64, 0u64);
    let mut last = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    tick.tick().await;
    let close = |code: u16, reason: &'static str| {
        Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        }))
    };
    let reason: &'static str = loop {
        tokio::select! {
            n = rd.read(&mut buf) => match n {
                Ok(0) | Err(_) => {
                    let _ = sink.send(close(1000, "host_closed")).await;
                    break "host_closed";
                }
                Ok(n) => {
                    down += n as u64;
                    last = Instant::now();
                    if sink.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                        break "client_gone";
                    }
                }
            },
            msg = source.next() => match msg {
                Some(Ok(Message::Binary(b))) => {
                    up += b.len() as u64;
                    last = Instant::now();
                    if wr.write_all(&b).await.is_err() {
                        let _ = sink.send(close(1000, "host_closed")).await;
                        break "host_closed";
                    }
                }
                Some(Ok(Message::Text(_) | Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break "client_closed",
            },
            _ = tick.tick() => {
                if last.elapsed() >= idle {
                    let _ = sink.send(close(1000, "idle")).await;
                    break "idle";
                }
                if sink.send(Message::Ping(Default::default())).await.is_err() {
                    break "client_gone";
                }
            }
            _ = guard.signed_out() => {
                let code = crate::room::EndCode::SignedOut;
                let _ = sink.send(close(code.close_code(), "signed_out")).await;
                break "signed_out";
            }
        }
    };
    let _ = wr.shutdown().await;
    let mut detail = audit.detail;
    detail["bytes_up"] = json!(up);
    detail["bytes_down"] = json!(down);
    detail["duration_ms"] = json!(started.elapsed().as_millis() as u64);
    detail["reason"] = json!(reason);
    detail["closed_at"] = json!(now_ms());
    tracing::info!(user = %audit.owner, host = %audit.host_id, up, down, reason, "relay closed");
    if let Err(e) = st
        .store
        .audit_vault(
            audit.owner,
            &audit.actor,
            "relay.close",
            Some(format!("host:{}", audit.host_id)),
            detail,
            audit.vault,
        )
        .await
    {
        tracing::warn!(error = %e, "could not audit the relay close");
    }
}
