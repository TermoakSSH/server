//! Client of `termoak-netd`, the optional service that joins the users'
//! private networks (WireGuard, Tailscale/Headscale, ZeroTier) in user
//! space and opens connections inside them. Protocol: `docs/NETWORKS.md`.
//!
//! One Unix socket connection per request. The server writes one JSON line
//! (the request) and reads one JSON line (the answer). After a successful
//! `dial` the same connection carries the raw bytes of the TCP connection
//! inside the network.
//!
//! The server never dials a host of a network by itself: without netd
//! (`[networks] netd_socket`) or with netd down, those connections fail with
//! `network_unavailable`.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::http::StatusCode;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use termoak_core::Id;
use termoak_core::error::codes;
use termoak_core::resolve::ResolvedNetwork;
use termoak_ssh::net::{BoxedStream, DialRequest, NetworkDialer};
use termoak_ssh::{Dialer, SshError};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use utoipa::ToSchema;

use crate::error::ApiError;

/// Protocol version this server speaks.
pub const PROTOCOL: u32 = 1;

/// Longest answer line accepted.
const MAX_LINE: u64 = 1 << 20;

/// Time for a control request (not `dial`, which has its own).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How often the server checks that netd is alive.
const HEALTH_EVERY: Duration = Duration::from_secs(30);

/// A network as netd receives it: everything needed to join it.
#[derive(Clone, Serialize)]
pub struct NetworkSpec {
    pub id: Id,
    pub name: String,
    /// `wireguard`, `tailscale` or `zerotier`.
    pub kind: String,
    /// Changes whenever the configuration or the secrets change: netd
    /// restarts the network's node when it differs from the running one.
    pub revision: String,
    /// The section of the network's kind (`Network.wireguard`...).
    pub config: Value,
    /// The secrets (private key, auth key, API token).
    pub secret: Value,
    /// Vault of the network (logs only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<Id>,
}

impl std::fmt::Debug for NetworkSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkSpec")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

impl NetworkSpec {
    pub fn new(n: &ResolvedNetwork, vault_id: Option<Id>) -> Self {
        use termoak_core::model::NetworkKind;
        let net = &n.network;
        let config = match net.kind {
            NetworkKind::Wireguard => serde_json::to_value(&net.wireguard),
            NetworkKind::Tailscale => serde_json::to_value(&net.tailscale),
            NetworkKind::Zerotier => serde_json::to_value(&net.zerotier),
            NetworkKind::Other(_) => Ok(Value::Null),
        }
        .unwrap_or(Value::Null);
        let secret = serde_json::to_value(&n.secret).unwrap_or(Value::Null);
        // The WireGuard public key is derived from the private key (in the
        // secret): it does not change the revision.
        let mut hashed = config.clone();
        if let Some(obj) = hashed.as_object_mut() {
            obj.remove("public_key");
        }
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
        ctx.update(net.kind.as_str().as_bytes());
        ctx.update(b"\0");
        ctx.update(hashed.to_string().as_bytes());
        ctx.update(b"\0");
        ctx.update(secret.to_string().as_bytes());
        let digest = ctx.finish();
        let revision: String = digest.as_ref()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Self {
            id: net.id,
            name: net.name.clone(),
            kind: net.kind.as_str().to_string(),
            revision,
            config,
            secret,
            vault_id,
        }
    }
}

/// `hello` answer.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct NetdHello {
    /// Protocol version of netd.
    #[serde(default)]
    pub v: u32,
    #[serde(default)]
    pub version: String,
    /// Network kinds this netd build can join (`wireguard`, and
    /// `tailscale` when built with the `tailscale` tag; ZeroTier may be
    /// left out).
    #[serde(default)]
    pub kinds: Vec<String>,
}

/// The server's node in a network.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct NetworkNode {
    /// Name in the network (Tailscale hostname...).
    #[serde(default)]
    pub name: Option<String>,
    /// Addresses of the server inside the network.
    #[serde(default)]
    pub addresses: Vec<String>,
    /// WireGuard public key.
    #[serde(default)]
    pub public_key: Option<String>,
    /// ZeroTier node id / Tailscale node id.
    #[serde(default)]
    pub node_id: Option<String>,
    /// Where to log the node in (Tailscale login URL, Headscale
    /// registration) while `state` is `needs_auth` with `auth: login`.
    /// Only Editors of the network's vault see it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_url: Option<String>,
    /// The node's MagicDNS name (Tailscale).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,
}

impl NetworkStatus {
    /// The network runs in netd (any state but `down`).
    pub fn is_running(&self) -> bool {
        !self.state.is_empty() && self.state != "down"
    }
}

/// State of a network in netd.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct NetworkStatus {
    #[serde(default)]
    pub network_id: Option<uuid::Uuid>,
    /// `down`, `starting`, `needs_auth` (authorize the node: see `auth`),
    /// `up` or `error` (`message`).
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub node: Option<NetworkNode>,
    /// Revision of the running configuration.
    #[serde(default)]
    pub revision: Option<String>,
    /// Since when it is in this state (ms).
    #[serde(default)]
    pub since: Option<i64>,
    #[serde(default)]
    pub last_used_at: Option<i64>,
    /// Bytes of the tunnel (WireGuard: from / to the peers).
    #[serde(default)]
    pub rx_bytes: u64,
    #[serde(default)]
    pub tx_bytes: u64,
    /// Latest handshake with a peer (ms; WireGuard). None: never (check
    /// the peer's endpoint and that it has the server's public key).
    #[serde(default)]
    pub last_handshake_at: Option<i64>,
    /// Connections open through the network now.
    #[serde(default)]
    pub streams: u64,
    /// Connections opened / failed since the network came up.
    #[serde(default)]
    pub dials: u64,
    #[serde(default)]
    pub dials_failed: u64,
    /// Tailscale: why a `needs_auth` node waits: `login` (open
    /// `node.auth_url`: no auth key, or the key was not enough) or
    /// `approval` (approve the device in the admin console).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    /// Tailscale: the control server (Tailscale's when the network has
    /// none).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_url: Option<String>,
    /// Tailscale: the tailnet's name and MagicDNS suffix, once logged in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tailnet: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magic_dns_suffix: Option<String>,
    /// Tailscale: devices the server's node sees (when `up`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_count: Option<u64>,
    /// Tailscale: the node leaves the tailnet when it stops.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<bool>,
    /// Tailscale: the latest error of the node (the control server refused
    /// the auth key...), also while it retries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// A device of the network (to import hosts).
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct NetworkPeer {
    pub name: String,
    #[serde(default)]
    pub dns_name: Option<String>,
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub online: Option<bool>,
    #[serde(default)]
    pub last_seen: Option<i64>,
    /// WireGuard: the peer's public key and endpoint.
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Tailscale: the device's ACL tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Tailscale: subnets the device routes for the tailnet (subnet
    /// router; exit routes left out).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<String>,
    /// Tailscale: the device's stable id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// A failed netd request.
#[derive(Debug, Clone)]
pub enum NetdError {
    /// netd is not running (or not answering).
    Unreachable(String),
    /// netd refused: `code` (`needs_auth`, `unsupported_kind`,
    /// `dial_failed`, `timeout`, `network_error`, `invalid`...); `auth`
    /// with `needs_auth` (`login` or `approval`).
    Refused {
        code: String,
        message: String,
        auth: Option<String>,
    },
}

impl std::fmt::Display for NetdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetdError::Unreachable(m) => write!(f, "termoak-netd is not responding: {m}"),
            NetdError::Refused { message, .. } => f.write_str(message),
        }
    }
}

impl From<NetdError> for SshError {
    fn from(e: NetdError) -> Self {
        let code = match &e {
            NetdError::Unreachable(_) => codes::NETWORK_UNAVAILABLE,
            NetdError::Refused { code, .. } if code == "unsupported_kind" => {
                codes::NETWORK_UNAVAILABLE
            }
            NetdError::Refused { .. } => codes::NETWORK_DIAL_FAILED,
        };
        SshError::Network {
            code,
            message: e.to_string(),
        }
    }
}

impl From<NetdError> for ApiError {
    fn from(e: NetdError) -> Self {
        let (netd_code, auth) = match &e {
            NetdError::Refused { code, auth, .. } => (Some(code.clone()), auth.clone()),
            NetdError::Unreachable(_) => (None, None),
        };
        let mut err: ApiError = SshError::from(e).into();
        if let Some(c) = netd_code {
            err = err.with_detail("netd_code", c);
        }
        if let Some(a) = auth {
            err = err.with_detail("auth", a);
        }
        err
    }
}

/// `network_unavailable` for a server without netd.
pub fn not_configured() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        codes::NETWORK_UNAVAILABLE,
        "this server cannot reach private networks (it has no termoak-netd)",
    )
}

/// Client of one netd socket. Cheap to share.
pub struct Netd {
    socket: PathBuf,
    healthy: AtomicBool,
    hello: RwLock<Option<NetdHello>>,
}

impl Netd {
    pub fn new(socket: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            socket,
            healthy: AtomicBool::new(false),
            hello: RwLock::new(None),
        })
    }

    /// netd answered the last check (or request).
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// The last `hello` answer.
    pub fn info(&self) -> Option<NetdHello> {
        self.hello.read().clone()
    }

    /// The network kinds netd can join (`hello`), while it is healthy.
    pub fn kinds(&self) -> Vec<String> {
        if !self.is_healthy() {
            return Vec::new();
        }
        self.hello
            .read()
            .as_ref()
            .map(|h| h.kinds.clone())
            .unwrap_or_default()
    }

    /// Checks netd now and then every 30 s (for `features.networks`).
    pub fn spawn_health(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(HEALTH_EVERY);
            loop {
                tick.tick().await;
                let Some(netd) = weak.upgrade() else { break };
                if let Err(e) = netd.hello().await {
                    tracing::warn!(error = %e, "termoak-netd is not available");
                }
            }
        });
    }

    /// Sends one request and reads the answer line; returns it with the
    /// connection (for `dial`).
    async fn exchange(
        &self,
        request: Value,
        timeout: Duration,
    ) -> Result<(Value, BufReader<UnixStream>), NetdError> {
        let run = async {
            let stream = UnixStream::connect(&self.socket)
                .await
                .map_err(|e| NetdError::Unreachable(e.to_string()))?;
            let mut reader = BufReader::new(stream);
            let mut line = request.to_string();
            line.push('\n');
            reader
                .get_mut()
                .write_all(line.as_bytes())
                .await
                .map_err(|e| NetdError::Unreachable(e.to_string()))?;
            let mut answer = String::new();
            let n = (&mut reader)
                .take(MAX_LINE)
                .read_line(&mut answer)
                .await
                .map_err(|e| NetdError::Unreachable(e.to_string()))?;
            if n == 0 || !answer.ends_with('\n') {
                return Err(NetdError::Unreachable("no answer".into()));
            }
            let v: Value = serde_json::from_str(answer.trim_end())
                .map_err(|e| NetdError::Unreachable(format!("invalid answer: {e}")))?;
            Ok((v, reader))
        };
        let result = tokio::time::timeout(timeout, run)
            .await
            .unwrap_or_else(|_| Err(NetdError::Unreachable("timed out".into())));
        match &result {
            Err(NetdError::Unreachable(_)) => self.healthy.store(false, Ordering::Relaxed),
            _ => self.healthy.store(true, Ordering::Relaxed),
        }
        let (v, reader) = result?;
        if v["ok"].as_bool() == Some(true) {
            Ok((v, reader))
        } else {
            Err(NetdError::Refused {
                code: v["code"].as_str().unwrap_or("error").to_string(),
                message: v["message"]
                    .as_str()
                    .unwrap_or("termoak-netd refused the request")
                    .to_string(),
                auth: v["auth"].as_str().map(str::to_string),
            })
        }
    }

    async fn call(&self, request: Value) -> Result<Value, NetdError> {
        Ok(self.exchange(request, REQUEST_TIMEOUT).await?.0)
    }

    /// Protocol version, build and the kinds it can join.
    pub async fn hello(&self) -> Result<NetdHello, NetdError> {
        let v = self.call(json!({"v": PROTOCOL, "op": "hello"})).await?;
        let hello: NetdHello = serde_json::from_value(v).unwrap_or_default();
        *self.hello.write() = Some(hello.clone());
        Ok(hello)
    }

    /// Brings a network up (or restarts it if its revision changed).
    pub async fn up(&self, spec: &NetworkSpec) -> Result<NetworkStatus, NetdError> {
        let v = self
            .call(json!({"v": PROTOCOL, "op": "up", "network": spec}))
            .await?;
        Ok(serde_json::from_value(v["status"].clone()).unwrap_or_default())
    }

    /// Takes a network down (its node leaves; nothing happens if it was
    /// not up).
    pub async fn down(&self, network_id: Id) -> Result<(), NetdError> {
        self.call(json!({"v": PROTOCOL, "op": "down", "network_id": network_id}))
            .await?;
        Ok(())
    }

    /// The network was deleted: takes it down and netd removes what it
    /// keeps of it (a persistent Tailscale node is logged out and its state
    /// deleted). An older netd ignores `forget` and only takes it down.
    pub async fn forget(&self, network_id: Id) -> Result<(), NetdError> {
        self.call(json!({"v": PROTOCOL, "op": "down", "network_id": network_id, "forget": true}))
            .await?;
        Ok(())
    }

    /// State of a network (without bringing it up).
    pub async fn status(&self, network_id: Id) -> Result<NetworkStatus, NetdError> {
        let v = self
            .call(json!({"v": PROTOCOL, "op": "status", "network_id": network_id}))
            .await?;
        Ok(serde_json::from_value(v["status"].clone()).unwrap_or_default())
    }

    /// Devices of a network (brings it up if needed).
    pub async fn peers(&self, spec: &NetworkSpec) -> Result<Vec<NetworkPeer>, NetdError> {
        let v = self
            .call(json!({"v": PROTOCOL, "op": "peers", "network": spec}))
            .await?;
        Ok(serde_json::from_value(v["peers"].clone()).unwrap_or_default())
    }

    /// Opens a TCP connection to `host:port` inside the network (brought
    /// up if needed): the returned stream carries its bytes.
    pub async fn dial(
        &self,
        spec: &NetworkSpec,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<BufReader<UnixStream>, NetdError> {
        let request = json!({
            "v": PROTOCOL,
            "op": "dial",
            "network": spec,
            "host": host,
            "port": port,
            "timeout_ms": timeout.as_millis() as u64,
        });
        let (_, stream) = self
            .exchange(request, timeout + Duration::from_secs(5))
            .await?;
        Ok(stream)
    }

    /// The SSH engine's dialer for hosts with a network (server sessions,
    /// tests, exec, SFTP and the AI).
    pub fn dialer(self: &Arc<Self>) -> Dialer {
        Dialer(Arc::new(NetdDialer(self.clone())))
    }
}

/// [`NetworkDialer`] backed by netd.
pub struct NetdDialer(pub Arc<Netd>);

#[async_trait::async_trait]
impl NetworkDialer for NetdDialer {
    async fn dial(&self, req: DialRequest<'_>) -> termoak_ssh::Result<BoxedStream> {
        let Some(network) = req.network else {
            return Err(SshError::Network {
                code: codes::NETWORK_NOT_FOUND,
                message: format!("network {} not found", req.network_id),
            });
        };
        let spec = NetworkSpec::new(network, None);
        let stream = self
            .0
            .dial(&spec, req.address, req.port, req.timeout)
            .await?;
        Ok(Box::new(stream))
    }
}
