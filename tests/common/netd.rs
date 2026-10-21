//! A fake `termoak-netd` for the tests (never part of the server binary):
//! it speaks the protocol of `docs/NETWORKS.md` on a Unix socket and
//! "dials inside the network" by connecting directly, recording every
//! request.

use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixListener, UnixStream};

/// A `dial` netd got.
#[derive(Debug, Clone)]
pub struct Dial {
    pub network_id: String,
    pub kind: String,
    pub revision: String,
    pub host: String,
    pub port: u16,
    /// The request carried the network's secret.
    pub secret: Value,
}

#[derive(Default)]
pub struct Log {
    pub dials: Vec<Dial>,
    /// `op` of every request, in order.
    pub ops: Vec<String>,
    pub up: Vec<String>,
    /// Networks running now (id → revision), like the real netd: brought
    /// up by `up`, `peers` and `dial`, taken down by `down`.
    pub running: std::collections::HashMap<String, String>,
    /// Ids of every `down`, in order.
    pub downs: Vec<String>,
}

pub struct FakeNetd {
    pub socket: PathBuf,
    pub log: Arc<Mutex<Log>>,
    _dir: tempfile::TempDir,
}

impl FakeNetd {
    pub fn dials(&self) -> Vec<Dial> {
        self.log.lock().dials.clone()
    }

    pub fn downs(&self) -> Vec<String> {
        self.log.lock().downs.clone()
    }

    /// The revision a network runs with (`None`: down).
    pub fn running(&self, id: &str) -> Option<String> {
        self.log.lock().running.get(id).cloned()
    }

    /// Waits until `id` was taken down `n` times in total.
    pub async fn wait_downs(&self, id: &str, n: usize) {
        for _ in 0..100 {
            if self.downs().iter().filter(|d| *d == id).count() >= n {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        }
        panic!("netd never got down #{n} for {id}: {:?}", self.downs());
    }
}

/// Starts the fake netd. Networks of kind `zerotier` are refused as
/// `unsupported_kind` (a build without ZeroTier); dials to port 1 fail
/// with `dial_failed`.
pub async fn start() -> FakeNetd {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("netd.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let log: Arc<Mutex<Log>> = Arc::default();
    let l = log.clone();
    tokio::spawn(async move {
        while let Ok((conn, _)) = listener.accept().await {
            let log = l.clone();
            tokio::spawn(async move {
                let _ = serve(conn, log).await;
            });
        }
    });
    FakeNetd {
        socket,
        log,
        _dir: dir,
    }
}

async fn answer(reader: &mut BufReader<UnixStream>, v: Value) -> std::io::Result<()> {
    let mut line = v.to_string();
    line.push('\n');
    reader.get_mut().write_all(line.as_bytes()).await
}

async fn serve(conn: UnixStream, log: Arc<Mutex<Log>>) -> std::io::Result<()> {
    let mut reader = BufReader::new(conn);
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Ok(());
    }
    let req: Value = match serde_json::from_str(line.trim_end()) {
        Ok(v) => v,
        Err(e) => {
            return answer(
                &mut reader,
                json!({"ok": false, "code": "invalid", "message": e.to_string()}),
            )
            .await;
        }
    };
    let op = req["op"].as_str().unwrap_or("").to_string();
    log.lock().ops.push(op.clone());
    let net = &req["network"];
    let id = net["id"]
        .as_str()
        .or(req["network_id"].as_str())
        .unwrap_or("")
        .to_string();
    if net["kind"] == "zerotier" {
        return answer(
            &mut reader,
            json!({"ok": false, "code": "unsupported_kind",
                   "message": "this termoak-netd was built without ZeroTier"}),
        )
        .await;
    }
    if matches!(op.as_str(), "up" | "peers" | "dial") {
        let rev = net["revision"].as_str().unwrap_or("").to_string();
        log.lock().running.insert(id.clone(), rev);
    }
    let running_rev = log.lock().running.get(&id).cloned();
    let status = |state: &str| {
        json!({"network_id": id, "state": state, "revision": running_rev,
               "node": {"name": "termoak-test", "addresses": ["100.64.0.1"],
                        "public_key": "ZmFrZQ=="}})
    };
    match op.as_str() {
        "hello" => {
            answer(
                &mut reader,
                json!({"ok": true, "v": 1, "version": "fake",
                       "kinds": ["wireguard", "tailscale"]}),
            )
            .await
        }
        "up" => {
            log.lock().up.push(id.clone());
            answer(&mut reader, json!({"ok": true, "status": status("up")})).await
        }
        "down" => {
            {
                let mut l = log.lock();
                l.running.remove(&id);
                l.downs.push(id.clone());
            }
            answer(&mut reader, json!({"ok": true})).await
        }
        "status" => {
            let up = running_rev.is_some();
            answer(
                &mut reader,
                json!({"ok": true, "status": status(if up { "up" } else { "down" })}),
            )
            .await
        }
        "peers" => {
            answer(
                &mut reader,
                json!({"ok": true, "peers": [
                    {"name": "nas", "dns_name": "nas.tail.ts.net", "addresses": ["100.64.0.7"],
                     "os": "linux", "online": true}
                ]}),
            )
            .await
        }
        "dial" => {
            let host = req["host"].as_str().unwrap_or("").to_string();
            let port = req["port"].as_u64().unwrap_or(0) as u16;
            log.lock().dials.push(Dial {
                network_id: id,
                kind: net["kind"].as_str().unwrap_or("").into(),
                revision: net["revision"].as_str().unwrap_or("").into(),
                host: host.clone(),
                port,
                secret: net["secret"].clone(),
            });
            let target = if port == 1 {
                Err(std::io::Error::other("refused"))
            } else {
                TcpStream::connect((host.as_str(), port)).await
            };
            match target {
                Ok(mut tcp) => {
                    answer(
                        &mut reader,
                        json!({"ok": true, "remote": format!("{host}:{port}")}),
                    )
                    .await?;
                    // Bytes the reader already took belong to the stream.
                    let early = reader.buffer().to_vec();
                    if !early.is_empty() {
                        tcp.write_all(&early).await?;
                    }
                    let mut conn = reader.into_inner();
                    let _ = tokio::io::copy_bidirectional(&mut conn, &mut tcp).await;
                    Ok(())
                }
                Err(e) => {
                    answer(
                        &mut reader,
                        json!({"ok": false, "code": "dial_failed",
                               "message": format!("could not reach {host}:{port}: {e}")}),
                    )
                    .await
                }
            }
        }
        _ => {
            answer(
                &mut reader,
                json!({"ok": false, "code": "invalid", "message": "unknown op"}),
            )
            .await
        }
    }
}
