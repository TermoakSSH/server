//! Helpers for the tests that use a real `sshd`.
#![allow(dead_code)]

use std::net::TcpListener as StdListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use futures::StreamExt;
use serde_json::Value;
use tokio_tungstenite::tungstenite::Message as WsMsg;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

pub mod srv;

pub struct Sshd {
    child: Child,
    pub port: u16,
    _dir: tempfile::TempDir,
    pub private_key: String,
    pub user: String,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub fn start_sshd() -> Option<Sshd> {
    // Linux only (on other systems the system sshd needs a different setup).
    if !cfg!(target_os = "linux") {
        return None;
    }
    let sshd = ["/usr/sbin/sshd", "/usr/local/sbin/sshd"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())?;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let hk = d.join("hk");
    Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&hk)
        .status()
        .ok()?;
    let key =
        termoak_ssh::keys::generate(termoak_ssh::keys::KeyType::Ed25519, "e2e", None).unwrap();
    std::fs::write(d.join("ak"), format!("{}\n", key.public_openssh)).unwrap();
    let port = free_port();
    std::fs::create_dir_all("/run/sshd").ok();
    let cfg = d.join("cfg");
    std::fs::write(
        &cfg,
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin yes\nAllowTcpForwarding yes\nSubsystem sftp internal-sftp\nLogLevel ERROR\n",
            hk.display(),
            d.join("pid").display(),
            d.join("ak").display()
        ),
    )
    .unwrap();
    let child = Command::new(sshd)
        .args(["-D", "-e", "-f"])
        .arg(&cfg)
        .stdout(Stdio::null())
        .spawn()
        .ok()?;
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            let user = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
                .unwrap()
                .trim()
                .to_string();
            return Some(Sshd {
                child,
                port,
                _dir: dir,
                private_key: key.private_openssh,
                user,
            });
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

pub type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

pub async fn ws_connect(base: &str, path: &str, token: Option<&str>) -> Ws {
    let url = format!("{}{path}", base.replace("http://", "ws://"));
    let mut req = url.into_client_request().unwrap();
    if let Some(t) = token {
        req.headers_mut()
            .insert("authorization", format!("Bearer {t}").parse().unwrap());
    }
    tokio_tungstenite::connect_async(req).await.unwrap().0
}

/// Reads from the WebSocket until `needle` shows up in the binary output.
pub async fn ws_wait_output(ws: &mut Ws, needle: &str) -> String {
    let mut seen = String::new();
    let ok = tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(Ok(msg)) = ws.next().await {
            if let WsMsg::Binary(b) = msg {
                seen.push_str(&String::from_utf8_lossy(&b));
                if seen.contains(needle) {
                    return true;
                }
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    assert!(ok, "\"{needle}\" did not show up in the output: {seen:?}");
    seen
}

pub async fn ws_wait_json(ws: &mut Ws, kind: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(Ok(msg)) = ws.next().await {
            if let WsMsg::Text(t) = msg {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v["type"] == kind {
                    return v;
                }
            }
        }
        panic!("WebSocket closed while waiting for {kind}");
    })
    .await
    .unwrap_or_else(|_| panic!("message {kind} never arrived"))
}
