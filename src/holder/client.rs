//! Server side: connection to the session holder (retried while the server
//! is running).

use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;
use parking_lot::Mutex;
use termoak_core::Id;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::net::UnixStream;
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::{mpsc, oneshot};

use super::proto::{Frame, PROTOCOL, ToHolder, ToServer, read_frame, write_frame};
use crate::sessions::SessionManager;

/// Connection to the holder.
pub struct HolderClient {
    pub path: PathBuf,
    tx: Mutex<Option<mpsc::UnboundedSender<Frame<ToHolder>>>>,
}

impl HolderClient {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            tx: Mutex::new(None),
        }
    }

    pub fn connected(&self) -> bool {
        self.tx.lock().as_ref().is_some_and(|tx| !tx.is_closed())
    }

    fn send_frame(&self, frame: Frame<ToHolder>) -> bool {
        self.tx
            .lock()
            .as_ref()
            .is_some_and(|tx| tx.send(frame).is_ok())
    }

    /// `false` if there is no connection to the holder right now.
    pub fn send(&self, msg: ToHolder) -> bool {
        self.send_frame(Frame::Msg(msg))
    }

    pub fn send_input(&self, id: Id, data: Bytes) -> bool {
        self.send_frame(Frame::Data(id, data))
    }
}

enum End {
    /// The holder closed or the connection was lost.
    Closed,
    /// Another server took over the holder.
    Replaced,
}

/// Keeps the connection to the holder. `synced` receives the sessions it
/// had the first time it connects.
pub(crate) async fn run(
    mgr: Weak<SessionManager>,
    client: Arc<HolderClient>,
    mut synced: Option<oneshot::Sender<Vec<Id>>>,
) {
    let mut failing = false;
    loop {
        match connection(&mgr, &client, &mut synced).await {
            Ok(End::Replaced) => {
                *client.tx.lock() = None;
                tracing::warn!(
                    "another server is using the session holder: this one stops using it"
                );
                return;
            }
            Ok(End::Closed) => {
                failing = false;
                tracing::warn!("lost the connection to the session holder");
            }
            Err(e) => {
                if !failing {
                    tracing::warn!(
                        error = format!("{e:#}"),
                        socket = %client.path.display(),
                        "could not connect to the session holder; retrying"
                    );
                }
                failing = true;
            }
        }
        *client.tx.lock() = None;
        if mgr.strong_count() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn connection(
    mgr: &Weak<SessionManager>,
    client: &HolderClient,
    synced: &mut Option<oneshot::Sender<Vec<Id>>>,
) -> anyhow::Result<End> {
    let stream = UnixStream::connect(&client.path)
        .await
        .with_context(|| format!("could not open {}", client.path.display()))?;
    let (mut rd, wr) = stream.into_split();
    match read_frame::<_, ToServer>(&mut rd).await? {
        Some(Frame::Msg(ToServer::Hello {
            protocol, version, ..
        })) => {
            anyhow::ensure!(
                protocol == PROTOCOL,
                "the session holder ({version}) uses protocol {protocol} and this server uses {PROTOCOL}: it must be restarted (its sessions will be cut)"
            );
            tracing::info!(%version, "connected to the session holder");
        }
        _ => anyhow::bail!("the session holder did not say hello"),
    }
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(writer(wr, rx));
    *client.tx.lock() = Some(tx);

    let mut held = Vec::new();
    loop {
        let Some(frame) = read_frame::<_, ToServer>(&mut rd).await? else {
            return Ok(End::Closed);
        };
        let Some(m) = mgr.upgrade() else {
            return Ok(End::Closed);
        };
        match frame {
            Frame::Data(id, data) => m.held_output(id, data),
            Frame::Snapshot(id, data) => m.held_snapshot(id, data),
            Frame::Msg(msg) => match msg {
                ToServer::Held {
                    id,
                    meta,
                    status,
                    cols,
                    rows,
                } => {
                    held.push(id);
                    m.adopt(id, meta, status, cols, rows).await;
                }
                ToServer::Synced => {
                    m.held_synced(&held).await;
                    if let Some(tx) = synced.take() {
                        let _ = tx.send(held.clone());
                    }
                }
                ToServer::Status { id, status } => m.held_status(id, status).await,
                ToServer::Ask { ask, id, question } => {
                    tokio::spawn(async move {
                        let answer = m.answer(id, question).await;
                        if let Some(h) = m.holder() {
                            h.send(ToHolder::Answer { ask, answer });
                        }
                    });
                }
                ToServer::Os { id, os, display } => {
                    tokio::spawn(async move { m.held_os(id, os, display).await });
                }
                ToServer::Replaced => return Ok(End::Replaced),
                ToServer::Hello { .. } => {}
            },
        }
    }
}

async fn writer(wr: OwnedWriteHalf, mut rx: mpsc::UnboundedReceiver<Frame<ToHolder>>) {
    let mut w = BufWriter::with_capacity(64 * 1024, wr);
    while let Some(frame) = rx.recv().await {
        if write_frame(&mut w, &frame).await.is_err() {
            break;
        }
        if rx.is_empty() && w.flush().await.is_err() {
            break;
        }
    }
    let _ = w.shutdown().await;
}
