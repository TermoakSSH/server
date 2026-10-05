//! Protocol between the server and the session holder (Unix socket).
//!
//! Each frame is its length (u32, big endian, not counting itself), a type
//! byte and the payload:
//!
//! - `0`: JSON control message ([`ToHolder`] or [`ToServer`]).
//! - `1`: terminal data: session id (16 bytes) and the bytes. From server to
//!   holder it is the typed input; from holder to server, the output.
//! - `2`: full scrollback of a session (id and bytes); replaces whatever the
//!   server had.
//!
//! Server and holder only understand each other with the same [`PROTOCOL`]:
//! if it changes, the holder must be restarted (and the sessions are cut).

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;

use bytes::{Bytes, BytesMut};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use termoak_core::Id;
use termoak_core::resolve::ResolvedHost;
use termoak_ssh::SshError;
use termoak_ssh::prompt::Prompt;
use termoak_ssh::recording::InputAuthor;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Protocol version. Bump it on any incompatible change.
pub const PROTOCOL: u32 = 1;

/// Additions to [`PROTOCOL`] a holder announces in [`ToServer::Hello`]
/// (`features`): the server only sends what the holder understands (an
/// older holder that keeps running after the server is updated does not
/// know them, and an unknown message would drop the connection).
pub const FEATURE_INPUT_AUTHORS: &str = "input_authors";

/// What this holder understands beyond [`PROTOCOL`].
pub const FEATURES: &[&str] = &[FEATURE_INPUT_AUTHORS];

/// Maximum frame size (a session's scrollback fits comfortably).
const MAX_FRAME: usize = 64 << 20;

const KIND_MSG: u8 = 0;
const KIND_DATA: u8 = 1;
const KIND_SNAPSHOT: u8 = 2;

/// A protocol frame.
#[derive(Debug)]
pub enum Frame<M> {
    Msg(M),
    Data(Id, Bytes),
    Snapshot(Id, Bytes),
}

/// From the server to the holder.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToHolder {
    /// Opens a new session.
    Open(Box<OpenSession>),
    Resize {
        id: Id,
        cols: u16,
        rows: u16,
    },
    Close {
        id: Id,
    },
    /// Server data about the session (title...); the holder stores it as is
    /// and sends it back on reconnect.
    Meta {
        id: Id,
        meta: Value,
    },
    /// Answer to a question ([`ToServer::Ask`]).
    Answer {
        ask: u64,
        answer: Answer,
    },
    /// Who types the input that follows (recording). Only to holders with
    /// [`FEATURE_INPUT_AUTHORS`].
    Author {
        id: Id,
        author: InputAuthor,
    },
}

/// Everything needed to open a session.
#[derive(Debug, Serialize, Deserialize)]
pub struct OpenSession {
    pub id: Id,
    pub meta: Value,
    pub host: ResolvedHost,
    pub term: String,
    pub cols: u16,
    pub rows: u16,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub startup_script: Option<String>,
    /// Scrollback kept (bytes).
    pub scrollback: usize,
    #[serde(default)]
    pub recording: Option<RecordingOptions>,
    /// Detect the host's OS and report it with [`ToServer::Os`].
    #[serde(default)]
    pub detect_os: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecordingOptions {
    pub path: PathBuf,
    pub title: String,
    pub input: bool,
}

/// From the holder to the server.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToServer {
    /// The first thing the holder sends.
    Hello {
        protocol: u32,
        version: String,
        pid: u32,
        /// See [`FEATURES`] (absent in older holders).
        #[serde(default)]
        features: Vec<String>,
    },
    /// A session the holder already had (`Synced` follows the `Held`
    /// frames). If it is open, its scrollback comes next.
    Held {
        id: Id,
        meta: Value,
        status: HeldStatus,
        cols: u16,
        rows: u16,
    },
    /// End of the session list.
    Synced,
    Status {
        id: Id,
        status: HeldStatus,
    },
    /// Question for the server (host fingerprint, password...).
    Ask {
        ask: u64,
        id: Id,
        question: Question,
    },
    /// OS detected on the session's host.
    Os {
        id: Id,
        os: String,
        display: String,
    },
    /// Another server connected to the holder: this one must stop using it.
    Replaced,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum HeldStatus {
    Connecting {
        message: String,
    },
    Running,
    Closed {
        exit_code: Option<u32>,
        reason: Option<String>,
        /// It never opened (connection error).
        failed: bool,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Question {
    /// Is this host key trusted? The server decides with its known hosts
    /// (asking the user if needed).
    HostKey {
        host: String,
        port: u16,
        /// Public key in OpenSSH format.
        key: String,
    },
    KeyboardInteractive {
        host: String,
        name: String,
        instructions: String,
        prompts: Vec<Prompt>,
    },
    Passphrase {
        host: String,
        key_label: String,
    },
    Password {
        host: String,
        user: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Answer {
    HostKey { error: Option<HostKeyError> },
    Answers { answers: Option<Vec<String>> },
    Text { text: Option<String> },
}

/// Why a key is not trusted (the same errors as in the server, so the user
/// sees the same message).
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostKeyError {
    Changed {
        host: String,
        expected: String,
        actual: String,
    },
    Unknown {
        host: String,
        fingerprint: String,
        key_type: String,
    },
    Rejected {
        host: String,
    },
    Other {
        host: String,
        message: String,
    },
}

impl HostKeyError {
    pub fn from_ssh(e: SshError, host: &str) -> Self {
        match e {
            SshError::HostKeyChanged {
                host,
                expected,
                actual,
            } => HostKeyError::Changed {
                host,
                expected,
                actual,
            },
            SshError::HostKeyUnknown {
                host,
                fingerprint,
                key_type,
            } => HostKeyError::Unknown {
                host,
                fingerprint,
                key_type,
            },
            SshError::HostKeyRejected { host } => HostKeyError::Rejected { host },
            other => HostKeyError::Other {
                host: host.to_string(),
                message: other.to_string(),
            },
        }
    }

    pub fn into_ssh(self) -> SshError {
        match self {
            HostKeyError::Changed {
                host,
                expected,
                actual,
            } => SshError::HostKeyChanged {
                host,
                expected,
                actual,
            },
            HostKeyError::Unknown {
                host,
                fingerprint,
                key_type,
            } => SshError::HostKeyUnknown {
                host,
                fingerprint,
                key_type,
            },
            HostKeyError::Rejected { host } => SshError::HostKeyRejected { host },
            HostKeyError::Other { host, message } => SshError::Connect {
                target: host,
                reason: message,
            },
        }
    }
}

/// Writes a frame (without flushing: the writer decides that).
pub async fn write_frame<W, M>(w: &mut W, frame: &Frame<M>) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    M: Serialize,
{
    match frame {
        Frame::Msg(m) => {
            let body = serde_json::to_vec(m).map_err(io::Error::other)?;
            w.write_u32(body.len() as u32 + 1).await?;
            w.write_u8(KIND_MSG).await?;
            w.write_all(&body).await
        }
        Frame::Data(id, data) | Frame::Snapshot(id, data) => {
            let kind = if matches!(frame, Frame::Data(..)) {
                KIND_DATA
            } else {
                KIND_SNAPSHOT
            };
            w.write_u32(data.len() as u32 + 17).await?;
            w.write_u8(kind).await?;
            w.write_all(id.as_bytes()).await?;
            w.write_all(data).await
        }
    }
}

/// Reads a frame; `None` if the other side closed.
pub async fn read_frame<R, M>(r: &mut R) -> io::Result<Option<Frame<M>>>
where
    R: AsyncRead + Unpin,
    M: DeserializeOwned,
{
    let len = match r.read_u32().await {
        Ok(n) => n as usize,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    };
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes"),
        ));
    }
    let kind = r.read_u8().await?;
    let mut body = BytesMut::zeroed(len - 1);
    r.read_exact(&mut body).await?;
    match kind {
        KIND_MSG => serde_json::from_slice(&body)
            .map(|m| Some(Frame::Msg(m)))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        KIND_DATA | KIND_SNAPSHOT if body.len() >= 16 => {
            let id = Id::from_slice(&body[..16])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let data = body.freeze().slice(16..);
            Ok(Some(if kind == KIND_DATA {
                Frame::Data(id, data)
            } else {
                Frame::Snapshot(id, data)
            }))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown frame type {kind}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_round_trip() {
        let id = termoak_core::new_id();
        let mut buf = Vec::new();
        write_frame(&mut buf, &Frame::Msg(ToHolder::Close { id }))
            .await
            .unwrap();
        write_frame::<_, ToHolder>(&mut buf, &Frame::Data(id, Bytes::from_static(b"ls\n")))
            .await
            .unwrap();
        write_frame::<_, ToHolder>(&mut buf, &Frame::Snapshot(id, Bytes::new()))
            .await
            .unwrap();
        let mut r = &buf[..];
        assert!(matches!(
            read_frame::<_, ToHolder>(&mut r).await.unwrap(),
            Some(Frame::Msg(ToHolder::Close { id: got })) if got == id
        ));
        assert!(matches!(
            read_frame::<_, ToHolder>(&mut r).await.unwrap(),
            Some(Frame::Data(got, d)) if got == id && &d[..] == b"ls\n"
        ));
        assert!(matches!(
            read_frame::<_, ToHolder>(&mut r).await.unwrap(),
            Some(Frame::Snapshot(got, d)) if got == id && d.is_empty()
        ));
        assert!(read_frame::<_, ToHolder>(&mut r).await.unwrap().is_none());
    }

    #[test]
    fn host_key_errors_keep_their_meaning() {
        let e = HostKeyError::from_ssh(
            SshError::HostKeyChanged {
                host: "h:22".into(),
                expected: "a".into(),
                actual: "b".into(),
            },
            "h",
        );
        assert!(matches!(e.into_ssh(), SshError::HostKeyChanged { .. }));
    }
}
