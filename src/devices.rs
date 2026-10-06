//! Sessions and devices: the open WebSockets of each signed-in device (so
//! signing a device out closes them right away) and the short description
//! of each device's client (`Firefox 131 on Linux`, `Termoak 0.4.0`...).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use termoak_core::Id;
use tokio_util::sync::CancellationToken;

/// Open WebSockets (events, terminal, sharing) per user and device.
#[derive(Default)]
pub struct Sockets {
    next: AtomicU64,
    open: Mutex<HashMap<u64, OpenSocket>>,
}

struct OpenSocket {
    user: Id,
    device: Id,
    kind: SocketKind,
    signed_out: CancellationToken,
}

/// What a WebSocket is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketKind {
    /// The user events (`/events/ws`).
    Events,
    /// A terminal session (own or shared).
    Session,
}

impl Sockets {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Registers a WebSocket of a device; it is forgotten when the guard is
    /// dropped.
    pub fn register(self: &Arc<Self>, user: Id, device: Id, kind: SocketKind) -> SocketGuard {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let signed_out = CancellationToken::new();
        self.open.lock().insert(
            id,
            OpenSocket {
                user,
                device,
                kind,
                signed_out: signed_out.clone(),
            },
        );
        SocketGuard {
            sockets: self.clone(),
            id,
            signed_out,
        }
    }

    /// The device was signed out: its WebSockets close. Returns how many.
    pub fn sign_out_device(&self, device: Id) -> usize {
        self.sign_out(|s| s.device == device)
    }

    /// Several devices were signed out.
    pub fn sign_out_devices(&self, devices: &[Id]) -> usize {
        self.sign_out(|s| devices.contains(&s.device))
    }

    /// All the user's devices were signed out (password reset).
    pub fn sign_out_user(&self, user: Id) -> usize {
        self.sign_out(|s| s.user == user)
    }

    /// The account was disabled or deleted: its events sockets close. Its
    /// terminal sockets are ended by the sessions themselves (`revoked`,
    /// `session_ended`), which say why.
    pub fn sign_out_user_events(&self, user: Id) -> usize {
        self.sign_out(|s| s.user == user && s.kind == SocketKind::Events)
    }

    /// Open WebSockets of a device.
    pub fn count_for_device(&self, device: Id) -> usize {
        self.open
            .lock()
            .values()
            .filter(|s| s.device == device)
            .count()
    }

    fn sign_out(&self, matches: impl Fn(&OpenSocket) -> bool) -> usize {
        let open = self.open.lock();
        let mut n = 0;
        for s in open.values().filter(|s| matches(s)) {
            s.signed_out.cancel();
            n += 1;
        }
        n
    }
}

/// A registered WebSocket.
pub struct SocketGuard {
    sockets: Arc<Sockets>,
    id: u64,
    signed_out: CancellationToken,
}

impl SocketGuard {
    /// Completes when its device is signed out.
    pub async fn signed_out(&self) {
        self.signed_out.cancelled().await
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        self.sockets.open.lock().remove(&self.id);
    }
}

/// Completes when the device of `guard` is signed out (never without one:
/// guests of a link have no device).
pub async fn signed_out(guard: &Option<SocketGuard>) {
    match guard {
        Some(g) => g.signed_out().await,
        None => std::future::pending().await,
    }
}

/// The client is one of the released apps from before the waiting room and
/// the keyboard requests (sharing protocol 2): desktop 0.2, Android 0.3 and
/// iOS 0.3 are built on the Termoak libraries 0.2 (`User-Agent:
/// Termoak/0.2.1`), and AceitunoakSSH before them. They cannot let a guest
/// in nor hand over the keyboard, so what they share keeps its old meaning.
pub fn is_legacy_app(user_agent: &str) -> bool {
    let product = user_agent.split_whitespace().next().unwrap_or("");
    let Some((name, version)) = product.split_once('/') else {
        return false;
    };
    if name.eq_ignore_ascii_case("AceitunoakSSH") || name.eq_ignore_ascii_case("Aceitunoak") {
        return true;
    }
    if name != "Termoak" {
        return false;
    }
    let mut parts = version.split(['.', '-']).map(|p| p.parse::<u64>().ok());
    matches!((parts.next(), parts.next()), (Some(Some(0)), Some(Some(minor))) if minor < 3)
}

/// Longest client description kept.
const CLIENT_MAX: usize = 100;

/// Short description of a client from its `User-Agent`: `Firefox 131 on
/// Linux`, `Safari 18 on iOS`, `Termoak 0.4.0`, `curl 8.5.0`...
pub fn describe_user_agent(ua: &str) -> Option<String> {
    let ua = ua.trim();
    if ua.is_empty() {
        return None;
    }
    let text = if ua.starts_with("Mozilla/") {
        describe_browser(ua)
    } else {
        // Apps and tools: their first product (`Termoak/0.4.0` → `Termoak 0.4.0`).
        let product = ua.split_whitespace().next().unwrap_or(ua);
        product.replacen('/', " ", 1)
    };
    let text: String = text
        .chars()
        .filter(|c| !c.is_control())
        .take(CLIENT_MAX)
        .collect();
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

fn describe_browser(ua: &str) -> String {
    // Major version after `token/`.
    let version = |token: &str| -> Option<String> {
        let start = ua.find(token)? + token.len();
        let v: String = ua[start..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        (!v.is_empty()).then_some(v)
    };
    // The order matters: Edge and Opera also say Chrome, and Chrome says Safari.
    let browsers = [
        ("Edg/", "Edge"),
        ("EdgA/", "Edge"),
        ("EdgiOS/", "Edge"),
        ("OPR/", "Opera"),
        ("SamsungBrowser/", "Samsung Internet"),
        ("Firefox/", "Firefox"),
        ("FxiOS/", "Firefox"),
        ("CriOS/", "Chrome"),
        ("Chrome/", "Chrome"),
    ];
    let browser = browsers
        .iter()
        .find(|(token, _)| ua.contains(token))
        .map(|(token, name)| match version(token) {
            Some(v) => format!("{name} {v}"),
            None => name.to_string(),
        })
        .or_else(|| {
            ua.contains("Safari/").then(|| match version("Version/") {
                Some(v) => format!("Safari {v}"),
                None => "Safari".to_string(),
            })
        })
        .unwrap_or_else(|| "Browser".to_string());
    let os = if ua.contains("Windows") {
        Some("Windows")
    } else if ua.contains("Android") {
        Some("Android")
    } else if ua.contains("iPhone") || ua.contains("iPad") || ua.contains("iPod") {
        Some("iOS")
    } else if ua.contains("CrOS") {
        Some("ChromeOS")
    } else if ua.contains("Macintosh") || ua.contains("Mac OS X") {
        Some("macOS")
    } else if ua.contains("Linux") || ua.contains("X11") {
        Some("Linux")
    } else {
        None
    };
    match os {
        Some(os) => format!("{browser} on {os}"),
        None => browser,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_apps() {
        for ua in [
            "Termoak/0.2.1",
            "Termoak/0.2.0",
            "Termoak/0.1.9",
            "AceitunoakSSH/0.1.4",
        ] {
            assert!(is_legacy_app(ua), "{ua}");
        }
        for ua in [
            "Termoak/0.4.0-next.4",
            "Termoak/0.3.0-next.3",
            "Termoak/1.0.0",
            "Termoak-updater/0.2.1",
            "Termoak",
            "Mozilla/5.0 (X11; Linux x86_64) Termoak/0.2.1",
            "curl/8.5.0",
            "",
        ] {
            assert!(!is_legacy_app(ua), "{ua}");
        }
    }

    #[test]
    fn user_agents() {
        let cases = [
            (
                "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
                "Firefox 131 on Linux",
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
                "Chrome 141 on Windows",
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0",
                "Edge 141 on Windows",
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
                "Safari 18 on macOS",
            ),
            (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
                "Safari 18 on iOS",
            ),
            (
                "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
                "Chrome 141 on Android",
            ),
            ("Termoak/0.4.0-next.4", "Termoak 0.4.0-next.4"),
            ("curl/8.5.0", "curl 8.5.0"),
            ("okhttp/4.12.0", "okhttp 4.12.0"),
        ];
        for (ua, want) in cases {
            assert_eq!(describe_user_agent(ua).as_deref(), Some(want), "{ua}");
        }
        assert_eq!(describe_user_agent("  "), None);
        assert_eq!(
            describe_user_agent(&"x".repeat(500)).map(|s| s.len()),
            Some(CLIENT_MAX)
        );
    }

    #[tokio::test]
    async fn signing_out_closes_the_device_sockets() {
        let sockets = Sockets::new();
        let (user, a, b) = (
            termoak_core::new_id(),
            termoak_core::new_id(),
            termoak_core::new_id(),
        );
        let ga = sockets.register(user, a, SocketKind::Events);
        let gb = sockets.register(user, b, SocketKind::Session);
        assert_eq!(sockets.sign_out_device(a), 1);
        ga.signed_out().await;
        assert!(!gb.signed_out.is_cancelled());
        drop(ga);
        assert_eq!(sockets.count_for_device(a), 0);
        assert_eq!(sockets.sign_out_user_events(user), 0);
        assert_eq!(sockets.sign_out_user(user), 1);
        gb.signed_out().await;
    }
}
