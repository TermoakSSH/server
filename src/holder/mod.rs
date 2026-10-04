//! Session holder: a separate process (`termoak-server sessions-holder`)
//! that keeps the SSH connections of the server sessions, so updating or
//! restarting the server does not cut them.
//!
//! It is optional: without `[sessions] holder_socket`, sessions live in the
//! server itself (and are closed when it restarts).

pub mod client;
pub mod daemon;
pub mod proto;

pub use client::HolderClient;
