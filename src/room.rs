//! Who is in a shared session and who has the keyboard.
//!
//! - **Participants** are people, not sockets: the same user on two devices
//!   (or a link guest that reconnects with the same `guest` key) is one
//!   participant with two devices.
//! - **One driver at a time**: the owner can always type; other participants
//!   join read-only and type only while they hold the keyboard (`driver`).
//!   The share permission is the most the owner can hand over: `view` never
//!   drives, `control` can ask for (and receive) the keyboard.
//! - **Waiting room**: with `require_approval`, whoever joins waits until the
//!   owner lets them in.
//!
//! Everything here is synchronous and in memory (under the session's lock);
//! [`crate::sessions::LiveSession`] sends the signals and the routes do the
//! audit and the notices.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use termoak_core::{Id, new_id};

use crate::sessions::{Access, Viewer};

/// Maximum length of a display name.
pub const MAX_NAME: usize = 40;

/// Kind of participant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantKind {
    Owner,
    /// A user of this server (invited directly, through a team or with a link).
    User,
    /// Someone without an account who joined with a link.
    Guest,
}

impl ParticipantKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ParticipantKind::Owner => "owner",
            ParticipantKind::User => "user",
            ParticipantKind::Guest => "guest",
        }
    }
}

/// Why a socket is sent away: a stable code on the `error` message and on
/// the WebSocket close frame (`4000 + n`, reason = the code).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndCode {
    /// The share was revoked (or sharing stopped, or the account is gone).
    Revoked,
    /// The owner kicked them out.
    Kicked,
    /// The share expired.
    Expired,
    /// The session ended.
    SessionEnded,
    /// The owner did not let them in.
    JoinDenied,
    /// No access.
    Forbidden,
}

impl EndCode {
    pub fn as_str(self) -> &'static str {
        match self {
            EndCode::Revoked => "revoked",
            EndCode::Kicked => "kicked",
            EndCode::Expired => "expired",
            EndCode::SessionEnded => "session_ended",
            EndCode::JoinDenied => "join_denied",
            EndCode::Forbidden => "forbidden",
        }
    }

    /// WebSocket close code (private range 4000-4999).
    pub fn close_code(self) -> u16 {
        match self {
            EndCode::Revoked => 4001,
            EndCode::Kicked => 4002,
            EndCode::Expired => 4003,
            EndCode::SessionEnded => 4004,
            EndCode::JoinDenied => 4005,
            EndCode::Forbidden => 4006,
        }
    }

    /// English text (older clients show it as is: keep the words "revoked"
    /// and "access" they look for).
    pub fn message(self) -> &'static str {
        match self {
            EndCode::Revoked => "your access to this session has been revoked",
            EndCode::Kicked => "the owner removed you from this session; you no longer have access",
            EndCode::Expired => "your access to this session has expired",
            EndCode::SessionEnded => "the session has ended",
            EndCode::JoinDenied => {
                "the owner did not let you in; you have no access to this session"
            }
            EndCode::Forbidden => "you no longer have access to this session",
        }
    }
}

/// What a share gives someone (the best one they have).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub share_id: Id,
    /// `Control` or `View`.
    pub access: Access,
    pub expires_at: Option<i64>,
    pub require_approval: bool,
    pub auto_grant: bool,
    /// A link share.
    pub link: bool,
}

/// Someone opening a socket.
#[derive(Debug, Clone)]
pub struct Joiner {
    pub kind: ParticipantKind,
    pub name: String,
    pub user_id: Option<Id>,
    /// `None` for the owner.
    pub grant: Option<Grant>,
    /// Link guests: key the client keeps between reconnects (so they stay
    /// the same participant).
    pub guest_key: Option<String>,
    /// Client that does not speak protocol 2 (no `proto=2`).
    pub legacy: bool,
    /// Host of a relay session.
    pub host: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    User(Id),
    Guest(Id, String),
    /// Guest without a key: each socket is a different person.
    Socket(Id),
}

#[derive(Debug)]
struct Person {
    id: Id,
    key: Key,
    name: String,
    kind: ParticipantKind,
    user_id: Option<Id>,
    grant: Option<Grant>,
    /// Let in (always, without a waiting room).
    admitted: bool,
    /// Sockets: id → (viewer data, legacy).
    sockets: HashMap<Id, (Viewer, bool)>,
    /// Since when they are present (first socket after being away).
    since: i64,
    /// Announced as joined (and not yet as left).
    present: bool,
    requested_control: bool,
    /// The owner took the keyboard away from them (or said no): an older
    /// client that types does not get it back by itself.
    legacy_blocked: bool,
    /// Bumped on every socket that arrives (cancels a pending leave).
    epoch: u64,
}

impl Person {
    fn access(&self) -> Access {
        match self.kind {
            ParticipantKind::Owner => Access::Owner,
            _ => self.grant.as_ref().map_or(Access::View, |g| g.access),
        }
    }

    fn can_drive(&self) -> bool {
        self.admitted && self.access() == Access::Control
    }
}

/// Result of [`Room::join`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Joined {
    pub participant: Id,
    pub admitted: bool,
    /// They were not present: announce (audit) the join.
    pub first: bool,
    /// A new join request for the owner.
    pub new_request: bool,
}

/// Result of [`Room::leave`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Left {
    pub participant: Id,
    /// It was their last socket.
    pub empty: bool,
    /// Value to pass to [`Room::finish_leave`].
    pub epoch: u64,
    /// They were in the waiting room (they are gone now).
    pub was_waiting: bool,
}

/// Someone who left for good (after the grace period).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gone {
    pub participant: Id,
    pub name: String,
    pub kind: ParticipantKind,
    pub user_id: Option<Id>,
    pub was_driver: bool,
}

/// A participant's data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonInfo {
    pub participant: Id,
    pub name: String,
    pub kind: ParticipantKind,
    pub user_id: Option<Id>,
    pub share_id: Option<Id>,
    pub link: bool,
    pub access: Access,
    pub admitted: bool,
}

/// Result of a request for the keyboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// They already drive (or are the owner).
    Already,
    /// Granted (`auto_grant`); `previous`: participant who lost it.
    Granted { previous: Option<Id> },
    /// Waiting for the owner; `new` if it was not asked already.
    Asked { new: bool },
    /// Their share does not allow it (view only) or they are not in yet.
    Forbidden,
}

/// Result of applying a share change to a participant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied {
    Unchanged,
    /// Access changed; `lost_drive`: they were driving and cannot any more.
    Changed {
        lost_drive: bool,
    },
    /// No share left: they were removed.
    Removed,
}

/// A participant as clients see it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParticipantView {
    pub id: Id,
    pub name: String,
    pub kind: ParticipantKind,
    pub access: Access,
    pub is_driver: bool,
    pub since: i64,
    /// Sockets attached (0 while reconnecting).
    pub devices: usize,
    pub requested_control: bool,
    /// In the waiting room (only in the owner's list).
    pub waiting: bool,
    /// It is whoever receives the list.
    pub you: bool,
    /// Owner's view only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Id>,
    /// Owner's view only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_id: Option<Id>,
}

/// Cleans a display name: no control or direction characters, single
/// spaces, at most [`MAX_NAME`] characters. `None` if nothing is left.
pub fn clean_name(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .filter(|c| {
            !c.is_control()
                && !matches!(*c as u32, 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x206F | 0xFEFF)
        })
        .collect();
    let words: Vec<&str> = cleaned.split(' ').filter(|w| !w.is_empty()).collect();
    let name: String = words.join(" ").chars().take(MAX_NAME).collect();
    let name = name.trim().to_string();
    (!name.is_empty()).then_some(name)
}

/// A link guest's key: 8-64 letters, digits, `-` or `_`.
pub fn clean_guest_key(raw: &str) -> Option<String> {
    let k = raw.trim();
    ((8..=64).contains(&k.len())
        && k.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
    .then(|| k.to_string())
}

/// Participants and keyboard of a session.
#[derive(Debug, Default)]
pub struct Room {
    persons: HashMap<Id, Person>,
    keys: HashMap<Key, Id>,
    /// Socket → participant.
    sockets: HashMap<Id, Id>,
    /// Participant with the keyboard (`None`: the owner).
    driver: Option<Id>,
    /// Guests named so far (for "Guest N").
    guests: u32,
}

impl Room {
    pub fn driver(&self) -> Option<Id> {
        self.driver
    }

    /// A socket arrives.
    pub fn join(&mut self, socket: Id, j: Joiner, now: i64) -> Joined {
        let key = match (j.kind, j.user_id, &j.guest_key, &j.grant) {
            (ParticipantKind::Guest, _, Some(k), Some(g)) => Key::Guest(g.share_id, k.clone()),
            (ParticipantKind::Guest, ..) | (_, None, ..) => Key::Socket(socket),
            (_, Some(u), ..) => Key::User(u),
        };
        let pid = match self.keys.get(&key) {
            Some(pid) => *pid,
            None => {
                let pid = new_id();
                let name = match j.kind {
                    ParticipantKind::Guest => clean_name(&j.name).unwrap_or_else(|| {
                        self.guests += 1;
                        format!("Guest {}", self.guests)
                    }),
                    _ => j.name.clone(),
                };
                let admitted = j.kind == ParticipantKind::Owner
                    || !j.grant.as_ref().is_some_and(|g| g.require_approval);
                self.persons.insert(
                    pid,
                    Person {
                        id: pid,
                        key: key.clone(),
                        name,
                        kind: j.kind,
                        user_id: j.user_id,
                        grant: j.grant.clone(),
                        admitted,
                        sockets: HashMap::new(),
                        since: now,
                        present: false,
                        requested_control: false,
                        legacy_blocked: false,
                        epoch: 0,
                    },
                );
                self.keys.insert(key, pid);
                pid
            }
        };
        let p = self.persons.get_mut(&pid).expect("participant just found");
        // The best share of this socket (a user may come with a link too).
        if p.kind != ParticipantKind::Owner
            && let Some(g) = j.grant
            && p.grant.as_ref().is_none_or(|old| better(&g, old))
        {
            if !g.require_approval {
                p.admitted = true;
            }
            p.grant = Some(g);
        }
        let viewer = Viewer {
            id: socket,
            name: p.name.clone(),
            user_id: j.user_id,
            access: p.access(),
            role: if j.host {
                "host".into()
            } else {
                "viewer".into()
            },
            since: now,
            share_id: p.grant.as_ref().map(|g| g.share_id),
            participant: Some(pid),
        };
        let was_empty = p.sockets.is_empty();
        p.sockets.insert(socket, (viewer, j.legacy));
        p.epoch += 1;
        self.sockets.insert(socket, pid);
        let first = p.admitted && !p.present;
        if first {
            p.present = true;
            p.since = now;
        }
        Joined {
            participant: pid,
            admitted: p.admitted,
            first,
            new_request: !p.admitted && was_empty,
        }
    }

    /// A socket goes away.
    pub fn leave(&mut self, socket: Id) -> Option<Left> {
        let pid = self.sockets.remove(&socket)?;
        let p = self.persons.get_mut(&pid)?;
        p.sockets.remove(&socket);
        let empty = p.sockets.is_empty();
        let was_waiting = !p.admitted;
        if empty && was_waiting {
            // Whoever leaves the waiting room is not waiting any more.
            self.remove(pid);
        }
        Some(Left {
            participant: pid,
            empty,
            epoch: self.persons.get(&pid).map_or(0, |p| p.epoch),
            was_waiting,
        })
    }

    /// After the grace period: if they did not come back, they left (they
    /// lose the keyboard and any pending request).
    pub fn finish_leave(&mut self, pid: Id, epoch: u64) -> Option<Gone> {
        let p = self.persons.get_mut(&pid)?;
        if !p.sockets.is_empty() || p.epoch != epoch || !p.present {
            return None;
        }
        p.present = false;
        p.requested_control = false;
        let was_driver = self.driver == Some(pid);
        if was_driver {
            self.driver = None;
        }
        Some(Gone {
            participant: pid,
            name: p.name.clone(),
            kind: p.kind,
            user_id: p.user_id,
            was_driver,
        })
    }

    fn remove(&mut self, pid: Id) -> Option<Person> {
        let p = self.persons.remove(&pid)?;
        self.keys.remove(&p.key);
        if self.driver == Some(pid) {
            self.driver = None;
        }
        Some(p)
    }

    pub fn participant_of(&self, socket: Id) -> Option<Id> {
        self.sockets.get(&socket).copied()
    }

    pub fn info(&self, pid: Id) -> Option<PersonInfo> {
        self.persons.get(&pid).map(|p| PersonInfo {
            participant: pid,
            name: p.name.clone(),
            kind: p.kind,
            user_id: p.user_id,
            share_id: p.grant.as_ref().map(|g| g.share_id),
            link: p.grant.as_ref().is_some_and(|g| g.link),
            access: p.access(),
            admitted: p.admitted,
        })
    }

    pub fn is_admitted(&self, pid: Id) -> bool {
        self.persons.get(&pid).is_some_and(|p| p.admitted)
    }

    /// Their input and resizes reach the terminal.
    pub fn can_write(&self, pid: Id) -> bool {
        self.persons.get(&pid).is_some_and(|p| {
            p.kind == ParticipantKind::Owner || (self.driver == Some(pid) && p.can_drive())
        })
    }

    pub fn name_of_driver(&self) -> Option<String> {
        self.driver
            .and_then(|d| self.persons.get(&d))
            .map(|p| p.name.clone())
    }

    /// Changes a guest's name.
    pub fn set_name(&mut self, pid: Id, raw: &str) -> bool {
        let Some(name) = clean_name(raw) else {
            return false;
        };
        match self.persons.get_mut(&pid) {
            Some(p) if p.kind == ParticipantKind::Guest && p.name != name => {
                p.name = name.clone();
                for (v, _) in p.sockets.values_mut() {
                    v.name = name.clone();
                }
                true
            }
            _ => false,
        }
    }

    /// The owner lets someone in.
    pub fn admit(&mut self, pid: Id, now: i64) -> bool {
        match self.persons.get_mut(&pid) {
            Some(p) if !p.admitted => {
                p.admitted = true;
                if !p.sockets.is_empty() {
                    p.present = true;
                    p.since = now;
                }
                true
            }
            _ => false,
        }
    }

    /// The owner does not let someone in: they are removed.
    pub fn deny(&mut self, pid: Id) -> Option<PersonInfo> {
        let info = self.info(pid).filter(|i| !i.admitted)?;
        self.remove(pid);
        Some(info)
    }

    /// Someone is sent away (kicked, revoked, expired): they are removed.
    pub fn kick(&mut self, pid: Id) -> Option<PersonInfo> {
        let info = self
            .info(pid)
            .filter(|i| i.kind != ParticipantKind::Owner)?;
        self.remove(pid);
        Some(info)
    }

    /// A participant asks for the keyboard (`legacy`: an older client typed).
    pub fn request_control(&mut self, pid: Id, legacy: bool) -> Request {
        let driver = self.driver;
        let Some(p) = self.persons.get_mut(&pid) else {
            return Request::Forbidden;
        };
        if p.kind == ParticipantKind::Owner || driver == Some(pid) {
            return Request::Already;
        }
        if !p.can_drive() {
            return Request::Forbidden;
        }
        let auto = p.grant.as_ref().is_some_and(|g| g.auto_grant);
        // Older clients cannot ask: typing takes the keyboard when nobody
        // else has it (as before), unless the owner took it away from them.
        let legacy_take = legacy && !p.legacy_blocked && driver.is_none();
        if auto || legacy_take {
            p.requested_control = false;
            p.legacy_blocked = false;
            self.driver = Some(pid);
            return Request::Granted { previous: driver };
        }
        if p.requested_control {
            return Request::Asked { new: false };
        }
        p.requested_control = true;
        Request::Asked { new: true }
    }

    /// The driver gives the keyboard back (or someone withdraws a request).
    pub fn release_control(&mut self, pid: Id) -> bool {
        let mut changed = false;
        if let Some(p) = self.persons.get_mut(&pid)
            && p.requested_control
        {
            p.requested_control = false;
            changed = true;
        }
        if self.driver == Some(pid) {
            self.driver = None;
            changed = true;
        }
        changed
    }

    /// The owner hands the keyboard to someone. `Err` with an error code.
    pub fn grant(&mut self, pid: Id) -> Result<Option<Id>, &'static str> {
        let previous = self.driver;
        let p = self.persons.get_mut(&pid).ok_or("participant_not_found")?;
        if p.kind == ParticipantKind::Owner {
            self.driver = None;
            return Ok(previous);
        }
        if !p.can_drive() {
            return Err("forbidden");
        }
        p.requested_control = false;
        p.legacy_blocked = false;
        self.driver = Some(pid);
        Ok(previous.filter(|d| *d != pid))
    }

    /// The owner says no to a request.
    pub fn deny_control(&mut self, pid: Id) -> bool {
        match self.persons.get_mut(&pid) {
            Some(p) if p.requested_control => {
                p.requested_control = false;
                p.legacy_blocked = true;
                true
            }
            _ => false,
        }
    }

    /// The owner takes the keyboard back. Returns who had it.
    pub fn take(&mut self) -> Option<Id> {
        let previous = self.driver.take()?;
        if let Some(p) = self.persons.get_mut(&previous) {
            p.legacy_blocked = true;
        }
        Some(previous)
    }

    /// Participants who joined with a share or are users (to re-check
    /// their access), except the owner.
    pub fn guests(&self) -> Vec<PersonInfo> {
        self.persons
            .keys()
            .filter_map(|pid| self.info(*pid))
            .filter(|i| i.kind != ParticipantKind::Owner)
            .collect()
    }

    /// Applies the best share someone has now (`None`: no access left).
    pub fn apply(&mut self, pid: Id, grant: Option<Grant>) -> Applied {
        let Some(g) = grant else {
            return match self.kick(pid) {
                Some(_) => Applied::Removed,
                None => Applied::Unchanged,
            };
        };
        let driver = self.driver;
        let Some(p) = self.persons.get_mut(&pid) else {
            return Applied::Unchanged;
        };
        if p.grant.as_ref() == Some(&g) {
            return Applied::Unchanged;
        }
        let access = g.access;
        for (v, _) in p.sockets.values_mut() {
            v.access = access;
            v.share_id = Some(g.share_id);
        }
        p.grant = Some(g);
        let mut lost_drive = false;
        if access != Access::Control {
            p.requested_control = false;
            if driver == Some(pid) {
                self.driver = None;
                lost_drive = true;
            }
        }
        Applied::Changed { lost_drive }
    }

    /// Participants whose share expired at `now`.
    pub fn expired(&self, now: i64) -> Vec<Id> {
        self.persons
            .values()
            .filter(|p| {
                p.grant
                    .as_ref()
                    .and_then(|g| g.expires_at)
                    .is_some_and(|e| e <= now)
            })
            .map(|p| p.id)
            .collect()
    }

    /// Participants who joined with a given share.
    pub fn with_share(&self, share_id: Id) -> Vec<Id> {
        self.persons
            .values()
            .filter(|p| p.grant.as_ref().is_some_and(|g| g.share_id == share_id))
            .map(|p| p.id)
            .collect()
    }

    /// Participants of a user (none or one).
    pub fn of_user(&self, user: Id) -> Option<Id> {
        self.keys.get(&Key::User(user)).copied()
    }

    /// A user has a socket in (and was let in).
    pub fn is_watching(&self, user: Id) -> bool {
        self.of_user(user)
            .and_then(|pid| self.persons.get(&pid))
            .is_some_and(|p| p.admitted && !p.sockets.is_empty())
    }

    /// Admitted sockets (the old `presence` list and the session's `viewers`).
    pub fn viewers(&self) -> Vec<Viewer> {
        let mut v: Vec<Viewer> = self
            .persons
            .values()
            .filter(|p| p.admitted)
            .flat_map(|p| p.sockets.values().map(|(v, _)| v.clone()))
            .collect();
        v.sort_by_key(|x| x.since);
        v
    }

    pub fn socket_count(&self) -> usize {
        self.sockets.len()
    }

    /// The list a participant (`me`) receives. The owner also sees who is
    /// waiting, user ids and share ids.
    pub fn participants(&self, owner_view: bool, me: Option<Id>) -> Vec<ParticipantView> {
        let mut list: Vec<ParticipantView> = self
            .persons
            .values()
            .filter(|p| p.present || (owner_view && !p.admitted && !p.sockets.is_empty()))
            .map(|p| ParticipantView {
                id: p.id,
                name: p.name.clone(),
                kind: p.kind,
                access: p.access(),
                is_driver: match p.kind {
                    ParticipantKind::Owner => self.driver.is_none(),
                    _ => self.driver == Some(p.id),
                },
                since: p.since,
                devices: p.sockets.len(),
                requested_control: p.requested_control,
                waiting: !p.admitted,
                you: me == Some(p.id),
                user_id: if owner_view { p.user_id } else { None },
                share_id: if owner_view {
                    p.grant.as_ref().map(|g| g.share_id)
                } else {
                    None
                },
            })
            .collect();
        list.sort_by_key(|p| (p.kind != ParticipantKind::Owner, p.waiting, p.since));
        list
    }

    /// Pending join requests (for an owner socket that arrives).
    pub fn waiting(&self) -> Vec<ParticipantView> {
        self.participants(true, None)
            .into_iter()
            .filter(|p| p.waiting)
            .collect()
    }

    /// Pending requests for the keyboard.
    pub fn control_requests(&self) -> Vec<ParticipantView> {
        self.participants(true, None)
            .into_iter()
            .filter(|p| p.requested_control)
            .collect()
    }

    pub fn view_of(&self, pid: Id, owner_view: bool) -> Option<ParticipantView> {
        self.participants(owner_view, None)
            .into_iter()
            .find(|p| p.id == pid)
    }

    /// Present participants (for counts).
    pub fn present_count(&self) -> usize {
        self.persons.values().filter(|p| p.present).count()
    }

    /// Sockets of everyone except the owner.
    pub fn guest_sockets(&self) -> HashSet<Id> {
        self.persons
            .values()
            .filter(|p| p.kind != ParticipantKind::Owner)
            .flat_map(|p| p.sockets.keys().copied())
            .collect()
    }
}

/// `a` gives more than `b`: more permission or, the same, without a
/// waiting room.
pub fn better(a: &Grant, b: &Grant) -> bool {
    let rank = |g: &Grant| (g.access == Access::Control, !g.require_approval, !g.link);
    rank(a) > rank(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(access: Access, approval: bool, auto: bool) -> Grant {
        Grant {
            share_id: new_id(),
            access,
            expires_at: None,
            require_approval: approval,
            auto_grant: auto,
            link: approval,
        }
    }

    fn owner(id: Id) -> Joiner {
        Joiner {
            kind: ParticipantKind::Owner,
            name: "Ana".into(),
            user_id: Some(id),
            grant: None,
            guest_key: None,
            legacy: false,
            host: false,
        }
    }

    fn user(id: Id, g: &Grant, legacy: bool) -> Joiner {
        Joiner {
            kind: ParticipantKind::User,
            name: "Bea".into(),
            user_id: Some(id),
            grant: Some(g.clone()),
            guest_key: None,
            legacy,
            host: false,
        }
    }

    fn guest(g: &Grant, name: &str, key: Option<&str>) -> Joiner {
        Joiner {
            kind: ParticipantKind::Guest,
            name: name.into(),
            user_id: None,
            grant: Some(g.clone()),
            guest_key: key.map(str::to_string),
            legacy: false,
            host: false,
        }
    }

    #[test]
    fn names_are_cleaned() {
        assert_eq!(
            clean_name("  Ana \n  María\u{202E} "),
            Some("Ana María".into())
        );
        assert_eq!(clean_name("\u{7}\t "), None);
        assert_eq!(
            clean_name(&"x".repeat(100)).unwrap().chars().count(),
            MAX_NAME
        );
        assert_eq!(clean_guest_key("abcdefgh-123"), Some("abcdefgh-123".into()));
        assert_eq!(clean_guest_key("short"), None);
        assert_eq!(clean_guest_key("bad key with spaces"), None);
    }

    #[test]
    fn one_driver_at_a_time() {
        let mut room = Room::default();
        let (ana, bea) = (new_id(), new_id());
        let control = grant(Access::Control, false, false);
        let o = room.join(new_id(), owner(ana), 1).participant;
        let b = room.join(new_id(), user(bea, &control, false), 2);
        assert!(b.admitted && b.first);
        let b = b.participant;
        // The owner always types; Bea joins read-only.
        assert!(room.can_write(o));
        assert!(!room.can_write(b));
        assert_eq!(room.request_control(b, false), Request::Asked { new: true });
        assert_eq!(
            room.request_control(b, false),
            Request::Asked { new: false }
        );
        assert_eq!(room.grant(b), Ok(None));
        assert!(room.can_write(b) && room.can_write(o));
        assert_eq!(room.driver(), Some(b));
        // The owner takes it back.
        assert_eq!(room.take(), Some(b));
        assert!(!room.can_write(b));
        // A view-only guest can never drive.
        let view = grant(Access::View, true, false);
        let g = room.join(new_id(), guest(&view, "Zoe", None), 3);
        assert!(!g.admitted && g.new_request);
        assert!(room.admit(g.participant, 4));
        assert_eq!(
            room.request_control(g.participant, false),
            Request::Forbidden
        );
        assert_eq!(room.grant(g.participant), Err("forbidden"));
        // Two sockets of the same user are one participant.
        let again = room.join(new_id(), user(bea, &control, false), 5);
        assert_eq!(again.participant, b);
        assert!(!again.first);
        let list = room.participants(false, Some(b));
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].kind, ParticipantKind::Owner);
        assert!(list[0].is_driver);
        let me = list.iter().find(|p| p.you).unwrap();
        assert_eq!(me.devices, 2);
        assert!(
            list.iter()
                .all(|p| p.user_id.is_none() && p.share_id.is_none())
        );
        assert!(
            room.participants(true, None)
                .iter()
                .any(|p| p.user_id == Some(bea))
        );
    }

    #[test]
    fn auto_grant_and_older_clients() {
        let mut room = Room::default();
        let auto = grant(Access::Control, false, true);
        let a = room
            .join(new_id(), user(new_id(), &auto, false), 1)
            .participant;
        let plain = grant(Access::Control, false, false);
        let old = room
            .join(new_id(), user(new_id(), &plain, true), 1)
            .participant;
        // An older client that types takes the free keyboard.
        assert_eq!(
            room.request_control(old, true),
            Request::Granted { previous: None }
        );
        // With auto_grant it is granted at once, even if someone drives.
        assert_eq!(
            room.request_control(a, false),
            Request::Granted {
                previous: Some(old)
            }
        );
        // The older client asks instead of taking it from someone.
        assert_eq!(
            room.request_control(old, true),
            Request::Asked { new: true }
        );
        assert!(room.deny_control(old));
        room.release_control(a);
        // Refused: typing does not take it back by itself.
        assert_eq!(
            room.request_control(old, true),
            Request::Asked { new: true }
        );
        assert_eq!(room.grant(old), Ok(None));
        assert!(room.can_write(old));
    }

    #[test]
    fn waiting_room_leave_and_reconnect() {
        let mut room = Room::default();
        let link = grant(Access::Control, true, false);
        let s1 = new_id();
        let j = room.join(s1, guest(&link, "", Some("key-0123456")), 1);
        assert!(!j.admitted && j.new_request);
        assert_eq!(room.waiting().len(), 1);
        assert!(room.participants(false, None).is_empty());
        assert!(
            room.info(j.participant)
                .unwrap()
                .name
                .starts_with("Guest 1")
        );
        // Leaving the waiting room removes the request.
        let left = room.leave(s1).unwrap();
        assert!(left.was_waiting && left.empty);
        assert!(room.waiting().is_empty());
        // Comes back, is let in, drives, drops and reconnects with the same key.
        let s2 = new_id();
        let pid = room
            .join(s2, guest(&link, "Zoe", Some("key-0123456")), 2)
            .participant;
        assert!(room.admit(pid, 3));
        assert_eq!(room.grant(pid), Ok(None));
        let left = room.leave(s2).unwrap();
        assert!(left.empty && !left.was_waiting);
        let back = room.join(new_id(), guest(&link, "Zoe", Some("key-0123456")), 4);
        assert_eq!(back.participant, pid);
        assert!(back.admitted && !back.first);
        // The pending leave is cancelled; they still drive.
        assert_eq!(room.finish_leave(pid, left.epoch), None);
        assert!(room.can_write(pid));
        // Gone for good: loses the keyboard.
        let s = room.persons[&pid].sockets.keys().next().copied().unwrap();
        let left = room.leave(s).unwrap();
        let gone = room.finish_leave(pid, left.epoch).unwrap();
        assert!(gone.was_driver);
        assert_eq!(room.driver(), None);
    }

    #[test]
    fn share_changes_and_expiry() {
        let mut room = Room::default();
        let mut g = grant(Access::Control, false, false);
        g.expires_at = Some(100);
        let pid = room
            .join(new_id(), user(new_id(), &g, false), 1)
            .participant;
        assert_eq!(room.grant(pid), Ok(None));
        let mut down = g.clone();
        down.access = Access::View;
        assert_eq!(
            room.apply(pid, Some(down)),
            Applied::Changed { lost_drive: true }
        );
        assert!(!room.can_write(pid));
        assert_eq!(room.expired(99), Vec::<Id>::new());
        assert_eq!(room.expired(100), vec![pid]);
        assert_eq!(room.apply(pid, None), Applied::Removed);
        assert!(room.info(pid).is_none());
    }
}
