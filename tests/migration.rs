//! Migration v9 (vaults) on a realistic schema-v8 database: every user gets
//! a personal vault with their entities, nothing else changes, the server
//! starts on it, old apps keep syncing and the legacy secrets are resealed
//! with vault keys in the background.
//!
//! `migration_on_a_copy` (ignored) runs the migration on a copy of a real
//! database: `TERMOAK_MIGRATION_DB=/path/to/termoak.db cargo test --test
//! migration -- --ignored --nocapture`. It never touches the original and
//! needs no master key.

mod common;

use std::path::Path;
use std::time::Instant;

use common::srv::User;
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use termoak_core::crypto::{LEGACY_AAD_PREFIX, MasterKey, hash_password};
use termoak_core::new_id;
use termoak_server::config::ServerConfig;
use termoak_server::{build_state, routes};

const USERS: usize = 40;
const HOSTS_PER_USER: usize = 25;

/// Fills a v8 database: users (one disabled), teams with members, hosts
/// with passwords, keys, snippets, sessions, audit and AI tasks.
fn fill_v8(path: &Path, key: &MasterKey) -> Vec<(String, String)> {
    termoak_core::store::create_at_version(path, 8).unwrap();
    let c = Connection::open(path).unwrap();
    let hash = hash_password("secure-password").unwrap();
    let mut users = Vec::new();
    let mut rev = 0i64;
    for u in 0..USERS {
        let id = new_id().to_string();
        let email = format!("user{u}@termoak.test");
        c.execute(
            "INSERT INTO users (id, email, name, password_hash, is_admin, disabled, created_at,
                                email_verified)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1000, 1)",
            params![
                id,
                email,
                format!("User {u}"),
                hash,
                (u == 0) as i64,
                (u == 7) as i64
            ],
        )
        .unwrap();
        let seal = |kind: &str, eid: &str, secret: Value| -> Vec<u8> {
            key.seal(
                secret.to_string().as_bytes(),
                format!("{LEGACY_AAD_PREFIX}:{kind}:{eid}").as_bytes(),
            )
            .unwrap()
        };
        let kid = new_id().to_string();
        rev += 1;
        c.execute(
            "INSERT INTO entities (id, owner_id, kind, data, secret, rev, updated_at)
             VALUES (?1, ?2, 'key', ?3, ?4, ?5, 1000)",
            params![
                kid,
                id,
                json!({"label": "k", "algorithm": "ssh-ed25519", "public_key": "ssh-ed25519 AAAA",
                       "fingerprint": format!("SHA256:{u}")})
                .to_string(),
                seal("key", &kid, json!({"private_key": format!("PRIVATE-{u}")})),
                rev
            ],
        )
        .unwrap();
        for h in 0..HOSTS_PER_USER {
            let hid = new_id().to_string();
            rev += 1;
            c.execute(
                "INSERT INTO entities (id, owner_id, kind, data, secret, rev, updated_at)
                 VALUES (?1, ?2, 'host', ?3, ?4, ?5, 1000)",
                params![
                    hid,
                    id,
                    json!({"label": format!("h{h}"), "address": format!("10.0.{u}.{h}"),
                           "settings": {"username": "root", "key_id": kid}})
                    .to_string(),
                    seal("host", &hid, json!({"password": format!("pw-{u}-{h}")})),
                    rev
                ],
            )
            .unwrap();
        }
        rev += 1;
        c.execute(
            "INSERT INTO entities (id, owner_id, kind, data, rev, updated_at, deleted)
             VALUES (?1, ?2, 'snippet', '{}', ?3, 1000, 1)",
            params![new_id().to_string(), id, rev],
        )
        .unwrap();
        c.execute(
            "INSERT INTO sessions (id, owner_id, title, status, kind, created_at)
             VALUES (?1, ?2, 't', 'closed', 'server', 1000)",
            params![new_id().to_string(), id],
        )
        .unwrap();
        c.execute(
            "INSERT INTO audit_log (owner_id, actor, action, created_at)
             VALUES (?1, ?2, 'session.open', 1000)",
            params![id, format!("user:{id}")],
        )
        .unwrap();
        users.push((id, email));
    }
    for t in 0..5 {
        let tid = new_id().to_string();
        c.execute(
            "INSERT INTO teams (id, name, created_by, created_at) VALUES (?1, ?2, ?3, 1000)",
            params![tid, format!("Team {t}"), users[t].0],
        )
        .unwrap();
        for (i, (uid, _)) in users.iter().enumerate().skip(t).take(6) {
            c.execute(
                "INSERT INTO team_members (team_id, user_id, role, added_at) VALUES (?1, ?2, ?3, 1000)",
                params![tid, uid, if i == t { "owner" } else { "member" }],
            )
            .unwrap();
        }
    }
    c.execute(
        "UPDATE meta SET value = ?1 WHERE key = 'rev'",
        [rev.to_string()],
    )
    .unwrap();
    users
}

fn count(c: &Connection, sql: &str) -> i64 {
    c.query_row(sql, [], |r| r.get(0)).unwrap()
}

/// Invariants after v9 (also used on real copies).
fn check_v9(c: &Connection) {
    let users = count(c, "SELECT COUNT(*) FROM users");
    assert_eq!(
        count(
            c,
            "SELECT COUNT(*) FROM vaults WHERE kind = 'personal' AND id = owner_user_id"
        ),
        users,
        "one personal vault per user (id = user id)"
    );
    assert_eq!(
        count(c, "SELECT COUNT(*) FROM vaults WHERE kind <> 'personal'"),
        0,
        "teams get no vault in the migration"
    );
    assert_eq!(
        count(
            c,
            "SELECT COUNT(*) FROM entities WHERE owner_id IN (SELECT id FROM users)
             AND (vault_id IS NULL OR vault_id <> owner_id)"
        ),
        0,
        "every entity of a user is in their personal vault"
    );
    assert_eq!(count(c, "SELECT COUNT(*) FROM vault_members"), 0);
    assert_eq!(count(c, "SELECT COUNT(*) FROM entity_departures"), 0);
    let v: i64 = c
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(v as usize, termoak_core::store::schema_version());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn migration_v9_on_a_realistic_database() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let data = tempfile::tempdir().unwrap();
    let db = data.path().join("termoak.db");
    let key = MasterKey::generate();
    std::fs::write(data.path().join("master.key"), key.to_base64().as_bytes()).unwrap();
    let users = fill_v8(&db, &key);
    let before = {
        let c = Connection::open(&db).unwrap();
        (
            count(&c, "SELECT COUNT(*) FROM entities"),
            count(&c, "SELECT COUNT(*) FROM sessions"),
            count(&c, "SELECT COUNT(*) FROM audit_log"),
            count(&c, "SELECT COUNT(*) FROM team_members"),
        )
    };

    // The server starts on it (migration + background reseal).
    let started = Instant::now();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut config = ServerConfig::default();
    config.server.listen = addr;
    config.server.data_dir = data.path().to_path_buf();
    let state = build_state(config).await.unwrap();
    eprintln!(
        "v8 → v9 with {} entities: {:?}",
        before.0,
        started.elapsed()
    );
    tokio::spawn(async move { axum::serve(listener, routes::router(state)).await.unwrap() });
    let base = format!("http://{addr}");
    {
        let c = Connection::open(&db).unwrap();
        check_v9(&c);
        assert_eq!(count(&c, "SELECT COUNT(*) FROM entities"), before.0);
        assert_eq!(count(&c, "SELECT COUNT(*) FROM sessions"), before.1);
        assert_eq!(count(&c, "SELECT COUNT(*) FROM audit_log"), before.2);
        assert_eq!(count(&c, "SELECT COUNT(*) FROM team_members"), before.3);
    }

    // The background job reseals every legacy secret with the vault keys.
    let mut legacy = i64::MAX;
    for _ in 0..200 {
        let c = Connection::open(&db).unwrap();
        legacy = count(
            &c,
            "SELECT COUNT(*) FROM entities WHERE secret IS NOT NULL AND key_version IS NULL",
        );
        if legacy == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(legacy, 0);
    {
        let c = Connection::open(&db).unwrap();
        assert_eq!(
            count(&c, "SELECT COUNT(*) FROM vault_keys"),
            USERS as i64,
            "one key per personal vault with secrets"
        );
    }

    // A user signs in: their hosts, secrets and the legacy sync are intact.
    let http = reqwest::Client::new();
    let (uid, email) = &users[3];
    let login: Value = http
        .post(format!("{base}/api/v1/auth/login"))
        .json(&json!({"email": email, "password": "secure-password", "platform": "cli"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let u = User {
        token: login["tokens"]["access_token"].as_str().unwrap().into(),
        id: uid.clone(),
        email: email.clone(),
    };
    let get = |path: String| {
        let http = http.clone();
        let token = u.token.clone();
        async move {
            http.get(path)
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    let hosts = get(format!("{base}/api/v1/hosts")).await;
    assert_eq!(hosts.as_array().unwrap().len(), HOSTS_PER_USER);
    assert!(
        hosts
            .as_array()
            .unwrap()
            .iter()
            .all(|h| h["vault_id"] == uid.as_str())
    );
    let h0 = hosts[0]["id"].as_str().unwrap();
    let secret = get(format!("{base}/api/v1/hosts/{h0}/secret")).await;
    assert!(secret["password"].as_str().unwrap().starts_with("pw-3-"));
    let sync: Value = http
        .post(format!("{base}/api/v1/sync"))
        .bearer_auth(&u.token)
        .json(&json!({"since": 0, "changes": []}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // 25 hosts, the key and the deleted snippet's tombstone.
    assert_eq!(
        sync["changes"].as_array().unwrap().len(),
        HOSTS_PER_USER + 2
    );
    assert!(
        sync["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["kind"] == "key" && c["secret"]["private_key"] == "PRIVATE-3")
    );
    let vaults = get(format!("{base}/api/v1/vaults")).await;
    assert_eq!(vaults.as_array().unwrap().len(), 1);
    assert_eq!(vaults[0]["kind"], "personal");
    assert_eq!(vaults[0]["item_counts"]["host"], HOSTS_PER_USER as i64);
}

/// Dry run on a copy of a real database (see the module docs).
#[test]
#[ignore]
fn migration_on_a_copy() {
    let Ok(src) = std::env::var("TERMOAK_MIGRATION_DB") else {
        eprintln!("set TERMOAK_MIGRATION_DB");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("copy.db");
    {
        let c = Connection::open(&src).unwrap();
        c.execute("VACUUM INTO ?1", [copy.to_str().unwrap()])
            .unwrap();
    }
    let c = Connection::open(&copy).unwrap();
    let version: i64 = c
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    let before = [
        ("users", count(&c, "SELECT COUNT(*) FROM users")),
        ("entities", count(&c, "SELECT COUNT(*) FROM entities")),
        (
            "entities with a secret",
            count(&c, "SELECT COUNT(*) FROM entities WHERE secret IS NOT NULL"),
        ),
        ("teams", count(&c, "SELECT COUNT(*) FROM teams")),
        ("sessions", count(&c, "SELECT COUNT(*) FROM sessions")),
        ("audit", count(&c, "SELECT COUNT(*) FROM audit_log")),
    ];
    drop(c);
    let started = Instant::now();
    // Opening runs the migrations (no master key needed for them).
    let store = termoak_core::Store::open(&copy, MasterKey::generate()).unwrap();
    let took = started.elapsed();
    drop(store);
    let c = Connection::open(&copy).unwrap();
    check_v9(&c);
    eprintln!(
        "schema v{version} → v{}: {took:?}",
        termoak_core::store::schema_version()
    );
    for (name, n) in before {
        eprintln!("  {name}: {n}");
    }
    eprintln!(
        "  personal vaults: {}\n  entities in a vault: {}\n  orphan entities (owner without a user): {}",
        count(&c, "SELECT COUNT(*) FROM vaults"),
        count(
            &c,
            "SELECT COUNT(*) FROM entities WHERE vault_id IS NOT NULL"
        ),
        count(&c, "SELECT COUNT(*) FROM entities WHERE vault_id IS NULL")
    );
    assert_eq!(
        count(&c, "SELECT COUNT(*) FROM entities"),
        before[1].1,
        "no entity lost"
    );
}
