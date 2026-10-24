//! Teams security (0.7 phase 4b, docs-next/TEAMS-SECURITY.md): the team and
//! personal SSH CA (create, rotate, export, install script, KRL), the
//! certificate rules (ownership and proofs, principals, TTLs, revocation,
//! removal from the team), server-side certificates against a real sshd
//! that trusts the CA, access policies with temporary access (approval,
//! self-approval, revoke, expiry, window end), team policies (reveal, 2FA,
//! AI, networks, recording, uploads) and the fine roles with their
//! compatibility mapping for older clients.

mod common;

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::srv::{Srv, User, wait_event};
use reqwest::Method;
use serde_json::{Value, json};
use termoak_core::time::now_ms;
use termoak_ssh::ca;

/// What a v0.7.0-next.8 core declares.
const FEATURES: &str = "roles_v2,policies,certificates,recording";

async fn req_f(
    srv: &Srv,
    method: Method,
    path: &str,
    u: &User,
    body: Option<Value>,
) -> common::srv::Resp {
    let mut r = srv
        .http
        .request(method, format!("{}{path}", srv.base))
        .bearer_auth(&u.token)
        .header("x-termoak-features", FEATURES);
    if let Some(b) = body {
        r = r.json(&b);
    }
    let resp = r.send().await.unwrap();
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let text = resp.text().await.unwrap();
    common::srv::Resp {
        status,
        body: serde_json::from_str(&text).unwrap_or(Value::String(text)),
        headers,
    }
}

/// Ana owns team "Ops" with Bea as a member; the team vault "Prod" gives
/// plain members `team_member_role`; Carla is a direct Connect-only member.
struct World {
    srv: Srv,
    ana: User,
    bea: User,
    carla: User,
    team: String,
    prod: String,
}

async fn world(team_member_role: &str) -> World {
    let srv = Srv::start().await;
    let _root = srv.user("Root").await; // the server administrator
    let ana = srv.user("Ana").await;
    let bea = srv.user("Bea").await;
    let carla = srv.user("Carla").await;
    let team = srv.ok("/api/v1/teams", &ana, json!({"name": "Ops"})).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    srv.ok(
        &format!("/api/v1/teams/{team}/members"),
        &ana,
        json!({"email": bea.email, "role": "member"}),
    )
    .await;
    let prod = srv
        .ok(
            "/api/v1/vaults",
            &ana,
            json!({"name": "Prod", "team_id": team, "team_member_role": team_member_role}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    srv.ok(
        &format!("/api/v1/vaults/{prod}/members"),
        &ana,
        json!({"email": carla.email, "role": "connect_only"}),
    )
    .await;
    World {
        srv,
        ana,
        bea,
        carla,
        team,
        prod,
    }
}

impl World {
    async fn ca(&self) -> Value {
        self.srv
            .ok(
                &format!("/api/v1/teams/{}/ca", self.team),
                &self.ana,
                json!({}),
            )
            .await
    }

    /// A host in Prod (`settings` merged over `{username: deploy}`).
    async fn host(&self, label: &str, address: &str, settings: Value, secret: Value) -> String {
        let mut s = json!({"username": "deploy"});
        for (k, v) in settings.as_object().unwrap() {
            s[k] = v.clone();
        }
        self.srv
            .ok(
                "/api/v1/hosts",
                &self.ana,
                json!({"label": label, "address": address, "settings": s,
                       "vault_id": self.prod, "secret": secret}),
            )
            .await["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn instance(&self) -> String {
        self.srv.state.instance_id.clone()
    }
}

/// A certificate request with a proof of possession for `private`.
fn proof_body(instance: &str, user: &User, host: &str, private: &str, skew_ms: i64) -> Value {
    let public = ca::public_key_of_private(private).unwrap();
    let text = ca::public_key_text(&public).unwrap();
    let ts = now_ms() + skew_ms;
    let msg = ca::proof_message(instance, &user.id, &text, ts);
    json!({
        "host_id": host,
        "public_key": text,
        "proof": ca::sign_proof(private, None, &msg).unwrap(),
        "timestamp": ts,
    })
}

#[tokio::test]
async fn ca_lifecycle_export_install_and_krl() {
    let w = world("use_only").await;
    let (srv, ana, bea) = (&w.srv, &w.ana, &w.bea);
    let base = format!("/api/v1/teams/{}/ca", w.team);
    let none = srv.get(&base, bea).await;
    assert_eq!(none.status, 200, "{}", none.body);
    assert!(none.body["ca"].is_null());
    // Members read; only owners and admins create.
    let r = srv.post(&base, bea, json!({})).await;
    assert_eq!((r.status, r.code()), (403, "team_admin_only"));
    let ca1 = w.ca().await;
    assert_eq!(ca1["ca"]["algorithm"], "ssh-ed25519");
    assert_eq!(ca1["ca"]["status"], "active");
    assert_eq!(
        ca1["sshd_config"][0],
        "TrustedUserCAKeys /etc/ssh/termoak_user_ca.pub"
    );
    let pk1 = ca1["ca"]["public_key"].as_str().unwrap().to_string();
    assert!(pk1.contains("termoak-ca Ops"));
    assert!(
        !ca1.to_string().contains("PRIVATE"),
        "no private key in the answer"
    );
    let r = srv.post(&base, ana, json!({})).await;
    assert_eq!((r.status, r.code()), (409, "ca_exists"));
    // Public keys file, no token.
    let keys = srv
        .http
        .get(format!("{}/api/v1/ssh-ca/{}/keys", srv.base, w.team))
        .send()
        .await
        .unwrap();
    assert_eq!(keys.status(), 200);
    assert_eq!(keys.text().await.unwrap().trim(), pk1.trim());
    // Rotation: both published, the new one signs.
    let ca2 = srv
        .ok(&format!("{base}/rotate"), ana, json!({"overlap_hours": 2}))
        .await;
    let pk2 = ca2["ca"]["public_key"].as_str().unwrap().to_string();
    assert_ne!(pk1, pk2);
    assert_eq!(ca2["previous"][0]["status"], "retiring");
    let file = ca2["keys_file"].as_str().unwrap();
    assert!(file.contains(pk1.trim()) && file.contains(pk2.trim()));
    // Install script: the keys, the lines, valid sh; bea cannot get it.
    assert_eq!(
        srv.get(&format!("{base}/install.sh"), bea).await.status,
        403
    );
    let script = srv
        .http
        .get(format!("{}{base}/install.sh?krl=1&principals=1", srv.base))
        .bearer_auth(&ana.token)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(script.starts_with("#!/bin/sh"));
    assert!(script.contains("TrustedUserCAKeys /etc/ssh/termoak_user_ca.pub"));
    assert!(script.contains("RevokedKeys /etc/ssh/termoak_revoked.krl"));
    assert!(script.contains("AuthorizedPrincipalsFile /etc/ssh/termoak_principals/%u"));
    assert!(script.contains(pk1.trim()) && script.contains(pk2.trim()));
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("i.sh"), &script).unwrap();
    let ok = Command::new("sh")
        .arg("-n")
        .arg(dir.path().join("i.sh"))
        .status()
        .unwrap();
    assert!(ok.success(), "the install script must be valid sh");
    // KRL (empty now): the OpenSSH magic.
    let krl = srv
        .http
        .get(format!("{}/api/v1/ssh-ca/{}/krl", srv.base, w.team))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(&krl[..8], b"SSHKRL\n\0");
    // Disable needs the team's name.
    let r = srv.delete(&base, ana).await;
    assert_eq!((r.status, r.code()), (400, "confirmation_required"));
    let r = srv.delete(&format!("{base}?confirm=Ops"), ana).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(srv.get(&base, ana).await.body["ca"].is_null());
    // Personal CA.
    let me = srv
        .ok("/api/v1/me/ca", bea, json!({"algorithm": "ecdsa-p256"}))
        .await;
    assert_eq!(me["ca"]["algorithm"], "ecdsa-sha2-nistp256");
    assert_eq!(me["can_manage"], true);
    // Audit.
    let audit = srv.get("/api/v1/audit", ana).await.body;
    let actions: Vec<&str> = audit
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["action"].as_str())
        .collect();
    assert!(
        actions.contains(&"ca.create")
            && actions.contains(&"ca.rotate")
            && actions.contains(&"ca.disable"),
        "{actions:?}"
    );
}

#[tokio::test]
async fn certificate_rules() {
    let w = world("use_only").await;
    let (srv, ana, bea, carla) = (&w.srv, &w.ana, &w.bea, &w.carla);
    let host = w
        .host(
            "db1",
            "db1.example.com",
            json!({"auth": "team_certificate"}),
            json!({}),
        )
        .await;
    let (eph, _) = ca::ephemeral_key("t").unwrap();
    // No CA yet.
    let r = srv
        .post(
            "/api/v1/certificates",
            bea,
            proof_body(&w.instance(), bea, &host, &eph, 0),
        )
        .await;
    assert_eq!(
        (r.status, r.code()),
        (404, "ca_not_configured"),
        "{}",
        r.body
    );
    let ca_info = w.ca().await;
    let ca_fp = ca_info["ca"]["fingerprint"].as_str().unwrap().to_string();

    // Ephemeral key + proof: a certificate for "deploy".
    let c = srv
        .ok(
            "/api/v1/certificates",
            bea,
            proof_body(&w.instance(), bea, &host, &eph, 0),
        )
        .await;
    let d = ca::parse_certificate(c["certificate"].as_str().unwrap()).unwrap();
    assert_eq!(d.principals, vec!["deploy"]);
    assert_eq!(d.ca_fingerprint, ca_fp);
    assert_eq!(d.serial as i64, c["serial"].as_i64().unwrap());
    assert!(
        d.key_id
            .starts_with(&format!("termoak:{}:{}:direct:", bea.email, bea.id)),
        "{}",
        d.key_id
    );
    assert_eq!(
        d.extensions,
        vec![
            "permit-agent-forwarding",
            "permit-port-forwarding",
            "permit-pty"
        ]
    );
    let ttl = c["valid_before"].as_i64().unwrap() - now_ms();
    assert!(ttl > 55 * 60_000 && ttl <= 60 * 60_000, "{ttl}");
    assert!(d.signature_valid);

    // Proofs: another user's, too old, or a mismatched key.
    let mut stolen = proof_body(&w.instance(), bea, &host, &eph, 0);
    let r = srv
        .post("/api/v1/certificates", carla, stolen.clone())
        .await;
    assert_eq!((r.status, r.code()), (403, "certificate_proof_invalid"));
    let r = srv
        .post(
            "/api/v1/certificates",
            bea,
            proof_body(&w.instance(), bea, &host, &eph, -10 * 60_000),
        )
        .await;
    assert_eq!((r.status, r.code()), (403, "certificate_proof_invalid"));
    let (other, _) = ca::ephemeral_key("o").unwrap();
    stolen["public_key"] =
        json!(ca::public_key_text(&ca::public_key_of_private(&other).unwrap()).unwrap());
    let r = srv.post("/api/v1/certificates", bea, stolen).await;
    assert_eq!((r.status, r.code()), (403, "certificate_proof_invalid"));
    let r = srv
        .post("/api/v1/certificates", bea, json!({"host_id": host}))
        .await;
    assert_eq!(r.status, 400);

    // Vault keys: a key of Prod (Bea is Use in a normal vault: hers to use).
    let key = srv
        .ok(
            "/api/v1/keys/generate",
            ana,
            json!({"label": "team", "vault_id": w.prod}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let c2 = srv
        .ok(
            "/api/v1/certificates",
            bea,
            json!({"host_id": host, "key_id": key}),
        )
        .await;
    assert!(c2["serial"].as_i64().unwrap() > c["serial"].as_i64().unwrap());
    // Ana's personal key: not Bea's.
    let personal = srv
        .ok("/api/v1/keys/generate", ana, json!({"label": "mine"}))
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = srv
        .post(
            "/api/v1/certificates",
            bea,
            json!({"host_id": host, "key_id": personal}),
        )
        .await;
    assert_eq!((r.status, r.code()), (403, "certificate_key_not_owned"));
    // Connect only: no JIT, no team key; an ephemeral key works.
    let r = srv
        .post(
            &format!("/api/v1/hosts/{host}/credentials"),
            carla,
            json!({}),
        )
        .await;
    assert_eq!((r.status, r.code()), (403, "connect_only"));
    let r = srv
        .post(
            "/api/v1/certificates",
            carla,
            json!({"host_id": host, "key_id": key}),
        )
        .await;
    assert_eq!((r.status, r.code()), (403, "certificate_key_not_owned"));
    let (ceph, _) = ca::ephemeral_key("c").unwrap();
    srv.ok(
        "/api/v1/certificates",
        carla,
        proof_body(&w.instance(), carla, &host, &ceph, 0),
    )
    .await;
    // Strict vault: Use members lose the key path too.
    let r = srv
        .req(
            Method::PATCH,
            &format!("/api/v1/vaults/{}", w.prod),
            &ana.token,
            Some(json!({"settings": {"use_only_local": false}})),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let r = srv
        .post(
            "/api/v1/certificates",
            bea,
            json!({"host_id": host, "key_id": key}),
        )
        .await;
    assert_eq!((r.status, r.code()), (403, "certificate_key_not_owned"));
    srv.req(
        Method::PATCH,
        &format!("/api/v1/vaults/{}", w.prod),
        &ana.token,
        Some(json!({"settings": {"use_only_local": true}})),
    )
    .await;

    // JIT credentials of a team-certificate host carry a certificate for
    // the team key.
    let kh = w
        .host(
            "db2",
            "db2.example.com",
            json!({"auth": "team_certificate", "key_id": key}),
            json!({}),
        )
        .await;
    let creds = srv
        .ok(
            &format!("/api/v1/hosts/{kh}/credentials"),
            bea,
            json!({"purpose": "ssh"}),
        )
        .await;
    let cert = creds["hops"][0]["key"]["certificate"]
        .as_str()
        .expect("certificate in the credentials");
    assert_eq!(
        ca::parse_certificate(cert).unwrap().principals,
        vec!["deploy"]
    );

    // Team policy: principals and TTL.
    let mut policy = srv
        .get(&format!("/api/v1/teams/{}/policy", w.team), bea)
        .await
        .body;
    policy["ca"]["principals"] = json!(["{login}", "{member}", "ops-{member}"]);
    policy["ca"]["max_ttl_minutes"] = json!(30);
    policy["ca"]["default_ttl_minutes"] = json!(20);
    policy["ca"]["source_address"] = json!("10.0.0.0/8");
    let r = srv
        .put(
            &format!("/api/v1/teams/{}/policy", w.team),
            ana,
            policy.clone(),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let mut body = proof_body(&w.instance(), bea, &host, &eph, 0);
    body["ttl_minutes"] = json!(600);
    let c3 = srv.ok("/api/v1/certificates", bea, body).await;
    let d3 = ca::parse_certificate(c3["certificate"].as_str().unwrap()).unwrap();
    assert_eq!(d3.principals, vec!["deploy", "bea", "ops-bea"]);
    assert_eq!(d3.critical_options, vec!["source-address=10.0.0.0/8"]);
    let ttl = c3["valid_before"].as_i64().unwrap() - now_ms();
    assert!(ttl <= 30 * 60_000 && ttl > 25 * 60_000, "{ttl}");
    // An admin-set principal.
    let r = srv
        .patch(
            &format!("/api/v1/teams/{}/members/{}", w.team, bea.id),
            ana,
            json!({"principal": "b.smith"}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let c4 = srv
        .ok(
            "/api/v1/certificates",
            bea,
            proof_body(&w.instance(), bea, &host, &eph, 0),
        )
        .await;
    assert_eq!(
        ca::parse_certificate(c4["certificate"].as_str().unwrap())
            .unwrap()
            .principals,
        vec!["deploy", "b.smith", "ops-b.smith"]
    );
    let r = srv
        .patch(
            &format!("/api/v1/teams/{}/members/{}", w.team, bea.id),
            ana,
            json!({"principal": "no spaces"}),
        )
        .await;
    assert_eq!(r.status, 400);
    // Bad policies are refused.
    policy["ca"]["extensions"] = json!(["permit-root"]);
    assert_eq!(
        srv.put(&format!("/api/v1/teams/{}/policy", w.team), ana, policy)
            .await
            .status,
        400
    );

    // Listing and revocation (serial, KRL with ssh-keygen -Q).
    let certs = srv
        .get(
            &format!("/api/v1/teams/{}/ca/certificates?active=1", w.team),
            ana,
        )
        .await
        .body;
    assert!(certs.as_array().unwrap().len() >= 5);
    assert_eq!(
        srv.get(&format!("/api/v1/teams/{}/ca/certificates", w.team), bea)
            .await
            .status,
        403
    );
    let serial = c4["serial"].as_i64().unwrap();
    let r = srv
        .ok(
            &format!("/api/v1/teams/{}/ca/revoke", w.team),
            ana,
            json!({"serial": serial, "reason": "lost laptop"}),
        )
        .await;
    assert_eq!(r["revoked"], json!([serial]));
    let krl = srv
        .http
        .get(format!("{}/api/v1/ssh-ca/{}/krl", srv.base, w.team))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("k.krl"), &krl).unwrap();
    std::fs::write(
        dir.path().join("c4-cert.pub"),
        format!("{}\n", c4["certificate"].as_str().unwrap()),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("c3-cert.pub"),
        format!("{}\n", c3["certificate"].as_str().unwrap()),
    )
    .unwrap();
    if Command::new("ssh-keygen").arg("-?").output().is_ok() {
        let out = Command::new("ssh-keygen")
            .args(["-Q", "-f"])
            .arg(dir.path().join("k.krl"))
            .arg(dir.path().join("c4-cert.pub"))
            .output()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("REVOKED"),
            "{out:?}"
        );
        let out = Command::new("ssh-keygen")
            .args(["-Q", "-f"])
            .arg(dir.path().join("k.krl"))
            .arg(dir.path().join("c3-cert.pub"))
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    }
    // A revoked key gets no new certificate.
    let public = ca::public_key_text(&ca::public_key_of_private(&eph).unwrap()).unwrap();
    srv.ok(
        &format!("/api/v1/teams/{}/ca/revoke", w.team),
        ana,
        json!({"public_key": public}),
    )
    .await;
    let r = srv
        .post(
            "/api/v1/certificates",
            bea,
            proof_body(&w.instance(), bea, &host, &eph, 0),
        )
        .await;
    assert_eq!((r.status, r.code()), (403, "certificate_key_revoked"));
    // My certificates.
    let mine = srv.get("/api/v1/certificates", bea).await.body;
    assert!(
        mine.as_array()
            .unwrap()
            .iter()
            .all(|c| c["user_id"] == json!(bea.id))
    );
    // Removing Bea from the team: no more certificates, hers are revoked.
    let r = srv
        .delete(&format!("/api/v1/teams/{}/members/{}", w.team, bea.id), ana)
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let (fresh, _) = ca::ephemeral_key("f").unwrap();
    let r = srv
        .post(
            "/api/v1/certificates",
            bea,
            proof_body(&w.instance(), bea, &host, &fresh, 0),
        )
        .await;
    assert_eq!(r.status, 404, "{}", r.body);
    let active = srv
        .get(
            &format!(
                "/api/v1/teams/{}/ca/certificates?active=1&user_id={}",
                w.team, bea.id
            ),
            ana,
        )
        .await
        .body;
    assert!(active.as_array().unwrap().is_empty(), "{active}");
    let audit = srv
        .get(&format!("/api/v1/vaults/{}/audit", w.prod), ana)
        .await
        .body;
    assert!(audit.to_string().contains("cert.issue"));
}

// ---------------------------------------------------------------------------
// A real sshd that trusts the CA
// ---------------------------------------------------------------------------

struct CaSshd {
    child: Child,
    port: u16,
    _dir: tempfile::TempDir,
    user: String,
}

impl Drop for CaSshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn ca_sshd(ca_keys: &str) -> Option<CaSshd> {
    let sshd = ["/usr/sbin/sshd", "/usr/local/sbin/sshd"]
        .iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.exists())?;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let hk = d.join("hk");
    Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&hk)
        .status()
        .ok()?;
    std::fs::write(d.join("ca.pub"), ca_keys).unwrap();
    std::fs::write(d.join("ak"), "").unwrap();
    let port = common::free_port();
    std::fs::create_dir_all("/run/sshd").ok();
    let cfg = d.join("cfg");
    std::fs::write(
        &cfg,
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\nTrustedUserCAKeys {}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin yes\nLogLevel ERROR\n",
            hk.display(),
            d.join("pid").display(),
            d.join("ak").display(),
            d.join("ca.pub").display(),
        ),
    )
    .unwrap();
    let child = Command::new(sshd)
        .args(["-D", "-e", "-f"])
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            let user = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
                .unwrap()
                .trim()
                .to_string();
            return Some(CaSshd {
                child,
                port,
                _dir: dir,
                user,
            });
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

#[tokio::test]
async fn server_side_certificates_reach_a_host_that_trusts_the_ca() {
    let w = world("use_only").await;
    let (srv, ana, bea, carla) = (&w.srv, &w.ana, &w.bea, &w.carla);
    let ca_info = w.ca().await;
    let Some(sshd) = ca_sshd(ca_info["keys_file"].as_str().unwrap()) else {
        eprintln!("sshd not available: skipped");
        return;
    };
    // No key, no password: only the team certificate opens it.
    let host = w
        .host(
            "trusting",
            "127.0.0.1",
            json!({"username": sshd.user, "port": sshd.port, "auth": "team_certificate"}),
            json!({}),
        )
        .await;
    for u in [bea, carla, ana] {
        let t = srv
            .ok(
                &format!("/api/v1/hosts/{host}/test?trust=true"),
                u,
                json!({}),
            )
            .await;
        assert_eq!(t["ok"], true, "{}: {t}", u.email);
    }
    let out = srv
        .ok(
            "/api/v1/exec",
            carla,
            json!({"host_ids": [host], "command": "echo cert-$((40+2))"}),
        )
        .await;
    assert_eq!(
        out[0]["stdout"].as_str().unwrap().trim(),
        "cert-42",
        "{out}"
    );
    // A server session (Connect only) gets through too.
    let s = req_f(
        srv,
        Method::POST,
        "/api/v1/sessions",
        carla,
        Some(json!({"host_id": host})),
    )
    .await;
    assert_eq!(s.status, 200, "{}", s.body);
    let sid = s.body["id"].as_str().unwrap().to_string();
    let mut last = Value::Null;
    for _ in 0..50 {
        last = srv
            .get(&format!("/api/v1/sessions/{sid}"), carla)
            .await
            .body;
        if last["status"] == "running" || last["state"]["status"] == "running" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        last.to_string().contains("running"),
        "the session did not start: {last}"
    );
    let _ = srv.delete(&format!("/api/v1/sessions/{sid}"), carla).await;
    // Without the team certificate setting the host refuses.
    let plain = w
        .host(
            "plain",
            "127.0.0.1",
            json!({"username": sshd.user, "port": sshd.port}),
            json!({}),
        )
        .await;
    let t = srv
        .ok(
            &format!("/api/v1/hosts/{plain}/test?trust=true"),
            bea,
            json!({}),
        )
        .await;
    assert_eq!(t["ok"], false, "{t}");
    // A host with a vault key that the sshd does not know: certified too.
    let key = srv
        .ok(
            "/api/v1/keys/generate",
            ana,
            json!({"label": "k", "vault_id": w.prod}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let keyed = w
        .host("keyed", "127.0.0.1", json!({"username": sshd.user, "port": sshd.port, "auth": "team_certificate", "key_id": key}), json!({}))
        .await;
    let t = srv
        .ok(
            &format!("/api/v1/hosts/{keyed}/test?trust=true"),
            bea,
            json!({}),
        )
        .await;
    assert_eq!(t["ok"], true, "{t}");
    // Server-side certificates are recorded with their purpose.
    let certs = srv
        .get(&format!("/api/v1/teams/{}/ca/certificates", w.team), ana)
        .await
        .body;
    assert!(
        certs
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["purpose"] == "server"),
        "{certs}"
    );
    // The CA is disabled: no certificate, the host refuses again.
    srv.delete(&format!("/api/v1/teams/{}/ca?confirm=Ops", w.team), ana)
        .await;
    let fresh = w
        .host(
            "after",
            "127.0.0.1",
            json!({"username": sshd.user, "port": sshd.port, "auth": "team_certificate"}),
            json!({}),
        )
        .await;
    let t = srv
        .ok(
            &format!("/api/v1/hosts/{fresh}/test?trust=true"),
            bea,
            json!({}),
        )
        .await;
    assert_eq!(t["ok"], false, "{t}");
}

#[tokio::test]
async fn temporary_access_with_approval() {
    let w = world("use_only").await;
    let (srv, ana, bea) = (&w.srv, &w.ana, &w.bea);
    w.ca().await;
    let host = w
        .host(
            "prod-db",
            "prod-db.example.com",
            json!({"auth": "team_certificate"}),
            json!({"password": "pw"}),
        )
        .await;
    let direct = w
        .host("staging", "staging.example.com", json!({}), json!({}))
        .await;
    // Policy on the host: approval, at most 60 minutes.
    let p = srv
        .put(
            &format!("/api/v1/vaults/{}/access-policies", w.prod),
            ana,
            json!({"target_kind": "host", "target_id": host, "policy": {"mode": "approval", "max_minutes": 60}}),
        )
        .await;
    assert_eq!(p.status, 200, "{}", p.body);
    assert_eq!(
        srv.put(
            &format!("/api/v1/vaults/{}/access-policies", w.prod),
            bea,
            json!({"target_kind": "host", "target_id": host, "policy": {}})
        )
        .await
        .status,
        403
    );
    let pols = srv
        .get(&format!("/api/v1/vaults/{}/access-policies", w.prod), bea)
        .await
        .body;
    assert_eq!(pols.as_array().unwrap().len(), 1);

    // Without a window: no certificate, no credentials, no server use.
    let (eph, _) = ca::ephemeral_key("e").unwrap();
    let r = srv
        .post(
            "/api/v1/certificates",
            bea,
            proof_body(&w.instance(), bea, &host, &eph, 0),
        )
        .await;
    assert_eq!(
        (r.status, r.code()),
        (403, "access_approval_required"),
        "{}",
        r.body
    );
    assert_eq!(r.body["error"]["host_id"], json!(host));
    assert_eq!(r.body["error"]["max_minutes"], 60);
    let r = srv
        .post(&format!("/api/v1/hosts/{host}/credentials"), bea, json!({}))
        .await;
    assert_eq!(r.code(), "access_approval_required");
    let r = srv
        .post(
            "/api/v1/exec",
            bea,
            json!({"host_ids": [host], "command": "true"}),
        )
        .await;
    assert!(r.body.to_string().contains("access window"), "{}", r.body);
    let a = srv
        .get(&format!("/api/v1/hosts/{host}/access"), bea)
        .await
        .body;
    assert_eq!(
        (
            a["mode"].as_str(),
            a["allowed"].as_bool(),
            a["can_request"].as_bool()
        ),
        (Some("approval"), Some(false), Some(true))
    );
    // Managers are exempt (by default); a direct host needs nothing.
    assert_eq!(
        srv.get(&format!("/api/v1/hosts/{host}/access"), ana)
            .await
            .body["allowed"],
        true
    );
    let r = srv
        .post(
            "/api/v1/access-requests",
            bea,
            json!({"host_id": direct, "minutes": 10, "reason": "x"}),
        )
        .await;
    assert_eq!((r.status, r.code()), (409, "access_request_not_needed"));
    let r = srv
        .post(
            "/api/v1/access-requests",
            ana,
            json!({"host_id": host, "minutes": 10, "reason": "x"}),
        )
        .await;
    assert_eq!((r.status, r.code()), (409, "access_request_not_needed"));
    // Validation.
    let r = srv
        .post(
            "/api/v1/access-requests",
            bea,
            json!({"host_id": host, "minutes": 61, "reason": "x"}),
        )
        .await;
    assert_eq!((r.status, r.code()), (400, "access_duration_too_long"));
    let r = srv
        .post(
            "/api/v1/access-requests",
            bea,
            json!({"host_id": host, "minutes": 30, "reason": " "}),
        )
        .await;
    assert_eq!(r.status, 400);

    // Bea asks; Ana sees it live.
    let mut ana_ws = srv.events(ana).await;
    let mut bea_ws = srv.events(bea).await;
    let req = srv
        .ok(
            "/api/v1/access-requests",
            bea,
            json!({"host_id": host, "minutes": 30, "reason": "deploy 1.2"}),
        )
        .await;
    let id = req["id"].as_str().unwrap().to_string();
    assert_eq!(req["status"], "pending");
    assert_eq!(req["can_decide"], false);
    let ev = wait_event(&mut ana_ws, |v| v["type"] == "access_request").await;
    assert_eq!(
        (ev["event"].as_str(), ev["request"]["id"].as_str()),
        (Some("created"), Some(id.as_str()))
    );
    let r = srv
        .post(
            "/api/v1/access-requests",
            bea,
            json!({"host_id": host, "minutes": 30, "reason": "again"}),
        )
        .await;
    assert_eq!((r.status, r.code()), (409, "access_request_exists"));
    assert_eq!(r.body["error"]["id"], json!(id));
    // Bea cannot approve; Ana's inbox has it.
    let r = srv
        .post(
            &format!("/api/v1/access-requests/{id}/approve"),
            bea,
            json!({}),
        )
        .await;
    assert_eq!(r.code(), "not_an_approver");
    let inbox = srv
        .get(
            "/api/v1/access-requests?scope=approvals&status=pending",
            ana,
        )
        .await
        .body;
    assert_eq!(inbox[0]["id"], json!(id));
    assert_eq!(inbox[0]["can_decide"], true);
    assert!(
        srv.get("/api/v1/access-requests?scope=approvals", bea)
            .await
            .body
            .as_array()
            .unwrap()
            .is_empty()
    );
    // Only shorter windows.
    let r = srv
        .post(
            &format!("/api/v1/access-requests/{id}/approve"),
            ana,
            json!({"minutes": 45}),
        )
        .await;
    assert_eq!(r.code(), "access_duration_too_long");
    let ok = srv
        .ok(
            &format!("/api/v1/access-requests/{id}/approve"),
            ana,
            json!({"minutes": 10, "reason": "go"}),
        )
        .await;
    assert_eq!(
        (
            ok["status"].as_str(),
            ok["active"].as_bool(),
            ok["minutes"].as_u64()
        ),
        (Some("approved"), Some(true), Some(10))
    );
    let ev = wait_event(&mut bea_ws, |v| {
        v["type"] == "access_request" && v["event"] == "approved"
    })
    .await;
    assert_eq!(ev["request"]["decided_by"], json!(ana.id));
    let r = srv
        .post(
            &format!("/api/v1/access-requests/{id}/deny"),
            ana,
            json!({}),
        )
        .await;
    assert_eq!((r.status, r.code()), (409, "access_request_closed"));

    // Inside the window: certificate capped to it, credentials work.
    let c = srv
        .ok(
            "/api/v1/certificates",
            bea,
            proof_body(&w.instance(), bea, &host, &eph, 0),
        )
        .await;
    assert!(c["valid_before"].as_i64().unwrap() <= ok["ends_at"].as_i64().unwrap());
    assert_eq!(c["request_id"], json!(id));
    assert!(
        ca::parse_certificate(c["certificate"].as_str().unwrap())
            .unwrap()
            .key_id
            .contains(&id)
    );
    srv.ok(&format!("/api/v1/hosts/{host}/credentials"), bea, json!({}))
        .await;
    let a = srv
        .get(&format!("/api/v1/hosts/{host}/access"), bea)
        .await
        .body;
    assert_eq!(
        (a["allowed"].as_bool(), a["grant"]["id"].as_str()),
        (Some(true), Some(id.as_str()))
    );

    // Revoked early: denied again, its certificates revoked.
    let rv = srv
        .ok(
            &format!("/api/v1/access-requests/{id}/revoke"),
            ana,
            json!({"reason": "done"}),
        )
        .await;
    assert_eq!(rv["status"], "revoked");
    let r = srv
        .post(
            "/api/v1/certificates",
            bea,
            proof_body(&w.instance(), bea, &host, &eph, 0),
        )
        .await;
    assert_eq!(r.code(), "access_approval_required");
    let certs = srv
        .get(&format!("/api/v1/teams/{}/ca/certificates", w.team), ana)
        .await
        .body;
    let issued = certs
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["serial"] == c["serial"])
        .unwrap();
    assert!(issued["revoked_at"].is_i64(), "{issued}");

    // Deny, cancel.
    let d = srv
        .ok(
            "/api/v1/access-requests",
            bea,
            json!({"host_id": host, "minutes": 5, "reason": "a"}),
        )
        .await;
    let did = d["id"].as_str().unwrap();
    assert_eq!(
        srv.ok(
            &format!("/api/v1/access-requests/{did}/deny"),
            ana,
            json!({"reason": "no"})
        )
        .await["status"],
        "denied"
    );
    let c2 = srv
        .ok(
            "/api/v1/access-requests",
            bea,
            json!({"host_id": host, "minutes": 5, "reason": "b"}),
        )
        .await;
    let cid = c2["id"].as_str().unwrap();
    assert_eq!(
        srv.post(
            &format!("/api/v1/access-requests/{cid}/cancel"),
            ana,
            json!({})
        )
        .await
        .status,
        404
    );
    assert_eq!(
        srv.ok(
            &format!("/api/v1/access-requests/{cid}/cancel"),
            bea,
            json!({})
        )
        .await["status"],
        "cancelled"
    );

    // Expiry (the job) and the end of a window (the job).
    let e = srv
        .ok(
            "/api/v1/access-requests",
            bea,
            json!({"host_id": host, "minutes": 5, "reason": "c"}),
        )
        .await;
    let eid = e["id"].as_str().unwrap().to_string();
    let store = srv.state.store.clone();
    let eid2 = eid.clone();
    store
        .call(move |c, _| {
            c.execute(
                "UPDATE access_requests SET expires_at = 1 WHERE id = ?1",
                [eid2],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    termoak_server::routes::security::run_job(&srv.state).await;
    assert_eq!(
        srv.get(&format!("/api/v1/access-requests/{eid}"), bea)
            .await
            .body["status"],
        "expired"
    );
    wait_event(&mut bea_ws, |v| {
        v["type"] == "access_request" && v["event"] == "expired"
    })
    .await;
    let g = srv
        .ok(
            "/api/v1/access-requests",
            bea,
            json!({"host_id": host, "minutes": 5, "reason": "d"}),
        )
        .await;
    let gid = g["id"].as_str().unwrap().to_string();
    srv.ok(
        &format!("/api/v1/access-requests/{gid}/approve"),
        ana,
        json!({}),
    )
    .await;
    srv.ok(&format!("/api/v1/hosts/{host}/credentials"), bea, json!({}))
        .await;
    let gid2 = gid.clone();
    store
        .call(move |c, _| {
            c.execute(
                "UPDATE access_requests SET ends_at = 2, starts_at = 1 WHERE id = ?1",
                [gid2],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    termoak_server::routes::security::run_job(&srv.state).await;
    wait_event(&mut bea_ws, |v| {
        v["type"] == "access_request" && v["event"] == "ended"
    })
    .await;
    let r = srv
        .post(&format!("/api/v1/hosts/{host}/credentials"), bea, json!({}))
        .await;
    assert_eq!(r.code(), "access_approval_required");

    // A group policy covers its hosts; a vault request covers everything.
    let group = srv
        .ok(
            "/api/v1/groups",
            ana,
            json!({"name": "Prod hosts", "vault_id": w.prod}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let gh = w
        .host("in-group", "g.example.com", json!({}), json!({}))
        .await;
    let r = srv.req(Method::PUT, &format!("/api/v1/hosts/{gh}"), &ana.token, Some(json!({"label": "in-group", "address": "g.example.com", "group_id": group, "settings": {"username": "deploy"}}))).await;
    assert_eq!(r.status, 200, "{}", r.body);
    srv.put(
        &format!("/api/v1/vaults/{}/access-policies", w.prod),
        ana,
        json!({"target_kind": "group", "target_id": group, "policy": {"mode": "approval"}}),
    )
    .await;
    assert_eq!(
        srv.get(&format!("/api/v1/hosts/{gh}/access"), bea)
            .await
            .body["allowed"],
        false
    );
    let gr = srv
        .ok(
            "/api/v1/access-requests",
            bea,
            json!({"group_id": group, "minutes": 5, "reason": "e"}),
        )
        .await;
    srv.ok(
        &format!(
            "/api/v1/access-requests/{}/approve",
            gr["id"].as_str().unwrap()
        ),
        ana,
        json!({}),
    )
    .await;
    assert_eq!(
        srv.get(&format!("/api/v1/hosts/{gh}/access"), bea)
            .await
            .body["allowed"],
        true
    );

    // Self-approval: refused unless the policy allows it.
    srv.put(&format!("/api/v1/vaults/{}/access-policies", w.prod), ana, json!({"target_kind": "host", "target_id": host, "policy": {"mode": "approval", "require_for_managers": true}})).await;
    let s = srv
        .ok(
            "/api/v1/access-requests",
            ana,
            json!({"host_id": host, "minutes": 5, "reason": "me"}),
        )
        .await;
    let sid = s["id"].as_str().unwrap();
    let r = srv
        .post(
            &format!("/api/v1/access-requests/{sid}/approve"),
            ana,
            json!({}),
        )
        .await;
    assert_eq!(r.code(), "self_approval_forbidden");
    srv.put(&format!("/api/v1/vaults/{}/access-policies", w.prod), ana, json!({"target_kind": "host", "target_id": host, "policy": {"mode": "approval", "require_for_managers": true, "allow_self_approval": true}})).await;
    let me = srv
        .ok(
            &format!("/api/v1/access-requests/{sid}/approve"),
            ana,
            json!({}),
        )
        .await;
    assert_eq!(
        (me["status"].as_str(), me["self_approved"].as_bool()),
        (Some("approved"), Some(true))
    );

    // Audit of the whole flow.
    let audit = srv
        .get(&format!("/api/v1/vaults/{}/audit?limit=200", w.prod), ana)
        .await
        .body
        .to_string();
    for action in [
        "access.request",
        "access.approve",
        "access.deny",
        "access.cancel",
        "access.revoke",
        "access.expire",
        "access.end",
        "access_policy.set",
        "cert.issue",
    ] {
        assert!(audit.contains(action), "{action} missing from the audit");
    }
}

#[tokio::test]
async fn team_policies_are_enforced() {
    let w = world("editor").await;
    let (srv, ana, bea) = (&w.srv, &w.ana, &w.bea);
    let host = w
        .host(
            "web",
            "127.0.0.1",
            json!({"port": 1}),
            json!({"password": "s3cret"}),
        )
        .await;
    let pol = format!("/api/v1/teams/{}/policy", w.team);
    // Before: Bea (Editor) reveals and syncs secrets.
    assert_eq!(
        srv.get(&format!("/api/v1/hosts/{host}/secret"), bea)
            .await
            .body["password"],
        "s3cret"
    );
    let mut policy = srv.get(&pol, bea).await.body;
    policy["allow_reveal"] = json!(false);
    policy["ai"]["allowed"] = json!(false);
    policy["networks_allowed"] = json!(false);
    policy["record_sessions"] = json!(true);
    let mut ws = srv.events(bea).await;
    assert_eq!(srv.put(&pol, bea, policy.clone()).await.status, 403);
    let r = srv.put(&pol, ana, policy.clone()).await;
    assert_eq!(r.status, 200, "{}", r.body);
    wait_event(&mut ws, |v| v["type"] == "team" && v["event"] == "policy").await;
    // Reveal and sync: hidden from Editors, not from managers.
    let r = srv.get(&format!("/api/v1/hosts/{host}/secret"), bea).await;
    assert_eq!((r.status, r.code()), (403, "secret_reveal_forbidden"));
    assert_eq!(
        srv.get(&format!("/api/v1/hosts/{host}/secret"), ana)
            .await
            .body["password"],
        "s3cret"
    );
    let sync = req_f(
        srv,
        Method::POST,
        "/api/v1/vaults/sync",
        bea,
        Some(json!({"vaults": [], "changes": []})),
    )
    .await
    .body;
    let rec = sync["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == json!(host))
        .unwrap();
    assert!(
        rec.get("secret").is_none() && rec["has_secret"] == true,
        "{rec}"
    );
    let vault = sync["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == json!(w.prod))
        .unwrap();
    assert_eq!(vault["policy"]["reveal_allowed"], false);
    assert_eq!(vault["policy"]["ai_allowed"], false);
    assert_eq!(vault["policy"]["record_sessions"], true);
    assert_eq!(vault["policy"]["team_id"], json!(w.team));
    // An old client gets no policy object.
    let old = srv.get("/api/v1/vaults", bea).await.body;
    assert!(
        old.as_array()
            .unwrap()
            .iter()
            .all(|v| v.get("policy").is_none())
    );
    // Bea still edits (the secret stays) and uses JIT credentials (with recording).
    let r = srv.req(Method::PUT, &format!("/api/v1/hosts/{host}"), &bea.token, Some(json!({"label": "web2", "address": "127.0.0.1", "settings": {"username": "deploy", "port": 1}}))).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(
        srv.get(&format!("/api/v1/hosts/{host}/secret"), ana)
            .await
            .body["password"],
        "s3cret"
    );
    // Taking items out of the vault is refused.
    let personal = bea.id.clone();
    let r = srv
        .post(
            &format!("/api/v1/vaults/{personal}/transfer"),
            bea,
            json!({"mode": "copy", "items": [{"kind": "host", "id": host}]}),
        )
        .await;
    assert_eq!(r.code(), "secret_reveal_forbidden");
    // Recording: credentials only for clients that record.
    let r = srv
        .post(&format!("/api/v1/hosts/{host}/credentials"), bea, json!({}))
        .await;
    assert_eq!((r.status, r.code()), (403, "recording_required"));
    let r = req_f(
        srv,
        Method::POST,
        &format!("/api/v1/hosts/{host}/credentials"),
        bea,
        Some(json!({})),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["hops"][0]["password"], "s3cret");
    // Server sessions are recorded whatever the client asks.
    let s = req_f(
        srv,
        Method::POST,
        "/api/v1/sessions",
        bea,
        Some(json!({"host_id": host, "record": false})),
    )
    .await;
    assert_eq!(s.status, 200, "{}", s.body);
    assert_eq!(s.body["recording"], true);
    // Uploaded recordings (apps) and the managers' list.
    let cast = "{\"version\": 2, \"width\": 80, \"height\": 24}\n[0.1, \"o\", \"hi\"]\n";
    let up = srv
        .http
        .post(format!(
            "{}/api/v1/recordings?host_id={host}&title=local",
            srv.base
        ))
        .bearer_auth(&bea.token)
        .body(cast)
        .send()
        .await
        .unwrap();
    assert_eq!(up.status(), 200);
    let up: Value = up.json().await.unwrap();
    let bad = srv
        .http
        .post(format!("{}/api/v1/recordings?host_id={host}", srv.base))
        .bearer_auth(&bea.token)
        .body("not a cast")
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400);
    assert_eq!(
        srv.get(&format!("/api/v1/vaults/{}/recordings", w.prod), bea)
            .await
            .status,
        403
    );
    let recs = srv
        .get(&format!("/api/v1/vaults/{}/recordings", w.prod), ana)
        .await
        .body;
    assert!(
        recs.as_array()
            .unwrap()
            .iter()
            .any(|r| r["session_id"] == up["id"] && r["kind"] == "device"),
        "{recs}"
    );
    let dl = srv
        .http
        .get(format!(
            "{}/api/v1/vaults/{}/recordings/{}",
            srv.base,
            w.prod,
            up["id"].as_str().unwrap()
        ))
        .bearer_auth(&ana.token)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(dl, cast);
    // Device recordings stay out of the owner's session list.
    let sessions = srv.get("/api/v1/sessions", bea).await.body;
    assert!(!sessions.to_string().contains(up["id"].as_str().unwrap()));
    // Networks: none in this vault.
    let r = srv.post("/api/v1/networks", ana, json!({"name": "wg", "kind": "wireguard", "vault_id": w.prod, "wireguard": {"address": ["10.9.0.2/32"], "peers": []}})).await;
    assert_eq!(r.code(), "networks_forbidden_by_policy", "{}", r.body);
    // AI: the team's hosts are not in the AI's inventory.
    use termoak_ai::hosts::HostProvider;
    let inv = termoak_ai::hosts::VaultHosts::new(srv.state.store.clone(), srv.state.pool.clone())
        .inventory(bea.id.parse().unwrap())
        .await
        .unwrap();
    assert!(inv.hosts.iter().all(|h| h.id.to_string() != host));
    policy["ai"]["allowed"] = json!(true);
    policy["ai"]["approval"] = json!("always");
    srv.put(&pol, ana, policy.clone()).await;
    let inv = termoak_ai::hosts::VaultHosts::new(srv.state.store.clone(), srv.state.pool.clone())
        .inventory(bea.id.parse().unwrap())
        .await
        .unwrap();
    let h = inv
        .hosts
        .iter()
        .find(|h| h.id.to_string() == host)
        .expect("visible again");
    assert!(h.always_confirm && h.use_only);

    // 2FA: Ana needs it herself first.
    policy["require_2fa"] = json!(true);
    let r = srv.put(&pol, ana, policy.clone()).await;
    assert_eq!((r.status, r.code()), (409, "policy_requires_2fa"));
    let store = srv.state.store.clone();
    let ana_id = ana.id.clone();
    store
        .call(move |c, _| {
            c.execute("UPDATE users SET totp_enabled = 1 WHERE id = ?1", [ana_id])?;
            Ok(())
        })
        .await
        .unwrap();
    store.bump_access();
    let r = srv.put(&pol, ana, policy.clone()).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.body["require_2fa_since"].is_i64());
    // Grace period running: Bea still has the vault, and is told.
    let me = srv.get("/api/v1/me", bea).await.body;
    assert_eq!(me["team_2fa"][0]["team_id"], json!(w.team));
    assert_eq!(me["team_2fa"][0]["blocked"], false);
    assert!(
        srv.get("/api/v1/vaults", bea)
            .await
            .body
            .to_string()
            .contains(&w.prod)
    );
    // Turning 2FA off is refused while the team requires it.
    let r = srv
        .post(
            "/api/v1/me/2fa/disable",
            ana,
            json!({"password": "secure-password", "code": "000000"}),
        )
        .await;
    assert_eq!(r.code(), "team_2fa_required");
    // Over the grace period: hidden until Bea enables 2FA.
    let (team, bea_id) = (w.team.clone(), bea.id.clone());
    store
        .call(move |c, _| {
            c.execute("UPDATE team_members SET added_at = 0 WHERE user_id = ?1", [bea_id])?;
            c.execute(
                "UPDATE teams SET policy = json_set(policy, '$.require_2fa_since', 1) WHERE id = ?1",
                [team],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    store.bump_access();
    let vaults = srv.get("/api/v1/vaults", bea).await.body;
    assert!(!vaults.to_string().contains(&w.prod), "{vaults}");
    assert_eq!(
        srv.get(&format!("/api/v1/hosts/{host}/secret"), bea)
            .await
            .status,
        404
    );
    assert_eq!(
        srv.get("/api/v1/me", bea).await.body["team_2fa"][0]["blocked"],
        true
    );
    let comp = srv
        .get(&format!("/api/v1/teams/{}/compliance", w.team), ana)
        .await
        .body;
    let row = comp["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["user_id"] == json!(bea.id))
        .unwrap();
    assert_eq!(
        (row["totp_enabled"].as_bool(), row["blocked"].as_bool()),
        (Some(false), Some(true))
    );
    assert_eq!(
        srv.get(&format!("/api/v1/teams/{}/compliance", w.team), bea)
            .await
            .status,
        403
    );
    let bea_id = bea.id.clone();
    store
        .call(move |c, _| {
            c.execute("UPDATE users SET totp_enabled = 1 WHERE id = ?1", [bea_id])?;
            Ok(())
        })
        .await
        .unwrap();
    store.bump_access();
    assert!(
        srv.get("/api/v1/vaults", bea)
            .await
            .body
            .to_string()
            .contains(&w.prod)
    );
}

#[tokio::test]
async fn fine_roles_and_compatibility() {
    let w = world("use_only").await;
    let (srv, ana, bea, carla) = (&w.srv, &w.ana, &w.bea, &w.carla);
    // Carla is Connect only: new clients see it, old ones see use_only.
    let new = req_f(
        srv,
        Method::GET,
        &format!("/api/v1/vaults/{}", w.prod),
        carla,
        None,
    )
    .await
    .body;
    assert_eq!(new["role"], "connect_only");
    let old = srv
        .get(&format!("/api/v1/vaults/{}", w.prod), carla)
        .await
        .body;
    assert_eq!(old["role"], "use_only");
    let members = srv
        .get(&format!("/api/v1/vaults/{}/members", w.prod), ana)
        .await
        .body;
    assert!(
        members.to_string().contains("use_only") && !members.to_string().contains("connect_only")
    );
    let members = req_f(
        srv,
        Method::GET,
        &format!("/api/v1/vaults/{}/members", w.prod),
        ana,
        None,
    )
    .await
    .body;
    assert!(members.to_string().contains("connect_only"));
    let sync = srv
        .post(
            "/api/v1/vaults/sync",
            carla,
            json!({"vaults": [], "changes": []}),
        )
        .await
        .body;
    assert!(!sync.to_string().contains("connect_only"), "{sync}");
    let sync = req_f(
        srv,
        Method::POST,
        "/api/v1/vaults/sync",
        carla,
        Some(json!({"vaults": [], "changes": []})),
    )
    .await
    .body;
    assert!(sync.to_string().contains("connect_only"));
    // Events: an old socket gets use_only.
    let mut old_ws = srv.events(carla).await;
    let grant = members
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["principal"]["id"] == json!(carla.id))
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    srv.patch(
        &format!("/api/v1/vaults/{}/members/{grant}", w.prod),
        ana,
        json!({"role": "connect_only"}),
    )
    .await;
    srv.patch(
        &format!("/api/v1/vaults/{}/members/{grant}", w.prod),
        ana,
        json!({"role": "editor"}),
    )
    .await;
    srv.patch(
        &format!("/api/v1/vaults/{}/members/{grant}", w.prod),
        ana,
        json!({"role": "connect_only"}),
    )
    .await;
    let ev = wait_event(&mut old_ws, |v| {
        v["type"] == "vault" && v["event"] == "access" && v["role"] != "editor"
    })
    .await;
    assert_eq!(ev["role"], "use_only");
    // Connect only uses the server, not secrets.
    let host = w
        .host("h", "h.example.com", json!({}), json!({"password": "x"}))
        .await;
    assert_eq!(
        srv.get(&format!("/api/v1/hosts/{host}/secret"), carla)
            .await
            .code(),
        "secret_hidden"
    );
    assert_eq!(
        srv.post(
            &format!("/api/v1/hosts/{host}/credentials"),
            carla,
            json!({})
        )
        .await
        .code(),
        "connect_only"
    );
    assert_eq!(
        srv.get(&format!("/api/v1/hosts/{host}/effective"), carla)
            .await
            .status,
        200
    );
    // Explicit Admin (manager) grant: manages members, cannot delete.
    let shared = srv.vault(ana, "Shared").await;
    srv.share(ana, &shared, bea, "manager").await;
    let v = srv.get(&format!("/api/v1/vaults/{shared}"), bea).await.body;
    assert_eq!(v["role"], "manager");
    srv.share(bea, &shared, carla, "use_only").await;
    let r = srv
        .delete(&format!("/api/v1/vaults/{shared}?confirm=Shared"), bea)
        .await;
    assert_eq!((r.status, r.code()), (403, "vault_owner_only"));
    assert_eq!(
        srv.delete(&format!("/api/v1/vaults/{shared}?confirm=Shared"), ana)
            .await
            .status,
        200
    );
    // Team members cannot be made managers through team_member_role.
    let r = srv
        .post(
            "/api/v1/vaults",
            ana,
            json!({"name": "X", "team_id": w.team, "team_member_role": "manager"}),
        )
        .await;
    assert_eq!(r.code(), "invalid_role");
    // Old cores keep `settings.auth` when they edit a host without it.
    let h2 = w
        .host(
            "h2",
            "h2.example.com",
            json!({"auth": "team_certificate"}),
            json!({}),
        )
        .await;
    let r = srv.req(Method::PUT, &format!("/api/v1/hosts/{h2}"), &ana.token, Some(json!({"label": "h2", "address": "h2.example.com", "settings": {"username": "deploy"}}))).await;
    assert_eq!(r.status, 200);
    assert_eq!(
        srv.get(&format!("/api/v1/hosts/{h2}"), ana).await.body["settings"]["auth"],
        "team_certificate"
    );
    // /info declares the features.
    let info = srv
        .http
        .get(format!("{}/api/v1/info", srv.base))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(info["features"]["teams_security"]["roles_v2"], true);
}
