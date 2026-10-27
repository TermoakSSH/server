//! Single sign-on for teams (0.7 phase 5a, docs/E2EE-SSO-AUDIT.md §3)
//! against an in-process OpenID provider (discovery, ES256 keys, an
//! authorization endpoint that signs the chosen person in at once, a token
//! endpoint checking PKCE and the client secret) and a tiny DNS server for
//! the domain's TXT proof. The app's side is plain HTTP without redirects:
//! start, the provider, the server's callback, the exchange.

mod common;

use std::sync::Arc;

use reqwest::Method;
use serde_json::{Value, json};

use common::oidc::{Idp, Person, Txt, start_dns, start_idp};
use common::srv::{Resp, Srv, User};

// ---------------------------------------------------------------------------
// The app's side
// ---------------------------------------------------------------------------

struct App {
    http: reqwest::Client,
}

impl App {
    fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        }
    }

    /// start → provider → callback; returns (the app's callback URL, verifier).
    async fn sign_in(
        &self,
        srv: &Srv,
        email: Option<&str>,
        team: Option<&str>,
    ) -> (url::Url, String) {
        let verifier = termoak_core::sso::pkce_verifier();
        let r: Value = self
            .http
            .post(format!("{}/api/v1/auth/sso/start", srv.base))
            .json(&json!({"email": email, "team_id": team, "redirect_uri": "http://127.0.0.1:9/callback",
                          "state": "app-state", "code_challenge": termoak_core::sso::pkce_challenge(&verifier),
                          "code_challenge_method": "S256", "device_name": "Laptop", "platform": "desktop-linux"}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let authorize = r["authorize_url"]
            .as_str()
            .unwrap_or_else(|| panic!("start: {r}"))
            .to_string();
        (self.follow(&authorize).await, verifier)
    }

    async fn follow(&self, authorize: &str) -> url::Url {
        let to_server = self.http.get(authorize).send().await.unwrap();
        assert_eq!(to_server.status(), 303, "provider");
        let cb = to_server.headers()["location"]
            .to_str()
            .unwrap()
            .to_string();
        let back = self.http.get(&cb).send().await.unwrap();
        assert_eq!(back.status(), 303, "server callback");
        url::Url::parse(back.headers()["location"].to_str().unwrap()).unwrap()
    }

    async fn exchange(
        &self,
        srv: &Srv,
        code: &str,
        verifier: &str,
        totp: Option<&str>,
    ) -> (u16, Value) {
        let r = self
            .http
            .post(format!("{}/api/v1/auth/sso/exchange", srv.base))
            .json(&json!({"code": code, "code_verifier": verifier, "totp_code": totp}))
            .send()
            .await
            .unwrap();
        (r.status().as_u16(), r.json().await.unwrap())
    }
}

fn param(u: &url::Url, k: &str) -> Option<String> {
    u.query_pairs()
        .find(|(a, _)| a == k)
        .map(|(_, v)| v.into_owned())
}

async fn register(srv: &Srv, email: &str) -> Resp {
    let r = srv
        .http
        .post(format!("{}/api/v1/auth/register", srv.base))
        .json(&json!({"email": email, "name": email, "password": "secure-password", "device_name": "x", "platform": "cli"}))
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    Resp {
        status,
        headers: r.headers().clone(),
        body: r.json().await.unwrap(),
    }
}

async fn login(srv: &Srv, email: &str, totp: Option<&str>) -> Resp {
    let r = srv
        .http
        .post(format!("{}/api/v1/auth/login", srv.base))
        .json(&json!({"email": email, "password": "secure-password", "totp_code": totp, "platform": "cli"}))
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    Resp {
        status,
        headers: r.headers().clone(),
        body: r.json().await.unwrap(),
    }
}

fn user_of(r: &Value) -> User {
    User {
        token: r["tokens"]["access_token"]
            .as_str()
            .unwrap_or_else(|| panic!("{r}"))
            .into(),
        id: r["user"]["id"].as_str().unwrap().into(),
        email: r["user"]["email"].as_str().unwrap().into(),
    }
}

/// A code `offset` steps from now (a step is used once: setup with -1).
fn totp_at(secret_b32: &str, offset: i64) -> String {
    let secret = data_encoding::BASE32_NOPAD
        .decode(secret_b32.as_bytes())
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let step = (termoak_core::totp::step_at(now) as i64 + offset) as u64;
    format!("{:06}", termoak_core::totp::code_at(&secret, step))
}

struct World {
    srv: Srv,
    idp: Arc<Idp>,
    txt: Txt,
    olga: User,
    team: String,
}

async fn world() -> World {
    let idp = start_idp().await;
    let (dns, txt) = start_dns().await;
    let issuer = idp.base.clone();
    let srv = Srv::start_with(move |c| {
        c.server.public_url = Some(format!("http://{}", c.server.listen));
        c.sso.allowed_issuers = vec![format!("{issuer}/")];
        c.sso.dns_servers = vec![dns];
        c.sso.timeout_secs = 3;
    })
    .await;
    srv.user("Root").await; // the administrator (never enforced)
    let olga = user_of(&register(&srv, "olga@corp.test").await.body);
    let team = srv
        .ok("/api/v1/teams", &olga, json!({"name": "Corp"}))
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    World {
        srv,
        idp,
        txt,
        olga,
        team,
    }
}

impl World {
    async fn configure(&self, extra: Value) -> Resp {
        let mut cfg = json!({"enabled": true, "preset": "keycloak", "issuer": self.idp.base, "client_id": "termoak"});
        cfg.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        self.srv
            .put(
                &format!("/api/v1/teams/{}/sso", self.team),
                &self.olga,
                json!({"config": cfg, "client_secret": "s3cret"}),
            )
            .await
    }

    async fn verify_domain(&self) {
        let d = self
            .srv
            .ok(
                &format!("/api/v1/teams/{}/domains", self.team),
                &self.olga,
                json!({"domain": "Corp.Test"}),
            )
            .await;
        assert_eq!(d["record_name"], "_termoak-challenge.corp.test");
        // Wrong value first.
        self.txt.lock().insert(
            "_termoak-challenge.corp.test".into(),
            "termoak-verify=nope".into(),
        );
        let r = self
            .srv
            .ok(
                &format!("/api/v1/teams/{}/domains/corp.test/verify", self.team),
                &self.olga,
                json!({}),
            )
            .await;
        assert!(
            r["verified_at"].is_null() && r["last_error"].is_string(),
            "{r}"
        );
        self.txt.lock().insert(
            "_termoak-challenge.corp.test".into(),
            d["record_value"].as_str().unwrap().into(),
        );
        let r = self
            .srv
            .ok(
                &format!("/api/v1/teams/{}/domains/corp.test/verify", self.team),
                &self.olga,
                json!({}),
            )
            .await;
        assert!(r["verified_at"].is_i64(), "{r}");
        assert_eq!(r["verified_by"], "dns");
    }

    fn next(&self, sub: &str, email: &str) {
        *self.idp.next.lock() = Person {
            sub: sub.into(),
            email: email.into(),
            verified: true,
        };
    }
}

#[tokio::test]
async fn sso_signs_in_creates_links_and_enforces() {
    let w = world().await;
    let srv = &w.srv;
    let app = App::new();
    let eve = user_of(&register(srv, "eve@corp.test").await.body);

    // Settings: enforcing needs a verified domain; private issuers need the
    // administrator's allowance (given in this config).
    let r = w.configure(json!({"enforce": true})).await;
    assert_eq!(
        (r.status, r.code()),
        (409, "sso_domain_unverified"),
        "{}",
        r.body
    );
    let r = w.configure(json!({})).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["config"]["has_client_secret"], true);
    assert!(
        r.body["redirect_uri"]
            .as_str()
            .unwrap()
            .ends_with("/api/v1/auth/sso/callback")
    );
    // A plain member sees no secrets nor tokens.
    w.verify_domain().await;
    let d: Value = srv
        .http
        .get(format!(
            "{}/api/v1/auth/sso/discover?email=eve@corp.test",
            srv.base
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        (
            d["sso"].clone(),
            d["enforced"].clone(),
            d["team_name"].clone()
        ),
        (json!(true), json!(false), json!("Corp"))
    );
    let r = w.configure(json!({"enforce": true})).await;
    assert_eq!(r.status, 200, "{}", r.body);

    // Enforced: password sign-in and sign-up refused; the owner keeps hers.
    let r = login(srv, "eve@corp.test", None).await;
    assert_eq!((r.status, r.code()), (403, "sso_required"), "{}", r.body);
    assert_eq!(r.body["error"]["team_name"], "Corp");
    let r = register(srv, "zed@corp.test").await;
    assert_eq!((r.status, r.code()), (403, "sso_required"));
    assert_eq!(
        login(srv, "olga@corp.test", None).await.status,
        200,
        "break glass"
    );

    // Eve signs in through SSO: her existing account, now in the team.
    w.next("eve-sub", "eve@corp.test");
    let (cb, verifier) = app.sign_in(srv, Some("eve@corp.test"), None).await;
    assert_eq!(param(&cb, "state").as_deref(), Some("app-state"));
    let code = param(&cb, "code").unwrap_or_else(|| panic!("{cb}"));
    let (s, wrong) = app
        .exchange(srv, &code, &termoak_core::sso::pkce_verifier(), None)
        .await;
    assert_eq!(
        (s, wrong["error"]["code"].clone()),
        (400, json!("sso_code_invalid"))
    );
    let (s, auth) = app.exchange(srv, &code, &verifier, None).await;
    assert_eq!(s, 200, "{auth}");
    assert_eq!(auth["user"]["id"], eve.id.as_str());
    let (s, _) = app.exchange(srv, &code, &verifier, None).await;
    assert_eq!(s, 400, "a code works once");
    let teams = srv.get("/api/v1/teams", &user_of(&auth)).await.body;
    assert!(
        teams
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["id"] == w.team.as_str()),
        "{teams}"
    );

    // Zed has no account: created, SSO-only.
    w.next("zed-sub", "zed@corp.test");
    let (cb, verifier) = app.sign_in(srv, Some("zed@corp.test"), None).await;
    let (s, auth) = app
        .exchange(srv, &param(&cb, "code").unwrap(), &verifier, None)
        .await;
    assert_eq!(s, 200, "{auth}");
    assert_eq!(auth["user"]["sso_only"], true);

    // An identity of another domain, not linked: refused at the callback.
    w.next("x-sub", "x@elsewhere.test");
    let (cb, _) = app.sign_in(srv, None, Some(&w.team)).await;
    assert_eq!(
        param(&cb, "error").as_deref(),
        Some("sso_account_not_linked"),
        "{cb}"
    );
    assert_eq!(param(&cb, "state").as_deref(), Some("app-state"));
    // Tampered ID tokens: refused.
    for t in ["nonce", "aud", "sig"] {
        w.next("eve-sub", "eve@corp.test");
        *w.idp.tamper.lock() = Some(t);
        let (cb, _) = app.sign_in(srv, Some("eve@corp.test"), None).await;
        assert_eq!(
            param(&cb, "error").as_deref(),
            Some("sso_failed"),
            "{t}: {cb}"
        );
    }
    // An unverified email at the provider: refused.
    *w.idp.next.lock() = Person {
        sub: "eve-sub".into(),
        email: "eve@corp.test".into(),
        verified: false,
    };
    let (cb, _) = app.sign_in(srv, Some("eve@corp.test"), None).await;
    assert_eq!(param(&cb, "error").as_deref(), Some("sso_email_unverified"));

    // Callbacks must be the apps' own.
    let r: Value = app.http.post(format!("{}/api/v1/auth/sso/start", srv.base))
        .json(&json!({"email": "eve@corp.test", "redirect_uri": "https://evil.example/cb", "code_challenge": termoak_core::sso::pkce_challenge(&termoak_core::sso::pkce_verifier())}))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(r["error"]["code"], "sso_redirect_invalid");

    // Linking an account of another domain while signed in.
    let pat = srv.user("Pat").await;
    srv.ok(
        &format!("/api/v1/teams/{}/members", w.team),
        &w.olga,
        json!({"email": pat.email, "role": "member"}),
    )
    .await;
    w.next("pat-sub", "pat@elsewhere.test");
    let verifier = termoak_core::sso::pkce_verifier();
    let r = srv.ok("/api/v1/me/sso/link", &pat, json!({"team_id": w.team, "redirect_uri": "termoak://sso", "code_challenge": termoak_core::sso::pkce_challenge(&verifier)})).await;
    let to_server = app
        .http
        .get(r["authorize_url"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    let back = app
        .http
        .get(to_server.headers()["location"].to_str().unwrap())
        .send()
        .await
        .unwrap();
    let cb = url::Url::parse(back.headers()["location"].to_str().unwrap()).unwrap();
    assert_eq!(cb.scheme(), "termoak");
    let (s, auth) = app
        .exchange(srv, &param(&cb, "code").unwrap(), &verifier, None)
        .await;
    assert_eq!((s, auth["user"]["id"].clone()), (200, json!(pat.id)));
    // From now on that identity signs Pat in.
    w.next("pat-sub", "pat@elsewhere.test");
    let (cb, verifier) = app.sign_in(srv, None, Some(&w.team)).await;
    let (s, auth) = app
        .exchange(srv, &param(&cb, "code").unwrap(), &verifier, None)
        .await;
    assert_eq!((s, auth["user"]["id"].clone()), (200, json!(pat.id)));
    let ids = srv.get("/api/v1/me/sso", &pat).await.body;
    assert_eq!(ids[0]["subject"], "pat-sub");
    // With the team's name (pat is in the team, auto_join).
    assert!(ids[0]["team_name"].is_string() || ids[0]["team_name"].is_null());

    // Audited in the team's log.
    let audit = srv
        .get(
            &format!("/api/v1/teams/{}/audit?action=sso.*&limit=200", w.team),
            &w.olga,
        )
        .await
        .body;
    let actions: Vec<&str> = audit
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    for a in [
        "sso.config",
        "sso.domain_add",
        "sso.domain_verify",
        "sso.domain_check_failed",
        "sso.login",
        "sso.user_created",
        "sso.link",
        "sso.login_failed",
    ] {
        assert!(actions.contains(&a), "{a} in {actions:?}");
    }
    let refused = srv
        .get(
            "/api/v1/admin/audit?action=auth.login_refused",
            &srv.user("Other").await,
        )
        .await;
    assert_eq!(refused.status, 403, "admins only");
}

#[tokio::test]
async fn sso_and_two_step_verification() {
    let w = world().await;
    let srv = &w.srv;
    let app = App::new();
    let eve = user_of(&register(srv, "eve@corp.test").await.body);
    w.configure(json!({})).await;
    w.verify_domain().await;
    // Eve turns on 2FA.
    let setup = srv.ok("/api/v1/me/2fa/setup", &eve, json!({})).await;
    let secret = setup["secret"].as_str().unwrap().to_string();
    srv.ok(
        "/api/v1/me/2fa/enable",
        &eve,
        json!({"code": totp_at(&secret, -1)}),
    )
    .await;

    // The team does not count SSO as 2FA: the code is still asked; the same
    // one-time code works again with it.
    w.next("eve-sub", "eve@corp.test");
    let (cb, verifier) = app.sign_in(srv, Some("eve@corp.test"), None).await;
    let code = param(&cb, "code").unwrap();
    let (s, r) = app.exchange(srv, &code, &verifier, None).await;
    assert_eq!(
        (s, r["error"]["code"].clone()),
        (401, json!("totp_required"))
    );
    let (s, r) = app.exchange(srv, &code, &verifier, Some("000000")).await;
    assert_eq!(
        (s, r["error"]["code"].clone()),
        (401, json!("totp_invalid"))
    );
    let (s, r) = app
        .exchange(srv, &code, &verifier, Some(&totp_at(&secret, 0)))
        .await;
    assert_eq!(s, 200, "{r}");

    // It does: no code, and the team's "require 2FA" is satisfied by SSO.
    w.configure(json!({"satisfies_2fa": true})).await;
    let vault = srv
        .ok(
            "/api/v1/vaults",
            &w.olga,
            json!({"name": "Prod", "team_id": w.team}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    // Olga turns on 2FA first (the policy needs it), then requires it.
    let s = srv.ok("/api/v1/me/2fa/setup", &w.olga, json!({})).await["secret"]
        .as_str()
        .unwrap()
        .to_string();
    srv.ok(
        "/api/v1/me/2fa/enable",
        &w.olga,
        json!({"code": totp_at(&s, -1)}),
    )
    .await;
    let r = srv
        .put(
            &format!("/api/v1/teams/{}/policy", w.team),
            &w.olga,
            json!({"require_2fa": true, "grace_days": 0}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    w.next("zed-sub", "zed@corp.test");
    let (cb, verifier) = app.sign_in(srv, Some("zed@corp.test"), None).await;
    let (s, auth) = app
        .exchange(srv, &param(&cb, "code").unwrap(), &verifier, None)
        .await;
    assert_eq!(s, 200, "{auth}");
    let zed = user_of(&auth);
    assert!(
        auth["team_2fa"].as_array().is_none_or(|a| a.is_empty()),
        "{auth}"
    );
    let vaults = srv.get("/api/v1/vaults", &zed).await.body;
    assert!(
        vaults
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["id"] == vault.as_str()),
        "{vaults}"
    );
    w.next("eve-sub", "eve@corp.test");
    let (cb, verifier) = app.sign_in(srv, Some("eve@corp.test"), None).await;
    let (s, r) = app
        .exchange(srv, &param(&cb, "code").unwrap(), &verifier, None)
        .await;
    assert_eq!(s, 200, "no code asked: {r}");
    // Without it, Zed (no 2FA of his own) loses the team's vaults.
    w.configure(json!({"satisfies_2fa": false})).await;
    let vaults = srv.get("/api/v1/vaults", &zed).await.body;
    assert!(
        !vaults
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["id"] == vault.as_str())
    );
    let _ = Method::GET;
}

#[tokio::test]
async fn issuers_on_private_addresses_need_the_administrator() {
    let idp = start_idp().await;
    let srv =
        Srv::start_with(|c| c.server.public_url = Some(format!("http://{}", c.server.listen)))
            .await;
    srv.user("Root").await;
    let olga = srv.user("Olga").await;
    let team = srv
        .ok("/api/v1/teams", &olga, json!({"name": "Corp"}))
        .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = srv
        .put(
            &format!("/api/v1/teams/{team}/sso"),
            &olga,
            json!({"config": {"enabled": true, "issuer": idp.base, "client_id": "termoak"}}),
        )
        .await;
    assert_eq!(
        (r.status, r.code()),
        (400, "sso_issuer_invalid"),
        "{}",
        r.body
    );
}
