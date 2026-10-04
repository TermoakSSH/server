//! Web platform: open registration with email verification, password reset,
//! email change, team invitations by email, plans and their limits, account
//! deletion and the website itself.

use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use termoak_server::config::{Registration, ServerConfig};
use termoak_server::state::AppState;
use termoak_server::{build_state, routes};

struct Srv {
    base: String,
    http: reqwest::Client,
    state: AppState,
    _data: tempfile::TempDir,
}

impl Srv {
    async fn start() -> Self {
        let data = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = ServerConfig::default();
        config.server.listen = addr;
        config.server.data_dir = data.path().to_path_buf();
        config.server.registration = Registration::Open;
        config.server.public_url = Some("https://ssh.example.test".into());
        config.email.smtp_url = Some("log://".into());
        config.email.require_verification = true;
        // A limit to check that it is enforced.
        config.plans.catalog[0].limits.max_teams = Some(1);
        // The default catalog has no team plan for now; the mechanism is still tested.
        config.plans.catalog.push(termoak_server::config::Plan {
            id: "team".into(),
            name: "Teams".into(),
            description: String::new(),
            price_cents: None,
            currency: "EUR".into(),
            available: false,
            for_teams: true,
            highlight: false,
            features: Vec::new(),
            limits: Default::default(),
        });
        let state = build_state(config).await.unwrap();
        let app = routes::router(state.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Srv {
            base: format!("http://{addr}"),
            http: reqwest::Client::new(),
            state,
            _data: data,
        }
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut req = self.http.request(method, format!("{}{path}", self.base));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn post(&self, path: &str, token: Option<&str>, body: Value) -> (StatusCode, Value) {
        self.call(Method::POST, path, token, Some(body)).await
    }

    async fn get(&self, path: &str, token: &str) -> (StatusCode, Value) {
        self.call(Method::GET, path, Some(token), None).await
    }

    async fn register(&self, email: &str, invite: Option<&str>) -> (String, Value) {
        let (s, v) = self
            .post(
                "/api/v1/auth/register",
                None,
                json!({"email": email, "name": email.split('@').next(), "password": "secure-password",
                       "platform": "web", "invite": invite}),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        (
            v["tokens"]["access_token"].as_str().unwrap().to_string(),
            v["user"].clone(),
        )
    }

    async fn login(&self, email: &str, password: &str) -> (StatusCode, Value) {
        self.post(
            "/api/v1/auth/login",
            None,
            json!({"email": email, "password": password, "platform": "web"}),
        )
        .await
    }

    /// Last email sent to `to`.
    fn last_mail(&self, to: &str) -> termoak_server::email::Email {
        self.state
            .mailer
            .sent()
            .into_iter()
            .rev()
            .find(|m| m.to == to)
            .unwrap_or_else(|| panic!("no email for {to}"))
    }

    fn mails_to(&self, to: &str) -> usize {
        self.state
            .mailer
            .sent()
            .iter()
            .filter(|m| m.to == to)
            .count()
    }
}

/// Token of a `...?token=XXX` or `/invite/XXX` link in the email text.
fn token_in(text: &str, marker: &str) -> String {
    let start = text
        .find(marker)
        .unwrap_or_else(|| panic!("no {marker}: {text}"))
        + marker.len();
    text[start..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect()
}

#[tokio::test]
async fn platform_accounts() {
    let srv = Srv::start().await;

    // --- Public information and plans ---
    let (_, info) = srv.call(Method::GET, "/api/v1/info", None, None).await;
    assert_eq!(info["registration"], "open");
    assert_eq!(info["features"]["email"], true);
    assert_eq!(info["features"]["email_verification"], true);
    assert_eq!(info["features"]["web"], true);
    let (_, plans) = srv.call(Method::GET, "/api/v1/plans", None, None).await;
    assert_eq!(plans["default"], "free");
    assert_eq!(plans["plans"].as_array().unwrap().len(), 3);

    // --- The first account is an administrator and needs no verification ---
    let (ana, ana_user) = srv.register("ana@example.test", None).await;
    assert_eq!(ana_user["is_admin"], true);
    assert_eq!(ana_user["email_verified"], true);
    assert_eq!(srv.mails_to("ana@example.test"), 0);

    // --- Open registration: the email must be confirmed ---
    let (beto, beto_user) = srv.register("beto@example.test", None).await;
    assert_eq!(beto_user["email_verified"], false);
    assert_eq!(beto_user["plan"], "free");
    let (s, v) = srv.get("/api/v1/teams", &beto).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(v["error"]["code"], "email_not_verified");
    // The user can still see their own account.
    let (s, me) = srv.get("/api/v1/me", &beto).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(me["plan"]["id"], "free");
    // Resending right away: wait a minute.
    let (s, _) = srv
        .post("/api/v1/me/verify-email", Some(&beto), json!({}))
        .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    let mail = srv.last_mail("beto@example.test");
    assert!(
        mail.text
            .contains("https://ssh.example.test/verify-email?token=")
    );
    let token = token_in(&mail.text, "token=");
    let (s, v) = srv
        .post("/api/v1/auth/verify-email", None, json!({"token": token}))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // The link is single-use.
    let (s, v) = srv
        .post("/api/v1/auth/verify-email", None, json!({"token": token}))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"]["code"], "invalid_link");
    let (s, _) = srv.get("/api/v1/teams", &beto).await;
    assert_eq!(s, StatusCode::OK);

    // --- Password reset ---
    let (s, _) = srv
        .post(
            "/api/v1/auth/forgot-password",
            None,
            json!({"email": "nobody@example.test"}),
        )
        .await;
    assert_eq!(
        s,
        StatusCode::OK,
        "same answer even if the account does not exist"
    );
    assert_eq!(srv.mails_to("nobody@example.test"), 0);
    let (s, _) = srv
        .post(
            "/api/v1/auth/forgot-password",
            None,
            json!({"email": "beto@example.test"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    // The email is sent in the background.
    let mut reset = None;
    for _ in 0..50 {
        if let Some(m) = srv
            .state
            .mailer
            .sent()
            .into_iter()
            .find(|m| m.to == "beto@example.test" && m.subject.contains("password"))
        {
            reset = Some(m);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let reset = reset.expect("password reset email");
    let token = token_in(&reset.text, "reset-password?token=");
    let (s, v) = srv
        .post(
            "/api/v1/auth/reset-password",
            None,
            json!({"token": token, "password": "short"}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "short password");
    assert_eq!(v["error"]["code"], "password_too_short");
    assert_eq!(v["error"]["min"], 10);
    let (s, v) = srv
        .post(
            "/api/v1/auth/reset-password",
            None,
            json!({"token": token, "password": "another-secure-password"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // All their sessions are closed.
    let (s, _) = srv.get("/api/v1/me", &beto).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, v) = srv.login("beto@example.test", "secure-password").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["error"]["code"], "invalid_credentials");
    let (s, v) = srv
        .login("beto@example.test", "another-secure-password")
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let beto = v["tokens"]["access_token"].as_str().unwrap().to_string();

    // --- Email change (confirmed at the new address) ---
    let (s, v) = srv
        .post(
            "/api/v1/me/email",
            Some(&beto),
            json!({"email": "beto.new@example.test", "password": "another-secure-password"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["pending"], true);
    let token = token_in(
        &srv.last_mail("beto.new@example.test").text,
        "confirm-email?token=",
    );
    let (s, v) = srv
        .post("/api/v1/auth/confirm-email", None, json!({"token": token}))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, me) = srv.get("/api/v1/me", &beto).await;
    assert_eq!(me["user"]["email"], "beto.new@example.test");

    // --- Teams: invite by email someone without an account ---
    let (s, team) = srv
        .post("/api/v1/teams", Some(&ana), json!({"name": "Operations"}))
        .await;
    assert_eq!(s, StatusCode::OK);
    let team_id = team["id"].as_str().unwrap().to_string();
    let (s, v) = srv
        .post(
            &format!("/api/v1/teams/{team_id}/invites"),
            Some(&ana),
            json!({"email": "carla@example.test", "role": "admin"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["added"], false);
    assert_eq!(v["emailed"], true);
    assert!(
        v["web_url"]
            .as_str()
            .unwrap()
            .starts_with("https://ssh.example.test/invite/aks_inv_")
    );
    let (_, pending) = srv
        .get(&format!("/api/v1/teams/{team_id}/invites"), &ana)
        .await;
    assert_eq!(pending.as_array().unwrap().len(), 1);
    let invite_mail = srv.last_mail("carla@example.test");
    assert!(invite_mail.text.contains("Operations"));
    let token = token_in(&invite_mail.text, "/invite/");
    let (_, carla_user) = srv.register("carla@example.test", Some(&token)).await;
    // The invitation was sent to their email: it is verified.
    assert_eq!(carla_user["email_verified"], true);
    let (_, members) = srv
        .get(&format!("/api/v1/teams/{team_id}/members"), &ana)
        .await;
    let carla = members
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["email"] == "carla@example.test")
        .expect("Carla joins the team");
    assert_eq!(carla["role"], "admin");

    // Inviting someone with an account: they join directly and are notified.
    let (s, v) = srv
        .post(
            &format!("/api/v1/teams/{team_id}/invites"),
            Some(&ana),
            json!({"email": "beto.new@example.test"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["added"], true);
    let mut notified = false;
    for _ in 0..50 {
        if srv
            .state
            .mailer
            .sent()
            .iter()
            .any(|m| m.to == "beto.new@example.test" && m.subject.contains("Operations"))
        {
            notified = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(notified, "notice that they were added to the team");

    // --- Plans: limits and assignment ---
    let (s, _) = srv
        .post("/api/v1/teams", Some(&beto), json!({"name": "Mine"}))
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = srv
        .post("/api/v1/teams", Some(&beto), json!({"name": "Other"}))
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(v["error"]["code"], "plan_limit");
    // Administrators have no limits.
    let (s, _) = srv
        .post("/api/v1/teams", Some(&ana), json!({"name": "Second"}))
        .await;
    assert_eq!(s, StatusCode::OK);
    let beto_id = me["user"]["id"].as_str().unwrap().to_string();
    let (s, v) = srv
        .call(
            Method::PATCH,
            &format!("/api/v1/admin/users/{beto_id}"),
            Some(&ana),
            Some(json!({"plan": "pro"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["plan"], "pro");
    let (s, v) = srv
        .call(
            Method::PATCH,
            &format!("/api/v1/admin/users/{beto_id}"),
            Some(&ana),
            Some(json!({"plan": "team"})),
        )
        .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "a team plan cannot be assigned to an account"
    );
    assert_eq!(v["error"]["code"], "unknown_plan");
    let (s, v) = srv
        .post(
            &format!("/api/v1/admin/teams/{team_id}/plan"),
            Some(&ana),
            json!({"plan": "team"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["plan"], "team");
    let (_, my_plan) = srv.get("/api/v1/me/plan", &beto).await;
    assert_eq!(my_plan["plan"]["id"], "pro");
    assert_eq!(my_plan["usage"]["teams_owned"], 1);

    // --- Account deletion ---
    let (s, _) = srv
        .call(
            Method::DELETE,
            "/api/v1/me",
            Some(&beto),
            Some(json!({"password": "wrong"})),
        )
        .await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "wrong password: the session is still valid"
    );
    // Ana is the only administrator.
    let (s, v) = srv
        .call(
            Method::DELETE,
            "/api/v1/me",
            Some(&ana),
            Some(json!({"password": "secure-password"})),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["error"]["code"], "last_admin");
    let (s, v) = srv
        .call(
            Method::DELETE,
            "/api/v1/me",
            Some(&beto),
            Some(json!({"password": "another-secure-password"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _) = srv
        .login("beto.new@example.test", "another-secure-password")
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (_, users) = srv.get("/api/v1/admin/users", &ana).await;
    assert_eq!(users.as_array().unwrap().len(), 2);
    let (_, members) = srv
        .get(&format!("/api/v1/teams/{team_id}/members"), &ana)
        .await;
    assert_eq!(members.as_array().unwrap().len(), 2, "Beto leaves the team");
}

#[tokio::test]
async fn web_is_served_with_security_headers() {
    let srv = Srv::start().await;
    for path in ["/", "/login", "/app", "/app/teams", "/invite/aks_inv_x"] {
        let resp = srv
            .http
            .get(format!("{}{path}", srv.base))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        let h = resp.headers();
        assert!(
            h[reqwest::header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        let csp = h["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'"));
        assert_eq!(h["referrer-policy"], "no-referrer");
        let body = resp.text().await.unwrap();
        assert!(!body.contains("{{VERSION}}"));
    }
    let icon = srv
        .http
        .get(format!("{}/assets/icon.svg", srv.base))
        .send()
        .await
        .unwrap();
    assert_eq!(icon.status(), StatusCode::OK);
    assert_eq!(
        icon.headers()[reqwest::header::CONTENT_TYPE],
        "image/svg+xml"
    );
    let etag = icon.headers()[reqwest::header::ETAG].clone();
    let again = srv
        .http
        .get(format!("{}/assets/icon.svg", srv.base))
        .header(reqwest::header::IF_NONE_MATCH, etag)
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), StatusCode::NOT_MODIFIED);
    for path in [
        "/assets/missing.js",
        "/assets/index.html",
        "/something-else",
    ] {
        let s = srv
            .http
            .get(format!("{}{path}", srv.base))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(s, StatusCode::NOT_FOUND, "{path}");
    }
    // The API still answers JSON.
    let s = srv
        .http
        .get(format!("{}/api/v1/info", srv.base))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn platform_locales() {
    let srv = Srv::start().await;

    // --- Available languages ---
    let (s, v) = srv.call(Method::GET, "/api/v1/locales", None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["default"], "en");
    let names: Vec<(String, String)> = v["locales"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| {
            (
                l["code"].as_str().unwrap().to_string(),
                l["name"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert!(names.contains(&("en".into(), "English".into())), "{v}");
    assert!(names.contains(&("es".into(), "Español".into())), "{v}");

    // --- Plans carry feature ids ---
    let (_, plans) = srv.call(Method::GET, "/api/v1/plans", None, None).await;
    let free = &plans["plans"][0];
    assert_eq!(free["id"], "free");
    assert_eq!(free["name"], "Free");
    assert!(
        free["features"]
            .as_array()
            .unwrap()
            .contains(&json!("ai_own_keys"))
    );

    // --- Registration: Accept-Language, unless the body says otherwise ---
    let register = |email: &str, locale: Option<&str>, accept: &str| {
        srv.http
            .post(format!("{}/api/v1/auth/register", srv.base))
            .header(reqwest::header::ACCEPT_LANGUAGE, accept.to_string())
            .json(&json!({"email": email, "password": "secure-password", "locale": locale}))
            .send()
    };
    let v: Value = register("ana@example.test", None, "es-ES,es;q=0.9,en;q=0.8")
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["user"]["locale"], "es");
    let ana = v["tokens"]["access_token"].as_str().unwrap().to_string();
    let v: Value = register("bea@example.test", Some("en"), "es")
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["user"]["locale"], "en");
    assert!(
        srv.last_mail("bea@example.test")
            .subject
            .starts_with("Your Termoak code: ")
    );
    let v: Value = register("carla@example.test", None, "fr, es-MX;q=0.5")
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["user"]["locale"], "es");
    assert!(
        srv.last_mail("carla@example.test")
            .subject
            .starts_with("Tu código de Termoak: ")
    );
    let v: Value = register("dani@example.test", None, "de")
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["user"]["locale"], "en", "no match: English");

    // --- PATCH /me ---
    let (s, v) = srv
        .call(
            Method::PATCH,
            "/api/v1/me",
            Some(&ana),
            Some(json!({"locale": "xx"})),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"]["code"], "invalid_locale");
    let (_, me) = srv.get("/api/v1/me", &ana).await;
    assert_eq!(me["user"]["locale"], "es", "unchanged");

    // Invitations to people without an account use the inviter's language.
    let (_, team) = srv
        .post("/api/v1/teams", Some(&ana), json!({"name": "Ops"}))
        .await;
    let team_id = team["id"].as_str().unwrap().to_string();
    let (s, v) = srv
        .post(
            &format!("/api/v1/teams/{team_id}/invites"),
            Some(&ana),
            json!({"email": "nobody@example.test"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let invite = srv.last_mail("nobody@example.test");
    assert_eq!(invite.subject, "Te han invitado a Termoak");
    assert!(invite.html.contains(r#"<html lang="es">"#));

    let (s, v) = srv
        .call(
            Method::PATCH,
            "/api/v1/me",
            Some(&ana),
            Some(json!({"locale": "en-GB"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["locale"], "en");
    let (_, me) = srv.get("/api/v1/me", &ana).await;
    assert_eq!(me["user"]["locale"], "en");

    // Emails to people with an account use their own language.
    let (s, v) = srv
        .post(
            "/api/v1/auth/forgot-password",
            None,
            json!({"email": "carla@example.test"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let reset = srv.last_mail("carla@example.test");
    assert_eq!(reset.subject, "Restablece tu contraseña de Termoak");
}

/// Code of a verification email (it is in the subject).
fn code_in(mail: &termoak_server::email::Email) -> String {
    let code: String = mail.subject.chars().filter(char::is_ascii_digit).collect();
    assert_eq!(code.len(), 6, "no code in {:?}", mail.subject);
    assert!(mail.text.contains(&code), "the code is in the body too");
    code
}

impl Srv {
    /// Waits until `to` has received `n` emails (some are sent in the
    /// background) and returns the last one.
    async fn wait_mails(&self, to: &str, n: usize) -> termoak_server::email::Email {
        for _ in 0..100 {
            if self.mails_to(to) >= n {
                return self.last_mail(to);
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("{to} received {} emails, not {n}", self.mails_to(to));
    }

    async fn verify_code(&self, email: &str, code: &str) -> (StatusCode, Value) {
        self.post(
            "/api/v1/auth/verify-code",
            None,
            json!({"email": email, "code": code, "device": "phone", "platform": "ios"}),
        )
        .await
    }

    async fn resend_code(&self, email: &str) -> (StatusCode, Value) {
        self.post("/api/v1/auth/resend-code", None, json!({"email": email}))
            .await
    }

    /// Makes every verification code expire.
    async fn expire_codes(&self) {
        self.state
            .store
            .call(|c, _| {
                c.execute(
                    "UPDATE email_tokens SET expires_at = 0 WHERE purpose = 'verify_code'",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn email_verification_with_a_code() {
    let srv = Srv::start().await;
    let (_, info) = srv.call(Method::GET, "/api/v1/info", None, None).await;
    assert_eq!(info["features"]["email_verification_code"], true);
    let (ana, _) = srv.register("ana@example.test", None).await;

    // --- Registration: verification pending, a code by email ---
    let (s, reg) = srv
        .post(
            "/api/v1/auth/register",
            None,
            json!({"email": "beto@example.test", "name": "Beto", "password": "secure-password",
                   "platform": "web", "locale": "es"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{reg}");
    assert_eq!(reg["verification_required"], true);
    assert_eq!(reg["user"]["email_verified"], false);
    let restricted = reg["tokens"]["access_token"].as_str().unwrap().to_string();
    let mail = srv.last_mail("beto@example.test");
    assert!(
        mail.subject.starts_with("Tu código de Termoak: "),
        "{}",
        mail.subject
    );
    let code = code_in(&mail);
    // The link is still there for older apps.
    assert!(
        mail.text
            .contains("https://ssh.example.test/verify-email?token=")
    );

    // The tokens only reach the account itself; the error says how to verify.
    let (s, v) = srv.get("/api/v1/teams", &restricted).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(v["error"]["code"], "email_not_verified");
    assert_eq!(v["error"]["email"], "beto@example.test");
    assert_eq!(v["error"]["verification"], json!(["code", "link"]));
    let (_, me) = srv.get("/api/v1/me", &restricted).await;
    assert_eq!(me["verification_required"], true);

    // --- Signing in before verifying: pending, no new email (the code works) ---
    let (s, v) = srv.login("beto@example.test", "secure-password").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["verification_required"], true);
    let (s, _) = srv
        .get(
            "/api/v1/teams",
            v["tokens"]["access_token"].as_str().unwrap(),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(srv.mails_to("beto@example.test"), 1);

    // --- Wrong codes: one generic answer, whether or not the account exists ---
    let wrong = format!("{:06}", (code.parse::<u32>().unwrap() + 1) % 1_000_000);
    for (email, code) in [
        ("beto@example.test", wrong.as_str()),
        ("beto@example.test", "12ab56"),
        ("nobody@example.test", "123456"),
        ("not-an-email", "123456"),
        ("ana@example.test", "123456"),
    ] {
        let (s, v) = srv.verify_code(email, code).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{email} {code}: {v}");
        assert_eq!(v["error"]["code"], "invalid_code");
    }

    // --- The right code (pasted with a space) verifies and signs in ---
    let spaced = format!("{} {}", &code[..3], &code[3..]);
    let (s, v) = srv.verify_code("Beto@Example.test", &spaced).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["verification_required"], false);
    assert_eq!(v["user"]["email_verified"], true);
    let beto = v["tokens"]["access_token"].as_str().unwrap().to_string();
    let (s, _) = srv.get("/api/v1/teams", &beto).await;
    assert_eq!(s, StatusCode::OK);
    let (_, devices) = srv.get("/api/v1/devices", &beto).await;
    assert!(
        devices["devices"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["name"] == "phone" && d["platform"] == "ios"),
        "{devices}"
    );
    // The earlier, restricted tokens work fully now too.
    let (s, _) = srv.get("/api/v1/teams", &restricted).await;
    assert_eq!(s, StatusCode::OK);
    // Single use.
    let (s, v) = srv.verify_code("beto@example.test", &code).await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_code"))
    );
    let (_, audit) = srv.get("/api/v1/admin/audit", &ana).await;
    assert!(
        audit
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "auth.email_verified" && e["detail"]["via"] == "code")
    );

    // --- Five wrong tries invalidate the code, even for the right one ---
    let (_, reg) = srv
        .post(
            "/api/v1/auth/register",
            None,
            json!({"email": "carla@example.test", "password": "secure-password"}),
        )
        .await;
    assert_eq!(reg["verification_required"], true);
    let mail = srv.last_mail("carla@example.test");
    assert!(
        mail.subject.starts_with("Your Termoak code: "),
        "{}",
        mail.subject
    );
    let code = code_in(&mail);
    let wrong = format!("{:06}", (code.parse::<u32>().unwrap() + 7) % 1_000_000);
    for _ in 0..5 {
        let (s, v) = srv.verify_code("carla@example.test", &wrong).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(v["error"]["code"], "invalid_code");
    }
    let (s, v) = srv.verify_code("carla@example.test", &code).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "invalidated: {v}");
    // Too many failures for that email: blocked for a while (like the login).
    for _ in 0..10 {
        srv.verify_code("carla@example.test", &wrong).await;
    }
    let (s, v) = srv.verify_code("carla@example.test", &code).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(v["error"]["code"], "too_many_attempts");

    // --- Resend: limited per address, the same answer for unknown ones ---
    let (s, v) = srv.resend_code("carla@example.test").await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "just registered: {v}");
    assert_eq!(v["error"]["code"], "too_many_attempts");
    let wait = v["error"]["retry_after"].as_i64().unwrap();
    assert!((1..=60).contains(&wait), "{v}");
    let (s, v) = srv.resend_code("nobody@example.test").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v, json!({"ok": true, "resend_after": 60}));
    let (s, v) = srv.resend_code("NOBODY@example.test").await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{v}");
    let (s, _) = srv.resend_code("not-an-email").await;
    assert_eq!(s, StatusCode::OK);
    // A verified account gets nothing either.
    let (s, _) = srv.resend_code("ana@example.test").await;
    assert_eq!(s, StatusCode::OK);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(srv.mails_to("nobody@example.test"), 0);
    assert_eq!(srv.mails_to("ana@example.test"), 0);

    // A minute later (forgotten here), a new code replaces the old one.
    srv.state.code_emails.reset();
    let (s, _) = srv.resend_code("dora@example.test").await;
    assert_eq!(s, StatusCode::OK);
    let (_, reg) = srv
        .post(
            "/api/v1/auth/register",
            None,
            json!({"email": "dora@example.test", "password": "secure-password"}),
        )
        .await;
    assert_eq!(
        reg["verification_required"], true,
        "asking for codes before signing up does not stop the first one"
    );
    let first = code_in(&srv.wait_mails("dora@example.test", 1).await);
    srv.state.code_emails.reset();
    let (s, _) = srv.resend_code("dora@example.test").await;
    assert_eq!(s, StatusCode::OK);
    let second = code_in(&srv.wait_mails("dora@example.test", 2).await);
    if first != second {
        let (s, _) = srv.verify_code("dora@example.test", &first).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }

    // --- Expired code: signing in sends a fresh one ---
    srv.expire_codes().await;
    let (s, v) = srv.verify_code("dora@example.test", &second).await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_code"))
    );
    srv.state.code_emails.reset();
    let (s, v) = srv.login("dora@example.test", "secure-password").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["verification_required"], true);
    let fresh = code_in(&srv.wait_mails("dora@example.test", 3).await);
    // Another sign-in right away sends nothing (the code is valid).
    srv.login("dora@example.test", "secure-password").await;
    assert_eq!(srv.mails_to("dora@example.test"), 3);
    let (s, v) = srv.verify_code("dora@example.test", &fresh).await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // --- The link (older apps) still works, and then the code does not ---
    let (_, reg) = srv
        .post(
            "/api/v1/auth/register",
            None,
            json!({"email": "eva@example.test", "password": "secure-password"}),
        )
        .await;
    let eva = reg["tokens"]["access_token"].as_str().unwrap().to_string();
    let mail = srv.last_mail("eva@example.test");
    let code = code_in(&mail);
    let token = token_in(&mail.text, "verify-email?token=");
    let (s, v) = srv
        .post("/api/v1/auth/verify-email", None, json!({"token": token}))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _) = srv.get("/api/v1/teams", &eva).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = srv.verify_code("eva@example.test", &code).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (_, v) = srv.login("eva@example.test", "secure-password").await;
    assert_eq!(v["verification_required"], false);

    // --- Accounts invited to their own email are verified: no code ---
    let (s, inv) = srv
        .post(
            "/api/v1/admin/invites",
            Some(&ana),
            json!({"email": "fede@example.test"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{inv}");
    let (s, v) = srv
        .post(
            "/api/v1/auth/register",
            None,
            json!({"email": "fede@example.test", "password": "secure-password",
                   "invite": inv["token"]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["verification_required"], false);
    assert_eq!(v["user"]["email_verified"], true);
    assert!(
        srv.state
            .mailer
            .sent()
            .iter()
            .all(|m| m.to != "fede@example.test" || !m.subject.contains("code")),
        "no code email for an invited account"
    );
    let (s, _) = srv
        .get(
            "/api/v1/teams",
            v["tokens"]["access_token"].as_str().unwrap(),
        )
        .await;
    assert_eq!(s, StatusCode::OK);

    // --- An account with two-step verification needs that code too ---
    let (_, reg) = srv
        .post(
            "/api/v1/auth/register",
            None,
            json!({"email": "gael@example.test", "password": "secure-password"}),
        )
        .await;
    let gael = reg["tokens"]["access_token"].as_str().unwrap().to_string();
    let code = code_in(&srv.last_mail("gael@example.test"));
    let (s, setup) = srv
        .post("/api/v1/me/2fa/setup", Some(&gael), json!({}))
        .await;
    assert_eq!(s, StatusCode::OK, "{setup}");
    let secret = termoak_core::totp::secret_from_base32(setup["secret"].as_str().unwrap()).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let step = termoak_core::totp::step_at(now);
    let totp = |step: u64| format!("{:06}", termoak_core::totp::code_at(&secret, step));
    let (s, v) = srv
        .post(
            "/api/v1/me/2fa/enable",
            Some(&gael),
            json!({"code": totp(step)}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = srv.verify_code("gael@example.test", &code).await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("totp_required"))
    );
    let (s, v) = srv
        .post(
            "/api/v1/auth/verify-code",
            None,
            json!({"email": "gael@example.test", "code": code, "totp_code": totp(step + 1)}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "the email code was kept for this: {v}");
    assert_eq!(v["user"]["email_verified"], true);
}
