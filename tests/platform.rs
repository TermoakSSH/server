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
    assert_eq!(
        srv.last_mail("bea@example.test").subject,
        "Confirm your email on Termoak"
    );
    let v: Value = register("carla@example.test", None, "fr, es-MX;q=0.5")
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["user"]["locale"], "es");
    assert_eq!(
        srv.last_mail("carla@example.test").subject,
        "Confirma tu email en Termoak"
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
