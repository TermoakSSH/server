//! An in-process OpenID provider and a DNS server answering TXT records
//! (SSO tests).
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Form, Query, State};
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use parking_lot::Mutex;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// The fake identity provider
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct Person {
    pub sub: String,
    pub email: String,
    pub verified: bool,
}

pub struct Idp {
    pub base: String,
    key: EcdsaKeyPair,
    /// The person the next authorization signs in.
    pub next: Mutex<Person>,
    /// code → (nonce, challenge, redirect_uri, person).
    codes: Mutex<HashMap<String, (String, String, String, Person)>>,
    /// Break the next ID token: `nonce`, `aud` or `sig`.
    pub tamper: Mutex<Option<&'static str>>,
}

#[derive(serde::Deserialize)]
struct AuthQ {
    client_id: String,
    redirect_uri: String,
    state: String,
    nonce: String,
    code_challenge: String,
    code_challenge_method: String,
}

async fn idp_discovery(State(idp): State<Arc<Idp>>) -> Json<Value> {
    Json(json!({
        "issuer": idp.base,
        "authorization_endpoint": format!("{}/auth", idp.base),
        "token_endpoint": format!("{}/token", idp.base),
        "jwks_uri": format!("{}/jwks", idp.base),
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
    }))
}

async fn idp_jwks(State(idp): State<Arc<Idp>>) -> Json<Value> {
    let pk = idp.key.public_key().as_ref();
    Json(
        json!({"keys": [{"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
        "x": URL_SAFE_NO_PAD.encode(&pk[1..33]), "y": URL_SAFE_NO_PAD.encode(&pk[33..65])}]}),
    )
}

async fn idp_auth(State(idp): State<Arc<Idp>>, Query(q): Query<AuthQ>) -> impl IntoResponse {
    assert_eq!(q.client_id, "termoak");
    assert_eq!(q.code_challenge_method, "S256");
    let code = termoak_core::sso::random_token();
    let person = idp.next.lock().clone();
    idp.codes.lock().insert(
        code.clone(),
        (q.nonce, q.code_challenge, q.redirect_uri.clone(), person),
    );
    Redirect::to(&format!("{}?code={code}&state={}", q.redirect_uri, q.state))
}

async fn idp_token(
    State(idp): State<Arc<Idp>>,
    Form(f): Form<HashMap<String, String>>,
) -> axum::response::Response {
    let err = |e: &str| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({"error": e})),
        )
            .into_response()
    };
    if f.get("client_id").map(String::as_str) != Some("termoak")
        || f.get("client_secret").map(String::as_str) != Some("s3cret")
    {
        return err("invalid_client");
    }
    let Some((nonce, challenge, redirect, person)) = idp
        .codes
        .lock()
        .remove(f.get("code").map(String::as_str).unwrap_or(""))
    else {
        return err("invalid_grant");
    };
    if f.get("redirect_uri") != Some(&redirect) {
        return err("invalid_grant");
    }
    if termoak_core::sso::pkce_challenge(f.get("code_verifier").map(String::as_str).unwrap_or(""))
        != challenge
    {
        return err("invalid_grant");
    }
    let now = chrono::Utc::now().timestamp();
    let tamper = idp.tamper.lock().take();
    let claims = json!({
        "iss": idp.base,
        "aud": if tamper == Some("aud") { "someone-else" } else { "termoak" },
        "sub": person.sub, "email": person.email, "email_verified": person.verified,
        "name": person.sub.to_uppercase(),
        "nonce": if tamper == Some("nonce") { "wrong" } else { nonce.as_str() },
        "iat": now, "exp": now + 300,
    });
    let header =
        URL_SAFE_NO_PAD.encode(json!({"alg": "ES256", "kid": "k1", "typ": "JWT"}).to_string());
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let msg = format!("{header}.{payload}");
    let mut sig = idp
        .key
        .sign(&SystemRandom::new(), msg.as_bytes())
        .unwrap()
        .as_ref()
        .to_vec();
    if tamper == Some("sig") {
        sig[5] ^= 1;
    }
    let token = format!("{msg}.{}", URL_SAFE_NO_PAD.encode(sig));
    Json(json!({"access_token": "at", "token_type": "Bearer", "id_token": token})).into_response()
}

pub async fn start_idp() -> Arc<Idp> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let idp = Arc::new(Idp {
        base,
        key,
        next: Default::default(),
        codes: Default::default(),
        tamper: Default::default(),
    });
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(idp_discovery))
        .route("/jwks", get(idp_jwks))
        .route("/auth", get(idp_auth))
        .route("/token", post(idp_token))
        .with_state(idp.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    idp
}

// ---------------------------------------------------------------------------
// A DNS server answering TXT records
// ---------------------------------------------------------------------------

pub type Txt = Arc<Mutex<HashMap<String, String>>>;

pub async fn start_dns() -> (String, Txt) {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap().to_string();
    let records: Txt = Default::default();
    let recs = records.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                break;
            };
            let q = &buf[..n];
            if n < 12 {
                continue;
            }
            // QNAME labels → name.
            let mut i = 12;
            let mut labels = Vec::new();
            while i < n && q[i] != 0 {
                let l = q[i] as usize;
                labels.push(String::from_utf8_lossy(&q[i + 1..i + 1 + l]).to_ascii_lowercase());
                i += 1 + l;
            }
            let qend = i + 1 + 4;
            let name = labels.join(".");
            let answer = recs.lock().get(&name).cloned();
            let mut out = Vec::new();
            out.extend_from_slice(&q[..2]);
            out.extend_from_slice(if answer.is_some() {
                &[0x81, 0x80]
            } else {
                &[0x81, 0x83]
            });
            out.extend_from_slice(&[0, 1, 0, answer.is_some() as u8, 0, 0, 0, 0]);
            out.extend_from_slice(&q[12..qend]);
            if let Some(text) = answer {
                out.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 60]);
                let rd = text.as_bytes();
                out.extend_from_slice(&((rd.len() + 1) as u16).to_be_bytes());
                out.push(rd.len() as u8);
                out.extend_from_slice(rd);
            }
            let _ = sock.send_to(&out, peer).await;
        }
    });
    (addr, records)
}
