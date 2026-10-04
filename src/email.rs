//! Outgoing email: email verification, password reset and invitations.
//!
//! Without `[email] smtp_url` nothing is sent and the website and apps show
//! the links to copy by hand. With `log://` emails are written to the log and
//! kept in memory (development and tests).
//!
//! Templates are translated (`locales/<lang>.json`, keys `email.*`) and take
//! the recipient's locale.

use std::time::Duration;

use lettre::message::{Mailbox, MultiPart};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use parking_lot::Mutex;
use rust_i18n::t;

use crate::config::EmailSection;

/// A composed email.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email {
    pub to: String,
    pub subject: String,
    pub text: String,
    pub html: String,
}

enum Transport {
    Disabled,
    Smtp(Box<AsyncSmtpTransport<Tokio1Executor>>),
    Log(Mutex<Vec<Email>>),
}

pub struct Mailer {
    transport: Transport,
    from: Option<Mailbox>,
}

/// Emails kept in memory with `log://`.
const LOG_KEEP: usize = 100;

impl Mailer {
    pub fn from_config(cfg: &EmailSection) -> anyhow::Result<Self> {
        let Some(url) = cfg
            .smtp_url
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
        else {
            return Ok(Self::disabled());
        };
        let from: Mailbox = cfg
            .from
            .parse()
            .map_err(|e| anyhow::anyhow!("[email] from is not a valid address: {e}"))?;
        let transport = if url.starts_with("log:") {
            tracing::warn!("email in log:// mode: emails (with their links) go to the log");
            Transport::Log(Mutex::new(Vec::new()))
        } else {
            let t = AsyncSmtpTransport::<Tokio1Executor>::from_url(url)
                .map_err(|e| anyhow::anyhow!("invalid [email] smtp_url: {e}"))?
                .timeout(Some(Duration::from_secs(20)))
                .build();
            Transport::Smtp(Box::new(t))
        };
        Ok(Self {
            transport,
            from: Some(from),
        })
    }

    pub fn disabled() -> Self {
        Self {
            transport: Transport::Disabled,
            from: None,
        }
    }

    /// Email is configured.
    pub fn enabled(&self) -> bool {
        !matches!(self.transport, Transport::Disabled)
    }

    /// Emails sent in `log://` mode (oldest first).
    pub fn sent(&self) -> Vec<Email> {
        match &self.transport {
            Transport::Log(v) => v.lock().clone(),
            _ => Vec::new(),
        }
    }

    /// Sends an email. Does nothing when email is not configured.
    pub async fn send(&self, email: Email) -> anyhow::Result<()> {
        let from = match (&self.transport, &self.from) {
            (Transport::Disabled, _) | (_, None) => return Ok(()),
            (_, Some(from)) => from.clone(),
        };
        match &self.transport {
            Transport::Disabled => Ok(()),
            Transport::Log(list) => {
                tracing::info!(to = %email.to, subject = %email.subject, "email (log://):\n{}", email.text);
                let mut list = list.lock();
                list.push(email);
                let excess = list.len().saturating_sub(LOG_KEEP);
                list.drain(..excess);
                Ok(())
            }
            Transport::Smtp(t) => {
                let to: Mailbox = email
                    .to
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid recipient: {e}"))?;
                let msg = Message::builder()
                    .from(from)
                    .to(to)
                    .subject(email.subject)
                    .multipart(MultiPart::alternative_plain_html(email.text, email.html))?;
                t.send(msg).await?;
                Ok(())
            }
        }
    }

    /// Sends in the background (errors are only logged).
    pub fn send_later(self: &std::sync::Arc<Self>, email: Email) {
        if !self.enabled() {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            let to = email.to.clone();
            if let Err(e) = me.send(email).await {
                tracing::warn!(%to, error = %e, "could not send an email");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

/// Escapes text for HTML.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Email with a paragraph, a button and a final note, all from the
/// `email.<template>.*` keys. `intro` is already translated.
fn compose(
    to: &str,
    locale: &str,
    subject: String,
    intro: String,
    template: &str,
    link: &str,
) -> Email {
    let locale = crate::i18n::resolve(locale);
    let button = t!(format!("email.{template}.button"), locale = locale);
    let note = t!(format!("email.{template}.note"), locale = locale);
    let signature = t!("email.signature", locale = locale);
    let text = format!("{intro}\n\n{button}: {link}\n\n{note}\n\n{signature}\n");
    let html = format!(
        r#"<!doctype html><html lang="{lang}"><body style="margin:0;padding:24px;background:#0f1115;font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#e6e8ee">
<table role="presentation" width="100%" style="max-width:520px;margin:0 auto;background:#171a21;border-radius:12px;padding:28px">
<tr><td style="font-size:18px;font-weight:600;color:#9fd36b">Termoak</td></tr>
<tr><td style="padding:16px 0;font-size:15px;line-height:1.5">{intro}</td></tr>
<tr><td><a href="{link}" style="display:inline-block;background:#6fbf3b;color:#0f1115;text-decoration:none;font-weight:600;padding:10px 18px;border-radius:8px">{button}</a></td></tr>
<tr><td style="padding-top:16px;font-size:12px;color:#8a90a0;word-break:break-all">{link}</td></tr>
<tr><td style="padding-top:16px;font-size:13px;color:#8a90a0">{note}</td></tr>
</table></body></html>"#,
        lang = escape(locale),
        intro = escape(&intro),
        button = escape(&button),
        link = escape(link),
        note = escape(&note),
    );
    Email {
        to: to.to_string(),
        subject,
        text,
        html,
    }
}

pub fn verify_email(to: &str, locale: &str, name: &str, link: &str) -> Email {
    let l = crate::i18n::resolve(locale);
    compose(
        to,
        l,
        t!("email.verify.subject", locale = l).into_owned(),
        t!("email.verify.intro", locale = l, name = name).into_owned(),
        "verify",
        link,
    )
}

pub fn change_email(to: &str, locale: &str, name: &str, link: &str) -> Email {
    let l = crate::i18n::resolve(locale);
    compose(
        to,
        l,
        t!("email.change.subject", locale = l).into_owned(),
        t!("email.change.intro", locale = l, name = name).into_owned(),
        "change",
        link,
    )
}

pub fn reset_password(to: &str, locale: &str, name: &str, link: &str) -> Email {
    let l = crate::i18n::resolve(locale);
    compose(
        to,
        l,
        t!("email.reset.subject", locale = l).into_owned(),
        t!("email.reset.intro", locale = l, name = name).into_owned(),
        "reset",
        link,
    )
}

/// Invitation to create an account. The recipient has no account yet, so
/// `locale` is the inviter's.
pub fn account_invite(
    to: &str,
    locale: &str,
    inviter: &str,
    team: Option<&str>,
    link: &str,
) -> Email {
    let l = crate::i18n::resolve(locale);
    let intro = match team {
        Some(team) => t!(
            "email.invite.intro_team",
            locale = l,
            inviter = inviter,
            team = team
        ),
        None => t!("email.invite.intro", locale = l, inviter = inviter),
    };
    compose(
        to,
        l,
        t!("email.invite.subject", locale = l).into_owned(),
        intro.into_owned(),
        "invite",
        link,
    )
}

pub fn added_to_team(to: &str, locale: &str, inviter: &str, team: &str, link: &str) -> Email {
    let l = crate::i18n::resolve(locale);
    compose(
        to,
        l,
        t!("email.team_added.subject", locale = l, team = team).into_owned(),
        t!(
            "email.team_added.intro",
            locale = l,
            inviter = inviter,
            team = team
        )
        .into_owned(),
        "team_added",
        link,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_escape_user_text() {
        let e = account_invite(
            "a@b.es",
            "en",
            "<script>alert(1)</script>",
            Some("Ops & \"Co\""),
            "https://x/invite/aks_inv_1",
        );
        assert!(!e.html.contains("<script>"));
        assert!(e.html.contains("&lt;script&gt;"));
        assert!(e.html.contains("Ops &amp; &quot;Co&quot;"));
        assert!(e.text.contains("https://x/invite/aks_inv_1"));
    }

    #[test]
    fn templates_follow_the_locale() {
        let en = verify_email("a@b.es", "en", "Ann", "https://x/v");
        assert_eq!(en.subject, "Confirm your email on Termoak");
        assert!(en.text.starts_with("Hi Ann."));
        assert!(en.html.contains(r#"<html lang="en">"#));
        let es = added_to_team("a@b.es", "es-ES", "Bea", "Ops", "https://x/teams");
        assert_eq!(es.subject, "Ahora formas parte de «Ops»");
        assert!(es.html.contains(r#"<html lang="es">"#));
        assert!(es.text.contains("Ver mis equipos: https://x/teams"));
        // Unknown languages fall back to English.
        let xx = reset_password("a@b.es", "xx", "Ann", "https://x/r");
        assert_eq!(xx.subject, "Reset your Termoak password");
    }

    #[tokio::test]
    async fn log_transport_keeps_mail() {
        let m = Mailer::from_config(&EmailSection {
            smtp_url: Some("log://".into()),
            ..Default::default()
        })
        .unwrap();
        assert!(m.enabled());
        m.send(verify_email(
            "a@b.es",
            "en",
            "Ana",
            "https://x/verify-email?token=t",
        ))
        .await
        .unwrap();
        assert_eq!(m.sent().len(), 1);
        assert!(!Mailer::disabled().enabled());
        assert!(
            Mailer::from_config(&EmailSection {
                smtp_url: Some("smtps://u:p@smtp.example.com:465".into()),
                ..Default::default()
            })
            .unwrap()
            .enabled()
        );
    }
}
