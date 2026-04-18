use anyhow::{Context, Result, bail};
use lettre::message::header::ContentType;
use lettre::message::{Mailbox, Message};
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::{SmtpTransport, Transport};
use mailparse::{MailHeaderMap, ParsedMail, parse_mail};
use native_tls::TlsConnector;

use crate::config::{AccountAuth, OAuthProviderKind, ResolvedAccountConfig, SmtpTlsMode};

use super::oauth::load_access_token;

#[derive(Clone, Debug, Default)]
pub struct EmailDraft {
    pub to: String,
    pub cc: String,
    pub bcc: String,
    pub subject: String,
    pub body: String,
}

#[derive(Clone, Debug)]
pub struct EmailMessage {
    pub id: u32,
    pub subject: String,
    pub from: String,
    pub date: String,
    pub preview: String,
    pub body: String,
    pub seen: bool,
}

pub struct MailClient;

impl MailClient {
    pub fn sync_folder(
        account: &ResolvedAccountConfig,
        folder: &str,
        limit: usize,
    ) -> Result<Vec<EmailMessage>> {
        let tls = TlsConnector::builder().build()?;
        let client = imap::connect(
            (account.imap.host.as_str(), account.imap.port),
            account.imap.host.as_str(),
            &tls,
        )
        .with_context(|| format!("failed to connect to {}", account.imap.host))?;

        let mut session = match &account.auth {
            AccountAuth::Password(secret_source) => {
                let password = secret_source.load_secret()?;
                client
                    .login(account.login.as_str(), password.as_str())
                    .map_err(|error| error.0)
                    .with_context(|| format!("failed to log into {}", sync_auth_label(account)))?
            }
            AccountAuth::OAuth(oauth) => {
                let access_token = load_access_token(oauth)?;
                let xoauth = XOAuth2Authenticator {
                    user: account.login.clone(),
                    access_token,
                };
                client
                    .authenticate("XOAUTH2", &xoauth)
                    .map_err(|(error, _)| error)
                    .with_context(|| format!("failed to log into {}", sync_auth_label(account)))?
            }
        };

        session
            .select(folder)
            .with_context(|| format!("failed to select folder '{folder}'"))?;

        let mut ids: Vec<u32> = session
            .search("ALL")
            .context("failed to search selected folder")?
            .into_iter()
            .collect();
        ids.sort_unstable();

        if ids.is_empty() {
            let _ = session.logout();
            return Ok(vec![]);
        }

        let fetch_set = ids
            .into_iter()
            .rev()
            .take(limit)
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let fetched = session
            .fetch(fetch_set, "RFC822 FLAGS")
            .context("failed to fetch messages")?;
        let mut messages = Vec::new();

        for item in fetched.iter() {
            let raw = item.body().context("message did not contain a body")?;
            messages.push(parse_message(item.message, item.flags(), raw)?);
        }

        let _ = session.logout();
        Ok(messages)
    }

    pub fn send(account: &ResolvedAccountConfig, draft: &EmailDraft) -> Result<()> {
        if draft.to.trim().is_empty() {
            bail!("draft needs at least one recipient");
        }
        if draft.subject.trim().is_empty() {
            bail!("draft subject is empty");
        }
        if draft.body.trim().is_empty() {
            bail!("draft body is empty");
        }

        let from = Mailbox::new(
            account.display_name.clone(),
            account
                .email
                .parse()
                .with_context(|| format!("invalid sender email '{}'", account.email))?,
        );

        let mut builder = Message::builder().from(from);
        for recipient in parse_recipients(&draft.to)? {
            builder = builder.to(recipient);
        }
        for recipient in parse_recipients(&draft.cc)? {
            builder = builder.cc(recipient);
        }
        for recipient in parse_recipients(&draft.bcc)? {
            builder = builder.bcc(recipient);
        }

        let message = builder
            .subject(&draft.subject)
            .header(ContentType::TEXT_PLAIN)
            .body(draft.body.clone())
            .context("failed to build SMTP message")?;

        let (credentials, mechanism) = match &account.auth {
            AccountAuth::Password(secret_source) => (
                Credentials::new(account.login.clone(), secret_source.load_secret()?),
                None,
            ),
            AccountAuth::OAuth(oauth) => (
                Credentials::new(account.login.clone(), load_access_token(oauth)?),
                Some(Mechanism::Xoauth2),
            ),
        };
        let transport = build_transport(account, credentials, mechanism)?;
        transport.send(&message).context("SMTP send failed")?;
        Ok(())
    }
}

fn build_transport(
    account: &ResolvedAccountConfig,
    credentials: Credentials,
    mechanism: Option<Mechanism>,
) -> Result<SmtpTransport> {
    let mut builder = match account.smtp.tls_mode {
        SmtpTlsMode::Wrapper => SmtpTransport::relay(account.smtp.host.as_str())
            .with_context(|| format!("failed to build SMTP relay for {}", account.smtp.host))?,
        SmtpTlsMode::Starttls => SmtpTransport::starttls_relay(account.smtp.host.as_str())
            .with_context(|| format!("failed to build STARTTLS relay for {}", account.smtp.host))?,
        SmtpTlsMode::Plain => SmtpTransport::builder_dangerous(account.smtp.host.as_str()),
    };

    builder = builder.port(account.smtp.port).credentials(credentials);
    if let Some(mechanism) = mechanism {
        builder = builder.authentication(vec![mechanism]);
    }
    Ok(builder.build())
}

struct XOAuth2Authenticator {
    user: String,
    access_token: String,
}

impl imap::Authenticator for XOAuth2Authenticator {
    type Response = String;

    fn process(&self, _: &[u8]) -> Self::Response {
        format!(
            "user={}\x01auth=Bearer {}\x01\x01",
            self.user, self.access_token
        )
    }
}

fn sync_auth_label(account: &ResolvedAccountConfig) -> String {
    match &account.auth {
        AccountAuth::Password(_) if account.provider == crate::config::ProviderKind::Gmail => {
            format!(
                "{} (Gmail password auth; use an App Password or run :authorize-account / o for OAuth)",
                account.sender_label()
            )
        }
        AccountAuth::Password(_) if account.provider == crate::config::ProviderKind::Outlook => {
            format!(
                "{} (Outlook password auth is often blocked; run :authorize-account / o for OAuth)",
                account.sender_label()
            )
        }
        AccountAuth::OAuth(oauth) => match oauth.provider {
            OAuthProviderKind::GoogleMail => {
                format!("{} via Google OAuth", account.sender_label())
            }
            OAuthProviderKind::MicrosoftMail => {
                format!("{} via Microsoft OAuth", account.sender_label())
            }
        },
        AccountAuth::Password(_) => account.sender_label(),
    }
}

fn parse_recipients(raw: &str) -> Result<Vec<Mailbox>> {
    raw.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse::<Mailbox>()
                .with_context(|| format!("invalid recipient mailbox '{part}'"))
        })
        .collect()
}

fn parse_message(
    message_id: u32,
    flags: &[imap::types::Flag<'_>],
    raw: &[u8],
) -> Result<EmailMessage> {
    let parsed = parse_mail(raw).context("failed to parse message body")?;
    let headers = parsed.get_headers();
    let subject = headers
        .get_first_value("Subject")
        .unwrap_or_else(|| "(no subject)".to_owned());
    let from = headers
        .get_first_value("From")
        .unwrap_or_else(|| "(unknown sender)".to_owned());
    let date = headers.get_first_value("Date").unwrap_or_default();
    let body = extract_best_body(&parsed);
    let preview = preview_text(&body);
    let seen = flags
        .iter()
        .any(|flag| matches!(flag, imap::types::Flag::Seen));

    Ok(EmailMessage {
        id: message_id,
        subject,
        from,
        date,
        preview,
        body,
        seen,
    })
}

fn extract_best_body(part: &ParsedMail<'_>) -> String {
    if part.subparts.is_empty() {
        let mime = part.ctype.mimetype.to_ascii_lowercase();
        if mime == "text/html" {
            return part
                .get_body()
                .map(|html| strip_html(&html))
                .unwrap_or_default();
        }

        return part.get_body().unwrap_or_default();
    }

    for child in &part.subparts {
        if child.ctype.mimetype.eq_ignore_ascii_case("text/plain") {
            let body = child.get_body().unwrap_or_default();
            if !body.trim().is_empty() {
                return body;
            }
        }
    }

    for child in &part.subparts {
        let body = extract_best_body(child);
        if !body.trim().is_empty() {
            return body;
        }
    }

    String::new()
}

fn preview_text(body: &str) -> String {
    let mut preview = String::with_capacity(body.len());
    let mut saw_whitespace = false;

    for ch in body.chars() {
        if ch.is_whitespace() {
            if !saw_whitespace && !preview.is_empty() {
                preview.push(' ');
            }
            saw_whitespace = true;
            continue;
        }

        saw_whitespace = false;
        preview.push(ch);
        if preview.chars().count() >= 140 {
            preview.push_str("...");
            break;
        }
    }

    if preview.is_empty() {
        "(empty message)".to_owned()
    } else {
        preview
    }
}

fn strip_html(html: &str) -> String {
    let mut text = String::with_capacity(html.len());
    let mut in_tag = false;

    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => text.push(ch),
            _ => {}
        }
    }

    text
}
