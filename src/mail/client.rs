use std::collections::{BTreeMap, BTreeSet};
use std::net::TcpStream;

use anyhow::{Context, Result, bail};
use lettre::message::header::ContentType;
use lettre::message::{Mailbox, Message};
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::{SmtpTransport, Transport};
use mailparse::{MailHeaderMap, ParsedMail, parse_mail};
use native_tls::{TlsConnector, TlsStream};
use serde::{Deserialize, Serialize};

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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EmailMessage {
    #[serde(alias = "id")]
    pub uid: u32,
    pub subject: String,
    pub from: String,
    pub date: String,
    pub preview: String,
    pub body: String,
    pub seen: bool,
}

#[derive(Clone, Debug)]
pub struct SyncedFolder {
    pub folder: String,
    pub messages: Vec<EmailMessage>,
}

#[derive(Clone, Debug)]
pub struct SyncBatch {
    pub folders: Vec<String>,
    pub synced_folders: Vec<SyncedFolder>,
}

#[derive(Clone, Debug, Default)]
pub struct SendOutcome {
    pub appended_to: Option<String>,
    pub append_error: Option<String>,
}

pub struct MailClient;

type ImapSession = imap::Session<TlsStream<TcpStream>>;

pub fn merge_messages_newest_first(
    existing: &[EmailMessage],
    incoming: &[EmailMessage],
) -> Vec<EmailMessage> {
    let mut by_uid = BTreeMap::new();
    for message in existing.iter().chain(incoming.iter()) {
        by_uid.insert(message.uid, message.clone());
    }

    by_uid.into_values().rev().collect()
}

pub fn oldest_loaded_uid(messages: &[EmailMessage]) -> Option<u32> {
    messages.iter().map(|message| message.uid).min()
}

fn sort_messages_newest_first(messages: &mut [EmailMessage]) {
    messages.sort_by(|left, right| right.uid.cmp(&left.uid));
}

impl MailClient {
    pub fn sync_folders(
        account: &ResolvedAccountConfig,
        preferred_folder: &str,
        limit: usize,
    ) -> Result<SyncBatch> {
        let mut session = open_session(account)?;
        let discovered = discover_folder_infos_with_session(&mut session)
            .unwrap_or_else(|_| folder_infos_from_names(account.folders.clone()));
        let folder_infos = if discovered.is_empty() {
            folder_infos_from_names(account.folders.clone())
        } else {
            discovered
        };
        let folders = folder_names(&folder_infos);
        let resolved_preferred = resolve_folder_alias(preferred_folder, &folder_infos)
            .unwrap_or_else(|| {
                account
                    .folders
                    .iter()
                    .find(|folder| folder.eq_ignore_ascii_case(preferred_folder))
                    .cloned()
                    .unwrap_or_else(|| preferred_folder.to_owned())
            });
        let targets = sync_targets(&folder_infos, &resolved_preferred);

        let mut synced_folders = Vec::new();
        for (index, folder) in targets.into_iter().enumerate() {
            match fetch_folder_with_session(&mut session, &folder, limit) {
                Ok(messages) => synced_folders.push(SyncedFolder { folder, messages }),
                Err(error) if index == 0 => {
                    return Err(error).with_context(|| format!("failed to sync folder '{folder}'"));
                }
                Err(_) => {}
            }
        }

        let _ = session.logout();
        Ok(SyncBatch {
            folders,
            synced_folders,
        })
    }

    pub fn send(account: &ResolvedAccountConfig, draft: &EmailDraft) -> Result<SendOutcome> {
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
        let formatted = message.formatted();

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

        let mut outcome = SendOutcome::default();
        match append_sent_copy(account, &formatted) {
            Ok(folder) => outcome.appended_to = Some(folder),
            Err(error) => outcome.append_error = Some(format!("{error:#}")),
        }

        Ok(outcome)
    }

    pub fn load_older(
        account: &ResolvedAccountConfig,
        folder: &str,
        before_uid: u32,
        limit: usize,
    ) -> Result<SyncedFolder> {
        let mut session = open_session(account)?;
        let messages = fetch_older_folder_with_session(&mut session, folder, before_uid, limit)
            .with_context(|| {
                format!(
                    "failed to load older messages from folder '{folder}' before UID {before_uid}"
                )
            })?;
        let _ = session.logout();
        Ok(SyncedFolder {
            folder: folder.to_owned(),
            messages,
        })
    }
}

fn open_session(account: &ResolvedAccountConfig) -> Result<ImapSession> {
    let tls = TlsConnector::builder().build()?;
    let client = imap::connect(
        (account.imap.host.as_str(), account.imap.port),
        account.imap.host.as_str(),
        &tls,
    )
    .with_context(|| format!("failed to connect to {}", account.imap.host))?;

    match &account.auth {
        AccountAuth::Password(secret_source) => {
            let password = secret_source.load_secret()?;
            client
                .login(account.login.as_str(), password.as_str())
                .map_err(|error| error.0)
                .with_context(|| format!("failed to log into {}", sync_auth_label(account)))
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
                .with_context(|| format!("failed to log into {}", sync_auth_label(account)))
        }
    }
}

fn fetch_folder_with_session(
    session: &mut ImapSession,
    folder: &str,
    limit: usize,
) -> Result<Vec<EmailMessage>> {
    fetch_folder_page_with_session(session, folder, FetchPage::Latest, limit)
}

fn fetch_older_folder_with_session(
    session: &mut ImapSession,
    folder: &str,
    before_uid: u32,
    limit: usize,
) -> Result<Vec<EmailMessage>> {
    fetch_folder_page_with_session(session, folder, FetchPage::OlderThan(before_uid), limit)
}

#[derive(Clone, Copy, Debug)]
enum FetchPage {
    Latest,
    OlderThan(u32),
}

fn fetch_folder_page_with_session(
    session: &mut ImapSession,
    folder: &str,
    page: FetchPage,
    limit: usize,
) -> Result<Vec<EmailMessage>> {
    session
        .select(folder)
        .with_context(|| format!("failed to select folder '{folder}'"))?;

    let search_query = match page {
        FetchPage::Latest => "ALL".to_owned(),
        FetchPage::OlderThan(0 | 1) => return Ok(vec![]),
        FetchPage::OlderThan(before_uid) => format!("UID 1:{}", before_uid - 1),
    };

    let ids = session
        .uid_search(&search_query)
        .with_context(|| format!("failed to search UIDs in folder '{folder}'"))?
        .into_iter()
        .collect::<Vec<_>>();
    let fetch_uids = page_uids(ids, page, limit);

    if fetch_uids.is_empty() {
        return Ok(vec![]);
    }

    let fetch_set = fetch_uids
        .into_iter()
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let fetched = session
        .uid_fetch(fetch_set, "(UID RFC822 FLAGS)")
        .context("failed to fetch messages by UID")?;
    let mut messages = Vec::new();

    for item in fetched.iter() {
        let raw = item.body().context("message did not contain a body")?;
        let uid = item.uid.context("message fetch did not include UID")?;
        messages.push(parse_message(uid, item.flags(), raw)?);
    }

    sort_messages_newest_first(&mut messages);
    Ok(messages)
}

fn page_uids(mut uids: Vec<u32>, page: FetchPage, limit: usize) -> Vec<u32> {
    uids.sort_unstable();
    if let FetchPage::OlderThan(before_uid) = page {
        uids.retain(|uid| *uid < before_uid);
    }

    uids.into_iter().rev().take(limit).collect()
}

fn discover_folder_infos_with_session(session: &mut ImapSession) -> Result<Vec<FolderInfo>> {
    let folders = session
        .list(None, Some("*"))
        .context("failed to list IMAP folders")?;
    let mut infos = Vec::new();

    for folder in folders.iter() {
        let selectable = !folder
            .attributes()
            .iter()
            .any(|attribute| matches!(attribute, imap::types::NameAttribute::NoSelect));
        if selectable && !folder.name().trim().is_empty() {
            let role = folder_role_from_attributes(folder.attributes())
                .unwrap_or_else(|| folder_role(folder.name()));
            infos.push(FolderInfo {
                name: folder.name().to_owned(),
                role,
            });
        }
    }

    Ok(normalize_folder_infos(infos))
}

fn append_sent_copy(account: &ResolvedAccountConfig, raw_message: &[u8]) -> Result<String> {
    let mut session = open_session(account)?;
    let discovered = discover_folder_infos_with_session(&mut session).unwrap_or_default();
    let folder_infos = if discovered.is_empty() {
        folder_infos_from_names(account.folders.clone())
    } else {
        discovered
    };
    let fallback_infos = folder_infos_from_names(account.folders.clone());
    let sent_folder = resolve_folder_for_role(FolderRole::Sent, &folder_infos)
        .or_else(|| resolve_folder_alias("Sent", &fallback_infos))
        .unwrap_or_else(|| "Sent".to_owned());

    session
        .append_with_flags(&sent_folder, raw_message, &[imap::types::Flag::Seen])
        .with_context(|| format!("failed to append sent copy to '{sent_folder}'"))?;
    let _ = session.logout();
    Ok(sent_folder)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FolderRole {
    Inbox,
    Sent,
    Drafts,
    Archive,
    Trash,
    Other,
}

#[derive(Clone, Debug)]
struct FolderInfo {
    name: String,
    role: FolderRole,
}

fn folder_infos_from_names(folders: Vec<String>) -> Vec<FolderInfo> {
    normalize_folder_infos(
        folders
            .into_iter()
            .map(|name| FolderInfo {
                role: folder_role(&name),
                name,
            })
            .collect(),
    )
}

fn folder_names(folders: &[FolderInfo]) -> Vec<String> {
    folders.iter().map(|folder| folder.name.clone()).collect()
}

fn normalize_folder_infos(folders: Vec<FolderInfo>) -> Vec<FolderInfo> {
    let mut seen = BTreeSet::new();
    let mut normalized = folders
        .into_iter()
        .filter_map(|folder| {
            let trimmed = folder.name.trim();
            if trimmed.is_empty() {
                return None;
            }

            let key = trimmed.to_ascii_lowercase();
            seen.insert(key).then(|| FolderInfo {
                name: trimmed.to_owned(),
                role: folder.role,
            })
        })
        .collect::<Vec<_>>();

    normalized.sort_by(|left, right| {
        folder_sort_key(left)
            .cmp(&folder_sort_key(right))
            .then_with(|| {
                left.name
                    .to_ascii_lowercase()
                    .cmp(&right.name.to_ascii_lowercase())
            })
    });
    normalized
}

fn sync_targets(folders: &[FolderInfo], preferred_folder: &str) -> Vec<String> {
    let mut targets = Vec::new();
    push_unique_folder(&mut targets, preferred_folder.to_owned());

    for role in [
        FolderRole::Inbox,
        FolderRole::Sent,
        FolderRole::Drafts,
        FolderRole::Archive,
        FolderRole::Trash,
    ] {
        if let Some(folder) = resolve_folder_for_role(role, folders) {
            push_unique_folder(&mut targets, folder);
        }
    }

    targets
}

fn push_unique_folder(targets: &mut Vec<String>, folder: String) {
    if !targets
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(&folder))
    {
        targets.push(folder);
    }
}

fn resolve_folder_alias(preferred: &str, folders: &[FolderInfo]) -> Option<String> {
    if let Some(folder) = folders
        .iter()
        .find(|folder| folder.name.eq_ignore_ascii_case(preferred))
    {
        return Some(folder.name.clone());
    }

    let role = folder_role(preferred);
    if role == FolderRole::Other {
        return None;
    }

    resolve_folder_for_role(role, folders)
}

fn resolve_folder_for_role(role: FolderRole, folders: &[FolderInfo]) -> Option<String> {
    folders
        .iter()
        .find(|folder| folder.role == role)
        .map(|folder| folder.name.clone())
}

fn folder_sort_key(folder: &FolderInfo) -> (u8, String) {
    let rank = match folder.role {
        FolderRole::Inbox => 0,
        FolderRole::Sent => 1,
        FolderRole::Drafts => 2,
        FolderRole::Archive => 3,
        FolderRole::Trash => 4,
        FolderRole::Other => 5,
    };

    (rank, folder.name.to_ascii_lowercase())
}

fn folder_role_from_attributes(
    attributes: &[imap::types::NameAttribute<'_>],
) -> Option<FolderRole> {
    attributes.iter().find_map(|attribute| {
        let imap::types::NameAttribute::Custom(value) = attribute else {
            return None;
        };

        match value.to_ascii_lowercase().as_str() {
            "\\inbox" => Some(FolderRole::Inbox),
            "\\sent" => Some(FolderRole::Sent),
            "\\drafts" => Some(FolderRole::Drafts),
            "\\archive" | "\\all" => Some(FolderRole::Archive),
            "\\trash" | "\\junk" => Some(FolderRole::Trash),
            _ => None,
        }
    })
}

fn folder_role(folder: &str) -> FolderRole {
    let lower = folder.to_ascii_lowercase();
    let leaf = lower
        .rsplit(['/', '.', '\\'])
        .next()
        .unwrap_or(lower.as_str())
        .trim();

    if lower == "inbox" || leaf == "inbox" {
        return FolderRole::Inbox;
    }
    if leaf.contains("sent") || lower.contains("/sent") || lower.contains("\\sent") {
        return FolderRole::Sent;
    }
    if leaf.contains("draft") {
        return FolderRole::Drafts;
    }
    if leaf.contains("archive") || leaf == "all mail" || lower.ends_with("/all mail") {
        return FolderRole::Archive;
    }
    if leaf.contains("trash") || leaf.contains("deleted") || leaf == "bin" {
        return FolderRole::Trash;
    }

    FolderRole::Other
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

fn parse_message(uid: u32, flags: &[imap::types::Flag<'_>], raw: &[u8]) -> Result<EmailMessage> {
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
        uid,
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
    let html = remove_html_blocks(
        html,
        &["head", "style", "script", "svg", "noscript", "template"],
    );
    let mut text = String::with_capacity(html.len());
    let mut index = 0;

    while index < html.len() {
        let Some(next_tag) = html[index..].find('<') else {
            text.push_str(&decode_html_entities(&html[index..]));
            break;
        };

        let tag_start = index + next_tag;
        text.push_str(&decode_html_entities(&html[index..tag_start]));

        let Some(tag_end_offset) = html[tag_start..].find('>') else {
            break;
        };
        let tag_end = tag_start + tag_end_offset;
        let tag = html[tag_start + 1..tag_end].trim().to_ascii_lowercase();
        append_tag_spacing(&tag, &mut text);
        index = tag_end + 1;
    }

    clean_extracted_text(&text)
}

fn remove_html_blocks(html: &str, tags: &[&str]) -> String {
    let lower = html.to_ascii_lowercase();
    let mut output = String::with_capacity(html.len());
    let mut index = 0;

    while index < html.len() {
        let Some(relative_tag_start) = lower[index..].find('<') else {
            output.push_str(&html[index..]);
            break;
        };
        let tag_start = index + relative_tag_start;
        output.push_str(&html[index..tag_start]);

        if let Some(tag_name) = matched_block_tag(&lower, tag_start, tags) {
            let close = format!("</{tag_name}");
            if let Some(relative_close_start) = lower[tag_start..].find(&close) {
                let close_start = tag_start + relative_close_start;
                if let Some(relative_close_end) = lower[close_start..].find('>') {
                    index = close_start + relative_close_end + 1;
                    output.push('\n');
                    continue;
                }
            }
        }

        output.push('<');
        index = tag_start + 1;
    }

    output
}

fn matched_block_tag<'a>(lower: &str, tag_start: usize, tags: &'a [&str]) -> Option<&'a str> {
    let rest = lower.get(tag_start + 1..)?;
    if rest.starts_with('/') || rest.starts_with('!') || rest.starts_with('?') {
        return None;
    }

    for tag in tags {
        if let Some(after_name) = rest.strip_prefix(tag) {
            if after_name
                .chars()
                .next()
                .is_none_or(|ch| ch.is_whitespace() || ch == '>' || ch == '/')
            {
                return Some(tag);
            }
        }
    }

    None
}

fn append_tag_spacing(tag: &str, text: &mut String) {
    let tag = tag.trim_start_matches('/');
    let tag_name = tag
        .split(|ch: char| ch.is_whitespace() || ch == '/' || ch == '>')
        .next()
        .unwrap_or_default();

    match tag_name {
        "br" | "p" | "div" | "section" | "article" | "header" | "footer" | "tr" | "table"
        | "blockquote" | "pre" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
            text.push('\n');
        }
        "li" => {
            text.push('\n');
            text.push_str("- ");
        }
        _ => {}
    }
}

fn decode_html_entities(raw: &str) -> String {
    let mut output = String::with_capacity(raw.len());
    let mut index = 0;

    while let Some(relative_amp) = raw[index..].find('&') {
        let amp = index + relative_amp;
        output.push_str(&raw[index..amp]);

        let Some(relative_semicolon) = raw[amp..].find(';') else {
            output.push('&');
            index = amp + 1;
            continue;
        };
        let semicolon = amp + relative_semicolon;
        let entity = &raw[amp + 1..semicolon];
        if let Some(decoded) = decode_entity(entity) {
            output.push(decoded);
            index = semicolon + 1;
        } else {
            output.push('&');
            index = amp + 1;
        }
    }

    output.push_str(&raw[index..]);
    output
}

fn decode_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some(' '),
        "ndash" | "mdash" => Some('-'),
        "hellip" => Some('.'),
        "zwnj" => Some('\u{200c}'),
        "zwj" => Some('\u{200d}'),
        "lrm" => Some('\u{200e}'),
        "rlm" => Some('\u{200f}'),
        "shy" => Some('\u{00ad}'),
        _ if entity.starts_with("#x") => u32::from_str_radix(&entity[2..], 16)
            .ok()
            .and_then(char::from_u32),
        _ if entity.starts_with('#') => entity[1..].parse::<u32>().ok().and_then(char::from_u32),
        _ => None,
    }
}

fn clean_extracted_text(raw: &str) -> String {
    let mut lines = Vec::new();
    let mut blank_count = 0;

    for line in raw.lines().map(clean_text_line) {
        let trimmed = line.trim();
        if trimmed.is_empty() || looks_like_css_noise(trimmed) {
            blank_count += 1;
            if blank_count <= 1 {
                lines.push(String::new());
            }
            continue;
        }

        blank_count = 0;
        lines.push(trimmed.to_owned());
    }

    lines.join("\n").trim().to_owned()
}

fn clean_text_line(raw: &str) -> String {
    let mut output = String::with_capacity(raw.len());
    let mut saw_space = false;

    for ch in raw.chars() {
        if is_zero_width_text_noise(ch) {
            continue;
        }

        if ch.is_whitespace() {
            if !saw_space {
                output.push(' ');
            }
            saw_space = true;
        } else {
            output.push(ch);
            saw_space = false;
        }
    }

    output
}

fn is_zero_width_text_noise(ch: char) -> bool {
    matches!(
        ch,
        '\u{00ad}' | '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{200e}' | '\u{200f}' | '\u{feff}'
    )
}

fn looks_like_css_noise(trimmed: &str) -> bool {
    let lower = trimmed.to_ascii_lowercase();
    lower.starts_with("@media")
        || lower.starts_with("@font-face")
        || lower.starts_with("body{")
        || lower.starts_with("body {")
        || lower.starts_with(".")
            && (lower.contains('{') || lower.contains("font-") || lower.contains("color:"))
        || lower.starts_with('#') && lower.contains('{')
        || lower.contains("font-family:") && lower.contains(';')
        || lower.contains("box-sizing:") && lower.contains(';')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(uid: u32, subject: &str) -> EmailMessage {
        EmailMessage {
            uid,
            subject: subject.to_owned(),
            from: "sender@example.com".to_owned(),
            date: "Sun, 19 Apr 2026 00:00:00 +0000".to_owned(),
            preview: subject.to_owned(),
            body: subject.to_owned(),
            seen: false,
        }
    }

    #[test]
    fn merge_messages_deduplicates_by_uid_and_keeps_newest_first() {
        let existing = vec![message(10, "ten old"), message(8, "eight")];
        let incoming = vec![
            message(9, "nine"),
            message(10, "ten fresh"),
            message(7, "seven"),
        ];

        let merged = merge_messages_newest_first(&existing, &incoming);
        let uids = merged.iter().map(|message| message.uid).collect::<Vec<_>>();
        let subjects = merged
            .iter()
            .map(|message| message.subject.as_str())
            .collect::<Vec<_>>();

        assert_eq!(uids, vec![10, 9, 8, 7]);
        assert_eq!(subjects, vec!["ten fresh", "nine", "eight", "seven"]);
    }

    #[test]
    fn oldest_loaded_uid_uses_stable_uid_identity() {
        let messages = vec![message(102, "new"), message(98, "old"), message(101, "mid")];

        assert_eq!(oldest_loaded_uid(&messages), Some(98));
        assert_eq!(oldest_loaded_uid(&[]), None);
    }

    #[test]
    fn latest_page_uses_highest_uids_first() {
        let page = page_uids(vec![2, 9, 4, 11, 1], FetchPage::Latest, 3);

        assert_eq!(page, vec![11, 9, 4]);
    }

    #[test]
    fn older_page_only_returns_uids_before_boundary() {
        let page = page_uids(vec![2, 9, 4, 11, 1], FetchPage::OlderThan(9), 3);

        assert_eq!(page, vec![4, 2, 1]);
    }
}
