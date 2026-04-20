use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::write_secure_file;
use crate::mail::EmailMessage;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CachedFolder {
    pub account_name: String,
    pub folder: String,
    pub last_sync: String,
    pub messages: Vec<EmailMessage>,
}

pub fn cache_root(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("cache")
        .join("messages")
}

pub fn load_folder(root: &Path, account_name: &str, folder: &str) -> Result<Option<CachedFolder>> {
    let path = folder_cache_path(root, account_name, folder);
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(&path)
        .with_context(|| format!("failed to read cached mail from {}", path.display()))?;
    let cached = serde_json::from_str::<CachedFolder>(&raw)
        .with_context(|| format!("failed to parse cached mail from {}", path.display()))?;
    Ok(Some(cached))
}

pub fn save_folder(
    root: &Path,
    account_name: &str,
    folder: &str,
    last_sync: &str,
    messages: &[EmailMessage],
) -> Result<()> {
    let cached = CachedFolder {
        account_name: account_name.to_owned(),
        folder: folder.to_owned(),
        last_sync: last_sync.to_owned(),
        messages: messages.to_vec(),
    };
    let raw = serde_json::to_string_pretty(&cached).context("failed to serialize mail cache")?;
    let path = folder_cache_path(root, account_name, folder);
    write_secure_file(&path, &raw)
}

pub fn remove_account(root: &Path, account_name: &str) -> Result<()> {
    let path = root.join(cache_key(account_name));
    if path.exists() {
        fs::remove_dir_all(&path)
            .with_context(|| format!("failed to remove mail cache {}", path.display()))?;
    }
    Ok(())
}

fn folder_cache_path(root: &Path, account_name: &str, folder: &str) -> PathBuf {
    root.join(cache_key(account_name))
        .join(format!("{}.json", cache_key(folder)))
}

fn cache_key(raw: &str) -> String {
    let slug = raw
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' => ch.to_ascii_lowercase(),
            _ => '-',
        })
        .collect::<String>();
    let trimmed = slug.trim_matches('-');
    let slug = if trimmed.is_empty() { "item" } else { trimmed };

    format!("{slug}-{:016x}", fnv1a64(raw.as_bytes()))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "email-client-tui-rs-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

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
    fn cache_round_trips_uid_messages() {
        let root = temp_root("round-trip");
        let messages = vec![message(42, "answer"), message(41, "older")];

        save_folder(&root, "personal", "INBOX", "2026-04-19 12:00:00", &messages)
            .expect("cache should save");
        let cached = load_folder(&root, "personal", "INBOX")
            .expect("cache should load")
            .expect("cache should exist");

        assert_eq!(cached.account_name, "personal");
        assert_eq!(cached.folder, "INBOX");
        assert_eq!(
            cached
                .messages
                .iter()
                .map(|message| message.uid)
                .collect::<Vec<_>>(),
            vec![42, 41]
        );

        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn cache_accepts_legacy_id_message_field() {
        let root = temp_root("legacy-id");
        let path = folder_cache_path(&root, "personal", "INBOX");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("cache parent should be created");
        }
        fs::write(
            &path,
            r#"{
  "account_name": "personal",
  "folder": "INBOX",
  "last_sync": "2026-04-19 12:00:00",
  "messages": [
    {
      "id": 77,
      "subject": "legacy",
      "from": "sender@example.com",
      "date": "Sun, 19 Apr 2026 00:00:00 +0000",
      "preview": "legacy",
      "body": "legacy",
      "seen": false
    }
  ]
}"#,
        )
        .expect("legacy cache fixture should be written");

        let cached = load_folder(&root, "personal", "INBOX")
            .expect("legacy cache should parse")
            .expect("legacy cache should exist");

        assert_eq!(cached.messages[0].uid, 77);
        assert_eq!(cached.messages[0].subject, "legacy");

        fs::remove_dir_all(root).ok();
    }
}
