use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AppConfig {
    #[serde(default)]
    pub accounts: Vec<AccountConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_account: Option<String>,
}

#[derive(Clone, Debug)]
pub struct LoadedConfig {
    pub path: PathBuf,
    pub config: AppConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountConfig {
    pub name: String,
    pub provider: ProviderKind,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub folders: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OAuthConfig>,
    #[serde(default)]
    pub imap: Option<ImapOverride>,
    #[serde(default)]
    pub smtp: Option<SmtpOverride>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderKind {
    Gmail,
    Outlook,
    Yahoo,
    Icloud,
    Fastmail,
    Custom,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ImapOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SmtpOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_mode: Option<SmtpTlsMode>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SmtpTlsMode {
    Wrapper,
    Starttls,
    Plain,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OAuthConfig {
    pub provider: OAuthProviderKind,
    pub data_file: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum OAuthProviderKind {
    GoogleMail,
    MicrosoftMail,
}

#[derive(Clone, Debug)]
pub struct ResolvedAccountConfig {
    pub name: String,
    pub provider: ProviderKind,
    pub provider_label: &'static str,
    pub email: String,
    pub login: String,
    pub display_name: Option<String>,
    pub folders: Vec<String>,
    pub imap: ImapSettings,
    pub smtp: SmtpSettings,
    pub auth: AccountAuth,
}

#[derive(Clone, Debug)]
pub struct ImapSettings {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug)]
pub struct SmtpSettings {
    pub host: String,
    pub port: u16,
    pub tls_mode: SmtpTlsMode,
}

#[derive(Clone, Debug)]
pub enum AccountAuth {
    Password(SecretSource),
    OAuth(ResolvedOAuthConfig),
}

#[derive(Clone, Debug)]
pub enum SecretSource {
    Env(String),
    Command(String),
    File(PathBuf),
}

#[derive(Clone, Debug)]
pub struct ResolvedOAuthConfig {
    pub provider: OAuthProviderKind,
    pub data_file: PathBuf,
}

#[derive(Clone, Debug)]
struct ProviderPreset {
    label: &'static str,
    imap: ImapSettings,
    smtp: SmtpSettings,
    folders: Vec<String>,
}

impl AppConfig {
    pub fn load() -> Result<LoadedConfig> {
        let path = default_config_path()?;
        if !path.exists() {
            return Ok(LoadedConfig {
                path,
                config: AppConfig::default(),
            });
        }

        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read config file at {}", path.display()))?;
        let config = toml::from_str::<AppConfig>(&raw)
            .with_context(|| format!("failed to parse config file at {}", path.display()))?;

        Ok(LoadedConfig { path, config })
    }

    pub fn save_to(&self, path: &PathBuf) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        let raw = toml::to_string_pretty(self).context("failed to serialize config")?;
        fs::write(path, raw).with_context(|| format!("failed to write {}", path.display()))?;
        tighten_permissions(path)?;
        Ok(())
    }
}

impl AccountConfig {
    pub fn resolve(&self) -> Result<ResolvedAccountConfig> {
        let preset = ProviderPreset::for_kind(self.provider);
        let imap = merge_imap(&preset, self.imap.as_ref())?;
        let smtp = merge_smtp(&preset, self.smtp.as_ref())?;
        let folders = if self.folders.is_empty() {
            preset.folders
        } else {
            self.folders.clone()
        };

        if folders.is_empty() {
            bail!("account '{}' does not define any folders", self.name);
        }

        let password_source = match (
            &self.password_env,
            &self.password_command,
            &self.password_file,
        ) {
            (Some(var), None, None) => Some(SecretSource::Env(var.clone())),
            (None, Some(command), None) => Some(SecretSource::Command(command.clone())),
            (None, None, Some(path)) => Some(SecretSource::File(PathBuf::from(path))),
            (None, None, None) => None,
            _ => bail!(
                "account '{}' must use exactly one of password_env, password_command, or password_file",
                self.name
            ),
        };

        if let Some(oauth) = &self.oauth {
            let expected_provider = self.provider.oauth_provider().ok_or_else(|| {
                anyhow!(
                    "account '{}' provider '{}' does not support OAuth",
                    self.name,
                    self.provider.label()
                )
            })?;

            if oauth.provider != expected_provider {
                bail!(
                    "account '{}' uses OAuth provider '{}' that does not match '{}'",
                    self.name,
                    oauth.provider.label(),
                    self.provider.label()
                );
            }
        }

        let auth = match (&self.oauth, password_source) {
            (Some(_), Some(_)) => bail!(
                "account '{}' must use exactly one auth source: password_env, password_command, password_file, or oauth",
                self.name
            ),
            (Some(oauth), None) => AccountAuth::OAuth(ResolvedOAuthConfig {
                provider: oauth.provider,
                data_file: PathBuf::from(&oauth.data_file),
            }),
            (None, Some(secret_source)) => AccountAuth::Password(secret_source),
            (None, None) => bail!(
                "account '{}' needs password_env, password_command, password_file, or oauth to authenticate",
                self.name
            ),
        };

        Ok(ResolvedAccountConfig {
            name: self.name.clone(),
            provider: self.provider,
            provider_label: preset.label,
            email: self.email.clone(),
            login: self.login.clone().unwrap_or_else(|| self.email.clone()),
            display_name: self.display_name.clone(),
            folders,
            imap,
            smtp,
            auth,
        })
    }

    pub fn auth_file_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        if let Some(path) = &self.password_file {
            paths.push(PathBuf::from(path));
        }
        if let Some(oauth) = &self.oauth {
            paths.push(PathBuf::from(&oauth.data_file));
        }

        paths
    }
}

impl SecretSource {
    pub fn load_secret(&self) -> Result<String> {
        let secret = match self {
            SecretSource::Env(var) => env::var(var)
                .with_context(|| format!("missing password env var '{var}'"))?
                .trim()
                .to_owned(),
            SecretSource::Command(command) => {
                let output = Command::new("sh")
                    .arg("-lc")
                    .arg(command)
                    .output()
                    .with_context(|| format!("failed to run password command `{command}`"))?;

                if !output.status.success() {
                    bail!(
                        "password command `{command}` failed with status {}",
                        output.status
                    );
                }

                String::from_utf8(output.stdout)
                    .context("password command output was not valid utf-8")?
                    .trim()
                    .to_owned()
            }
            SecretSource::File(path) => fs::read_to_string(path)
                .with_context(|| format!("failed to read password file {}", path.display()))?
                .trim()
                .to_owned(),
        };

        if secret.is_empty() {
            return Err(anyhow!("resolved account secret was empty"));
        }

        Ok(secret)
    }
}

impl ResolvedAccountConfig {
    pub fn sender_label(&self) -> String {
        self.display_name
            .as_ref()
            .map(|name| format!("{name} <{}>", self.email))
            .unwrap_or_else(|| self.email.clone())
    }

    pub fn auth_label(&self) -> &'static str {
        match &self.auth {
            AccountAuth::Password(_) => "password",
            AccountAuth::OAuth(oauth) => oauth.provider.label(),
        }
    }
}

impl ProviderKind {
    pub const ALL: [ProviderKind; 6] = [
        ProviderKind::Gmail,
        ProviderKind::Outlook,
        ProviderKind::Yahoo,
        ProviderKind::Icloud,
        ProviderKind::Fastmail,
        ProviderKind::Custom,
    ];

    pub fn label(self) -> &'static str {
        match self {
            ProviderKind::Gmail => "Gmail",
            ProviderKind::Outlook => "Outlook",
            ProviderKind::Yahoo => "Yahoo",
            ProviderKind::Icloud => "iCloud",
            ProviderKind::Fastmail => "Fastmail",
            ProviderKind::Custom => "Custom",
        }
    }

    pub fn requires_custom_servers(self) -> bool {
        matches!(self, ProviderKind::Custom)
    }

    pub fn default_imap(self) -> Option<(&'static str, u16)> {
        match self {
            ProviderKind::Gmail => Some(("imap.gmail.com", 993)),
            ProviderKind::Outlook => Some(("outlook.office365.com", 993)),
            ProviderKind::Yahoo => Some(("imap.mail.yahoo.com", 993)),
            ProviderKind::Icloud => Some(("imap.mail.me.com", 993)),
            ProviderKind::Fastmail => Some(("imap.fastmail.com", 993)),
            ProviderKind::Custom => None,
        }
    }

    pub fn default_smtp(self) -> Option<(&'static str, u16, SmtpTlsMode)> {
        match self {
            ProviderKind::Gmail => Some(("smtp.gmail.com", 587, SmtpTlsMode::Starttls)),
            ProviderKind::Outlook => Some(("smtp.office365.com", 587, SmtpTlsMode::Starttls)),
            ProviderKind::Yahoo => Some(("smtp.mail.yahoo.com", 587, SmtpTlsMode::Starttls)),
            ProviderKind::Icloud => Some(("smtp.mail.me.com", 587, SmtpTlsMode::Starttls)),
            ProviderKind::Fastmail => Some(("smtp.fastmail.com", 587, SmtpTlsMode::Starttls)),
            ProviderKind::Custom => None,
        }
    }

    pub fn oauth_provider(self) -> Option<OAuthProviderKind> {
        match self {
            ProviderKind::Gmail => Some(OAuthProviderKind::GoogleMail),
            ProviderKind::Outlook => Some(OAuthProviderKind::MicrosoftMail),
            ProviderKind::Yahoo
            | ProviderKind::Icloud
            | ProviderKind::Fastmail
            | ProviderKind::Custom => None,
        }
    }
}

impl SmtpTlsMode {
    pub const ALL: [SmtpTlsMode; 3] = [
        SmtpTlsMode::Starttls,
        SmtpTlsMode::Wrapper,
        SmtpTlsMode::Plain,
    ];

    pub fn label(self) -> &'static str {
        match self {
            SmtpTlsMode::Wrapper => "wrapper-tls",
            SmtpTlsMode::Starttls => "starttls",
            SmtpTlsMode::Plain => "plain",
        }
    }
}

impl OAuthProviderKind {
    pub fn label(self) -> &'static str {
        match self {
            OAuthProviderKind::GoogleMail => "google-oauth",
            OAuthProviderKind::MicrosoftMail => "microsoft-oauth",
        }
    }
}

fn merge_imap(
    preset: &ProviderPreset,
    override_config: Option<&ImapOverride>,
) -> Result<ImapSettings> {
    match (preset.imap.host.as_str(), override_config) {
        ("", None) => bail!("custom provider requires [accounts.imap] host and port"),
        _ => {}
    }

    Ok(ImapSettings {
        host: override_config
            .and_then(|imap| imap.host.clone())
            .unwrap_or_else(|| preset.imap.host.clone()),
        port: override_config
            .and_then(|imap| imap.port)
            .unwrap_or(preset.imap.port),
    })
}

fn merge_smtp(
    preset: &ProviderPreset,
    override_config: Option<&SmtpOverride>,
) -> Result<SmtpSettings> {
    match (preset.smtp.host.as_str(), override_config) {
        ("", None) => bail!("custom provider requires [accounts.smtp] host, port, and tls_mode"),
        _ => {}
    }

    Ok(SmtpSettings {
        host: override_config
            .and_then(|smtp| smtp.host.clone())
            .unwrap_or_else(|| preset.smtp.host.clone()),
        port: override_config
            .and_then(|smtp| smtp.port)
            .unwrap_or(preset.smtp.port),
        tls_mode: override_config
            .and_then(|smtp| smtp.tls_mode)
            .unwrap_or(preset.smtp.tls_mode),
    })
}

impl ProviderPreset {
    fn for_kind(kind: ProviderKind) -> Self {
        match kind {
            ProviderKind::Gmail => Self {
                label: "Gmail",
                imap: ImapSettings {
                    host: "imap.gmail.com".to_owned(),
                    port: 993,
                },
                smtp: SmtpSettings {
                    host: "smtp.gmail.com".to_owned(),
                    port: 587,
                    tls_mode: SmtpTlsMode::Starttls,
                },
                folders: default_folders(),
            },
            ProviderKind::Outlook => Self {
                label: "Outlook",
                imap: ImapSettings {
                    host: "outlook.office365.com".to_owned(),
                    port: 993,
                },
                smtp: SmtpSettings {
                    host: "smtp.office365.com".to_owned(),
                    port: 587,
                    tls_mode: SmtpTlsMode::Starttls,
                },
                folders: default_folders(),
            },
            ProviderKind::Yahoo => Self {
                label: "Yahoo",
                imap: ImapSettings {
                    host: "imap.mail.yahoo.com".to_owned(),
                    port: 993,
                },
                smtp: SmtpSettings {
                    host: "smtp.mail.yahoo.com".to_owned(),
                    port: 587,
                    tls_mode: SmtpTlsMode::Starttls,
                },
                folders: default_folders(),
            },
            ProviderKind::Icloud => Self {
                label: "iCloud",
                imap: ImapSettings {
                    host: "imap.mail.me.com".to_owned(),
                    port: 993,
                },
                smtp: SmtpSettings {
                    host: "smtp.mail.me.com".to_owned(),
                    port: 587,
                    tls_mode: SmtpTlsMode::Starttls,
                },
                folders: default_folders(),
            },
            ProviderKind::Fastmail => Self {
                label: "Fastmail",
                imap: ImapSettings {
                    host: "imap.fastmail.com".to_owned(),
                    port: 993,
                },
                smtp: SmtpSettings {
                    host: "smtp.fastmail.com".to_owned(),
                    port: 587,
                    tls_mode: SmtpTlsMode::Starttls,
                },
                folders: default_folders(),
            },
            ProviderKind::Custom => Self {
                label: "Custom",
                imap: ImapSettings {
                    host: String::new(),
                    port: 993,
                },
                smtp: SmtpSettings {
                    host: String::new(),
                    port: 587,
                    tls_mode: SmtpTlsMode::Starttls,
                },
                folders: default_folders(),
            },
        }
    }
}

fn default_folders() -> Vec<String> {
    ["INBOX", "Sent", "Drafts", "Archive", "Trash"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn default_config_path() -> Result<PathBuf> {
    let config_root = dirs::config_dir().context("could not resolve config directory")?;
    Ok(config_root.join("email-client-tui-rs").join("config.toml"))
}

pub fn write_secure_file(path: &PathBuf, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    fs::write(path, contents).with_context(|| format!("failed to write {}", path.display()))?;
    tighten_permissions(path)?;
    Ok(())
}

pub fn write_secret_file(path: &PathBuf, secret: &str) -> Result<()> {
    write_secure_file(path, secret)
}

fn tighten_permissions(path: &PathBuf) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let permissions = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions)
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gmail_preset_fills_defaults() {
        let account = AccountConfig {
            name: "personal".into(),
            provider: ProviderKind::Gmail,
            email: "me@example.com".into(),
            login: None,
            display_name: None,
            folders: vec![],
            password_env: Some("MAIL_SECRET".into()),
            password_command: None,
            password_file: None,
            oauth: None,
            imap: None,
            smtp: None,
        };

        let resolved = account.resolve().expect("account should resolve");
        assert_eq!(resolved.imap.host, "imap.gmail.com");
        assert_eq!(resolved.smtp.host, "smtp.gmail.com");
        assert_eq!(resolved.login, "me@example.com");
        assert_eq!(resolved.folders[0], "INBOX");
        assert_eq!(resolved.provider, ProviderKind::Gmail);
    }

    #[test]
    fn custom_provider_requires_endpoints() {
        let account = AccountConfig {
            name: "custom".into(),
            provider: ProviderKind::Custom,
            email: "me@example.com".into(),
            login: None,
            display_name: None,
            folders: vec![],
            password_env: Some("MAIL_SECRET".into()),
            password_command: None,
            password_file: None,
            oauth: None,
            imap: None,
            smtp: None,
        };

        assert!(account.resolve().is_err());
    }

    #[test]
    fn gmail_oauth_resolves_without_password() {
        let account = AccountConfig {
            name: "gmail".into(),
            provider: ProviderKind::Gmail,
            email: "me@example.com".into(),
            login: None,
            display_name: None,
            folders: vec![],
            password_env: None,
            password_command: None,
            password_file: None,
            oauth: Some(OAuthConfig {
                provider: OAuthProviderKind::GoogleMail,
                data_file: "/tmp/gmail-oauth.toml".into(),
            }),
            imap: None,
            smtp: None,
        };

        let resolved = account.resolve().expect("oauth account should resolve");
        assert!(matches!(resolved.auth, AccountAuth::OAuth(_)));
    }

    #[test]
    fn mixed_password_and_oauth_is_rejected() {
        let account = AccountConfig {
            name: "mixed".into(),
            provider: ProviderKind::Outlook,
            email: "me@example.com".into(),
            login: None,
            display_name: None,
            folders: vec![],
            password_env: Some("MAIL_SECRET".into()),
            password_command: None,
            password_file: None,
            oauth: Some(OAuthConfig {
                provider: OAuthProviderKind::MicrosoftMail,
                data_file: "/tmp/outlook-oauth.toml".into(),
            }),
            imap: None,
            smtp: None,
        };

        assert!(account.resolve().is_err());
    }
}
