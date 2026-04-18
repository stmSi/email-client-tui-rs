use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use oauth2::basic::BasicClient;
use oauth2::reqwest;
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    PkceCodeChallenge, RedirectUrl, RefreshToken, Scope, StandardTokenResponse, TokenResponse,
    TokenUrl,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::config::{OAuthProviderKind, ResolvedOAuthConfig, write_secure_file};

const TOKEN_EXPIRY_SKEW_SECS: u64 = 60;
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(240);

type MailTokenResponse =
    StandardTokenResponse<EmptyExtraTokenFields, oauth2::basic::BasicTokenType>;

#[derive(Clone, Debug)]
pub struct OAuthAuthorizeRequest {
    pub provider: OAuthProviderKind,
    pub account_name: String,
    pub account_email: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub data_file: PathBuf,
}

#[derive(Clone, Debug)]
pub struct AuthorizedAccount {
    pub account_name: String,
    pub provider: OAuthProviderKind,
    pub data_file: PathBuf,
}

#[derive(Clone, Debug)]
pub enum OAuthAuthorizeUpdate {
    Progress { message: String, auth_url: String },
    Complete(Result<AuthorizedAccount, String>),
}

#[derive(Clone, Debug)]
pub struct StoredOAuthClient {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredProviderClient {
    client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredOAuthSession {
    provider: OAuthProviderKind,
    account_email: String,
    client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
    access_token: String,
    refresh_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at_unix: Option<u64>,
}

#[derive(Clone, Debug)]
struct ProviderSpec {
    auth_url: &'static str,
    token_url: &'static str,
    redirect_path: &'static str,
    auth_type: Option<AuthType>,
    scopes: &'static [&'static str],
}

pub fn start_authorize_worker(
    request: OAuthAuthorizeRequest,
    sender: Sender<OAuthAuthorizeUpdate>,
) {
    thread::spawn(move || {
        let result = authorize_account(&request, &sender).map_err(|error| format!("{error:#}"));
        let _ = sender.send(OAuthAuthorizeUpdate::Complete(result));
    });
}

pub fn load_saved_oauth_client(path: &Path) -> Result<StoredOAuthClient> {
    let session = load_session(path)?;
    Ok(StoredOAuthClient {
        client_id: session.client_id,
        client_secret: session.client_secret.unwrap_or_default(),
    })
}

pub fn load_provider_oauth_client(path: &Path) -> Result<StoredOAuthClient> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read provider OAuth file {}", path.display()))?;
    let stored = toml::from_str::<StoredProviderClient>(&raw)
        .with_context(|| format!("failed to parse provider OAuth file {}", path.display()))?;
    Ok(StoredOAuthClient {
        client_id: stored.client_id,
        client_secret: stored.client_secret.unwrap_or_default(),
    })
}

pub fn save_provider_oauth_client(path: &Path, client: &StoredOAuthClient) -> Result<()> {
    let stored = StoredProviderClient {
        client_id: client.client_id.trim().to_owned(),
        client_secret: (!client.client_secret.trim().is_empty())
            .then(|| client.client_secret.trim().to_owned()),
    };
    let raw =
        toml::to_string_pretty(&stored).context("failed to serialize provider OAuth client")?;
    write_secure_file(&path.to_path_buf(), &raw)
}

pub fn find_google_desktop_oauth_client(dir: &Path) -> Result<Option<StoredOAuthClient>> {
    let mut entries = fs::read_dir(dir)
        .with_context(|| format!("failed to read directory {}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to enumerate directory {}", dir.display()))?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !(file_name.starts_with("client_secret_") && file_name.ends_with(".json")
            || file_name == "credentials.json")
        {
            continue;
        }

        if let Ok(client) = load_google_desktop_oauth_client_file(&path) {
            return Ok(Some(client));
        }
    }

    Ok(None)
}

fn load_google_desktop_oauth_client_file(path: &Path) -> Result<StoredOAuthClient> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read Google OAuth client file {}", path.display()))?;
    let value = serde_json::from_str::<Value>(&raw)
        .with_context(|| format!("failed to parse Google OAuth client file {}", path.display()))?;
    let installed = value
        .get("installed")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("Google OAuth client file {} is missing 'installed'", path.display()))?;
    let client_id = installed
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Google OAuth client file {} is missing client_id", path.display()))?;
    let client_secret = installed
        .get("client_secret")
        .and_then(Value::as_str)
        .unwrap_or_default();

    Ok(StoredOAuthClient {
        client_id: client_id.to_owned(),
        client_secret: client_secret.to_owned(),
    })
}

pub fn load_access_token(oauth: &ResolvedOAuthConfig) -> Result<String> {
    let mut session = load_session(&oauth.data_file)?;
    if session.provider != oauth.provider {
        bail!(
            "OAuth data file {} is configured for '{}' but account expects '{}'",
            oauth.data_file.display(),
            session.provider.label(),
            oauth.provider.label()
        );
    }

    if session.has_fresh_access_token() {
        return Ok(session.access_token.clone());
    }

    let token = refresh_access_token(&session)?;
    session.apply_token_response(&token)?;
    save_session(&oauth.data_file, &session)?;
    Ok(session.access_token.clone())
}

fn authorize_account(
    request: &OAuthAuthorizeRequest,
    sender: &Sender<OAuthAuthorizeUpdate>,
) -> Result<AuthorizedAccount> {
    let spec = provider_spec(request.provider);
    let listener =
        TcpListener::bind("127.0.0.1:0").context("failed to bind local OAuth callback listener")?;
    listener
        .set_nonblocking(true)
        .context("failed to set callback listener to non-blocking mode")?;
    let port = listener
        .local_addr()
        .context("failed to read callback listener address")?
        .port();
    let redirect_uri = match request.provider {
        OAuthProviderKind::GoogleMail => format!("http://127.0.0.1:{port}"),
        OAuthProviderKind::MicrosoftMail => format!("http://localhost:{port}{}", spec.redirect_path),
    };
    let expected_path = match request.provider {
        OAuthProviderKind::GoogleMail => "/",
        OAuthProviderKind::MicrosoftMail => spec.redirect_path,
    };

    let client = build_client(
        request.provider,
        request.client_id.clone(),
        request.client_secret.clone(),
        Some(redirect_uri.clone()),
    )?;
    let http_client = oauth_http_client()?;
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let mut auth_request = client.authorize_url(CsrfToken::new_random);
    for scope in spec.scopes {
        auth_request = auth_request.add_scope(Scope::new((*scope).to_owned()));
    }
    if !request.account_email.trim().is_empty() {
        auth_request = auth_request.add_extra_param("login_hint", request.account_email.clone());
    }
    if request.provider == OAuthProviderKind::GoogleMail {
        auth_request = auth_request
            .add_extra_param("access_type", "offline")
            .add_extra_param("prompt", "consent");
    }
    let (authorize_url, csrf_state) = auth_request.set_pkce_challenge(pkce_challenge).url();

    let browser_opened = open_browser(authorize_url.as_str()).is_ok();
    let message = if browser_opened {
        format!(
            "Browser opened for {}. Complete sign-in and consent, then return here.",
            request.provider.label()
        )
    } else {
        format!(
            "Browser open failed. Open this URL manually to continue {} OAuth.",
            request.provider.label()
        )
    };
    let _ = sender.send(OAuthAuthorizeUpdate::Progress {
        message,
        auth_url: authorize_url.to_string(),
    });

    let code = wait_for_callback(&listener, csrf_state.secret(), expected_path)?;
    let token = client
        .exchange_code(code)
        .set_pkce_verifier(pkce_verifier)
        .request(&http_client)
        .context("failed to exchange OAuth authorization code for tokens")?;

    let refresh_token = token
        .refresh_token()
        .map(|value| value.secret().to_owned())
        .ok_or_else(|| anyhow!("provider did not return a refresh token"))?;

    let mut session = StoredOAuthSession {
        provider: request.provider,
        account_email: request.account_email.clone(),
        client_id: request.client_id.clone(),
        client_secret: request
            .client_secret
            .clone()
            .filter(|value| !value.trim().is_empty()),
        access_token: token.access_token().secret().to_owned(),
        refresh_token,
        expires_at_unix: None,
    };
    session.apply_token_response(&token)?;
    save_session(&request.data_file, &session)?;

    Ok(AuthorizedAccount {
        account_name: request.account_name.clone(),
        provider: request.provider,
        data_file: request.data_file.clone(),
    })
}

fn refresh_access_token(session: &StoredOAuthSession) -> Result<MailTokenResponse> {
    let client = build_client(
        session.provider,
        session.client_id.clone(),
        session.client_secret.clone(),
        None,
    )?;
    let http_client = oauth_http_client()?;

    client
        .exchange_refresh_token(&RefreshToken::new(session.refresh_token.clone()))
        .request(&http_client)
        .context("failed to refresh OAuth access token")
}

fn build_client(
    provider: OAuthProviderKind,
    client_id: String,
    client_secret: Option<String>,
    redirect_uri: Option<String>,
) -> Result<
    BasicClient<
        oauth2::EndpointSet,
        oauth2::EndpointNotSet,
        oauth2::EndpointNotSet,
        oauth2::EndpointNotSet,
        oauth2::EndpointSet,
    >,
> {
    let spec = provider_spec(provider);
    let mut client = BasicClient::new(ClientId::new(client_id))
        .set_auth_uri(
            AuthUrl::new(spec.auth_url.to_owned()).context("invalid OAuth authorization URL")?,
        )
        .set_token_uri(
            TokenUrl::new(spec.token_url.to_owned()).context("invalid OAuth token URL")?,
        );

    if let Some(secret) = client_secret.filter(|value| !value.trim().is_empty()) {
        client = client.set_client_secret(ClientSecret::new(secret));
    }
    if let Some(auth_type) = spec.auth_type {
        client = client.set_auth_type(auth_type);
    }
    if let Some(redirect_uri) = redirect_uri {
        client = client.set_redirect_uri(
            RedirectUrl::new(redirect_uri).context("invalid OAuth redirect URL")?,
        );
    }

    Ok(client)
}

fn oauth_http_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build OAuth HTTP client")
}

fn wait_for_callback(
    listener: &TcpListener,
    expected_state: &str,
    expected_path: &str,
) -> Result<AuthorizationCode> {
    let deadline = Instant::now() + CALLBACK_TIMEOUT;

    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut reader = BufReader::new(&stream);
                let mut request_line = String::new();
                reader
                    .read_line(&mut request_line)
                    .context("failed to read OAuth callback request")?;
                let redirect_target = request_line.split_whitespace().nth(1).ok_or_else(|| {
                    anyhow!("OAuth callback request was missing the redirect target")
                })?;
                let url = Url::parse(&format!("http://localhost{redirect_target}"))
                    .context("failed to parse OAuth callback URL")?;
                if url.path() != expected_path {
                    write_callback_response(
                        &mut stream,
                        "Wrong callback",
                        "This callback path does not belong to the mail client.",
                    )?;
                    continue;
                }

                if let Some((_, error)) = url.query_pairs().find(|(key, _)| key == "error") {
                    let description = url
                        .query_pairs()
                        .find(|(key, _)| key == "error_description")
                        .map(|(_, value)| value.into_owned())
                        .unwrap_or_else(|| "OAuth provider returned an error".to_owned());
                    write_callback_response(
                        &mut stream,
                        "Authorization failed",
                        "The provider rejected the authorization request. You can close this tab.",
                    )?;
                    bail!("{error}: {description}");
                }

                let code = url
                    .query_pairs()
                    .find(|(key, _)| key == "code")
                    .map(|(_, value)| AuthorizationCode::new(value.into_owned()))
                    .ok_or_else(|| {
                        anyhow!("OAuth callback did not include an authorization code")
                    })?;
                let state = url
                    .query_pairs()
                    .find(|(key, _)| key == "state")
                    .map(|(_, value)| value.into_owned())
                    .ok_or_else(|| anyhow!("OAuth callback did not include a state token"))?;

                if state != expected_state {
                    write_callback_response(
                        &mut stream,
                        "State mismatch",
                        "The authorization response failed a CSRF check. You can close this tab.",
                    )?;
                    bail!("OAuth state mismatch");
                }

                write_callback_response(
                    &mut stream,
                    "Mail access approved",
                    "Authorization completed. You can close this browser tab and return to the terminal.",
                )?;
                return Ok(code);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    bail!("timed out waiting for the OAuth browser callback");
                }
                thread::sleep(Duration::from_millis(150));
            }
            Err(error) => return Err(error).context("failed to accept OAuth callback connection"),
        }
    }
}

fn write_callback_response(
    stream: &mut std::net::TcpStream,
    title: &str,
    message: &str,
) -> Result<()> {
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title></head><body><h1>{title}</h1><p>{message}</p></body></html>"
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(response.as_bytes())
        .context("failed to write OAuth callback response")?;
    stream.flush().ok();
    Ok(())
}

fn save_session(path: &Path, session: &StoredOAuthSession) -> Result<()> {
    let raw = toml::to_string_pretty(session).context("failed to serialize OAuth session")?;
    write_secure_file(&path.to_path_buf(), &raw)
}

fn load_session(path: &Path) -> Result<StoredOAuthSession> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read OAuth data file {}", path.display()))?;
    toml::from_str(&raw)
        .with_context(|| format!("failed to parse OAuth data file {}", path.display()))
}

fn provider_spec(provider: OAuthProviderKind) -> ProviderSpec {
    match provider {
        OAuthProviderKind::GoogleMail => ProviderSpec {
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth",
            token_url: "https://oauth2.googleapis.com/token",
            redirect_path: "/oauth/google/callback",
            auth_type: None,
            scopes: &["https://mail.google.com/"],
        },
        OAuthProviderKind::MicrosoftMail => ProviderSpec {
            auth_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            redirect_path: "/oauth/microsoft/callback",
            auth_type: Some(AuthType::RequestBody),
            scopes: &[
                "https://outlook.office.com/IMAP.AccessAsUser.All",
                "https://outlook.office.com/SMTP.Send",
                "offline_access",
            ],
        },
    }
}

fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = Command::new("open");
        command.arg(url);
        command
    };

    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = Command::new("cmd");
        command.args(["/C", "start", "", url]);
        command
    };

    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = {
        let mut command = Command::new("xdg-open");
        command.arg(url);
        command
    };

    command
        .spawn()
        .context("failed to launch the system browser")?;
    Ok(())
}

impl StoredOAuthSession {
    fn has_fresh_access_token(&self) -> bool {
        match self.expires_at_unix {
            Some(expires_at) => {
                current_unix_timestamp().saturating_add(TOKEN_EXPIRY_SKEW_SECS) < expires_at
            }
            None => false,
        }
    }

    fn apply_token_response(&mut self, token: &MailTokenResponse) -> Result<()> {
        self.access_token = token.access_token().secret().to_owned();
        if let Some(refresh_token) = token.refresh_token() {
            self.refresh_token = refresh_token.secret().to_owned();
        }
        self.expires_at_unix = token
            .expires_in()
            .map(|duration| current_unix_timestamp().saturating_add(duration.as_secs()));

        if self.access_token.trim().is_empty() {
            bail!("OAuth provider returned an empty access token");
        }

        Ok(())
    }
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}
