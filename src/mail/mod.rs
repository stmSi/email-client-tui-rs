mod client;
mod oauth;

pub use client::{
    EmailDraft, EmailMessage, MailClient, SyncBatch, merge_messages_newest_first, oldest_loaded_uid,
};
pub use oauth::{
    AuthorizedAccount, OAuthAuthorizeRequest, OAuthAuthorizeUpdate, StoredOAuthClient,
    find_google_desktop_oauth_client, load_provider_oauth_client, load_saved_oauth_client,
    save_provider_oauth_client, start_authorize_worker,
};
