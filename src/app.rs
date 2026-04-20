use std::cmp;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver},
};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::Local;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use fuzzy_matcher::FuzzyMatcher;
use fuzzy_matcher::skim::SkimMatcherV2;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};

use crate::cache;
use crate::command::{AppCommand, CommandMatch, search_commands};
use crate::config::{
    AccountConfig, AppConfig, ImapOverride, LoadedConfig, OAuthConfig, OAuthProviderKind,
    ProviderKind, ResolvedAccountConfig, SmtpOverride, SmtpTlsMode, write_secret_file,
};
use crate::mail::{
    AuthorizedAccount, EmailDraft, EmailMessage, MailClient, OAuthAuthorizeRequest,
    OAuthAuthorizeUpdate, StoredOAuthClient, SyncBatch, find_google_desktop_oauth_client,
    load_provider_oauth_client, load_saved_oauth_client, merge_messages_newest_first,
    oldest_loaded_uid, save_provider_oauth_client, start_authorize_worker,
};

const AUTO_SYNC_INTERVAL: Duration = Duration::from_secs(300);
const LONG_TOKEN_BREAK_CHARS: usize = 32;
const MESSAGE_ROW_HEIGHT: u16 = 3;
const SPINNER_FRAMES: [&str; 4] = ["|", "/", "-", "\\"];

pub struct App {
    config: AppConfig,
    config_path: PathBuf,
    cache_root: PathBuf,
    accounts: Vec<AccountState>,
    selected_account: usize,
    next_auto_account: usize,
    focus: Pane,
    mode: Mode,
    command_input: String,
    command_matches: Vec<CommandMatch>,
    command_index: usize,
    reader_scroll: u16,
    compose: ComposeState,
    account_setup: AccountSetupState,
    oauth_setup: OAuthSetupState,
    confirm_delete: ConfirmDeleteState,
    sync_receiver: Option<Receiver<SyncWorkerResult>>,
    sync_job: Option<SyncJob>,
    last_auto_sync: Instant,
    animation_frame: usize,
    hitboxes: UiHitboxes,
    pending_g: bool,
    status: String,
    should_quit: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Normal,
    Command,
    Compose,
    Reader,
    Search,
    AccountSetup,
    AccountOAuth,
    ConfirmDeleteAccount,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pane {
    Accounts,
    Folders,
    Messages,
    Preview,
}

struct AccountState {
    config: ResolvedAccountConfig,
    selected_folder: usize,
    selected_message: usize,
    message_scroll: usize,
    synced_folder: Option<String>,
    messages: Vec<EmailMessage>,
    message_query: String,
    last_sync: Option<String>,
}

struct SyncJob {
    account_name: String,
    requested_folder: String,
    reason: SyncReason,
}

struct SyncWorkerResult {
    account_index: usize,
    account_name: String,
    requested_folder: String,
    reason: SyncReason,
    result: std::result::Result<SyncBatch, String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SyncReason {
    Manual,
    Auto,
    SentCopy,
    LoadOlder,
}

#[derive(Default)]
struct ComposeState {
    to: String,
    cc: String,
    bcc: String,
    subject: String,
    body: String,
    field: ComposeField,
    suggestions: Vec<String>,
    suggestion_index: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ComposeField {
    #[default]
    To,
    Cc,
    Bcc,
    Subject,
    Body,
}

struct AccountSetupState {
    provider_index: usize,
    provider_dropdown_open: bool,
    provider_dropdown_index: usize,
    name: String,
    email: String,
    login: String,
    display_name: String,
    password: String,
    show_password: bool,
    imap_host: String,
    imap_port: String,
    smtp_host: String,
    smtp_port: String,
    tls_mode: SmtpTlsMode,
    field: SetupField,
}

struct OAuthSetupState {
    account_name: String,
    account_email: String,
    provider: Option<OAuthProviderKind>,
    client_id: String,
    client_secret: String,
    show_client_secret: bool,
    field: OAuthField,
    running: bool,
    progress_message: String,
    auth_url: String,
    receiver: Option<Receiver<OAuthAuthorizeUpdate>>,
    cancellation: Option<Arc<AtomicBool>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SetupField {
    Provider,
    Name,
    Email,
    Login,
    DisplayName,
    Password,
    ImapHost,
    ImapPort,
    SmtpHost,
    SmtpPort,
    TlsMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OAuthField {
    ClientId,
    ClientSecret,
    Start,
    Cancel,
}

#[derive(Clone, Debug, Default)]
struct UiHitboxes {
    accounts: Rect,
    folders: Rect,
    messages: Rect,
    preview: Rect,
    command: Option<CommandHitboxes>,
    compose: Option<ComposeHitboxes>,
    search: Option<SearchHitboxes>,
    account_setup: Option<AccountSetupHitboxes>,
    oauth_setup: Option<OAuthSetupHitboxes>,
    confirm_delete: Option<ConfirmDeleteHitboxes>,
}

#[derive(Clone, Debug)]
struct CommandHitboxes {
    input: Rect,
    list: Rect,
}

#[derive(Clone, Debug)]
struct ComposeHitboxes {
    to: Rect,
    cc: Rect,
    bcc: Rect,
    subject: Rect,
    suggestions: Rect,
    body: Rect,
}

#[derive(Clone, Debug)]
struct SearchHitboxes {
    input: Rect,
}

#[derive(Clone, Debug)]
struct AccountSetupHitboxes {
    provider: Rect,
    provider_dropdown: Option<Rect>,
    name: Rect,
    email: Rect,
    login: Rect,
    display_name: Rect,
    password: Rect,
    imap_host: Rect,
    imap_port: Rect,
    smtp_host: Rect,
    smtp_port: Rect,
    tls_mode: Rect,
}

#[derive(Clone, Debug)]
struct OAuthSetupHitboxes {
    dialog: Rect,
    client_id: Rect,
    client_secret: Rect,
    start: Rect,
    cancel: Rect,
}

#[derive(Clone, Debug)]
struct ConfirmDeleteHitboxes {
    dialog: Rect,
    confirm: Rect,
    cancel: Rect,
}

#[derive(Clone, Debug, Default)]
struct ConfirmDeleteState {
    account_name: String,
    confirm_selected: bool,
}

impl App {
    pub fn new(loaded: LoadedConfig) -> Result<Self> {
        let config = loaded.config;
        let cache_root = cache::cache_root(&loaded.path);
        let (mut accounts, selected_account) = resolve_accounts(&config)?;
        for account in &mut accounts {
            load_cached_folder_into_state(&cache_root, account);
        }
        let command_matches = search_commands("");
        let status = if accounts.is_empty() {
            format!(
                "No accounts configured. Press a to add one in-app or edit {}.",
                loaded.path.display()
            )
        } else {
            format!(
                "Loaded {} account(s). Use h/l or Tab/Shift-Tab to change pane, j/k to move, a to add account, o to authorize, s to sync.",
                accounts.len()
            )
        };

        Ok(Self {
            config,
            config_path: loaded.path,
            cache_root,
            accounts,
            selected_account,
            next_auto_account: 0,
            focus: Pane::Accounts,
            mode: Mode::Normal,
            command_input: String::new(),
            command_matches,
            command_index: 0,
            reader_scroll: 0,
            compose: ComposeState::default(),
            account_setup: AccountSetupState::default(),
            oauth_setup: OAuthSetupState::default(),
            confirm_delete: ConfirmDeleteState::default(),
            sync_receiver: None,
            sync_job: None,
            last_auto_sync: Instant::now(),
            animation_frame: 0,
            hitboxes: UiHitboxes::default(),
            pending_g: false,
            status,
            should_quit: false,
        })
    }

    pub fn draw(&mut self, frame: &mut Frame) {
        self.poll_oauth_updates();
        self.hitboxes = UiHitboxes::default();
        let [title_area, body_area, status_area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .areas(frame.area());

        frame.render_widget(self.title_bar(), title_area);
        self.draw_main(frame, body_area);
        frame.render_widget(self.status_bar(), status_area);

        if self.mode == Mode::Command {
            self.draw_command_palette(frame);
        }

        if self.mode == Mode::Compose {
            self.draw_compose(frame);
        }

        if self.mode == Mode::Reader {
            self.draw_message_reader(frame);
        }

        if self.mode == Mode::Search {
            self.draw_search_popup(frame);
        }

        if self.mode == Mode::AccountSetup {
            self.draw_account_setup(frame);
        }

        if self.mode == Mode::AccountOAuth {
            self.draw_account_oauth(frame);
        }

        if self.mode == Mode::ConfirmDeleteAccount {
            self.draw_confirm_delete(frame);
        }
    }

    pub fn tick(&mut self) {
        self.poll_sync_updates();
        self.maybe_start_auto_sync();
        if self.is_busy() {
            self.animation_frame = self.animation_frame.wrapping_add(1);
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Result<()> {
        match self.mode {
            Mode::Normal => self.handle_normal_mode(key),
            Mode::Command => self.handle_command_mode(key),
            Mode::Compose => self.handle_compose_mode(key),
            Mode::Reader => self.handle_reader_mode(key),
            Mode::Search => self.handle_search_mode(key),
            Mode::AccountSetup => self.handle_account_setup_mode(key),
            Mode::AccountOAuth => self.handle_account_oauth_mode(key),
            Mode::ConfirmDeleteAccount => self.handle_confirm_delete_mode(key),
        }
    }

    pub fn handle_mouse(&mut self, mouse: MouseEvent) -> Result<()> {
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) | MouseEventKind::Down(MouseButton::Middle) => {
                self.handle_mouse_click(mouse)
            }
            MouseEventKind::ScrollDown => self.handle_mouse_scroll(mouse, 1),
            MouseEventKind::ScrollUp => self.handle_mouse_scroll(mouse, -1),
            _ => Ok(()),
        }
    }

    fn handle_mouse_click(&mut self, mouse: MouseEvent) -> Result<()> {
        match self.mode {
            Mode::AccountSetup => self.handle_account_setup_click(mouse),
            Mode::AccountOAuth => self.handle_account_oauth_click(mouse),
            Mode::Compose => self.handle_compose_click(mouse),
            Mode::Reader => Ok(()),
            Mode::Command => self.handle_command_click(mouse),
            Mode::Search => self.handle_search_click(mouse),
            Mode::ConfirmDeleteAccount => self.handle_confirm_delete_click(mouse),
            Mode::Normal => self.handle_normal_click(mouse),
        }
    }

    fn handle_mouse_scroll(&mut self, mouse: MouseEvent, delta: isize) -> Result<()> {
        match self.mode {
            Mode::Normal => self.handle_normal_scroll(mouse, delta),
            Mode::Command => self.handle_command_scroll(mouse, delta),
            Mode::Compose => {
                self.handle_compose_scroll(mouse, delta);
                Ok(())
            }
            Mode::Reader => {
                self.scroll_reader(delta, 3);
                Ok(())
            }
            Mode::Search => {
                self.handle_search_scroll(mouse, delta);
                Ok(())
            }
            Mode::AccountSetup => {
                self.handle_account_setup_scroll(mouse, delta);
                Ok(())
            }
            Mode::AccountOAuth => Ok(()),
            Mode::ConfirmDeleteAccount => Ok(()),
        }
    }

    pub fn should_quit(&self) -> bool {
        self.should_quit
    }

    pub fn set_status(&mut self, status: String) {
        self.status = status;
    }

    fn is_busy(&self) -> bool {
        self.sync_job.is_some() || self.oauth_setup.running
    }

    fn spinner(&self) -> &'static str {
        SPINNER_FRAMES[self.animation_frame % SPINNER_FRAMES.len()]
    }

    fn draw_main(&mut self, frame: &mut Frame, area: Rect) {
        frame.render_widget(Block::default().style(app_background_style()), area);
        let [accounts_area, folders_area, messages_area, preview_area] = Layout::horizontal([
            Constraint::Length(24),
            Constraint::Length(20),
            Constraint::Length(42),
            Constraint::Min(36),
        ])
        .areas(area);

        self.hitboxes.accounts = accounts_area;
        self.hitboxes.folders = folders_area;
        self.hitboxes.messages = messages_area;
        self.hitboxes.preview = preview_area;

        self.draw_accounts(frame, accounts_area);
        self.draw_folders(frame, folders_area);
        self.draw_messages(frame, messages_area);
        self.draw_preview(frame, preview_area);
    }

    fn title_bar(&self) -> Line<'static> {
        let account_label = self
            .current_account()
            .map(|account| {
                format!(
                    "{} ({})",
                    account.config.name, account.config.provider_label
                )
            })
            .unwrap_or_else(|| "no account".to_owned());

        let mut spans = vec![
            Span::styled(
                " mail-tui ",
                Style::new()
                    .fg(Color::Rgb(15, 23, 42))
                    .bg(Color::Rgb(42, 157, 143))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" mode:{} ", self.mode_label()),
                Style::new()
                    .fg(Color::Rgb(15, 23, 42))
                    .bg(Color::Rgb(233, 196, 106))
                    .add_modifier(Modifier::BOLD),
            ),
        ];

        if let Some(job) = &self.sync_job {
            spans.push(Span::styled(
                format!(
                    " {}:{} {}:{} ",
                    sync_reason_label(job.reason),
                    self.spinner(),
                    job.account_name,
                    job.requested_folder
                ),
                Style::new()
                    .fg(Color::Rgb(15, 23, 42))
                    .bg(Color::Rgb(163, 230, 53))
                    .add_modifier(Modifier::BOLD),
            ));
        } else if self.oauth_setup.running {
            spans.push(Span::styled(
                format!(" oauth:{} ", self.spinner()),
                Style::new()
                    .fg(Color::Rgb(15, 23, 42))
                    .bg(Color::Rgb(163, 230, 53))
                    .add_modifier(Modifier::BOLD),
            ));
        }

        spans.extend([
            Span::styled(
                format!(" account:{account_label} "),
                Style::new()
                    .fg(Color::Rgb(241, 245, 249))
                    .bg(Color::Rgb(45, 55, 72)),
            ),
            Span::styled(
                " vim: h/l or Tab focus, j/k move, s sync, m older, a account, o auth, : palette, c compose ",
                Style::new().fg(Color::Rgb(148, 163, 184)),
            ),
        ]);

        Line::from(spans)
    }

    fn status_bar(&self) -> Line<'_> {
        let style = if self.status.starts_with("Error:") {
            Style::new()
                .fg(Color::Rgb(255, 245, 245))
                .bg(Color::Rgb(153, 27, 27))
        } else {
            Style::new()
                .fg(Color::Rgb(226, 232, 240))
                .bg(Color::Rgb(30, 41, 59))
        };

        let text = if self.is_busy() && !self.status.starts_with("Error:") {
            format!("{} {}", self.spinner(), self.status)
        } else {
            self.status.clone()
        };

        Line::from(text).style(style)
    }

    fn draw_accounts(&self, frame: &mut Frame, area: Rect) {
        let items = if self.accounts.is_empty() {
            vec![ListItem::new("No accounts configured")]
        } else {
            self.accounts
                .iter()
                .map(|account| {
                    let mut lines = vec![Line::from(account.config.name.clone().bold())];
                    lines.push(
                        Line::from(account.config.email.clone())
                            .style(Style::new().fg(Color::Rgb(203, 213, 225))),
                    );
                    lines.push(
                        Line::from(format!(
                            "{}  {}",
                            account.config.provider_label,
                            account.config.auth_label()
                        ))
                        .style(Style::new().fg(Color::Rgb(94, 234, 212))),
                    );
                    if let Some(last_sync) = &account.last_sync {
                        lines.push(
                            Line::from(format!("synced {last_sync}"))
                                .style(Style::new().fg(Color::Rgb(163, 230, 53))),
                        );
                    }
                    if let Some(job) = &self.sync_job
                        && job.account_name == account.config.name
                    {
                        lines.push(
                            Line::from(format!(
                                "{} syncing {}",
                                self.spinner(),
                                job.requested_folder
                            ))
                            .style(Style::new().fg(Color::Rgb(250, 204, 21))),
                        );
                    }
                    ListItem::new(lines)
                })
                .collect()
        };

        let list = List::new(items)
            .block(self.pane_block("Accounts", Pane::Accounts))
            .highlight_style(selected_style())
            .highlight_symbol("▸ ");
        let mut state = ListState::default();
        if !self.accounts.is_empty() {
            state.select(Some(self.selected_account));
        }
        frame.render_stateful_widget(list, area, &mut state);
    }

    fn draw_folders(&self, frame: &mut Frame, area: Rect) {
        let items = self
            .current_account()
            .map(|account| {
                account
                    .config
                    .folders
                    .iter()
                    .map(|folder| {
                        let label = if self.sync_job.as_ref().is_some_and(|job| {
                            job.account_name == account.config.name
                                && folder.eq_ignore_ascii_case(&job.requested_folder)
                        }) {
                            format!("{} {}", self.spinner(), folder)
                        } else {
                            folder.clone()
                        };
                        ListItem::new(label)
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec![ListItem::new("No folders")]);

        let list = List::new(items)
            .block(self.pane_block("Folders", Pane::Folders))
            .highlight_style(selected_style())
            .highlight_symbol("▸ ");
        let mut state = ListState::default();
        if let Some(account) = self.current_account() {
            state.select(Some(account.selected_folder));
        }
        frame.render_stateful_widget(list, area, &mut state);
    }

    fn draw_messages(&self, frame: &mut Frame, area: Rect) {
        let items = self
            .current_account()
            .map(|account| {
                let filtered = account.filtered_message_indices();
                if account.messages.is_empty() {
                    vec![ListItem::new("No messages synced yet")]
                } else if filtered.is_empty() {
                    vec![ListItem::new(format!(
                        "No matches for /{} in this folder",
                        account.message_query
                    ))]
                } else {
                    filtered
                        .into_iter()
                        .filter_map(|index| account.messages.get(index))
                        .map(|message| {
                            let subject_style = if message.seen {
                                Style::new().fg(Color::Rgb(241, 245, 249))
                            } else {
                                Style::new()
                                    .fg(Color::Rgb(250, 204, 21))
                                    .add_modifier(Modifier::BOLD)
                            };
                            let marker = if message.seen { "read" } else { "new " };

                            let lines = vec![
                                Line::from(message.subject.clone()).style(subject_style),
                                Line::from(format!(
                                    "[{marker}] {}  {}",
                                    message.from, message.date
                                ))
                                .style(Style::new().fg(Color::Rgb(125, 211, 252))),
                                Line::from(message.preview.clone())
                                    .style(Style::new().fg(Color::Rgb(148, 163, 184))),
                            ];
                            ListItem::new(lines)
                        })
                        .collect()
                }
            })
            .unwrap_or_else(|| vec![ListItem::new("No account selected")]);

        let title = self.message_title();
        let list = List::new(items)
            .block(self.pane_block(&title, Pane::Messages))
            .highlight_style(selected_style())
            .highlight_symbol("▸ ");
        let mut state = ListState::default();
        if let Some(account) = self.current_account() {
            if account.filtered_message_count() > 0 {
                let offset = message_scroll_for_selection(
                    account.message_scroll,
                    account.selected_message,
                    account.filtered_message_count(),
                    self.message_visible_count(),
                );
                *state.offset_mut() = offset;
                state.select(Some(account.selected_message));
            }
        }
        frame.render_stateful_widget(list, area, &mut state);
    }

    fn draw_preview(&self, frame: &mut Frame, area: Rect) {
        let text = if let Some(message) = self.selected_message() {
            message_text(message, false)
        } else if self.accounts.is_empty() {
            Text::from(vec![
                Line::from("Add an account in-app with `a` or edit:"),
                Line::from(self.config_path.display().to_string()).bold(),
                Line::from(""),
                Line::from("Then restart and press `s` or `:sync`."),
            ])
        } else {
            Text::from(vec![
                Line::from("No message selected."),
                Line::from(if self.current_message_query().is_empty() {
                    "Focus folders or messages, then sync the active folder."
                } else {
                    "Search is active. Edit it with `/` or clear the query."
                }),
            ])
        };

        let paragraph = Paragraph::new(text)
            .block(self.pane_block("Preview", Pane::Preview))
            .wrap(Wrap { trim: false });
        frame.render_widget(paragraph, area);
    }

    fn draw_message_reader(&self, frame: &mut Frame) {
        let area = frame.area();
        frame.render_widget(Clear, area);

        let Some(message) = self.selected_message() else {
            frame.render_widget(
                Paragraph::new("No message selected.")
                    .block(reader_block("Reader"))
                    .wrap(Wrap { trim: false }),
                area,
            );
            return;
        };

        let title = format!(
            "Reader: {}   Esc/q close   j/k/wheel scroll   PgUp/PgDn page",
            truncate_title(&message.subject, 72)
        );
        let paragraph = Paragraph::new(message_text(message, true))
            .block(reader_block(&title))
            .scroll((self.reader_scroll, 0))
            .wrap(Wrap { trim: false });
        frame.render_widget(paragraph, area);
    }

    fn draw_command_palette(&mut self, frame: &mut Frame) {
        let area = centered_rect(72, 45, frame.area());
        frame.render_widget(Clear, area);

        let [input_area, list_area] =
            Layout::vertical([Constraint::Length(3), Constraint::Min(3)]).areas(area);

        self.hitboxes.command = Some(CommandHitboxes {
            input: input_area,
            list: list_area,
        });

        let input = Paragraph::new(format!(":{}", self.command_input)).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Command")
                .border_style(
                    Style::new()
                        .fg(Color::Rgb(42, 157, 143))
                        .add_modifier(Modifier::BOLD),
                )
                .style(popup_style()),
        );
        frame.render_widget(input, input_area);

        let items = if self.command_matches.is_empty() {
            vec![ListItem::new("No matches")]
        } else {
            self.command_matches
                .iter()
                .map(|item| {
                    ListItem::new(vec![
                        Line::from(item.name.bold()),
                        Line::from(item.description)
                            .style(Style::new().fg(Color::Rgb(148, 163, 184))),
                    ])
                })
                .collect()
        };

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("fzf-ish palette")
                    .border_style(
                        Style::new()
                            .fg(Color::Rgb(233, 196, 106))
                            .add_modifier(Modifier::BOLD),
                    )
                    .style(popup_style()),
            )
            .highlight_style(selected_style())
            .highlight_symbol("▸ ");
        let mut state = ListState::default();
        if !self.command_matches.is_empty() {
            state.select(Some(self.command_index));
        }
        frame.render_stateful_widget(list, list_area, &mut state);
    }

    fn draw_compose(&mut self, frame: &mut Frame) {
        let area = centered_rect(82, 72, frame.area());
        frame.render_widget(Clear, area);

        let [
            header_area,
            to_area,
            cc_area,
            bcc_area,
            subject_area,
            suggestions_area,
            body_area,
            footer_area,
        ] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(7),
            Constraint::Min(8),
            Constraint::Length(1),
        ])
        .areas(area);

        self.hitboxes.compose = Some(ComposeHitboxes {
            to: to_area,
            cc: cc_area,
            bcc: bcc_area,
            subject: subject_area,
            suggestions: suggestions_area,
            body: body_area,
        });

        frame.render_widget(
            Line::from(" Compose   Tab cycle fields   Ctrl-S send   Esc discard ").style(
                Style::new()
                    .fg(Color::Rgb(15, 23, 42))
                    .bg(Color::Rgb(163, 230, 53))
                    .add_modifier(Modifier::BOLD),
            ),
            header_area,
        );

        frame.render_widget(
            Paragraph::new(self.compose.to.as_str())
                .block(field_block("To", self.compose.field == ComposeField::To)),
            to_area,
        );
        frame.render_widget(
            Paragraph::new(self.compose.cc.as_str())
                .block(field_block("Cc", self.compose.field == ComposeField::Cc)),
            cc_area,
        );
        frame.render_widget(
            Paragraph::new(self.compose.bcc.as_str())
                .block(field_block("Bcc", self.compose.field == ComposeField::Bcc)),
            bcc_area,
        );
        frame.render_widget(
            Paragraph::new(self.compose.subject.as_str()).block(field_block(
                "Subject",
                self.compose.field == ComposeField::Subject,
            )),
            subject_area,
        );
        self.draw_address_suggestions(frame, suggestions_area);
        frame.render_widget(
            Paragraph::new(self.compose.body.as_str())
                .block(field_block(
                    "Body",
                    self.compose.field == ComposeField::Body,
                ))
                .wrap(Wrap { trim: false }),
            body_area,
        );

        frame.render_widget(
            Line::from("Address fields: Up/Down choose, Enter accepts. Body: Enter adds newline.")
                .style(Style::new().fg(Color::Rgb(148, 163, 184))),
            footer_area,
        );
    }

    fn draw_search_popup(&mut self, frame: &mut Frame) {
        let area = centered_rect(62, 16, frame.area());
        frame.render_widget(Clear, area);
        let [input_area, info_area] =
            Layout::vertical([Constraint::Length(3), Constraint::Length(3)]).areas(area);

        self.hitboxes.search = Some(SearchHitboxes { input: input_area });

        frame.render_widget(
            Paragraph::new(format!("/{}", self.current_message_query())).block(
                Block::default()
                    .title("Search Mail")
                    .borders(Borders::ALL)
                    .border_style(
                        Style::new()
                            .fg(Color::Rgb(96, 165, 250))
                            .add_modifier(Modifier::BOLD),
                    )
                    .style(popup_style()),
            ),
            input_area,
        );

        let info = if let Some(account) = self.current_account() {
            format!(
                "{} match(es) in {}. Subject, sender, preview, body, and date are searched.",
                account.filtered_message_count(),
                account.current_folder()
            )
        } else {
            "Configure an account and sync a folder to search mail.".to_owned()
        };

        frame.render_widget(
            Paragraph::new(info)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Scope")
                        .border_style(
                            Style::new()
                                .fg(Color::Rgb(233, 196, 106))
                                .add_modifier(Modifier::BOLD),
                        )
                        .style(popup_style()),
                )
                .wrap(Wrap { trim: true }),
            info_area,
        );
    }

    fn draw_account_setup(&mut self, frame: &mut Frame) {
        let area = centered_rect(90, 78, frame.area());
        frame.render_widget(Clear, area);

        let rows = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(4),
        ])
        .split(area);

        let [provider_area, name_area] =
            Layout::horizontal([Constraint::Percentage(48), Constraint::Percentage(52)])
                .areas(rows[1]);
        let [email_area, login_area] =
            Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)])
                .areas(rows[2]);
        let [display_name_area, password_area] =
            Layout::horizontal([Constraint::Percentage(48), Constraint::Percentage(52)])
                .areas(rows[3]);
        let [imap_host_area, imap_port_area] =
            Layout::horizontal([Constraint::Percentage(72), Constraint::Percentage(28)])
                .areas(rows[4]);
        let [smtp_host_area, smtp_port_area] =
            Layout::horizontal([Constraint::Percentage(72), Constraint::Percentage(28)])
                .areas(rows[5]);
        let [tls_mode_area, summary_area] =
            Layout::horizontal([Constraint::Percentage(32), Constraint::Percentage(68)])
                .areas(rows[6]);

        self.hitboxes.account_setup = Some(AccountSetupHitboxes {
            provider: provider_area,
            provider_dropdown: None,
            name: name_area,
            email: email_area,
            login: login_area,
            display_name: display_name_area,
            password: password_area,
            imap_host: imap_host_area,
            imap_port: imap_port_area,
            smtp_host: smtp_host_area,
            smtp_port: smtp_port_area,
            tls_mode: tls_mode_area,
        });

        let provider = self.account_setup.provider();
        let provider_hint = if provider.requires_custom_servers() {
            "Custom provider: fill in IMAP/SMTP endpoints below."
        } else if provider.oauth_provider().is_some() {
            "Provider preset supplies IMAP/SMTP defaults. Save with a password now, or switch to OAuth afterward with o."
        } else {
            "Provider preset supplies IMAP/SMTP defaults. You only need mailbox credentials."
        };

        frame.render_widget(
            Line::from(" Add Account   Tab cycle fields   Ctrl-V show/hide password   Ctrl-S save   Esc cancel ")
                .style(
                    Style::new()
                        .fg(Color::Rgb(15, 23, 42))
                        .bg(Color::Rgb(96, 165, 250))
                        .add_modifier(Modifier::BOLD),
            ),
            rows[0],
        );

        frame.render_widget(
            Paragraph::new(provider.label()).block(field_block(
                "Provider",
                self.account_setup.field == SetupField::Provider,
            )),
            provider_area,
        );
        frame.render_widget(
            Paragraph::new(self.account_setup.name.as_str()).block(field_block(
                "Account Name",
                self.account_setup.field == SetupField::Name,
            )),
            name_area,
        );
        frame.render_widget(
            Paragraph::new(self.account_setup.email.as_str()).block(field_block(
                "Email",
                self.account_setup.field == SetupField::Email,
            )),
            email_area,
        );
        frame.render_widget(
            Paragraph::new(self.account_setup.login.as_str()).block(field_block(
                "Login Override",
                self.account_setup.field == SetupField::Login,
            )),
            login_area,
        );
        frame.render_widget(
            Paragraph::new(self.account_setup.display_name.as_str()).block(field_block(
                "Display Name",
                self.account_setup.field == SetupField::DisplayName,
            )),
            display_name_area,
        );
        frame.render_widget(
            Paragraph::new(self.account_setup.password_display()).block(field_block(
                if self.account_setup.show_password {
                    "Password / App Password (visible)"
                } else {
                    "Password / App Password (hidden)"
                },
                self.account_setup.field == SetupField::Password,
            )),
            password_area,
        );

        let imap_host = if provider.requires_custom_servers() {
            self.account_setup.imap_host.clone()
        } else {
            provider
                .default_imap()
                .map(|(host, port)| format!("{host}:{port}"))
                .unwrap_or_else(|| "-".to_owned())
        };
        let imap_port = if provider.requires_custom_servers() {
            self.account_setup.imap_port.clone()
        } else {
            "preset".to_owned()
        };
        let smtp_host = if provider.requires_custom_servers() {
            self.account_setup.smtp_host.clone()
        } else {
            provider
                .default_smtp()
                .map(|(host, port, mode)| format!("{host}:{port} ({})", mode.label()))
                .unwrap_or_else(|| "-".to_owned())
        };
        let smtp_port = if provider.requires_custom_servers() {
            self.account_setup.smtp_port.clone()
        } else {
            "preset".to_owned()
        };
        let tls_mode = if provider.requires_custom_servers() {
            self.account_setup.tls_mode.label().to_owned()
        } else {
            provider
                .default_smtp()
                .map(|(_, _, mode)| mode.label().to_owned())
                .unwrap_or_else(|| "-".to_owned())
        };

        frame.render_widget(
            Paragraph::new(imap_host).block(setup_field_block(
                "IMAP Host",
                self.account_setup.field == SetupField::ImapHost,
                provider.requires_custom_servers(),
            )),
            imap_host_area,
        );
        frame.render_widget(
            Paragraph::new(imap_port).block(setup_field_block(
                "IMAP Port",
                self.account_setup.field == SetupField::ImapPort,
                provider.requires_custom_servers(),
            )),
            imap_port_area,
        );
        frame.render_widget(
            Paragraph::new(smtp_host).block(setup_field_block(
                "SMTP Host",
                self.account_setup.field == SetupField::SmtpHost,
                provider.requires_custom_servers(),
            )),
            smtp_host_area,
        );
        frame.render_widget(
            Paragraph::new(smtp_port).block(setup_field_block(
                "SMTP Port",
                self.account_setup.field == SetupField::SmtpPort,
                provider.requires_custom_servers(),
            )),
            smtp_port_area,
        );
        frame.render_widget(
            Paragraph::new(tls_mode).block(setup_field_block(
                "SMTP TLS Mode",
                self.account_setup.field == SetupField::TlsMode,
                provider.requires_custom_servers(),
            )),
            tls_mode_area,
        );
        frame.render_widget(
            Paragraph::new(if provider.requires_custom_servers() {
                "Custom mode: fill host, port, and TLS fields."
            } else {
                "Preset mode: IMAP/SMTP values come from the selected provider."
            })
            .block(
                Block::default()
                    .title("Provider Summary")
                    .borders(Borders::ALL)
                    .border_style(
                        Style::new()
                            .fg(Color::Rgb(233, 196, 106))
                            .add_modifier(Modifier::BOLD),
                    )
                    .style(popup_style()),
            )
            .wrap(Wrap { trim: true }),
            summary_area,
        );
        frame.render_widget(
            Paragraph::new(format!(
                "{provider_hint} Credentials are saved to a local secret file under {}.",
                self.config_path
                    .parent()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "~/.config/email-client-tui-rs".to_owned())
            ))
            .block(
                Block::default()
                    .title("Login Flow")
                    .borders(Borders::ALL)
                    .border_style(
                        Style::new()
                            .fg(Color::Rgb(42, 157, 143))
                            .add_modifier(Modifier::BOLD),
                    )
                    .style(popup_style()),
            )
            .wrap(Wrap { trim: true }),
            rows[7],
        );

        if self.account_setup.provider_dropdown_open {
            let popup_bottom = area.y.saturating_add(area.height);
            let dropdown_height = (ProviderKind::ALL.len() as u16 + 2).min(
                popup_bottom.saturating_sub(provider_area.y.saturating_add(provider_area.height)),
            );
            let dropdown_area = Rect {
                x: provider_area.x,
                y: provider_area.y.saturating_add(provider_area.height),
                width: provider_area.width,
                height: dropdown_height.max(3),
            };
            if let Some(hitboxes) = self.hitboxes.account_setup.as_mut() {
                hitboxes.provider_dropdown = Some(dropdown_area);
            }

            frame.render_widget(Clear, dropdown_area);
            let items = ProviderKind::ALL
                .iter()
                .map(|provider| ListItem::new(provider.label()))
                .collect::<Vec<_>>();
            let list = List::new(items)
                .block(
                    Block::default()
                        .title("Choose Provider")
                        .borders(Borders::ALL)
                        .border_style(
                            Style::new()
                                .fg(Color::Rgb(96, 165, 250))
                                .add_modifier(Modifier::BOLD),
                        )
                        .style(popup_style()),
                )
                .highlight_style(selected_style())
                .highlight_symbol("▸ ");
            let mut state = ListState::default();
            state.select(Some(self.account_setup.provider_dropdown_index));
            frame.render_stateful_widget(list, dropdown_area, &mut state);
        }
    }

    fn draw_account_oauth(&mut self, frame: &mut Frame) {
        let area = centered_rect(78, 52, frame.area());
        frame.render_widget(Clear, area);

        let [
            header_area,
            info_area,
            client_id_area,
            client_secret_area,
            buttons_area,
        ] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(8),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
        ])
        .areas(area);
        let [start_area, cancel_area] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(buttons_area);

        self.hitboxes.oauth_setup = Some(OAuthSetupHitboxes {
            dialog: area,
            client_id: client_id_area,
            client_secret: client_secret_area,
            start: start_area,
            cancel: cancel_area,
        });

        let provider_label = self
            .oauth_setup
            .provider
            .map(|provider| provider.label())
            .unwrap_or("oauth");
        let header = if self.oauth_setup.running {
            format!(
                " Authorize {}   {} Waiting for browser callback   Esc/q/Cancel closes ",
                provider_label,
                self.spinner()
            )
        } else {
            format!(
                " Authorize {}   Tab fields   Ctrl-V show/hide secret ",
                provider_label
            )
        };

        frame.render_widget(
            Line::from(header).style(
                Style::new()
                    .fg(Color::Rgb(15, 23, 42))
                    .bg(Color::Rgb(42, 157, 143))
                    .add_modifier(Modifier::BOLD),
            ),
            header_area,
        );

        let instructions = match self.oauth_setup.provider {
            Some(OAuthProviderKind::GoogleMail) => {
                "Google setup: place a Google OAuth Desktop client JSON like client_secret_*.json in the current directory, or paste the client ID manually. This flow requests https://mail.google.com/ and stores a refresh token locally."
            }
            Some(OAuthProviderKind::MicrosoftMail) => {
                "Microsoft setup: create an Entra app that supports personal Microsoft accounts for live.com, add delegated IMAP.AccessAsUser.All + SMTP.Send permissions, request offline_access, and register http://localhost/oauth/microsoft/callback as a redirect URI."
            }
            None => "OAuth is only available for Gmail and Outlook accounts right now.",
        };
        let progress = if self.oauth_setup.progress_message.is_empty() {
            instructions.to_owned()
        } else if self.oauth_setup.auth_url.is_empty() {
            format!("{instructions}\n\n{}", self.oauth_setup.progress_message)
        } else {
            format!(
                "{instructions}\n\n{}\n\n{}",
                self.oauth_setup.progress_message, self.oauth_setup.auth_url
            )
        };

        frame.render_widget(
            Paragraph::new(progress)
                .block(
                    Block::default()
                        .title(format!(
                            "{} <{}>",
                            self.oauth_setup.account_name, self.oauth_setup.account_email
                        ))
                        .borders(Borders::ALL)
                        .border_style(
                            Style::new()
                                .fg(Color::Rgb(96, 165, 250))
                                .add_modifier(Modifier::BOLD),
                        )
                        .style(popup_style()),
                )
                .wrap(Wrap { trim: true }),
            info_area,
        );

        frame.render_widget(
            Paragraph::new(self.oauth_setup.client_id.as_str()).block(field_block(
                "OAuth Client ID",
                self.oauth_setup.field == OAuthField::ClientId && !self.oauth_setup.running,
            )),
            client_id_area,
        );
        frame.render_widget(
            Paragraph::new(self.oauth_setup.client_secret_display()).block(field_block(
                if self.oauth_setup.show_client_secret {
                    "Client Secret (visible, optional)"
                } else {
                    "Client Secret (hidden, optional)"
                },
                self.oauth_setup.field == OAuthField::ClientSecret && !self.oauth_setup.running,
            )),
            client_secret_area,
        );

        let start_label = if self.oauth_setup.running {
            format!("{} Authorizing...", self.spinner())
        } else {
            "Open Browser".to_owned()
        };
        frame.render_widget(
            Paragraph::new(start_label).block(confirm_block(
                self.oauth_setup.field == OAuthField::Start && !self.oauth_setup.running,
            )),
            start_area,
        );
        frame.render_widget(
            Paragraph::new("Cancel").block(confirm_block(
                self.oauth_setup.field == OAuthField::Cancel && !self.oauth_setup.running,
            )),
            cancel_area,
        );
    }

    fn draw_confirm_delete(&mut self, frame: &mut Frame) {
        let area = centered_rect(52, 28, frame.area());
        frame.render_widget(Clear, area);

        let [header_area, body_area, buttons_area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(4),
            Constraint::Length(3),
        ])
        .areas(area);
        let [confirm_area, cancel_area] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(buttons_area);

        self.hitboxes.confirm_delete = Some(ConfirmDeleteHitboxes {
            dialog: area,
            confirm: confirm_area,
            cancel: cancel_area,
        });

        frame.render_widget(
            Line::from(" Remove Account   Enter confirm   Tab switch   Esc cancel ").style(
                Style::new()
                    .fg(Color::Rgb(15, 23, 42))
                    .bg(Color::Rgb(244, 162, 97))
                    .add_modifier(Modifier::BOLD),
            ),
            header_area,
        );
        frame.render_widget(
            Paragraph::new(format!(
                "Delete account '{}'?\n\nThis will remove it from saved config and delete its local secret file if one exists.",
                self.confirm_delete.account_name
            ))
            .block(
                Block::default()
                    .title("Confirm Removal")
                    .borders(Borders::ALL)
                    .border_style(
                        Style::new()
                            .fg(Color::Rgb(244, 162, 97))
                            .add_modifier(Modifier::BOLD),
                    )
                    .style(popup_style()),
            )
            .wrap(Wrap { trim: true }),
            body_area,
        );
        frame.render_widget(
            Paragraph::new("Delete").block(confirm_block(self.confirm_delete.confirm_selected)),
            confirm_area,
        );
        frame.render_widget(
            Paragraph::new("Cancel").block(confirm_block(!self.confirm_delete.confirm_selected)),
            cancel_area,
        );
    }

    fn handle_normal_click(&mut self, mouse: MouseEvent) -> Result<()> {
        let x = mouse.column;
        let y = mouse.row;

        if rect_contains(self.hitboxes.accounts, x, y) {
            self.focus = Pane::Accounts;
            if let Some(index) = list_index_from_click(
                inner_rect(self.hitboxes.accounts),
                y,
                &self.account_row_heights(),
            ) {
                self.selected_account = index;
                self.status = format!(
                    "Selected account {}.",
                    self.current_account()
                        .map(|account| account.config.name.as_str())
                        .unwrap_or("unknown")
                );
            }
            return Ok(());
        }

        if rect_contains(self.hitboxes.folders, x, y) {
            self.focus = Pane::Folders;
            if let Some(account) = self.current_account() {
                let heights = vec![1; account.config.folders.len()];
                if let Some(index) =
                    list_index_from_click(inner_rect(self.hitboxes.folders), y, &heights)
                {
                    self.set_folder_selection(index);
                }
            }
            return Ok(());
        }

        if rect_contains(self.hitboxes.messages, x, y) {
            self.focus = Pane::Messages;
            if let Some(index) = self.message_index_from_click(y) {
                self.set_message_selection(index);
                self.enter_reader_mode();
            }
            return Ok(());
        }

        if rect_contains(self.hitboxes.preview, x, y) {
            self.focus = Pane::Preview;
            self.enter_reader_mode();
        }

        Ok(())
    }

    fn handle_command_click(&mut self, mouse: MouseEvent) -> Result<()> {
        let Some(hitboxes) = self.hitboxes.command.clone() else {
            return Ok(());
        };

        let x = mouse.column;
        let y = mouse.row;
        if rect_contains(hitboxes.input, x, y) {
            return Ok(());
        }

        if rect_contains(hitboxes.list, x, y) {
            let heights = vec![2; self.command_matches.len()];
            if let Some(index) = list_index_from_click(inner_rect(hitboxes.list), y, &heights) {
                self.command_index = index;
                if let Some(command) = self.command_matches.get(index).map(|item| item.action) {
                    self.leave_command_mode();
                    self.run_command(command)?;
                }
            }
        }

        Ok(())
    }

    fn handle_compose_click(&mut self, mouse: MouseEvent) -> Result<()> {
        let Some(hitboxes) = self.hitboxes.compose.clone() else {
            return Ok(());
        };

        let x = mouse.column;
        let y = mouse.row;
        if rect_contains(hitboxes.to, x, y) {
            self.compose.field = ComposeField::To;
            self.refresh_compose_suggestions();
            return Ok(());
        }
        if rect_contains(hitboxes.cc, x, y) {
            self.compose.field = ComposeField::Cc;
            self.refresh_compose_suggestions();
            return Ok(());
        }
        if rect_contains(hitboxes.bcc, x, y) {
            self.compose.field = ComposeField::Bcc;
            self.refresh_compose_suggestions();
            return Ok(());
        }
        if rect_contains(hitboxes.subject, x, y) {
            self.compose.field = ComposeField::Subject;
            self.refresh_compose_suggestions();
            return Ok(());
        }
        if rect_contains(hitboxes.body, x, y) {
            self.compose.field = ComposeField::Body;
            self.refresh_compose_suggestions();
            return Ok(());
        }
        if rect_contains(hitboxes.suggestions, x, y) && self.compose.field.is_address() {
            let heights = vec![1; self.compose.suggestions.len()];
            if let Some(index) =
                list_index_from_click(inner_rect(hitboxes.suggestions), y, &heights)
            {
                self.compose.suggestion_index = index;
                self.accept_compose_suggestion();
            }
        }

        Ok(())
    }

    fn handle_search_click(&mut self, mouse: MouseEvent) -> Result<()> {
        let Some(hitboxes) = self.hitboxes.search.clone() else {
            return Ok(());
        };

        if rect_contains(hitboxes.input, mouse.column, mouse.row) {
            return Ok(());
        }

        if rect_contains(self.hitboxes.messages, mouse.column, mouse.row) {
            self.focus = Pane::Messages;
            if let Some(index) = self.message_index_from_click(mouse.row) {
                self.set_message_selection(index);
            }
        }

        Ok(())
    }

    fn handle_account_setup_click(&mut self, mouse: MouseEvent) -> Result<()> {
        let Some(hitboxes) = self.hitboxes.account_setup.clone() else {
            return Ok(());
        };

        let x = mouse.column;
        let y = mouse.row;
        if rect_contains(hitboxes.provider, x, y) {
            self.account_setup.field = SetupField::Provider;
            if self.account_setup.provider_dropdown_open {
                self.account_setup.close_provider_dropdown();
            } else {
                self.account_setup.open_provider_dropdown();
            }
        } else if let Some(dropdown) = hitboxes.provider_dropdown {
            if rect_contains(dropdown, x, y) {
                let heights = vec![1; ProviderKind::ALL.len()];
                if let Some(index) = list_index_from_click(inner_rect(dropdown), y, &heights) {
                    self.account_setup.provider_dropdown_index = index;
                    self.account_setup.select_provider_dropdown();
                }
            } else {
                self.account_setup.close_provider_dropdown();
            }
        } else if rect_contains(hitboxes.name, x, y) {
            self.account_setup.close_provider_dropdown();
            self.account_setup.field = SetupField::Name;
        } else if rect_contains(hitboxes.email, x, y) {
            self.account_setup.close_provider_dropdown();
            self.account_setup.field = SetupField::Email;
        } else if rect_contains(hitboxes.login, x, y) {
            self.account_setup.close_provider_dropdown();
            self.account_setup.field = SetupField::Login;
        } else if rect_contains(hitboxes.display_name, x, y) {
            self.account_setup.close_provider_dropdown();
            self.account_setup.field = SetupField::DisplayName;
        } else if rect_contains(hitboxes.password, x, y) {
            self.account_setup.close_provider_dropdown();
            self.account_setup.field = SetupField::Password;
        } else if self.account_setup.provider().requires_custom_servers()
            && rect_contains(hitboxes.imap_host, x, y)
        {
            self.account_setup.close_provider_dropdown();
            self.account_setup.field = SetupField::ImapHost;
        } else if self.account_setup.provider().requires_custom_servers()
            && rect_contains(hitboxes.imap_port, x, y)
        {
            self.account_setup.close_provider_dropdown();
            self.account_setup.field = SetupField::ImapPort;
        } else if self.account_setup.provider().requires_custom_servers()
            && rect_contains(hitboxes.smtp_host, x, y)
        {
            self.account_setup.close_provider_dropdown();
            self.account_setup.field = SetupField::SmtpHost;
        } else if self.account_setup.provider().requires_custom_servers()
            && rect_contains(hitboxes.smtp_port, x, y)
        {
            self.account_setup.close_provider_dropdown();
            self.account_setup.field = SetupField::SmtpPort;
        } else if self.account_setup.provider().requires_custom_servers()
            && rect_contains(hitboxes.tls_mode, x, y)
        {
            self.account_setup.close_provider_dropdown();
            self.account_setup.field = SetupField::TlsMode;
        } else {
            self.account_setup.close_provider_dropdown();
        }

        Ok(())
    }

    fn handle_account_oauth_click(&mut self, mouse: MouseEvent) -> Result<()> {
        let Some(hitboxes) = self.hitboxes.oauth_setup.clone() else {
            return Ok(());
        };

        if rect_contains(hitboxes.cancel, mouse.column, mouse.row)
            || !rect_contains(hitboxes.dialog, mouse.column, mouse.row)
        {
            self.close_account_oauth(
                "Account OAuth cancelled. Close the browser tab if it is still open.",
            );
            return Ok(());
        }

        if self.oauth_setup.running {
            return Ok(());
        }

        if rect_contains(hitboxes.client_id, mouse.column, mouse.row) {
            self.oauth_setup.field = OAuthField::ClientId;
        } else if rect_contains(hitboxes.client_secret, mouse.column, mouse.row) {
            self.oauth_setup.field = OAuthField::ClientSecret;
        } else if rect_contains(hitboxes.start, mouse.column, mouse.row) {
            self.oauth_setup.field = OAuthField::Start;
            self.start_account_oauth()?;
        }

        Ok(())
    }

    fn handle_confirm_delete_click(&mut self, mouse: MouseEvent) -> Result<()> {
        let Some(hitboxes) = self.hitboxes.confirm_delete.clone() else {
            return Ok(());
        };

        if rect_contains(hitboxes.confirm, mouse.column, mouse.row) {
            self.confirm_delete.confirm_selected = true;
            return self.confirm_remove_selected_account();
        }

        if rect_contains(hitboxes.cancel, mouse.column, mouse.row) {
            self.cancel_remove_selected_account();
            return Ok(());
        }

        if !rect_contains(hitboxes.dialog, mouse.column, mouse.row) {
            self.cancel_remove_selected_account();
        }

        Ok(())
    }

    fn handle_normal_scroll(&mut self, mouse: MouseEvent, delta: isize) -> Result<()> {
        let x = mouse.column;
        let y = mouse.row;

        if rect_contains(self.hitboxes.accounts, x, y) {
            self.focus = Pane::Accounts;
            self.move_account_selection(delta);
        } else if rect_contains(self.hitboxes.folders, x, y) {
            self.focus = Pane::Folders;
            self.move_folder_selection(delta);
        } else if rect_contains(self.hitboxes.messages, x, y) {
            self.focus = Pane::Messages;
            self.move_message_selection(delta);
        }

        Ok(())
    }

    fn handle_command_scroll(&mut self, mouse: MouseEvent, delta: isize) -> Result<()> {
        if let Some(hitboxes) = self.hitboxes.command.clone() {
            if rect_contains(hitboxes.list, mouse.column, mouse.row) {
                self.step_command_match(delta);
            }
        }

        Ok(())
    }

    fn handle_compose_scroll(&mut self, mouse: MouseEvent, delta: isize) {
        if let Some(hitboxes) = self.hitboxes.compose.clone() {
            if rect_contains(hitboxes.suggestions, mouse.column, mouse.row) {
                self.step_compose_suggestion(delta);
            }
        }
    }

    fn handle_search_scroll(&mut self, mouse: MouseEvent, delta: isize) {
        if rect_contains(self.hitboxes.messages, mouse.column, mouse.row) {
            self.focus = Pane::Messages;
            self.move_message_selection(delta);
        }
    }

    fn handle_account_setup_scroll(&mut self, mouse: MouseEvent, delta: isize) {
        if let Some(hitboxes) = self.hitboxes.account_setup.clone() {
            if let Some(dropdown) = hitboxes.provider_dropdown {
                if rect_contains(dropdown, mouse.column, mouse.row) {
                    self.account_setup.step_dropdown(delta);
                    return;
                }
            }

            if rect_contains(hitboxes.provider, mouse.column, mouse.row) {
                self.account_setup.field = SetupField::Provider;
                self.account_setup.open_provider_dropdown();
                self.account_setup.step_dropdown(delta);
            } else if self.account_setup.provider().requires_custom_servers()
                && rect_contains(hitboxes.tls_mode, mouse.column, mouse.row)
            {
                self.account_setup.field = SetupField::TlsMode;
                self.account_setup.step_selector(delta);
            }
        }
    }

    fn handle_confirm_delete_mode(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Esc | KeyCode::Char('n') => {
                self.cancel_remove_selected_account();
            }
            KeyCode::Char('y') => {
                self.confirm_delete.confirm_selected = true;
                self.confirm_remove_selected_account()?;
            }
            KeyCode::Left | KeyCode::Char('h') => self.confirm_delete.confirm_selected = true,
            KeyCode::Right | KeyCode::Char('l') => self.confirm_delete.confirm_selected = false,
            KeyCode::Tab | KeyCode::BackTab => {
                self.confirm_delete.confirm_selected = !self.confirm_delete.confirm_selected;
            }
            KeyCode::Enter => {
                if self.confirm_delete.confirm_selected {
                    self.confirm_remove_selected_account()?;
                } else {
                    self.cancel_remove_selected_account();
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn handle_normal_mode(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char(':') => self.enter_command_mode(),
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('a') => self.enter_account_setup_mode(),
            KeyCode::Char('o') => self.enter_account_oauth_mode()?,
            KeyCode::Char('c') => self.enter_compose_mode(),
            KeyCode::Char('/') => self.enter_search_mode(),
            KeyCode::Char('s') => self.sync_current_account()?,
            KeyCode::Char('m') => self.load_older_current_folder()?,
            KeyCode::Tab => self.focus = self.focus.next(),
            KeyCode::BackTab => self.focus = self.focus.previous(),
            KeyCode::Char('h') | KeyCode::Left => self.focus = self.focus.previous(),
            KeyCode::Char('l') | KeyCode::Right => self.focus = self.focus.next(),
            KeyCode::Char('j') | KeyCode::Down => self.move_selection(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_selection(-1),
            KeyCode::Char('g') => {
                if self.pending_g {
                    self.move_to_edge(false);
                    self.pending_g = false;
                } else {
                    self.pending_g = true;
                }
            }
            KeyCode::Char('G') => {
                self.move_to_edge(true);
                self.pending_g = false;
            }
            KeyCode::Enter => {
                self.pending_g = false;
                match self.focus {
                    Pane::Accounts => {
                        self.focus = Pane::Folders;
                        self.status = "Folders focused.".to_owned();
                    }
                    Pane::Folders => {
                        self.sync_current_account()?;
                        self.focus = Pane::Messages;
                    }
                    Pane::Messages | Pane::Preview => {
                        self.enter_reader_mode();
                    }
                }
            }
            _ => self.pending_g = false,
        }

        Ok(())
    }

    fn handle_reader_mode(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.mode = Mode::Normal;
                self.status = "Closed message reader.".to_owned();
            }
            KeyCode::Char('j') | KeyCode::Down => self.scroll_reader(1, 1),
            KeyCode::Char('k') | KeyCode::Up => self.scroll_reader(-1, 1),
            KeyCode::PageDown | KeyCode::Char(' ') | KeyCode::Char('l') => {
                self.scroll_reader(1, 12)
            }
            KeyCode::PageUp | KeyCode::Char('h') => self.scroll_reader(-1, 12),
            KeyCode::Char('g') => self.reader_scroll = 0,
            KeyCode::Char('G') => self.reader_scroll = u16::MAX,
            _ => {}
        }

        Ok(())
    }

    fn handle_account_setup_mode(&mut self, key: KeyEvent) -> Result<()> {
        if key.code == KeyCode::Esc {
            if self.account_setup.provider_dropdown_open {
                self.account_setup.close_provider_dropdown();
                return Ok(());
            }
            self.mode = Mode::Normal;
            self.account_setup = AccountSetupState::default();
            self.status = "Account setup cancelled.".to_owned();
            return Ok(());
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('v') {
            self.account_setup.show_password = !self.account_setup.show_password;
            self.status = if self.account_setup.show_password {
                "Password is visible in the account setup form.".to_owned()
            } else {
                "Password is hidden in the account setup form.".to_owned()
            };
            return Ok(());
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
            self.save_account_setup()?;
            return Ok(());
        }

        match key.code {
            KeyCode::Tab => {
                self.account_setup.close_provider_dropdown();
                self.account_setup.next_field();
            }
            KeyCode::BackTab => self.account_setup.previous_field(),
            KeyCode::Enter => {
                if self.account_setup.field == SetupField::Provider {
                    if self.account_setup.provider_dropdown_open {
                        self.account_setup.select_provider_dropdown();
                    } else {
                        self.account_setup.open_provider_dropdown();
                    }
                } else {
                    self.account_setup.next_field();
                }
            }
            KeyCode::Left => self.account_setup.step_selector(-1),
            KeyCode::Right => self.account_setup.step_selector(1),
            KeyCode::Down => self.account_setup.step_dropdown(1),
            KeyCode::Up => self.account_setup.step_dropdown(-1),
            KeyCode::Backspace => self.account_setup.backspace(),
            KeyCode::Char(ch) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.account_setup.push_char(ch);
            }
            _ => {}
        }

        Ok(())
    }

    fn handle_account_oauth_mode(&mut self, key: KeyEvent) -> Result<()> {
        if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) {
            self.close_account_oauth(
                "Account OAuth cancelled. Close the browser tab if it is still open.",
            );
            return Ok(());
        }

        if self.oauth_setup.running {
            return Ok(());
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('v') {
            self.oauth_setup.show_client_secret = !self.oauth_setup.show_client_secret;
            self.status = if self.oauth_setup.show_client_secret {
                "OAuth client secret is visible.".to_owned()
            } else {
                "OAuth client secret is hidden.".to_owned()
            };
            return Ok(());
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
            self.start_account_oauth()?;
            return Ok(());
        }

        match key.code {
            KeyCode::Tab => self.oauth_setup.next_field(),
            KeyCode::BackTab => self.oauth_setup.previous_field(),
            KeyCode::Enter => match self.oauth_setup.field {
                OAuthField::ClientId | OAuthField::ClientSecret => self.oauth_setup.next_field(),
                OAuthField::Start => self.start_account_oauth()?,
                OAuthField::Cancel => self.close_account_oauth("Account OAuth cancelled."),
            },
            KeyCode::Backspace => self.oauth_setup.backspace(),
            KeyCode::Char(ch) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.oauth_setup.push_char(ch);
            }
            _ => {}
        }

        Ok(())
    }

    fn handle_search_mode(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                self.mode = Mode::Normal;
                self.status = if self.current_message_query().is_empty() {
                    "Search cleared.".to_owned()
                } else {
                    format!("Search active: /{}", self.current_message_query())
                };
            }
            KeyCode::Backspace => {
                let visible_count = self.message_visible_count();
                if let Some(account) = self.current_account_mut() {
                    account.message_query.pop();
                    account.clamp_selected_message();
                    account.sync_message_scroll(visible_count);
                }
            }
            KeyCode::Down => {
                self.focus = Pane::Messages;
                self.move_message_selection(1);
            }
            KeyCode::Up => {
                self.focus = Pane::Messages;
                self.move_message_selection(-1);
            }
            KeyCode::Char(ch) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                let visible_count = self.message_visible_count();
                if let Some(account) = self.current_account_mut() {
                    account.message_query.push(ch);
                    account.clamp_selected_message();
                    account.sync_message_scroll(visible_count);
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn handle_command_mode(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Esc => self.leave_command_mode(),
            KeyCode::Enter => {
                if let Some(command) = self
                    .command_matches
                    .get(self.command_index)
                    .map(|item| item.action)
                {
                    self.leave_command_mode();
                    self.run_command(command)?;
                } else {
                    self.status = "No matching command.".to_owned();
                }
            }
            KeyCode::Backspace => {
                self.command_input.pop();
                self.refresh_command_matches();
            }
            KeyCode::Down | KeyCode::Tab => self.step_command_match(1),
            KeyCode::Up | KeyCode::BackTab => self.step_command_match(-1),
            KeyCode::Char(ch) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.command_input.push(ch);
                self.refresh_command_matches();
            }
            _ => {}
        }

        Ok(())
    }

    fn handle_compose_mode(&mut self, key: KeyEvent) -> Result<()> {
        if key.code == KeyCode::Esc {
            self.mode = Mode::Normal;
            self.status = "Draft discarded.".to_owned();
            self.compose = ComposeState::default();
            return Ok(());
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
            self.send_current_draft()?;
            return Ok(());
        }

        match key.code {
            KeyCode::Tab => {
                self.compose.field = self.compose.field.next();
                self.refresh_compose_suggestions();
            }
            KeyCode::BackTab => {
                self.compose.field = self.compose.field.previous();
                self.refresh_compose_suggestions();
            }
            KeyCode::Down => self.step_compose_suggestion(1),
            KeyCode::Up => self.step_compose_suggestion(-1),
            KeyCode::Backspace => {
                self.current_compose_field_mut().pop();
                self.refresh_compose_suggestions();
            }
            KeyCode::Enter => {
                if self.compose.field.is_address() && !self.compose.suggestions.is_empty() {
                    self.accept_compose_suggestion();
                } else if self.compose.field == ComposeField::Body {
                    self.compose.body.push('\n');
                } else {
                    self.compose.field = self.compose.field.next();
                    self.refresh_compose_suggestions();
                }
            }
            KeyCode::Char(ch) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.current_compose_field_mut().push(ch);
                self.refresh_compose_suggestions();
            }
            _ => {}
        }

        Ok(())
    }

    fn run_command(&mut self, command: AppCommand) -> Result<()> {
        match command {
            AppCommand::Sync => self.sync_current_account(),
            AppCommand::LoadOlder => self.load_older_current_folder(),
            AppCommand::AddAccount => {
                self.enter_account_setup_mode();
                Ok(())
            }
            AppCommand::RemoveAccount => self.prompt_remove_selected_account(),
            AppCommand::AuthorizeAccount => self.enter_account_oauth_mode(),
            AppCommand::Compose => {
                self.enter_compose_mode();
                Ok(())
            }
            AppCommand::Search => {
                self.enter_search_mode();
                Ok(())
            }
            AppCommand::FocusAccounts => {
                self.focus = Pane::Accounts;
                Ok(())
            }
            AppCommand::FocusFolders => {
                self.focus = Pane::Folders;
                Ok(())
            }
            AppCommand::FocusMessages => {
                self.focus = Pane::Messages;
                Ok(())
            }
            AppCommand::FocusPreview => {
                self.focus = Pane::Preview;
                Ok(())
            }
            AppCommand::NextAccount => {
                self.focus = Pane::Accounts;
                self.move_selection(1);
                Ok(())
            }
            AppCommand::PreviousAccount => {
                self.focus = Pane::Accounts;
                self.move_selection(-1);
                Ok(())
            }
            AppCommand::NextFolder => {
                self.focus = Pane::Folders;
                self.move_selection(1);
                Ok(())
            }
            AppCommand::PreviousFolder => {
                self.focus = Pane::Folders;
                self.move_selection(-1);
                Ok(())
            }
            AppCommand::Quit => {
                self.should_quit = true;
                Ok(())
            }
        }
    }

    fn sync_current_account(&mut self) -> Result<()> {
        self.start_sync_for_account(self.selected_account, None, SyncReason::Manual)
    }

    fn load_older_current_folder(&mut self) -> Result<()> {
        self.start_sync_for_account(self.selected_account, None, SyncReason::LoadOlder)
    }

    fn start_sync_for_account(
        &mut self,
        account_index: usize,
        folder_override: Option<String>,
        reason: SyncReason,
    ) -> Result<()> {
        if let Some(job) = &self.sync_job {
            self.status = format!(
                "Sync already running for {} / {}.",
                job.account_name, job.requested_folder
            );
            return Ok(());
        }

        let account_state = self
            .accounts
            .get(account_index)
            .ok_or_else(|| anyhow::anyhow!("no account selected"))?;
        let account = account_state.config.clone();
        let requested_folder =
            folder_override.unwrap_or_else(|| account_state.current_folder().to_owned());
        let before_uid = if reason == SyncReason::LoadOlder {
            match oldest_loaded_uid(&account_state.messages) {
                Some(uid) => Some(uid),
                None => {
                    self.status = "Sync this folder before loading older messages.".to_owned();
                    return Ok(());
                }
            }
        } else {
            None
        };
        let fetch_limit = self.config.fetch_limit();
        let account_name = account.name.clone();
        let (sender, receiver) = mpsc::channel();
        let worker_account_name = account_name.clone();
        let worker_requested_folder = requested_folder.clone();

        thread::spawn(move || {
            let result = match before_uid {
                Some(uid) => {
                    MailClient::load_older(&account, &worker_requested_folder, uid, fetch_limit)
                        .map(|synced| SyncBatch {
                            folders: vec![],
                            synced_folders: vec![synced],
                        })
                }
                None => MailClient::sync_folders(&account, &worker_requested_folder, fetch_limit),
            }
            .map_err(|error| format!("{error:#}"));
            let _ = sender.send(SyncWorkerResult {
                account_index,
                account_name: worker_account_name,
                requested_folder: worker_requested_folder,
                reason,
                result,
            });
        });

        self.sync_receiver = Some(receiver);
        self.sync_job = Some(SyncJob {
            account_name: account_name.clone(),
            requested_folder: requested_folder.clone(),
            reason,
        });
        self.status = match reason {
            SyncReason::Manual => {
                format!("Syncing {} / {}...", account_name, requested_folder)
            }
            SyncReason::Auto => {
                format!("Auto-syncing {} / {}...", account_name, requested_folder)
            }
            SyncReason::SentCopy => {
                format!(
                    "Refreshing {} / {} after send...",
                    account_name, requested_folder
                )
            }
            SyncReason::LoadOlder => {
                format!(
                    "Loading older messages from {} / {}...",
                    account_name, requested_folder
                )
            }
        };
        Ok(())
    }

    fn poll_sync_updates(&mut self) {
        let mut result = None;
        if let Some(receiver) = &self.sync_receiver
            && let Ok(update) = receiver.try_recv()
        {
            result = Some(update);
        }

        let Some(update) = result else {
            return;
        };

        self.sync_receiver = None;
        self.sync_job = None;

        let SyncWorkerResult {
            account_index,
            account_name,
            requested_folder,
            reason,
            result,
        } = update;

        match result {
            Ok(batch) => {
                if let Err(error) =
                    self.finish_sync(account_index, account_name, requested_folder, reason, batch)
                {
                    self.status = format!("Error: {error:#}");
                }
            }
            Err(error) => {
                self.status = format!("Error: sync failed: {error}");
            }
        }
    }

    fn maybe_start_auto_sync(&mut self) {
        if self.mode != Mode::Normal
            || self.accounts.is_empty()
            || self.sync_job.is_some()
            || self.last_auto_sync.elapsed() < AUTO_SYNC_INTERVAL
        {
            return;
        }

        let index = self
            .next_auto_account
            .min(self.accounts.len().saturating_sub(1));
        self.next_auto_account = if self.accounts.is_empty() {
            0
        } else {
            (index + 1) % self.accounts.len()
        };
        self.last_auto_sync = Instant::now();

        if let Err(error) = self.start_sync_for_account(index, None, SyncReason::Auto) {
            self.status = format!("Error: auto-sync failed to start: {error:#}");
        }
    }

    fn finish_sync(
        &mut self,
        account_index: usize,
        account_name: String,
        requested_folder: String,
        reason: SyncReason,
        batch: SyncBatch,
    ) -> Result<()> {
        if account_index >= self.accounts.len()
            || self.accounts[account_index].config.name != account_name
        {
            return Ok(());
        }

        let synced_at = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        if reason != SyncReason::LoadOlder {
            for synced in &batch.synced_folders {
                cache::save_folder(
                    &self.cache_root,
                    &account_name,
                    &synced.folder,
                    &synced_at,
                    &synced.messages,
                )?;
            }
        }

        self.apply_discovered_folders(account_index, &batch.folders)?;

        let folder_to_show = match reason {
            SyncReason::Manual | SyncReason::SentCopy | SyncReason::LoadOlder => batch
                .synced_folders
                .first()
                .map(|synced| synced.folder.as_str())
                .unwrap_or(requested_folder.as_str()),
            SyncReason::Auto => self.accounts[account_index].current_folder(),
        }
        .to_owned();

        if let Some(position) = matching_folder_position(
            &self.accounts[account_index].config.folders,
            &folder_to_show,
        ) {
            self.accounts[account_index].selected_folder = position;
        }

        let current_folder = self.accounts[account_index].current_folder().to_owned();
        let mut loaded_older_count = 0;
        if let Some(synced) = batch
            .synced_folders
            .iter()
            .find(|synced| synced.folder.eq_ignore_ascii_case(current_folder.as_str()))
        {
            let account_state = &mut self.accounts[account_index];
            loaded_older_count = synced.messages.len();
            account_state.messages = if reason == SyncReason::LoadOlder {
                merge_messages_newest_first(&account_state.messages, &synced.messages)
            } else {
                synced.messages.clone()
            };
            if reason != SyncReason::LoadOlder {
                account_state.selected_message = 0;
                account_state.message_scroll = 0;
            }
            account_state.synced_folder = Some(synced.folder.clone());
            account_state.last_sync = Some(synced_at.clone());
            if reason != SyncReason::LoadOlder {
                account_state.message_query.clear();
            }
            if reason == SyncReason::LoadOlder {
                cache::save_folder(
                    &self.cache_root,
                    &account_name,
                    &synced.folder,
                    &synced_at,
                    &account_state.messages,
                )?;
            }
        } else {
            load_cached_folder_into_state(&self.cache_root, &mut self.accounts[account_index]);
        }

        if account_index == self.selected_account
            && matches!(reason, SyncReason::Manual | SyncReason::LoadOlder)
        {
            self.focus = Pane::Messages;
        }

        let current = &self.accounts[account_index];
        self.status = match reason {
            SyncReason::Manual => format!(
                "Synced {} message(s) from {} / {} at {}.",
                current.messages.len(),
                current.config.name,
                current.current_folder(),
                synced_at
            ),
            SyncReason::Auto => format!(
                "Auto-synced {} / {} at {}.",
                current.config.name,
                current.current_folder(),
                synced_at
            ),
            SyncReason::SentCopy => format!(
                "Updated {} / {} after send at {}.",
                current.config.name,
                current.current_folder(),
                synced_at
            ),
            SyncReason::LoadOlder => format!(
                "Loaded {} older message(s) for {} / {}. {} total cached at {}.",
                loaded_older_count,
                current.config.name,
                current.current_folder(),
                current.messages.len(),
                synced_at
            ),
        };
        Ok(())
    }

    fn apply_discovered_folders(&mut self, account_index: usize, folders: &[String]) -> Result<()> {
        if folders.is_empty() {
            return Ok(());
        }

        let account_name = self.accounts[account_index].config.name.clone();
        if self.accounts[account_index].config.folders == folders {
            return Ok(());
        }

        let current_folder = self.accounts[account_index].current_folder().to_owned();
        self.accounts[account_index].config.folders = folders.to_vec();
        self.accounts[account_index].selected_folder =
            matching_folder_position(folders, &current_folder).unwrap_or(0);

        if let Some(config_account) = self
            .config
            .accounts
            .iter_mut()
            .find(|account| account.name == account_name)
        {
            config_account.folders = folders.to_vec();
            self.config.save_to(&self.config_path)?;
        }

        Ok(())
    }

    fn send_current_draft(&mut self) -> Result<()> {
        let account_index = self.selected_account;
        let account = self
            .current_account()
            .map(|account| account.config.clone())
            .ok_or_else(|| anyhow::anyhow!("no account selected"))?;
        let draft = EmailDraft {
            to: self.compose.to.clone(),
            cc: self.compose.cc.clone(),
            bcc: self.compose.bcc.clone(),
            subject: self.compose.subject.clone(),
            body: self.compose.body.clone(),
        };

        let outcome = MailClient::send(&account, &draft)?;

        self.mode = Mode::Normal;
        self.compose = ComposeState::default();
        let refresh_folder = outcome.appended_to.clone();
        self.status = if let Some(error) = outcome.append_error {
            format!(
                "Sent message through {}, but saving the Sent copy failed: {error}",
                account.sender_label()
            )
        } else if let Some(sent_folder) = outcome.appended_to {
            format!(
                "Sent message through {} and saved a copy to {}.",
                account.sender_label(),
                sent_folder
            )
        } else {
            format!("Sent message through {}.", account.sender_label())
        };

        if let Some(sent_folder) = refresh_folder
            && self.sync_job.is_none()
        {
            self.start_sync_for_account(account_index, Some(sent_folder), SyncReason::SentCopy)?;
        }
        Ok(())
    }

    fn save_account_setup(&mut self) -> Result<()> {
        let draft = self.account_setup.to_account_config(&self.config_path)?;
        if self
            .config
            .accounts
            .iter()
            .any(|account| account.name == draft.name)
        {
            anyhow::bail!("an account named '{}' already exists", draft.name);
        }

        if let Some(secret_path) = &draft.password_file {
            write_secret_file(
                &PathBuf::from(secret_path),
                self.account_setup.password.trim(),
            )?;
        }

        self.config.accounts.push(draft.clone());
        if self.config.default_account.is_none() {
            self.config.default_account = Some(draft.name.clone());
        }
        self.config.save_to(&self.config_path)?;

        let new_state = resolve_account_state(&draft)?;
        self.accounts.push(new_state);
        self.selected_account = self.accounts.len().saturating_sub(1);
        self.focus = Pane::Accounts;
        self.mode = Mode::Normal;
        self.account_setup = AccountSetupState::default();
        self.status = match draft.provider.oauth_provider() {
            Some(_) => format!(
                "Saved account {}. Press o or run :authorize-account for OAuth, or s to test password login.",
                draft.name
            ),
            None => format!(
                "Saved account {}. Press s to test login and sync INBOX.",
                draft.name
            ),
        };
        Ok(())
    }

    fn prompt_remove_selected_account(&mut self) -> Result<()> {
        if self.accounts.is_empty() || self.selected_account >= self.accounts.len() {
            anyhow::bail!("no account selected");
        }

        self.mode = Mode::ConfirmDeleteAccount;
        self.confirm_delete = ConfirmDeleteState {
            account_name: self.accounts[self.selected_account].config.name.clone(),
            confirm_selected: false,
        };
        self.status = format!(
            "Confirm removing account {}.",
            self.confirm_delete.account_name
        );
        Ok(())
    }

    fn confirm_remove_selected_account(&mut self) -> Result<()> {
        if self.accounts.is_empty() || self.selected_account >= self.accounts.len() {
            anyhow::bail!("no account selected");
        }

        let removed_name = self.accounts[self.selected_account].config.name.clone();
        let removed_files = self
            .config
            .accounts
            .iter()
            .find(|account| account.name == removed_name)
            .map(AccountConfig::auth_file_paths)
            .unwrap_or_default();

        self.accounts.remove(self.selected_account);
        self.config
            .accounts
            .retain(|account| account.name != removed_name);

        if self.config.default_account.as_deref() == Some(removed_name.as_str()) {
            self.config.default_account = self
                .config
                .accounts
                .first()
                .map(|account| account.name.clone());
        }

        self.config.save_to(&self.config_path)?;

        for path in removed_files {
            if path.exists() {
                fs::remove_file(&path).map_err(|error| {
                    anyhow::anyhow!("failed to remove {}: {error}", path.display())
                })?;
            }
        }
        cache::remove_account(&self.cache_root, &removed_name)?;

        if self.accounts.is_empty() {
            self.selected_account = 0;
            self.focus = Pane::Accounts;
            self.status = format!("Removed account {}. No accounts remain.", removed_name);
        } else {
            self.selected_account = self.selected_account.min(self.accounts.len() - 1);
            self.focus = Pane::Accounts;
            self.status = format!("Removed account {}.", removed_name);
        }

        self.mode = Mode::Normal;
        self.confirm_delete = ConfirmDeleteState::default();

        Ok(())
    }

    fn cancel_remove_selected_account(&mut self) {
        self.mode = Mode::Normal;
        self.status = "Account removal cancelled.".to_owned();
        self.confirm_delete = ConfirmDeleteState::default();
    }

    fn enter_command_mode(&mut self) {
        self.mode = Mode::Command;
        self.command_input.clear();
        self.command_index = 0;
        self.refresh_command_matches();
        self.pending_g = false;
    }

    fn leave_command_mode(&mut self) {
        self.mode = Mode::Normal;
        self.command_input.clear();
        self.command_index = 0;
        self.refresh_command_matches();
    }

    fn enter_compose_mode(&mut self) {
        self.mode = Mode::Compose;
        self.compose = ComposeState::default();
        self.refresh_compose_suggestions();
        self.status = "Compose mode. Tab switches fields, Ctrl-S sends.".to_owned();
    }

    fn enter_reader_mode(&mut self) {
        if self.selected_message().is_none() {
            self.status = "No message selected to open.".to_owned();
            return;
        }

        self.mode = Mode::Reader;
        self.reader_scroll = 0;
        self.status = "Reader mode. Esc/q closes, j/k or mouse wheel scrolls.".to_owned();
    }

    fn enter_account_setup_mode(&mut self) {
        self.mode = Mode::AccountSetup;
        self.account_setup = AccountSetupState::default();
        self.status = "Account setup. Enter IMAP/SMTP credentials, then Ctrl-S to save. Gmail and Outlook can switch to OAuth afterward with o.".to_owned();
    }

    fn enter_account_oauth_mode(&mut self) -> Result<()> {
        let account = self
            .current_account()
            .ok_or_else(|| anyhow::anyhow!("no account selected"))?;
        let account_name = account.config.name.clone();
        let account_email = account.config.email.clone();
        let provider = account.config.provider.oauth_provider().ok_or_else(|| {
            anyhow::anyhow!("OAuth is currently available only for Gmail and Outlook accounts")
        })?;

        let stored_client = self.resolve_oauth_client(provider, &account_name);

        self.mode = Mode::AccountOAuth;
        self.oauth_setup =
            OAuthSetupState::new(account_name.clone(), account_email, provider, stored_client);
        if !self.oauth_setup.client_id.trim().is_empty() {
            self.status = format!(
                "OAuth client for {} is configured. Opening the browser login flow.",
                account_name
            );
            self.start_account_oauth()?;
        } else {
            self.status = format!(
                "OAuth setup for {}. Paste the provider client ID, then Ctrl-S or Enter on Open Browser.",
                account_name
            );
        }
        Ok(())
    }

    fn close_account_oauth(&mut self, status: &str) {
        if let Some(cancellation) = &self.oauth_setup.cancellation {
            cancellation.store(true, Ordering::Relaxed);
        }
        self.mode = Mode::Normal;
        self.oauth_setup = OAuthSetupState::default();
        self.status = status.to_owned();
    }

    fn start_account_oauth(&mut self) -> Result<()> {
        let provider = self
            .oauth_setup
            .provider
            .ok_or_else(|| anyhow::anyhow!("selected account does not support OAuth"))?;
        let client_id = self.oauth_setup.client_id.trim();
        if client_id.is_empty() {
            anyhow::bail!("OAuth client ID is required");
        }

        let request = OAuthAuthorizeRequest {
            provider,
            account_name: self.oauth_setup.account_name.clone(),
            account_email: self.oauth_setup.account_email.clone(),
            client_id: client_id.to_owned(),
            client_secret: non_empty_option(&self.oauth_setup.client_secret),
            data_file: self.oauth_data_path_for(&self.oauth_setup.account_name),
        };
        let (sender, receiver) = mpsc::channel();
        let cancellation = Arc::new(AtomicBool::new(false));
        start_authorize_worker(request, sender, Arc::clone(&cancellation));

        self.oauth_setup.running = true;
        self.oauth_setup.progress_message =
            format!("Starting {} OAuth in your browser...", provider.label());
        self.oauth_setup.auth_url.clear();
        self.oauth_setup.receiver = Some(receiver);
        self.oauth_setup.cancellation = Some(cancellation);
        self.status = self.oauth_setup.progress_message.clone();
        Ok(())
    }

    fn enter_search_mode(&mut self) {
        self.mode = Mode::Search;
        self.focus = Pane::Messages;
        self.status =
            "Search mode. Type to filter the current folder; Enter keeps the filter.".to_owned();
        let visible_count = self.message_visible_count();
        if let Some(account) = self.current_account_mut() {
            account.clamp_selected_message();
            account.sync_message_scroll(visible_count);
        }
    }

    fn poll_oauth_updates(&mut self) {
        let mut updates = Vec::new();
        if let Some(receiver) = &self.oauth_setup.receiver {
            while let Ok(update) = receiver.try_recv() {
                updates.push(update);
            }
        }

        for update in updates {
            match update {
                OAuthAuthorizeUpdate::Progress { message, auth_url } => {
                    self.oauth_setup.progress_message = message.clone();
                    self.oauth_setup.auth_url = auth_url;
                    self.status = message;
                }
                OAuthAuthorizeUpdate::Complete(result) => {
                    self.oauth_setup.running = false;
                    self.oauth_setup.receiver = None;
                    match result {
                        Ok(authorized) => {
                            if let Err(error) = self.finish_account_oauth(authorized) {
                                self.oauth_setup.progress_message = format!("{error:#}");
                                self.status = format!("Error: {error:#}");
                            }
                        }
                        Err(error) => {
                            self.oauth_setup.progress_message = error.clone();
                            self.status = format!("Error: {error}");
                        }
                    }
                }
            }
        }
    }

    fn finish_account_oauth(&mut self, authorized: AuthorizedAccount) -> Result<()> {
        let provider_client = StoredOAuthClient {
            client_id: self.oauth_setup.client_id.trim().to_owned(),
            client_secret: self.oauth_setup.client_secret.trim().to_owned(),
        };
        if !provider_client.client_id.is_empty() {
            save_provider_oauth_client(
                &self.provider_oauth_client_path(authorized.provider),
                &provider_client,
            )?;
        }

        let account = self
            .config
            .accounts
            .iter_mut()
            .find(|account| account.name == authorized.account_name)
            .ok_or_else(|| {
                anyhow::anyhow!("account '{}' no longer exists", authorized.account_name)
            })?;

        let old_files = account.auth_file_paths();
        account.password_env = None;
        account.password_command = None;
        account.password_file = None;
        account.oauth = Some(OAuthConfig {
            provider: authorized.provider,
            data_file: authorized.data_file.display().to_string(),
        });
        self.config.save_to(&self.config_path)?;

        for path in old_files {
            if path != authorized.data_file && path.exists() {
                fs::remove_file(&path).map_err(|error| {
                    anyhow::anyhow!("failed to remove {}: {error}", path.display())
                })?;
            }
        }

        let state_index = self
            .accounts
            .iter()
            .position(|item| item.config.name == authorized.account_name)
            .ok_or_else(|| anyhow::anyhow!("selected account state not found"))?;
        let previous_selected_folder = self.accounts[state_index].selected_folder;
        let previous_selected_message = self.accounts[state_index].selected_message;
        let previous_message_scroll = self.accounts[state_index].message_scroll;
        let previous_synced_folder = self.accounts[state_index].synced_folder.clone();
        let previous_messages = self.accounts[state_index].messages.clone();
        let previous_query = self.accounts[state_index].message_query.clone();
        let previous_last_sync = self.accounts[state_index].last_sync.clone();

        let refreshed = resolve_account_state(
            self.config
                .accounts
                .iter()
                .find(|item| item.name == authorized.account_name)
                .expect("updated account config must exist"),
        )?;

        let account_state = &mut self.accounts[state_index];
        account_state.config = refreshed.config;
        account_state.selected_folder =
            previous_selected_folder.min(account_state.config.folders.len().saturating_sub(1));
        account_state.selected_message = previous_selected_message;
        account_state.message_scroll = previous_message_scroll;
        account_state.synced_folder = previous_synced_folder;
        account_state.messages = previous_messages;
        account_state.message_query = previous_query;
        account_state.last_sync = previous_last_sync;
        account_state.clamp_selected_message();

        let name = authorized.account_name.clone();
        self.mode = Mode::Normal;
        self.oauth_setup = OAuthSetupState::default();
        self.status = format!(
            "Authorized {} with {}. Future sync/send uses OAuth.",
            name,
            authorized.provider.label()
        );
        Ok(())
    }

    fn oauth_data_path_for(&self, account_name: &str) -> PathBuf {
        self.config_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("oauth")
            .join(format!("{}.oauth.toml", slugify(account_name)))
    }

    fn provider_oauth_client_path(&self, provider: OAuthProviderKind) -> PathBuf {
        let file_name = match provider {
            OAuthProviderKind::GoogleMail => "google-client.toml",
            OAuthProviderKind::MicrosoftMail => "microsoft-client.toml",
        };

        self.config_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("oauth")
            .join(file_name)
    }

    fn resolve_oauth_client(
        &self,
        provider: OAuthProviderKind,
        account_name: &str,
    ) -> StoredOAuthClient {
        if let Ok(saved) = load_provider_oauth_client(&self.provider_oauth_client_path(provider)) {
            if !saved.client_id.trim().is_empty() {
                return saved;
            }
        }

        if let Some(config_account) = self
            .config
            .accounts
            .iter()
            .find(|item| item.name == account_name)
            && let Some(oauth) = &config_account.oauth
            && let Ok(saved) = load_saved_oauth_client(&PathBuf::from(&oauth.data_file))
            && !saved.client_id.trim().is_empty()
        {
            return saved;
        }

        if provider == OAuthProviderKind::GoogleMail
            && let Ok(current_dir) = std::env::current_dir()
            && let Ok(Some(client)) = find_google_desktop_oauth_client(&current_dir)
        {
            let _ = save_provider_oauth_client(&self.provider_oauth_client_path(provider), &client);
            return client;
        }

        StoredOAuthClient {
            client_id: String::new(),
            client_secret: String::new(),
        }
    }

    fn move_selection(&mut self, delta: isize) {
        match self.focus {
            Pane::Accounts => self.move_account_selection(delta),
            Pane::Folders => self.move_folder_selection(delta),
            Pane::Messages => self.move_message_selection(delta),
            Pane::Preview => {}
        }
    }

    fn move_to_edge(&mut self, bottom: bool) {
        match self.focus {
            Pane::Accounts => {
                if !self.accounts.is_empty() {
                    self.selected_account = if bottom { self.accounts.len() - 1 } else { 0 };
                }
            }
            Pane::Folders => {
                if let Some(account) = self.current_account_mut() {
                    account.selected_folder = if bottom {
                        account.config.folders.len().saturating_sub(1)
                    } else {
                        0
                    };
                }
                self.load_cached_selected_folder();
            }
            Pane::Messages => {
                let visible_count = self.message_visible_count();
                if let Some(account) = self.current_account_mut() {
                    let count = account.filtered_message_count();
                    if count == 0 {
                        account.selected_message = 0;
                        account.message_scroll = 0;
                    } else if bottom {
                        account.selected_message = count - 1;
                        account.message_scroll = count.saturating_sub(visible_count.max(1));
                    } else {
                        account.selected_message = 0;
                        account.message_scroll = 0;
                    }
                }
            }
            Pane::Preview => {}
        }
    }

    fn move_account_selection(&mut self, delta: isize) {
        if self.accounts.is_empty() {
            return;
        }

        self.selected_account = wrap_index(self.selected_account, self.accounts.len(), delta);
        self.status = format!(
            "Selected account {}.",
            self.current_account()
                .map(|account| account.config.name.as_str())
                .unwrap_or("unknown")
        );
    }

    fn move_folder_selection(&mut self, delta: isize) {
        let mut folder = None;
        if let Some(account) = self.current_account_mut() {
            if account.config.folders.is_empty() {
                return;
            }

            account.selected_folder =
                wrap_index(account.selected_folder, account.config.folders.len(), delta);
            folder = Some(account.current_folder().to_owned());
        }

        if let Some(folder) = folder {
            if self.load_cached_selected_folder() {
                self.status = format!("Loaded cached {folder}. Press s to refresh.");
            } else {
                self.status = format!("Selected folder {folder}. Press s to sync.");
            }
        }
    }

    fn move_message_selection(&mut self, delta: isize) {
        let visible_count = self.message_visible_count();
        if let Some(account) = self.current_account_mut() {
            let count = account.filtered_message_count();
            if count == 0 {
                return;
            }

            account.selected_message = wrap_index(account.selected_message, count, delta);
            account.sync_message_scroll(visible_count);
            self.reader_scroll = 0;
        }
    }

    fn set_folder_selection(&mut self, index: usize) {
        let mut folder = None;
        if let Some(account) = self.current_account_mut() {
            if index >= account.config.folders.len() {
                return;
            }

            account.selected_folder = index;
            folder = Some(account.current_folder().to_owned());
        }

        if let Some(folder) = folder {
            if self.load_cached_selected_folder() {
                self.status = format!("Loaded cached {folder}. Press s to refresh.");
            } else {
                self.status = format!("Selected folder {folder}. Press s to sync.");
            }
        }
    }

    fn set_message_selection(&mut self, index: usize) {
        let visible_count = self.message_visible_count();
        if let Some(account) = self.current_account_mut() {
            if index < account.filtered_message_count() {
                account.selected_message = index;
                account.sync_message_scroll(visible_count);
                self.reader_scroll = 0;
            }
        }
    }

    fn scroll_reader(&mut self, delta: isize, amount: u16) {
        let distance = amount as isize * delta;
        self.reader_scroll = if distance.is_negative() {
            self.reader_scroll
                .saturating_sub(distance.unsigned_abs() as u16)
        } else {
            self.reader_scroll.saturating_add(distance as u16)
        };
    }

    fn refresh_command_matches(&mut self) {
        self.command_matches = search_commands(&self.command_input);
        self.command_index = cmp::min(
            self.command_index,
            self.command_matches.len().saturating_sub(1),
        );
    }

    fn step_command_match(&mut self, delta: isize) {
        if self.command_matches.is_empty() {
            self.command_index = 0;
            return;
        }

        self.command_index = wrap_index(self.command_index, self.command_matches.len(), delta);
    }

    fn current_account(&self) -> Option<&AccountState> {
        self.accounts.get(self.selected_account)
    }

    fn current_account_mut(&mut self) -> Option<&mut AccountState> {
        self.accounts.get_mut(self.selected_account)
    }

    fn load_cached_selected_folder(&mut self) -> bool {
        let Some(account) = self.accounts.get_mut(self.selected_account) else {
            return false;
        };

        load_cached_folder_into_state(&self.cache_root, account)
    }

    fn selected_message(&self) -> Option<&EmailMessage> {
        let account = self.current_account()?;
        let index = *account
            .filtered_message_indices()
            .get(account.selected_message)?;
        account.messages.get(index)
    }

    fn message_visible_count(&self) -> usize {
        let rows = inner_rect(self.hitboxes.messages).height / MESSAGE_ROW_HEIGHT;
        rows.max(1) as usize
    }

    fn message_index_from_click(&self, y: u16) -> Option<usize> {
        let account = self.current_account()?;
        let count = account.filtered_message_count();
        if count == 0 {
            return None;
        }

        let offset = message_scroll_for_selection(
            account.message_scroll,
            account.selected_message,
            count,
            self.message_visible_count(),
        );
        fixed_height_list_index_from_click(
            inner_rect(self.hitboxes.messages),
            y,
            MESSAGE_ROW_HEIGHT,
            offset,
            count,
        )
    }

    fn account_row_heights(&self) -> Vec<u16> {
        self.accounts
            .iter()
            .map(|account| {
                let mut height = if account.last_sync.is_some() { 4 } else { 3 };
                if self
                    .sync_job
                    .as_ref()
                    .is_some_and(|job| job.account_name == account.config.name)
                {
                    height += 1;
                }
                height
            })
            .collect()
    }

    fn current_compose_field_mut(&mut self) -> &mut String {
        match self.compose.field {
            ComposeField::To => &mut self.compose.to,
            ComposeField::Cc => &mut self.compose.cc,
            ComposeField::Bcc => &mut self.compose.bcc,
            ComposeField::Subject => &mut self.compose.subject,
            ComposeField::Body => &mut self.compose.body,
        }
    }

    fn current_compose_field(&self) -> &str {
        match self.compose.field {
            ComposeField::To => &self.compose.to,
            ComposeField::Cc => &self.compose.cc,
            ComposeField::Bcc => &self.compose.bcc,
            ComposeField::Subject => &self.compose.subject,
            ComposeField::Body => &self.compose.body,
        }
    }

    fn mode_label(&self) -> &'static str {
        match self.mode {
            Mode::Normal => "normal",
            Mode::Command => "command",
            Mode::Compose => "compose",
            Mode::Reader => "reader",
            Mode::Search => "search",
            Mode::AccountSetup => "account-setup",
            Mode::AccountOAuth => "account-oauth",
            Mode::ConfirmDeleteAccount => "confirm-delete",
        }
    }

    fn current_message_query(&self) -> &str {
        self.current_account()
            .map(|account| account.message_query.as_str())
            .unwrap_or("")
    }

    fn message_title(&self) -> String {
        let query = self.current_message_query();
        if query.is_empty() {
            "Messages".to_owned()
        } else {
            format!("Messages /{query}")
        }
    }

    fn pane_block<'a>(&self, title: &'a str, pane: Pane) -> Block<'a> {
        let accent = pane_accent(pane);
        let border_style = if self.focus == pane && self.mode == Mode::Normal {
            Style::new().fg(accent).add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(Color::Rgb(71, 85, 105))
        };

        Block::default()
            .title(Line::from(title).style(Style::new().fg(accent).add_modifier(Modifier::BOLD)))
            .borders(Borders::ALL)
            .border_style(border_style)
            .style(panel_style())
    }

    fn draw_address_suggestions(&self, frame: &mut Frame, area: Rect) {
        let items = if !self.compose.field.is_address() {
            vec![ListItem::new(
                "Suggestions appear for To / Cc / Bcc fields.",
            )]
        } else if self.compose.suggestions.is_empty() {
            vec![ListItem::new(
                "No matches yet. Sync mail to build richer suggestions.",
            )]
        } else {
            self.compose
                .suggestions
                .iter()
                .map(|suggestion| ListItem::new(suggestion.clone()))
                .collect()
        };

        let list = List::new(items)
            .block(
                Block::default()
                    .title("Address Suggestions")
                    .borders(Borders::ALL)
                    .border_style(
                        Style::new()
                            .fg(Color::Rgb(96, 165, 250))
                            .add_modifier(Modifier::BOLD),
                    )
                    .style(popup_style()),
            )
            .highlight_style(selected_style())
            .highlight_symbol("▸ ");
        let mut state = ListState::default();
        if self.compose.field.is_address() && !self.compose.suggestions.is_empty() {
            state.select(Some(self.compose.suggestion_index));
        }
        frame.render_stateful_widget(list, area, &mut state);
    }

    fn refresh_compose_suggestions(&mut self) {
        if !self.compose.field.is_address() {
            self.compose.suggestions.clear();
            self.compose.suggestion_index = 0;
            return;
        }

        let query = current_address_query(self.current_compose_field());
        let matcher = SkimMatcherV2::default().ignore_case();
        let mut scored = self
            .address_candidates()
            .into_iter()
            .filter_map(|candidate| {
                let score = if query.is_empty() {
                    Some(0)
                } else {
                    matcher.fuzzy_match(&candidate, query)
                }?;
                Some((score, candidate))
            })
            .collect::<Vec<_>>();

        scored.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
        self.compose.suggestions = scored.into_iter().take(8).map(|(_, value)| value).collect();
        self.compose.suggestion_index = cmp::min(
            self.compose.suggestion_index,
            self.compose.suggestions.len().saturating_sub(1),
        );
    }

    fn address_candidates(&self) -> Vec<String> {
        let mut seen = BTreeSet::new();
        let mut candidates = Vec::new();

        for account in &self.accounts {
            push_candidate(&mut seen, &mut candidates, account.config.sender_label());
            push_candidate(&mut seen, &mut candidates, account.config.email.clone());

            for message in &account.messages {
                push_candidate(&mut seen, &mut candidates, message.from.clone());
            }
        }

        candidates
    }

    fn step_compose_suggestion(&mut self, delta: isize) {
        if !self.compose.field.is_address() || self.compose.suggestions.is_empty() {
            return;
        }

        self.compose.suggestion_index = wrap_index(
            self.compose.suggestion_index,
            self.compose.suggestions.len(),
            delta,
        );
    }

    fn accept_compose_suggestion(&mut self) {
        let Some(suggestion) = self
            .compose
            .suggestions
            .get(self.compose.suggestion_index)
            .cloned()
        else {
            return;
        };

        let updated = apply_address_suggestion(self.current_compose_field(), &suggestion);
        *self.current_compose_field_mut() = updated;
        self.refresh_compose_suggestions();
    }
}

impl Pane {
    fn next(self) -> Self {
        match self {
            Pane::Accounts => Pane::Folders,
            Pane::Folders => Pane::Messages,
            Pane::Messages => Pane::Preview,
            Pane::Preview => Pane::Accounts,
        }
    }

    fn previous(self) -> Self {
        match self {
            Pane::Accounts => Pane::Preview,
            Pane::Folders => Pane::Accounts,
            Pane::Messages => Pane::Folders,
            Pane::Preview => Pane::Messages,
        }
    }
}

impl AccountState {
    fn current_folder(&self) -> &str {
        self.config
            .folders
            .get(self.selected_folder)
            .map(String::as_str)
            .unwrap_or("INBOX")
    }

    fn clear_messages(&mut self) {
        self.messages.clear();
        self.selected_message = 0;
        self.message_scroll = 0;
        self.synced_folder = None;
        self.message_query.clear();
        self.last_sync = None;
    }

    fn filtered_message_indices(&self) -> Vec<usize> {
        if self.message_query.trim().is_empty() {
            return (0..self.messages.len()).collect();
        }

        let query = self.message_query.to_ascii_lowercase();
        self.messages
            .iter()
            .enumerate()
            .filter_map(|(index, message)| {
                let haystack = format!(
                    "{}\n{}\n{}\n{}\n{}",
                    message.subject, message.from, message.preview, message.body, message.date
                );
                haystack
                    .to_ascii_lowercase()
                    .contains(&query)
                    .then_some(index)
            })
            .collect()
    }

    fn filtered_message_count(&self) -> usize {
        self.filtered_message_indices().len()
    }

    fn clamp_selected_message(&mut self) {
        let count = self.filtered_message_count();
        if count == 0 {
            self.selected_message = 0;
            self.message_scroll = 0;
        } else if self.selected_message >= count {
            self.selected_message = count - 1;
        }
    }

    fn sync_message_scroll(&mut self, visible_count: usize) {
        self.message_scroll = message_scroll_for_selection(
            self.message_scroll,
            self.selected_message,
            self.filtered_message_count(),
            visible_count,
        );
    }
}

impl ComposeField {
    fn is_address(self) -> bool {
        matches!(
            self,
            ComposeField::To | ComposeField::Cc | ComposeField::Bcc
        )
    }

    fn next(self) -> Self {
        match self {
            ComposeField::To => ComposeField::Cc,
            ComposeField::Cc => ComposeField::Bcc,
            ComposeField::Bcc => ComposeField::Subject,
            ComposeField::Subject => ComposeField::Body,
            ComposeField::Body => ComposeField::To,
        }
    }

    fn previous(self) -> Self {
        match self {
            ComposeField::To => ComposeField::Body,
            ComposeField::Cc => ComposeField::To,
            ComposeField::Bcc => ComposeField::Cc,
            ComposeField::Subject => ComposeField::Bcc,
            ComposeField::Body => ComposeField::Subject,
        }
    }
}

impl Default for AccountSetupState {
    fn default() -> Self {
        Self {
            provider_index: 0,
            provider_dropdown_open: false,
            provider_dropdown_index: 0,
            name: String::new(),
            email: String::new(),
            login: String::new(),
            display_name: String::new(),
            password: String::new(),
            show_password: false,
            imap_host: String::new(),
            imap_port: "993".to_owned(),
            smtp_host: String::new(),
            smtp_port: "587".to_owned(),
            tls_mode: SmtpTlsMode::Starttls,
            field: SetupField::Provider,
        }
    }
}

impl Default for OAuthSetupState {
    fn default() -> Self {
        Self {
            account_name: String::new(),
            account_email: String::new(),
            provider: None,
            client_id: String::new(),
            client_secret: String::new(),
            show_client_secret: false,
            field: OAuthField::ClientId,
            running: false,
            progress_message: String::new(),
            auth_url: String::new(),
            receiver: None,
            cancellation: None,
        }
    }
}

impl AccountSetupState {
    fn password_display(&self) -> String {
        if self.show_password {
            self.password.clone()
        } else {
            mask_secret(&self.password)
        }
    }

    fn provider(&self) -> ProviderKind {
        ProviderKind::ALL[self.provider_index]
    }

    fn open_provider_dropdown(&mut self) {
        self.field = SetupField::Provider;
        self.provider_dropdown_open = true;
        self.provider_dropdown_index = self.provider_index;
    }

    fn close_provider_dropdown(&mut self) {
        self.provider_dropdown_open = false;
    }

    fn step_dropdown(&mut self, delta: isize) {
        if self.provider_dropdown_open {
            self.provider_dropdown_index =
                wrap_index(self.provider_dropdown_index, ProviderKind::ALL.len(), delta);
        }
    }

    fn select_provider_dropdown(&mut self) {
        if self.provider_dropdown_open {
            self.provider_index = self.provider_dropdown_index;
            self.provider_dropdown_open = false;
            self.ensure_visible_field();
        }
    }

    fn next_field(&mut self) {
        self.close_provider_dropdown();
        let fields = self.visible_fields();
        let position = fields
            .iter()
            .position(|field| *field == self.field)
            .unwrap_or(0);
        self.field = fields[(position + 1) % fields.len()];
    }

    fn previous_field(&mut self) {
        self.close_provider_dropdown();
        let fields = self.visible_fields();
        let position = fields
            .iter()
            .position(|field| *field == self.field)
            .unwrap_or(0);
        self.field = fields[(position + fields.len() - 1) % fields.len()];
    }

    fn visible_fields(&self) -> Vec<SetupField> {
        let mut fields = vec![
            SetupField::Provider,
            SetupField::Name,
            SetupField::Email,
            SetupField::Login,
            SetupField::DisplayName,
            SetupField::Password,
        ];

        if self.provider().requires_custom_servers() {
            fields.extend([
                SetupField::ImapHost,
                SetupField::ImapPort,
                SetupField::SmtpHost,
                SetupField::SmtpPort,
                SetupField::TlsMode,
            ]);
        }

        fields
    }

    fn step_selector(&mut self, delta: isize) {
        match self.field {
            SetupField::Provider => {
                self.provider_index =
                    wrap_index(self.provider_index, ProviderKind::ALL.len(), delta);
                self.provider_dropdown_index = self.provider_index;
                self.ensure_visible_field();
            }
            SetupField::TlsMode if self.provider().requires_custom_servers() => {
                let current = SmtpTlsMode::ALL
                    .iter()
                    .position(|mode| *mode == self.tls_mode)
                    .unwrap_or(0);
                let next = wrap_index(current, SmtpTlsMode::ALL.len(), delta);
                self.tls_mode = SmtpTlsMode::ALL[next];
            }
            _ => {}
        }
    }

    fn ensure_visible_field(&mut self) {
        if !self.visible_fields().contains(&self.field) {
            self.field = SetupField::Provider;
        }
    }

    fn push_char(&mut self, ch: char) {
        self.close_provider_dropdown();
        match self.field {
            SetupField::Provider | SetupField::TlsMode => {}
            SetupField::Name => self.name.push(ch),
            SetupField::Email => self.email.push(ch),
            SetupField::Login => self.login.push(ch),
            SetupField::DisplayName => self.display_name.push(ch),
            SetupField::Password => self.password.push(ch),
            SetupField::ImapHost if self.provider().requires_custom_servers() => {
                self.imap_host.push(ch)
            }
            SetupField::ImapPort if self.provider().requires_custom_servers() => {
                self.imap_port.push(ch)
            }
            SetupField::SmtpHost if self.provider().requires_custom_servers() => {
                self.smtp_host.push(ch)
            }
            SetupField::SmtpPort if self.provider().requires_custom_servers() => {
                self.smtp_port.push(ch)
            }
            _ => {}
        }
    }

    fn backspace(&mut self) {
        self.close_provider_dropdown();
        match self.field {
            SetupField::Provider | SetupField::TlsMode => {}
            SetupField::Name => {
                self.name.pop();
            }
            SetupField::Email => {
                self.email.pop();
            }
            SetupField::Login => {
                self.login.pop();
            }
            SetupField::DisplayName => {
                self.display_name.pop();
            }
            SetupField::Password => {
                self.password.pop();
            }
            SetupField::ImapHost if self.provider().requires_custom_servers() => {
                self.imap_host.pop();
            }
            SetupField::ImapPort if self.provider().requires_custom_servers() => {
                self.imap_port.pop();
            }
            SetupField::SmtpHost if self.provider().requires_custom_servers() => {
                self.smtp_host.pop();
            }
            SetupField::SmtpPort if self.provider().requires_custom_servers() => {
                self.smtp_port.pop();
            }
            _ => {}
        }
    }

    fn to_account_config(&self, config_path: &PathBuf) -> Result<AccountConfig> {
        let name = self.name.trim();
        let email = self.email.trim();
        let password = self.password.trim();
        if name.is_empty() {
            anyhow::bail!("account name is required");
        }
        if email.is_empty() {
            anyhow::bail!("email is required");
        }
        if password.is_empty() {
            anyhow::bail!("password or app password is required");
        }

        let provider = self.provider();
        let secret_dir = config_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("secrets");
        let secret_file = secret_dir.join(format!("{}.secret", slugify(name)));

        let (imap, smtp) = if provider.requires_custom_servers() {
            let imap_host = self.imap_host.trim();
            let smtp_host = self.smtp_host.trim();
            if imap_host.is_empty() {
                anyhow::bail!("custom provider needs an IMAP host");
            }
            if smtp_host.is_empty() {
                anyhow::bail!("custom provider needs an SMTP host");
            }

            let imap_port = self
                .imap_port
                .trim()
                .parse::<u16>()
                .map_err(|_| anyhow::anyhow!("IMAP port must be a valid number"))?;
            let smtp_port = self
                .smtp_port
                .trim()
                .parse::<u16>()
                .map_err(|_| anyhow::anyhow!("SMTP port must be a valid number"))?;

            (
                Some(ImapOverride {
                    host: Some(imap_host.to_owned()),
                    port: Some(imap_port),
                }),
                Some(SmtpOverride {
                    host: Some(smtp_host.to_owned()),
                    port: Some(smtp_port),
                    tls_mode: Some(self.tls_mode),
                }),
            )
        } else {
            (None, None)
        };

        Ok(AccountConfig {
            name: name.to_owned(),
            provider,
            email: email.to_owned(),
            login: non_empty_option(&self.login),
            display_name: non_empty_option(&self.display_name),
            folders: vec![],
            password_env: None,
            password_command: None,
            password_file: Some(secret_file.display().to_string()),
            oauth: None,
            imap,
            smtp,
        })
    }
}

impl OAuthSetupState {
    fn new(
        account_name: String,
        account_email: String,
        provider: OAuthProviderKind,
        stored_client: StoredOAuthClient,
    ) -> Self {
        Self {
            account_name,
            account_email,
            provider: Some(provider),
            client_id: stored_client.client_id,
            client_secret: stored_client.client_secret,
            show_client_secret: false,
            field: OAuthField::ClientId,
            running: false,
            progress_message: String::new(),
            auth_url: String::new(),
            receiver: None,
            cancellation: None,
        }
    }

    fn next_field(&mut self) {
        self.field = match self.field {
            OAuthField::ClientId => OAuthField::ClientSecret,
            OAuthField::ClientSecret => OAuthField::Start,
            OAuthField::Start => OAuthField::Cancel,
            OAuthField::Cancel => OAuthField::ClientId,
        };
    }

    fn previous_field(&mut self) {
        self.field = match self.field {
            OAuthField::ClientId => OAuthField::Cancel,
            OAuthField::ClientSecret => OAuthField::ClientId,
            OAuthField::Start => OAuthField::ClientSecret,
            OAuthField::Cancel => OAuthField::Start,
        };
    }

    fn push_char(&mut self, ch: char) {
        match self.field {
            OAuthField::ClientId => self.client_id.push(ch),
            OAuthField::ClientSecret => self.client_secret.push(ch),
            OAuthField::Start | OAuthField::Cancel => {}
        }
    }

    fn backspace(&mut self) {
        match self.field {
            OAuthField::ClientId => {
                self.client_id.pop();
            }
            OAuthField::ClientSecret => {
                self.client_secret.pop();
            }
            OAuthField::Start | OAuthField::Cancel => {}
        }
    }

    fn client_secret_display(&self) -> String {
        if self.show_client_secret {
            self.client_secret.clone()
        } else {
            mask_secret(&self.client_secret)
        }
    }
}

fn resolve_accounts(config: &AppConfig) -> Result<(Vec<AccountState>, usize)> {
    let accounts = config
        .accounts
        .iter()
        .map(resolve_account_state)
        .collect::<Result<Vec<_>>>()?;
    let default_index = config
        .default_account
        .as_ref()
        .and_then(|name| {
            accounts
                .iter()
                .position(|account| &account.config.name == name)
        })
        .unwrap_or(0);
    Ok((accounts, default_index))
}

fn resolve_account_state(account: &AccountConfig) -> Result<AccountState> {
    Ok(AccountState {
        config: account.resolve()?,
        selected_folder: 0,
        selected_message: 0,
        message_scroll: 0,
        synced_folder: None,
        messages: Vec::new(),
        message_query: String::new(),
        last_sync: None,
    })
}

fn load_cached_folder_into_state(cache_root: &PathBuf, account: &mut AccountState) -> bool {
    let account_name = account.config.name.clone();
    let folder = account.current_folder().to_owned();

    match cache::load_folder(cache_root, &account_name, &folder) {
        Ok(Some(cached)) => {
            account.messages = cached.messages;
            account.selected_message = 0;
            account.message_scroll = 0;
            account.synced_folder = Some(cached.folder);
            account.message_query.clear();
            account.last_sync = Some(cached.last_sync);
            true
        }
        Ok(None) | Err(_) => {
            account.clear_messages();
            false
        }
    }
}

fn wrap_index(current: usize, len: usize, delta: isize) -> usize {
    if len == 0 {
        return 0;
    }

    let len = len as isize;
    let current = current as isize;
    let next = (current + delta).rem_euclid(len);
    next as usize
}

fn selected_style() -> Style {
    Style::new()
        .fg(Color::Rgb(15, 23, 42))
        .bg(Color::Rgb(42, 157, 143))
        .add_modifier(Modifier::BOLD)
}

fn field_block<'a>(title: &'a str, active: bool) -> Block<'a> {
    let border_style = if active {
        Style::new()
            .fg(Color::Rgb(233, 196, 106))
            .add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(Color::Rgb(71, 85, 105))
    };

    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(border_style)
        .style(popup_style())
}

fn setup_field_block<'a>(title: &'a str, active: bool, enabled: bool) -> Block<'a> {
    let border_style = if active && enabled {
        Style::new()
            .fg(Color::Rgb(233, 196, 106))
            .add_modifier(Modifier::BOLD)
    } else if enabled {
        Style::new().fg(Color::Rgb(71, 85, 105))
    } else {
        Style::new().fg(Color::Rgb(51, 65, 85))
    };

    let style = if enabled {
        popup_style()
    } else {
        popup_style().fg(Color::Rgb(100, 116, 139))
    };

    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(border_style)
        .style(style)
}

fn confirm_block(selected: bool) -> Block<'static> {
    let border_style = if selected {
        Style::new()
            .fg(Color::Rgb(244, 162, 97))
            .add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(Color::Rgb(71, 85, 105))
    };

    Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .style(popup_style())
}

fn reader_block(title: &str) -> Block<'_> {
    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(
            Style::new()
                .fg(Color::Rgb(96, 165, 250))
                .add_modifier(Modifier::BOLD),
        )
        .style(reader_style())
}

fn message_text(message: &EmailMessage, full: bool) -> Text<'static> {
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                "Subject: ",
                Style::new()
                    .fg(Color::Rgb(250, 204, 21))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                message.subject.clone(),
                Style::new()
                    .fg(Color::Rgb(255, 247, 237))
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "From: ",
                Style::new()
                    .fg(Color::Rgb(94, 234, 212))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                message.from.clone(),
                Style::new().fg(Color::Rgb(204, 251, 241)),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "Date: ",
                Style::new()
                    .fg(Color::Rgb(125, 211, 252))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                message.date.clone(),
                Style::new().fg(Color::Rgb(186, 230, 253)),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "UID: ",
                Style::new()
                    .fg(Color::Rgb(244, 162, 97))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                message.uid.to_string(),
                Style::new().fg(Color::Rgb(254, 215, 170)),
            ),
        ]),
        Line::from(""),
    ];

    if full {
        lines.push(
            Line::from("Message").style(
                Style::new()
                    .fg(Color::Rgb(233, 196, 106))
                    .add_modifier(Modifier::BOLD),
            ),
        );
        lines.push(Line::from(""));
    }

    for raw in message.body.lines() {
        lines.push(style_body_line(raw));
    }

    Text::from(lines)
}

fn style_body_line(raw: &str) -> Line<'static> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Line::from("");
    }

    if trimmed.starts_with('>') {
        return Line::from(raw.to_owned()).style(
            Style::new()
                .fg(Color::Rgb(134, 239, 172))
                .add_modifier(Modifier::ITALIC),
        );
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("unsubscribe") || lower.contains("privacy policy") {
        return Line::from(raw.to_owned()).style(Style::new().fg(Color::Rgb(100, 116, 139)));
    }

    if lower.contains("urgent")
        || lower.contains("warning")
        || lower.contains("security")
        || lower.contains("verify")
    {
        return Line::from(link_spans(raw, Style::new().fg(Color::Rgb(254, 226, 226)))).style(
            Style::new()
                .fg(Color::Rgb(254, 226, 226))
                .bg(Color::Rgb(127, 29, 29)),
        );
    }

    if looks_like_heading(trimmed) {
        return Line::from(raw.to_owned()).style(
            Style::new()
                .fg(Color::Rgb(253, 230, 138))
                .add_modifier(Modifier::BOLD),
        );
    }

    let base = if trimmed.starts_with('-') || trimmed.starts_with('*') {
        Style::new().fg(Color::Rgb(226, 232, 240))
    } else {
        Style::new().fg(Color::Rgb(203, 213, 225))
    };

    Line::from(link_spans(raw, base))
}

fn link_spans(raw: &str, base: Style) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let mut first = true;

    for token in raw.split_whitespace() {
        if !first {
            spans.push(Span::raw(" "));
        }
        first = false;

        let style = if token.starts_with("http://")
            || token.starts_with("https://")
            || token.starts_with("mailto:")
        {
            Style::new()
                .fg(Color::Rgb(56, 189, 248))
                .add_modifier(Modifier::UNDERLINED)
        } else {
            base
        };
        push_breakable_token_spans(&mut spans, token, style);
    }

    spans
}

fn push_breakable_token_spans(spans: &mut Vec<Span<'static>>, token: &str, style: Style) {
    if token.chars().count() <= LONG_TOKEN_BREAK_CHARS {
        spans.push(Span::styled(token.to_owned(), style));
        return;
    }

    let mut chunk = String::new();
    for ch in token.chars() {
        chunk.push(ch);
        if chunk.chars().count() >= LONG_TOKEN_BREAK_CHARS {
            spans.push(Span::styled(std::mem::take(&mut chunk), style));
            spans.push(Span::raw(" "));
        }
    }

    if !chunk.is_empty() {
        spans.push(Span::styled(chunk, style));
    } else if spans.last().is_some_and(|span| span.content == " ") {
        spans.pop();
    }
}

fn looks_like_heading(trimmed: &str) -> bool {
    let len = trimmed.chars().count();
    len <= 72
        && len > 3
        && !trimmed.ends_with('.')
        && !trimmed.ends_with(',')
        && !trimmed.contains("://")
        && (trimmed.starts_with('#')
            || trimmed.chars().any(char::is_alphabetic)
                && trimmed.chars().filter(|ch| ch.is_uppercase()).count() >= 2)
}

fn truncate_title(raw: &str, max_chars: usize) -> String {
    if raw.chars().count() <= max_chars {
        return raw.to_owned();
    }

    let mut out = raw
        .chars()
        .take(max_chars.saturating_sub(3))
        .collect::<String>();
    out.push_str("...");
    out
}

fn rect_contains(rect: Rect, x: u16, y: u16) -> bool {
    x >= rect.x
        && x < rect.x.saturating_add(rect.width)
        && y >= rect.y
        && y < rect.y.saturating_add(rect.height)
}

fn inner_rect(rect: Rect) -> Rect {
    Rect {
        x: rect.x.saturating_add(1),
        y: rect.y.saturating_add(1),
        width: rect.width.saturating_sub(2),
        height: rect.height.saturating_sub(2),
    }
}

fn list_index_from_click(inner: Rect, y: u16, item_heights: &[u16]) -> Option<usize> {
    if !rect_contains(inner, inner.x, y) || y < inner.y {
        return None;
    }

    let mut cursor = inner.y;
    for (index, height) in item_heights.iter().enumerate() {
        let next = cursor.saturating_add(*height);
        if y >= cursor && y < next && y < inner.y.saturating_add(inner.height) {
            return Some(index);
        }
        cursor = next;
        if cursor >= inner.y.saturating_add(inner.height) {
            break;
        }
    }

    None
}

fn fixed_height_list_index_from_click(
    inner: Rect,
    y: u16,
    item_height: u16,
    offset: usize,
    total: usize,
) -> Option<usize> {
    if item_height == 0 || total == 0 || !rect_contains(inner, inner.x, y) || y < inner.y {
        return None;
    }

    let visible_index = (y - inner.y) / item_height;
    let index = offset.saturating_add(visible_index as usize);
    (index < total).then_some(index)
}

fn message_scroll_for_selection(
    scroll: usize,
    selected: usize,
    total: usize,
    visible_count: usize,
) -> usize {
    if total == 0 {
        return 0;
    }

    let visible_count = visible_count.max(1);
    let selected = selected.min(total - 1);
    let max_scroll = total.saturating_sub(visible_count);
    let scroll = scroll.min(max_scroll);

    if selected < scroll {
        selected
    } else if selected >= scroll.saturating_add(visible_count) {
        selected.saturating_add(1).saturating_sub(visible_count)
    } else {
        scroll
    }
}

fn mask_secret(secret: &str) -> String {
    if secret.is_empty() {
        String::new()
    } else {
        "*".repeat(secret.chars().count())
    }
}

fn current_address_query(raw: &str) -> &str {
    raw.rsplit(',').next().map(str::trim).unwrap_or("")
}

fn apply_address_suggestion(existing: &str, suggestion: &str) -> String {
    let prefix = existing.rsplit_once(',').map(|(head, _)| head.trim());
    match prefix {
        Some(head) if !head.is_empty() => format!("{head}, {suggestion}, "),
        _ => format!("{suggestion}, "),
    }
}

fn push_candidate(seen: &mut BTreeSet<String>, out: &mut Vec<String>, candidate: String) {
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        return;
    }

    let key = trimmed.to_ascii_lowercase();
    if seen.insert(key) {
        out.push(trimmed.to_owned());
    }
}

fn non_empty_option(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn matching_folder_position(folders: &[String], requested: &str) -> Option<usize> {
    folders
        .iter()
        .position(|folder| folder.eq_ignore_ascii_case(requested))
        .or_else(|| {
            let requested_role = special_folder_role(requested)?;
            folders
                .iter()
                .position(|folder| special_folder_role(folder) == Some(requested_role))
        })
}

fn sync_reason_label(reason: SyncReason) -> &'static str {
    match reason {
        SyncReason::Manual => "sync",
        SyncReason::Auto => "auto",
        SyncReason::SentCopy => "sent",
        SyncReason::LoadOlder => "older",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpecialFolderRole {
    Inbox,
    Sent,
    Drafts,
    Archive,
    Trash,
}

fn special_folder_role(folder: &str) -> Option<SpecialFolderRole> {
    let lower = folder.to_ascii_lowercase();
    let leaf = lower
        .rsplit(['/', '.', '\\'])
        .next()
        .unwrap_or(lower.as_str())
        .trim();

    if lower == "inbox" || leaf == "inbox" {
        Some(SpecialFolderRole::Inbox)
    } else if leaf.contains("sent") || lower.contains("/sent") || lower.contains("\\sent") {
        Some(SpecialFolderRole::Sent)
    } else if leaf.contains("draft") {
        Some(SpecialFolderRole::Drafts)
    } else if leaf.contains("archive") || leaf == "all mail" || lower.ends_with("/all mail") {
        Some(SpecialFolderRole::Archive)
    } else if leaf.contains("trash") || leaf.contains("deleted") || leaf == "bin" {
        Some(SpecialFolderRole::Trash)
    } else {
        None
    }
}

fn slugify(raw: &str) -> String {
    let slug = raw
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' => ch.to_ascii_lowercase(),
            _ => '-',
        })
        .collect::<String>();
    let trimmed = slug.trim_matches('-');
    if trimmed.is_empty() {
        "account".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .areas(area);
    let [_, middle, _] = vertical;

    let horizontal = Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .areas(middle);
    let [_, center, _] = horizontal;
    center
}

fn pane_accent(pane: Pane) -> Color {
    match pane {
        Pane::Accounts => Color::Rgb(96, 165, 250),
        Pane::Folders => Color::Rgb(42, 157, 143),
        Pane::Messages => Color::Rgb(233, 196, 106),
        Pane::Preview => Color::Rgb(244, 162, 97),
    }
}

fn app_background_style() -> Style {
    Style::new()
        .bg(Color::Rgb(15, 23, 42))
        .fg(Color::Rgb(226, 232, 240))
}

fn panel_style() -> Style {
    Style::new()
        .bg(Color::Rgb(17, 24, 39))
        .fg(Color::Rgb(226, 232, 240))
}

fn popup_style() -> Style {
    Style::new()
        .bg(Color::Rgb(11, 18, 32))
        .fg(Color::Rgb(241, 245, 249))
}

fn reader_style() -> Style {
    Style::new()
        .bg(Color::Rgb(8, 13, 24))
        .fg(Color::Rgb(226, 232, 240))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_scroll_stays_when_selection_moves_inside_view() {
        assert_eq!(message_scroll_for_selection(10, 12, 100, 5), 10);
    }

    #[test]
    fn message_scroll_moves_only_after_selection_crosses_top_boundary() {
        assert_eq!(message_scroll_for_selection(10, 10, 100, 5), 10);
        assert_eq!(message_scroll_for_selection(10, 9, 100, 5), 9);
    }

    #[test]
    fn message_scroll_moves_only_after_selection_crosses_bottom_boundary() {
        assert_eq!(message_scroll_for_selection(10, 14, 100, 5), 10);
        assert_eq!(message_scroll_for_selection(10, 15, 100, 5), 11);
    }

    #[test]
    fn message_scroll_clamps_when_message_count_shrinks() {
        assert_eq!(message_scroll_for_selection(30, 30, 12, 5), 7);
        assert_eq!(message_scroll_for_selection(30, 30, 0, 5), 0);
    }
}
