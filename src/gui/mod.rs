//! Iced desktop interface.

mod style;
mod view;

use std::sync::Arc;
use std::time::{Duration, Instant};

use iced::widget::text_editor;
use iced::futures::SinkExt;
use iced::{Size, Subscription, Task};

use crate::apikeys::{ApiKey, Role};
use crate::config::Config;
use crate::core::blocklist::BlockRecord;
use crate::core::checker::{render_text, CheckOptions, KeyReport};
use crate::core::key::ProductKey;
use crate::server::{self, ServerHandle};
use crate::system::{self, InstalledLicense, Target};
use crate::Services;

pub fn run(config: Config) -> anyhow::Result<()> {
    iced::application(move || App::new(config.clone()), App::update, App::view)
        .title(|app: &App| match &app.server {
            Some(h) => format!("PID Key Checker {} — API on {}", env!("CARGO_PKG_VERSION"), h.addr),
            None => format!("PID Key Checker {}", env!("CARGO_PKG_VERSION")),
        })
        .theme(|_: &App| style::theme())
        .subscription(App::subscription)
        .default_font(style::ui_font())
        .window(iced::window::Settings {
            size: Size::new(980.0, 600.0),
            min_size: Some(Size::new(980.0, 600.0)),
            icon: style::window_icon(),
            ..Default::default()
        })
        .centered()
        .run()
        .map_err(|e| anyhow::anyhow!("{e}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Check,
    Batch,
    Blocklist,
    System,
    Server,
    ApiKeys,
    About,
}

impl Page {
    pub const ALL: [(Page, &'static str, char); 7] = [
        (Page::Check, "Key Checker", style::icon::KEY),
        (Page::Batch, "Batch Check", style::icon::LIST),
        (Page::Blocklist, "Blocked Keys", style::icon::SHIELD),
        (Page::System, "This PC", style::icon::PC),
        (Page::Server, "Server & Settings", style::icon::SERVER),
        (Page::ApiKeys, "API Keys", style::icon::LOCK),
        (Page::About, "About", style::icon::INFO),
    ];
}

/// Editable copy of the server settings as text fields.
#[derive(Debug, Clone, Default)]
pub struct ServerForm {
    pub host: String,
    pub port: String,
    pub max_batch: String,
    pub rpm: String,
    pub burst: String,
    pub rate_limit: bool,
    pub require_auth: bool,
    pub cors: bool,
    pub autostart: bool,
    pub online_check: bool,
    pub record_blocked: bool,
    pub record_revoked: bool,
    pub cache_enabled: bool,
    pub cache_ttl: String,
    pub cache_max: String,
}

impl ServerForm {
    fn from_config(c: &Config) -> Self {
        Self {
            host: c.server.host.clone(),
            port: c.server.port.to_string(),
            max_batch: c.checker.max_batch_size.to_string(),
            rpm: c.rate_limit.requests_per_minute.to_string(),
            burst: c.rate_limit.burst.to_string(),
            rate_limit: c.rate_limit.enabled,
            require_auth: c.api.require_auth,
            cors: c.server.cors,
            autostart: c.server.autostart,
            online_check: c.checker.online_check,
            record_blocked: c.checker.record_blocked,
            record_revoked: c.checker.record_revoked,
            cache_enabled: c.checker.cache_enabled,
            cache_ttl: c.checker.cache_ttl_secs.to_string(),
            cache_max: c.checker.cache_max_entries.to_string(),
        }
    }

    fn apply(&self, c: &mut Config) -> Result<(), String> {
        let num = |s: &str, name: &str| s.trim().parse::<u64>().map_err(|_| format!("{name} must be a number"));
        c.server.host = self.host.trim().to_string();
        c.server.port = num(&self.port, "Port")?.try_into().map_err(|_| "Port must be 1-65535".to_string())?;
        c.checker.max_batch_size = num(&self.max_batch, "Max batch size")?.max(1) as usize;
        c.rate_limit.requests_per_minute = num(&self.rpm, "Requests per minute")?.max(1) as u32;
        c.rate_limit.burst = num(&self.burst, "Burst")?.max(1) as u32;
        c.rate_limit.enabled = self.rate_limit;
        c.api.require_auth = self.require_auth;
        c.server.cors = self.cors;
        c.server.autostart = self.autostart;
        c.checker.online_check = self.online_check;
        c.checker.record_blocked = self.record_blocked;
        c.checker.record_revoked = self.record_revoked;
        c.checker.cache_enabled = self.cache_enabled;
        c.checker.cache_ttl_secs = num(&self.cache_ttl, "Cache lifetime")?.max(1);
        c.checker.cache_max_entries = num(&self.cache_max, "Cache size")?.max(1) as usize;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum FormField {
    Host(String),
    Port(String),
    MaxBatch(String),
    Rpm(String),
    Burst(String),
    RateLimit(bool),
    RequireAuth(bool),
    Cors(bool),
    Autostart(bool),
    OnlineCheck(bool),
    RecordBlocked(bool),
    RecordRevoked(bool),
    CacheEnabled(bool),
    CacheTtl(String),
    CacheMax(String),
}

#[derive(Debug, Clone)]
pub enum Message {
    Navigate(Page),
    OpenUrl(&'static str),
    Notice(String),
    CopyText(String),
    // Single key
    KeyInput(String),
    Online(bool),
    Check,
    Checked(Box<KeyReport>),
    Install(Target),
    Installed(Result<String, String>),
    // Batch
    BatchEdit(text_editor::Action),
    BatchCheck,
    BatchProgress(Vec<KeyReport>),
    BatchDone,
    SelectResult(Option<usize>),
    Tick,
    ClearCache,
    BatchClear,
    BatchExport,
    // Blocklist
    BlockEdit(text_editor::Action),
    BlockNote(String),
    BlockAdd,
    BlockRemove,
    BlockLookup,
    // System
    SysRefresh,
    SysLoaded(Result<Vec<InstalledLicense>, String>),
    SysDetails,
    SysDetailsLoaded(Result<String, String>),
    // Server
    Form(FormField),
    SaveConfig,
    StartServer,
    StopServer,
    ServerStopped,
    // API keys
    KeyName(String),
    KeyRole(Role),
    KeyDays(String),
    CreateKey,
    RevokeKey(String),
    DeleteKey(String),
    DismissToken,
}

pub struct App {
    services: Option<Arc<Services>>,
    load_error: Option<String>,
    config: Config,
    page: Page,
    notice: Option<String>,
    os_name: String,

    key_input: String,
    online: bool,
    checking: bool,
    report: Option<KeyReport>,
    action_log: Option<String>,

    batch_input: text_editor::Content,
    batch_running: bool,
    batch_results: Vec<KeyReport>,
    batch_total: usize,
    batch_started: Option<Instant>,
    batch_elapsed_ms: f64,
    selected: Option<usize>,
    /// Animation phase for indeterminate progress bars (0..1).
    phase: f32,

    block_input: text_editor::Content,
    block_note: String,
    block_status: Option<String>,

    licenses: Vec<InstalledLicense>,
    sys_loading: bool,
    sys_error: Option<String>,
    sys_details: Option<String>,

    server: Option<ServerHandle>,
    server_busy: bool,
    server_error: Option<String>,
    form: ServerForm,

    key_name: String,
    key_role: Role,
    key_days: String,
    new_token: Option<String>,
    api_keys: Vec<ApiKey>,
    key_error: Option<String>,
}

impl App {
    fn new(config: Config) -> (Self, Task<Message>) {
        let started = Instant::now();
        let (services, load_error) = match Services::load(config.clone()) {
            Ok(s) => (Some(Arc::new(s)), None),
            Err(e) => (None, Some(format!("{e:#}"))),
        };
        tracing::info!("services loaded in {:?}", started.elapsed());
        let api_keys = services.as_ref().map(|s| s.keys.list()).unwrap_or_default();
        let mut app = App {
            online: config.checker.online_check,
            form: ServerForm::from_config(&config),
            services,
            load_error,
            config,
            page: Page::Check,
            notice: None,
            os_name: String::new(),
            key_input: String::new(),
            checking: false,
            report: None,
            action_log: None,
            batch_input: text_editor::Content::new(),
            batch_running: false,
            batch_results: Vec::new(),
            batch_total: 0,
            batch_started: None,
            batch_elapsed_ms: 0.0,
            selected: None,
            phase: 0.0,
            block_input: text_editor::Content::new(),
            block_note: String::new(),
            block_status: None,
            licenses: Vec::new(),
            sys_loading: false,
            sys_error: None,
            sys_details: None,
            server: None,
            server_busy: false,
            server_error: None,
            key_name: String::new(),
            key_role: Role::User,
            key_days: String::new(),
            new_token: None,
            api_keys,
            key_error: None,
        };
        let mut tasks = vec![Task::perform(async { system::os_name() }, |n| Message::Notice(format!("os:{n}")))];
        if app.config.server.autostart {
            tasks.push(app.start_server());
        }
        (app, Task::batch(tasks))
    }

    fn services(&self) -> Option<Arc<Services>> {
        self.services.clone()
    }

    fn start_server(&mut self) -> Task<Message> {
        let Some(s) = self.services() else { return Task::none() };
        match server::spawn(&self.config, s.checker.clone(), s.keys.clone()) {
            Ok(h) => {
                self.server_error = None;
                self.notice = Some(format!("REST API listening on http://{}/api/v1", h.addr));
                self.server = Some(h);
            }
            Err(e) => self.server_error = Some(format!("{e:#}")),
        }
        Task::none()
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Navigate(p) => {
                self.page = p;
                if p == Page::ApiKeys {
                    self.refresh_keys();
                }
                if p == Page::System && self.licenses.is_empty() && !self.sys_loading {
                    return self.update(Message::SysRefresh);
                }
            }
            Message::OpenUrl(url) => system::open_url(url),
            Message::Notice(n) => match n.strip_prefix("os:") {
                Some(os) => self.os_name = os.to_string(),
                None => self.notice = Some(n),
            },
            Message::CopyText(t) => {
                self.notice = Some("Copied to clipboard".into());
                return iced::clipboard::write(t);
            }

            Message::KeyInput(k) => self.key_input = k,
            Message::Online(v) => self.online = v,
            Message::Check => {
                let Some(s) = self.services() else { return Task::none() };
                if self.key_input.trim().is_empty() || self.checking {
                    return Task::none();
                }
                self.checking = true;
                self.action_log = None;
                let (key, opts) = (self.key_input.clone(), CheckOptions { online: self.online });
                return Task::perform(async move { Box::new(s.checker.check_one(key, opts).await) }, Message::Checked);
            }
            Message::Checked(r) => {
                self.checking = false;
                self.report = Some(*r);
            }
            Message::Install(target) => {

}