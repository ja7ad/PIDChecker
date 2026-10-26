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
use crate::core::catalog;
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
    pub catalog_sync: bool,
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
            catalog_sync: c.catalog.auto_sync,
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
        c.catalog.auto_sync = self.catalog_sync;
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
    CatalogSync(bool),
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
    // Catalog (`true` = requested by the user)
    CatalogSync(bool),
    CatalogSynced(bool, Result<Option<String>, String>),
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

    catalog_syncing: bool,
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
            catalog_syncing: false,
        };
        let mut tasks = vec![Task::perform(async { system::os_name() }, |n| Message::Notice(format!("os:{n}")))];
        if app.config.server.autostart {
            tasks.push(app.start_server());
        }
        if app.config.catalog.auto_sync {
            tasks.push(app.sync_catalog(false));
        }
        (app, Task::batch(tasks))
    }

    fn services(&self) -> Option<Arc<Services>> {
        self.services.clone()
    }

    /// Fetch catalog updates in the background; the checker reloads in place.
    fn sync_catalog(&mut self, manual: bool) -> Task<Message> {
        let Some(s) = self.services() else { return Task::none() };
        if self.catalog_syncing {
            return Task::none();
        }
        self.catalog_syncing = true;
        let url = self.config.catalog.url.clone();
        Task::perform(
            async move {
                catalog::sync_and_reload(&s.checker, &url).await.map(|r| r.map(|r| r.summary())).map_err(|e| format!("{e:#}"))
            },
            move |r| Message::CatalogSynced(manual, r),
        )
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
                let Ok(key) = ProductKey::parse(&self.key_input) else {
                    self.notice = Some("Enter a valid key first".into());
                    return Task::none();
                };
                self.action_log = Some("Installing key and activating… (requires administrator rights)".into());
                let key = key.as_string();
                return Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || system::install_and_activate(&key, target))
                            .await
                            .map_err(|e| e.to_string())?
                            .map_err(|e| format!("{e:#}"))
                    },
                    Message::Installed,
                );
            }
            Message::Installed(r) => self.action_log = Some(r.unwrap_or_else(|e| format!("Error: {e}"))),

            Message::BatchEdit(a) => self.batch_input.perform(a),
            Message::BatchClear => {
                self.batch_input = text_editor::Content::new();
                self.batch_results.clear();
                self.selected = None;
            }
            Message::BatchCheck => {
                let Some(s) = self.services() else { return Task::none() };
                let keys = extract_keys(&self.batch_input.text());
                if keys.is_empty() || self.batch_running {
                    return Task::none();
                }
                let max = self.config.checker.max_batch_size;
                if keys.len() > max {
                    self.notice = Some(format!("{} keys exceed the batch limit of {max} (see Settings)", keys.len()));
                    return Task::none();
                }
                self.batch_running = true;
                self.batch_results.clear();
                self.selected = None;
                self.batch_total = keys.len();
                self.batch_started = Some(Instant::now());
                let opts = CheckOptions { online: self.online };
                // Online lookups are the slow part: send them in groups that fill
                // the configured concurrency; offline-only batches use larger steps.
                let step = if opts.online {
                    (self.config.checker.online_chunk_size * self.config.checker.online_concurrency).max(1)
                } else {
                    250
                };
                let stream = iced::stream::channel(4, async move |mut tx| {
                    for chunk in keys.chunks(step) {
                        let reports = s.checker.check_many(chunk.to_vec(), opts).await;
                        if tx.send(Message::BatchProgress(reports)).await.is_err() {
                            return;
                        }
                    }
                    let _ = tx.send(Message::BatchDone).await;
                });
                return Task::run(stream, |m| m);
            }
            Message::BatchProgress(mut r) => self.batch_results.append(&mut r),
            Message::BatchDone => {
                self.batch_running = false;
                self.batch_elapsed_ms = self.batch_started.map(|t| t.elapsed().as_secs_f64() * 1000.0).unwrap_or(0.0);
            }
            Message::SelectResult(i) => self.selected = i,
            Message::Tick => self.phase = (self.phase + 0.012) % 1.0,
            Message::ClearCache => {
                if let Some(s) = &self.services {
                    let n = s.checker.cache_len();
                    s.checker.clear_cache();
                    self.notice = Some(format!("Cleared {n} cached result(s)"));
                }
            }
            Message::BatchExport => {
                if self.batch_results.is_empty() {
                    return Task::none();
                }
                let dir = self.config.path.parent().map(|p| p.to_path_buf()).unwrap_or_default();
                let path = dir.join(format!("results-{}.csv", chrono::Local::now().format("%Y%m%d-%H%M%S")));
                self.notice = Some(match std::fs::write(&path, to_csv(&self.batch_results)) {
                    Ok(()) => format!("Exported {} rows to {}", self.batch_results.len(), path.display()),
                    Err(e) => format!("Export failed: {e}"),
                });
            }

            Message::BlockEdit(a) => self.block_input.perform(a),
            Message::BlockNote(n) => self.block_note = n,
            Message::BlockAdd | Message::BlockRemove | Message::BlockLookup => {
                let Some(s) = self.services() else { return Task::none() };
                let keys = crate::core::key::find_keys(&self.block_input.text());
                let bl = s.checker.blocklist();
                let mut msg = match message {
                    Message::BlockAdd => {
                        let note = self.block_note.trim();
                        let rec = BlockRecord {
                            source: if note.is_empty() { "manual".into() } else { note.to_string() },
                            error_code: None,
                            added_at: chrono::Utc::now(),
                        };
                        match bl.insert_many(&keys, &rec) {
                            Ok(n) => format!("Added {n} key(s), {} already present.", keys.len() - n),
                            Err(e) => format!("Error: {e:#}"),
                        }
                    }
                    Message::BlockRemove => match bl.remove_many(&keys) {
                        Ok(n) => format!("Removed {n} key(s), {} were not listed.", keys.len() - n),
                        Err(e) => format!("Error: {e:#}"),
                    },
                    _ => keys
                        .iter()
                        .map(|k| match bl.get(k) {
                            Some(r) => format!(
                                "{k}: BLOCKED — {}{} ({})",
                                r.source,
                                r.error_code.map(|c| format!(", code {c}")).unwrap_or_default(),
                                r.added_at.format("%Y-%m-%d")
                            ),
                            None => format!("{k}: not blocked"),
                        })
                        .collect::<Vec<_>>()
                        .join("\n"),
                };
                if keys.is_empty() {
                    msg = "No product keys found in the text.".into();
                }
                self.block_status = Some(msg);
            }
            Message::SysRefresh => {
                self.sys_loading = true;
                self.sys_error = None;
                return Task::perform(
                    async {
                        tokio::task::spawn_blocking(system::installed_licenses)
                            .await
                            .map_err(|e| e.to_string())?
                            .map_err(|e| format!("{e:#}"))
                    },
                    Message::SysLoaded,
                );
            }
            Message::SysLoaded(r) => {
                self.sys_loading = false;
                match r {
                    Ok(l) => self.licenses = l,
                    Err(e) => self.sys_error = Some(e),
                }
            }
            Message::SysDetails => {
                return Task::perform(
                    async {
                        tokio::task::spawn_blocking(system::license_details)
                            .await
                            .map_err(|e| e.to_string())?
                            .map_err(|e| format!("{e:#}"))
                    },
                    Message::SysDetailsLoaded,
                );
            }
            Message::SysDetailsLoaded(r) => self.sys_details = Some(r.unwrap_or_else(|e| format!("Error: {e}"))),

            Message::Form(f) => match f {
                FormField::Host(v) => self.form.host = v,
                FormField::Port(v) => self.form.port = v,
                FormField::MaxBatch(v) => self.form.max_batch = v,
                FormField::Rpm(v) => self.form.rpm = v,
                FormField::Burst(v) => self.form.burst = v,
                FormField::RateLimit(v) => self.form.rate_limit = v,
                FormField::RequireAuth(v) => self.form.require_auth = v,
                FormField::Cors(v) => self.form.cors = v,
                FormField::Autostart(v) => self.form.autostart = v,
                FormField::OnlineCheck(v) => self.form.online_check = v,
                FormField::RecordBlocked(v) => self.form.record_blocked = v,
                FormField::RecordRevoked(v) => self.form.record_revoked = v,
                FormField::CacheEnabled(v) => self.form.cache_enabled = v,
                FormField::CacheTtl(v) => self.form.cache_ttl = v,
                FormField::CacheMax(v) => self.form.cache_max = v,
                FormField::CatalogSync(v) => self.form.catalog_sync = v,
            },
            Message::CatalogSync(manual) => return self.sync_catalog(manual),
            Message::CatalogSynced(manual, r) => {
                self.catalog_syncing = false;
                match r {
                    Ok(Some(summary)) => self.notice = Some(summary),
                    Ok(None) if manual => self.notice = Some("Catalog is up to date".into()),
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!("catalog sync failed: {e}");
                        if manual {
                            self.notice = Some(format!("Catalog sync failed: {e}"));
                        }
                    }
                }
            }
            Message::SaveConfig => {
                let was_syncing = self.config.catalog.auto_sync;
                let mut cfg = self.config.clone();
                match self.form.apply(&mut cfg).map_err(anyhow::Error::msg).and_then(|_| cfg.save()) {
                    Ok(()) => {
                        self.config = cfg;
                        self.server_error = None;
                        // Checker settings apply immediately; server settings on restart.
                        if let Some(s) = &self.services {
                            s.checker.apply_settings(&self.config.checker_resolved());
                        }
                        self.notice = Some(format!(
                            "Saved {}{}",
                            self.config.path.display(),
                            if self.server.is_some() { " — restart the server to apply" } else { "" }
                        ));
                        if self.config.catalog.auto_sync && !was_syncing {
                            return self.sync_catalog(false);
                        }
                    }
                    Err(e) => self.server_error = Some(format!("{e:#}")),
                }
            }
            Message::StartServer => {
                if self.server.is_none() {
                    return self.start_server();
                }
            }
            Message::StopServer => {
                if let Some(h) = self.server.take() {
                    self.server_busy = true;
                    return Task::perform(h.stop(), |_| Message::ServerStopped);
                }
            }
            Message::ServerStopped => {
                self.server_busy = false;
                self.notice = Some("REST server stopped".into());
            }

            Message::KeyName(v) => self.key_name = v,
            Message::KeyRole(r) => self.key_role = r,
            Message::KeyDays(v) => self.key_days = v,
            Message::CreateKey => {
                let Some(s) = self.services() else { return Task::none() };
                let days = match self.key_days.trim() {
                    "" => None,
                    d => match d.parse::<u32>() {
                        Ok(n) => Some(n),
                        Err(_) => {
                            self.key_error = Some("Expiry must be a number of days".into());
                            return Task::none();
                        }
                    },
                };
                match s.keys.create(&self.key_name, self.key_role, days) {
                    Ok((_, token)) => {
                        self.new_token = Some(token);
                        self.key_name.clear();
                        self.key_error = None;
                    }
                    Err(e) => self.key_error = Some(format!("{e:#}")),
                }
                self.refresh_keys();
            }
            Message::RevokeKey(id) => {
                if let Some(s) = self.services()
                    && let Err(e) = s.keys.revoke(&id) {
                        self.key_error = Some(format!("{e:#}"));
                    }
                self.refresh_keys();
            }
            Message::DeleteKey(id) => {
                if let Some(s) = self.services()
                    && let Err(e) = s.keys.delete(&id) {
                        self.key_error = Some(format!("{e:#}"));
                    }
                self.refresh_keys();
            }
            Message::DismissToken => self.new_token = None,
        }
        Task::none()
    }

    fn subscription(&self) -> Subscription<Message> {
        let tick = if self.checking || self.batch_running {
            iced::time::every(Duration::from_millis(16)).map(|_| Message::Tick)
        } else {
            Subscription::none()
        };
        let sync = if self.config.catalog.auto_sync {
            iced::time::every(self.config.catalog.interval()).map(|_| Message::CatalogSync(false))
        } else {
            Subscription::none()
        };
        Subscription::batch([tick, sync])
    }

    fn refresh_keys(&mut self) {
        if let Some(s) = &self.services {
            self.api_keys = s.keys.list();
        }
    }

    fn report_text(&self) -> Option<String> {
        self.report.as_ref().map(render_text)
    }
}

/// Keys pasted into a text area: every key found anywhere in the text.
fn extract_keys(text: &str) -> Vec<String> {
    crate::core::key::find_keys(text).iter().map(ProductKey::as_string).collect()
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.to_string() }
}

pub fn to_csv(rows: &[KeyReport]) -> String {
    let mut out = String::from("key,status,product,description,edition,license_type,channel,crypto_id,mak_remaining,blocked,blocked_reason,message\n");
    for r in rows {
        let d = r.details.clone().unwrap_or_default();
        let mak = r.activation.as_ref().and_then(|a| a.remaining).map(|n| n.to_string()).unwrap_or_default();
        let fields = [
            r.key.clone().unwrap_or_else(|| r.input.clone()),
            r.status.label().to_string(),
            d.product,
            d.description,
            d.edition_id,
            d.key_type,
            d.channel,
            if d.crypto_id > 0 { d.crypto_id.to_string() } else { String::new() },
            mak,
            r.blocked.to_string(),
            r.blocked_reason.clone().unwrap_or_default(),
            r.message.clone(),
        ];
        out.push_str(&fields.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}
