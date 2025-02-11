//! Command line interface
//! Colorized terminal output. interface shared by `pkc` (console) and `pidkeychecker` (GUI).

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use crate::apikeys::{ApiKeyStore, Role};
use crate::config::Config;
use crate::core::blocklist::{BlockRecord, Blocklist};
use crate::core::checker::{render_text, CheckOptions};
use crate::core::codes;
use crate::core::key::find_keys;
use crate::{instance, server, Services};

#[derive(Parser)]
#[command(name = "pkc", version, about = "PID Key Checker: validate Microsoft product keys, run the REST API, manage keys")]
pub struct Cli {
    /// Path to config.toml (default: next to the executable, then the current directory)
    #[arg(long, short, global = true)]
    pub config: Option<PathBuf>,
    /// Log filter, e.g. info, debug, "pidkeychecker=debug,actix_web=info"
    #[arg(long, global = true, default_value = "info")]
    pub log_level: String,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Open the desktop interface
    Gui,
    /// Run the REST API server (no GUI); request logs go to the console. Ctrl+C to stop.
    Serve {
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        port: Option<u16>,
    },
    /// Query a running server's health endpoint
    Status,
    /// Check keys (arguments, or any text on stdin with "-" / no arguments)
    Check {
        keys: Vec<String>,
        /// Skip the online MAK count / blocked lookup
        #[arg(long)]
        offline: bool,
        /// Print JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Manage REST API keys
    #[command(subcommand)]
    Apikey(ApiKeyCmd),
    /// Manage the blocked-keys database (stop the GUI / server first)
    #[command(subcommand)]
    Blocklist(BlocklistCmd),
    /// Show configuration
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Explain an activation / licensing error code (e.g. 0x67, 0xC004C003)
    Error { code: String },
    /// Diagnostics: time PidGenX calls (Windows only)
    #[command(hide = true)]
    PidgenxProbe { key: String, files: Vec<PathBuf> },
}

#[derive(Subcommand)]
pub enum ApiKeyCmd {
    /// Create a key; the token is printed once
    Create {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "user")]
        role: Role,
        /// Expire after N days
        #[arg(long)]
        expires_days: Option<u32>,
        /// Per-key requests per minute (default: server setting)
        #[arg(long)]
        rate_limit: Option<u32>,
    },
    /// List keys
    List,
    /// Revoke a key (kept for audit)
    Revoke { id: String },
    /// Delete a key
    Delete { id: String },
    /// Set (or with 0, clear) a key's requests-per-minute limit
    RateLimit { id: String, requests_per_minute: u32 },
}

#[derive(Subcommand)]
pub enum BlocklistCmd {
    /// Number of blocked keys
    Count,
    /// Add keys (arguments, or any text on stdin)
    Add {
        keys: Vec<String>,
        /// Note stored with the entries
        #[arg(long, default_value = "manual")]
        note: String,
    },
    /// Remove keys (arguments, or any text on stdin)
    Remove { keys: Vec<String> },
    /// Show whether keys are blocked and why
    Check { keys: Vec<String> },
}

#[derive(Subcommand)]
pub enum ConfigCmd {
    /// Print the effective configuration
    Show,
    /// Print the path of config.toml
    Path,
}

pub fn init_tracing(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if level.contains('=') { level.into() } else { format!("pidkeychecker={level},actix_web={level}").into() }
    });
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

/// Keys from arguments, or from any text on stdin when none (or "-") are given.
fn keys_or_stdin(keys: Vec<String>) -> Result<Vec<String>> {
    if keys.is_empty() || keys == ["-"] {
        let text = std::io::read_to_string(std::io::stdin())?;
        return Ok(find_keys(&text).iter().map(|k| k.as_string()).collect());
    }
    Ok(keys)
}

fn config_dir(config: &Config) -> PathBuf {
    config.path.parent().map(Path::to_path_buf).unwrap_or_default()
}

/// Take the single-instance lock or explain who holds it.
pub fn lock(config: &Config, role: &str) -> Result<instance::InstanceLock> {
    instance::acquire(&config_dir(config), role).map_err(|e| match e {
        instance::LockError::AlreadyRunning { .. } => {
            anyhow::anyhow!("{e}\nStop it first, or use the REST API / GUI of the running instance.")
        }
        other => other.into(),
    })
}

/// Run a CLI command. `None` (no subcommand) is handled by the caller.
pub fn run(cli: Cli, command: Command) -> Result<()> {
    let mut config = Config::discover(cli.config.as_deref())?;
    match command {
        Command::Gui => {
            #[cfg(feature = "gui")]
            {
                let _lock = lock(&config, "gui")?;
                crate::gui::run(config)
            }
            #[cfg(not(feature = "gui"))]
            bail!("built without the GUI")
        }
        Command::Serve { host, port } => {
            if let Some(h) = host {
                config.server.host = h;
            }
            if let Some(p) = port {
                config.server.port = p;
            }
            let _lock = lock(&config, "serve")?;
            serve(config)
        }
        Command::Status => status(&config),
        Command::Check { keys, offline, json } => {
            let _lock = lock(&config, "check")?;
            check(config, keys_or_stdin(keys)?, offline, json)
        }
        Command::Apikey(cmd) => apikey(&config, cmd),
        Command::Blocklist(cmd) => {
            let _lock = lock(&config, "blocklist")?;
            blocklist(&config, cmd)
        }
        Command::Config(ConfigCmd::Path) => {
            println!("{}", config.path.display());
            Ok(())
        }
        Command::Config(ConfigCmd::Show) => {
            println!("# {}\n{}", config.path.display(), toml::to_string_pretty(&config)?);
            Ok(())
        }
        Command::Error { code } => {
            explain(&code);
            Ok(())
        }
        Command::PidgenxProbe { key, files } => probe(&config, &key, &files),
    }
}

fn serve(config: Config) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let services = Services::load(config)?;
        let stats = services.checker.stats();
        tracing::info!(
            "loaded {} products from {} pkeyconfigs in {} ms; {} blocked keys; config {}",
            stats.configurations,
            stats.files,
            stats.load_ms,
            services.checker.blocklist().len(),
            services.config.path.display()
        );
        if services.config.api.require_auth && !services.keys.has_active_keys() {
            tracing::warn!("authentication is required but no API keys exist; create one with `pkc apikey create --name admin --role admin`");
        }
        let rl = &services.config.rate_limit;
        tracing::info!(
            "rate limit: {}",
            if rl.enabled { format!("{} req/min, burst {}", rl.requests_per_minute, rl.burst) } else { "disabled".into() }
        );
        let handle = server::spawn(&services.config, services.checker.clone(), services.keys.clone())?;
        tokio::signal::ctrl_c().await?;
        tracing::info!("shutting down");
        handle.stop().await;
        Ok(())
    })
}

fn status(config: &Config) -> Result<()> {
    let host = if config.server.host == "0.0.0.0" { "127.0.0.1" } else { config.server.host.as_str() };
    let url = format!("http://{host}:{}/api/v1/health", config.server.port);
    let rt = tokio::runtime::Runtime::new()?;
    let body = rt.block_on(async {
        let resp = reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).build()?.get(&url).send().await?;
        anyhow::Ok(resp.text().await?)
    });
    match body {
        Ok(text) => {
            let v: serde_json::Value = serde_json::from_str(&text).context("unexpected response")?;
            println!("Server running at {url}");
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        Err(e) => {
            println!("No server reachable at {url} ({e:#})");
            if let Ok(owner) = std::fs::read_to_string(config_dir(config).join(instance::FILE_NAME))
                && !owner.trim().is_empty()
            {
                println!("Last instance: {}", owner.trim());
            }
            std::process::exit(1);
        }
    }
    Ok(())
}

fn check(config: Config, keys: Vec<String>, offline: bool, json: bool) -> Result<()> {
    if keys.is_empty() {
        bail!("no keys given");
    }
    let rt = tokio::runtime::Runtime::new()?;
    let services = Services::load(config)?;
    let online = !offline && services.checker.online_default();
    let reports = rt.block_on(services.checker.check_many(keys, CheckOptions { online }));
    if json {
        println!("{}", serde_json::to_string_pretty(&reports)?);
    } else {
        for r in &reports {
            println!("{}", render_text(r));
        }
    }
    Ok(())
}

fn apikey(config: &Config, cmd: ApiKeyCmd) -> Result<()> {
    let store = ApiKeyStore::open(&config.keys_file())?;
    let found = |ok: bool, what: &str| println!("{}", if ok { what } else { "not found" });
    match cmd {
        ApiKeyCmd::Create { name, role, expires_days, rate_limit } => {
            let (key, token) = store.create(&name, role, expires_days)?;
            if rate_limit.is_some() {
                store.set_rate_limit(&key.id, rate_limit)?;
            }
            println!("Created {} key '{}' (id {})", key.role, key.name, key.id);
            println!("Token (shown once): {token}");
            println!("Use it as:  Authorization: Bearer {token}");
        }
        ApiKeyCmd::List => {
            let keys = store.list();
            if keys.is_empty() {
                println!("No API keys. Create one with `pkc apikey create --name admin --role admin`.");
            }
            println!("{:<36}  {:<20} {:<5} {:<8} {:<12} {:>9} {:>8}  last used", "id", "name", "role", "state", "prefix", "requests", "rpm");
            for k in keys {
                println!(
                    "{:<36}  {:<20} {:<5} {:<8} {:<12} {:>9} {:>8}  {}",
                    k.id,
                    k.name,
                    k.role,
                    if k.revoked { "revoked" } else if k.is_active() { "active" } else { "expired" },
                    format!("{}…", k.prefix),
                    k.requests,
                    k.rate_limit_per_minute.map(|r| r.to_string()).unwrap_or_else(|| "default".into()),
                    k.last_used_at.map(|t| t.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_else(|| "never".into()),
                );
            }
        }
        ApiKeyCmd::Revoke { id } => found(store.revoke(&id)?, "revoked"),
        ApiKeyCmd::Delete { id } => found(store.delete(&id)?, "deleted"),
        ApiKeyCmd::RateLimit { id, requests_per_minute } => {
            found(store.set_rate_limit(&id, Some(requests_per_minute))?, "updated")
        }
    }
    Ok(())
}

fn blocklist(config: &Config, cmd: BlocklistCmd) -> Result<()> {
    let bl = Blocklist::open(&config.checker_resolved().blocklist_db)?;
    let parse = |keys: Vec<String>| -> Result<_> {
        let text = keys_or_stdin(keys)?.join("\n");
        let keys = find_keys(&text);
        if keys.is_empty() {
            bail!("no valid product keys given");
        }
        Ok(keys)
    };
    match cmd {
        BlocklistCmd::Count => println!("{}", bl.len()),
        BlocklistCmd::Add { keys, note } => {
            let keys = parse(keys)?;
            let rec = BlockRecord { source: note, error_code: None, added_at: chrono::Utc::now() };
            let n = bl.insert_many(&keys, &rec)?;
            println!("added {n}, already present {}, total {}", keys.len() - n, bl.len());
        }
        BlocklistCmd::Remove { keys } => {
            let keys = parse(keys)?;
            let n = bl.remove_many(&keys)?;
            println!("removed {n}, not listed {}, total {}", keys.len() - n, bl.len());
        }
        BlocklistCmd::Check { keys } => {
            for k in parse(keys)? {
                match bl.get(&k) {
                    Some(r) => println!(
                        "{k}  BLOCKED  {}{}  {}",
                        r.source,
                        r.error_code.map(|c| format!(" ({c})")).unwrap_or_default(),
                        r.added_at.format("%Y-%m-%d")
                    ),
                    None => println!("{k}  not blocked"),
                }
            }
        }
    }
    Ok(())
}

fn explain(code: &str) {
    match codes::lookup(code) {
        Some(c) => {
            println!("{} {}", codes::format_code(c.code), c.name.as_deref().unwrap_or(""));
            println!("  Message   : {}", c.message);
            println!("  Category  : {}{}", c.category, if c.blocked { " (key blocked)" } else { "" });
            if let Some(x) = &c.cause {
                println!("  Cause     : {x}");
            }
            if let Some(x) = &c.resolution {
                println!("  Resolution: {x}");
            }
        }
        None => println!("Unknown code {code}"),
    }
}

#[cfg(windows)]
fn probe(config: &Config, key: &str, files: &[PathBuf]) -> Result<()> {
    let (pgx, path) = crate::core::pidgenx::load_any(&config.checker_resolved().pidgenx_path)?;
    println!("dll: {}", path.display());
    for f in files {
        let t = std::time::Instant::now();
        let (hr, res) = pgx.check(key, f);
        println!("{:>10.3}s  0x{:08X}  {}  {:?}", t.elapsed().as_secs_f64(), hr as u32, f.display(), res.map(|r| r.act_config_id));
    }
    Ok(())
}

#[cfg(not(windows))]
fn probe(_: &Config, _: &str, _: &[PathBuf]) -> Result<()> {
    bail!("pidgenx is only available on Windows")
}
