//! Command line interface shared by `pkc` (console) and `pidkeychecker` (GUI).

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

}