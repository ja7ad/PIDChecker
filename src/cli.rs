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