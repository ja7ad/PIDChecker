//! `config.toml` handling. The file lives next to the executable (falling back
//! to the current directory); relative paths inside it resolve against the
//! file's own directory.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const FILE_NAME: &str = "config.toml";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    /// Start the REST server automatically when the GUI opens.
    pub autostart: bool,
    /// Allow cross-origin browser requests.
    pub cors: bool,
    /// Maximum request body size in KiB.
    pub max_body_kb: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self { host: "127.0.0.1".into(), port: 8080, autostart: false, cors: false, max_body_kb: 1024 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct CheckerConfig {
    pub data_dir: PathBuf,
    /// Blocked-key database (redb).
    pub blocklist_db: PathBuf,
    /// Maximum keys per batch request (API and GUI).
    pub max_batch_size: usize,
    /// Maximum keys per blocklist add/remove request.
    pub max_blocklist_batch: usize,
    /// Query Microsoft for remaining activations / blocked status by default.
    pub online_check: bool,
    /// `ProductKeyType` substrings eligible for the online lookup ("*" = all).
    pub online_key_types: Vec<String>,
    pub online_timeout_secs: u64,
    /// PIDs per activation-service request.
    pub online_chunk_size: usize,
    /// Parallel activation-service requests.
    pub online_concurrency: usize,
    /// Store keys Microsoft reports as blocked (0x67) in the blocklist database.
    pub record_blocked: bool,
    /// Also store keys from key ranges Microsoft marked invalid (revoked).
    pub record_revoked: bool,
    /// Cache check results (including online MAK counts).
    pub cache_enabled: bool,
    /// Seconds before a cached result expires.
    pub cache_ttl_secs: u64,
    /// Upper bound on cached results; the oldest are evicted first.
    pub cache_max_entries: usize,
    /// Windows only: use pidgenx.dll for legacy (Win7 / Office 2010) keys.
    pub pidgenx_enabled: bool,
    pub pidgenx_path: PathBuf,
    /// Parallel PidGenX instances for legacy keys (0 = number of CPU cores, max 16).
    pub pidgenx_instances: usize,
}

impl Default for CheckerConfig {
    fn default() -> Self {
        Self {
            data_dir: "data".into(),
            blocklist_db: "blocked.redb".into(),
            max_batch_size: 500,
            max_blocklist_batch: 10_000,
            online_check: true,
            online_key_types: vec!["MAK".into()],
            online_timeout_secs: 15,
            online_chunk_size: 25,
            online_concurrency: 4,
            record_blocked: true,
            record_revoked: true,
            cache_enabled: true,
            cache_ttl_secs: 3600,
            cache_max_entries: 100_000,
            pidgenx_enabled: true,
            pidgenx_path: "pidgenx.dll".into(),
            pidgenx_instances: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RateLimitConfig {
    pub enabled: bool,
    /// Sustained requests per minute per client (API key, or IP without one).
    pub requests_per_minute: u32,
    /// Requests allowed in a burst before throttling starts.
    pub burst: u32,
    /// Use `X-Forwarded-For` / `Forwarded` for the client IP (behind a reverse proxy only).
    pub trust_proxy_headers: bool,

}