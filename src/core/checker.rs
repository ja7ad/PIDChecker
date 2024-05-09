//! High level key checking: offline validation, local blocklist and the
//! optional online MAK / blocked lookup.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use rayon::prelude::*;
use serde::Serialize;

use super::blocklist::{BlockRecord, Blocklist};
use super::database::{DbStats, KeyDatabase};
use super::key::{KeyFormat, ProductKey};
use super::mak::{ActivationInfo, MakClient, MPC};
use crate::config::CheckerConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    Valid,
    InvalidFormat,
    InvalidChecksum,
    UnknownProduct,
    RevokedRange,
    /// Legacy key that cannot be validated on this platform.
    Unsupported,
    Invalid,
}

impl KeyStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Valid => "Valid",
            Self::InvalidFormat => "Invalid format",
            Self::InvalidChecksum => "Invalid checksum",
            Self::UnknownProduct => "Unknown product",
            Self::RevokedRange => "Revoked range",
            Self::Unsupported => "Unsupported",
            Self::Invalid => "Invalid",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct KeyDetails {
    pub product_id: String,
    pub extended_pid: String,
    pub sku_id: String,
    pub description: String,
    pub edition_id: String,
    /// `ProductKeyType` from pkeyconfig, e.g. `Volume:MAK`, `Retail`, `OEM:DM`.
    pub key_type: String,
    /// `EulaType` of the matching key range, e.g. `Retail`, `Volume`, `OEM`.
    pub channel: String,
    pub part_number: String,
    /// What this key type can be used for (from Microsoft's activation docs).
    pub license_note: String,
    pub crypto_id: u32,
    pub crypto_id_hex: String,
    pub serial: Option<u32>,
    pub security_value: Option<String>,
    pub upgrade: bool,
    pub is_randomized: bool,
    pub pkeyconfig: String,
    /// Product family from the data catalog, e.g. "Office 2021 / 2019 / 2016 / 365".
    pub product: String,
    pub category: String,
    pub algorithm: String,
    pub partial_key: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyReport {
    pub input: String,
    pub key: Option<String>,
    pub status: KeyStatus,
    pub valid: bool,
    pub message: String,
    pub format: Option<KeyFormat>,
    pub details: Option<KeyDetails>,
    pub activation: Option<ActivationInfo>,
    pub activation_error: Option<String>,
    pub blocked: bool,
    pub blocked_reason: Option<String>,
    /// Served from the result cache.
    pub cached: bool,
    pub checked_at: chrono::DateTime<chrono::Utc>,
    pub elapsed_us: u64,
}

impl KeyReport {
    fn new(input: &str, status: KeyStatus, message: impl Into<String>) -> Self {
        Self {
            input: input.trim().to_string(),
            key: None,
            status,
            valid: status == KeyStatus::Valid,
            message: message.into(),
            format: None,
            details: None,
            activation: None,
            activation_error: None,
            blocked: false,
            blocked_reason: None,
            cached: false,
            checked_at: chrono::Utc::now(),
            elapsed_us: 0,
        }
    }

    /// Whether this key qualifies for an online activation-count lookup.
    fn wants_online(&self, types: &[String]) -> bool {
        self.valid
            && self.details.as_ref().is_some_and(|d| {
                types.iter().any(|t| t == "*" || d.key_type.to_ascii_lowercase().contains(&t.to_ascii_lowercase()))
            })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CheckOptions {
    pub online: bool,
}

/// Settings that can change while running (from the GUI settings page).
#[derive(Debug, Clone)]
pub struct RuntimeSettings {
    pub online_default: bool,
    pub online_types: Vec<String>,
    pub record_blocked: bool,
    pub record_revoked: bool,
    pub cache_enabled: bool,
    pub cache_ttl: Duration,
    pub cache_max_entries: usize,
}

impl RuntimeSettings {
    pub fn from_config(cfg: &CheckerConfig) -> Self {
        Self {
            online_default: cfg.online_check,
            online_types: cfg.online_key_types.clone(),
            record_blocked: cfg.record_blocked,
            record_revoked: cfg.record_revoked,
            cache_enabled: cfg.cache_enabled,
            cache_ttl: Duration::from_secs(cfg.cache_ttl_secs),
            cache_max_entries: cfg.cache_max_entries.max(1),
        }
    }
}

/// Recently checked keys, keyed by (canonical key, online lookup performed).
#[derive(Default)]
struct ResultCache {
    entries: HashMap<(String, bool), (Instant, KeyReport)>,
}

impl ResultCache {
    fn get(&self, key: &(String, bool), ttl: Duration) -> Option<KeyReport> {
        let (at, r) = self.entries.get(key)?;

}