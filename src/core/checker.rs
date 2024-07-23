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
        (at.elapsed() < ttl).then(|| r.clone())
    }

    fn insert(&mut self, key: (String, bool), report: KeyReport, ttl: Duration, max: usize) {
        if self.entries.len() >= max {
            self.entries.retain(|_, (at, _)| at.elapsed() < ttl);
        }
        if self.entries.len() >= max {
            // Evict the oldest tenth.
            let mut ages: Vec<_> = self.entries.iter().map(|(k, (at, _))| (*at, k.clone())).collect();
            ages.sort_unstable_by_key(|(at, _)| *at);
            for (_, k) in ages.into_iter().take(max / 10 + 1) {
                self.entries.remove(&k);
            }
        }
        self.entries.insert(key, (Instant::now(), report));
    }
}

pub struct Checker {
    db: KeyDatabase,
    blocklist: Blocklist,
    mak: MakClient,
    settings: parking_lot::RwLock<RuntimeSettings>,
    cache: parking_lot::Mutex<ResultCache>,
    #[cfg(windows)]
    pidgenx: Option<super::pidgenx::Pool>,
    /// Legacy sources ordered most-recently-matched first.
    #[cfg(windows)]
    legacy_order: parking_lot::Mutex<Vec<usize>>,
}

impl Checker {
    pub fn new(cfg: &CheckerConfig) -> Result<Self> {
        let db = KeyDatabase::load(&cfg.data_dir)
            .map_err(|e| anyhow::anyhow!("loading pkeyconfig data from {}: {e}", cfg.data_dir.display()))?;
        for e in &db.errors {
            tracing::warn!("{e}");
        }
        let blocklist = Blocklist::open(&cfg.blocklist_db)?;
        let mak = MakClient::new(
            Duration::from_secs(cfg.online_timeout_secs),
            cfg.online_chunk_size,
            cfg.online_concurrency,
        )?;
        #[cfg(windows)]
        let pidgenx = if cfg.pidgenx_enabled {
            let n = match cfg.pidgenx_instances {
                0 => std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4),
                n => n,
            }
            .clamp(1, 16);
            match super::pidgenx::Pool::load(&cfg.pidgenx_path, n) {
                Ok(pool) => {
                    tracing::info!("pidgenx backend loaded from {} ({} instances)", pool.path.display(), pool.size());
                    Some(pool)
                }
                Err(e) => {
                    tracing::warn!("pidgenx backend unavailable: {e:#}");
                    None
                }
            }
        } else {
            None
        };
        Ok(Self {
            blocklist,
            mak,
            settings: parking_lot::RwLock::new(RuntimeSettings::from_config(cfg)),
            cache: parking_lot::Mutex::new(ResultCache::default()),
            #[cfg(windows)]
            legacy_order: parking_lot::Mutex::new(db.legacy_sources.clone()),
            db,
            #[cfg(windows)]
            pidgenx,
        })
    }

    pub fn stats(&self) -> DbStats {
        self.db.stats()
    }

    pub fn blocklist(&self) -> &Blocklist {
        &self.blocklist
    }

    pub fn online_default(&self) -> bool {
        self.settings.read().online_default
    }

    pub fn settings(&self) -> RuntimeSettings {
        self.settings.read().clone()
    }

    /// Apply changed settings without restarting (cache, auto-block, online defaults).
    pub fn apply_settings(&self, cfg: &CheckerConfig) {
        let new = RuntimeSettings::from_config(cfg);
        if !new.cache_enabled {
            self.clear_cache();
        }
        *self.settings.write() = new;
    }

    pub fn cache_len(&self) -> usize {
        self.cache.lock().entries.len()
    }

    pub fn clear_cache(&self) {
        self.cache.lock().entries.clear();
    }

    pub fn legacy_supported(&self) -> bool {
        #[cfg(windows)]
        {
            self.pidgenx.is_some()
        }
        #[cfg(not(windows))]
        {
            false
        }
    }

    /// Offline validation of a single key. Pure CPU work, typically a few µs.
    pub fn check_offline(&self, input: &str) -> KeyReport {
        let started = Instant::now();
        let mut report = self.validate(input);
        self.apply_blocklist(&mut report);
        if report.status == KeyStatus::RevokedRange && !report.blocked && self.settings.read().record_revoked {
            self.record(&report, "revoked-range", None);
            self.apply_blocklist(&mut report);
        }
        report.elapsed_us = started.elapsed().as_micros() as u64;
        report
    }

    fn apply_blocklist(&self, report: &mut KeyReport) {
        let Some(key) = report.key.as_deref().and_then(|k| ProductKey::parse(k).ok()) else { return };
        if let Some(rec) = self.blocklist.get(&key) {
            report.blocked = true;
            report.blocked_reason = Some(match rec.error_code {
                Some(code) => format!("Blocked by Microsoft ({code}), recorded {}", rec.added_at.format("%Y-%m-%d")),
                None => format!("In blocklist database ({})", rec.source),
            });
        }
    }

    fn record(&self, report: &KeyReport, source: &str, error_code: Option<String>) {
        let Some(k) = report.key.as_deref().and_then(|k| ProductKey::parse(k).ok()) else { return };
        let rec = BlockRecord { source: source.into(), error_code, added_at: chrono::Utc::now() };
        match self.blocklist.insert(&k, &rec) {
            Ok(true) => tracing::info!("recorded {k} in blocklist ({source})"),
            Ok(false) => {}
            Err(e) => tracing::warn!("could not update blocklist: {e:#}"),
        }
    }

    fn validate(&self, input: &str) -> KeyReport {
        let key = match ProductKey::parse(input) {
            Ok(k) => k,
            Err(e) => return KeyReport::new(input, KeyStatus::InvalidFormat, e.to_string()),
        };
        let format = key.format();
        let mut report = match format {
            KeyFormat::Pkey2009 => self.validate_2009(input, &key),
            KeyFormat::Pkey2005 => self.validate_legacy(input, &key),
        };
        report.key = Some(key.as_string());
        report.format = Some(format);
        if let Some(d) = report.details.as_mut() {
            d.partial_key = key.partial();
        }
        report
    }

    fn validate_2009(&self, input: &str, key: &ProductKey) -> KeyReport {
        let decoded = key.decode().expect("pkey2009 key decodes");
        if !decoded.checksum_valid {
            return KeyReport::new(input, KeyStatus::InvalidChecksum, "Key checksum does not match");
        }
        let Some(m) = self.db.lookup(decoded.group, decoded.serial) else {
            let mut r = KeyReport::new(input, KeyStatus::UnknownProduct, "No pkeyconfig contains this key's group");
            r.details = Some(KeyDetails {
                crypto_id: decoded.group,
                crypto_id_hex: format!("{:x}", decoded.group),
                serial: Some(decoded.serial),
                ..Default::default()
            });
            return r;
        };
        let cfg = &m.entry.config;
        let (status, message) = match m.range {
            Some(r) if r.is_valid => (KeyStatus::Valid, "Valid key"),
            Some(_) => (KeyStatus::RevokedRange, "Key belongs to a range marked invalid by Microsoft"),
            None => (KeyStatus::Invalid, "Serial is outside every known key range"),
        };
        let mut report = KeyReport::new(input, status, message);
        report.details = Some(KeyDetails {
            product_id: decoded.product_id(),
            extended_pid: decoded.extended_pid("XXXXX"),
            sku_id: cfg.act_config_id.clone(),
            description: cfg.description.clone(),
            edition_id: cfg.edition_id.clone(),
            key_type: cfg.key_type.clone(),
            license_note: license_note(&cfg.key_type).to_string(),
            channel: m.range.map(|r| r.eula_type.clone()).unwrap_or_default(),
            part_number: m.range.map(|r| r.part_number.clone()).unwrap_or_default(),
            crypto_id: decoded.group,
            crypto_id_hex: format!("{:x}", decoded.group),
            serial: Some(decoded.serial),
            security_value: Some(format!("{:x}", decoded.security)),
            upgrade: decoded.upgrade,
            is_randomized: cfg.is_randomized,
            pkeyconfig: self.db.source(m.entry.sources[0]).map(|s| s.name.clone()).unwrap_or_default(),
            product: self.db.source(m.entry.sources[0]).map(|s| s.product.clone()).unwrap_or_default(),
            category: self.db.source(m.entry.sources[0]).map(|s| s.category.clone()).unwrap_or_default(),
            algorithm: self.db.algorithm(decoded.group).unwrap_or("msft:rm/algorithm/pkey/2009").to_string(),
            partial_key: String::new(),
        });
        report
    }

    #[cfg(not(windows))]
    fn validate_legacy(&self, input: &str, _key: &ProductKey) -> KeyReport {
        KeyReport::new(
            input,
            KeyStatus::Unsupported,
            "Legacy (pkey2005) key: validation requires pidgenx.dll on Windows",
        )
    }

    #[cfg(windows)]
    fn validate_legacy(&self, input: &str, key: &ProductKey) -> KeyReport {
        let Some(pgx) = &self.pidgenx else {
            return KeyReport::new(input, KeyStatus::Unsupported, "Legacy (pkey2005) key: pidgenx.dll not available");
        };
        let key_str = key.as_string();
        let order = self.legacy_order.lock().clone();
        let files: Vec<&std::path::Path> = order.iter().map(|&i| self.db.sources[i].path.as_path()).collect();
        let started = Instant::now();
        let outcome = pgx.check_first(&key_str, &files);
        tracing::debug!("pidgenx: {key_str} resolved in {:?}", started.elapsed());
        let last_hr = match outcome {
            Ok((pos, res)) => {
                let src = order[pos];
                if pos > 0 {
                    // Most-recently-matched first: batches of similar keys get faster.
                    let mut o = self.legacy_order.lock();
                    if let Some(i) = o.iter().position(|&x| x == src) {
                        let v = o.remove(i);
                        o.insert(0, v);
                    }
                }
                let entry = self.db.by_act_config_id(&res.act_config_id);
                let mut report = KeyReport::new(input, KeyStatus::Valid, "Valid key");
                report.details = Some(KeyDetails {
                    product_id: res.product_id,
                    extended_pid: res.extended_pid,
                    sku_id: super::pkeyconfig::normalize_guid(&res.act_config_id),
                    description: entry.map(|e| e.config.description.clone()).unwrap_or_else(|| res.edition_type.clone()),
                    edition_id: entry.map(|e| e.config.edition_id.clone()).unwrap_or(res.edition_type),
                    license_note: license_note(&res.license_type).to_string(),
                    key_type: res.license_type,
                    channel: res.channel,
                    part_number: res.sub_type,
                    crypto_id: entry.map(|e| e.config.ref_group_id).unwrap_or_default(),
                    crypto_id_hex: entry.map(|e| format!("{:x}", e.config.ref_group_id)).unwrap_or_default(),
                    pkeyconfig: self.db.sources[src].name.clone(),
                    product: self.db.sources[src].product.clone(),
                    category: self.db.sources[src].category.clone(),
                    algorithm: "msft:rm/algorithm/pkey/2005".into(),
                    ..Default::default()
                });
                return report;
            }
            Err(hr) => hr,
        };
        let msg = super::codes::lookup(&last_hr.to_string())
            .map(|c| c.message.to_string())
            .unwrap_or_else(|| format!("Rejected by every pkeyconfig (0x{:08X})", last_hr as u32));
        KeyReport::new(input, KeyStatus::Invalid, msg)
    }

    /// Check many keys. Offline validation runs in parallel; online lookups are
    /// batched into as few service calls as possible.
    pub async fn check_many(self: &Arc<Self>, inputs: Vec<String>, opts: CheckOptions) -> Vec<KeyReport> {
        let settings = self.settings();
        let cache_key = |input: &str| ProductKey::parse(input).ok().map(|k| (k.as_string(), opts.online));

        // Serve what we can from the cache.
        let mut out: Vec<Option<KeyReport>> = vec![None; inputs.len()];
        let mut misses = Vec::new();
        {
            let cache = self.cache.lock();
            for (i, input) in inputs.iter().enumerate() {
                let hit = settings.cache_enabled.then(|| cache_key(input)).flatten().and_then(|k| cache.get(&k, settings.cache_ttl));
                match hit {
                    Some(mut r) => {
                        r.cached = true;
                        r.input = input.trim().to_string();
                        out[i] = Some(r);
                    }
                    None => misses.push(i),
                }
            }
        }
        for r in out.iter_mut().flatten() {
            // The blocklist may have changed since the result was cached.
            r.blocked = false;
            r.blocked_reason = None;
            if let Some(a) = &r.activation
                && a.blocked {
                    r.blocked = true;
                    r.blocked_reason = Some(format!("Blocked by Microsoft ({})", a.error_code.as_deref().unwrap_or("?")));
                }
            if !r.blocked {
                self.apply_blocklist(r);
            }
        }

        let this = self.clone();
        let todo: Vec<String> = misses.iter().map(|&i| inputs[i].clone()).collect();
        let mut fresh = if todo.len() > 32 {
            tokio::task::spawn_blocking(move || todo.par_iter().map(|k| this.check_offline(k)).collect())
                .await
                .unwrap_or_default()
        } else {
            todo.iter().map(|k| this.check_offline(k)).collect::<Vec<_>>()
        };
        if opts.online {
            self.apply_online(&mut fresh, &settings).await;
        }

        if settings.cache_enabled {
            let mut cache = self.cache.lock();
            for r in &fresh {
                // Do not cache transient network failures.
                if r.activation_error.is_some() {
                    continue;
                }
                if let Some(k) = cache_key(&r.input) {
                    cache.insert(k, r.clone(), settings.cache_ttl, settings.cache_max_entries);
                }
            }
        }
        for (i, r) in misses.into_iter().zip(fresh) {
            out[i] = Some(r);
        }
        out.into_iter().flatten().collect()
    }

    pub async fn check_one(self: &Arc<Self>, input: String, opts: CheckOptions) -> KeyReport {
        self.check_many(vec![input], opts).await.pop().expect("one report")
    }

    async fn apply_online(&self, reports: &mut [KeyReport], settings: &RuntimeSettings) {
        let started = Instant::now();
        let targets: Vec<(usize, String)> = reports
            .iter()
            .enumerate()
            .filter(|(_, r)| r.wants_online(&settings.online_types))
            .filter_map(|(i, r)| {
                let epid = r.details.as_ref()?.extended_pid.replace("XXXXX", MPC);
                Some((i, epid))
            })
            .collect();
        if targets.is_empty() {
            return;
        }
        let pids: Vec<String> = targets.iter().map(|(_, p)| p.clone()).collect();
        let results = self.mak.query(&pids).await;
        let elapsed = started.elapsed().as_micros() as u64;
        for (idx, pid) in targets {
            let report = &mut reports[idx];
            report.elapsed_us += elapsed;
            match results.get(&pid) {
                Some(Ok(info)) => {
                    if info.blocked {
                        report.blocked = true;
                        report.blocked_reason = Some(format!(
                            "Blocked by Microsoft ({})",
                            info.error_code.as_deref().unwrap_or("?")
                        ));
                        if settings.record_blocked {
                            self.record(report, "microsoft", info.error_code.clone());
                        }
                    }
                    report.activation = Some(info.clone());
                }
                Some(Err(e)) => report.activation_error = Some(e.clone()),
                None => report.activation_error = Some("no response".into()),
            }
        }
    }
}

/// Plain-language explanation of a `ProductKeyType`, per Microsoft's
/// licensing-and-activation documentation.
pub fn license_note(key_type: &str) -> &'static str {
    let t = key_type.to_ascii_lowercase();
    if t.contains("gvlk") || t.contains("kms_client") || t.contains("kmsclient") {
        "Public KMS client setup key: activates only against a KMS host or Active Directory, never with Microsoft"
    } else if t.contains("csvlk") || t.contains("kms_host") || t.contains("kmshost") {
        "KMS host key (CSVLK): activates a KMS host, limited to 10 activations on up to 6 hosts"
    } else if t.contains("mak") {
        "Multiple Activation Key: activates online or by phone with Microsoft, for a limited number of activations"
    } else if t.contains("oem") {
        "OEM key: tied to the manufacturer's hardware (BIOS/firmware licensing)"
    } else if t.contains("retail") {
        "Retail key: activates with Microsoft; cannot be activated through KMS"
    } else if t.contains("volume") {
        "Volume license key"
    } else {
        ""
    }
}

/// Render a report in the classic text layout of the original tool.
pub fn render_text(r: &KeyReport) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let mut line = |label: &str, value: &str| {
        let _ = writeln!(s, "{label:<15}: {value}");
    };
    line("Key", r.key.as_deref().unwrap_or(&r.input));
    line("Key Status", if r.valid { "Valid" } else { r.status.label() });
    if !r.valid {
        line("Reason", &r.message);
    }
    if let Some(d) = &r.details {
        if !d.product.is_empty() {
            line("Product", &format!("{} [{}]", d.product, d.category));
            line("PKeyConfig", &d.pkeyconfig);
        }
        if !d.product_id.is_empty() {
            line("Product ID", &d.product_id);
            line("Extended PID", &d.extended_pid);
            line("SKU ID", &d.sku_id);
            line("Description", &d.description);
            line("Edition ID", &d.edition_id);
            line("License Type", &d.key_type);
            if !d.license_note.is_empty() {
                line("License Note", &d.license_note);
            }
            line("Channel", &d.channel);
            line("Part Number", &d.part_number);
        }
        line("Crypto ID", &format!("{} (0x{})", d.crypto_id, d.crypto_id_hex));
        if let Some(serial) = d.serial {
            line("Serial", &serial.to_string());
        }
        if let Some(sec) = &d.security_value {
            line("Security Value", &format!("0x{sec}"));
        }
        if d.upgrade {
            line("Upgrade", "Yes");
        }
    }
    if let Some(a) = &r.activation {
        let count = match (a.remaining, &a.error_code) {
            (Some(n), _) => n.to_string(),
            (None, Some(code)) => format!("Not available ({code})"),
            (None, None) => "Not available".into(),
        };
        line("Activ. Count", &format!("{count}{}", if r.cached { " (cached)" } else { "" }));
        if let Some(m) = &a.error_message {
            line("Service Note", m);
        }
    } else if let Some(e) = &r.activation_error {
        line("Activ. Count", &format!("Error: {e}"));
    }

}