//! In-memory index of every pkeyconfig file, keyed by group id.
//!
//! The original application re-parsed every file for each key; indexing once at
//! startup turns a check into a hash lookup plus a short range scan.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Result;
use rayon::prelude::*;

use super::pkeyconfig::{normalize_guid, Configuration, KeyRange, PKeyConfig};

#[derive(Debug, Clone)]
pub struct Source {
    /// Path relative to the data directory, e.g. `windows/11/pkeyconfig.xrm-ms`.
    pub name: String,
    pub path: PathBuf,
    /// Product name from `catalog.toml` (or the directory name).
    pub product: String,
    pub category: String,
}

#[derive(Debug, serde::Deserialize)]
struct Catalog {
    #[serde(default)]
    product: Vec<CatalogProduct>,
}

#[derive(Debug, serde::Deserialize)]
struct CatalogProduct {
    name: String,
    category: String,
    dir: String,
}

#[derive(Debug, Clone)]
pub struct GroupEntry {
    pub config: Configuration,
    pub ranges: Vec<KeyRange>,
    /// Indices into [`KeyDatabase::sources`], highest priority first.
    pub sources: Vec<usize>,
}

#[derive(Debug, Default)]
pub struct KeyDatabase {
    pub sources: Vec<Source>,
    groups: HashMap<u32, Vec<GroupEntry>>,
    by_act_config: HashMap<String, (u32, usize)>,
    algorithms: HashMap<u32, String>,
    /// Minimal, ordered list of sources to try PidGenX against for legacy
    /// (`pkey2005`) keys; see [`KeyDatabase::plan_legacy`].
    pub legacy_sources: Vec<usize>,
    /// Per source: legacy (group, start, end) ranges and share of legacy groups.
    legacy_ranges: Vec<LegacyCoverage>,
    pub errors: Vec<String>,
    pub load_time: Duration,
}

/// (source index, share of legacy groups, legacy (group, start, end) ranges)
type LegacyCoverage = (usize, f32, std::collections::HashSet<(u32, u32, u32)>);

pub struct Match<'a> {
    pub entry: &'a GroupEntry,
    pub range: Option<&'a KeyRange>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DbStats {
    pub files: usize,
    pub legacy_files: usize,
    pub groups: usize,
    pub configurations: usize,
    pub errors: usize,
    pub load_ms: u128,
}

impl KeyDatabase {
    pub fn load(dir: &Path) -> Result<Self> {
        let started = Instant::now();
        let mut files = Vec::new();
        collect_files(dir, &mut files)?;
        let catalog: Catalog = match std::fs::read_to_string(dir.join("catalog.toml")) {
            Ok(text) => toml::from_str(&text)?,
            Err(_) => Catalog { product: Vec::new() },
        };
        let mut sources: Vec<(usize, Source)> = files
            .into_iter()
            .map(|path| {
                let name = path.strip_prefix(dir).unwrap_or(&path).to_string_lossy().replace('\\', "/");
                let parent = name.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
                let (rank, product, category) = match catalog.product.iter().position(|p| p.dir == parent) {
                    Some(i) => (i, catalog.product[i].name.clone(), catalog.product[i].category.clone()),
                    None => (usize::MAX, parent.to_string(), "Other".to_string()),
                };
                (rank, Source { name, path, product, category })
            })
            .collect();
        // Catalog order first; inside a product the main file before csvlk/downlevel variants.
        sources.sort_by(|(ra, a), (rb, b)| ra.cmp(rb).then_with(|| a.name.len().cmp(&b.name.len())).then_with(|| a.name.cmp(&b.name)));
        let sources: Vec<Source> = sources.into_iter().map(|(_, s)| s).collect();

        let parsed: Vec<Result<PKeyConfig>> = sources.par_iter().map(|s| PKeyConfig::load(&s.path)).collect();

        let mut db = KeyDatabase { sources, ..Default::default() };
        for (idx, result) in parsed.into_iter().enumerate() {
            match result {
                Ok(cfg) => db.merge(idx, cfg),
                Err(e) => db.errors.push(format!("{e:#}")),
            }
        }
        db.plan_legacy();
        db.load_time = started.elapsed();
        Ok(db)
    }

    fn merge(&mut self, source: usize, cfg: PKeyConfig) {
        let mut ranges: HashMap<&str, Vec<&KeyRange>> = HashMap::new();
        for r in &cfg.key_ranges {
            ranges.entry(r.ref_act_config_id.as_str()).or_default().push(r);
        }
        for pk in &cfg.public_keys {
            self.algorithms.entry(pk.group_id).or_insert_with(|| pk.algorithm.clone());
        }
        let legacy_groups: std::collections::HashSet<u32> =
            cfg.public_keys.iter().filter(|pk| pk.algorithm.ends_with("2005")).map(|pk| pk.group_id).collect();
        if !legacy_groups.is_empty() {
            let group_of: HashMap<&str, u32> =
                cfg.configurations.iter().map(|c| (c.act_config_id.as_str(), c.ref_group_id)).collect();
            let set: std::collections::HashSet<(u32, u32, u32)> = cfg
                .key_ranges
                .iter()
                .filter_map(|r| group_of.get(r.ref_act_config_id.as_str()).map(|&g| (g, r.start, r.end)))
                .filter(|(g, _, _)| legacy_groups.contains(g))
                .collect();
            let all: std::collections::HashSet<u32> = cfg.configurations.iter().map(|c| c.ref_group_id).collect();
            let configured = all.iter().filter(|g| legacy_groups.contains(g)).count();
            if !set.is_empty() {
                self.legacy_ranges.push((source, configured as f32 / all.len().max(1) as f32, set));
            }
        }
        for config in &cfg.configurations {
            let own = ranges.remove(config.act_config_id.as_str()).unwrap_or_default();
            if let Some(&(group, idx)) = self.by_act_config.get(&config.act_config_id) {
                let entry = &mut self.groups.get_mut(&group).expect("indexed group")[idx];
                if !entry.sources.contains(&source) {
                    entry.sources.push(source);
                }
                for r in own {
                    if !entry.ranges.iter().any(|e| e.start == r.start && e.end == r.end) {
                        entry.ranges.push(r.clone());
                    }
                }
                continue;
            }
            let list = self.groups.entry(config.ref_group_id).or_default();
            self.by_act_config.insert(config.act_config_id.clone(), (config.ref_group_id, list.len()));
            list.push(GroupEntry {
                config: config.clone(),
                ranges: own.into_iter().cloned().collect(),
                sources: vec![source],
            });
        }
    }

    /// Legacy keys do not expose their group, so PidGenX must try files one by
    /// one, and each call costs ~1 s (the DLL re-verifies the whole signed
    /// file). Keep only files that add legacy (group, range) coverage, trying
    /// "native" legacy products (Vista/7/Office 2010/...) first, largest first.
    /// Newer files mostly duplicate those groups for downlevel upgrades; those
    /// are kept only when they add (group, range) coverage.
    fn plan_legacy(&mut self) {
        let mut candidates = std::mem::take(&mut self.legacy_ranges);
        candidates.sort_by(|a, b| {
            let native = |x: &LegacyCoverage| x.1 >= 0.5;
            native(b)
                .cmp(&native(a))
                .then_with(|| if native(a) { b.2.len().cmp(&a.2.len()) } else { a.0.cmp(&b.0) })
        });
        // Native legacy files are always kept: PidGenX may reject a key in one
        // file and accept it in another listing the same ranges (Vista SP2 vs
        // 6002.18005). Only downlevel copies in newer files are pruned.
        let mut covered = std::collections::HashSet::new();
        for (source, share, ranges) in candidates {
            if share >= 0.5 || ranges.iter().any(|r| !covered.contains(r)) {
                covered.extend(ranges);
                self.legacy_sources.push(source);
            }
        }
    }

    /// Find the configuration and key range for a decoded pkey2009 key.
    ///
    /// Prefers a valid range, then an invalid (revoked) one, then a group-only
    /// match without any range.
    pub fn lookup(&self, group: u32, serial: u32) -> Option<Match<'_>> {
        let entries = self.groups.get(&group)?;
        let mut invalid = None;
        for entry in entries {
            for range in &entry.ranges {
                if serial >= range.start && serial <= range.end {
                    if range.is_valid {
                        return Some(Match { entry, range: Some(range) });
                    }
                    invalid.get_or_insert(Match { entry, range: Some(range) });
                }
            }
        }
        invalid.or_else(|| entries.first().map(|entry| Match { entry, range: None }))
    }

    pub fn by_act_config_id(&self, id: &str) -> Option<&GroupEntry> {
        let (group, idx) = self.by_act_config.get(&normalize_guid(id))?;
        self.groups.get(group).map(|l| &l[*idx])
    }

    pub fn algorithm(&self, group: u32) -> Option<&str> {
        self.algorithms.get(&group).map(String::as_str)
    }

    pub fn source(&self, idx: usize) -> Option<&Source> {
        self.sources.get(idx)
    }

    pub fn stats(&self) -> DbStats {
        DbStats {
            files: self.sources.len(),
            legacy_files: self.legacy_sources.len(),
            groups: self.groups.len(),
            configurations: self.by_act_config.len(),
            errors: self.errors.len(),
            load_ms: self.load_time.as_millis(),
        }
    }
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_files(&path, out)?;
        } else if matches!(
            path.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase()).as_deref(),
            Some("xrm-ms" | "xml")
        ) {
            out.push(path);
        }
    }
    Ok(())
}
