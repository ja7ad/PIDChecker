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