//! Parsing of `pkeyconfig*.xrm-ms` license files.

use std::path::Path;

use anyhow::{Context, Result};
use base64::Engine;
use serde::Serialize;

use super::xml;

#[derive(Debug, Clone, Serialize)]
pub struct Configuration {
    pub act_config_id: String,
    pub ref_group_id: u32,
    pub edition_id: String,
    pub description: String,
    pub key_type: String,
    pub is_randomized: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyRange {
    pub ref_act_config_id: String,
    pub part_number: String,
    pub eula_type: String,
    pub is_valid: bool,
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicKey {
    pub group_id: u32,
    pub algorithm: String,
}

#[derive(Debug, Clone, Default)]
pub struct PKeyConfig {
    pub configurations: Vec<Configuration>,
    pub key_ranges: Vec<KeyRange>,
    pub public_keys: Vec<PublicKey>,
}

/// Normalises an ActConfigId to lowercase `{guid}` form.
pub fn normalize_guid(id: &str) -> String {
    let id = id.trim().trim_start_matches('{').trim_end_matches('}');
    format!("{{{}}}", id.to_ascii_lowercase())
}

impl PKeyConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let doc = decode_text(&bytes);
        Self::parse_license(&doc).with_context(|| format!("parsing {}", path.display()))
    }

    /// Parse the outer XrML license, extracting the embedded base64 config.
    pub fn parse_license(doc: &str) -> Result<Self> {
        const MARKER: &str = "name=\"pkeyConfigData\">";
        let start = doc.find(MARKER).context("pkeyConfigData not found")? + MARKER.len();
