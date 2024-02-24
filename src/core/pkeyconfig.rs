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
        let len = doc[start..].find('<').context("unterminated pkeyConfigData")?;
        let b64: String = doc[start..start + len].chars().filter(|c| !c.is_whitespace()).collect();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .context("invalid base64 in pkeyConfigData")?;
        Ok(Self::parse_config(&decode_text(&raw)))
    }

    /// Parse the inner `ProductKeyConfiguration` document.
    pub fn parse_config(doc: &str) -> Self {
        let doc = &*xml::strip_prefixes(doc);
        let section = |name: &str| xml::element(doc, name).unwrap_or("");
        let field = |block: &str, name: &str| xml::text(block, name).unwrap_or_default();
        let number = |block: &str, name: &str| field(block, name).parse::<u32>().unwrap_or(0);
        let flag = |block: &str, name: &str| field(block, name).eq_ignore_ascii_case("true");

        let configurations = xml::elements(section("Configurations"), "Configuration")
            .map(|b| Configuration {
                act_config_id: normalize_guid(&field(b, "ActConfigId")),
                ref_group_id: number(b, "RefGroupId"),
                edition_id: field(b, "EditionId"),
                description: field(b, "ProductDescription"),
                key_type: field(b, "ProductKeyType"),
                is_randomized: flag(b, "IsRandomized"),
            })
            .collect();
        let key_ranges = xml::elements(section("KeyRanges"), "KeyRange")
            .map(|b| KeyRange {
                ref_act_config_id: normalize_guid(&field(b, "RefActConfigId")),
                part_number: field(b, "PartNumber"),
                eula_type: field(b, "EulaType"),
                is_valid: flag(b, "IsValid"),
                start: number(b, "Start"),
                end: number(b, "End"),
            })
            .collect();
        let public_keys = xml::elements(section("PublicKeys"), "PublicKey")
            .map(|b| PublicKey { group_id: number(b, "GroupId"), algorithm: field(b, "AlgorithmId") })
            .collect();
        Self { configurations, key_ranges, public_keys }
    }
}

/// Decode UTF-8 (with or without BOM) or UTF-16 LE/BE text.
fn decode_text(bytes: &[u8]) -> String {
    match bytes {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, u16::from_le_bytes),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, u16::from_be_bytes),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

fn utf16(bytes: &[u8], f: fn([u8; 2]) -> u16) -> String {
    let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|c| f([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_inner_config() {
        let doc = r#"<ProductKeyConfiguration><Configurations><Configuration>
            <ActConfigId>{ABC}</ActConfigId><RefGroupId>3308</RefGroupId><EditionId>Professional</EditionId>
            <ProductDescription>Win 10 RTM Professional Retail</ProductDescription><ProductKeyType>Retail</ProductKeyType>
            <IsRandomized>false</IsRandomized></Configuration></Configurations>
            <KeyRanges><KeyRange><RefActConfigId>{abc}</RefActConfigId><PartNumber>X</PartNumber><EulaType>Retail</EulaType>
            <IsValid>true</IsValid><Start>0</Start><End>10</End></KeyRange></KeyRanges>
            <PublicKeys><PublicKey><GroupId>3308</GroupId><AlgorithmId>msft:rm/algorithm/pkey/2009</AlgorithmId></PublicKey></PublicKeys>
            </ProductKeyConfiguration>"#;
        let c = PKeyConfig::parse_config(doc);
        assert_eq!(c.configurations[0].act_config_id, "{abc}");
        assert_eq!(c.configurations[0].ref_group_id, 3308);
        assert_eq!(c.key_ranges[0].end, 10);
        assert!(c.key_ranges[0].is_valid);
        assert_eq!(c.public_keys[0].group_id, 3308);
    }
}
