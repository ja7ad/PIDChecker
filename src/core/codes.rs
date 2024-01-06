//! Known error codes: the BatchActivation web service codes, plus the
//! Windows / Office activation and licensing HRESULTs documented in
//! Microsoft's support articles (`docs/activation-error-codes.json`, embedded
//! at build time).

use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorCode {
    #[serde(deserialize_with = "de_code", serialize_with = "ser_code")]
    pub code: u32,
    pub name: Option<String>,
    pub message: String,
    #[serde(default)]
    pub cause: Option<String>,
    #[serde(default)]
    pub resolution: Option<String>,
    /// key_invalid, key_blocked, mak_limit, kms, network, licensing_service, sku_mismatch, other
    pub category: String,
    /// The key is permanently unusable (blocked / revoked) when this code is returned.
    pub blocked: bool,
    #[serde(default)]
    pub source: Option<String>,
}

fn de_code<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u32, D::Error> {
    let s = String::deserialize(d)?;
    parse_code(&s).ok_or_else(|| serde::de::Error::custom(format!("bad code {s}")))
}

fn ser_code<S: serde::Serializer>(code: &u32, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format_code(*code))
}

fn service(code: u32, name: &str, message: &str, category: &str, blocked: bool) -> ErrorCode {
    ErrorCode {
        code,
        name: Some(name.into()),
        message: message.into(),
        cause: None,
        resolution: None,
        category: category.into(),
        blocked,
        source: Some("BatchActivation service".into()),
    }
}

/// `ErrorCode` values returned per PID by the BatchActivation web service.
