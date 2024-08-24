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
static SERVICE_CODES: LazyLock<Vec<ErrorCode>> = LazyLock::new(|| {
    vec![
        service(0x67, "KEY_BLOCKED", "The product key has been blocked by Microsoft", "key_blocked", true),
        service(0x68, "INVALID_KEY", "The product key is not valid for this service", "key_invalid", false),
        service(0x86, "INVALID_KEY_TYPE", "The key type is not supported by this service (not a MAK)", "key_invalid", false),
        service(0x90, "CHECK_PID", "The request could not be validated; check the PID", "other", false),
    ]
});

/// HRESULTs documented by Microsoft (licensing-and-activation support articles).
static DOC_CODES: LazyLock<Vec<ErrorCode>> = LazyLock::new(|| {
    let mut codes: Vec<ErrorCode> =
        serde_json::from_str(include_str!("../../docs/activation-error-codes.json")).expect("embedded error code table");
    // PidGenX results are not covered by the articles.
    codes.push(ErrorCode {
        code: 0x8A01_0101,
        name: Some("PGX_MALFORMEDKEY".into()),
        message: "PidGenX rejected the product key".into(),
        cause: Some("The key does not belong to the pkeyconfig it was checked against.".into()),
        resolution: None,
        category: "key_invalid".into(),
        blocked: false,
        source: Some("pidgenx.dll".into()),
    });
    codes
});

/// Parse `0x67`, `67h`, `C004C003`, `0xC004C003` or a decimal/negative HRESULT.
pub fn parse_code(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).or_else(|| s.strip_suffix(['h', 'H'])) {
        return u32::from_str_radix(hex, 16).ok();
    }
    if let Ok(n) = s.parse::<i64>() {
        return Some(n as u32);
    }
    u32::from_str_radix(s, 16).ok()
}

pub fn activation_code(code: u32) -> Option<&'static ErrorCode> {
    SERVICE_CODES.iter().find(|c| c.code == code)
}

/// Look up any known code; service codes take precedence for small values.
pub fn lookup(s: &str) -> Option<&'static ErrorCode> {
    let code = parse_code(s)?;
    activation_code(code).or_else(|| DOC_CODES.iter().find(|c| c.code == code))
}

/// Every known code, service codes first.
pub fn all() -> impl Iterator<Item = &'static ErrorCode> {
    SERVICE_CODES.iter().chain(DOC_CODES.iter())
}

pub fn format_code(code: u32) -> String {
    if code <= 0xFFFF { format!("0x{code:X}") } else { format!("0x{code:08X}") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_codes() {
        assert_eq!(parse_code("0x67"), Some(0x67));
        assert_eq!(parse_code("C004C003"), Some(0xC004C003));
        assert_eq!(parse_code("-1073430525"), Some(0xC004C003));
        assert!(lookup("0x67").unwrap().blocked);
        assert!(lookup("0xC004C003").unwrap().blocked);
        assert!(lookup("0xC004F051").unwrap().blocked);
        assert!(!lookup("0xC004C020").unwrap().blocked);
        assert!(all().count() > 40);
    }
}
