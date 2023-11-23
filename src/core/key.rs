//! Product key decoding.
//!
//! Windows 8+ / Office 2013+ keys use the `pkey2009` scheme: the 25 characters
//! encode a 115 bit number (one `N` marks the position of the most significant
//! base-24 digit). The number contains:
//!
//! | bits      | field          |
//! |-----------|----------------|
//! | 0..20     | group id       |
//! | 20..50    | serial         |
//! | 50..103   | security value |
//! | 103..113  | checksum       |
//! | 113       | upgrade flag   |
//! | 114       | `N` flag       |
//!
//! The checksum is the low 10 bits of `!crc32_mpeg2` over the 16 byte little
//! endian value with the checksum and `N` bits cleared.

use serde::Serialize;

pub const ALPHABET: &[u8; 24] = b"BCDFGHJKMPQRTVWXY2346789";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyFormat {
    /// Windows 8+ / Office 2013+ keys (contain one `N`).
    Pkey2009,
    /// Vista / 7 / Office 2010 era keys (no `N`).
    Pkey2005,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyParseError {
    #[error("key must contain 25 characters (got {0})")]
    Length(usize),
    #[error("invalid character '{0}' in key")]
    InvalidChar(char),
    #[error("key contains more than one 'N'")]
    MultipleN,
}

/// A syntactically valid product key in canonical `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX` form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProductKey {
    chars: [u8; 25],
}

impl ProductKey {
    pub fn parse(input: &str) -> Result<Self, KeyParseError> {
        let mut chars = [0u8; 25];
        let mut len = 0usize;
        let mut n_count = 0;
        for c in input.chars() {
            if c == '-' || c.is_whitespace() {
                continue;
            }
            let u = c.to_ascii_uppercase();
            if u == 'N' {
                n_count += 1;
                if n_count > 1 {
                    return Err(KeyParseError::MultipleN);
                }
            } else if !u.is_ascii() || !ALPHABET.contains(&(u as u8)) {
                return Err(KeyParseError::InvalidChar(c));
            }
            if len < 25 {
                chars[len] = u as u8;
            }
            len += 1;
        }
        if len != 25 {
            return Err(KeyParseError::Length(len));
        }
        Ok(Self { chars })
    }


}