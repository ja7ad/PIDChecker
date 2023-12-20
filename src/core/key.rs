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

    pub fn format(&self) -> KeyFormat {
        if self.chars.contains(&b'N') {
            KeyFormat::Pkey2009
        } else {
            KeyFormat::Pkey2005
        }
    }

    /// Canonical dashed representation.
    pub fn as_string(&self) -> String {
        let mut s = String::with_capacity(29);
        for (i, c) in self.chars.iter().enumerate() {
            if i > 0 && i % 5 == 0 {
                s.push('-');
            }
            s.push(*c as char);
        }
        s
    }

    /// Compact, lossless numeric form (base 25 over the alphabet plus `N`),
    /// used as the blocklist database key.
    pub fn to_u128(&self) -> u128 {
        self.chars.iter().fold(0u128, |acc, &c| {
            let idx = ALPHABET.iter().position(|&a| a == c).unwrap_or(24) as u128;
            acc * 25 + idx
        })
    }

    pub fn from_u128(mut v: u128) -> Self {
        let mut chars = [0u8; 25];
        for c in chars.iter_mut().rev() {
            let idx = (v % 25) as usize;
            *c = if idx == 24 { b'N' } else { ALPHABET[idx] };
            v /= 25;
        }
        Self { chars }
    }

    /// Last five characters, as shown by Windows ("Partial Product Key").
    pub fn partial(&self) -> String {
        String::from_utf8_lossy(&self.chars[20..]).into_owned()
    }

    /// Decode a `pkey2009` key. Returns `None` for legacy keys.
    pub fn decode(&self) -> Option<DecodedKey> {
        let n_pos = self.chars.iter().position(|&c| c == b'N')?;
        let mut value: u128 = n_pos as u128;
        for (i, &c) in self.chars.iter().enumerate() {
            if i == n_pos {
                continue;
            }
            let idx = ALPHABET.iter().position(|&a| a == c)? as u128;
            value = value * 24 + idx;
        }
        Some(DecodedKey::from_raw(value))
    }
}

/// Find every well-formed product key embedded in arbitrary text (logs,
/// e-mails, web pages), in order of appearance and without duplicates.
///
/// A key is five groups of five key characters separated by `-`, bounded by
/// characters that cannot belong to a key.
pub fn find_keys(text: &str) -> Vec<ProductKey> {
    fn is_key_char(c: u8) -> bool {
        c == b'N' || ALPHABET.contains(&c)
    }
    let bytes: Vec<u8> = text.bytes().map(|b| b.to_ascii_uppercase()).collect();
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut i = 0;
    while i + 29 <= bytes.len() {
        let boundary_before = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        let window = &bytes[i..i + 29];
        let shape_ok = window.iter().enumerate().all(|(j, &c)| if j % 6 == 5 { c == b'-' } else { is_key_char(c) });
        let boundary_after = bytes.get(i + 29).is_none_or(|c| !c.is_ascii_alphanumeric());
        if boundary_before && shape_ok && boundary_after
            && let Ok(key) = ProductKey::parse(std::str::from_utf8(window).unwrap_or_default()) {
                if seen.insert(key.clone()) {
                    out.push(key);
                }
                i += 29;
                continue;
            }
        i += 1;
    }
    out
}

impl std::fmt::Display for ProductKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DecodedKey {
    pub group: u32,
    pub serial: u32,
    pub security: u64,
    pub checksum: u16,
    pub upgrade: bool,
    pub checksum_valid: bool,
}

const CHECKSUM_SHIFT: u32 = 103;
const CHECKSUM_MASK: u128 = 0x3ff;

impl DecodedKey {
    fn from_raw(value: u128) -> Self {
        let checksum = ((value >> CHECKSUM_SHIFT) & CHECKSUM_MASK) as u16;
        Self {
            group: (value & 0xfffff) as u32,
            serial: ((value >> 20) & 0x3fff_ffff) as u32,
            security: ((value >> 50) & ((1u128 << 53) - 1)) as u64,
            checksum,
            upgrade: (value >> 113) & 1 == 1,
            checksum_valid: compute_checksum(value) == checksum,
        }
    }

    fn raw_without_checksum(&self) -> u128 {
        (self.group as u128)
            | ((self.serial as u128) << 20)
            | ((self.security as u128) << 50)
            | ((self.upgrade as u128) << 113)
    }

    /// Re-encode into a product key (used for tests and round-tripping).
    pub fn encode(&self) -> ProductKey {
        let base = self.raw_without_checksum();
        let mut value = base | ((compute_checksum(base) as u128) << CHECKSUM_SHIFT);
        let mut digits = [0u8; 25];
        for d in digits.iter_mut().rev() {
            *d = (value % 24) as u8;
            value /= 24;
        }
        let n_pos = digits[0] as usize;
        let mut out = Vec::with_capacity(25);
        for &d in &digits[1..] {
            out.push(ALPHABET[d as usize]);
        }
        out.insert(n_pos, b'N');
        let mut chars = [0u8; 25];
        chars.copy_from_slice(&out);
        ProductKey { chars }
    }

    /// Short product ID, e.g. `00330-80000-00000-AAxxx`.
    ///
    /// The trailing three digits are installation specific and cannot be
    /// derived from the key alone.
    pub fn product_id(&self) -> String {
        let digits = format!("{:06}{:09}", self.group, self.serial);
        format!("{}-{}-{}-AAxxx", &digits[0..5], &digits[5..10], &digits[10..15])
    }

    /// Extended PID in the same layout PidGenX produces.
    pub fn extended_pid(&self, mpc: &str) -> String {
        let now = chrono::Utc::now();
        use chrono::Datelike;
        format!(
            "{mpc}-{:05}-{:03}-{:06}-03-1033-9200.0000-{:03}{}",
            self.group,
            self.serial / 1_000_000,
            self.serial % 1_000_000,
            now.ordinal(),
            now.year()
        )
    }
}

fn compute_checksum(value: u128) -> u16 {
    let cleared = value & !(CHECKSUM_MASK << CHECKSUM_SHIFT) & !(1u128 << 114);
    (!crc32_mpeg2(&cleared.to_le_bytes()) & 0x3ff) as u16
}

const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = (i as u32) << 24;
        let mut j = 0;
        while j < 8 {
            c = if c & 0x8000_0000 != 0 { (c << 1) ^ 0x04C1_1DB7 } else { c << 1 };
            j += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

fn crc32_mpeg2(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = (crc << 8) ^ CRC_TABLE[(((crc >> 24) as u8) ^ b) as usize];
    }
