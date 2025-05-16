//! Opaque API keys for the REST server.
//!
//! Tokens look like `pkc_<43 base62 chars>` (256 bits of entropy). Only the
//! SHA-256 hash is persisted; the plaintext is shown once at creation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PREFIX: &str = "pkc_";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// May check keys.
    #[default]
    User,
    /// May also manage API keys.
    Admin,
}

impl Role {
    pub const ALL: [Role; 2] = [Role::User, Role::Admin];
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Role::User => "user",
            Role::Admin => "admin",
        })
    }
}

impl std::str::FromStr for Role {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "user" => Ok(Role::User),
            "admin" => Ok(Role::Admin),
            _ => bail!("unknown role '{s}' (expected user or admin)"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub name: String,
    pub role: Role,
    /// First characters of the token, for identification in listings.
    pub prefix: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub requests: u64,
    #[serde(default)]
    pub revoked: bool,
    /// Per-key override of `rate_limit.requests_per_minute`.
    #[serde(default)]
    pub rate_limit_per_minute: Option<u32>,
}

impl ApiKey {
    pub fn is_active(&self) -> bool {
        !self.revoked && self.expires_at.is_none_or(|e| e > Utc::now())
    }

    /// Copy without the hash, for API responses.
    pub fn public(&self) -> ApiKey {
        ApiKey { hash: String::new(), ..self.clone() }
    }
}

#[derive(Default, Serialize, Deserialize)]
struct StoreFile {
    keys: Vec<ApiKey>,
}

pub struct ApiKeyStore {
    path: PathBuf,
    inner: RwLock<Inner>,
}

#[derive(Default)]
struct Inner {
    keys: Vec<ApiKey>,
    by_hash: HashMap<String, usize>,
    dirty: bool,
}

impl Inner {
    fn reindex(&mut self) {
        self.by_hash = self.keys.iter().enumerate().map(|(i, k)| (k.hash.clone(), i)).collect();
    }
}

fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn generate_token() -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut out = String::from(PREFIX);
    // Rejection sampling keeps the distribution uniform.
    while out.len() < PREFIX.len() + 43 {
        let mut buf = [0u8; 64];
        rand::fill(&mut buf);
        for b in buf {
            if (b as usize) < ALPHABET.len() * 4 && out.len() < PREFIX.len() + 43 {
                out.push(ALPHABET[b as usize % ALPHABET.len()] as char);
            }
        }
    }
    out
}

impl ApiKeyStore {
    pub fn open(path: &Path) -> Result<Self> {
        let mut inner = Inner::default();
        if path.exists() {
            let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
            let file: StoreFile = serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
            inner.keys = file.keys;
            inner.reindex();
        }
        Ok(Self { path: path.to_path_buf(), inner: RwLock::new(inner) })
    }

    fn persist(&self, inner: &mut Inner) -> Result<()> {
        let file = StoreFile { keys: inner.keys.clone() };
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&file)?)?;
        std::fs::rename(&tmp, &self.path)?;
        inner.dirty = false;
        Ok(())
    }

    /// Create a key. Returns the record and the plaintext token (shown once).
    pub fn create(&self, name: &str, role: Role, expires_in_days: Option<u32>) -> Result<(ApiKey, String)> {
        let name = name.trim();
        if name.is_empty() {
            bail!("name must not be empty");
        }
        let token = generate_token();
        let now = Utc::now();
        let key = ApiKey {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            role,
            prefix: token[..PREFIX.len() + 6].to_string(),
            hash: hash_token(&token),

}