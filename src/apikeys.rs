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
            created_at: now,
            expires_at: expires_in_days.filter(|d| *d > 0).map(|d| now + chrono::Duration::days(d as i64)),
            last_used_at: None,
            requests: 0,
            revoked: false,
            rate_limit_per_minute: None,
        };
        let mut inner = self.inner.write();
        inner.keys.push(key.clone());
        inner.reindex();
        self.persist(&mut inner)?;
        Ok((key.public(), token))
    }

    /// Validate a presented token and record its use.
    pub fn authenticate(&self, token: &str) -> Option<ApiKey> {
        if !token.starts_with(PREFIX) {
            return None;
        }
        let hash = hash_token(token);
        let mut inner = self.inner.write();
        let idx = *inner.by_hash.get(&hash)?;
        let key = &mut inner.keys[idx];
        if !key.is_active() {
            return None;
        }
        key.last_used_at = Some(Utc::now());
        key.requests += 1;
        let out = key.public();
        inner.dirty = true;
        Some(out)
    }

    /// Look up an active key without recording usage.
    pub fn find(&self, token: &str) -> Option<ApiKey> {
        let inner = self.inner.read();
        let idx = *inner.by_hash.get(&hash_token(token))?;
        Some(&inner.keys[idx]).filter(|k| k.is_active()).map(ApiKey::public)
    }

    pub fn set_rate_limit(&self, id: &str, per_minute: Option<u32>) -> Result<bool> {
        let mut inner = self.inner.write();
        let Some(k) = inner.keys.iter_mut().find(|k| k.id == id) else { return Ok(false) };
        k.rate_limit_per_minute = per_minute.filter(|v| *v > 0);
        self.persist(&mut inner)?;
        Ok(true)
    }

    pub fn list(&self) -> Vec<ApiKey> {
        self.inner.read().keys.iter().map(ApiKey::public).collect()
    }

    pub fn has_active_keys(&self) -> bool {
        self.inner.read().keys.iter().any(ApiKey::is_active)
    }

    pub fn revoke(&self, id: &str) -> Result<bool> {
        let mut inner = self.inner.write();
        let Some(k) = inner.keys.iter_mut().find(|k| k.id == id) else { return Ok(false) };
        k.revoked = true;
        self.persist(&mut inner)?;
        Ok(true)
    }

    pub fn delete(&self, id: &str) -> Result<bool> {
        let mut inner = self.inner.write();
        let before = inner.keys.len();
        inner.keys.retain(|k| k.id != id);
        if inner.keys.len() == before {
            return Ok(false);
        }
        inner.reindex();
        self.persist(&mut inner)?;
        Ok(true)
    }

    /// Persist usage statistics if they changed (called periodically).
    pub fn flush(&self) -> Result<()> {
        let mut inner = self.inner.write();
        if inner.dirty {
            self.persist(&mut inner)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_authenticate_revoke() {
        let dir = std::env::temp_dir().join(format!("pkc-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = ApiKeyStore::open(&dir.join("keys.json")).unwrap();
        let (rec, token) = store.create("ci", Role::Admin, None).unwrap();
        assert!(token.starts_with(PREFIX) && token.len() == PREFIX.len() + 43);
        assert_eq!(store.authenticate(&token).unwrap().id, rec.id);
        assert!(store.authenticate("pkc_wrong").is_none());
        store.revoke(&rec.id).unwrap();
        assert!(store.authenticate(&token).is_none());
        // Reload from disk.
        let reopened = ApiKeyStore::open(&dir.join("keys.json")).unwrap();
        assert_eq!(reopened.list().len(), 1);
        std::fs::remove_dir_all(dir).ok();
    }
}
