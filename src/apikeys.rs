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

}