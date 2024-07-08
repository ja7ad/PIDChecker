//! Blocked-key database.
//!
//! Keys are stored on disk in a `redb` table keyed by their compact `u128`
//! form, with a small JSON record describing why the key is blocked. The full
//! key set is mirrored in memory, so a lookup is a single hash probe.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};

use super::key::ProductKey;

const TABLE: TableDefinition<u128, &str> = TableDefinition::new("blocked_keys");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRecord {
    /// Where the entry came from: `microsoft`, `import:<file>`, `manual`.
    pub source: String,
    /// Activation service error code, when reported by Microsoft.
    pub error_code: Option<String>,
    pub added_at: DateTime<Utc>,
}

pub struct Blocklist {
    db: Database,
    keys: RwLock<HashSet<u128>>,
}

impl Blocklist {
    /// Open (or create) the database.
    pub fn open(path: &Path) -> Result<Self> {
        let db = Database::create(path).with_context(|| format!("opening {}", path.display()))?;
        {
            let tx = db.begin_write()?;
            tx.open_table(TABLE)?;
            tx.commit()?;
        }
        let keys = {
            let tx = db.begin_read()?;
            let table = tx.open_table(TABLE)?;
            let mut set = HashSet::with_capacity(table.len()? as usize);
            for row in table.iter()? {
                set.insert(row?.0.value());
            }
            set
        };
        Ok(Self { db, keys: RwLock::new(keys) })
    }

    pub fn contains(&self, key: &ProductKey) -> bool {
        self.keys.read().contains(&key.to_u128())
    }

    pub fn get(&self, key: &ProductKey) -> Option<BlockRecord> {
        if !self.contains(key) {
            return None;
        }
        let tx = self.db.begin_read().ok()?;
        let table = tx.open_table(TABLE).ok()?;
        let row = table.get(key.to_u128()).ok()??;
        serde_json::from_str(row.value()).ok()
    }

    pub fn len(&self) -> usize {
        self.keys.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

}