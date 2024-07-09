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

    /// Insert many keys in a single transaction. Returns how many were new.
    pub fn insert_many<'a>(&self, keys: impl IntoIterator<Item = &'a ProductKey>, record: &BlockRecord) -> Result<usize> {
        let json = serde_json::to_string(record)?;
        let mut added = HashSet::new();
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(TABLE)?;
            let known = self.keys.read();
            for key in keys {
                let id = key.to_u128();
                if !known.contains(&id) && added.insert(id) {
                    table.insert(id, json.as_str())?;
                }
            }
        }
        tx.commit()?;
        let n = added.len();
        self.keys.write().extend(added);
        Ok(n)
    }

    pub fn insert(&self, key: &ProductKey, record: &BlockRecord) -> Result<bool> {
        Ok(self.insert_many([key], record)? == 1)
    }

    pub fn remove(&self, key: &ProductKey) -> Result<bool> {
        Ok(self.remove_many([key])? == 1)
    }

    /// Remove many keys in a single transaction. Returns how many existed.
    pub fn remove_many<'a>(&self, keys: impl IntoIterator<Item = &'a ProductKey>) -> Result<usize> {
        let mut removed = Vec::new();
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(TABLE)?;
            for key in keys {
                let id = key.to_u128();
                if table.remove(id)?.is_some() {
                    removed.push(id);
                }
            }
        }
        tx.commit()?;
        let mut set = self.keys.write();
        for id in &removed {
            set.remove(id);
        }
        Ok(removed.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_lookup_persist() {
        let dir = std::env::temp_dir().join(format!("pkc-bl-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("b.redb");
        {
            let bl = Blocklist::open(&db).unwrap();
            assert!(bl.is_empty());
            let k = ProductKey::parse("VK7JG-NPHTM-C97JM-9MPGT-3V66T").unwrap();
            assert!(!bl.contains(&k));
            let rec = BlockRecord { source: "microsoft".into(), error_code: Some("0x67".into()), added_at: Utc::now() };
            assert!(bl.insert(&k, &rec).unwrap());
            assert!(!bl.insert(&k, &rec).unwrap());
            assert_eq!(bl.get(&k).unwrap().error_code.as_deref(), Some("0x67"));
        }
        let bl = Blocklist::open(&db).unwrap();
        assert_eq!(bl.len(), 1);
        std::fs::remove_dir_all(dir).ok();
    }
}
