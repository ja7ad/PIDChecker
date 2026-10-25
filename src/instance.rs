//! Single-instance guard.
//!
//! The GUI and `serve` both own the blocked-keys database, which only one
//! process may open, so at most one of them runs per data folder. The guard is
//! an exclusive OS file lock on `pidkeychecker.lock` next to `config.toml`; the
//! OS releases it when the process exits, even after a crash.
//!
//! Windows locks are mandatory (other processes cannot even read a locked
//! file), so the owner description lives in a separate, unlocked
//! `pidkeychecker.owner` file.

use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

pub const FILE_NAME: &str = "pidkeychecker.lock";
pub const OWNER_FILE: &str = "pidkeychecker.owner";

/// Description of the process holding (or that last held) the lock in `dir`.
pub fn owner(dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(dir.join(OWNER_FILE)).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

pub struct InstanceLock {
    _file: File,
    pub path: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("PID Key Checker is already running ({owner}); lock file {path}")]
    AlreadyRunning { owner: String, path: PathBuf },
    #[error("cannot open lock file {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
}

/// Acquire the lock for `dir`, recording who holds it (e.g. "gui", "serve").
pub fn acquire(dir: &Path, role: &str) -> Result<InstanceLock, LockError> {
    let path = dir.join(FILE_NAME);
    let io = |source| LockError::Io { path: path.clone(), source };
    let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&path).map_err(io)?;
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => {
            return Err(LockError::AlreadyRunning { owner: owner(dir).unwrap_or_else(|| "unknown process".into()), path });
        }
        Err(TryLockError::Error(e)) => return Err(io(e)),
    }
    // Record the owner for the error message other instances show.
    let info = format!("{role}, pid {}, started {}", std::process::id(), chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
    std::fs::write(dir.join(OWNER_FILE), info).map_err(io)?;
    Ok(InstanceLock { _file: file, path })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_lock_fails_until_released() {
        let dir = std::env::temp_dir().join(format!("pkc-lock-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let first = acquire(&dir, "gui").unwrap();
        match acquire(&dir, "serve") {
            Err(LockError::AlreadyRunning { owner, .. }) => assert!(owner.starts_with("gui, pid")),
            other => panic!("expected AlreadyRunning, got {:?}", other.map(|_| ())),
        }
        drop(first);
        assert!(acquire(&dir, "serve").is_ok());
        std::fs::remove_dir_all(dir).ok();
    }
}
