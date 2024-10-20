//! Single-instance guard.
//!
//! The GUI and `serve` both own the blocked-keys database, which only one
//! process may open, so at most one of them runs per data folder. The guard is
//! an exclusive OS file lock on `pidkeychecker.lock` next to `config.toml`; the
//! OS releases it when the process exits, even after a crash.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

pub const FILE_NAME: &str = "pidkeychecker.lock";

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
    let mut file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&path).map_err(io)?;
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => {
            let mut owner = String::new();
            let _ = file.read_to_string(&mut owner);
            let owner = owner.trim();
            return Err(LockError::AlreadyRunning {
                owner: if owner.is_empty() { "unknown process".into() } else { owner.to_string() },
                path,
            });
        }
        Err(TryLockError::Error(e)) => return Err(io(e)),
    }
    // Record the owner for the error message other instances show.

}