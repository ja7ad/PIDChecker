//! PID Key Checker: offline Microsoft product key validation, MAK count and
//! blocked-key lookups, exposed through a CLI, a REST API and an Iced GUI.

pub mod apikeys;
pub mod cli;
pub mod config;
pub mod core;
#[cfg(feature = "gui")]
pub mod gui;
pub mod instance;
pub mod ratelimit;
pub mod server;
pub mod system;

use std::sync::Arc;

use anyhow::Result;

/// Shared services used by the GUI, the server and the CLI.
pub struct Services {
    pub config: config::Config,
    pub checker: Arc<core::checker::Checker>,
    pub keys: Arc<apikeys::ApiKeyStore>,
}

impl Services {
    pub fn load(config: config::Config) -> Result<Self> {
        let checker = Arc::new(core::checker::Checker::new(&config.checker_resolved())?);
        let keys = Arc::new(apikeys::ApiKeyStore::open(&config.keys_file())?);
        Ok(Self { config, checker, keys })
    }
}

// Step 106

// Step 107
