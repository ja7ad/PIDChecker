//! Remaining-activation (MAK count) lookups against Microsoft's
//! BatchActivation web service.
//!
//! The service accepts several PIDs per request, so batches are chunked into a
//! handful of SOAP calls executed concurrently, and results are cached.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::codes;
use super::xml;

const ENDPOINT: &str = "https://activation.sls.microsoft.com/BatchActivation/BatchActivation.asmx";
const SOAP_ACTION: &str = "http://www.microsoft.com/BatchActivationService/BatchActivate";
const REQUEST_NS: &str = "http://www.microsoft.com/DRM/SL/BatchActivationRequest/1.0";
/// MPC substituted into the extended PID sent to the service.
pub const MPC: &str = "55041";

const HMAC_KEY: [u8; 32] = [
    254, 49, 152, 117, 251, 72, 132, 134, 156, 243, 241, 206, 153, 168, 144, 100, 171, 87, 31, 202, 71, 4,
    80, 88, 48, 36, 226, 20, 98, 135, 121, 160,
];

#[derive(Debug, Clone, Serialize)]
pub struct ActivationInfo {
    /// Remaining activations, when the service reports them.
    pub remaining: Option<i64>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub blocked: bool,
}

pub struct MakClient {
    http: reqwest::Client,
    chunk_size: usize,
    concurrency: usize,
}

impl MakClient {
    pub fn new(timeout: Duration, chunk_size: usize, concurrency: usize) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(concat!("PIDKeyChecker/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            http,
            chunk_size: chunk_size.max(1),
            concurrency: concurrency.max(1),
        })
    }

    /// Query the remaining activation count for each extended PID, keyed by PID.
    pub async fn query(&self, pids: &[String]) -> HashMap<String, Result<ActivationInfo, String>> {
        let mut out = HashMap::new();
        let mut seen = std::collections::HashSet::new();
