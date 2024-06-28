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
        let pending: Vec<String> = pids.iter().filter(|p| seen.insert(p.as_str())).cloned().collect();

        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(self.concurrency));
        let mut tasks = tokio::task::JoinSet::new();
        for chunk in pending.chunks(self.chunk_size) {
            let (http, chunk, semaphore) = (self.http.clone(), chunk.to_vec(), semaphore.clone());
            tasks.spawn(async move {
                let _permit = semaphore.acquire_owned().await;
                let res = request(&http, &chunk).await;
                (chunk, res)
            });
        }
        let mut results = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            if let Ok(r) = joined {
                results.push(r);
            }
        }

        for (chunk, res) in results {
            match res {
                Ok(infos) => {
                    for (pid, info) in chunk.iter().zip(infos) {
                        out.insert(pid.clone(), Ok(info));
                    }
                }
                Err(e) => {
                    for pid in chunk {
                        out.insert(pid, Err(format!("{e:#}")));
                    }
                }
            }
        }
        out
    }
}

async fn request(http: &reqwest::Client, pids: &[String]) -> Result<Vec<ActivationInfo>> {
    let resp = http
        .post(ENDPOINT)
        .header("Content-Type", "text/xml; charset=\"utf-8\"")
        .header("SOAPAction", SOAP_ACTION)
        .body(build_envelope(pids))
        .send()
        .await
        .context("activation service unreachable")?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        bail!("activation service returned HTTP {status}");
    }
    parse_response(&text, pids.len())
}

fn build_envelope(pids: &[String]) -> String {
    let mut request = format!(
        "<ActivationRequest xmlns=\"{REQUEST_NS}\"><VersionNumber>2.0</VersionNumber><RequestType>2</RequestType><Requests>"
    );
    for pid in pids {
        request.push_str("<Request><PID>");
        request.push_str(&xml::escape(pid));
        request.push_str("</PID></Request>");
    }
    request.push_str("</Requests></ActivationRequest>");

    // The service expects the request as UTF-16LE bytes (.NET Encoding.Unicode).
    let bytes: Vec<u8> = request.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let b64 = base64::engine::general_purpose::STANDARD;
    let digest = b64.encode(hmac_sha256(&HMAC_KEY, &bytes));
    let payload = b64.encode(&bytes);

}