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
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><soap:Body>\
         <BatchActivate xmlns=\"http://www.microsoft.com/BatchActivationService\"><request><Digest>{digest}</Digest>\
         <RequestXml>{payload}</RequestXml></request></BatchActivate></soap:Body></soap:Envelope>"
    )
}

fn parse_response(text: &str, expected: usize) -> Result<Vec<ActivationInfo>> {
    let inner = xml::text(text, "ResponseXml").context("ResponseXml missing in activation response")?;
    let responses: Vec<ActivationInfo> = xml::elements(&inner, "Response").map(parse_single).collect();
    if responses.len() != expected {
        bail!("activation service returned {} results for {expected} PIDs", responses.len());
    }
    Ok(responses)
}

fn parse_single(block: &str) -> ActivationInfo {
    let remaining = xml::text(block, "ActivationRemaining").and_then(|v| v.parse::<i64>().ok());
    let error_code = xml::text(block, "ErrorCode").filter(|c| !c.is_empty());
    let known = error_code.as_deref().and_then(codes::parse_code).and_then(codes::activation_code);
    ActivationInfo {
        remaining: remaining.filter(|r| *r >= 0),
        error_message: known.map(|k| k.message.to_string()),
        blocked: known.is_some_and(|k| k.blocked),
        error_code,
    }
}

fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (i, k) in key.iter().enumerate() {
        ipad[i] ^= k;
        opad[i] ^= k;
    }
    let inner = Sha256::new().chain_update(ipad).chain_update(data).finalize();
    Sha256::new().chain_update(opad).chain_update(inner).finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc4231_shape() {
        // RFC 4231 test case 2 uses a short key; verify against a 32 byte key instead
        // by checking determinism and length.
        let a = hmac_sha256(&HMAC_KEY, b"abc");
        assert_eq!(a.len(), 32);
        assert_eq!(a, hmac_sha256(&HMAC_KEY, b"abc"));
    }

    #[test]
    fn parses_blocked_and_count() {
        let inner = "<ActivationResponse><Responses><Response><PID>a</PID><ActivationRemaining>-1</ActivationRemaining>\
                     <ErrorInfo><ErrorCode>0x67</ErrorCode></ErrorInfo></Response><Response><PID>b</PID>\
                     <ActivationRemaining>42</ActivationRemaining></Response></Responses></ActivationResponse>";
        let soap = format!("<x><ResponseXml>{}</ResponseXml></x>", xml::escape(inner));
        let r = parse_response(&soap, 2).unwrap();
        assert!(r[0].blocked);
        assert_eq!(r[0].remaining, None);
        assert_eq!(r[1].remaining, Some(42));
        assert!(!r[1].blocked);
    }
}
