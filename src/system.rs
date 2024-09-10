//! Windows licensing integration: installed licenses (SPP / OSPP via WMI) and
//! installing / activating a key, mirroring the original tool's buttons.

#[cfg(not(windows))]
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InstalledLicense {
    pub name: String,
    pub description: String,
    pub sku_id: String,
    pub partial_key: String,
    pub channel: String,
    pub status: String,
    pub grace_minutes: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Windows,
    Office,
}

pub fn license_status(code: u32) -> &'static str {
    match code {
        0 => "Unlicensed",
        1 => "Licensed (activated)",
        2 => "Initial grace period",
        3 => "Additional grace period",
        4 => "Non-genuine grace period",
        5 => "Notification (needs activation)",
        6 => "Extended grace period",
        _ => "Unknown",
    }
}

#[cfg(windows)]
mod imp {
    use std::os::windows::process::CommandExt;
    use std::path::PathBuf;
    use std::process::Command;

    use anyhow::{bail, Context, Result};
    use serde::Deserialize;

    use super::{license_status, InstalledLicense, Target};

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Row {
        name: Option<String>,
        description: Option<String>,
        #[serde(rename = "ID")]
        id: Option<String>,
        partial_product_key: Option<String>,
        product_key_channel: Option<String>,
        license_status: Option<u32>,
        grace_period_remaining: Option<u32>,
    }

    fn run(program: &str, args: &[&str]) -> Result<String> {
        let out = Command::new(program)
            .args(args)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .with_context(|| format!("running {program}"))?;
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        Ok(text)
    }

    fn query(class: &str) -> Result<Vec<InstalledLicense>> {
        let script = format!(
            "Get-CimInstance -ClassName {class} -Filter \"PartialProductKey IS NOT NULL\" -ErrorAction SilentlyContinue | \
             Select-Object Name,Description,ID,PartialProductKey,ProductKeyChannel,LicenseStatus,GracePeriodRemaining | \
             ConvertTo-Json -Compress"
        );
        let out = run("powershell.exe", &["-NoProfile", "-NonInteractive", "-Command", &script])?;
        let out = out.trim();
        if out.is_empty() {
            return Ok(Vec::new());
        }
        // A single object is not wrapped in an array.
        let rows: Vec<Row> = if out.starts_with('[') {
            serde_json::from_str(out)?
        } else {
            vec![serde_json::from_str(out)?]

}