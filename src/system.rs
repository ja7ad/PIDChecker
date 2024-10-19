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
        };
        Ok(rows
            .into_iter()
            .map(|r| InstalledLicense {
                name: r.name.unwrap_or_default(),
                description: r.description.unwrap_or_default(),
                sku_id: r.id.unwrap_or_default(),
                partial_key: r.partial_product_key.unwrap_or_default(),
                channel: r.product_key_channel.unwrap_or_default(),
                status: license_status(r.license_status.unwrap_or(99)).to_string(),
                grace_minutes: r.grace_period_remaining.unwrap_or(0),
            })
            .collect())
    }

    pub fn installed_licenses() -> Result<Vec<InstalledLicense>> {
        let mut all = query("SoftwareLicensingProduct")?;
        // Office 2010 / 2013 on Windows 7 use the separate OSPP service.
        all.extend(query("OfficeSoftwareProtectionProduct").unwrap_or_default());
        Ok(all)
    }

    fn system32() -> PathBuf {
        PathBuf::from(std::env::var_os("WINDIR").unwrap_or_else(|| "C:\\Windows".into())).join("System32")
    }

    fn ospp_vbs() -> Option<PathBuf> {
        let roots = [std::env::var_os("ProgramFiles"), std::env::var_os("ProgramFiles(x86)")];
        for root in roots.into_iter().flatten() {
            for sub in ["Microsoft Office\\Office16", "Microsoft Office\\root\\Office16", "Microsoft Office\\Office15", "Microsoft Office\\Office14"] {
                let p = PathBuf::from(&root).join(sub).join("OSPP.VBS");
                if p.exists() {
                    return Some(p);
                }
            }
        }
        None
    }

    /// Install the key and request online activation. Requires elevation.
    pub fn install_and_activate(key: &str, target: Target) -> Result<String> {
        let cscript = system32().join("cscript.exe");
        let cscript = cscript.to_string_lossy();
        let (script, install, activate) = match target {
            Target::Windows => (system32().join("slmgr.vbs"), format!("/ipk {key}"), "/ato".to_string()),
            Target::Office => {
                let Some(p) = ospp_vbs() else { bail!("Office (OSPP.VBS) was not found") };
                (p, format!("/inpkey:{key}"), "/act".to_string())
            }
        };
        let script = script.to_string_lossy();
        let mut log = run(&cscript, &["//nologo", &script, &install])?;
        log.push('\n');
        log.push_str(&run(&cscript, &["//nologo", &script, &activate])?);
        Ok(log)
    }

    /// Detailed license information (`slmgr /dlv`).
    pub fn license_details() -> Result<String> {
        let cscript = system32().join("cscript.exe");
        let script = system32().join("slmgr.vbs");
        run(&cscript.to_string_lossy(), &["//nologo", &script.to_string_lossy(), "/dlv"])
    }

    /// Windows edition, read from the registry (no child process, so nothing
    /// can flash on screen at startup).
    pub fn os_name() -> String {
        let product = reg_string("ProductName").unwrap_or_else(|| "Windows".into());
        let build: u32 = reg_string("CurrentBuildNumber").and_then(|b| b.parse().ok()).unwrap_or(0);
        // Windows 11 still reports "Windows 10" in ProductName.
        let name = if build >= 22000 { product.replacen("Windows 10", "Windows 11", 1) } else { product };
        match reg_string("DisplayVersion") {
            Some(v) => format!("Microsoft {name} {v}"),
            None => format!("Microsoft {name}"),
        }
    }

    fn reg_string(value: &str) -> Option<String> {
        use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
        let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        let key = wide("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
        let name = wide(value);
        let mut buf = [0u16; 256];
        let mut len = (buf.len() * 2) as u32;
        // SAFETY: buffer and length describe valid writable memory.
        let rc = unsafe {
            RegGetValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), name.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut len)
        };
        if rc != 0 {
            return None;
        }
        let chars = (len as usize / 2).saturating_sub(1);
        Some(String::from_utf16_lossy(&buf[..chars]))
    }
}

#[cfg(windows)]
pub use imp::{install_and_activate, installed_licenses, license_details, os_name};

#[cfg(not(windows))]
pub fn installed_licenses() -> Result<Vec<InstalledLicense>> {
    bail!("installed license information is only available on Windows")
}

#[cfg(not(windows))]
pub fn install_and_activate(_key: &str, _target: Target) -> Result<String> {
    bail!("installing keys is only available on Windows")
}

#[cfg(not(windows))]
pub fn license_details() -> Result<String> {
    bail!("license details are only available on Windows")
}

#[cfg(not(windows))]
pub fn os_name() -> String {
    std::env::consts::OS.to_string()
}

/// Open a web link in the default browser.
pub fn open_url(url: &str) {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return;
    }
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
        let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        ShellExecuteW(std::ptr::null_mut(), wide("open").as_ptr(), wide(url).as_ptr(), std::ptr::null(), std::ptr::null(), SW_SHOWNORMAL);
    }
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
}
