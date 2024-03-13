//! Optional backend calling Microsoft's `pidgenx.dll` (Windows only).
//!
//! Native decoding covers every `pkey2009` key (Windows 8+, Office 2013+).
//! Legacy `pkey2005` keys (Vista/7, Office 2010) are signature based and are
//! only validated through PidGenX. The DLL must match the process
//! architecture (64-bit Windows ships its own in `System32`).
//!
//! For legacy keys PidGenX verifies the key signature against every
//! `pkey2005` public key in a file, which is deliberately CPU-expensive: one
//! call takes 15-35 s. Running several calls for the same key in parallel only
//! slows each down, so [`Pool`] instead loads private copies of the DLL (a
//! module is not re-entrant) and lets different keys of a batch run in parallel.

#[derive(Debug, Clone, Default)]
pub struct LegacyResult {
    pub product_id: String,
    pub extended_pid: String,
    pub act_config_id: String,
    pub edition_type: String,
    pub sub_type: String,
    pub license_type: String,
    pub channel: String,
    pub source: usize,
}

#[cfg(windows)]
mod imp {
    use std::path::{Path, PathBuf};

    use anyhow::{Context, Result};
    use parking_lot::Mutex;

    use super::LegacyResult;

    type PidGenXFn =
        unsafe extern "system" fn(*const u16, *const u16, *const u16, i32, *mut u8, *mut u8, *mut u8) -> i32;

    pub struct PidGenX {
        _lib: libloading::Library,
        func: PidGenXFn,
        // The DLL keeps global state; serialise calls.
        lock: Mutex<()>,
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn read_wide(buf: &[u8], offset: usize, bytes: usize) -> String {
        let units: Vec<u16> = buf[offset..offset + bytes]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        String::from_utf16_lossy(&units)
    }

    impl PidGenX {
        pub fn load(path: &Path) -> Result<Self> {
            // SAFETY: loading a trusted system DLL configured by the user.
            unsafe {
                let lib = libloading::Library::new(path).with_context(|| format!("loading {}", path.display()))?;
                let func = *lib.get::<PidGenXFn>(b"PidGenX\0").context("PidGenX export not found")?;
                Ok(Self { _lib: lib, func, lock: Mutex::new(()) })
            }
        }

        /// Returns the HRESULT and, on success, the parsed product IDs.
        pub fn check(&self, key: &str, pkeyconfig: &Path) -> (i32, Option<LegacyResult>) {
            let mut pid = [0u8; 100];
            let mut dpid = [0u8; 164];
            let mut dpid4 = [0u8; 1272];
            pid[0] = 50;
            dpid[0] = 164;
            dpid4[0] = 0xF8;
            dpid4[1] = 0x04;
            let (k, p, m) = (wide(key), wide(&pkeyconfig.to_string_lossy()), wide("XXXXX"));
            let _guard = self.lock.lock();
            // SAFETY: buffers are sized as PidGenX expects (matches the original tool).
            let hr = unsafe {
