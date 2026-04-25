//! Embeds `assets/app.ico` as the executable icon on Windows.
//!
//! A compiled resource (`.res`) file is written directly instead of invoking
//! `rc.exe`, so cross-compiling with cargo-xwin needs no resource compiler;
//! link.exe / lld-link accept `.res` inputs.

use std::path::PathBuf;

const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;
const LANG_EN_US: u16 = 0x0409;

fn main() {
    println!("cargo:rerun-if-changed=assets/app.ico");
    println!("cargo:rerun-if-changed=build.rs");
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("windows-msvc") {
        return;
    }
    let ico = std::fs::read("assets/app.ico").expect("assets/app.ico");
    let res = ico_to_res(&ico);
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("app.res");
    std::fs::write(&out, res).expect("write app.res");
    // link.exe / lld-link parse a leading `/` as an option, so an absolute Unix
    // path (cross-compiling from macOS/Linux) would be ignored as an unknown
    // flag. The linker runs in the package root, so pass a relative path there.
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let arg = match out.strip_prefix(&manifest) {
        Ok(rel) if out.starts_with("/") => rel.to_path_buf(),
        _ => out,
    };
    println!("cargo:rustc-link-arg-bins={}", arg.display());
}

fn u16_at(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}

fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

/// One `.res` entry with numeric type and name.
fn entry(out: &mut Vec<u8>, kind: u16, name: u16, flags: u16, data: &[u8]) {
    out.extend((data.len() as u32).to_le_bytes()); // DataSize
    out.extend(32u32.to_le_bytes()); // HeaderSize
    out.extend([0xFF, 0xFF]);
    out.extend(kind.to_le_bytes());
    out.extend([0xFF, 0xFF]);
    out.extend(name.to_le_bytes());
    out.extend(0u32.to_le_bytes()); // DataVersion
    out.extend(flags.to_le_bytes()); // MemoryFlags
    out.extend(LANG_EN_US.to_le_bytes());
    out.extend(0u32.to_le_bytes()); // Version
    out.extend(0u32.to_le_bytes()); // Characteristics
    out.extend(data);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

fn ico_to_res(ico: &[u8]) -> Vec<u8> {
    let count = u16_at(ico, 4) as usize;
    let mut res = Vec::new();
    // Every .res file starts with this exact empty entry; linkers use it as the
    // file signature.
    res.extend([
        0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    let mut group = Vec::new();
    group.extend(0u16.to_le_bytes());
    group.extend(1u16.to_le_bytes());
    group.extend((count as u16).to_le_bytes());
    for i in 0..count {
        let e = 6 + i * 16;
        let size = u32_at(ico, e + 8) as usize;
        let offset = u32_at(ico, e + 12) as usize;
        let id = (i + 1) as u16;
        entry(&mut res, RT_ICON, id, 0x1010, &ico[offset..offset + size]);
        group.extend(&ico[e..e + 8]); // width, height, colours, reserved, planes, bit count
        group.extend((size as u32).to_le_bytes());
        group.extend(id.to_le_bytes());
    }
    entry(&mut res, RT_GROUP_ICON, 1, 0x1030, &group);
    res
}
