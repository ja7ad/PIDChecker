//! `pidkeychecker.exe`: the desktop application.
//!
//! Built for the Windows GUI subsystem, so no console window ever appears.
//! Subcommands still work when started from a terminal (output is attached to
//! the parent console), but `pkc.exe` is the console tool for `serve` and
//! management.
#![cfg_attr(windows, windows_subsystem = "windows")]

use anyhow::Result;
use clap::Parser;
use pidkeychecker::cli::{self, Cli};
use pidkeychecker::config::Config;

fn main() -> Result<()> {
    let mut cli = Cli::parse();
    if let Some(command) = cli.command.take() {
        attach_parent_console();
        cli::init_tracing(&cli.log_level);
        return cli::run(cli, command).inspect_err(|e| eprintln!("error: {e:#}"));
    }
    cli::init_tracing(&cli.log_level);
    let config = match Config::discover(cli.config.as_deref()) {
        Ok(c) => c,
        Err(e) => return fail(&format!("Cannot load configuration:\n{e:#}")),
    };
    let _lock = match cli::lock(&config, "gui") {
        Ok(l) => l,
        Err(e) => return fail(&format!("{e:#}")),
    };
    pidkeychecker::gui::run(config).or_else(|e| fail(&format!("{e:#}")))
}

/// Report a startup error: a message box (there is no console to print to).
fn fail(message: &str) -> Result<()> {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONWARNING, MB_OK};
        let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        MessageBoxW(std::ptr::null_mut(), wide(message).as_ptr(), wide("PID Key Checker").as_ptr(), MB_OK | MB_ICONWARNING);
    }
    #[cfg(not(windows))]
    eprintln!("{message}");
    std::process::exit(1)
}

/// Send output of CLI subcommands to the terminal the GUI exe was started from.
fn attach_parent_console() {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Console::{AttachConsole, ATTACH_PARENT_PROCESS};
        AttachConsole(ATTACH_PARENT_PROCESS);
    }
}
