//! `pkc.exe`: console tool — run the REST server headless with live logs,
//! check keys, and manage API keys, the blocklist and configuration.

use anyhow::Result;
use clap::{CommandFactory, Parser};
use pidkeychecker::cli::{self, Cli};

fn main() -> Result<()> {
    let mut cli = Cli::parse();
    let Some(command) = cli.command.take() else {
        Cli::command().print_help()?;
        return Ok(());
    };
    cli::init_tracing(&cli.log_level);
    cli::run(cli, command)
}
