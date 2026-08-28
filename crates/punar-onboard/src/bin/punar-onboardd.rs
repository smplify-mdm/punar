#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use punar_onboard::identity::{IdentityPaths, IdentityStore, consume_first_login};

#[derive(Parser)]
#[command(name = "punar-onboardd", about = "Punar first-run identity service")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the admitted pre-login account-creation socket until success.
    Serve {
        #[arg(long, default_value = "/run/punar-onboardd/onboard.sock")]
        socket: PathBuf,
    },
    /// Materialize persistent /var identity into /run/userdb before login.
    Materialize,
    /// One-shot PAM seam for the session immediately after account creation.
    #[command(hide = true)]
    FirstLogin,
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Serve { socket } => punar_onboard::server::serve(&socket).map_err(|_| ()),
        Command::Materialize => IdentityStore::production().materialize().map_err(|_| ()),
        Command::FirstLogin => {
            let username = env::var("PAM_USER").unwrap_or_default();
            consume_first_login(&IdentityPaths::production(), &username)
                .then_some(())
                .ok_or(())
        }
    };
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
