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
    /// Serve one systemd-accepted connection on stdin/stdout, then exit.
    ///
    /// What the image runs. `punar-onboardd.socket` holds the listening socket
    /// so account creation and recovery redemption stay reachable for the life
    /// of the machine without a privileged process resident in between.
    Session,
    /// Bind the socket directly and serve until the first success.
    ///
    /// For tests and non-systemd callers only. Stopping on first success is
    /// wrong for the shipped path, where the recovery door has to outlive the
    /// first person who opens it.
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
        Command::Session => punar_onboard::server::session().map_err(|_| ()),
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
