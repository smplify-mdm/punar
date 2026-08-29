//! `punar-netd` — kernel-enforced project networking and bounded local
//! connection visibility.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use punar_netd::runtime::Runtime;
use punar_netd::server::{Daemon, NetdConfig};

#[derive(Parser)]
#[command(
    name = "punar-netd",
    version,
    about = "Punar network policy and local privacy service"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the root-owned local daemon.
    Run(RunArgs),
}

#[derive(clap::Args)]
struct RunArgs {
    #[arg(long, default_value = punar_common::network::NETD_SOCKET_PATH)]
    socket: PathBuf,
    #[arg(long, default_value = punar_common::audit::AUDIT_LOG_PATH)]
    audit_file: PathBuf,
    #[arg(long, default_value = "/var/lib/punar/device-id")]
    device_id_file: PathBuf,
    #[arg(long, default_value = "/etc/passwd")]
    passwd_file: PathBuf,
    #[arg(long, default_value = "/etc/group")]
    group_file: PathBuf,
    #[arg(long, default_value = "punar")]
    group: String,
    #[arg(long, default_value_t = 1000)]
    console_uid: u32,
}

fn run(args: RunArgs) -> ExitCode {
    let runtime = match Runtime::production() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("punar-netd: startup data is invalid: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut config = NetdConfig::production();
    config.socket_path = args.socket;
    config.audit_path = args.audit_file;
    config.device_id_path = args.device_id_file;
    config.passwd_file = args.passwd_file;
    config.group_file = args.group_file;
    config.group = args.group;
    config.console_uid = args.console_uid;
    let daemon = match Daemon::new(config, runtime) {
        Ok(daemon) => daemon,
        Err(error) => {
            eprintln!("punar-netd: startup failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    let handle = match daemon.spawn() {
        Ok(handle) => handle,
        Err(error) => {
            eprintln!("punar-netd: could not bind the local socket: {error}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!(
        "punar-netd: listening on {} (protocol v1)",
        handle.socket_path().display()
    );
    let mut signals = match signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
    ]) {
        Ok(signals) => signals,
        Err(error) => {
            eprintln!("punar-netd: could not install signal handlers: {error}");
            handle.stop();
            return ExitCode::FAILURE;
        }
    };
    let signal = signals.forever().next();
    eprintln!("punar-netd: received signal {signal:?}, shutting down");
    handle.stop();
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Run(args)) => run(args),
        None => {
            eprintln!("punar-netd: no command given; the service runs `punar-netd run`");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::Cli;

    #[test]
    fn command_line_contract_is_well_formed() {
        Cli::command().debug_assert();
        assert!(Cli::command().get_version().is_some());
    }
}
