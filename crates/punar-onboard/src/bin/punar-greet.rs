#![forbid(unsafe_code)]

use std::env;
use std::io::{self, BufRead, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use punar_onboard::greetd::{GreetError, start_session};
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

const MAX_LOGIN_REQUEST: usize = 2048;

#[derive(Parser)]
#[command(name = "punar-greet", about = "Punar graphical greetd client")]
struct Cli {
    #[arg(long, hide = true)]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Authenticate a normal login; reads username/password JSON from stdin.
    Login,
    /// Consume the root-owned first-session PAM token, then start the desktop.
    First { username: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginWire {
    username: String,
    password: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let socket = cli
        .socket
        .or_else(|| env::var_os("GREETD_SOCK").map(PathBuf::from));
    let Some(socket) = socket else {
        print_error(
            "service_unavailable",
            "The login service is unavailable. Restart and try again.",
        );
        return ExitCode::FAILURE;
    };

    let result = match cli.command {
        Command::First { username } => start_session(&socket, &username, None),
        Command::Login => read_login()
            .and_then(|(username, password)| start_session(&socket, &username, Some(password))),
    };
    match result {
        Ok(()) => {
            println!("{{\"ok\":true}}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            let (code, message) = public_error(&error);
            print_error(code, message);
            ExitCode::FAILURE
        }
    }
}

fn read_login() -> Result<(String, Zeroizing<String>), GreetError> {
    let mut payload = Zeroizing::new(Vec::with_capacity(256));
    io::stdin()
        .lock()
        .take((MAX_LOGIN_REQUEST + 1) as u64)
        .read_until(b'\n', &mut payload)
        .map_err(|_| GreetError::Protocol)?;
    if payload.last() == Some(&b'\n') {
        payload.pop();
    }
    if payload.is_empty() || payload.len() > MAX_LOGIN_REQUEST {
        payload.zeroize();
        return Err(GreetError::Protocol);
    }
    let wire: LoginWire = serde_json::from_slice(&payload).map_err(|_| GreetError::Protocol)?;
    payload.zeroize();
    Ok((wire.username, Zeroizing::new(wire.password)))
}

fn public_error(error: &GreetError) -> (&'static str, &'static str) {
    match error {
        GreetError::Authentication => (
            "authentication_failed",
            "That password did not unlock this account. Try again.",
        ),
        GreetError::Unsupported => (
            "authentication_unsupported",
            "This account needs an authentication step this build cannot show.",
        ),
        GreetError::Unavailable => (
            "service_unavailable",
            "The login service is unavailable. Restart and try again.",
        ),
        GreetError::Protocol | GreetError::Start => (
            "session_failed",
            "The desktop could not start. Your account was not changed; try again.",
        ),
    }
}

fn print_error(code: &str, message: &str) {
    let body = serde_json::json!({"ok": false, "code": code, "message": message});
    let _ = writeln!(io::stdout(), "{body}");
}
