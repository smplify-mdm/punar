#![forbid(unsafe_code)]
//! The privileged half. One systemd-accepted connection, one verdict, exit.
//!
//! No arguments and no configuration: the socket is systemd's, the PAM service
//! name is compiled in, and the account is whichever uid the kernel reports for
//! the peer. There is nothing here for a caller to steer.

use std::process::ExitCode;

fn main() -> ExitCode {
    match punar_auth::server::session() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // The verdict has already been written, or the peer was gone before
            // one could be. The secret is never in this message.
            eprintln!("punar-authd: {error}");
            ExitCode::FAILURE
        }
    }
}
