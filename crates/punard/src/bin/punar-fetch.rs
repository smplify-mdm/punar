//! `punar-fetch` — the unprivileged half of punard's downloads.
//!
//! `punar-fetch.socket` starts one instance of `punar-fetch@.service` per
//! connection, with the connection as standard input. The instance runs as a
//! dynamic user with no capabilities, a read-only file system and only IPv4
//! and IPv6 sockets. It serves exactly one request from punard, writes the
//! response body into the one descriptor that request carried, answers, and
//! exits. Everything it does is `punard::fetch::serve`; see that module for
//! the protocol and the reasons.

#![forbid(unsafe_code)]

use std::os::fd::AsFd;
use std::path::PathBuf;
use std::process::ExitCode;

use punard::fetch::{HelperConfig, serve};

/// The downloader. This binary is the only Punar program that names it:
/// punard does not contain this path, and check-release-image.sh A19 fails a
/// release tree in which any other Punar binary does.
const DOWNLOADER: &str = "/usr/bin/curl";

fn main() -> ExitCode {
    let config = HelperConfig {
        downloader: PathBuf::from(DOWNLOADER),
        // Only punard, which runs as root, may ask.
        requester_uid: 0,
    };
    let connection = std::io::stdin();
    match serve(connection.as_fd(), &config) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("punar-fetch: {error}");
            ExitCode::FAILURE
        }
    }
}
