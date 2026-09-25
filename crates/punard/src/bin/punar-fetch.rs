//! `punar-fetch` — the unprivileged half of punard's downloads.
//!
//! `punar-fetch.socket` starts one instance of `punar-fetch@.service` per
//! connection, with the connection as standard input. The instance runs as a
//! dynamic user with no capabilities, a read-only file system and only IPv4
//! and IPv6 sockets to public addresses. It serves exactly one request from
//! punard, writes the response body into the pipe that request carried,
//! answers, and exits. Everything it does is `punard::fetch::serve`; see that
//! module for the protocol and the reasons.

#![forbid(unsafe_code)]

use std::os::fd::AsFd;
use std::path::PathBuf;
use std::process::ExitCode;

use punard::fetch::{DEFAULT_UPDATE_BASE_FILE, HelperConfig, ProxySettings, serve};
use rustix::process::{DumpableBehavior, set_dumpable_behavior};

/// The downloader. This binary is the only Punar program that names it:
/// punard does not contain this path, and check-release-image.sh A19 fails a
/// release tree in which any other Punar binary does.
const DOWNLOADER: &str = "/usr/bin/curl";

fn main() -> ExitCode {
    // The downloader runs as this process's own (dynamic) user and parses
    // everything a server sends. Undumpable, this process cannot be traced
    // or have its memory written through /proc by that child, so a
    // downloader taken over by a hostile server cannot take this process
    // over too and speak for it.
    if let Err(error) = set_dumpable_behavior(DumpableBehavior::NotDumpable) {
        eprintln!("punar-fetch: could not make this process undumpable: {error}");
        return ExitCode::FAILURE;
    }
    let config = HelperConfig {
        downloader: PathBuf::from(DOWNLOADER),
        // Only punard, which runs as root, may ask.
        requester_uid: 0,
        update_base_file: PathBuf::from(DEFAULT_UPDATE_BASE_FILE),
        update_base_owner_uid: 0,
        // Only root sets this process's environment.
        proxy: ProxySettings::from_environment(),
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
