//! The shipped `punar-fetch` binary, not the library it calls.
//!
//! The helper runs the downloader as its own child, under the same dynamic
//! user. A downloader taken over by a hostile server could otherwise trace
//! its parent or write its memory through /proc and speak for it. The binary
//! makes itself undumpable before it reads a request, and the kernel then
//! reports its /proc entries as root's, which is what this test observes.

#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rustix::net::{AddressFamily, SocketFlags, SocketType};

#[test]
fn the_helper_is_undumpable_before_it_reads_a_request() {
    let (ours, theirs) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    let mut helper = Command::new(env!("CARGO_BIN_EXE_punar-fetch"))
        .stdin(Stdio::from(theirs))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_clear()
        .spawn()
        .unwrap();
    let memory = format!("/proc/{}/mem", helper.id());
    let started = Instant::now();
    let owner = loop {
        let owner = fs::metadata(&memory).map(|metadata| metadata.uid()).ok();
        if owner == Some(0) || started.elapsed() > Duration::from_secs(10) {
            break owner;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    // Closing our end ends the helper's wait for a request.
    drop(ours);
    let _ = helper.wait();
    assert_eq!(
        owner,
        Some(0),
        "the helper's /proc entries stayed its own user's, so it is still dumpable"
    );
}
