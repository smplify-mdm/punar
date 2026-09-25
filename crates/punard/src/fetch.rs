//! Unprivileged downloads for punard.
//!
//! punard runs as root. It used to run the system HTTP client itself for
//! update-channel metadata, release artifacts and catalog-pinned vendor
//! packages, so the TLS and HTTP parsing of every byte an update server or a
//! vendor CDN sent ran with every privilege on the machine. It no longer
//! starts a downloader at all.
//!
//! Instead punard opens the file the bytes belong in, privately (`0600`, in
//! its own `0700` staging directory), and hands that ONE open descriptor to
//! `punar-fetch`: a socket-activated helper (`punar-fetch.socket`,
//! `punar-fetch@.service`) that runs as a dynamic user, with no capabilities,
//! a read-only file system, no `/home`, `/var` or `/run`, and only IPv4 and
//! IPv6 sockets, none of them to this machine's own services. The descriptor
//! is the only thing the helper can write. punard keeps every decision about
//! trust: it verifies the signature or digest of what arrived exactly as
//! before, and it alone moves verified bytes into place.
//!
//! The protocol is one `SOCK_SEQPACKET` record each way. punard sends a
//! [`FetchRequest`] with the destination descriptor attached as
//! `SCM_RIGHTS`; the helper answers with a [`FetchResponse`]. The helper
//! accepts a request only from uid 0, only with exactly one descriptor, and
//! only when that descriptor is an empty regular file. A request cannot choose
//! the downloader's options: the helper builds the argument list itself from
//! the request's kind, and each kind has a fixed origin rule:
//!
//! - [`FetchKind::Update`]: one `https://` URL beneath the root-owned channel
//!   base, validated as strictly as the base itself (no userinfo, query,
//!   fragment, escape, IPv6 literal or unsafe path segment), and redirects
//!   are refused.
//! - [`FetchKind::Vendor`]: a URL beneath one of [`VENDOR_ORIGINS`], the same
//!   fixed prefixes the signed catalog is validated against. Redirects are
//!   followed over HTTPS only, because vendor CDNs redirect; the catalog pins
//!   the size and SHA-256, which punard checks after the transfer.
//!
//! This module holds both halves so the two cannot drift: [`FetchClient`] is
//! what punard calls, and [`serve`] is the whole of what the helper binary
//! (`src/bin/punar-fetch.rs`) runs. The downloader's path is not in this
//! module: the helper binary supplies it, so punard's own binary never
//! contains it (check-release-image.sh A19 checks exactly that).

use std::fs::File;
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use rustix::net::sockopt::Timeout;
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketAddrUnix, SocketFlags, SocketType,
    recvmsg, sendmsg,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Where `punar-fetch.socket` listens. The directory is `0700 root`, the
/// socket `0600 root`: only punard can ask for a download.
pub const DEFAULT_FETCH_SOCKET: &str = "/run/punar-fetch/request.sock";

/// The only origins a vendor package may come from. The signed catalog is
/// validated against these (apps.rs) and the helper refuses anything else,
/// so neither a catalog nor a request can widen the set on its own.
pub const VENDOR_ORIGINS: [&str; 3] = [
    "https://persistent.oaistatic.com/codex-app-prod/linux/deb/",
    "https://downloads.claude.ai/claude-desktop/apt/stable/pool/main/",
    "https://downloads.slack-edge.com/desktop-releases/linux/x64/",
];

/// The largest transfer any request may ask for. Release payloads are the
/// biggest thing Punar downloads; this is a ceiling on a mistake, not a
/// budget.
pub const MAX_FETCH_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// The longest transfer any request may ask for, matching the unit's
/// `RuntimeMaxSec=` less a margin.
pub const MAX_FETCH_SECONDS: u64 = 60 * 60;

/// How long a connection may take before the transfer starts.
const CONNECT_TIMEOUT_SECONDS: u64 = 10;

/// How long punard waits for an answer beyond the transfer's own limit.
const ANSWER_GRACE: Duration = Duration::from_secs(15);

const RECORD_MAX: usize = 4096;
const URL_MAX: usize = 2048;
const STDERR_KEPT: usize = 4096;
const COPY_CHUNK: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FetchKind {
    /// A document or artifact beneath the update channel's root-owned base.
    Update,
    /// A catalog-pinned vendor package beneath one of [`VENDOR_ORIGINS`].
    Vendor,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchRequest {
    pub v: u32,
    pub kind: FetchKind,
    pub url: String,
    /// The transfer fails, and nothing is kept, past this many bytes.
    pub max_bytes: u64,
    /// The whole transfer's time limit, connection included.
    pub timeout_seconds: u64,
}

impl FetchRequest {
    pub fn update(url: impl Into<String>, max_bytes: u64, timeout: Duration) -> Self {
        Self::new(FetchKind::Update, url, max_bytes, timeout)
    }

    pub fn vendor(url: impl Into<String>, max_bytes: u64, timeout: Duration) -> Self {
        Self::new(FetchKind::Vendor, url, max_bytes, timeout)
    }

    fn new(kind: FetchKind, url: impl Into<String>, max_bytes: u64, timeout: Duration) -> Self {
        Self {
            v: 1,
            kind,
            url: url.into(),
            max_bytes,
            timeout_seconds: timeout.as_secs().clamp(1, MAX_FETCH_SECONDS),
        }
    }

    /// The downloader's complete argument list for this request, or the
    /// reason the request is refused. Nothing in it comes from the request
    /// except the validated URL and the two bounds.
    pub fn arguments(&self) -> Result<Vec<String>, String> {
        if self.v != 1 {
            return Err(format!("request version {} is not supported", self.v));
        }
        if self.max_bytes == 0 || self.max_bytes > MAX_FETCH_BYTES {
            return Err(format!(
                "a transfer may be 1 to {MAX_FETCH_BYTES} bytes, not {}",
                self.max_bytes
            ));
        }
        if self.timeout_seconds == 0 || self.timeout_seconds > MAX_FETCH_SECONDS {
            return Err(format!(
                "a transfer may take 1 to {MAX_FETCH_SECONDS} seconds, not {}",
                self.timeout_seconds
            ));
        }
        let url = match self.kind {
            FetchKind::Update => validate_https_url(&self.url)
                .map_err(|reason| format!("the update URL is refused: {reason}"))?,
            FetchKind::Vendor => validate_vendor_url(&self.url)
                .map_err(|reason| format!("the vendor URL is refused: {reason}"))?,
        };
        let mut arguments: Vec<String> = [
            // No configuration file may add options, proxies or credentials.
            "--disable",
            "--fail",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--connect-timeout",
        ]
        .iter()
        .map(|argument| (*argument).to_string())
        .collect();
        arguments.push(CONNECT_TIMEOUT_SECONDS.to_string());
        arguments.push("--max-time".to_string());
        arguments.push(self.timeout_seconds.to_string());
        arguments.push("--max-filesize".to_string());
        arguments.push(self.max_bytes.to_string());
        match self.kind {
            FetchKind::Update => {
                arguments.extend(["--max-redirs".to_string(), "0".to_string()]);
            }
            FetchKind::Vendor => {
                arguments.extend([
                    "--location".to_string(),
                    "--max-redirs".to_string(),
                    "5".to_string(),
                ]);
            }
        }
        arguments.push(url);
        Ok(arguments)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchResponse {
    pub v: u32,
    pub ok: bool,
    /// Bytes written to the descriptor. Zero on failure: the helper empties
    /// the file rather than leave a partial transfer in it.
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("the download helper is unavailable: {0}")]
    Unavailable(String),
    #[error("{0}")]
    Refused(String),
    #[error("the download helper's answer was malformed: {0}")]
    Protocol(String),
}

/// punard's side: one connection per transfer.
#[derive(Clone, Debug)]
pub struct FetchClient {
    socket: PathBuf,
}

impl FetchClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    /// Ask the helper to write `request`'s bytes into `destination`, which
    /// must be an empty regular file opened for writing. Returns the number
    /// of bytes written; the caller still verifies what they are.
    pub fn fetch(&self, request: &FetchRequest, destination: &File) -> Result<u64, FetchError> {
        let unavailable = |what: &str, error: io::Error| {
            FetchError::Unavailable(format!("{what} {}: {error}", self.socket.display()))
        };
        let socket = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|error| unavailable("could not open a socket for", error.into()))?;
        let address = SocketAddrUnix::new(self.socket.as_path())
            .map_err(|error| unavailable("could not address", error.into()))?;
        rustix::net::connect(&socket, &address)
            .map_err(|error| unavailable("could not connect to", error.into()))?;
        let answer_within = Duration::from_secs(request.timeout_seconds)
            .saturating_add(Duration::from_secs(CONNECT_TIMEOUT_SECONDS))
            .saturating_add(ANSWER_GRACE);
        rustix::net::sockopt::set_socket_timeout(&socket, Timeout::Recv, Some(answer_within))
            .map_err(|error| unavailable("could not bound the wait on", error.into()))?;
        rustix::net::sockopt::set_socket_timeout(
            &socket,
            Timeout::Send,
            Some(Duration::from_secs(10)),
        )
        .map_err(|error| unavailable("could not bound the send on", error.into()))?;

        let record =
            serde_json::to_vec(request).map_err(|error| FetchError::Protocol(error.to_string()))?;
        if record.len() > RECORD_MAX {
            return Err(FetchError::Refused(
                "the download request is too large to send".into(),
            ));
        }
        send_record(&socket, &record, Some(destination.as_fd()))
            .map_err(|error| unavailable("could not send the request to", error))?;

        let (answer, descriptors) = receive_record(&socket)
            .map_err(|error| unavailable("no answer arrived from", error))?;
        if !descriptors.is_empty() {
            return Err(FetchError::Protocol(
                "the answer carried a descriptor".into(),
            ));
        }
        let response: FetchResponse = serde_json::from_slice(&answer)
            .map_err(|error| FetchError::Protocol(error.to_string()))?;
        if response.v != 1 {
            return Err(FetchError::Protocol(format!(
                "answer version {} is not supported",
                response.v
            )));
        }
        if !response.ok {
            return Err(FetchError::Refused(
                response
                    .error
                    .unwrap_or_else(|| "the download failed".to_string()),
            ));
        }
        // The helper's count and the file must agree; anything else means
        // the answer does not describe these bytes.
        let length = destination
            .metadata()
            .map_err(|error| FetchError::Protocol(error.to_string()))?
            .len();
        if length != response.bytes || length > request.max_bytes {
            return Err(FetchError::Protocol(format!(
                "the helper reported {} bytes but the file holds {length}",
                response.bytes
            )));
        }
        Ok(length)
    }
}

/// The helper's configuration. The binary supplies every field; tests point
/// them at fixtures.
#[derive(Clone, Debug)]
pub struct HelperConfig {
    /// The downloader the helper runs, with a fixed argument list.
    pub downloader: PathBuf,
    /// The only uid whose requests are served: punard's, 0.
    pub requester_uid: u32,
}

/// Serve exactly one request on `connection` and answer it. The helper
/// binary calls this with its socket-activated standard input.
pub fn serve(connection: BorrowedFd<'_>, config: &HelperConfig) -> Result<u64, FetchError> {
    let result = serve_request(connection, config);
    let response = match &result {
        Ok(bytes) => FetchResponse {
            v: 1,
            ok: true,
            bytes: *bytes,
            error: None,
        },
        Err(reason) => FetchResponse {
            v: 1,
            ok: false,
            bytes: 0,
            error: Some(reason.clone()),
        },
    };
    let record =
        serde_json::to_vec(&response).map_err(|error| FetchError::Protocol(error.to_string()))?;
    send_record(connection, &record, None).map_err(|error| {
        FetchError::Unavailable(format!("could not answer the requester: {error}"))
    })?;
    result.map_err(FetchError::Refused)
}

fn serve_request(connection: BorrowedFd<'_>, config: &HelperConfig) -> Result<u64, String> {
    // Read the request before judging it, even from a peer that will be
    // refused: a socket closed with its request unread resets the
    // connection, and the refusal would never reach the requester.
    let (record, mut descriptors) = receive_record(connection)
        .map_err(|error| format!("the request could not be read: {error}"))?;
    let credentials = rustix::net::sockopt::socket_peercred(connection)
        .map_err(|error| format!("the requester could not be identified: {error}"))?;
    if credentials.uid.as_raw() != config.requester_uid {
        return Err(format!(
            "only uid {} may ask for a download",
            config.requester_uid
        ));
    }
    if descriptors.len() != 1 {
        return Err(format!(
            "a request carries exactly one destination descriptor, not {}",
            descriptors.len()
        ));
    }
    let destination = File::from(descriptors.pop().expect("length checked"));
    let request: FetchRequest = serde_json::from_slice(&record)
        .map_err(|error| format!("the request is malformed: {error}"))?;
    let arguments = request.arguments()?;
    let metadata = destination
        .metadata()
        .map_err(|error| format!("the destination could not be inspected: {error}"))?;
    if !metadata.file_type().is_file() || metadata.len() != 0 {
        return Err("the destination must be an empty regular file".to_string());
    }
    let written = download(
        &config.downloader,
        &arguments,
        request.max_bytes,
        &destination,
    );
    if written.is_err() {
        // Never leave part of a transfer where a whole one belongs.
        let _ = destination.set_len(0);
    }
    written
}

/// Run the downloader with `arguments`, copying its standard output into
/// `destination` and stopping it the moment the output passes `max_bytes`.
fn download(
    downloader: &Path,
    arguments: &[String],
    max_bytes: u64,
    destination: &File,
) -> Result<u64, String> {
    let mut child = Command::new(downloader)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("the downloader could not start: {error}"))?;
    let stderr = child.stderr.take().map(|mut stream| {
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            let _ = (&mut stream)
                .take(STDERR_KEPT as u64)
                .read_to_end(&mut kept);
            // Drain the rest so the downloader never blocks on a full pipe.
            let _ = io::copy(&mut stream, &mut io::sink());
            kept
        })
    });
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "the downloader's output was not captured".to_string())?;
    let mut output: &File = destination;
    let mut written: u64 = 0;
    let mut chunk = vec![0_u8; COPY_CHUNK];
    let copied = loop {
        let count = match stdout.read(&mut chunk) {
            Ok(0) => break Ok(()),
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => break Err(format!("the download could not be read: {error}")),
        };
        let total = written.saturating_add(count as u64);
        if total > max_bytes {
            break Err(format!(
                "the response is larger than the {max_bytes} bytes it may be"
            ));
        }
        if let Err(error) = output.write_all(&chunk[..count]) {
            break Err(format!("the destination could not be written: {error}"));
        }
        written = total;
    };
    if copied.is_err() {
        let _ = child.kill();
    }
    drop(stdout);
    let status = child
        .wait()
        .map_err(|error| format!("the downloader could not be waited for: {error}"))?;
    let stderr = stderr
        .and_then(|reader| reader.join().ok())
        .unwrap_or_default();
    copied?;
    if !status.success() {
        let detail = first_line(&stderr);
        return Err(match (status.code(), detail.is_empty()) {
            (Some(code), true) => format!("the download failed (downloader exit {code})"),
            (Some(code), false) => {
                format!("the download failed (downloader exit {code}): {detail}")
            }
            (None, _) => "the downloader was stopped by a signal".to_string(),
        });
    }
    destination
        .sync_all()
        .map_err(|error| format!("the destination could not be synced: {error}"))?;
    Ok(written)
}

/// One line of the downloader's complaint, safe to show: no control
/// characters, no more than 200 characters.
fn first_line(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("")
        .chars()
        .filter(|character| !character.is_control())
        .take(200)
        .collect()
}

fn send_record(
    socket: impl AsFd,
    record: &[u8],
    descriptor: Option<BorrowedFd<'_>>,
) -> io::Result<()> {
    let rights: Vec<BorrowedFd<'_>> = descriptor.into_iter().collect();
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !rights.is_empty() && !ancillary.push(SendAncillaryMessage::ScmRights(&rights)) {
        return Err(io::Error::other("the descriptor did not fit the record"));
    }
    let sent = sendmsg(
        socket,
        &[IoSlice::new(record)],
        &mut ancillary,
        SendFlags::NOSIGNAL,
    )?;
    if sent == record.len() {
        Ok(())
    } else {
        Err(io::Error::other("the record was only partly sent"))
    }
}

fn receive_record(socket: impl AsFd) -> io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    let mut payload = vec![0_u8; RECORD_MAX];
    let mut vectors = [IoSliceMut::new(&mut payload)];
    // Room for more than one descriptor, so a record that carries two is
    // refused by count rather than truncated to one that looks acceptable.
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(4))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = recvmsg(
        socket,
        &mut vectors,
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )?;
    let mut descriptors = Vec::new();
    let mut unexpected = false;
    for message in ancillary.drain() {
        match message {
            RecvAncillaryMessage::ScmRights(rights) => descriptors.extend(rights),
            _ => unexpected = true,
        }
    }
    if received.bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the peer sent nothing",
        ));
    }
    if received
        .flags
        .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || unexpected
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the record was truncated or carried unexpected metadata",
        ));
    }
    payload.truncate(received.bytes);
    Ok((payload, descriptors))
}

/// One unambiguous `https://` URL: a DNS hostname or IPv4 address, an
/// optional port, and a path of plain segments. No userinfo, query,
/// fragment, percent-escape, backslash, IPv6 literal, empty, `.` or `..`
/// segment. Returned without a trailing slash.
pub fn validate_https_url(value: &str) -> Result<String, &'static str> {
    if value.is_empty()
        || value.len() > URL_MAX
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err("the URL must be one non-empty line without whitespace");
    }
    let normalized = value.strip_suffix('/').unwrap_or(value);
    let rest = normalized
        .strip_prefix("https://")
        .ok_or("only an https:// URL is accepted")?;
    if rest.contains(['?', '#', '@', '%', '\\']) {
        return Err("userinfo, query, fragment, escapes and backslashes are not accepted");
    }
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() || authority.contains(['[', ']']) {
        return Err("a DNS hostname or IPv4 address is required");
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) if !port.contains(':') => (host, Some(port)),
        Some(_) => return Err("IPv6 literals are not accepted"),
        None => (authority, None),
    };
    if host.len() > 253
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
        })
    {
        return Err("the hostname is invalid");
    }
    if let Some(port) = port {
        if port.is_empty() || port.parse::<u16>().ok().filter(|port| *port != 0).is_none() {
            return Err("the HTTPS port is invalid");
        }
    }
    if !path.is_empty()
        && path.split('/').any(|segment| {
            segment.is_empty()
                || matches!(segment, "." | "..")
                || !segment.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
                })
        })
    {
        return Err("the path contains an unsafe segment");
    }
    Ok(normalized.to_string())
}

/// A vendor package URL: beneath one of [`VENDOR_ORIGINS`], one line, with
/// no backslash or `..` segment that could climb out of the prefix.
pub fn validate_vendor_url(value: &str) -> Result<String, &'static str> {
    if value.len() > URL_MAX
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control() || byte == b'\\')
    {
        return Err("the URL must be one line without whitespace or backslashes");
    }
    let origin = VENDOR_ORIGINS
        .iter()
        .find(|origin| value.starts_with(*origin))
        .ok_or("it is not beneath a catalog vendor origin")?;
    let rest = &value[origin.len()..];
    let path = rest.split(['?', '#']).next().unwrap_or("");
    if path.is_empty()
        || path
            .split('/')
            .any(|segment| matches!(segment, "." | "..") || segment.contains('%'))
    {
        return Err("the package path is empty or escapes its origin");
    }
    Ok(value.to_string())
}

/// A helper serving a fixture downloader on a real socket, for the tests of
/// this module and of the two callers. The listener thread runs [`serve`],
/// the same function the shipped binary runs.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    pub(crate) fn spawn_helper(socket: &Path, downloader: &Path) {
        let listener = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let _ = std::fs::remove_file(socket);
        rustix::net::bind(&listener, &SocketAddrUnix::new(socket).unwrap()).unwrap();
        rustix::net::listen(&listener, 8).unwrap();
        let config = HelperConfig {
            downloader: downloader.to_path_buf(),
            requester_uid: rustix::process::geteuid().as_raw(),
        };
        std::thread::spawn(move || {
            while let Ok(connection) = rustix::net::accept(&listener) {
                let _ = serve(connection.as_fd(), &config);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "punar-fetch-{name}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn downloader(root: &Path, body: &str) -> PathBuf {
        let path = root.join("downloader");
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn destination(root: &Path) -> (PathBuf, File) {
        let path = root.join("staged");
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        (path, file)
    }

    fn client_for(root: &Path, body: &str) -> FetchClient {
        let socket = root.join("fetch.sock");
        testing::spawn_helper(&socket, &downloader(root, body));
        FetchClient::new(socket)
    }

    const UPDATE_URL: &str = "https://updates.example.test/punar/stable/aarch64/uefi/channel.json";

    #[test]
    fn the_bytes_land_in_the_one_descriptor_and_the_count_is_checked() {
        let root = root("ok");
        let client = client_for(
            &root,
            &format!(
                "printf '%s\\n' \"$@\" > '{}'\nprintf verified-bytes",
                root.join("argv").display()
            ),
        );
        let (path, file) = destination(&root);
        let bytes = client
            .fetch(
                &FetchRequest::update(UPDATE_URL, 64, Duration::from_secs(30)),
                &file,
            )
            .unwrap();
        assert_eq!(bytes, 14);
        assert_eq!(fs::read(&path).unwrap(), b"verified-bytes");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "the helper never chooses the staged file's mode"
        );
        let argv = fs::read_to_string(root.join("argv")).unwrap();
        for fixed in [
            "--disable\n",
            "--proto\n=https\n",
            "--proto-redir\n=https\n",
            "--tlsv1.2\n",
            "--max-redirs\n0\n",
            "--max-filesize\n64\n",
            "--max-time\n30\n",
        ] {
            assert!(argv.contains(fixed), "missing {fixed:?} in {argv}");
        }
        assert!(!argv.contains("--location"));
        assert!(argv.ends_with(&format!("{UPDATE_URL}\n")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_response_past_its_bound_is_refused_and_nothing_is_kept() {
        let root = root("oversized");
        let client = client_for(&root, "head -c 200000 /dev/zero");
        let (path, file) = destination(&root);
        let error = client
            .fetch(
                &FetchRequest::update(UPDATE_URL, 1000, Duration::from_secs(30)),
                &file,
            )
            .unwrap_err();
        assert!(matches!(error, FetchError::Refused(_)), "{error}");
        assert!(error.to_string().contains("larger than the 1000 bytes"));
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_failed_download_is_refused_with_one_safe_line_and_an_empty_file() {
        let root = root("failed");
        let client = client_for(
            &root,
            "printf partial\nprintf 'curl: (22) The requested URL returned error: 404\\n\\033]52;c;x\\007second line\\n' >&2\nexit 22",
        );
        let (path, file) = destination(&root);
        let error = client
            .fetch(
                &FetchRequest::update(UPDATE_URL, 1000, Duration::from_secs(30)),
                &file,
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("downloader exit 22"), "{error}");
        assert!(error.contains("returned error: 404"), "{error}");
        assert!(!error.contains("second line"));
        assert!(!error.chars().any(char::is_control));
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_vendor_download_follows_https_redirects_only_from_a_catalog_origin() {
        let root = root("vendor");
        let client = client_for(
            &root,
            &format!(
                "printf '%s\\n' \"$@\" > '{}'\nprintf package",
                root.join("argv").display()
            ),
        );
        let url = "https://downloads.claude.ai/claude-desktop/apt/stable/pool/main/c/claude-desktop_1.0_amd64.deb";
        let (_path, file) = destination(&root);
        client
            .fetch(
                &FetchRequest::vendor(url, 7, Duration::from_secs(60)),
                &file,
            )
            .unwrap();
        let argv = fs::read_to_string(root.join("argv")).unwrap();
        assert!(argv.contains("--location\n--max-redirs\n5\n"));
        assert!(argv.contains("--proto-redir\n=https\n"));

        let (_other, file) = {
            let path = root.join("other");
            let file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            (path, file)
        };
        let refused = client
            .fetch(
                &FetchRequest::vendor(
                    "https://attacker.example/claude-desktop_1.0_amd64.deb",
                    7,
                    Duration::from_secs(60),
                ),
                &file,
            )
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("not beneath a catalog vendor origin"),
            "{refused}"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn requests_that_choose_their_own_origin_or_options_are_refused() {
        for url in [
            "http://updates.example.test/punar/channel.json",
            "https://user@updates.example.test/channel.json",
            "https://updates.example.test/channel.json?x=1",
            "https://updates.example.test/../channel.json",
            "https://updates.example.test/%2e%2e/channel.json",
            "https://[::1]/channel.json",
            "--config=/etc/shadow",
            "https://updates.example.test/a b",
        ] {
            let request = FetchRequest::update(url, 10, Duration::from_secs(10));
            assert!(request.arguments().is_err(), "accepted {url:?}");
        }
        for url in [
            "https://downloads.claude.ai/claude-desktop/apt/stable/pool/main/../../../../x.deb",
            "https://downloads.claude.ai/claude-desktop/apt/stable/pool/main/",
            "https://downloads.claude.ai.attacker.example/claude-desktop/apt/stable/pool/main/x.deb",
            "https://downloads.claude.ai/claude-desktop/apt/stable/pool/main/%2e%2e/x.deb",
        ] {
            let request = FetchRequest::vendor(url, 10, Duration::from_secs(10));
            assert!(request.arguments().is_err(), "accepted {url:?}");
        }
        let mut request = FetchRequest::update(UPDATE_URL, 0, Duration::from_secs(10));
        assert!(request.arguments().is_err(), "a zero-byte bound");
        request.max_bytes = MAX_FETCH_BYTES + 1;
        assert!(request.arguments().is_err(), "a bound past the ceiling");
        request.max_bytes = 10;
        request.timeout_seconds = MAX_FETCH_SECONDS + 1;
        assert!(request.arguments().is_err(), "a limit past the ceiling");
        request.timeout_seconds = 10;
        request.v = 2;
        assert!(request.arguments().is_err(), "an unknown version");
        let unknown = r#"{"v":1,"kind":"update","url":"https://updates.example.test/x","max_bytes":1,"timeout_seconds":1,"args":["--insecure"]}"#;
        assert!(serde_json::from_str::<FetchRequest>(unknown).is_err());
    }

    #[test]
    fn a_destination_that_is_not_an_empty_regular_file_is_refused() {
        let root = root("destination");
        let client = client_for(&root, "printf bytes");
        let (_path, mut file) = destination(&root);
        file.write_all(b"already here").unwrap();
        let error = client
            .fetch(
                &FetchRequest::update(UPDATE_URL, 64, Duration::from_secs(30)),
                &file,
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("empty regular file"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn only_the_configured_requester_is_served() {
        let root = root("peer");
        let socket = root.join("fetch.sock");
        let listener = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        rustix::net::bind(&listener, &SocketAddrUnix::new(&socket).unwrap()).unwrap();
        rustix::net::listen(&listener, 1).unwrap();
        let config = HelperConfig {
            downloader: downloader(&root, "printf bytes"),
            requester_uid: rustix::process::geteuid().as_raw().wrapping_add(1),
        };
        let server = std::thread::spawn(move || {
            let connection = rustix::net::accept(&listener).unwrap();
            serve(connection.as_fd(), &config)
        });
        let (path, file) = destination(&root);
        let error = FetchClient::new(&socket)
            .fetch(
                &FetchRequest::update(UPDATE_URL, 64, Duration::from_secs(30)),
                &file,
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("may ask for a download"), "{error}");
        assert!(server.join().unwrap().is_err());
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_missing_helper_is_unavailable_not_a_download_failure() {
        let root = root("absent");
        let (_path, file) = destination(&root);
        let error = FetchClient::new(root.join("absent.sock"))
            .fetch(
                &FetchRequest::update(UPDATE_URL, 64, Duration::from_secs(30)),
                &file,
            )
            .unwrap_err();
        assert!(matches!(error, FetchError::Unavailable(_)), "{error}");
        fs::remove_dir_all(root).unwrap();
    }
}
