//! Unprivileged downloads for punard.
//!
//! punard runs as root. It used to run the system HTTP client itself for
//! update-channel metadata, release artifacts and catalog-pinned vendor
//! packages, so the TLS and HTTP parsing of every byte an update server or a
//! vendor CDN sent ran with every privilege on the machine. It no longer
//! starts a downloader at all.
//!
//! Each transfer is its own instance of `punar-fetch`, a socket-activated
//! helper (`punar-fetch.socket`, `punar-fetch@.service`) that runs as a
//! dynamic user with no capabilities, a read-only file system, no `/home`,
//! nothing of `/var` or `/run` but the resolver's files, and only IPv4 and
//! IPv6 sockets. The kernel drops every packet it sends to a loopback address
//! (the DNS stub apart), to link-local and multicast addresses, and to the
//! private, shared, reserved and documentation ranges, so the helper reaches
//! public addresses only (by address: a public address this machine holds
//! itself is one of them). An administrator who serves updates from the local
//! network, or sends them through a proxy, allows that address in a drop-in
//! (docs/api/ipc.md).
//!
//! The helper never holds anything of punard's but one pipe. punard sends the
//! pipe's write end with the request, reads the body from the read end into a
//! private `0600` file in its own `0700` staging directory, and counts and
//! bounds the bytes itself. The helper cannot reach that file, before or after
//! it answers: once punard has read to the end of the pipe, nothing the helper
//! or its downloader does can change what punard verifies. punard then checks
//! the signature or digest of that file exactly as before, and it alone moves
//! verified bytes into place.
//!
//! The protocol is one `SOCK_SEQPACKET` record each way. punard sends a
//! [`FetchRequest`] with the pipe's write end attached as `SCM_RIGHTS`; the
//! helper writes the body into the pipe, closes it, and answers with a
//! [`FetchResponse`]. The helper accepts a request only from uid 0 and only
//! with exactly one descriptor, a pipe. A request cannot choose the
//! downloader's options: the helper builds the argument list itself from the
//! request's kind, never follows a redirect, and holds each kind to a fixed
//! origin rule:
//!
//! - [`FetchKind::Update`]: one `https://` URL beneath the update channel's
//!   base, which the helper reads itself from the same root-owned file punard
//!   reads (`/etc/punar/update-repository.url`), validated as strictly as the
//!   base (no userinfo, query, fragment, escape, IPv6 literal or unsafe path
//!   segment).
//! - [`FetchKind::Vendor`]: a URL beneath one of [`VENDOR_ORIGINS`], the same
//!   fixed prefixes the signed catalog is validated against. The catalog pins
//!   the size and SHA-256, which punard checks after the transfer.
//!
//! This module holds both halves so the two cannot drift: [`FetchClient`] is
//! what punard calls, and [`serve`] is the whole of what the helper binary
//! (`src/bin/punar-fetch.rs`) runs. The downloader's path is not in this
//! module: the helper binary supplies it, so punard's own binary never
//! contains it (check-release-image.sh A19 checks exactly that), and
//! punard.service makes the downloader inaccessible to punard at run time.

use std::fs::File;
use std::io::{self, IoSlice, IoSliceMut, PipeReader, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec};
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

/// The root-owned file naming the update channel's base URL. punard builds
/// every update URL beneath it, and the helper refuses any update URL that is
/// not.
pub const DEFAULT_UPDATE_BASE_FILE: &str = "/etc/punar/update-repository.url";

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

/// The protocol both halves speak. Version 2 carries a pipe, never a file:
/// a helper and a punard from different builds refuse each other rather
/// than misread what the descriptor is.
const PROTOCOL_VERSION: u32 = 2;

/// How long a connection may take before the transfer starts.
const CONNECT_TIMEOUT_SECONDS: u64 = 10;

/// How long punard waits for an answer beyond the transfer's own limit.
const ANSWER_GRACE: Duration = Duration::from_secs(15);

/// The downloader's exit status when a server answers with a redirect,
/// which the helper never follows (`--location --max-redirs 0`).
const DOWNLOADER_REDIRECT_REFUSED: i32 = 47;

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
            v: PROTOCOL_VERSION,
            kind,
            url: url.into(),
            max_bytes,
            timeout_seconds: timeout.as_secs().clamp(1, MAX_FETCH_SECONDS),
        }
    }

    /// The downloader's complete argument list for this request, or the
    /// reason the request is refused. Nothing in it comes from the request
    /// except the validated URL and the two bounds. `update_base` is the
    /// update channel's validated base URL, which every update URL must lie
    /// beneath; with none, no update URL is accepted.
    pub fn arguments(&self, update_base: Option<&str>) -> Result<Vec<String>, String> {
        if self.v != PROTOCOL_VERSION {
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
            FetchKind::Update => {
                let url = validate_https_url(&self.url)
                    .map_err(|reason| format!("the update URL is refused: {reason}"))?;
                let base = update_base.ok_or_else(|| {
                    "the update URL is refused: no update channel base is configured".to_string()
                })?;
                if !url.starts_with(base) || url.as_bytes().get(base.len()) != Some(&b'/') {
                    return Err(
                        "the update URL is refused: it is not beneath the update channel's base"
                            .to_string(),
                    );
                }
                url
            }
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
            // A redirect is a failure, never followed: `--location` with no
            // redirects allowed makes the downloader refuse one outright,
            // rather than hand back the redirect's own body as if it were the
            // file.
            "--location",
            "--max-redirs",
            "0",
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
        arguments.push(url);
        Ok(arguments)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchResponse {
    pub v: u32,
    pub ok: bool,
    /// Bytes written into the pipe. punard counts what it read and refuses
    /// the transfer if the two differ.
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

    /// Download `request` into `destination`, an empty regular file punard
    /// opened for writing. The file never leaves punard: the helper gets a
    /// pipe, and punard copies what arrives on it, up to `max_bytes`, into
    /// the file. On any failure the file is emptied. Returns the number of
    /// bytes written; the caller still verifies what they are.
    pub fn fetch(&self, request: &FetchRequest, destination: &File) -> Result<u64, FetchError> {
        let result = self.transfer(request, destination);
        match &result {
            Ok(_) => destination
                .sync_all()
                .map_err(|error| FetchError::Unavailable(format!("could not sync: {error}")))?,
            Err(_) => {
                // Never leave part of a transfer where a whole one belongs.
                let _ = destination.set_len(0);
            }
        }
        result
    }

    fn transfer(&self, request: &FetchRequest, destination: &File) -> Result<u64, FetchError> {
        let unavailable = |what: &str, error: io::Error| {
            FetchError::Unavailable(format!("{what} {}: {error}", self.socket.display()))
        };
        let started = Instant::now();
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
        let deadline = started
            + Duration::from_secs(request.timeout_seconds)
                .saturating_add(Duration::from_secs(CONNECT_TIMEOUT_SECONDS))
                .saturating_add(ANSWER_GRACE);
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
        let (body, body_end) =
            io::pipe().map_err(|error| unavailable("could not open a pipe for", error))?;
        send_record(&socket, &record, Some(body_end.as_fd()))
            .map_err(|error| unavailable("could not send the request to", error))?;
        // punard keeps no write end: the pipe ends when the helper's does.
        drop(body_end);

        let received = receive_body(body, destination, request.max_bytes, deadline)?;

        // The helper answers only after its end of the pipe is closed, so the
        // answer describes every byte that arrived.
        let left = deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_secs(1));
        rustix::net::sockopt::set_socket_timeout(&socket, Timeout::Recv, Some(left))
            .map_err(|error| unavailable("could not bound the wait on", error.into()))?;
        let (answer, descriptors) = receive_record(&socket)
            .map_err(|error| unavailable("no answer arrived from", error))?;
        if !descriptors.is_empty() {
            return Err(FetchError::Protocol(
                "the answer carried a descriptor".into(),
            ));
        }
        let response: FetchResponse = serde_json::from_slice(&answer)
            .map_err(|error| FetchError::Protocol(error.to_string()))?;
        if response.v != PROTOCOL_VERSION {
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
        // The helper's count and punard's must agree; anything else means
        // the answer does not describe these bytes.
        if received != response.bytes {
            return Err(FetchError::Protocol(format!(
                "the helper reported {} bytes but {received} arrived",
                response.bytes
            )));
        }
        Ok(received)
    }
}

/// Copy the pipe into `destination` until every write end is closed, at most
/// `max_bytes`, and no later than `deadline`. Returning drops the read end,
/// so a helper still writing gets a broken pipe and stops at once instead of
/// running on to its own time limit.
fn receive_body(
    body: PipeReader,
    destination: &File,
    max_bytes: u64,
    deadline: Instant,
) -> Result<u64, FetchError> {
    let mut body = body;
    let mut output = destination;
    let mut written: u64 = 0;
    let mut chunk = vec![0_u8; COPY_CHUNK];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(FetchError::Unavailable(
                "the download did not finish in time".to_string(),
            ));
        }
        let timeout = Timespec::try_from(left).map_err(|error| {
            FetchError::Unavailable(format!("could not bound the wait: {error}"))
        })?;
        let polled = {
            let mut ready = [PollFd::new(&body, PollFlags::IN)];
            rustix::event::poll(&mut ready, Some(&timeout))
        };
        match polled {
            Ok(0) => continue,
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => {
                return Err(FetchError::Unavailable(format!(
                    "the download could not be waited for: {error}"
                )));
            }
        }
        let count = match body.read(&mut chunk) {
            Ok(0) => return Ok(written),
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(FetchError::Unavailable(format!(
                    "the download could not be read: {error}"
                )));
            }
        };
        let total = written.saturating_add(count as u64);
        if total > max_bytes {
            return Err(FetchError::Refused(format!(
                "the response is larger than the {max_bytes} bytes it may be"
            )));
        }
        output.write_all(&chunk[..count]).map_err(|error| {
            FetchError::Unavailable(format!("the staged file could not be written: {error}"))
        })?;
        written = total;
    }
}

/// Proxy settings for the downloader, read from the helper's own environment.
/// Only root sets that environment (the service manager's
/// `DefaultEnvironment=`, or a drop-in for `punar-fetch@.service`); a request
/// cannot. The helper validates them and passes these two variables, and
/// nothing else of its environment, to the downloader. A proxy on this
/// machine or the local network is also subject to the unit's address rules,
/// so it needs an `IPAddressAllow=` for its address beside it.
#[derive(Clone, Debug, Default)]
pub struct ProxySettings {
    pub https_proxy: Option<String>,
    pub no_proxy: Option<String>,
}

impl ProxySettings {
    /// The settings in this process's environment: `https_proxy` or
    /// `HTTPS_PROXY`, and `no_proxy` or `NO_PROXY`, lower case first as the
    /// downloader itself reads them.
    pub fn from_environment() -> Self {
        let read = |lower: &str, upper: &str| {
            [lower, upper]
                .into_iter()
                .find_map(|name| match std::env::var(name) {
                    Ok(value) if !value.is_empty() => Some(value),
                    Ok(_) | Err(std::env::VarError::NotPresent) => None,
                    // Present but unreadable is refused below, never ignored:
                    // going direct would bypass a proxy an organization requires.
                    Err(std::env::VarError::NotUnicode(value)) => {
                        Some(value.to_string_lossy().into_owned())
                    }
                })
        };
        Self {
            https_proxy: read("https_proxy", "HTTPS_PROXY"),
            no_proxy: read("no_proxy", "NO_PROXY"),
        }
    }

    /// The downloader's environment, or why the configured proxy is refused.
    /// A proxy that is set but invalid refuses every transfer rather than
    /// letting one go direct.
    fn environment(&self) -> Result<Vec<(&'static str, String)>, String> {
        let mut environment = Vec::new();
        if let Some(proxy) = &self.https_proxy {
            let proxy = validate_proxy_url(proxy)
                .map_err(|reason| format!("the configured https_proxy is refused: {reason}"))?;
            environment.push(("https_proxy", proxy));
        }
        if let Some(exceptions) = &self.no_proxy {
            if exceptions.len() > URL_MAX
                || !exceptions.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(
                            byte,
                            b'.' | b',' | b'-' | b'_' | b'*' | b':' | b'/' | b'[' | b']' | b' '
                        )
                })
            {
                return Err(
                    "the configured no_proxy is refused: it must be a list of hosts, domains or addresses"
                        .to_string(),
                );
            }
            environment.push(("no_proxy", exceptions.clone()));
        }
        Ok(environment)
    }
}

/// An `http://` or `https://` proxy: a scheme and an authority (optional
/// userinfo, a host or bracketed address, an optional port), nothing after
/// but an optional `/`.
pub fn validate_proxy_url(value: &str) -> Result<String, &'static str> {
    if value.is_empty()
        || value.len() > URL_MAX
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err("it must be one line of ASCII without whitespace");
    }
    let lower = value.to_ascii_lowercase();
    let scheme = ["http://", "https://"]
        .into_iter()
        .find(|scheme| lower.starts_with(scheme))
        .ok_or("only an http:// or https:// proxy is accepted")?;
    let authority = &value[scheme.len()..];
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    if authority.is_empty()
        || !authority.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'-' | b'.'
                        | b'_'
                        | b'~'
                        | b':'
                        | b'@'
                        | b'['
                        | b']'
                        | b'%'
                        | b'!'
                        | b'$'
                        | b'&'
                        | b'\''
                        | b'('
                        | b')'
                        | b'*'
                        | b'+'
                        | b','
                        | b';'
                        | b'='
                )
        })
    {
        return Err("only a host and port may follow the scheme");
    }
    Ok(value.to_string())
}

/// The helper's configuration. The binary supplies every field; tests point
/// them at fixtures.
#[derive(Clone, Debug)]
pub struct HelperConfig {
    /// The downloader the helper runs, with a fixed argument list.
    pub downloader: PathBuf,
    /// The only uid whose requests are served: punard's, 0.
    pub requester_uid: u32,
    /// The root-owned file naming the update channel's base URL.
    pub update_base_file: PathBuf,
    /// The uid that file must belong to: root's, 0.
    pub update_base_owner_uid: u32,
    /// The proxy, if root configured one for the helper.
    pub proxy: ProxySettings,
}

/// Serve exactly one request on `connection` and answer it. The helper
/// binary calls this with its socket-activated standard input.
pub fn serve(connection: BorrowedFd<'_>, config: &HelperConfig) -> Result<u64, FetchError> {
    // Every descriptor the request carried, the pipe included, is closed
    // when this returns, before the answer is sent: punard reads the body to
    // its end first, and the end arrives only once the pipe is closed.
    let result = serve_request(connection, config);
    let response = match &result {
        Ok(bytes) => FetchResponse {
            v: PROTOCOL_VERSION,
            ok: true,
            bytes: *bytes,
            error: None,
        },
        Err(reason) => FetchResponse {
            v: PROTOCOL_VERSION,
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
            "a request carries exactly one descriptor, not {}",
            descriptors.len()
        ));
    }
    let body = File::from(descriptors.pop().expect("length checked"));
    let is_pipe = body
        .metadata()
        .map_err(|error| format!("the descriptor could not be inspected: {error}"))?
        .file_type()
        .is_fifo();
    if !is_pipe {
        return Err("the descriptor must be a pipe".to_string());
    }
    let request: FetchRequest = serde_json::from_slice(&record)
        .map_err(|error| format!("the request is malformed: {error}"))?;
    let update_base = match request.kind {
        FetchKind::Update => Some(
            read_update_base(&config.update_base_file, config.update_base_owner_uid).map_err(
                |reason| {
                    format!(
                        "the update channel base {} is unusable: {reason}",
                        config.update_base_file.display()
                    )
                },
            )?,
        ),
        FetchKind::Vendor => None,
    };
    let arguments = request.arguments(update_base.as_deref())?;
    let environment = config.proxy.environment()?;
    download(
        &config.downloader,
        &arguments,
        &environment,
        request.max_bytes,
        &body,
    )
    .map_err(|reason| match (&config.proxy.https_proxy, reason) {
        (Some(_), Unreached::Connect(reason)) => format!(
            "{reason}; a proxy is configured, and one on this machine or the local network \
             needs an IPAddressAllow= drop-in for punar-fetch@.service"
        ),
        (_, Unreached::Connect(reason) | Unreached::Other(reason)) => reason,
    })
}

/// Why a download failed, split so a proxy's connection failure can carry
/// the one hint that fixes it.
enum Unreached {
    Connect(String),
    Other(String),
}

/// Run the downloader with `arguments`, copying its standard output into
/// the pipe and stopping it the moment the output passes `max_bytes` or
/// punard stops reading.
fn download(
    downloader: &Path,
    arguments: &[String],
    environment: &[(&'static str, String)],
    max_bytes: u64,
    body: &File,
) -> Result<u64, Unreached> {
    let mut child = Command::new(downloader)
        .args(arguments)
        .env_clear()
        .envs(environment.iter().map(|(name, value)| (*name, value)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| Unreached::Other(format!("the downloader could not start: {error}")))?;
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
        .ok_or_else(|| Unreached::Other("the downloader's output was not captured".to_string()))?;
    let mut output: &File = body;
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
            break Err(format!("punard stopped reading the download: {error}"));
        }
        written = total;
    };
    if copied.is_err() {
        let _ = child.kill();
    }
    drop(stdout);
    let status = child.wait().map_err(|error| {
        Unreached::Other(format!("the downloader could not be waited for: {error}"))
    })?;
    let stderr = stderr
        .and_then(|reader| reader.join().ok())
        .unwrap_or_default();
    copied.map_err(Unreached::Other)?;
    if !status.success() {
        let detail = first_line(&stderr);
        return Err(match status.code() {
            Some(DOWNLOADER_REDIRECT_REFUSED) => Unreached::Other(
                "the server answered with a redirect, and downloads never follow one".to_string(),
            ),
            Some(code) => {
                let reason = if detail.is_empty() {
                    format!("the download failed (downloader exit {code})")
                } else {
                    format!("the download failed (downloader exit {code}): {detail}")
                };
                // 5: the proxy's name did not resolve; 7: the connection was
                // refused; 28 with "Connection timed out": nothing answered,
                // which is what the kernel dropping the packets looks like.
                // (28 is also the whole transfer's limit, which says
                // "Operation timed out" instead.)
                if matches!(code, 5 | 7) || (code == 28 && detail.contains("Connection timed out"))
                {
                    Unreached::Connect(reason)
                } else {
                    Unreached::Other(reason)
                }
            }
            None => Unreached::Other("the downloader was stopped by a signal".to_string()),
        });
    }
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

/// The update channel's base URL from its root-owned file: a regular file,
/// not a symlink, owned by `expected_uid`, writable by no one else and
/// readable by everyone, one line that passes [`validate_https_url`]. punard
/// and the helper both read it through this function, so they cannot
/// disagree about the origin, and punard refuses a file the helper could not
/// read (the helper runs as a dynamic user, so only "other" read access
/// reaches it) instead of letting every download fail on a permission error.
pub fn read_update_base(path: &Path, expected_uid: u32) -> Result<String, String> {
    const BASE_MAX: u64 = 2048;
    let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(i32::try_from(flags.bits()).expect("open flags fit libc::c_int"))
        .open(path)
        .map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() {
        return Err("it is not a regular file".to_string());
    }
    if metadata.uid() != expected_uid || metadata.mode() & 0o022 != 0 {
        return Err(format!(
            "it must be owned by uid {expected_uid} and not be group/other writable"
        ));
    }
    if metadata.mode() & 0o004 == 0 {
        return Err(
            "it must be readable by others (mode 0644): the unprivileged download helper, \
             which runs as a dynamic user, reads it too"
                .to_string(),
        );
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(BASE_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > BASE_MAX {
        return Err("it exceeds 2048 bytes".to_string());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "it is not UTF-8".to_string())?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    let line = line.strip_suffix('\r').unwrap_or(line);
    validate_https_url(line).map_err(str::to_string)
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

    /// A helper configuration for tests: `downloader` is a fixture, the
    /// requester and the update base's owner are this test process.
    pub(crate) fn config(downloader: &Path, update_base_file: &Path) -> HelperConfig {
        let uid = rustix::process::geteuid().as_raw();
        HelperConfig {
            downloader: downloader.to_path_buf(),
            requester_uid: uid,
            update_base_file: update_base_file.to_path_buf(),
            update_base_owner_uid: uid,
            proxy: ProxySettings::default(),
        }
    }

    pub(crate) fn spawn_helper(socket: &Path, config: HelperConfig) {
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
    use std::os::unix::fs::PermissionsExt;
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

    /// The update base file every update request here is beneath.
    fn update_base(root: &Path) -> PathBuf {
        let path = root.join("update-repository.url");
        fs::write(&path, format!("{UPDATE_BASE}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        path
    }

    fn client_for(root: &Path, body: &str) -> FetchClient {
        client_with(root, body, ProxySettings::default())
    }

    fn client_with(root: &Path, body: &str, proxy: ProxySettings) -> FetchClient {
        let socket = root.join("fetch.sock");
        let mut config = testing::config(&downloader(root, body), &update_base(root));
        config.proxy = proxy;
        testing::spawn_helper(&socket, config);
        FetchClient::new(socket)
    }

    /// A stand-in for a helper that has been taken over: it serves one
    /// connection with `behave`, which gets the request's descriptor.
    fn rogue_helper(
        socket: &Path,
        behave: impl FnOnce(BorrowedFd<'_>, File) + Send + 'static,
    ) -> std::thread::JoinHandle<()> {
        let listener = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        rustix::net::bind(&listener, &SocketAddrUnix::new(socket).unwrap()).unwrap();
        rustix::net::listen(&listener, 1).unwrap();
        std::thread::spawn(move || {
            let connection = rustix::net::accept(&listener).unwrap();
            let (_, mut descriptors) = receive_record(&connection).unwrap();
            behave(connection.as_fd(), File::from(descriptors.pop().unwrap()));
        })
    }

    fn answer(connection: BorrowedFd<'_>, bytes: u64) {
        let record = serde_json::to_vec(&FetchResponse {
            v: PROTOCOL_VERSION,
            ok: true,
            bytes,
            error: None,
        })
        .unwrap();
        send_record(connection, &record, None).unwrap();
    }

    const UPDATE_BASE: &str = "https://updates.example.test/punar";
    const UPDATE_URL: &str = "https://updates.example.test/punar/stable/aarch64/uefi/channel.json";

    #[test]
    fn the_bytes_land_in_punards_own_file_and_the_count_is_checked() {
        let root = root("ok");
        let client = client_for(
            &root,
            &format!(
                "printf '%s\\n' \"$@\" > '{}'\nenv > '{}'\nprintf verified-bytes",
                root.join("argv").display(),
                root.join("env").display()
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
            "--location\n--max-redirs\n0\n",
            "--tlsv1.2\n",
            "--max-filesize\n64\n",
            "--max-time\n30\n",
        ] {
            assert!(argv.contains(fixed), "missing {fixed:?} in {argv}");
        }
        assert!(argv.ends_with(&format!("{UPDATE_URL}\n")));
        let environment = fs::read_to_string(root.join("env")).unwrap();
        assert!(
            !environment.contains("proxy"),
            "no proxy was configured, so none reaches the downloader: {environment}"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_helper_is_handed_a_pipe_and_never_punards_file() {
        // What punard verifies is a file only punard holds. The helper gets
        // the write end of a pipe, so neither it nor a downloader that took
        // it over can reach that file, before or after it answers.
        let root = root("pipe-only");
        let socket = root.join("fetch.sock");
        let (report, reported) = std::sync::mpsc::channel();
        let rogue = rogue_helper(&socket, move |connection, body| {
            let is_pipe = body.metadata().unwrap().file_type().is_fifo();
            let mut writer = &body;
            writer.write_all(b"verified-bytes").unwrap();
            drop(body);
            answer(connection, 14);
            report.send(is_pipe).unwrap();
        });
        let (path, file) = destination(&root);
        let bytes = FetchClient::new(&socket)
            .fetch(
                &FetchRequest::update(UPDATE_URL, 64, Duration::from_secs(30)),
                &file,
            )
            .unwrap();
        rogue.join().unwrap();
        assert!(reported.recv().unwrap(), "the helper is handed a pipe");
        assert_eq!(bytes, 14);
        assert_eq!(fs::read(&path).unwrap(), b"verified-bytes");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bytes_written_after_the_answer_fail_the_transfer_instead_of_joining_it() {
        // A helper that answers "ok" for the real bytes and then keeps
        // writing gets nothing past punard: punard reads to the end of the
        // pipe before it reads the answer, the answer must count every byte
        // that arrived, and a mismatch empties the file.
        let root = root("late-write");
        let socket = root.join("fetch.sock");
        let rogue = rogue_helper(&socket, move |connection, body| {
            let mut writer = &body;
            writer.write_all(b"verified-bytes").unwrap();
            answer(connection, 14);
            std::thread::sleep(Duration::from_millis(200));
            writer.write_all(b"-and-a-payload").unwrap();
        });
        let (path, file) = destination(&root);
        let error = FetchClient::new(&socket)
            .fetch(
                &FetchRequest::update(UPDATE_URL, 64, Duration::from_secs(30)),
                &file,
            )
            .unwrap_err();
        rogue.join().unwrap();
        assert!(matches!(error, FetchError::Protocol(_)), "{error}");
        assert!(
            error
                .to_string()
                .contains("reported 14 bytes but 28 arrived")
        );
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_helper_that_writes_past_the_bound_is_cut_off_and_nothing_is_kept() {
        // punard bounds the transfer itself, whatever the helper claims, and
        // the helper's next write after punard gives up is a broken pipe, so
        // it stops at once rather than running on to its time limit.
        let root = root("rogue-oversize");
        let socket = root.join("fetch.sock");
        let (report, reported) = std::sync::mpsc::channel();
        let rogue = rogue_helper(&socket, move |_connection, body| {
            let mut writer = &body;
            let chunk = [b'x'; 1024];
            let outcome = loop {
                if let Err(error) = writer.write_all(&chunk) {
                    break error.kind();
                }
            };
            report.send(outcome).unwrap();
        });
        let (path, file) = destination(&root);
        let error = FetchClient::new(&socket)
            .fetch(
                &FetchRequest::update(UPDATE_URL, 4096, Duration::from_secs(30)),
                &file,
            )
            .unwrap_err();
        assert!(matches!(error, FetchError::Refused(_)), "{error}");
        assert!(error.to_string().contains("larger than the 4096 bytes"));
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
        rogue.join().unwrap();
        assert_eq!(reported.recv().unwrap(), io::ErrorKind::BrokenPipe);
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
    fn a_redirect_is_refused_for_every_kind() {
        let root = root("redirect");
        let client = client_for(
            &root,
            &format!(
                "printf '%s\\n' \"$@\" > '{}'\nprintf 'curl: (47) Maximum (0) redirects followed\\n' >&2\nexit 47",
                root.join("argv").display()
            ),
        );
        for request in [
            FetchRequest::update(UPDATE_URL, 64, Duration::from_secs(30)),
            FetchRequest::vendor(
                "https://downloads.claude.ai/claude-desktop/apt/stable/pool/main/c/claude-desktop_1.0_amd64.deb",
                64,
                Duration::from_secs(30),
            ),
        ] {
            let (_path, file) = {
                let path = root.join(format!("staged-{:?}", request.kind));
                let file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .unwrap();
                (path, file)
            };
            let error = client.fetch(&request, &file).unwrap_err().to_string();
            assert!(error.contains("never follow"), "{error}");
            let argv = fs::read_to_string(root.join("argv")).unwrap();
            assert!(argv.contains("--location\n--max-redirs\n0\n"), "{argv}");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_vendor_download_comes_only_from_a_catalog_origin() {
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
        assert!(argv.contains("--location\n--max-redirs\n0\n"), "{argv}");
        assert!(argv.ends_with(&format!("{url}\n")));

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
    fn an_update_download_comes_only_from_beneath_the_root_owned_base() {
        let root = root("update-origin");
        let client = client_for(&root, "printf bytes");
        for url in [
            // Another host entirely.
            "https://attacker.example/punar/stable/aarch64/uefi/channel.json",
            // A host that merely starts with the base's.
            "https://updates.example.test.attacker.example/punar/channel.json",
            // A sibling path that shares the base's prefix.
            "https://updates.example.test/punar-evil/channel.json",
            // The base itself names a directory, not a file.
            "https://updates.example.test/punar",
        ] {
            let path = root.join(format!("staged-{}", SEQ.fetch_add(1, Ordering::SeqCst)));
            let file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            let error = client
                .fetch(
                    &FetchRequest::update(url, 64, Duration::from_secs(30)),
                    &file,
                )
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("not beneath the update channel's base"),
                "accepted {url:?}: {error}"
            );
        }

        // No base, or a base anyone could have written, refuses every update
        // URL: the helper never falls back to trusting the request.
        let base = root.join("update-repository.url");
        fs::set_permissions(&base, fs::Permissions::from_mode(0o666)).unwrap();
        let (_path, file) = destination(&root);
        let error = client
            .fetch(
                &FetchRequest::update(UPDATE_URL, 64, Duration::from_secs(30)),
                &file,
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("group/other writable"), "{error}");
        fs::remove_file(&base).unwrap();
        let path = root.join("staged-absent");
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let error = client
            .fetch(
                &FetchRequest::update(UPDATE_URL, 64, Duration::from_secs(30)),
                &file,
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("update channel base"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_proxy_root_configured_reaches_the_downloader_and_nothing_else_does() {
        let root = root("proxy");
        let client = client_with(
            &root,
            &format!("env > '{}'\nprintf bytes", root.join("env").display()),
            ProxySettings {
                https_proxy: Some("http://10.20.30.40:3128".to_string()),
                no_proxy: Some("localhost,.corp.example".to_string()),
            },
        );
        let (_path, file) = destination(&root);
        client
            .fetch(
                &FetchRequest::update(UPDATE_URL, 64, Duration::from_secs(30)),
                &file,
            )
            .unwrap();
        let environment = fs::read_to_string(root.join("env")).unwrap();
        let mut names: Vec<&str> = environment
            .lines()
            .filter_map(|line| line.split_once('=').map(|(name, _)| name))
            .filter(|name| !matches!(*name, "PWD" | "OLDPWD" | "SHLVL" | "_"))
            .collect();
        names.sort_unstable();
        assert_eq!(names, ["https_proxy", "no_proxy"], "{environment}");
        assert!(environment.contains("https_proxy=http://10.20.30.40:3128\n"));
        assert!(environment.contains("no_proxy=localhost,.corp.example\n"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn an_invalid_proxy_refuses_the_transfer_rather_than_going_direct() {
        for (proxy, no_proxy) in [
            (Some("socks4://10.0.0.1:1080"), None),
            (Some("http://proxy.example:3128/path?x"), None),
            (Some("http://proxy.example:3128\n--insecure"), None),
            (Some("--proxy-insecure"), None),
            (None, Some("localhost;rm")),
        ] {
            let root = root("bad-proxy");
            let client = client_with(
                &root,
                &format!("printf ran > '{}'", root.join("ran").display()),
                ProxySettings {
                    https_proxy: proxy.map(str::to_string),
                    no_proxy: no_proxy.map(str::to_string),
                },
            );
            let (_path, file) = destination(&root);
            let error = client
                .fetch(
                    &FetchRequest::update(UPDATE_URL, 64, Duration::from_secs(30)),
                    &file,
                )
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("is refused"),
                "{proxy:?} {no_proxy:?}: {error}"
            );
            assert!(
                !root.join("ran").exists(),
                "the downloader never runs with a refused proxy"
            );
            fs::remove_dir_all(root).unwrap();
        }
        for accepted in [
            "http://proxy.corp.example:3128",
            "https://10.1.2.3:8443/",
            "http://[fd00::1]:3128",
            "HTTP://proxy:8080",
        ] {
            assert!(validate_proxy_url(accepted).is_ok(), "{accepted}");
        }
    }

    #[test]
    fn a_proxy_that_cannot_be_reached_names_the_drop_in_that_allows_it() {
        // Refused, and dropped by the kernel (which only times out); a
        // transfer that ran out of time is not a reachability problem.
        for (body, code, hinted) in [
            (
                "printf 'curl: (7) Failed to connect to 10.20.30.40 port 3128\\n' >&2\nexit 7",
                7,
                true,
            ),
            (
                "printf 'curl: (28) Connection timed out after 10001 milliseconds\\n' >&2\nexit 28",
                28,
                true,
            ),
            (
                "printf 'curl: (28) Operation timed out after 30000 milliseconds with 5 bytes received\\n' >&2\nexit 28",
                28,
                false,
            ),
        ] {
            let root = root("proxy-unreached");
            let client = client_with(
                &root,
                body,
                ProxySettings {
                    https_proxy: Some("http://10.20.30.40:3128".to_string()),
                    no_proxy: None,
                },
            );
            let (_path, file) = destination(&root);
            let error = client
                .fetch(
                    &FetchRequest::update(UPDATE_URL, 64, Duration::from_secs(30)),
                    &file,
                )
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(&format!("downloader exit {code}")),
                "{error}"
            );
            assert_eq!(error.contains("IPAddressAllow="), hinted, "{error}");
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn requests_that_choose_their_own_origin_or_options_are_refused() {
        let base = Some(UPDATE_BASE);
        for url in [
            "http://updates.example.test/punar/channel.json",
            "https://user@updates.example.test/punar/channel.json",
            "https://updates.example.test/punar/channel.json?x=1",
            "https://updates.example.test/punar/../channel.json",
            "https://updates.example.test/punar/%2e%2e/channel.json",
            "https://[::1]/channel.json",
            "--config=/etc/shadow",
            "https://updates.example.test/punar/a b",
        ] {
            let request = FetchRequest::update(url, 10, Duration::from_secs(10));
            assert!(request.arguments(base).is_err(), "accepted {url:?}");
        }
        assert!(
            FetchRequest::update(UPDATE_URL, 10, Duration::from_secs(10))
                .arguments(None)
                .is_err(),
            "an update URL with no configured base"
        );
        for url in [
            "https://downloads.claude.ai/claude-desktop/apt/stable/pool/main/../../../../x.deb",
            "https://downloads.claude.ai/claude-desktop/apt/stable/pool/main/",
            "https://downloads.claude.ai.attacker.example/claude-desktop/apt/stable/pool/main/x.deb",
            "https://downloads.claude.ai/claude-desktop/apt/stable/pool/main/%2e%2e/x.deb",
        ] {
            let request = FetchRequest::vendor(url, 10, Duration::from_secs(10));
            assert!(request.arguments(None).is_err(), "accepted {url:?}");
        }
        let mut request = FetchRequest::update(UPDATE_URL, 0, Duration::from_secs(10));
        assert!(request.arguments(base).is_err(), "a zero-byte bound");
        request.max_bytes = MAX_FETCH_BYTES + 1;
        assert!(request.arguments(base).is_err(), "a bound past the ceiling");
        request.max_bytes = 10;
        request.timeout_seconds = MAX_FETCH_SECONDS + 1;
        assert!(request.arguments(base).is_err(), "a limit past the ceiling");
        request.timeout_seconds = 10;
        request.v = 1;
        assert!(request.arguments(base).is_err(), "an older version");
        request.v = PROTOCOL_VERSION;
        assert!(request.arguments(base).is_ok());
        let unknown = r#"{"v":2,"kind":"update","url":"https://updates.example.test/punar/x","max_bytes":1,"timeout_seconds":1,"args":["--insecure"]}"#;
        assert!(serde_json::from_str::<FetchRequest>(unknown).is_err());
    }

    #[test]
    fn a_descriptor_that_is_not_a_pipe_is_refused() {
        // A request that hands the helper a file instead of a pipe is
        // refused before anything is downloaded, and the file is untouched.
        let root = root("not-a-pipe");
        let socket = root.join("fetch.sock");
        let ran = root.join("ran");
        testing::spawn_helper(
            &socket,
            testing::config(
                &downloader(&root, &format!("printf ran > '{}'", ran.display())),
                &update_base(&root),
            ),
        );
        let (path, file) = destination(&root);
        let connection = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        rustix::net::connect(&connection, &SocketAddrUnix::new(&socket).unwrap()).unwrap();
        let record = serde_json::to_vec(&FetchRequest::update(
            UPDATE_URL,
            64,
            Duration::from_secs(30),
        ))
        .unwrap();
        send_record(&connection, &record, Some(file.as_fd())).unwrap();
        let (answer, _) = receive_record(&connection).unwrap();
        let response: FetchResponse = serde_json::from_slice(&answer).unwrap();
        assert!(!response.ok);
        assert!(
            response
                .error
                .as_deref()
                .unwrap_or("")
                .contains("must be a pipe"),
            "{response:?}"
        );
        assert!(!ran.exists());
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
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
        let mut config = testing::config(&downloader(&root, "printf bytes"), &update_base(&root));
        config.requester_uid = config.requester_uid.wrapping_add(1);
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
