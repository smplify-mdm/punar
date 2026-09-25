//! A deliberately small HTTPS/1.1 client: one request per connection, TLS
//! 1.2+, the platform's root store through the same verifier punar-pimd
//! uses (ADR-011), an optional client certificate for the device identity,
//! and a hard wall-clock budget. `http://` is not a scheme this client knows.
//!
//! Small on purpose: every byte that reaches Smplify is composed here, and
//! there is no cookie jar, redirect follower, proxy discovery or connection
//! pool to reason about.
use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls_platform_verifier::BuilderVerifierExt;

/// The largest response body accepted from the control plane.
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("only https:// URLs are accepted")]
    Scheme,
    #[error("malformed URL")]
    Url,
    #[error("TLS configuration failed")]
    Tls,
    #[error("the host could not be resolved")]
    Resolve,
    #[error("connecting timed out")]
    Timeout,
    #[error("transport failed ({0})")]
    Io(ErrorKind),
    #[error("the response was not HTTP/1.1")]
    Malformed,
    #[error("the response was larger than {MAX_RESPONSE_BYTES} bytes")]
    TooLarge,
}

impl From<io::Error> for HttpError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            ErrorKind::TimedOut | ErrorKind::WouldBlock => HttpError::Timeout,
            kind => HttpError::Io(kind),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub host: String,
    pub port: u16,
    /// Path plus query, always starting with `/`.
    pub path: String,
}

impl Url {
    /// Join a path onto a base URL's authority, replacing the base path.
    pub fn with_path(&self, path: &str) -> Url {
        Url {
            host: self.host.clone(),
            port: self.port,
            path: if path.starts_with('/') {
                path.to_string()
            } else {
                format!("/{path}")
            },
        }
    }

    /// The origin (`https://host[:port]`) for messages and storage.
    pub fn origin(&self) -> String {
        if self.port == 443 {
            format!("https://{}", self.host)
        } else {
            format!("https://{}:{}", self.host, self.port)
        }
    }
}

pub fn parse_https_url(raw: &str) -> Result<Url, HttpError> {
    let rest = raw.strip_prefix("https://").ok_or(HttpError::Scheme)?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(HttpError::Url);
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h, p.parse::<u16>().map_err(|_| HttpError::Url)?),
        _ => (authority, 443),
    };
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return Err(HttpError::Url);
    }
    Ok(Url {
        host: host.to_ascii_lowercase(),
        port,
        path: path.to_string(),
    })
}

/// The device's own certificate and key for the mTLS hop.
pub struct ClientIdentity {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

pub struct Request<'a> {
    pub method: &'a str,
    pub url: &'a Url,
    /// The media types this call can use. Spring answers 406 when none of
    /// them is what the endpoint produces, so each call names its own.
    pub accept: &'a str,
    pub bearer: Option<&'a str>,
    pub body: Option<&'a [u8]>,
}

/// What every JSON endpoint of the device API produces.
pub const ACCEPT_JSON: &str = "application/json";

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub struct Client {
    config: Arc<ClientConfig>,
    budget: Duration,
}

impl Client {
    pub fn new(identity: Option<ClientIdentity>, budget: Duration) -> Result<Client, HttpError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| HttpError::Tls)?
            .with_platform_verifier()
            .map_err(|_| HttpError::Tls)?;
        let config = match identity {
            Some(identity) => builder
                .with_client_auth_cert(identity.certs, identity.key)
                .map_err(|_| HttpError::Tls)?,
            None => builder.with_no_client_auth(),
        };
        Ok(Client {
            config: Arc::new(config),
            budget,
        })
    }

    pub fn send(&self, request: &Request<'_>) -> Result<Response, HttpError> {
        let started = Instant::now();
        let target = (request.url.host.clone(), request.url.port);
        let addrs = resolve_within(self.remaining(started)?, move || {
            target.to_socket_addrs().map(Iterator::collect)
        })?;
        let mut tcp = None;
        for addr in addrs {
            let remaining = self.remaining(started)?;
            if let Ok(stream) = TcpStream::connect_timeout(&addr, remaining) {
                tcp = Some(stream);
                break;
            }
        }
        let tcp = tcp.ok_or(HttpError::Resolve)?;
        tcp.set_nodelay(true)?;
        let server_name =
            ServerName::try_from(request.url.host.clone()).map_err(|_| HttpError::Url)?;
        let connection = ClientConnection::new(Arc::clone(&self.config), server_name)
            .map_err(|_| HttpError::Tls)?;
        let mut stream = StreamOwned::new(
            connection,
            Deadlined {
                tcp,
                deadline: started + self.budget,
            },
        );

        let head = request_head(request);

        stream.write_all(head.as_bytes())?;
        if let Some(body) = request.body {
            stream.write_all(body)?;
        }
        stream.flush()?;

        let mut raw = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    raw.extend_from_slice(&chunk[..n]);
                    if raw.len() > MAX_RESPONSE_BYTES {
                        return Err(HttpError::TooLarge);
                    }
                }
                // A peer that closes without close_notify is common; the
                // bytes so far are the response.
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
        }
        parse_response(&raw)
    }

    fn remaining(&self, started: Instant) -> Result<Duration, HttpError> {
        let elapsed = started.elapsed();
        if elapsed >= self.budget {
            return Err(HttpError::Timeout);
        }
        Ok(self.budget - elapsed)
    }
}

/// Resolve a name, waiting at most `within` for the answer. The system
/// resolver has no deadline of its own (a cold lookup can take seconds, a
/// broken one half a minute), and the agent serves one call at a time, so a
/// lookup that outlives the request's budget would hold every call queued
/// behind it past punard's wait. It runs on a thread of its own, which is
/// left to finish when the request gives up on it.
fn resolve_within(
    within: Duration,
    resolve: impl FnOnce() -> io::Result<Vec<SocketAddr>> + Send + 'static,
) -> Result<Vec<SocketAddr>, HttpError> {
    let (answer, answered) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("punar-smplifyd-resolve".to_string())
        .spawn(move || {
            let _ = answer.send(resolve());
        })
        .map_err(|_| HttpError::Resolve)?;
    match answered.recv_timeout(within) {
        Ok(Ok(addrs)) => Ok(addrs),
        Ok(Err(_)) => Err(HttpError::Resolve),
        Err(_) => Err(HttpError::Timeout),
    }
}

/// The connection's socket, held to the request's deadline: every read and
/// every write — the TLS handshake's included, which happens inside the
/// first write — may wait only for the time left. A timeout set once, or
/// only around the response, let a server that accepted the connection and
/// never answered the handshake hold the agent, which serves one call at a
/// time, for good.
struct Deadlined {
    tcp: TcpStream,
    deadline: Instant,
}

impl Deadlined {
    fn left(&self) -> io::Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::from(ErrorKind::TimedOut));
        }
        Ok(left)
    }
}

impl Read for Deadlined {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.left()?;
        self.tcp.set_read_timeout(Some(left))?;
        self.tcp.read(buf)
    }
}

impl Write for Deadlined {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let left = self.left()?;
        self.tcp.set_write_timeout(Some(left))?;
        self.tcp.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

fn host_header(url: &Url) -> String {
    if url.port == 443 {
        url.host.clone()
    } else {
        format!("{}:{}", url.host, url.port)
    }
}

pub fn parse_response(raw: &[u8]) -> Result<Response, HttpError> {
    let head_end = find(raw, b"\r\n\r\n").ok_or(HttpError::Malformed)?;
    let head = std::str::from_utf8(&raw[..head_end]).map_err(|_| HttpError::Malformed)?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or(HttpError::Malformed)?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().ok_or(HttpError::Malformed)?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(HttpError::Malformed);
    }
    let status = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or(HttpError::Malformed)?;
    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(HttpError::Malformed)?;
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    let body_raw = &raw[head_end + 4..];
    let chunked = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
    });
    let body = if chunked {
        dechunk(body_raw)?
    } else {
        let declared = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.parse::<usize>().ok());
        match declared {
            Some(n) if n <= body_raw.len() => body_raw[..n].to_vec(),
            Some(_) => return Err(HttpError::Malformed),
            None => body_raw.to_vec(),
        }
    };
    Ok(Response {
        status,
        headers,
        body,
    })
}

fn dechunk(mut raw: &[u8]) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::new();
    loop {
        let line_end = find(raw, b"\r\n").ok_or(HttpError::Malformed)?;
        let size_text = std::str::from_utf8(&raw[..line_end]).map_err(|_| HttpError::Malformed)?;
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| HttpError::Malformed)?;
        raw = &raw[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if raw.len() < size + 2 {
            return Err(HttpError::Malformed);
        }
        out.extend_from_slice(&raw[..size]);
        if out.len() > MAX_RESPONSE_BYTES {
            return Err(HttpError::TooLarge);
        }
        raw = &raw[size + 2..];
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The request line and headers, exactly as sent.
pub(crate) fn request_head(request: &Request<'_>) -> String {
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: punar-smplifyd/{}\r\nAccept: {}\r\nConnection: close\r\n",
        request.method,
        request.url.path,
        host_header(request.url),
        env!("CARGO_PKG_VERSION"),
        request.accept,
    );
    if let Some(token) = request.bearer {
        head.push_str("Authorization: Bearer ");
        head.push_str(token);
        head.push_str("\r\n");
    }
    if let Some(body) = request.body {
        head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    head.push_str("\r\n");
    head
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_request_names_the_media_types_it_accepts() {
        let url =
            parse_https_url("https://api.smplify.test/api/v1/linux/mdm/devices/d/bundle").unwrap();
        let head = request_head(&Request {
            method: "GET",
            url: &url,
            accept: "application/gzip, application/json;q=0.5",
            bearer: None,
            body: None,
        });
        assert!(
            head.contains("\r\nAccept: application/gzip, application/json;q=0.5\r\n"),
            "{head}"
        );
        assert_eq!(head.matches("Accept:").count(), 1, "{head}");
        assert!(head.ends_with("\r\n\r\n"));
    }

    /// A server that accepts the connection and never answers the TLS
    /// handshake costs one budget, not the agent's every later call.
    #[test]
    fn a_silent_server_costs_one_budget_even_during_the_handshake() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming() {
                held.push(stream);
            }
        });
        let budget = Duration::from_millis(500);
        let client = Client::new(None, budget).unwrap();
        let url = parse_https_url(&format!("https://127.0.0.1:{port}/x")).unwrap();
        let (sender, answer) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let started = Instant::now();
            let result = client.send(&Request {
                method: "GET",
                url: &url,
                accept: ACCEPT_JSON,
                bearer: None,
                body: None,
            });
            let _ = sender.send((started.elapsed(), result.map(|r| r.status)));
        });
        let (took, result) = answer
            .recv_timeout(budget * 10)
            .expect("the request outlived ten budgets");
        assert!(matches!(result, Err(HttpError::Timeout)), "{result:?}");
        assert!(took < budget * 2, "{took:?}");
    }

    /// A name lookup is held to the request's budget like everything after
    /// it: one the system resolver takes far longer to answer is given up on
    /// when the budget ends, and one that answers in time is used.
    #[test]
    fn a_slow_name_lookup_is_given_up_on_at_the_budget() {
        let budget = Duration::from_millis(300);
        let started = Instant::now();
        let slow = resolve_within(budget, || {
            std::thread::sleep(Duration::from_secs(5));
            Ok(vec!["127.0.0.1:443".parse().unwrap()])
        });
        assert!(matches!(slow, Err(HttpError::Timeout)), "{slow:?}");
        assert!(started.elapsed() < budget * 2, "{:?}", started.elapsed());
        let quick = resolve_within(budget, || Ok(vec!["127.0.0.1:443".parse().unwrap()]));
        assert_eq!(quick.unwrap(), vec!["127.0.0.1:443".parse().unwrap()]);
        let failed = resolve_within(budget, || Err(io::Error::other("no such name")));
        assert!(matches!(failed, Err(HttpError::Resolve)), "{failed:?}");
    }

    #[test]
    fn parses_urls_and_refuses_plaintext() {
        let u = parse_https_url("https://api.smplify.test:8443/api/v1/x?y=1").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("api.smplify.test", 8443, "/api/v1/x?y=1")
        );
        assert_eq!(parse_https_url("https://Example.com").unwrap().path, "/");
        assert_eq!(
            parse_https_url("https://Example.com").unwrap().host,
            "example.com"
        );
        assert!(matches!(
            parse_https_url("http://x"),
            Err(HttpError::Scheme)
        ));
        assert!(matches!(
            parse_https_url("https://u@x"),
            Err(HttpError::Url)
        ));
        assert!(matches!(
            parse_https_url("https://x:notaport"),
            Err(HttpError::Url)
        ));
        assert_eq!(
            parse_https_url("https://a.b").unwrap().with_path("c").path,
            "/c"
        );
        assert_eq!(
            parse_https_url("https://a.b:8443").unwrap().origin(),
            "https://a.b:8443"
        );
    }

    #[test]
    fn parses_content_length_and_chunked_bodies() {
        let r = parse_response(b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"a\":1}").unwrap();
        assert_eq!(r.status, 201);
        assert_eq!(r.body, b"{\"a\":1}");
        assert_eq!(r.header("content-type"), Some("application/json"));
        let r = parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3;ext\r\n:1}\r\n0\r\n\r\n").unwrap();
        assert_eq!(r.body, b"{\"a\":1}");
        assert!(matches!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort"),
            Err(HttpError::Malformed)
        ));
        assert!(matches!(
            parse_response(b"garbage"),
            Err(HttpError::Malformed)
        ));
        assert_eq!(
            parse_response(b"HTTP/1.1 204 No Content\r\n\r\n")
                .unwrap()
                .body,
            b""
        );
    }
}
