//! TLS-authenticated IMAP and SMTP verification for open-protocol accounts.
//!
//! The verifier accepts no insecure-certificate switch. Both implicit TLS and
//! STARTTLS authenticate the configured hostname through Punar's platform CA
//! policy. Each network phase has an absolute deadline, and the IMAP wrapper
//! caps aggregate response bytes before the upstream parser's larger ceiling.

use std::fmt::Debug;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_imap::Client;
use mail_send::SmtpClientBuilder;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::runtime::Builder;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::{
    MailServerConfig, MailServerSecurity, OpenProtocolAccountInput, OpenProtocolConfig,
    OpenProtocolVerifier, ProviderCheckError, VerifiedOpenProtocolIdentity,
};

const DEFAULT_NETWORK_DEADLINE: Duration = Duration::from_secs(20);
const MAX_IMAP_VERIFY_BYTES: usize = 1024 * 1024;
const READ_CHUNK_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct NetworkOpenProtocolVerifier {
    deadline: Duration,
}

impl Default for NetworkOpenProtocolVerifier {
    fn default() -> Self {
        Self {
            deadline: DEFAULT_NETWORK_DEADLINE,
        }
    }
}

impl NetworkOpenProtocolVerifier {
    #[must_use]
    pub fn with_deadline(deadline: Duration) -> Self {
        Self { deadline }
    }

    async fn verify_async(
        &self,
        config: &OpenProtocolConfig,
        password: &str,
    ) -> Result<(), ProviderCheckError> {
        self.verify_imap(config, password).await?;
        self.verify_smtp(config, password).await
    }

    async fn verify_imap(
        &self,
        config: &OpenProtocolConfig,
        password: &str,
    ) -> Result<(), ProviderCheckError> {
        let (stream, needs_greeting) = self.connect_imap(&config.imap).await?;
        let mut client = Client::new(stream);
        if needs_greeting {
            let greeting = timeout(self.deadline, client.read_response())
                .await
                .map_err(|_| ProviderCheckError::Unreachable)?
                .map_err(|_| ProviderCheckError::InvalidResponse)?;
            if greeting.is_none() {
                return Err(ProviderCheckError::InvalidResponse);
            }
        }

        let login = timeout(
            self.deadline,
            client.login(config.username.as_str(), password),
        )
        .await
        .map_err(|_| ProviderCheckError::Unreachable)?;
        let mut session = login.map_err(|(error, _)| map_imap_login_error(error))?;
        let _ = timeout(self.deadline, session.logout()).await;
        Ok(())
    }

    async fn connect_imap(
        &self,
        server: &MailServerConfig,
    ) -> Result<(BoundedIo<TlsStream<TcpStream>>, bool), ProviderCheckError> {
        let tcp = timeout(
            self.deadline,
            TcpStream::connect((server.host.as_str(), server.port)),
        )
        .await
        .map_err(|_| ProviderCheckError::Unreachable)?
        .map_err(|_| ProviderCheckError::Unreachable)?;

        let connector = tls_connector()?;
        let server_name =
            ServerName::try_from(server.host.clone()).map_err(|_| ProviderCheckError::Tls)?;

        match server.security {
            MailServerSecurity::Tls => {
                let stream = timeout(self.deadline, connector.connect(server_name, tcp))
                    .await
                    .map_err(|_| ProviderCheckError::Unreachable)?
                    .map_err(|_| ProviderCheckError::Tls)?;
                Ok((BoundedIo::new(stream, MAX_IMAP_VERIFY_BYTES), true))
            }
            MailServerSecurity::StartTls => {
                let mut client = Client::new(BoundedIo::new(tcp, MAX_IMAP_VERIFY_BYTES));
                let greeting = timeout(self.deadline, client.read_response())
                    .await
                    .map_err(|_| ProviderCheckError::Unreachable)?
                    .map_err(|_| ProviderCheckError::InvalidResponse)?;
                if greeting.is_none() {
                    return Err(ProviderCheckError::InvalidResponse);
                }
                timeout(
                    self.deadline,
                    client.run_command_and_check_ok("STARTTLS", None),
                )
                .await
                .map_err(|_| ProviderCheckError::Unreachable)?
                .map_err(|_| ProviderCheckError::Tls)?;
                let tcp = client.into_inner().into_inner();
                let stream = timeout(self.deadline, connector.connect(server_name, tcp))
                    .await
                    .map_err(|_| ProviderCheckError::Unreachable)?
                    .map_err(|_| ProviderCheckError::Tls)?;
                Ok((BoundedIo::new(stream, MAX_IMAP_VERIFY_BYTES), false))
            }
        }
    }

    async fn verify_smtp(
        &self,
        config: &OpenProtocolConfig,
        password: &str,
    ) -> Result<(), ProviderCheckError> {
        let builder = SmtpClientBuilder::new(config.smtp.host.as_str(), config.smtp.port)
            .map_err(|_| ProviderCheckError::Tls)?
            .implicit_tls(config.smtp.security == MailServerSecurity::Tls)
            .credentials((config.username.as_str(), password))
            .timeout(self.deadline);
        let client = builder.connect().await.map_err(map_smtp_error)?;
        let _ = client.quit().await;
        Ok(())
    }
}

impl OpenProtocolVerifier for NetworkOpenProtocolVerifier {
    fn verify(
        &self,
        config: &OpenProtocolConfig,
        identity: &OpenProtocolAccountInput,
        password: &[u8],
    ) -> Result<VerifiedOpenProtocolIdentity, ProviderCheckError> {
        let password =
            std::str::from_utf8(password).map_err(|_| ProviderCheckError::InvalidCredentials)?;
        let runtime = Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|_| ProviderCheckError::Internal)?;
        runtime.block_on(self.verify_async(config, password))?;
        Ok(VerifiedOpenProtocolIdentity {
            display_name: identity.display_name.clone(),
            primary_address: identity.primary_address.clone(),
        })
    }
}

fn tls_connector() -> Result<TlsConnector, ProviderCheckError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| ProviderCheckError::Tls)?
        .with_platform_verifier()
        .map_err(|_| ProviderCheckError::Tls)?
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

fn map_imap_login_error(error: async_imap::error::Error) -> ProviderCheckError {
    match error {
        async_imap::error::Error::No(_) => ProviderCheckError::InvalidCredentials,
        async_imap::error::Error::Io(_) | async_imap::error::Error::ConnectionLost => {
            ProviderCheckError::Unreachable
        }
        _ => ProviderCheckError::InvalidResponse,
    }
}

fn map_smtp_error(error: mail_send::Error) -> ProviderCheckError {
    match error {
        mail_send::Error::AuthenticationFailed(_) => ProviderCheckError::InvalidCredentials,
        mail_send::Error::Tls(_)
        | mail_send::Error::InvalidTLSName
        | mail_send::Error::MissingStartTls => ProviderCheckError::Tls,
        mail_send::Error::Io(_) | mail_send::Error::Timeout => ProviderCheckError::Unreachable,
        _ => ProviderCheckError::InvalidResponse,
    }
}

/// Aggregate read cap used around the third-party IMAP parser. It also limits
/// each individual read so a peer cannot force a large transient allocation.
#[derive(Debug)]
struct BoundedIo<T> {
    inner: T,
    read: usize,
    max_read: usize,
}

impl<T> BoundedIo<T> {
    fn new(inner: T, max_read: usize) -> Self {
        Self {
            inner,
            read: 0,
            max_read,
        }
    }

    fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for BoundedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let remaining = self.max_read.saturating_sub(self.read);
        if remaining == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IMAP verification response exceeded its byte limit",
            )));
        }
        let wanted = remaining.min(output.remaining()).min(READ_CHUNK_BYTES);
        if wanted == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut scratch = [0_u8; READ_CHUNK_BYTES];
        let mut bounded = ReadBuf::new(&mut scratch[..wanted]);
        match Pin::new(&mut self.inner).poll_read(context, &mut bounded) {
            Poll::Ready(Ok(())) => {
                let bytes = bounded.filled();
                self.read += bytes.len();
                output.put_slice(bytes);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for BoundedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn imap_transport_stops_at_the_aggregate_read_limit() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let (mut writer, reader) = tokio::io::duplex(64);
            let sender = tokio::spawn(async move {
                writer.write_all(b"0123456789abcdefoverflow").await.unwrap();
            });
            let mut bounded = BoundedIo::new(reader, 16);
            let mut first = [0_u8; 16];
            bounded.read_exact(&mut first).await.unwrap();
            assert_eq!(&first, b"0123456789abcdef");
            let mut extra = [0_u8; 1];
            let error = bounded.read(&mut extra).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            sender.await.unwrap();
        });
    }

    #[test]
    fn provider_error_mapping_never_exposes_server_text() {
        let mapped = map_imap_login_error(async_imap::error::Error::No(
            "server-secret diagnostic".into(),
        ));
        assert_eq!(mapped, ProviderCheckError::InvalidCredentials);
        assert!(!mapped.to_string().contains("server-secret"));
    }

    #[test]
    fn non_utf8_password_is_rejected_before_network_use() {
        let verifier = NetworkOpenProtocolVerifier::with_deadline(Duration::from_millis(1));
        let config = OpenProtocolConfig {
            username: "alice".into(),
            imap: MailServerConfig {
                host: "imap.example.com".into(),
                port: 993,
                security: MailServerSecurity::Tls,
            },
            smtp: MailServerConfig {
                host: "smtp.example.com".into(),
                port: 465,
                security: MailServerSecurity::Tls,
            },
        };
        let identity = OpenProtocolAccountInput {
            display_name: "Alice".into(),
            primary_address: crate::EmailAddress {
                name: None,
                address: "alice@example.com".into(),
            },
        };
        assert_eq!(
            verifier.verify(&config, &identity, &[0xff]),
            Err(ProviderCheckError::InvalidCredentials)
        );
    }
}
