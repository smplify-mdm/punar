//! Bounded account-setup session lifecycle.
//!
//! Settings can request an opaque setup id, but never receives the helper
//! descriptor or credentials. A privileged fixed launcher must claim the
//! matching unnamed helper endpoint from this coordinator and hand it directly
//! to the short-lived account-entry UI. Unclaimed sessions expire, cancellation
//! closes both ends, and at most four sessions exist per profile service.

use std::collections::BTreeMap;
use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::{
    AccountCoordinator, AccountEntryCode, CredentialVault, EncryptedStorageProof, MailStore,
    NetworkOpenProtocolVerifier, PimStore, ProviderType, VaultError, account_entry_pair,
    complete_account_entry,
};

const MAX_SETUP_SESSIONS: usize = 4;
const SETUP_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountSetupStage {
    AwaitingCredentials,
    Discovering,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSetupStatus {
    pub setup_id: String,
    pub provider_type: ProviderType,
    pub state: AccountSetupStage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AccountConnectError {
    #[error("the requested account provider is not implemented")]
    UnsupportedProvider,
    #[error("too many account setup sessions are active")]
    RateLimited,
    #[error("account setup session was not found")]
    NotFound,
    #[error("account setup runtime failed")]
    Runtime,
}

pub trait AccountConnectLifecycle: Send + Sync + 'static {
    fn begin(&self, provider_type: ProviderType)
    -> Result<AccountSetupStatus, AccountConnectError>;
    fn cancel(&self, setup_id: &str) -> Result<(), AccountConnectError>;
}

pub trait AccountEntryRunner: Send + Sync + 'static {
    fn run(&self, channel: OwnedFd);
}

struct Session {
    created: Instant,
    helper: Option<OwnedFd>,
    service: Option<OwnedFd>,
    cancellation: Option<UnixDatagram>,
}

struct SetupInner {
    runner: Arc<dyn AccountEntryRunner>,
    sessions: Mutex<BTreeMap<String, Session>>,
    ttl: Duration,
    maximum: usize,
}

pub struct SetupSessionCoordinator {
    inner: Arc<SetupInner>,
}

impl SetupSessionCoordinator {
    #[must_use]
    pub fn new(runner: Arc<dyn AccountEntryRunner>) -> Arc<Self> {
        Self::with_limits(runner, SETUP_TTL, MAX_SETUP_SESSIONS)
    }

    fn with_limits(
        runner: Arc<dyn AccountEntryRunner>,
        ttl: Duration,
        maximum: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(SetupInner {
                runner,
                sessions: Mutex::new(BTreeMap::new()),
                ttl,
                maximum,
            }),
        })
    }

    /// Privileged-launcher side: consume the one helper endpoint and start its
    /// service worker. The returned descriptor must go directly to the fixed
    /// helper; it must never be returned through Settings IPC.
    pub fn claim_helper(&self, setup_id: &str) -> Result<OwnedFd, AccountConnectError> {
        validate_setup_id(setup_id)?;
        let mut sessions = self.inner.sessions.lock().unwrap();
        purge_expired(&mut sessions, self.inner.ttl);
        let session = sessions
            .get_mut(setup_id)
            .ok_or(AccountConnectError::NotFound)?;
        let helper = session.helper.take().ok_or(AccountConnectError::NotFound)?;
        let service = session.service.take().ok_or(AccountConnectError::Runtime)?;
        let service = UnixDatagram::from(service);
        let cancellation = match service.try_clone() {
            Ok(channel) => channel,
            Err(_) => {
                session.helper = Some(helper);
                session.service = Some(service.into());
                return Err(AccountConnectError::Runtime);
            }
        };
        session.cancellation = Some(cancellation);

        let inner = Arc::clone(&self.inner);
        let worker_setup_id = setup_id.to_string();
        let spawn = thread::Builder::new()
            .name("punar-pim-account-entry".into())
            .spawn(move || {
                inner.runner.run(service.into());
                inner.sessions.lock().unwrap().remove(&worker_setup_id);
            });
        if spawn.is_err() {
            sessions.remove(setup_id);
            return Err(AccountConnectError::Runtime);
        }
        Ok(helper)
    }

    #[cfg(test)]
    fn active(&self) -> usize {
        self.inner.sessions.lock().unwrap().len()
    }
}

impl AccountConnectLifecycle for SetupSessionCoordinator {
    fn begin(
        &self,
        provider_type: ProviderType,
    ) -> Result<AccountSetupStatus, AccountConnectError> {
        if provider_type != ProviderType::OpenProtocols {
            return Err(AccountConnectError::UnsupportedProvider);
        }
        let mut sessions = self.inner.sessions.lock().unwrap();
        purge_expired(&mut sessions, self.inner.ttl);
        if sessions.len() >= self.inner.maximum {
            return Err(AccountConnectError::RateLimited);
        }
        let setup_id = mint_setup_id()?;
        let (helper, service) = account_entry_pair().map_err(|_| AccountConnectError::Runtime)?;
        sessions.insert(
            setup_id.clone(),
            Session {
                created: Instant::now(),
                helper: Some(helper),
                service: Some(service),
                cancellation: None,
            },
        );
        Ok(AccountSetupStatus {
            setup_id,
            provider_type,
            state: AccountSetupStage::AwaitingCredentials,
        })
    }

    fn cancel(&self, setup_id: &str) -> Result<(), AccountConnectError> {
        validate_setup_id(setup_id)?;
        let mut sessions = self.inner.sessions.lock().unwrap();
        purge_expired(&mut sessions, self.inner.ttl);
        let session = sessions
            .remove(setup_id)
            .ok_or(AccountConnectError::NotFound)?;
        if let Some(channel) = session.cancellation {
            let _ = channel.shutdown(Shutdown::Both);
        }
        Ok(())
    }
}

fn purge_expired(sessions: &mut BTreeMap<String, Session>, ttl: Duration) {
    let now = Instant::now();
    sessions.retain(|_, session| {
        let keep = now
            .checked_duration_since(session.created)
            .is_none_or(|age| age < ttl);
        if !keep && let Some(channel) = &session.cancellation {
            let _ = channel.shutdown(Shutdown::Both);
        }
        keep
    });
}

fn validate_setup_id(setup_id: &str) -> Result<(), AccountConnectError> {
    let suffix = setup_id
        .strip_prefix("setup_")
        .ok_or(AccountConnectError::NotFound)?;
    if setup_id.len() <= 80
        && !suffix.is_empty()
        && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        Ok(())
    } else {
        Err(AccountConnectError::NotFound)
    }
}

fn mint_setup_id() -> Result<String, AccountConnectError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| AccountConnectError::Runtime)?;
    let mut id = String::with_capacity(6 + bytes.len() * 2);
    id.push_str("setup_");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        id.push(HEX[(byte >> 4) as usize] as char);
        id.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(id)
}

pub struct OpenProtocolEntryRunner {
    store: Arc<PimStore>,
    mail_store: Arc<MailStore>,
    state_root: PathBuf,
    profile_id: String,
}

impl OpenProtocolEntryRunner {
    #[must_use]
    pub fn new(
        store: Arc<PimStore>,
        mail_store: Arc<MailStore>,
        state_root: &Path,
        profile_id: &str,
    ) -> Self {
        Self {
            store,
            mail_store,
            state_root: state_root.to_path_buf(),
            profile_id: profile_id.to_string(),
        }
    }
}

impl AccountEntryRunner for OpenProtocolEntryRunner {
    fn run(&self, channel: OwnedFd) {
        let proof = match EncryptedStorageProof::verify(&self.state_root) {
            Ok(proof) => proof,
            Err(error) => {
                reject_for_vault_error(channel, error);
                return;
            }
        };
        let vault = match CredentialVault::open(&self.state_root, &self.profile_id, &proof) {
            Ok(vault) => vault,
            Err(error) => {
                reject_for_vault_error(channel, error);
                return;
            }
        };
        let coordinator = AccountCoordinator::new(
            &self.store,
            &self.mail_store,
            &vault,
            NetworkOpenProtocolVerifier::default(),
        );
        let _ = complete_account_entry(
            &coordinator,
            channel,
            &punar_common::time::utc_now_rfc3339(),
        );
    }
}

fn reject_for_vault_error(channel: OwnedFd, error: VaultError) {
    let code = match error {
        VaultError::StorageEncryptionRequired => AccountEntryCode::StorageEncryptionRequired,
        VaultError::Io(_)
        | VaultError::Invalid
        | VaultError::ProfileMismatch
        | VaultError::Crypto
        | VaultError::Entropy
        | VaultError::NotFound
        | VaultError::CredentialEntry(_) => AccountEntryCode::Internal,
    };
    let _ = crate::account_entry::reject_account_entry(channel, code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AccountEntryHelper, AccountEntryOutcome, EmailAddress, MailServerConfig,
        MailServerSecurity, OpenProtocolAccountInput, OpenProtocolConfig, OpenProtocolSetup,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Runner {
        calls: AtomicUsize,
    }

    impl AccountEntryRunner for Runner {
        fn run(&self, channel: OwnedFd) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let channel = UnixDatagram::from(channel);
            let mut input = vec![0_u8; 16 * 1024];
            assert!(channel.recv(&mut input).unwrap() > 0);
            assert!(channel.recv(&mut input).unwrap() > 0);
            let outcome = AccountEntryOutcome {
                v: 1,
                ok: true,
                code: AccountEntryCode::Connected,
                account_id: Some("acct_A1".into()),
            };
            channel
                .send(&serde_json::to_vec(&outcome).unwrap())
                .unwrap();
        }
    }

    fn setup() -> OpenProtocolSetup {
        OpenProtocolSetup {
            identity: OpenProtocolAccountInput {
                display_name: "Alice".into(),
                primary_address: EmailAddress {
                    name: Some("Alice".into()),
                    address: "alice@example.com".into(),
                },
            },
            config: OpenProtocolConfig {
                username: "alice@example.com".into(),
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
            },
        }
    }

    #[test]
    fn begin_claim_and_helper_completion_are_one_use_and_bounded() {
        let runner = Arc::new(Runner {
            calls: AtomicUsize::new(0),
        });
        let trait_runner: Arc<dyn AccountEntryRunner> = runner.clone();
        let coordinator = SetupSessionCoordinator::new(trait_runner);
        let status = coordinator.begin(ProviderType::OpenProtocols).unwrap();
        assert_eq!(status.state, AccountSetupStage::AwaitingCredentials);
        let helper_channel = coordinator.claim_helper(&status.setup_id).unwrap();
        assert!(matches!(
            coordinator.claim_helper(&status.setup_id),
            Err(AccountConnectError::NotFound)
        ));
        let helper = AccountEntryHelper::lock_down(helper_channel).unwrap();
        let mut password = b"app-password".to_vec();
        let outcome = helper.submit(&setup(), &mut password).unwrap();
        assert!(outcome.ok);
        assert!(password.iter().all(|byte| *byte == 0));
        let started = Instant::now();
        while coordinator.active() != 0 {
            assert!(started.elapsed() < Duration::from_secs(2));
            thread::yield_now();
        }
        assert_eq!(runner.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cancellation_and_expiry_drop_unclaimed_helper_capabilities() {
        let runner: Arc<dyn AccountEntryRunner> = Arc::new(Runner {
            calls: AtomicUsize::new(0),
        });
        let coordinator = SetupSessionCoordinator::with_limits(runner, Duration::from_millis(1), 2);
        let first = coordinator.begin(ProviderType::OpenProtocols).unwrap();
        coordinator.cancel(&first.setup_id).unwrap();
        assert!(matches!(
            coordinator.claim_helper(&first.setup_id),
            Err(AccountConnectError::NotFound)
        ));
        let expired = coordinator.begin(ProviderType::OpenProtocols).unwrap();
        thread::sleep(Duration::from_millis(2));
        assert!(matches!(
            coordinator.claim_helper(&expired.setup_id),
            Err(AccountConnectError::NotFound)
        ));
    }

    #[test]
    fn unsupported_providers_and_session_flood_fail_closed() {
        let runner: Arc<dyn AccountEntryRunner> = Arc::new(Runner {
            calls: AtomicUsize::new(0),
        });
        let coordinator = SetupSessionCoordinator::with_limits(runner, Duration::from_secs(60), 1);
        assert!(matches!(
            coordinator.begin(ProviderType::Google),
            Err(AccountConnectError::UnsupportedProvider)
        ));
        coordinator.begin(ProviderType::OpenProtocols).unwrap();
        assert!(matches!(
            coordinator.begin(ProviderType::OpenProtocols),
            Err(AccountConnectError::RateLimited)
        ));
    }
}
