//! Bounded, non-resident synchronization jobs.
//!
//! `sync.trigger` must acknowledge quickly: IMAP deadlines are intentionally
//! longer than the application IPC deadline. This coordinator admits at most
//! two concurrent account jobs, coalesces duplicate triggers, runs provider
//! work outside the request thread and persists only a closed public outcome.
//! It owns no loop or timer; every worker exits after one bounded batch.

use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use thiserror::Error;

use crate::store::AccountSyncOutcome;
use crate::{
    AccountAuthState, AccountCapability, CredentialVault, EncryptedStorageProof, MailStore,
    MailSyncReport, OpenProtocolMailSynchronizer, OpenProtocolSyncError, PimStore,
    ProviderCheckError, StoreError, VaultError,
};

const MAX_CONCURRENT_SYNCS: usize = 2;
const RETRY_DELAY_SECONDS: u64 = 5 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncFailure {
    AuthRequired,
    Offline,
    ProviderState,
    StorageEncryptionRequired,
    Internal,
}

pub trait MailSyncRunner: Send + Sync + 'static {
    fn sync_account(&self, account_id: &str) -> Result<MailSyncReport, SyncFailure>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedSync {
    pub operation_id: String,
    pub account_id: String,
}

#[derive(Debug, Error)]
pub enum SyncTriggerError {
    #[error("Mail account was not found")]
    NotFound,
    #[error("account cannot synchronize Mail")]
    UnsupportedAccount,
    #[error("account authentication needs attention")]
    AuthRequired,
    #[error("too many Mail synchronizations are active")]
    RateLimited,
    #[error("Mail synchronization worker could not start")]
    Runtime,
}

pub struct SyncCoordinator {
    store: Arc<PimStore>,
    runner: Arc<dyn MailSyncRunner>,
    in_flight: Mutex<HashMap<String, String>>,
}

impl SyncCoordinator {
    #[must_use]
    pub fn new(store: Arc<PimStore>, runner: Arc<dyn MailSyncRunner>) -> Arc<Self> {
        Arc::new(Self {
            store,
            runner,
            in_flight: Mutex::new(HashMap::new()),
        })
    }

    /// Admit one bounded sync job. Repeated triggers for an account already in
    /// flight return the existing operation rather than creating a retry loop.
    pub fn trigger(self: &Arc<Self>, account_id: &str) -> Result<AcceptedSync, SyncTriggerError> {
        let account = self
            .store
            .snapshot()
            .accounts
            .into_iter()
            .find(|account| account.account_id == account_id)
            .ok_or(SyncTriggerError::NotFound)?;
        if !account.capabilities.contains(&AccountCapability::Mail) {
            return Err(SyncTriggerError::UnsupportedAccount);
        }
        if account.auth_state != AccountAuthState::Ready {
            return Err(SyncTriggerError::AuthRequired);
        }

        let mut in_flight = self.in_flight.lock().unwrap();
        if let Some(operation_id) = in_flight.get(account_id) {
            return Ok(AcceptedSync {
                operation_id: operation_id.clone(),
                account_id: account_id.to_string(),
            });
        }
        if in_flight.len() >= MAX_CONCURRENT_SYNCS {
            return Err(SyncTriggerError::RateLimited);
        }
        let operation_id = mint_operation_id()?;
        in_flight.insert(account_id.to_string(), operation_id.clone());
        drop(in_flight);

        let coordinator = Arc::clone(self);
        let worker_account = account_id.to_string();
        if thread::Builder::new()
            .name("punar-pim-sync".into())
            .spawn(move || coordinator.run_one(worker_account))
            .is_err()
        {
            self.in_flight.lock().unwrap().remove(account_id);
            return Err(SyncTriggerError::Runtime);
        }
        Ok(AcceptedSync {
            operation_id,
            account_id: account_id.to_string(),
        })
    }

    fn run_one(&self, account_id: String) {
        let result = catch_unwind(AssertUnwindSafe(|| self.runner.sync_account(&account_id)))
            .unwrap_or(Err(SyncFailure::Internal));
        let now = punar_common::time::utc_now_rfc3339();
        let outcome = match result {
            Ok(_) => AccountSyncOutcome::Success,
            Err(SyncFailure::AuthRequired) => AccountSyncOutcome::AuthRequired,
            Err(SyncFailure::Offline) => AccountSyncOutcome::Offline {
                retry_at: retry_at(),
            },
            Err(
                SyncFailure::ProviderState
                | SyncFailure::StorageEncryptionRequired
                | SyncFailure::Internal,
            ) => AccountSyncOutcome::Error {
                retry_at: retry_at(),
            },
        };
        let _ = self
            .store
            .record_account_sync_outcome(&account_id, outcome, &now);
        self.in_flight.lock().unwrap().remove(&account_id);
    }

    #[cfg(test)]
    fn is_in_flight(&self, account_id: &str) -> bool {
        self.in_flight.lock().unwrap().contains_key(account_id)
    }
}

/// Production open-protocol runner. Credential storage is opened only inside
/// the short-lived worker and only after kernel-backed LUKS2 verification.
pub struct OpenProtocolSyncRunner {
    store: Arc<PimStore>,
    mail_store: Arc<MailStore>,
    state_root: PathBuf,
    profile_id: String,
    deadline: Duration,
}

impl OpenProtocolSyncRunner {
    #[must_use]
    pub fn new(
        store: Arc<PimStore>,
        mail_store: Arc<MailStore>,
        state_root: &Path,
        profile_id: &str,
        deadline: Duration,
    ) -> Self {
        Self {
            store,
            mail_store,
            state_root: state_root.to_path_buf(),
            profile_id: profile_id.to_string(),
            deadline,
        }
    }
}

impl MailSyncRunner for OpenProtocolSyncRunner {
    fn sync_account(&self, account_id: &str) -> Result<MailSyncReport, SyncFailure> {
        let proof = EncryptedStorageProof::verify(&self.state_root).map_err(map_vault_error)?;
        let vault = CredentialVault::open(&self.state_root, &self.profile_id, &proof)
            .map_err(map_vault_error)?;
        let config = self
            .store
            .open_protocol_config(account_id)
            .map_err(map_store_error)?;
        OpenProtocolMailSynchronizer::with_deadline(&self.mail_store, &vault, self.deadline)
            .sync_inbox(account_id, &config)
            .map_err(map_sync_error)
    }
}

fn map_sync_error(error: OpenProtocolSyncError) -> SyncFailure {
    match error {
        OpenProtocolSyncError::Vault(error) => map_vault_error(error),
        OpenProtocolSyncError::Provider(ProviderCheckError::InvalidCredentials) => {
            SyncFailure::AuthRequired
        }
        OpenProtocolSyncError::Provider(ProviderCheckError::Unreachable) => SyncFailure::Offline,
        OpenProtocolSyncError::Provider(
            ProviderCheckError::Tls | ProviderCheckError::InvalidResponse,
        )
        | OpenProtocolSyncError::UnsupportedMailbox
        | OpenProtocolSyncError::MalformedRemoteData => SyncFailure::ProviderState,
        OpenProtocolSyncError::Provider(ProviderCheckError::Internal)
        | OpenProtocolSyncError::Store(_)
        | OpenProtocolSyncError::Runtime => SyncFailure::Internal,
    }
}

fn map_vault_error(error: VaultError) -> SyncFailure {
    match error {
        VaultError::StorageEncryptionRequired => SyncFailure::StorageEncryptionRequired,
        VaultError::NotFound => SyncFailure::AuthRequired,
        VaultError::Io(_)
        | VaultError::Invalid
        | VaultError::ProfileMismatch
        | VaultError::Crypto
        | VaultError::Entropy
        | VaultError::CredentialEntry(_) => SyncFailure::Internal,
    }
}

fn map_store_error(error: StoreError) -> SyncFailure {
    match error {
        StoreError::NotFound => SyncFailure::AuthRequired,
        StoreError::Io(_)
        | StoreError::Corrupt(_)
        | StoreError::UnsupportedVersion { .. }
        | StoreError::ProfileMismatch
        | StoreError::Invalid(_)
        | StoreError::Conflict { .. }
        | StoreError::CursorExpired => SyncFailure::Internal,
    }
}

fn retry_at() -> String {
    let now = u64::try_from(punar_common::time::unix_now_millis() / 1000).unwrap_or(0);
    punar_common::time::rfc3339_utc_from_unix_seconds(now.saturating_add(RETRY_DELAY_SECONDS))
}

fn mint_operation_id() -> Result<String, SyncTriggerError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| SyncTriggerError::Runtime)?;
    let mut id = String::with_capacity(3 + bytes.len() * 2);
    id.push_str("op_");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        id.push(HEX[(byte >> 4) as usize] as char);
        id.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Account, AccountAuthState, AccountKind, Connectivity, EmailAddress, MailServerConfig,
        MailServerSecurity, OpenProtocolConfig, ProviderType,
    };
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    struct Runner {
        result: Result<MailSyncReport, SyncFailure>,
        calls: AtomicUsize,
        delay: Duration,
    }

    impl MailSyncRunner for Runner {
        fn sync_account(&self, _account_id: &str) -> Result<MailSyncReport, SyncFailure> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            thread::sleep(self.delay);
            self.result
        }
    }

    fn root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "punar-sync-runtime-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn coordinator(
        name: &str,
        result: Result<MailSyncReport, SyncFailure>,
        delay: Duration,
    ) -> (PathBuf, Arc<PimStore>, Arc<Runner>, Arc<SyncCoordinator>) {
        let root = root(name);
        let store =
            Arc::new(PimStore::open(&root.join("records.json"), "profile_A1", 1000).unwrap());
        store
            .register_open_protocol_account(account("acct_A1"), config(), &now())
            .unwrap();
        let runner = Arc::new(Runner {
            result,
            calls: AtomicUsize::new(0),
            delay,
        });
        let trait_runner: Arc<dyn MailSyncRunner> = runner.clone();
        let coordinator = SyncCoordinator::new(Arc::clone(&store), trait_runner);
        (root, store, runner, coordinator)
    }

    fn wait(coordinator: &SyncCoordinator, account_id: &str) {
        let started = Instant::now();
        while coordinator.is_in_flight(account_id) {
            assert!(started.elapsed() < Duration::from_secs(2));
            thread::yield_now();
        }
    }

    #[test]
    fn successful_job_returns_immediately_and_persists_public_sync_state() {
        let report = MailSyncReport {
            uid_validity: 7,
            last_uid: 9,
            fetched: 2,
            skipped_malformed: 0,
        };
        let (root, store, runner, coordinator) =
            coordinator("success", Ok(report), Duration::from_millis(20));
        let accepted = coordinator.trigger("acct_A1").unwrap();
        assert!(accepted.operation_id.starts_with("op_"));
        assert!(coordinator.is_in_flight("acct_A1"));
        wait(&coordinator, "acct_A1");
        let account = &store.snapshot().accounts[0];
        assert_eq!(account.connectivity, Connectivity::Online);
        assert!(account.last_sync_at.is_some());
        assert_eq!(runner.calls.load(Ordering::SeqCst), 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn repeated_trigger_coalesces_and_auth_failure_never_retries() {
        let (root, store, runner, coordinator) = coordinator(
            "auth",
            Err(SyncFailure::AuthRequired),
            Duration::from_millis(30),
        );
        let first = coordinator.trigger("acct_A1").unwrap();
        let second = coordinator.trigger("acct_A1").unwrap();
        assert_eq!(first, second);
        wait(&coordinator, "acct_A1");
        let account = &store.snapshot().accounts[0];
        assert_eq!(account.auth_state, AccountAuthState::ActionRequired);
        assert!(account.next_retry_at.is_none());
        assert_eq!(runner.calls.load(Ordering::SeqCst), 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn offline_failure_sets_one_bounded_retry_time_without_a_loop() {
        let (root, store, runner, coordinator) = coordinator(
            "offline",
            Err(SyncFailure::Offline),
            Duration::from_millis(1),
        );
        coordinator.trigger("acct_A1").unwrap();
        wait(&coordinator, "acct_A1");
        let account = &store.snapshot().accounts[0];
        assert_eq!(account.connectivity, Connectivity::Offline);
        assert!(account.next_retry_at.is_some());
        assert_eq!(runner.calls.load(Ordering::SeqCst), 1);
        let _ = fs::remove_dir_all(root);
    }

    fn account(account_id: &str) -> Account {
        Account {
            kind: AccountKind::Account,
            account_id: account_id.into(),
            provider_type: ProviderType::OpenProtocols,
            display_name: "Alice".into(),
            primary_address: Some(EmailAddress {
                name: Some("Alice".into()),
                address: "alice@example.com".into(),
            }),
            capabilities: vec![AccountCapability::Mail],
            auth_state: AccountAuthState::Ready,
            connectivity: Connectivity::Unknown,
            last_sync_at: None,
            next_retry_at: None,
        }
    }

    fn config() -> OpenProtocolConfig {
        OpenProtocolConfig {
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
        }
    }

    fn now() -> String {
        "2026-09-22T17:00:00Z".into()
    }
}
