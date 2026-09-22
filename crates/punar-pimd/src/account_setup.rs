//! Transaction coordinator for open-protocol mail account setup.
//!
//! The normal PIM protocol carries only non-secret account intent. A fixed,
//! short-lived helper transfers one password over an unnamed channel. This
//! coordinator validates configuration, commits both typed vault records,
//! verifies IMAP and SMTP through a provider adapter, and only then publishes
//! the account metadata. Every pre-commit failure removes the staged secret.
//! Removal requires a profile-bound sync-quiescence permit before it erases
//! cached Mail, credentials and public metadata.

use std::os::fd::OwnedFd;

use thiserror::Error;

use crate::{
    Account, AccountAuthState, AccountCapability, AccountKind, AccountRemovalPermit, Connectivity,
    CredentialKind, CredentialVault, EmailAddress, MailStore, MailStoreError, OpenProtocolConfig,
    PimStore, ProviderType, StoreError, VaultError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProviderCheckError {
    #[error("mail account credentials were rejected")]
    InvalidCredentials,
    #[error("mail provider could not be reached")]
    Unreachable,
    #[error("mail provider transport could not be authenticated")]
    Tls,
    #[error("mail provider returned an invalid response")]
    InvalidResponse,
    #[error("mail provider verification could not start")]
    Internal,
}

/// Identity returned only after an adapter has authenticated both incoming
/// and outgoing mail. Response bodies and credentials are not representable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOpenProtocolIdentity {
    pub display_name: String,
    pub primary_address: EmailAddress,
}

/// User-visible identity kept separate from the provider login name. Some
/// self-hosted servers authenticate a short username rather than an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenProtocolAccountInput {
    pub display_name: String,
    pub primary_address: EmailAddress,
}

/// Service-internal verification boundary. Implementations must authenticate
/// both configured endpoints and must not retain `password` after returning.
pub trait OpenProtocolVerifier {
    fn verify(
        &self,
        config: &OpenProtocolConfig,
        identity: &OpenProtocolAccountInput,
        password: &[u8],
    ) -> Result<VerifiedOpenProtocolIdentity, ProviderCheckError>;
}

#[derive(Debug, Error)]
pub enum AccountSetupError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error(transparent)]
    MailStore(#[from] MailStoreError),
    #[error(transparent)]
    Provider(#[from] ProviderCheckError),
    #[error("mail account identifier entropy is unavailable")]
    Entropy,
    #[error("mail account setup failed and staged credentials could not be removed")]
    Cleanup,
    #[error("mail account removal permit belongs to another profile service")]
    RemovalPermitMismatch,
}

pub struct AccountCoordinator<'a, V> {
    store: &'a PimStore,
    mail_store: &'a MailStore,
    vault: &'a CredentialVault,
    verifier: V,
}

impl<'a, V: OpenProtocolVerifier> AccountCoordinator<'a, V> {
    #[must_use]
    pub fn new(
        store: &'a PimStore,
        mail_store: &'a MailStore,
        vault: &'a CredentialVault,
        verifier: V,
    ) -> Self {
        Self {
            store,
            mail_store,
            vault,
            verifier,
        }
    }

    /// Complete an open-protocol account transaction. The channel is the
    /// service endpoint of a one-use credential-entry pair; no password is
    /// accepted as an ordinary argument or returned to the caller.
    pub fn connect_open_protocol(
        &self,
        identity: OpenProtocolAccountInput,
        config: OpenProtocolConfig,
        credential_channel: OwnedFd,
        now: &str,
    ) -> Result<Account, AccountSetupError> {
        let account_id = mint_account_id()?;
        let candidate = ready_account(
            account_id.clone(),
            VerifiedOpenProtocolIdentity {
                display_name: identity.display_name.clone(),
                primary_address: identity.primary_address.clone(),
            },
        );
        self.store
            .validate_open_protocol_candidate(&candidate, &config)?;

        self.vault
            .receive_and_store_shared_password(&account_id, credential_channel)?;

        let verified = match self.vault.with_secret(
            &account_id,
            CredentialKind::IncomingPassword,
            |password| self.verifier.verify(&config, &identity, password),
        ) {
            Ok(Ok(identity)) => identity,
            Ok(Err(error)) => {
                self.rollback_credentials(&account_id)?;
                return Err(error.into());
            }
            Err(error) => {
                self.rollback_credentials(&account_id)?;
                return Err(error.into());
            }
        };

        let account = ready_account(account_id.clone(), verified);
        if let Err(error) = self
            .store
            .register_open_protocol_account(account.clone(), config, now)
        {
            self.rollback_credentials(&account_id)?;
            return Err(error.into());
        }
        Ok(account)
    }

    /// Re-authenticate a persisted account without exposing its configuration
    /// or password through application IPC. This is the primitive used by the
    /// first sync and later connection health checks.
    pub fn verify_existing(
        &self,
        account_id: &str,
    ) -> Result<VerifiedOpenProtocolIdentity, AccountSetupError> {
        let config = self.store.open_protocol_config(account_id)?;
        let account = self
            .store
            .snapshot()
            .accounts
            .into_iter()
            .find(|account| account.account_id == account_id)
            .ok_or(StoreError::NotFound)?;
        let identity = OpenProtocolAccountInput {
            display_name: account.display_name,
            primary_address: account.primary_address.ok_or(StoreError::NotFound)?,
        };
        self.vault
            .with_secret(account_id, CredentialKind::IncomingPassword, |password| {
                self.verifier.verify(&config, &identity, password)
            })?
            .map_err(Into::into)
    }

    /// Remove cached Mail and credentials before publishing the metadata
    /// deletion. Checked failures therefore leave the account visible and
    /// retryable until its private state has been erased. Every cleanup step
    /// before the metadata commit is idempotent.
    pub fn remove_account(
        &self,
        permit: &AccountRemovalPermit,
        now: &str,
    ) -> Result<(), AccountSetupError> {
        if !permit.authorizes(self.store) {
            return Err(AccountSetupError::RemovalPermitMismatch);
        }
        let account_id = permit.account_id();
        self.mail_store.remove_account(account_id)?;
        self.vault.remove_account(account_id)?;
        self.store.remove_account_metadata(account_id, now)?;
        Ok(())
    }

    fn rollback_credentials(&self, account_id: &str) -> Result<(), AccountSetupError> {
        self.vault
            .remove_account(account_id)
            .map(|_| ())
            .map_err(|_| AccountSetupError::Cleanup)
    }
}

fn ready_account(account_id: String, identity: VerifiedOpenProtocolIdentity) -> Account {
    Account {
        kind: AccountKind::Account,
        account_id,
        provider_type: ProviderType::OpenProtocols,
        display_name: identity.display_name,
        primary_address: Some(identity.primary_address),
        capabilities: vec![AccountCapability::Mail],
        auth_state: AccountAuthState::Ready,
        connectivity: Connectivity::Online,
        last_sync_at: None,
        next_retry_at: None,
    }
}

fn mint_account_id() -> Result<String, AccountSetupError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| AccountSetupError::Entropy)?;
    let mut id = String::with_capacity(5 + bytes.len() * 2);
    id.push_str("acct_");
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
        CredentialEntryHelper, MailBatchItem, MailIngestInput, MailServerConfig,
        MailServerSecurity, MailSyncReport, MailSyncRunner, SyncCoordinator, SyncFailure,
        credential_entry_pair, ingest_message,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const NOW: &str = "2026-09-22T17:00:00Z";

    #[derive(Clone, Copy)]
    struct Verifier {
        outcome: Result<(), ProviderCheckError>,
        invalid_identity: bool,
    }

    impl OpenProtocolVerifier for Verifier {
        fn verify(
            &self,
            config: &OpenProtocolConfig,
            identity: &OpenProtocolAccountInput,
            password: &[u8],
        ) -> Result<VerifiedOpenProtocolIdentity, ProviderCheckError> {
            assert_eq!(config.username, "alice-login");
            assert_eq!(identity.primary_address.address, "alice@example.com");
            assert_eq!(password, b"app-password");
            self.outcome?;
            Ok(VerifiedOpenProtocolIdentity {
                display_name: if self.invalid_identity {
                    "x".repeat(161)
                } else {
                    "Alice Work".into()
                },
                primary_address: EmailAddress {
                    name: Some("Alice".into()),
                    address: "alice@example.com".into(),
                },
            })
        }
    }

    struct TestState(PathBuf);

    struct IdleRunner;

    impl MailSyncRunner for IdleRunner {
        fn sync_account(&self, _account_id: &str) -> Result<MailSyncReport, SyncFailure> {
            panic!("account removal test must not start provider work")
        }
    }

    impl TestState {
        fn new(name: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            Self(std::env::temp_dir().join(format!(
                "punar-pimd-account-setup-{name}-{}-{nonce}",
                std::process::id()
            )))
        }

        fn store(&self) -> PathBuf {
            self.0.join("store/state.json")
        }

        fn vault(&self) -> PathBuf {
            self.0.join("vault")
        }

        fn mail(&self) -> PathBuf {
            self.0.join("mail/mail.redb")
        }
    }

    impl Drop for TestState {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn config() -> OpenProtocolConfig {
        OpenProtocolConfig {
            username: "alice-login".into(),
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

    fn identity() -> OpenProtocolAccountInput {
        OpenProtocolAccountInput {
            display_name: "Alice Work".into(),
            primary_address: EmailAddress {
                name: Some("Alice".into()),
                address: "alice@example.com".into(),
            },
        }
    }

    fn send_password() -> (OwnedFd, std::thread::JoinHandle<()>) {
        let (helper, service) = credential_entry_pair().unwrap();
        let sender = std::thread::spawn(move || {
            let helper = CredentialEntryHelper::lock_down(helper).unwrap();
            let mut password = b"app-password".to_vec();
            helper.submit(&mut password).unwrap();
            assert!(password.iter().all(|byte| *byte == 0));
        });
        (service, sender)
    }

    fn open(state: &TestState) -> (Arc<PimStore>, Arc<MailStore>, CredentialVault) {
        (
            Arc::new(PimStore::open(&state.store(), "profile_A1", 1000).unwrap()),
            Arc::new(MailStore::open(&state.mail(), "profile_A1", 1000).unwrap()),
            CredentialVault::open_for_test(&state.vault(), "profile_A1").unwrap(),
        )
    }

    fn connect(
        state: &TestState,
        verifier: Verifier,
    ) -> Result<(Account, Arc<PimStore>, Arc<MailStore>, CredentialVault), AccountSetupError> {
        let (store, mail_store, vault) = open(state);
        let (service, sender) = send_password();
        let result = AccountCoordinator::new(&store, &mail_store, &vault, verifier)
            .connect_open_protocol(identity(), config(), service, NOW);
        sender.join().unwrap();
        result.map(|account| (account, store, mail_store, vault))
    }

    #[test]
    fn verified_account_commits_metadata_config_and_both_typed_credentials() {
        let state = TestState::new("success");
        let (account, store, mail_store, vault) = connect(
            &state,
            Verifier {
                outcome: Ok(()),
                invalid_identity: false,
            },
        )
        .unwrap();
        assert_eq!(store.snapshot().accounts, vec![account.clone()]);
        assert_eq!(
            store.open_protocol_config(&account.account_id).unwrap(),
            config()
        );
        assert!(vault.contains(&account.account_id, CredentialKind::IncomingPassword));
        assert!(vault.contains(&account.account_id, CredentialKind::OutgoingPassword));

        drop(store);
        drop(mail_store);
        drop(vault);
        let (store, mail_store, vault) = open(&state);
        let verified = AccountCoordinator::new(
            &store,
            &mail_store,
            &vault,
            Verifier {
                outcome: Ok(()),
                invalid_identity: false,
            },
        )
        .verify_existing(&account.account_id)
        .unwrap();
        assert_eq!(verified.primary_address.address, "alice@example.com");
    }

    #[test]
    fn rejected_credentials_leave_no_account_or_vault_record() {
        let state = TestState::new("rejected");
        let result = connect(
            &state,
            Verifier {
                outcome: Err(ProviderCheckError::InvalidCredentials),
                invalid_identity: false,
            },
        );
        assert!(matches!(result, Err(AccountSetupError::Provider(_))));
        let (store, _, vault) = open(&state);
        assert!(store.snapshot().accounts.is_empty());
        let disk = fs::read_to_string(state.vault().join("credentials.json")).unwrap();
        assert!(!disk.contains("acct_"));
        assert!(!disk.contains("app-password"));
        drop(vault);
    }

    #[test]
    fn invalid_verified_identity_rolls_back_staged_credentials() {
        let state = TestState::new("bad-identity");
        let result = connect(
            &state,
            Verifier {
                outcome: Ok(()),
                invalid_identity: true,
            },
        );
        assert!(matches!(result, Err(AccountSetupError::Store(_))));
        let (store, _, _) = open(&state);
        assert!(store.snapshot().accounts.is_empty());
        let disk = fs::read_to_string(state.vault().join("credentials.json")).unwrap();
        assert!(!disk.contains("acct_"));
    }

    #[test]
    fn removal_clears_metadata_private_config_credentials_and_mail_across_restart() {
        let state = TestState::new("remove");
        let (account, store, mail_store, vault) = connect(
            &state,
            Verifier {
                outcome: Ok(()),
                invalid_identity: false,
            },
        )
        .unwrap();
        let raw = b"From: Example <sender@example.com>\r\n\
To: Alice <alice@example.com>\r\n\
Message-ID: <remove-me@example.com>\r\n\
Date: Mon, 22 Sep 2026 17:00:00 +0000\r\n\
Subject: Remove me\r\n\
Content-Type: text/plain; charset=utf-8\r\n\r\n\
Private cached message";
        let parsed = ingest_message(MailIngestInput {
            account_id: &account.account_id,
            mailbox_id: "INBOX",
            uid_validity: 7,
            uid: 1,
            received_at: NOW,
            unread: true,
            starred: false,
            labels: &["Inbox".to_string()],
            raw_message: raw,
        })
        .unwrap();
        mail_store
            .store_batch(
                &account.account_id,
                "INBOX",
                7,
                vec![MailBatchItem { uid: 1, parsed }],
                1,
            )
            .unwrap();
        assert_eq!(
            mail_store
                .list_summaries(&account.account_id, None, 20)
                .unwrap()
                .summaries
                .len(),
            1
        );
        assert!(
            mail_store
                .sync_cursor(&account.account_id, "INBOX")
                .unwrap()
                .is_some()
        );
        let runner: Arc<dyn MailSyncRunner> = Arc::new(IdleRunner);
        let sync = SyncCoordinator::new(Arc::clone(&store), runner);
        let permit = sync
            .begin_account_removal(&account.account_id, Duration::from_secs(1))
            .unwrap();
        AccountCoordinator::new(
            &store,
            &mail_store,
            &vault,
            Verifier {
                outcome: Ok(()),
                invalid_identity: false,
            },
        )
        .remove_account(&permit, "2026-09-22T17:01:00Z")
        .unwrap();
        assert!(store.snapshot().accounts.is_empty());
        assert!(matches!(
            store.open_protocol_config(&account.account_id),
            Err(StoreError::NotFound)
        ));
        assert!(!vault.contains(&account.account_id, CredentialKind::IncomingPassword));
        assert!(!vault.contains(&account.account_id, CredentialKind::OutgoingPassword));
        assert!(
            mail_store
                .list_summaries(&account.account_id, None, 20)
                .unwrap()
                .summaries
                .is_empty()
        );
        assert!(
            mail_store
                .sync_cursor(&account.account_id, "INBOX")
                .unwrap()
                .is_none()
        );

        drop(store);
        drop(mail_store);
        drop(vault);
        let (store, mail_store, vault) = open(&state);
        assert!(store.snapshot().accounts.is_empty());
        assert!(
            mail_store
                .list_summaries(&account.account_id, None, 20)
                .unwrap()
                .summaries
                .is_empty()
        );
        assert!(
            mail_store
                .sync_cursor(&account.account_id, "INBOX")
                .unwrap()
                .is_none()
        );
        assert!(!vault.contains(&account.account_id, CredentialKind::IncomingPassword));
    }

    #[test]
    fn malformed_server_config_is_rejected_before_credential_entry() {
        let state = TestState::new("invalid-config");
        let (store, mail_store, vault) = open(&state);
        let (helper, service) = credential_entry_pair().unwrap();
        let mut invalid = config();
        invalid.imap.host = "bad host".into();
        let result = AccountCoordinator::new(
            &store,
            &mail_store,
            &vault,
            Verifier {
                outcome: Ok(()),
                invalid_identity: false,
            },
        )
        .connect_open_protocol(identity(), invalid, service, NOW);
        drop(helper);
        assert!(matches!(result, Err(AccountSetupError::Store(_))));
        assert!(store.snapshot().accounts.is_empty());
        let disk = fs::read_to_string(state.vault().join("credentials.json")).unwrap();
        assert!(!disk.contains("acct_"));
    }
}
