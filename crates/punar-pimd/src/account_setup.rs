//! Transaction coordinator for open-protocol mail account setup.
//!
//! The normal PIM protocol carries only non-secret account intent. A fixed,
//! short-lived helper transfers one password over an unnamed channel. This
//! coordinator validates configuration, commits both typed vault records,
//! verifies IMAP and SMTP through a provider adapter, and only then publishes
//! the account metadata. Every pre-commit failure removes the staged secret.

use std::os::fd::OwnedFd;

use thiserror::Error;

use crate::{
    Account, AccountAuthState, AccountCapability, AccountKind, Connectivity, CredentialKind,
    CredentialVault, EmailAddress, OpenProtocolConfig, PimStore, ProviderType, StoreError,
    VaultError,
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
}

/// Identity returned only after an adapter has authenticated both incoming
/// and outgoing mail. Response bodies and credentials are not representable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOpenProtocolIdentity {
    pub display_name: String,
    pub primary_address: EmailAddress,
}

/// Service-internal verification boundary. Implementations must authenticate
/// both configured endpoints and must not retain `password` after returning.
pub trait OpenProtocolVerifier {
    fn verify(
        &self,
        config: &OpenProtocolConfig,
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
    Provider(#[from] ProviderCheckError),
    #[error("mail account identifier entropy is unavailable")]
    Entropy,
    #[error("mail account setup failed and staged credentials could not be removed")]
    Cleanup,
}

pub struct AccountCoordinator<'a, V> {
    store: &'a PimStore,
    vault: &'a CredentialVault,
    verifier: V,
}

impl<'a, V: OpenProtocolVerifier> AccountCoordinator<'a, V> {
    #[must_use]
    pub fn new(store: &'a PimStore, vault: &'a CredentialVault, verifier: V) -> Self {
        Self {
            store,
            vault,
            verifier,
        }
    }

    /// Complete an open-protocol account transaction. The channel is the
    /// service endpoint of a one-use credential-entry pair; no password is
    /// accepted as an ordinary argument or returned to the caller.
    pub fn connect_open_protocol(
        &self,
        config: OpenProtocolConfig,
        credential_channel: OwnedFd,
        now: &str,
    ) -> Result<Account, AccountSetupError> {
        let account_id = mint_account_id()?;
        self.store.validate_open_protocol_config(&config)?;

        self.vault
            .receive_and_store_shared_password(&account_id, credential_channel)?;

        let verified = match self.vault.with_secret(
            &account_id,
            CredentialKind::IncomingPassword,
            |password| self.verifier.verify(&config, password),
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
        self.vault
            .with_secret(account_id, CredentialKind::IncomingPassword, |password| {
                self.verifier.verify(&config, password)
            })?
            .map_err(Into::into)
    }

    /// Remove public metadata first, then erase all credential records. If a
    /// crash occurs between those writes, any leftover ciphertext is an
    /// unreachable orphan and cannot resurrect the account.
    pub fn remove_account(&self, account_id: &str, now: &str) -> Result<(), AccountSetupError> {
        self.store.remove_account_metadata(account_id, now)?;
        self.vault.remove_account(account_id)?;
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
        CredentialEntryHelper, MailServerConfig, MailServerSecurity, credential_entry_pair,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

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
            password: &[u8],
        ) -> Result<VerifiedOpenProtocolIdentity, ProviderCheckError> {
            assert_eq!(config.username, "alice@example.com");
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
    }

    impl Drop for TestState {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
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

    fn open(state: &TestState) -> (PimStore, CredentialVault) {
        (
            PimStore::open(&state.store(), "profile_A1", 1000).unwrap(),
            CredentialVault::open_for_test(&state.vault(), "profile_A1").unwrap(),
        )
    }

    fn connect(
        state: &TestState,
        verifier: Verifier,
    ) -> Result<(Account, PimStore, CredentialVault), AccountSetupError> {
        let (store, vault) = open(state);
        let (service, sender) = send_password();
        let result = AccountCoordinator::new(&store, &vault, verifier).connect_open_protocol(
            config(),
            service,
            NOW,
        );
        sender.join().unwrap();
        result.map(|account| (account, store, vault))
    }

    #[test]
    fn verified_account_commits_metadata_config_and_both_typed_credentials() {
        let state = TestState::new("success");
        let (account, store, vault) = connect(
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
        drop(vault);
        let (store, vault) = open(&state);
        let verified = AccountCoordinator::new(
            &store,
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
        let (store, vault) = open(&state);
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
        let (store, _) = open(&state);
        assert!(store.snapshot().accounts.is_empty());
        let disk = fs::read_to_string(state.vault().join("credentials.json")).unwrap();
        assert!(!disk.contains("acct_"));
    }

    #[test]
    fn removal_clears_metadata_private_config_and_credentials() {
        let state = TestState::new("remove");
        let (account, store, vault) = connect(
            &state,
            Verifier {
                outcome: Ok(()),
                invalid_identity: false,
            },
        )
        .unwrap();
        AccountCoordinator::new(
            &store,
            &vault,
            Verifier {
                outcome: Ok(()),
                invalid_identity: false,
            },
        )
        .remove_account(&account.account_id, "2026-09-22T17:01:00Z")
        .unwrap();
        assert!(store.snapshot().accounts.is_empty());
        assert!(matches!(
            store.open_protocol_config(&account.account_id),
            Err(StoreError::NotFound)
        ));
        assert!(!vault.contains(&account.account_id, CredentialKind::IncomingPassword));
        assert!(!vault.contains(&account.account_id, CredentialKind::OutgoingPassword));
    }

    #[test]
    fn malformed_server_config_is_rejected_before_credential_entry() {
        let state = TestState::new("invalid-config");
        let (store, vault) = open(&state);
        let (helper, service) = credential_entry_pair().unwrap();
        let mut invalid = config();
        invalid.imap.host = "bad host".into();
        let result = AccountCoordinator::new(
            &store,
            &vault,
            Verifier {
                outcome: Ok(()),
                invalid_identity: false,
            },
        )
        .connect_open_protocol(invalid, service, NOW);
        drop(helper);
        assert!(matches!(result, Err(AccountSetupError::Store(_))));
        assert!(store.snapshot().accounts.is_empty());
        let disk = fs::read_to_string(state.vault().join("credentials.json")).unwrap();
        assert!(!disk.contains("acct_"));
    }
}
