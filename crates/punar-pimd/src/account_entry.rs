//! One-use protected entry transport for an open-protocol Mail account.
//!
//! The ordinary Settings and Mail application channels never carry provider
//! endpoints, login names or passwords. A fixed short-lived helper receives
//! an unnamed sequenced-packet endpoint from the privileged launcher, locks
//! itself down before collecting input, then sends one bounded non-secret
//! setup frame followed by one opaque password frame. The service consumes
//! the endpoint once and commits through [`crate::AccountCoordinator`].

use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    Account, AccountCoordinator, AccountSetupError, CredentialEntryError, CredentialEntryHelper,
    OpenProtocolAccountInput, OpenProtocolConfig, OpenProtocolVerifier, ProcessSecurityError,
    credential_entry_pair, lock_down_current_process,
};

const ENTRY_VERSION: u8 = 1;
const MAX_SETUP_BYTES: usize = 8 * 1024;
const MAX_PASSWORD_BYTES: usize = 64 * 1024;
const ENTRY_DEADLINE: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenProtocolSetup {
    pub identity: OpenProtocolAccountInput,
    pub config: OpenProtocolConfig,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupFrame {
    v: u8,
    setup: OpenProtocolSetup,
}

#[derive(Debug, Error)]
pub enum AccountEntryError {
    #[error("account-entry channel failed: {0}")]
    Io(#[from] io::Error),
    #[error("account entry was cancelled")]
    Cancelled,
    #[error("account entry was malformed")]
    Invalid,
    #[error("account entry exceeded its fixed limit")]
    TooLarge,
    #[error(transparent)]
    ProcessSecurity(#[from] ProcessSecurityError),
    #[error(transparent)]
    CredentialEntry(#[from] CredentialEntryError),
    #[error(transparent)]
    Setup(#[from] AccountSetupError),
}

pub fn account_entry_pair() -> Result<(OwnedFd, OwnedFd), AccountEntryError> {
    socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|error| io::Error::from(error).into())
}

/// Helper-side guard. Construction must happen before the helper creates any
/// password field. Consuming `self` makes the capability one-use.
pub struct AccountEntryHelper {
    channel: OwnedFd,
}

impl AccountEntryHelper {
    pub fn lock_down(channel: OwnedFd) -> Result<Self, AccountEntryError> {
        lock_down_current_process()?;
        Ok(Self { channel })
    }

    /// Send one setup description and password. `password` is cleared on all
    /// success and failure paths; it never enters JSON, argv or environment.
    pub fn submit(
        self,
        setup: &OpenProtocolSetup,
        password: &mut [u8],
    ) -> Result<(), AccountEntryError> {
        let result = self.submit_inner(setup, password);
        password.zeroize();
        result
    }

    fn submit_inner(
        self,
        setup: &OpenProtocolSetup,
        password: &[u8],
    ) -> Result<(), AccountEntryError> {
        if password.is_empty() {
            return Err(AccountEntryError::Invalid);
        }
        if password.len() > MAX_PASSWORD_BYTES {
            return Err(AccountEntryError::TooLarge);
        }
        let frame = serde_json::to_vec(&SetupFrame {
            v: ENTRY_VERSION,
            setup: setup.clone(),
        })
        .map_err(|_| AccountEntryError::Invalid)?;
        if frame.is_empty() || frame.len() > MAX_SETUP_BYTES {
            return Err(AccountEntryError::TooLarge);
        }

        let channel = UnixDatagram::from(self.channel);
        channel.set_write_timeout(Some(ENTRY_DEADLINE))?;
        send_packet(&channel, &frame)?;
        send_packet(&channel, password)
    }
}

/// Consume one helper session and commit it through the existing transactional
/// coordinator. The password is relayed over the already-tested vault entry
/// channel and every intermediate buffer is zeroizing.
pub fn complete_account_entry<V: OpenProtocolVerifier>(
    coordinator: &AccountCoordinator<'_, V>,
    channel: OwnedFd,
    now: &str,
) -> Result<Account, AccountEntryError> {
    let (setup, mut password) = receive_account_entry(channel, ENTRY_DEADLINE)?;
    let (helper_channel, vault_channel) = credential_entry_pair()?;
    let helper = CredentialEntryHelper::lock_down(helper_channel)?;
    helper.submit(&mut password)?;
    coordinator
        .connect_open_protocol(setup.identity, setup.config, vault_channel, now)
        .map_err(Into::into)
}

fn receive_account_entry(
    channel: OwnedFd,
    deadline: Duration,
) -> Result<(OpenProtocolSetup, Zeroizing<Vec<u8>>), AccountEntryError> {
    let channel = UnixDatagram::from(channel);
    channel.set_read_timeout(Some(deadline))?;
    let setup_bytes = receive_packet(&channel, MAX_SETUP_BYTES)?;
    let frame: SetupFrame =
        serde_json::from_slice(&setup_bytes).map_err(|_| AccountEntryError::Invalid)?;
    if frame.v != ENTRY_VERSION {
        return Err(AccountEntryError::Invalid);
    }
    let password = receive_packet(&channel, MAX_PASSWORD_BYTES)?;
    Ok((frame.setup, password))
}

fn send_packet(channel: &UnixDatagram, value: &[u8]) -> Result<(), AccountEntryError> {
    let written = channel.send(value)?;
    if written != value.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "account-entry packet was only partially sent",
        )
        .into());
    }
    Ok(())
}

fn receive_packet(
    channel: &UnixDatagram,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, AccountEntryError> {
    let mut bytes = Zeroizing::new(vec![0_u8; maximum + 1]);
    let received = match channel.recv(&mut bytes) {
        Ok(received) => received,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            return Err(AccountEntryError::Cancelled);
        }
        Err(error) => return Err(error.into()),
    };
    if received == 0 {
        return Err(AccountEntryError::Cancelled);
    }
    if received > maximum {
        return Err(AccountEntryError::TooLarge);
    }
    bytes.truncate(received);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CredentialKind, CredentialVault, EmailAddress, MailServerConfig, MailServerSecurity,
        MailStore, PimStore, ProviderCheckError, VerifiedOpenProtocolIdentity,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    const NOW: &str = "2026-09-22T18:00:00Z";

    fn setup() -> OpenProtocolSetup {
        OpenProtocolSetup {
            identity: OpenProtocolAccountInput {
                display_name: "Alice Work".into(),
                primary_address: EmailAddress {
                    name: Some("Alice".into()),
                    address: "alice@example.com".into(),
                },
            },
            config: OpenProtocolConfig {
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
            },
        }
    }

    struct Verifier;

    impl OpenProtocolVerifier for Verifier {
        fn verify(
            &self,
            config: &OpenProtocolConfig,
            identity: &OpenProtocolAccountInput,
            password: &[u8],
        ) -> Result<VerifiedOpenProtocolIdentity, ProviderCheckError> {
            assert_eq!(config.username, "alice-login");
            assert_eq!(password, b"app-password");
            Ok(VerifiedOpenProtocolIdentity {
                display_name: identity.display_name.clone(),
                primary_address: identity.primary_address.clone(),
            })
        }
    }

    fn root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "punar-account-entry-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn protected_entry_commits_verified_account_without_secret_in_setup_frame() {
        let root = root("commit");
        let store = PimStore::open(&root.join("records.json"), "profile_A1", 1000).unwrap();
        let mail_store = MailStore::open(&root.join("mail.redb"), "profile_A1", 1000).unwrap();
        let vault = CredentialVault::open_for_test(&root.join("vault"), "profile_A1").unwrap();
        let coordinator = AccountCoordinator::new(&store, &mail_store, &vault, Verifier);
        let (helper_channel, service_channel) = account_entry_pair().unwrap();
        let sender = thread::spawn(move || {
            let helper = AccountEntryHelper::lock_down(helper_channel).unwrap();
            let mut password = b"app-password".to_vec();
            helper.submit(&setup(), &mut password).unwrap();
            assert!(password.iter().all(|byte| *byte == 0));
        });
        let account = complete_account_entry(&coordinator, service_channel, NOW).unwrap();
        sender.join().unwrap();
        assert_eq!(store.snapshot().accounts, vec![account.clone()]);
        assert!(vault.contains(&account.account_id, CredentialKind::IncomingPassword));
        assert!(vault.contains(&account.account_id, CredentialKind::OutgoingPassword));
        let setup_disk = fs::read(root.join("records.json")).unwrap();
        assert!(
            !setup_disk
                .windows(12)
                .any(|window| window == b"app-password")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cancellation_and_oversized_password_leave_no_account() {
        let (helper, service) = account_entry_pair().unwrap();
        drop(helper);
        assert!(matches!(
            receive_account_entry(service, Duration::from_millis(50)),
            Err(AccountEntryError::Cancelled)
        ));

        let (helper, _service) = account_entry_pair().unwrap();
        let helper = AccountEntryHelper::lock_down(helper).unwrap();
        let mut password = vec![7_u8; MAX_PASSWORD_BYTES + 1];
        assert!(matches!(
            helper.submit(&setup(), &mut password),
            Err(AccountEntryError::TooLarge)
        ));
        assert!(password.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn extended_or_wrong_version_setup_frame_fails_closed_before_password_use() {
        for frame in [
            serde_json::json!({"v":2,"setup":setup()}),
            serde_json::json!({"v":1,"setup":setup(),"password":"leak"}),
        ] {
            let (helper, service) = account_entry_pair().unwrap();
            let helper = UnixDatagram::from(helper);
            helper.send(&serde_json::to_vec(&frame).unwrap()).unwrap();
            helper.send(b"never-consumed").unwrap();
            assert!(matches!(
                receive_account_entry(service, Duration::from_millis(50)),
                Err(AccountEntryError::Invalid)
            ));
        }
    }
}
