//! Composition root for one profile-bound PIM service instance.
//!
//! This still creates no listener and is not staged in an image. It proves the
//! security-sensitive ordering for an already-authenticated control
//! connection: lock down the process, open only the bound profile state, admit
//! a root-brokered capability, then serve the strict local dispatcher.

use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;

#[cfg(test)]
use crate::channel::receive_client_channel_from_broker;
#[cfg(test)]
use crate::setup_control::receive_account_helper_claim_from_broker;
use crate::{
    AccountConnectError, AccountConnectLifecycle, AccountCoordinator, AccountEntryRunner,
    AccountHelperClaim, AccountHelperControlError, AccountHelperReplyCode, AccountLifecycle,
    AccountLifecycleError, AccountSetupError, AdmissionError, ConnectionError, CredentialVault,
    CursorKeyError, CursorSigner, EncryptedStorageProof, LocalDispatcher, MailStore,
    MailStoreError, NetworkOpenProtocolVerifier, OpenProtocolEntryRunner, OpenProtocolSyncRunner,
    PimStore, ProcessSecurityError, SetupSessionCoordinator, StoreError, SyncCoordinator,
    SyncQuiesceError, VaultError, lock_down_current_process, receive_account_helper_claim,
    receive_client_channel, serve_granted_channel,
};

const ACCOUNT_REMOVAL_TIMEOUT: Duration = Duration::from_secs(25);

#[derive(Debug, Error)]
pub enum PimServiceError {
    #[error(transparent)]
    ProcessSecurity(#[from] ProcessSecurityError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    CursorKey(#[from] CursorKeyError),
    #[error(transparent)]
    MailStore(#[from] MailStoreError),
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    #[error(transparent)]
    AccountHelperControl(#[from] AccountHelperControlError),
}

pub struct PimService {
    profile_uid: u32,
    dispatcher: LocalDispatcher,
    account_connect: Arc<SetupSessionCoordinator>,
}

struct BoundAccountLifecycle {
    store: Arc<PimStore>,
    mail_store: Arc<MailStore>,
    sync: Arc<SyncCoordinator>,
    state_root: PathBuf,
    profile_id: String,
}

impl AccountLifecycle for BoundAccountLifecycle {
    fn remove_account(
        &self,
        account_id: &str,
        delete_local_data: bool,
    ) -> Result<(), AccountLifecycleError> {
        if !delete_local_data {
            return Err(AccountLifecycleError::LocalDataDeletionRequired);
        }
        let permit = self
            .sync
            .begin_account_removal(account_id, ACCOUNT_REMOVAL_TIMEOUT)
            .map_err(map_quiesce_error)?;
        let proof = EncryptedStorageProof::verify(&self.state_root).map_err(map_vault_error)?;
        let vault = CredentialVault::open(&self.state_root, &self.profile_id, &proof)
            .map_err(map_vault_error)?;
        AccountCoordinator::new(
            &self.store,
            &self.mail_store,
            &vault,
            NetworkOpenProtocolVerifier::default(),
        )
        .remove_account(&permit, &punar_common::time::utc_now_rfc3339())
        .map_err(map_account_setup_error)
    }
}

impl PimService {
    /// Open one service instance below a private, service-owned state root.
    /// Process lockdown happens before the first state or cursor-key read.
    pub fn open(
        state_root: &Path,
        profile_id: &str,
        profile_uid: u32,
    ) -> Result<Self, PimServiceError> {
        lock_down_current_process()?;
        let store = Arc::new(PimStore::open(
            &state_root.join("records.json"),
            profile_id,
            profile_uid,
        )?);
        let mail_store = Arc::new(MailStore::open(
            &state_root.join("mail.redb"),
            profile_id,
            profile_uid,
        )?);
        let signer = CursorSigner::load_or_create(&state_root.join("cursor-key.json"), profile_id)?;
        let runner = Arc::new(OpenProtocolSyncRunner::new(
            Arc::clone(&store),
            Arc::clone(&mail_store),
            state_root,
            profile_id,
            Duration::from_secs(20),
        ));
        let sync = SyncCoordinator::new(Arc::clone(&store), runner);
        let lifecycle: Arc<dyn AccountLifecycle> = Arc::new(BoundAccountLifecycle {
            store: Arc::clone(&store),
            mail_store: Arc::clone(&mail_store),
            sync: Arc::clone(&sync),
            state_root: state_root.to_path_buf(),
            profile_id: profile_id.to_string(),
        });
        let entry_runner: Arc<dyn AccountEntryRunner> = Arc::new(OpenProtocolEntryRunner::new(
            Arc::clone(&store),
            Arc::clone(&mail_store),
            state_root,
            profile_id,
        ));
        let account_connect = SetupSessionCoordinator::new(entry_runner);
        let account_connect_lifecycle: Arc<dyn AccountConnectLifecycle> = account_connect.clone();
        Ok(Self {
            profile_uid,
            dispatcher: LocalDispatcher::with_runtime(
                store,
                mail_store,
                signer,
                sync,
                lifecycle,
                account_connect_lifecycle,
            ),
            account_connect,
        })
    }

    /// Privileged-launcher side of protected account entry. The descriptor is
    /// intentionally unavailable through the application request protocol.
    pub fn claim_account_helper(&self, setup_id: &str) -> Result<OwnedFd, AccountConnectError> {
        self.account_connect.claim_helper(setup_id)
    }

    /// Serve one root-brokered helper claim. A closed refusal contains no
    /// descriptor; success consumes the setup's one helper endpoint.
    pub fn serve_account_helper_control(&self, control: impl AsFd) -> Result<(), PimServiceError> {
        let claim = receive_account_helper_claim(&control, self.profile_uid)?;
        self.answer_account_helper_claim(control, &claim)
    }

    /// Admit exactly one channel from a kernel-attested root control peer and
    /// serve it until orderly EOF or a connection-fatal frame error.
    pub fn serve_control(&self, control: impl AsFd) -> Result<(), PimServiceError> {
        let granted = receive_client_channel(control, self.profile_uid)?;
        self.serve_granted(granted)
    }

    fn serve_granted(&self, granted: crate::GrantedChannel) -> Result<(), PimServiceError> {
        serve_granted_channel(granted, |grant, request| {
            self.dispatcher.dispatch(grant, request)
        })?;
        Ok(())
    }

    fn answer_account_helper_claim(
        &self,
        control: impl AsFd,
        claim: &AccountHelperClaim,
    ) -> Result<(), PimServiceError> {
        match self.claim_account_helper(&claim.setup_id) {
            Ok(channel) => {
                crate::setup_control::send_account_helper_grant(control, claim, channel)?
            }
            Err(AccountConnectError::NotFound) => {
                crate::setup_control::send_account_helper_refusal(
                    control,
                    claim,
                    AccountHelperReplyCode::NotFound,
                )?
            }
            Err(
                AccountConnectError::UnsupportedProvider
                | AccountConnectError::RateLimited
                | AccountConnectError::Runtime,
            ) => crate::setup_control::send_account_helper_refusal(
                control,
                claim,
                AccountHelperReplyCode::Internal,
            )?,
        }
        Ok(())
    }

    #[cfg(test)]
    fn serve_control_from_uid(
        &self,
        control: impl AsFd,
        broker_uid: u32,
    ) -> Result<(), PimServiceError> {
        let granted = receive_client_channel_from_broker(control, self.profile_uid, broker_uid)?;
        self.serve_granted(granted)
    }

    #[cfg(test)]
    fn serve_account_helper_control_from_uid(
        &self,
        control: impl AsFd,
        broker_uid: u32,
    ) -> Result<(), PimServiceError> {
        let claim =
            receive_account_helper_claim_from_broker(&control, self.profile_uid, broker_uid)?;
        self.answer_account_helper_claim(control, &claim)
    }
}

fn map_quiesce_error(error: SyncQuiesceError) -> AccountLifecycleError {
    match error {
        SyncQuiesceError::NotFound => AccountLifecycleError::NotFound,
        SyncQuiesceError::AlreadyRemoving | SyncQuiesceError::Busy => AccountLifecycleError::Busy,
    }
}

fn map_vault_error(error: VaultError) -> AccountLifecycleError {
    match error {
        VaultError::StorageEncryptionRequired => AccountLifecycleError::StorageEncryptionRequired,
        VaultError::NotFound
        | VaultError::Io(_)
        | VaultError::Invalid
        | VaultError::ProfileMismatch
        | VaultError::Crypto
        | VaultError::Entropy
        | VaultError::CredentialEntry(_) => AccountLifecycleError::Internal,
    }
}

fn map_account_setup_error(error: AccountSetupError) -> AccountLifecycleError {
    match error {
        AccountSetupError::Store(StoreError::NotFound) => AccountLifecycleError::NotFound,
        AccountSetupError::Vault(VaultError::StorageEncryptionRequired) => {
            AccountLifecycleError::StorageEncryptionRequired
        }
        AccountSetupError::Store(_)
        | AccountSetupError::Vault(_)
        | AccountSetupError::MailStore(_)
        | AccountSetupError::Provider(_)
        | AccountSetupError::Entropy
        | AccountSetupError::Cleanup
        | AccountSetupError::RemovalPermitMismatch => AccountLifecycleError::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AccountHelperClaim, AccountHelperControlError, AccountHelperReplyCode, ClientGrant,
        PimClient, ProviderType, client_channel_pair, control_channel_pair,
        receive_account_helper_channel, send_account_helper_claim, send_client_channel,
    };
    use serde_json::Value;
    use std::fs;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::thread;

    fn temp_root() -> PathBuf {
        let mut suffix = [0_u8; 12];
        getrandom::fill(&mut suffix).unwrap();
        let suffix = suffix
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        std::env::temp_dir().join(format!("punar-pimd-service-test-{suffix}"))
    }

    #[test]
    fn admitted_channel_reaches_only_the_bound_fixture_free_service() {
        let root = temp_root();
        let profile_uid = rustix::process::getuid().as_raw();
        let service = Arc::new(PimService::open(&root, "profile_A1", profile_uid).unwrap());
        let (broker, service_control) = control_channel_pair().unwrap();
        let (application, service_endpoint) = client_channel_pair().unwrap();
        send_client_channel(
            &broker,
            service_endpoint,
            &ClientGrant::new("grant_A1", profile_uid, PimClient::Settings),
        )
        .unwrap();

        let worker = {
            let service = Arc::clone(&service);
            thread::spawn(move || {
                service
                    .serve_control_from_uid(&service_control, rustix::process::getuid().as_raw())
                    .unwrap();
            })
        };

        let mut application = UnixStream::from(application);
        application
            .write_all(
                b"{\"v\":1,\"id\":\"status-1\",\"method\":\"service.status\",\"params\":{}}\n",
            )
            .unwrap();
        application.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        BufReader::new(application)
            .read_line(&mut response)
            .unwrap();
        let response: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(response["id"], "status-1");
        assert_eq!(response["result"]["profile_id"], "profile_A1");
        assert_eq!(response["result"]["accounts"], 0);
        assert_eq!(response["result"]["storage_encryption"], "unverified");
        assert!(!response.to_string().contains("demo"));

        worker.join().unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn root_broker_claims_each_setup_helper_exactly_once() {
        let root = temp_root();
        let profile_uid = rustix::process::getuid().as_raw();
        let service = PimService::open(&root, "profile_A1", profile_uid).unwrap();
        let status = service
            .account_connect
            .begin(ProviderType::OpenProtocols)
            .unwrap();

        let (broker, service_control) = control_channel_pair().unwrap();
        send_account_helper_claim(
            &broker,
            &AccountHelperClaim::new(&status.setup_id, profile_uid),
        )
        .unwrap();
        service
            .serve_account_helper_control_from_uid(
                &service_control,
                rustix::process::getuid().as_raw(),
            )
            .unwrap();
        let granted =
            receive_account_helper_channel(&broker, &status.setup_id, profile_uid).unwrap();
        assert_eq!(granted.setup_id, status.setup_id);
        drop(granted);

        let (broker, service_control) = control_channel_pair().unwrap();
        send_account_helper_claim(
            &broker,
            &AccountHelperClaim::new(&status.setup_id, profile_uid),
        )
        .unwrap();
        service
            .serve_account_helper_control_from_uid(
                &service_control,
                rustix::process::getuid().as_raw(),
            )
            .unwrap();
        assert!(matches!(
            receive_account_helper_channel(&broker, &status.setup_id, profile_uid),
            Err(AccountHelperControlError::Refused(
                AccountHelperReplyCode::NotFound
            ))
        ));

        let _ = fs::remove_dir_all(root);
    }
}
