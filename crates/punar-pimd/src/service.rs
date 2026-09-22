//! Composition root for one profile-bound PIM service instance.
//!
//! This still creates no listener and is not staged in an image. It proves the
//! security-sensitive ordering for an already-authenticated control
//! connection: lock down the process, open only the bound profile state, admit
//! a root-brokered capability, then serve the strict local dispatcher.

use std::os::fd::AsFd;
use std::path::Path;

use thiserror::Error;

#[cfg(test)]
use crate::channel::receive_client_channel_from_broker;
use crate::{
    AdmissionError, ConnectionError, CursorKeyError, CursorSigner, LocalDispatcher, MailStore,
    MailStoreError, PimStore, ProcessSecurityError, StoreError, lock_down_current_process,
    receive_client_channel, serve_granted_channel,
};

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
}

pub struct PimService {
    profile_uid: u32,
    dispatcher: LocalDispatcher,
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
        let store = PimStore::open(&state_root.join("records.json"), profile_id, profile_uid)?;
        let mail_store = MailStore::open(&state_root.join("mail.redb"), profile_id, profile_uid)?;
        let signer = CursorSigner::load_or_create(&state_root.join("cursor-key.json"), profile_id)?;
        Ok(Self {
            profile_uid,
            dispatcher: LocalDispatcher::new(store, mail_store, signer),
        })
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

    #[cfg(test)]
    fn serve_control_from_uid(
        &self,
        control: impl AsFd,
        broker_uid: u32,
    ) -> Result<(), PimServiceError> {
        let granted = receive_client_channel_from_broker(control, self.profile_uid, broker_uid)?;
        self.serve_granted(granted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ClientGrant, PimClient, client_channel_pair, control_channel_pair, send_client_channel,
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
}
