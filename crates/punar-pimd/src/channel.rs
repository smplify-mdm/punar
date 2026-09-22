//! Capability-channel admission for future `punar-pimd` service wiring.
//!
//! There is deliberately no application-readable filesystem socket. A root
//! broker creates a connected client channel, gives one endpoint directly to
//! the fixed first-party application launch, and transfers the other endpoint
//! over a root/service-only `SOCK_SEQPACKET` control channel. Possession of the
//! inherited endpoint is the capability; a same-UID process cannot connect by
//! guessing a path because there is no path.
//!
//! This module implements and tests the descriptor-transfer primitive and
//! verifies the kernel-attested control-channel peer is root before it reads a
//! grant. The future service must still bind the instance to the expected
//! profile, sandbox the application launch, and make the application process
//! non-dumpable before production staging.

use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};

use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags, SocketType, recvmsg,
    sendmsg, socketpair,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const GRANT_VERSION: u8 = 1;
const MAX_GRANT_BYTES: usize = 512;

#[derive(Debug, Error)]
pub enum AdmissionError {
    #[error("PIM capability channel kernel operation failed: {0}")]
    Kernel(#[from] rustix::io::Errno),
    #[error("PIM capability grant is malformed: {0}")]
    Malformed(String),
    #[error("PIM capability grant is for another profile")]
    ProfileMismatch,
    #[error("PIM capability grant did not come from the privileged broker")]
    BrokerMismatch,
}

/// Fixed first-party client identity stamped by the privileged launcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PimClient {
    Mail,
    Calendar,
    Reminders,
    Settings,
}

impl PimClient {
    /// Least-privilege method partition. The service still validates the full
    /// method and params against `schemas/pim/ipc-message.json`.
    #[must_use]
    pub fn allows_method(self, method: &str) -> bool {
        match self {
            Self::Mail => matches!(
                method,
                "service.status"
                    | "mail.list"
                    | "mail.thread"
                    | "mail.message_body"
                    | "mail.draft_create"
                    | "mail.draft_update"
                    | "mail.send"
                    | "mail.archive"
                    | "mail.delete"
                    | "contacts.search"
                    | "changes.since"
            ),
            Self::Calendar => matches!(
                method,
                "service.status"
                    | "calendar.list"
                    | "events.list"
                    | "events.create"
                    | "events.update"
                    | "events.delete"
                    | "events.respond"
                    | "contacts.search"
                    | "changes.since"
            ),
            Self::Reminders => matches!(
                method,
                "service.status"
                    | "reminder_lists.list"
                    | "reminders.list"
                    | "reminders.create"
                    | "reminders.update"
                    | "reminders.complete"
                    | "reminders.delete"
                    | "changes.since"
            ),
            Self::Settings => matches!(
                method,
                "service.status"
                    | "accounts.list"
                    | "accounts.begin_connect"
                    | "accounts.cancel_connect"
                    | "accounts.remove"
                    | "sync.trigger"
                    | "changes.since"
            ),
        }
    }
}

/// Non-secret metadata accompanying exactly one transferred channel endpoint.
/// `grant_id` is audit correlation, never a bearer token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientGrant {
    pub v: u8,
    pub grant_id: String,
    pub profile_uid: u32,
    pub client: PimClient,
}

impl ClientGrant {
    pub fn new(grant_id: impl Into<String>, profile_uid: u32, client: PimClient) -> Self {
        Self {
            v: GRANT_VERSION,
            grant_id: grant_id.into(),
            profile_uid,
            client,
        }
    }

    fn validate(&self, expected_uid: u32) -> Result<(), AdmissionError> {
        if self.v != GRANT_VERSION {
            return Err(AdmissionError::Malformed(format!(
                "unsupported grant version {}",
                self.v
            )));
        }
        let suffix = self
            .grant_id
            .strip_prefix("grant_")
            .ok_or_else(|| AdmissionError::Malformed("grant id must begin with 'grant_'".into()))?;
        if suffix.is_empty()
            || self.grant_id.len() > 80
            || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(AdmissionError::Malformed(
                "grant id has invalid characters".into(),
            ));
        }
        if self.profile_uid != expected_uid {
            return Err(AdmissionError::ProfileMismatch);
        }
        Ok(())
    }
}

/// One admitted application channel and its trusted broker-stamped identity.
#[derive(Debug)]
pub struct GrantedChannel {
    pub grant: ClientGrant,
    pub channel: OwnedFd,
}

/// Create the unnamed stream used directly between one application window and
/// the PIM service. Both ends are close-on-exec unless explicitly inherited by
/// the fixed launch path.
pub fn client_channel_pair() -> Result<(OwnedFd, OwnedFd), AdmissionError> {
    Ok(socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )?)
}

/// Create the broker/service control transport. `SOCK_SEQPACKET` keeps one
/// small grant header and its `SCM_RIGHTS` descriptor in one bounded record.
pub fn control_channel_pair() -> Result<(OwnedFd, OwnedFd), AdmissionError> {
    Ok(socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?)
}

/// Transfer one client endpoint to the service and consume the sender's copy.
pub fn send_client_channel(
    control: impl AsFd,
    channel: OwnedFd,
    grant: &ClientGrant,
) -> Result<(), AdmissionError> {
    // Structural validation here catches programmer mistakes before a grant
    // enters the trusted control channel. The receiver independently checks
    // its bound uid.
    grant.validate(grant.profile_uid)?;
    let frame =
        serde_json::to_vec(grant).map_err(|error| AdmissionError::Malformed(error.to_string()))?;
    if frame.len() > MAX_GRANT_BYTES {
        return Err(AdmissionError::Malformed("grant frame is too large".into()));
    }

    let rights = [channel.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&rights)) {
        return Err(AdmissionError::Malformed(
            "descriptor did not fit the fixed grant frame".into(),
        ));
    }
    let written = sendmsg(
        control,
        &[IoSlice::new(&frame)],
        &mut ancillary,
        SendFlags::empty(),
    )?;
    if written != frame.len() {
        return Err(AdmissionError::Malformed(
            "grant frame was only partially sent".into(),
        ));
    }
    // `channel` drops here. After a successful send the broker keeps no app
    // endpoint it could accidentally reuse or leak.
    Ok(())
}

/// Receive exactly one client endpoint over the already-authenticated control
/// channel. Truncated payloads/ancillary data, absent/extra descriptors,
/// extensions and cross-profile grants all fail closed.
pub fn receive_client_channel(
    control: impl AsFd,
    expected_uid: u32,
) -> Result<GrantedChannel, AdmissionError> {
    receive_client_channel_from_broker(control, expected_uid, 0)
}

fn receive_client_channel_from_broker(
    control: impl AsFd,
    expected_uid: u32,
    expected_broker_uid: u32,
) -> Result<GrantedChannel, AdmissionError> {
    let credentials = rustix::net::sockopt::socket_peercred(&control)?;
    if credentials.uid.as_raw() != expected_broker_uid {
        return Err(AdmissionError::BrokerMismatch);
    }

    let mut payload = [0_u8; MAX_GRANT_BYTES];
    let mut vectors = [IoSliceMut::new(&mut payload)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = recvmsg(
        control,
        &mut vectors,
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )?;
    if received.bytes == 0 {
        return Err(AdmissionError::Malformed("empty grant frame".into()));
    }
    if received
        .flags
        .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
    {
        return Err(AdmissionError::Malformed("truncated grant frame".into()));
    }

    let mut descriptors = Vec::new();
    for message in ancillary.drain() {
        match message {
            RecvAncillaryMessage::ScmRights(rights) => descriptors.extend(rights),
            _ => {
                return Err(AdmissionError::Malformed(
                    "unexpected control metadata".into(),
                ));
            }
        }
    }
    if descriptors.len() != 1 {
        return Err(AdmissionError::Malformed(format!(
            "grant carried {} descriptors instead of one",
            descriptors.len()
        )));
    }

    let grant: ClientGrant = serde_json::from_slice(&payload[..received.bytes])
        .map_err(|error| AdmissionError::Malformed(error.to_string()))?;
    grant.validate(expected_uid)?;
    Ok(GrantedChannel {
        grant,
        channel: descriptors.pop().expect("length checked"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    fn receive_from_test_broker(
        control: impl AsFd,
        expected_uid: u32,
    ) -> Result<GrantedChannel, AdmissionError> {
        receive_client_channel_from_broker(
            control,
            expected_uid,
            rustix::process::getuid().as_raw(),
        )
    }

    #[test]
    fn one_unnamed_endpoint_is_transferred_and_carries_application_data() {
        let (broker, service) = control_channel_pair().unwrap();
        let (application, service_endpoint) = client_channel_pair().unwrap();
        let grant = ClientGrant::new("grant_A1", 1000, PimClient::Calendar);
        send_client_channel(&broker, service_endpoint, &grant).unwrap();
        let admitted = receive_from_test_broker(&service, 1000).unwrap();
        assert_eq!(admitted.grant, grant);

        let mut application = UnixStream::from(application);
        let mut service_endpoint = UnixStream::from(admitted.channel);
        application.write_all(b"calendar.list\n").unwrap();
        let mut payload = [0_u8; 14];
        service_endpoint.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"calendar.list\n");
    }

    #[test]
    fn cross_profile_grant_is_refused_and_the_received_fd_is_dropped() {
        let (broker, service) = control_channel_pair().unwrap();
        let (_application, service_endpoint) = client_channel_pair().unwrap();
        send_client_channel(
            &broker,
            service_endpoint,
            &ClientGrant::new("grant_A2", 1000, PimClient::Mail),
        )
        .unwrap();
        assert!(matches!(
            receive_from_test_broker(&service, 1001),
            Err(AdmissionError::ProfileMismatch)
        ));
    }

    #[test]
    fn untrusted_control_peer_is_rejected_before_the_grant_is_read() {
        let (broker, service) = control_channel_pair().unwrap();
        let (_application, service_endpoint) = client_channel_pair().unwrap();
        send_client_channel(
            &broker,
            service_endpoint,
            &ClientGrant::new("grant_A3", 1000, PimClient::Mail),
        )
        .unwrap();
        let current_uid = rustix::process::getuid().as_raw();
        let different_uid = if current_uid == u32::MAX {
            current_uid - 1
        } else {
            current_uid + 1
        };
        assert!(matches!(
            receive_client_channel_from_broker(&service, 1000, different_uid),
            Err(AdmissionError::BrokerMismatch)
        ));
    }

    #[test]
    fn grant_extensions_fail_closed() {
        let (broker, service) = control_channel_pair().unwrap();
        let (_application, service_endpoint) = client_channel_pair().unwrap();
        send_raw(
            &broker,
            service_endpoint,
            br#"{"v":1,"grant_id":"grant_A3","profile_uid":1000,"client":"mail","admin":true}"#,
        );
        assert!(matches!(
            receive_from_test_broker(&service, 1000),
            Err(AdmissionError::Malformed(_))
        ));
    }

    #[test]
    fn absent_descriptor_fails_closed() {
        let (broker, service) = control_channel_pair().unwrap();
        let grant =
            serde_json::to_vec(&ClientGrant::new("grant_A4", 1000, PimClient::Reminders)).unwrap();
        let mut ancillary = SendAncillaryBuffer::default();
        sendmsg(
            &broker,
            &[IoSlice::new(&grant)],
            &mut ancillary,
            SendFlags::empty(),
        )
        .unwrap();
        assert!(matches!(
            receive_from_test_broker(&service, 1000),
            Err(AdmissionError::Malformed(_))
        ));
    }

    #[test]
    fn two_descriptors_are_rejected_as_truncated_ancillary_data() {
        let (broker, service) = control_channel_pair().unwrap();
        let (_app_one, fd_one) = client_channel_pair().unwrap();
        let (_app_two, fd_two) = client_channel_pair().unwrap();
        let grant =
            serde_json::to_vec(&ClientGrant::new("grant_A5", 1000, PimClient::Settings)).unwrap();
        let rights = [fd_one.as_fd(), fd_two.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&rights)));
        sendmsg(
            &broker,
            &[IoSlice::new(&grant)],
            &mut ancillary,
            SendFlags::empty(),
        )
        .unwrap();
        assert!(matches!(
            receive_from_test_broker(&service, 1000),
            Err(AdmissionError::Malformed(_))
        ));
    }

    #[test]
    fn each_client_has_a_closed_least_privilege_method_set() {
        assert!(PimClient::Mail.allows_method("mail.thread"));
        assert!(!PimClient::Mail.allows_method("events.delete"));
        assert!(PimClient::Calendar.allows_method("events.update"));
        assert!(!PimClient::Calendar.allows_method("mail.send"));
        assert!(PimClient::Reminders.allows_method("reminders.complete"));
        assert!(!PimClient::Reminders.allows_method("accounts.remove"));
        assert!(PimClient::Settings.allows_method("accounts.begin_connect"));
        assert!(!PimClient::Settings.allows_method("mail.message_body"));
        for client in [
            PimClient::Mail,
            PimClient::Calendar,
            PimClient::Reminders,
            PimClient::Settings,
        ] {
            assert!(!client.allows_method("system.exec"));
            assert!(!client.allows_method("secrets.get"));
        }
    }

    fn send_raw(control: impl AsFd, channel: OwnedFd, frame: &[u8]) {
        let rights = [channel.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&rights)));
        sendmsg(
            control,
            &[IoSlice::new(frame)],
            &mut ancillary,
            SendFlags::empty(),
        )
        .unwrap();
    }
}
