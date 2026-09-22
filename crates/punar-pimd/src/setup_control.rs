//! Root-broker control transport for one protected account-entry helper.
//!
//! This is deliberately separate from both application IPC and the helper's
//! secret-bearing sequenced-packet channel. The broker sends only an opaque
//! setup id plus the profile uid. The bound service verifies the kernel peer
//! is root, consumes that setup once, and returns either exactly one unnamed
//! helper descriptor or a closed denial code. Passwords and server settings
//! are not representable on this transport.

use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};

use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const CONTROL_VERSION: u8 = 1;
const MAX_CONTROL_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountHelperClaim {
    pub v: u8,
    pub setup_id: String,
    pub profile_uid: u32,
}

impl AccountHelperClaim {
    #[must_use]
    pub fn new(setup_id: impl Into<String>, profile_uid: u32) -> Self {
        Self {
            v: CONTROL_VERSION,
            setup_id: setup_id.into(),
            profile_uid,
        }
    }

    fn validate(&self, expected_uid: u32) -> Result<(), AccountHelperControlError> {
        if self.v != CONTROL_VERSION {
            return Err(AccountHelperControlError::Malformed);
        }
        validate_setup_id(&self.setup_id)?;
        if self.profile_uid != expected_uid {
            return Err(AccountHelperControlError::ProfileMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountHelperReplyCode {
    Granted,
    NotFound,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountHelperReply {
    v: u8,
    setup_id: String,
    profile_uid: u32,
    code: AccountHelperReplyCode,
}

#[derive(Debug)]
pub struct GrantedAccountHelper {
    pub setup_id: String,
    pub channel: OwnedFd,
}

#[derive(Debug, Error)]
pub enum AccountHelperControlError {
    #[error("account-helper control kernel operation failed: {0}")]
    Kernel(#[from] rustix::io::Errno),
    #[error("account-helper control frame is malformed")]
    Malformed,
    #[error("account-helper claim belongs to another profile")]
    ProfileMismatch,
    #[error("account-helper claim did not come from the privileged broker")]
    BrokerMismatch,
    #[error("account-helper claim was refused: {0:?}")]
    Refused(AccountHelperReplyCode),
}

/// Broker side: send the non-secret claim request. The setup id is an opaque
/// correlation value, not a credential or bearer capability.
pub fn send_account_helper_claim(
    control: impl AsFd,
    claim: &AccountHelperClaim,
) -> Result<(), AccountHelperControlError> {
    claim.validate(claim.profile_uid)?;
    send_frame(control, claim, None)
}

/// Service side: receive a strict claim only after verifying the control peer
/// is root. Ancillary data on the request is always rejected.
pub fn receive_account_helper_claim(
    control: impl AsFd,
    expected_uid: u32,
) -> Result<AccountHelperClaim, AccountHelperControlError> {
    receive_account_helper_claim_from_broker(control, expected_uid, 0)
}

pub(crate) fn receive_account_helper_claim_from_broker(
    control: impl AsFd,
    expected_uid: u32,
    expected_broker_uid: u32,
) -> Result<AccountHelperClaim, AccountHelperControlError> {
    let credentials = rustix::net::sockopt::socket_peercred(&control)?;
    if credentials.uid.as_raw() != expected_broker_uid {
        return Err(AccountHelperControlError::BrokerMismatch);
    }
    let (payload, descriptors) = receive_frame(control)?;
    if !descriptors.is_empty() {
        return Err(AccountHelperControlError::Malformed);
    }
    let claim: AccountHelperClaim =
        serde_json::from_slice(&payload).map_err(|_| AccountHelperControlError::Malformed)?;
    claim.validate(expected_uid)?;
    Ok(claim)
}

pub(crate) fn send_account_helper_grant(
    control: impl AsFd,
    claim: &AccountHelperClaim,
    channel: OwnedFd,
) -> Result<(), AccountHelperControlError> {
    send_reply(
        control,
        claim,
        AccountHelperReplyCode::Granted,
        Some(channel),
    )
}

pub(crate) fn send_account_helper_refusal(
    control: impl AsFd,
    claim: &AccountHelperClaim,
    code: AccountHelperReplyCode,
) -> Result<(), AccountHelperControlError> {
    if code == AccountHelperReplyCode::Granted {
        return Err(AccountHelperControlError::Malformed);
    }
    send_reply(control, claim, code, None)
}

/// Broker side: accept exactly one descriptor only for a matching granted
/// reply. Closed refusals carry no descriptor and never reveal provider text.
pub fn receive_account_helper_channel(
    control: impl AsFd,
    expected_setup_id: &str,
    expected_uid: u32,
) -> Result<GrantedAccountHelper, AccountHelperControlError> {
    validate_setup_id(expected_setup_id)?;
    let (payload, mut descriptors) = receive_frame(control)?;
    let reply: AccountHelperReply =
        serde_json::from_slice(&payload).map_err(|_| AccountHelperControlError::Malformed)?;
    if reply.v != CONTROL_VERSION
        || reply.setup_id != expected_setup_id
        || reply.profile_uid != expected_uid
    {
        return Err(AccountHelperControlError::Malformed);
    }
    match reply.code {
        AccountHelperReplyCode::Granted if descriptors.len() == 1 => Ok(GrantedAccountHelper {
            setup_id: reply.setup_id,
            channel: descriptors.pop().expect("length checked"),
        }),
        AccountHelperReplyCode::Granted => Err(AccountHelperControlError::Malformed),
        code if descriptors.is_empty() => Err(AccountHelperControlError::Refused(code)),
        _ => Err(AccountHelperControlError::Malformed),
    }
}

fn send_reply(
    control: impl AsFd,
    claim: &AccountHelperClaim,
    code: AccountHelperReplyCode,
    channel: Option<OwnedFd>,
) -> Result<(), AccountHelperControlError> {
    send_frame(
        control,
        &AccountHelperReply {
            v: CONTROL_VERSION,
            setup_id: claim.setup_id.clone(),
            profile_uid: claim.profile_uid,
            code,
        },
        channel,
    )
}

fn send_frame<T: Serialize>(
    control: impl AsFd,
    frame: &T,
    channel: Option<OwnedFd>,
) -> Result<(), AccountHelperControlError> {
    let payload = serde_json::to_vec(frame).map_err(|_| AccountHelperControlError::Malformed)?;
    if payload.is_empty() || payload.len() > MAX_CONTROL_BYTES {
        return Err(AccountHelperControlError::Malformed);
    }
    let written = if let Some(channel) = channel.as_ref() {
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        let rights = [channel.as_fd()];
        if !ancillary.push(SendAncillaryMessage::ScmRights(&rights)) {
            return Err(AccountHelperControlError::Malformed);
        }
        sendmsg(
            &control,
            &[IoSlice::new(&payload)],
            &mut ancillary,
            SendFlags::empty(),
        )?
    } else {
        let mut ancillary = SendAncillaryBuffer::default();
        sendmsg(
            &control,
            &[IoSlice::new(&payload)],
            &mut ancillary,
            SendFlags::empty(),
        )?
    };
    if written != payload.len() {
        return Err(AccountHelperControlError::Malformed);
    }
    Ok(())
}

fn receive_frame(control: impl AsFd) -> Result<(Vec<u8>, Vec<OwnedFd>), AccountHelperControlError> {
    let mut payload = [0_u8; MAX_CONTROL_BYTES];
    let mut vectors = [IoSliceMut::new(&mut payload)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = recvmsg(
        control,
        &mut vectors,
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )?;
    if received.bytes == 0
        || received
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
    {
        return Err(AccountHelperControlError::Malformed);
    }
    let mut descriptors = Vec::new();
    for message in ancillary.drain() {
        match message {
            RecvAncillaryMessage::ScmRights(rights) => descriptors.extend(rights),
            _ => return Err(AccountHelperControlError::Malformed),
        }
    }
    Ok((payload[..received.bytes].to_vec(), descriptors))
}

fn validate_setup_id(setup_id: &str) -> Result<(), AccountHelperControlError> {
    let suffix = setup_id
        .strip_prefix("setup_")
        .ok_or(AccountHelperControlError::Malformed)?;
    if setup_id.len() <= 80
        && !suffix.is_empty()
        && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        Ok(())
    } else {
        Err(AccountHelperControlError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{account_entry_pair, control_channel_pair};
    use std::os::unix::net::UnixDatagram;

    fn receive_claim_from_test_broker(
        control: impl AsFd,
        expected_uid: u32,
    ) -> Result<AccountHelperClaim, AccountHelperControlError> {
        receive_account_helper_claim_from_broker(
            control,
            expected_uid,
            rustix::process::getuid().as_raw(),
        )
    }

    #[test]
    fn strict_claim_returns_exactly_one_working_helper_endpoint() {
        let (broker, service) = control_channel_pair().unwrap();
        let claim = AccountHelperClaim::new("setup_A1", 1000);
        send_account_helper_claim(&broker, &claim).unwrap();
        let received = receive_claim_from_test_broker(&service, 1000).unwrap();
        assert_eq!(received, claim);

        let (helper, account_service) = account_entry_pair().unwrap();
        send_account_helper_grant(&service, &received, helper).unwrap();
        let granted = receive_account_helper_channel(&broker, "setup_A1", 1000).unwrap();
        assert_eq!(granted.setup_id, "setup_A1");

        let helper = UnixDatagram::from(granted.channel);
        let account_service = UnixDatagram::from(account_service);
        helper.send(b"private-entry").unwrap();
        let mut payload = [0_u8; 32];
        let size = account_service.recv(&mut payload).unwrap();
        assert_eq!(&payload[..size], b"private-entry");
    }

    #[test]
    fn refusal_has_no_descriptor_and_preserves_only_closed_reason() {
        let (broker, service) = control_channel_pair().unwrap();
        let claim = AccountHelperClaim::new("setup_A2", 1000);
        send_account_helper_claim(&broker, &claim).unwrap();
        let received = receive_claim_from_test_broker(&service, 1000).unwrap();
        send_account_helper_refusal(&service, &received, AccountHelperReplyCode::NotFound).unwrap();
        assert!(matches!(
            receive_account_helper_channel(&broker, "setup_A2", 1000),
            Err(AccountHelperControlError::Refused(
                AccountHelperReplyCode::NotFound
            ))
        ));
    }

    #[test]
    fn cross_profile_extended_and_descriptor_bearing_claims_fail_closed() {
        let (broker, service) = control_channel_pair().unwrap();
        send_account_helper_claim(&broker, &AccountHelperClaim::new("setup_A3", 1000)).unwrap();
        assert!(matches!(
            receive_claim_from_test_broker(&service, 1001),
            Err(AccountHelperControlError::ProfileMismatch)
        ));

        let (broker, service) = control_channel_pair().unwrap();
        let extended = br#"{"v":1,"setup_id":"setup_A3","profile_uid":1000,"password":"no"}"#;
        let mut ancillary = SendAncillaryBuffer::default();
        sendmsg(
            &broker,
            &[IoSlice::new(extended)],
            &mut ancillary,
            SendFlags::empty(),
        )
        .unwrap();
        assert!(matches!(
            receive_claim_from_test_broker(&service, 1000),
            Err(AccountHelperControlError::Malformed)
        ));

        let (broker, service) = control_channel_pair().unwrap();
        let (descriptor, _) = account_entry_pair().unwrap();
        send_frame(
            &broker,
            &AccountHelperClaim::new("setup_A4", 1000),
            Some(descriptor),
        )
        .unwrap();
        assert!(matches!(
            receive_claim_from_test_broker(&service, 1000),
            Err(AccountHelperControlError::Malformed)
        ));
    }

    #[test]
    fn wrong_broker_is_rejected_before_claim_read() {
        let (broker, service) = control_channel_pair().unwrap();
        send_account_helper_claim(&broker, &AccountHelperClaim::new("setup_A5", 1000)).unwrap();
        let current = rustix::process::getuid().as_raw();
        let other = if current == u32::MAX {
            current - 1
        } else {
            current + 1
        };
        assert!(matches!(
            receive_account_helper_claim_from_broker(&service, 1000, other),
            Err(AccountHelperControlError::BrokerMismatch)
        ));
    }
}
