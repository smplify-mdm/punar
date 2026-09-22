//! Privileged handoff for the one-use Mail account-entry surface.
//!
//! A fixed root broker transfers exactly two capabilities to the locked
//! `punar-mail-account` identity: the one-use sequenced-packet credential
//! entry endpoint and an already-verified Wayland stream. The frame contains
//! only bounded correlation metadata; provider configuration and password
//! bytes never cross this control socket.

use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};

use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, SocketType, recvmsg, sendmsg, sockopt,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const LAUNCH_VERSION: u8 = 1;
const MAX_LAUNCH_BYTES: usize = 384;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountLaunch {
    pub v: u8,
    pub launch_id: String,
    pub setup_id: String,
    pub profile_uid: u32,
}

impl AccountLaunch {
    #[must_use]
    pub fn new(
        launch_id: impl Into<String>,
        setup_id: impl Into<String>,
        profile_uid: u32,
    ) -> Self {
        Self {
            v: LAUNCH_VERSION,
            launch_id: launch_id.into(),
            setup_id: setup_id.into(),
            profile_uid,
        }
    }

    fn validate(&self, expected_uid: u32) -> Result<(), AccountLaunchError> {
        if self.v != LAUNCH_VERSION || self.profile_uid == 0 || self.profile_uid != expected_uid {
            return Err(AccountLaunchError::Malformed);
        }
        validate_id(&self.launch_id, "launch_")?;
        validate_id(&self.setup_id, "setup_")?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct AccountLaunchCapabilities {
    pub launch: AccountLaunch,
    pub entry_channel: OwnedFd,
    pub wayland_channel: OwnedFd,
}

#[derive(Debug, Error)]
pub enum AccountLaunchError {
    #[error("Mail account launch handoff kernel operation failed: {0}")]
    Kernel(#[from] rustix::io::Errno),
    #[error("Mail account launch handoff is malformed")]
    Malformed,
    #[error("Mail account launch handoff did not come from the privileged broker")]
    BrokerMismatch,
}

pub fn send_account_launch(
    control: impl AsFd,
    entry_channel: OwnedFd,
    wayland_channel: OwnedFd,
    launch: &AccountLaunch,
) -> Result<(), AccountLaunchError> {
    launch.validate(launch.profile_uid)?;
    validate_connected(&entry_channel, SocketType::SEQPACKET)?;
    validate_connected(&wayland_channel, SocketType::STREAM)?;
    let payload = serde_json::to_vec(launch).map_err(|_| AccountLaunchError::Malformed)?;
    if payload.is_empty() || payload.len() > MAX_LAUNCH_BYTES {
        return Err(AccountLaunchError::Malformed);
    }
    let rights = [entry_channel.as_fd(), wayland_channel.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&rights)) {
        return Err(AccountLaunchError::Malformed);
    }
    let written = sendmsg(
        control,
        &[IoSlice::new(&payload)],
        &mut ancillary,
        SendFlags::empty(),
    )?;
    if written != payload.len() {
        return Err(AccountLaunchError::Malformed);
    }
    Ok(())
}

pub fn receive_account_launch(
    control: impl AsFd,
    expected_uid: u32,
) -> Result<AccountLaunchCapabilities, AccountLaunchError> {
    receive_account_launch_from_broker(control, expected_uid, 0)
}

fn receive_account_launch_from_broker(
    control: impl AsFd,
    expected_uid: u32,
    expected_broker_uid: u32,
) -> Result<AccountLaunchCapabilities, AccountLaunchError> {
    let credentials = sockopt::socket_peercred(&control)?;
    if credentials.uid.as_raw() != expected_broker_uid {
        return Err(AccountLaunchError::BrokerMismatch);
    }
    let mut payload = [0_u8; MAX_LAUNCH_BYTES];
    let mut vectors = [IoSliceMut::new(&mut payload)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
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
        return Err(AccountLaunchError::Malformed);
    }
    let mut descriptors = Vec::new();
    for message in ancillary.drain() {
        match message {
            RecvAncillaryMessage::ScmRights(rights) => descriptors.extend(rights),
            _ => return Err(AccountLaunchError::Malformed),
        }
    }
    if descriptors.len() != 2 {
        return Err(AccountLaunchError::Malformed);
    }
    let launch: AccountLaunch = serde_json::from_slice(&payload[..received.bytes])
        .map_err(|_| AccountLaunchError::Malformed)?;
    launch.validate(expected_uid)?;
    let wayland_channel = descriptors.pop().expect("length checked");
    let entry_channel = descriptors.pop().expect("length checked");
    validate_connected(&entry_channel, SocketType::SEQPACKET)?;
    validate_connected(&wayland_channel, SocketType::STREAM)?;
    Ok(AccountLaunchCapabilities {
        launch,
        entry_channel,
        wayland_channel,
    })
}

fn validate_connected(
    descriptor: &OwnedFd,
    expected: SocketType,
) -> Result<(), AccountLaunchError> {
    if sockopt::socket_type(descriptor)? != expected || sockopt::socket_acceptconn(descriptor)? {
        return Err(AccountLaunchError::Malformed);
    }
    Ok(())
}

fn validate_id(value: &str, prefix: &str) -> Result<(), AccountLaunchError> {
    let suffix = value
        .strip_prefix(prefix)
        .ok_or(AccountLaunchError::Malformed)?;
    if value.len() > 80
        || suffix.is_empty()
        || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(AccountLaunchError::Malformed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{account_entry_pair, control_channel_pair};
    use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};

    fn receive_from_test_broker(
        control: impl AsFd,
        expected_uid: u32,
    ) -> Result<AccountLaunchCapabilities, AccountLaunchError> {
        receive_account_launch_from_broker(
            control,
            expected_uid,
            rustix::process::getuid().as_raw(),
        )
    }

    #[test]
    fn transfers_only_entry_and_display_capabilities() {
        let (broker, bridge) = control_channel_pair().unwrap();
        let (entry, service) = account_entry_pair().unwrap();
        let (wayland, server) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        send_account_launch(
            &broker,
            entry,
            wayland,
            &AccountLaunch::new("launch_A1", "setup_A1", 1000),
        )
        .unwrap();
        let received = receive_from_test_broker(&bridge, 1000).unwrap();
        assert_eq!(received.launch.setup_id, "setup_A1");
        drop(received);
        drop(service);
        drop(server);
    }

    #[test]
    fn rejects_wrong_profile_shape_peer_and_descriptor_types() {
        let (broker, bridge) = control_channel_pair().unwrap();
        let (entry, _) = account_entry_pair().unwrap();
        let (wayland, _) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        send_account_launch(
            &broker,
            entry,
            wayland,
            &AccountLaunch::new("launch_A2", "setup_A2", 1000),
        )
        .unwrap();
        assert!(receive_from_test_broker(&bridge, 1001).is_err());

        let (broker, bridge) = control_channel_pair().unwrap();
        let (entry, _) = account_entry_pair().unwrap();
        let (wrong_wayland, _) = account_entry_pair().unwrap();
        assert!(
            send_account_launch(
                &broker,
                entry,
                wrong_wayland,
                &AccountLaunch::new("launch_A3", "setup_A3", 1000),
            )
            .is_err()
        );
        drop(bridge);

        let (broker, bridge) = control_channel_pair().unwrap();
        let (entry, _) = account_entry_pair().unwrap();
        let (wayland, _) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        send_account_launch(
            &broker,
            entry,
            wayland,
            &AccountLaunch::new("launch_A4", "setup_A4", 1000),
        )
        .unwrap();
        assert!(
            receive_account_launch_from_broker(
                &bridge,
                1000,
                rustix::process::getuid().as_raw().saturating_add(1),
            )
            .is_err()
        );
    }
}
