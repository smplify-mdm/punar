//! Privileged launch handoff for the first-party Mail surface.
//!
//! The desktop user never receives a PIM service descriptor and the Mail
//! bridge never discovers either endpoint by pathname.  A fixed root broker
//! transfers exactly two connected stream capabilities to the locked
//! `punar-mail` identity: the Mail-scoped PIM channel and an already-verified
//! Wayland connection.  This sequenced-packet control frame contains only
//! bounded, non-secret correlation metadata.

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
const MAX_LAUNCH_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailLaunch {
    pub v: u8,
    pub launch_id: String,
    pub profile_uid: u32,
}

impl MailLaunch {
    #[must_use]
    pub fn new(launch_id: impl Into<String>, profile_uid: u32) -> Self {
        Self {
            v: LAUNCH_VERSION,
            launch_id: launch_id.into(),
            profile_uid,
        }
    }

    fn validate(&self, expected_uid: u32) -> Result<(), MailLaunchError> {
        if self.v != LAUNCH_VERSION || self.profile_uid == 0 {
            return Err(MailLaunchError::Malformed);
        }
        let suffix = self
            .launch_id
            .strip_prefix("launch_")
            .ok_or(MailLaunchError::Malformed)?;
        if suffix.is_empty()
            || self.launch_id.len() > 80
            || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(MailLaunchError::Malformed);
        }
        if self.profile_uid != expected_uid {
            return Err(MailLaunchError::ProfileMismatch);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct MailLaunchCapabilities {
    pub launch: MailLaunch,
    pub pim_channel: OwnedFd,
    pub wayland_channel: OwnedFd,
}

#[derive(Debug, Error)]
pub enum MailLaunchError {
    #[error("Mail launch handoff kernel operation failed: {0}")]
    Kernel(#[from] rustix::io::Errno),
    #[error("Mail launch handoff is malformed")]
    Malformed,
    #[error("Mail launch handoff belongs to another profile")]
    ProfileMismatch,
    #[error("Mail launch handoff did not come from the privileged broker")]
    BrokerMismatch,
}

/// Broker side: consume the only copies the broker keeps of the application
/// and display capabilities after one complete sequenced-packet transfer.
pub fn send_mail_launch(
    control: impl AsFd,
    pim_channel: OwnedFd,
    wayland_channel: OwnedFd,
    launch: &MailLaunch,
) -> Result<(), MailLaunchError> {
    launch.validate(launch.profile_uid)?;
    validate_stream(&pim_channel)?;
    validate_stream(&wayland_channel)?;

    let payload = serde_json::to_vec(launch).map_err(|_| MailLaunchError::Malformed)?;
    if payload.is_empty() || payload.len() > MAX_LAUNCH_BYTES {
        return Err(MailLaunchError::Malformed);
    }
    let rights = [pim_channel.as_fd(), wayland_channel.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&rights)) {
        return Err(MailLaunchError::Malformed);
    }
    let written = sendmsg(
        control,
        &[IoSlice::new(&payload)],
        &mut ancillary,
        SendFlags::empty(),
    )?;
    if written != payload.len() {
        return Err(MailLaunchError::Malformed);
    }
    Ok(())
}

/// Mail bridge side: verify the kernel-attested root peer before reading the
/// frame, then accept exactly two non-listening stream descriptors in their
/// fixed order.  Ancillary extensions and truncation fail closed.
pub fn receive_mail_launch(
    control: impl AsFd,
    expected_uid: u32,
) -> Result<MailLaunchCapabilities, MailLaunchError> {
    receive_mail_launch_from_broker(control, expected_uid, 0)
}

fn receive_mail_launch_from_broker(
    control: impl AsFd,
    expected_uid: u32,
    expected_broker_uid: u32,
) -> Result<MailLaunchCapabilities, MailLaunchError> {
    let credentials = sockopt::socket_peercred(&control)?;
    if credentials.uid.as_raw() != expected_broker_uid {
        return Err(MailLaunchError::BrokerMismatch);
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
        return Err(MailLaunchError::Malformed);
    }

    let mut descriptors = Vec::new();
    for message in ancillary.drain() {
        match message {
            RecvAncillaryMessage::ScmRights(rights) => descriptors.extend(rights),
            _ => return Err(MailLaunchError::Malformed),
        }
    }
    if descriptors.len() != 2 {
        return Err(MailLaunchError::Malformed);
    }
    let launch: MailLaunch = serde_json::from_slice(&payload[..received.bytes])
        .map_err(|_| MailLaunchError::Malformed)?;
    launch.validate(expected_uid)?;

    let wayland_channel = descriptors.pop().expect("length checked");
    let pim_channel = descriptors.pop().expect("length checked");
    validate_stream(&pim_channel)?;
    validate_stream(&wayland_channel)?;
    Ok(MailLaunchCapabilities {
        launch,
        pim_channel,
        wayland_channel,
    })
}

fn validate_stream(descriptor: &OwnedFd) -> Result<(), MailLaunchError> {
    if sockopt::socket_type(descriptor)? != SocketType::STREAM
        || sockopt::socket_acceptconn(descriptor)?
    {
        return Err(MailLaunchError::Malformed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{client_channel_pair, control_channel_pair};
    use rustix::net::{
        AddressFamily, SendAncillaryBuffer, SendAncillaryMessage, SocketFlags, SocketType,
        socketpair,
    };
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    fn receive_from_test_broker(
        control: impl AsFd,
        expected_uid: u32,
    ) -> Result<MailLaunchCapabilities, MailLaunchError> {
        receive_mail_launch_from_broker(control, expected_uid, rustix::process::getuid().as_raw())
    }

    fn stream_pair() -> (OwnedFd, OwnedFd) {
        socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap()
    }

    #[test]
    fn transfers_only_the_two_fixed_capabilities() {
        let (broker, bridge) = control_channel_pair().unwrap();
        let (pim_client, pim_service) = client_channel_pair().unwrap();
        let (wayland_bridge, wayland_server) = stream_pair();
        let launch = MailLaunch::new("launch_A1", 1000);
        send_mail_launch(&broker, pim_client, wayland_bridge, &launch).unwrap();

        let received = receive_from_test_broker(&bridge, 1000).unwrap();
        assert_eq!(received.launch, launch);
        let mut pim_channel = UnixStream::from(received.pim_channel);
        let mut pim_service = UnixStream::from(pim_service);
        pim_channel.write_all(b"mail.list\n").unwrap();
        let mut frame = [0_u8; 10];
        pim_service.read_exact(&mut frame).unwrap();
        assert_eq!(&frame, b"mail.list\n");
        let mut display = UnixStream::from(received.wayland_channel);
        display.write_all(b"display").unwrap();
        let mut frame = [0_u8; 7];
        UnixStream::from(wayland_server)
            .read_exact(&mut frame)
            .unwrap();
        assert_eq!(&frame, b"display");
    }

    #[test]
    fn rejects_cross_profile_or_untrusted_broker() {
        let (broker, bridge) = control_channel_pair().unwrap();
        let (pim, _pim_peer) = stream_pair();
        let (wayland, _wayland_peer) = stream_pair();
        send_mail_launch(&broker, pim, wayland, &MailLaunch::new("launch_A2", 1000)).unwrap();
        assert!(matches!(
            receive_from_test_broker(&bridge, 1001),
            Err(MailLaunchError::ProfileMismatch)
        ));

        let (broker, bridge) = control_channel_pair().unwrap();
        let (pim, _pim_peer) = stream_pair();
        let (wayland, _wayland_peer) = stream_pair();
        send_mail_launch(&broker, pim, wayland, &MailLaunch::new("launch_A3", 1000)).unwrap();
        let current = rustix::process::getuid().as_raw();
        let other = if current == u32::MAX {
            current - 1
        } else {
            current + 1
        };
        assert!(matches!(
            receive_mail_launch_from_broker(&bridge, 1000, other),
            Err(MailLaunchError::BrokerMismatch)
        ));
    }

    #[test]
    fn rejects_extensions_missing_extra_or_wrong_descriptor_types() {
        let (broker, bridge) = control_channel_pair().unwrap();
        let (one, _one_peer) = stream_pair();
        send_raw(
            &broker,
            &[one.as_fd()],
            br#"{"v":1,"launch_id":"launch_A4","profile_uid":1000}"#,
        );
        assert!(matches!(
            receive_from_test_broker(&bridge, 1000),
            Err(MailLaunchError::Malformed)
        ));

        let (broker, bridge) = control_channel_pair().unwrap();
        let (one, _one_peer) = stream_pair();
        let (two, _two_peer) = stream_pair();
        let (three, _three_peer) = stream_pair();
        send_raw(
            &broker,
            &[one.as_fd(), two.as_fd(), three.as_fd()],
            br#"{"v":1,"launch_id":"launch_A5","profile_uid":1000}"#,
        );
        assert!(matches!(
            receive_from_test_broker(&bridge, 1000),
            Err(MailLaunchError::Malformed)
        ));

        let (broker, bridge) = control_channel_pair().unwrap();
        let datagrams = socketpair(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let (stream, _stream_peer) = stream_pair();
        send_raw(
            &broker,
            &[datagrams.0.as_fd(), stream.as_fd()],
            br#"{"v":1,"launch_id":"launch_A6","profile_uid":1000}"#,
        );
        assert!(matches!(
            receive_from_test_broker(&bridge, 1000),
            Err(MailLaunchError::Malformed)
        ));

        let (broker, bridge) = control_channel_pair().unwrap();
        let (one, _one_peer) = stream_pair();
        let (two, _two_peer) = stream_pair();
        send_raw(
            &broker,
            &[one.as_fd(), two.as_fd()],
            br#"{"v":1,"launch_id":"launch_A7","profile_uid":1000,"command":"sh"}"#,
        );
        assert!(matches!(
            receive_from_test_broker(&bridge, 1000),
            Err(MailLaunchError::Malformed)
        ));
    }

    fn send_raw(control: impl AsFd, rights: &[std::os::fd::BorrowedFd<'_>], frame: &[u8]) {
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(rights)));
        sendmsg(
            control,
            &[IoSlice::new(frame)],
            &mut ancillary,
            SendFlags::empty(),
        )
        .unwrap();
    }
}
