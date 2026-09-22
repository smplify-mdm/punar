//! One-use password/token transfer from a short-lived entry helper.
//!
//! The service creates an unnamed sequenced-packet socketpair and gives one
//! endpoint only to the fixed credential-entry helper. The helper becomes
//! non-dumpable, disables core dumps and future privilege gain, sends one
//! bounded opaque value, zeroizes its input and exits. No pathname, profile,
//! account, credential kind or generic secret operation crosses this channel.

use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{ProcessSecurityError, lock_down_current_process};

const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;
const ENTRY_DEADLINE: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Error)]
pub enum CredentialEntryError {
    #[error("credential-entry channel failed: {0}")]
    Io(#[from] io::Error),
    #[error("credential entry was cancelled")]
    Cancelled,
    #[error("credential entry was empty or malformed")]
    Invalid,
    #[error("credential entry exceeded its fixed limit")]
    TooLarge,
    #[error(transparent)]
    ProcessSecurity(#[from] ProcessSecurityError),
}

/// Create the unnamed one-use helper/service transport. Both descriptors are
/// close-on-exec until the fixed launcher deliberately inherits the helper end.
pub fn credential_entry_pair() -> Result<(OwnedFd, OwnedFd), CredentialEntryError> {
    socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|error| io::Error::from(error).into())
}

/// Helper-side guard. Construction must be the entry executable's first action
/// so the process is non-dumpable before a password field or provider token
/// exists. Consuming `self` on submit makes the channel one-use.
pub struct CredentialEntryHelper {
    channel: OwnedFd,
}

impl CredentialEntryHelper {
    pub fn lock_down(channel: OwnedFd) -> Result<Self, CredentialEntryError> {
        lock_down_current_process()?;
        Ok(Self { channel })
    }

    /// Send exactly one value. `secret` is cleared whether validation or
    /// transport succeeds or fails.
    pub fn submit(self, secret: &mut [u8]) -> Result<(), CredentialEntryError> {
        let result = self.submit_inner(secret);
        secret.zeroize();
        result
    }

    fn submit_inner(self, secret: &[u8]) -> Result<(), CredentialEntryError> {
        if secret.is_empty() {
            return Err(CredentialEntryError::Invalid);
        }
        if secret.len() > MAX_CREDENTIAL_BYTES {
            return Err(CredentialEntryError::TooLarge);
        }
        let channel = UnixDatagram::from(self.channel);
        channel.set_write_timeout(Some(ENTRY_DEADLINE))?;
        let written = channel.send(secret)?;
        if written != secret.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "credential-entry frame was only partially sent",
            )
            .into());
        }
        Ok(())
    }
}

/// Service-side receive. It stays private to the crate so the only supported
/// consumer can move the zeroizing buffer directly into the credential vault.
pub(crate) fn receive_credential(
    channel: OwnedFd,
) -> Result<Zeroizing<Vec<u8>>, CredentialEntryError> {
    receive_with_deadline(channel, ENTRY_DEADLINE)
}

fn receive_with_deadline(
    channel: OwnedFd,
    deadline: Duration,
) -> Result<Zeroizing<Vec<u8>>, CredentialEntryError> {
    let channel = UnixDatagram::from(channel);
    channel.set_read_timeout(Some(deadline))?;
    let mut bytes = Zeroizing::new(vec![0_u8; MAX_CREDENTIAL_BYTES + 1]);
    let received = match channel.recv(&mut bytes) {
        Ok(received) => received,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            return Err(CredentialEntryError::Cancelled);
        }
        Err(error) => return Err(error.into()),
    };
    if received == 0 {
        return Err(CredentialEntryError::Cancelled);
    }
    if received > MAX_CREDENTIAL_BYTES {
        return Err(CredentialEntryError::TooLarge);
    }
    bytes.truncate(received);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn helper_input_is_zeroized_and_exact_value_arrives_once() {
        let (helper, service) = credential_entry_pair().unwrap();
        let receiver = thread::spawn(move || receive_credential(service).unwrap());
        let helper = CredentialEntryHelper::lock_down(helper).unwrap();
        let mut input = b"app-specific password".to_vec();
        helper.submit(&mut input).unwrap();
        assert!(input.iter().all(|byte| *byte == 0));
        let received = receiver.join().unwrap();
        assert_eq!(&*received, b"app-specific password");
    }

    #[test]
    fn rejected_helper_input_is_always_zeroized() {
        let (helper, _service) = credential_entry_pair().unwrap();
        let helper = CredentialEntryHelper::lock_down(helper).unwrap();
        let mut oversized = vec![7_u8; MAX_CREDENTIAL_BYTES + 1];
        assert!(matches!(
            helper.submit(&mut oversized),
            Err(CredentialEntryError::TooLarge)
        ));
        assert!(oversized.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn closed_helper_is_a_cancellation_not_an_empty_password() {
        let (helper, service) = credential_entry_pair().unwrap();
        drop(helper);
        assert!(matches!(
            receive_with_deadline(service, Duration::from_millis(50)),
            Err(CredentialEntryError::Cancelled)
        ));
    }

    #[test]
    fn hostile_oversized_packet_is_refused_and_zeroized() {
        let (helper, service) = credential_entry_pair().unwrap();
        let helper = UnixDatagram::from(helper);
        helper.send(&vec![9_u8; MAX_CREDENTIAL_BYTES + 1]).unwrap();
        assert!(matches!(
            receive_with_deadline(service, Duration::from_millis(50)),
            Err(CredentialEntryError::TooLarge)
        ));
    }
}
