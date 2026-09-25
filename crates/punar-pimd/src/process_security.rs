//! Irreversible process hardening applied before PIM authority or content is
//! handled.
//!
//! A same-uid process must not be able to ptrace a first-party PIM bridge and
//! duplicate its inherited capability descriptor. Core files must not contain
//! messages or credentials, and later execs must not gain privilege. Keep the
//! three kernel controls together so a caller cannot accidentally apply only
//! the most visible one.

use rustix::process::{DumpableBehavior, Resource, Rlimit};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProcessSecurityError {
    #[error("PIM process security kernel operation failed: {0}")]
    Kernel(#[from] rustix::io::Errno),
    #[error("PIM process security state did not match the requested lockdown")]
    Verification,
}

/// Permanently disable core dumps, ptrace-style dumpability and future
/// privilege gain for the calling process. This operation is intentionally
/// irreversible and must run before an application receives its capability
/// endpoint or a service loads account state.
pub fn lock_down_current_process() -> Result<(), ProcessSecurityError> {
    rustix::process::setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )?;
    rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
    rustix::thread::set_no_new_privs(true)?;

    let core = rustix::process::getrlimit(Resource::Core);
    if core.current != Some(0)
        || core.maximum != Some(0)
        || rustix::process::dumpable_behavior()? != DumpableBehavior::NotDumpable
        || !rustix::thread::no_new_privs()?
    {
        return Err(ProcessSecurityError::Verification);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockdown_is_verified_and_idempotent() {
        lock_down_current_process().unwrap();
        lock_down_current_process().unwrap();

        let core = rustix::process::getrlimit(Resource::Core);
        assert_eq!(core.current, Some(0));
        assert_eq!(core.maximum, Some(0));
        assert_eq!(
            rustix::process::dumpable_behavior().unwrap(),
            DumpableBehavior::NotDumpable
        );
        assert!(rustix::thread::no_new_privs().unwrap());
    }
}
