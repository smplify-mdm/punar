//! Socket-activated entry point for one profile-bound PIM service.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::env;
use std::os::fd::{AsFd, OwnedFd};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use punar_pimd::{PimService, serve_profile};
use rustix::io::{FdFlags, fcntl_setfd};
use rustix::net::{SocketType, sockopt};
use thiserror::Error;

const PROFILE_UID_ENV: &str = "PUNAR_PROFILE_UID";
const APPLICATION_FD_NAME: &str = "application";
const ACCOUNT_HELPER_FD_NAME: &str = "account-helper";
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
enum StartError {
    #[error("profile uid is missing or invalid")]
    InvalidProfileUid,
    #[error("socket activation descriptors are invalid")]
    InvalidDescriptors,
    #[error("socket activation could not be read")]
    Activation(#[from] sd_listen_fds::Error),
    #[error("socket descriptor validation failed")]
    Kernel(#[from] rustix::io::Errno),
    #[error("profile service could not be opened")]
    Service(#[from] punar_pimd::PimServiceError),
    #[error("profile service failed")]
    Runtime(#[from] punar_pimd::PimDaemonError),
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("punar-pimd: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), StartError> {
    if env::args_os().len() != 1 {
        return Err(StartError::InvalidDescriptors);
    }
    let profile_uid = parse_profile_uid(env::var_os(PROFILE_UID_ENV))?;
    let descriptors = sd_listen_fds::get()?
        .into_iter()
        .map(|(name, descriptor)| (name, descriptor.into_std()))
        .collect();
    let (application_listener, helper_listener) = select_descriptors(descriptors)?;
    let profile_id = format!("profile_uid{profile_uid}");
    let state_root = PathBuf::from("/var/lib/punar-pim").join(profile_uid.to_string());
    let service = Arc::new(PimService::open(&state_root, &profile_id, profile_uid)?);
    serve_profile(service, application_listener, helper_listener, IDLE_TIMEOUT)?;
    Ok(())
}

fn parse_profile_uid(value: Option<std::ffi::OsString>) -> Result<u32, StartError> {
    let value = value
        .and_then(|value| value.into_string().ok())
        .ok_or(StartError::InvalidProfileUid)?;
    let parsed = value
        .parse::<u32>()
        .map_err(|_| StartError::InvalidProfileUid)?;
    if parsed == 0 || parsed.to_string() != value {
        return Err(StartError::InvalidProfileUid);
    }
    Ok(parsed)
}

fn select_descriptors(
    descriptors: Vec<(Option<String>, OwnedFd)>,
) -> Result<(OwnedFd, OwnedFd), StartError> {
    if descriptors.len() != 2 {
        return Err(StartError::InvalidDescriptors);
    }
    let mut named = BTreeMap::new();
    for (name, descriptor) in descriptors {
        let name = name.ok_or(StartError::InvalidDescriptors)?;
        if name != APPLICATION_FD_NAME && name != ACCOUNT_HELPER_FD_NAME {
            return Err(StartError::InvalidDescriptors);
        }
        validate_listener(&descriptor)?;
        if named.insert(name, descriptor).is_some() {
            return Err(StartError::InvalidDescriptors);
        }
    }
    let application = named
        .remove(APPLICATION_FD_NAME)
        .ok_or(StartError::InvalidDescriptors)?;
    let helper = named
        .remove(ACCOUNT_HELPER_FD_NAME)
        .ok_or(StartError::InvalidDescriptors)?;
    Ok((application, helper))
}

fn validate_listener(descriptor: &OwnedFd) -> Result<(), StartError> {
    fcntl_setfd(descriptor.as_fd(), FdFlags::CLOEXEC)?;
    if sockopt::socket_type(descriptor)? != SocketType::SEQPACKET
        || !sockopt::socket_acceptconn(descriptor)?
    {
        return Err(StartError::InvalidDescriptors);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, bind, listen, socket_with};
    use std::fs;
    use std::path::{Path, PathBuf};

    fn temp_root() -> PathBuf {
        let mut suffix = [0_u8; 12];
        getrandom::fill(&mut suffix).unwrap();
        let suffix = suffix
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        std::env::temp_dir().join(format!("punar-pimd-entrypoint-{suffix}"))
    }

    fn listener(path: &Path) -> OwnedFd {
        typed_listener(path, SocketType::SEQPACKET)
    }

    fn typed_listener(path: &Path, socket_type: SocketType) -> OwnedFd {
        let descriptor =
            socket_with(AddressFamily::UNIX, socket_type, SocketFlags::empty(), None).unwrap();
        bind(&descriptor, &SocketAddrUnix::new(path).unwrap()).unwrap();
        listen(&descriptor, 8).unwrap();
        descriptor
    }

    #[test]
    fn profile_uid_is_strict_and_never_root() {
        assert_eq!(
            parse_profile_uid(Some("1000".into())).expect("valid uid"),
            1000
        );
        for invalid in [
            None,
            Some("".into()),
            Some("0".into()),
            Some("01000".into()),
        ] {
            assert!(parse_profile_uid(invalid).is_err());
        }
    }

    #[test]
    fn accepts_only_the_two_named_listening_seqpacket_descriptors() {
        let root = temp_root();
        fs::create_dir_all(&root).unwrap();
        let selected = select_descriptors(vec![
            (
                Some(ACCOUNT_HELPER_FD_NAME.into()),
                listener(&root.join("helper.sock")),
            ),
            (
                Some(APPLICATION_FD_NAME.into()),
                listener(&root.join("application.sock")),
            ),
        ])
        .unwrap();
        assert_eq!(
            sockopt::socket_type(&selected.0).unwrap(),
            SocketType::SEQPACKET
        );
        assert!(sockopt::socket_acceptconn(&selected.1).unwrap());
        drop(selected);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_unnamed_or_unknown_activation_descriptors() {
        let root = temp_root();
        fs::create_dir_all(&root).unwrap();
        let unnamed = select_descriptors(vec![
            (None, listener(&root.join("unnamed.sock"))),
            (
                Some(ACCOUNT_HELPER_FD_NAME.into()),
                listener(&root.join("helper.sock")),
            ),
        ]);
        assert!(matches!(unnamed, Err(StartError::InvalidDescriptors)));

        let unknown = select_descriptors(vec![
            (
                Some("unexpected".into()),
                listener(&root.join("unknown.sock")),
            ),
            (
                Some(ACCOUNT_HELPER_FD_NAME.into()),
                listener(&root.join("helper-2.sock")),
            ),
        ]);
        assert!(matches!(unknown, Err(StartError::InvalidDescriptors)));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_duplicate_extra_or_wrong_socket_type() {
        let root = temp_root();
        fs::create_dir_all(&root).unwrap();
        let duplicate = select_descriptors(vec![
            (
                Some(APPLICATION_FD_NAME.into()),
                listener(&root.join("application-1.sock")),
            ),
            (
                Some(APPLICATION_FD_NAME.into()),
                listener(&root.join("application-2.sock")),
            ),
        ]);
        assert!(matches!(duplicate, Err(StartError::InvalidDescriptors)));

        let extra = select_descriptors(vec![
            (
                Some(APPLICATION_FD_NAME.into()),
                listener(&root.join("application-3.sock")),
            ),
            (
                Some(ACCOUNT_HELPER_FD_NAME.into()),
                listener(&root.join("helper-3.sock")),
            ),
            (Some("extra".into()), listener(&root.join("extra.sock"))),
        ]);
        assert!(matches!(extra, Err(StartError::InvalidDescriptors)));

        let wrong_type = select_descriptors(vec![
            (
                Some(APPLICATION_FD_NAME.into()),
                typed_listener(&root.join("application-stream.sock"), SocketType::STREAM),
            ),
            (
                Some(ACCOUNT_HELPER_FD_NAME.into()),
                listener(&root.join("helper-4.sock")),
            ),
        ]);
        assert!(matches!(wrong_type, Err(StartError::InvalidDescriptors)));
        let _ = fs::remove_dir_all(root);
    }
}
