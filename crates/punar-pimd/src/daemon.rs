//! Non-resident runtime for one profile-bound PIM service.
//!
//! systemd owns two root/service-only `SOCK_SEQPACKET` listeners: application
//! grants and account-helper claims. This loop polls both plus an unnamed
//! worker-completion socket, admits at most 32 concurrent connections, and
//! exits after a bounded idle period. It has no timer thread and performs no
//! network work on the accept path.

use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::net::{
    AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, accept_with, recv, send,
    socketpair,
};
use thiserror::Error;

use crate::PimService;

const MAX_CONNECTIONS: usize = 32;

#[derive(Debug, Error)]
pub enum PimDaemonError {
    #[error("PIM runtime kernel operation failed: {0}")]
    Kernel(#[from] rustix::io::Errno),
    #[error("PIM runtime worker could not start")]
    WorkerStart,
}

#[derive(Debug, Clone, Copy)]
enum ControlKind {
    Application,
    AccountHelper,
}

/// Serve a single already-opened profile until it has no active work for the
/// requested idle interval. Both listener descriptors remain owned by the
/// caller's process and are never exposed to an application.
pub fn serve_profile(
    service: Arc<PimService>,
    application_listener: OwnedFd,
    helper_listener: OwnedFd,
    idle_timeout: Duration,
) -> Result<(), PimDaemonError> {
    serve_profile_from_broker_uid(
        service,
        application_listener,
        helper_listener,
        idle_timeout,
        0,
    )
}

fn serve_profile_from_broker_uid(
    service: Arc<PimService>,
    application_listener: OwnedFd,
    helper_listener: OwnedFd,
    idle_timeout: Duration,
    broker_uid: u32,
) -> Result<(), PimDaemonError> {
    if idle_timeout.is_zero() {
        return Err(PimDaemonError::Kernel(rustix::io::Errno::INVAL));
    }
    let (completion_read, completion_write) = socketpair(
        AddressFamily::UNIX,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?;
    let mut active = 0_usize;
    let mut idle_deadline = Instant::now() + idle_timeout;

    loop {
        let ready = if active >= MAX_CONNECTIONS {
            poll_completion_only(&completion_read)?
        } else {
            poll_controls(
                &application_listener,
                &helper_listener,
                &completion_read,
                active,
                idle_deadline,
            )?
        };

        if ready.completion {
            let mut byte = [0_u8; 1];
            if recv(&completion_read, &mut byte, RecvFlags::empty()).is_ok() {
                active = active.saturating_sub(1);
                idle_deadline = Instant::now() + idle_timeout;
            }
        }
        if ready.application {
            spawn_connection(
                Arc::clone(&service),
                &application_listener,
                &completion_write,
                ControlKind::Application,
                broker_uid,
            )?;
            active += 1;
            idle_deadline = Instant::now() + idle_timeout;
        }
        if ready.helper && active < MAX_CONNECTIONS {
            spawn_connection(
                Arc::clone(&service),
                &helper_listener,
                &completion_write,
                ControlKind::AccountHelper,
                broker_uid,
            )?;
            active += 1;
            idle_deadline = Instant::now() + idle_timeout;
        }
        if !ready.any() && active == 0 && Instant::now() >= idle_deadline {
            return Ok(());
        }
    }
}

#[derive(Default)]
struct Ready {
    application: bool,
    helper: bool,
    completion: bool,
}

impl Ready {
    fn any(&self) -> bool {
        self.application || self.helper || self.completion
    }
}

fn poll_controls(
    application_listener: &OwnedFd,
    helper_listener: &OwnedFd,
    completion_read: &OwnedFd,
    active: usize,
    idle_deadline: Instant,
) -> Result<Ready, rustix::io::Errno> {
    let mut fds = [
        PollFd::new(application_listener, PollFlags::IN),
        PollFd::new(helper_listener, PollFlags::IN),
        PollFd::new(completion_read, PollFlags::IN),
    ];
    let timeout = if active == 0 {
        Some(duration_to_timespec(
            idle_deadline.saturating_duration_since(Instant::now()),
        ))
    } else {
        None
    };
    poll(&mut fds, timeout.as_ref())?;
    refuse_broken_poll(&fds)?;
    Ok(Ready {
        application: fds[0].revents().contains(PollFlags::IN),
        helper: fds[1].revents().contains(PollFlags::IN),
        completion: fds[2].revents().contains(PollFlags::IN),
    })
}

fn poll_completion_only(completion_read: &OwnedFd) -> Result<Ready, rustix::io::Errno> {
    let mut fds = [PollFd::new(completion_read, PollFlags::IN)];
    poll(&mut fds, None)?;
    refuse_broken_poll(&fds)?;
    Ok(Ready {
        completion: fds[0].revents().contains(PollFlags::IN),
        ..Ready::default()
    })
}

fn refuse_broken_poll(fds: &[PollFd<'_>]) -> Result<(), rustix::io::Errno> {
    let broken = PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL;
    if fds.iter().any(|fd| fd.revents().intersects(broken)) {
        return Err(rustix::io::Errno::IO);
    }
    Ok(())
}

fn spawn_connection(
    service: Arc<PimService>,
    listener: &OwnedFd,
    completion: &OwnedFd,
    kind: ControlKind,
    broker_uid: u32,
) -> Result<(), PimDaemonError> {
    let connection = accept_with(listener, SocketFlags::CLOEXEC)?;
    let completion = rustix::io::dup(completion)?;
    thread::Builder::new()
        .name(
            match kind {
                ControlKind::Application => "punar-pim-application",
                ControlKind::AccountHelper => "punar-pim-account-helper",
            }
            .to_string(),
        )
        .spawn(move || {
            match kind {
                ControlKind::Application => {
                    let _ = service.serve_control_from_uid(connection, broker_uid);
                }
                ControlKind::AccountHelper => {
                    let _ = service.serve_account_helper_control_from_uid(connection, broker_uid);
                }
            }
            let _ = send(&completion, &[1], SendFlags::empty());
        })
        .map_err(|_| PimDaemonError::WorkerStart)?;
    Ok(())
}

fn duration_to_timespec(duration: Duration) -> Timespec {
    Timespec {
        tv_sec: duration.as_secs().try_into().unwrap_or(i64::MAX),
        tv_nsec: duration.subsec_nanos().into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AccountHelperClaim, ClientGrant, PimClient, client_channel_pair,
        receive_account_helper_channel, send_account_helper_claim, send_client_channel,
    };
    use rustix::net::{SocketAddrUnix, bind, connect, listen, socket_with};
    use serde_json::Value;
    use std::fs;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};

    fn temp_root() -> PathBuf {
        let mut suffix = [0_u8; 12];
        getrandom::fill(&mut suffix).unwrap();
        let suffix = suffix
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        std::env::temp_dir().join(format!("punar-pimd-daemon-test-{suffix}"))
    }

    fn listener(path: &Path) -> OwnedFd {
        let fd = socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        bind(&fd, &SocketAddrUnix::new(path).unwrap()).unwrap();
        listen(&fd, 8).unwrap();
        fd
    }

    fn connect_control(path: &Path) -> OwnedFd {
        let fd = socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        connect(&fd, &SocketAddrUnix::new(path).unwrap()).unwrap();
        fd
    }

    #[test]
    fn runtime_serves_both_control_planes_then_reaches_zero_idle_residency() {
        let root = temp_root();
        fs::create_dir_all(&root).unwrap();
        let application_path = root.join("application.sock");
        let helper_path = root.join("helper.sock");
        let application_listener = listener(&application_path);
        let helper_listener = listener(&helper_path);
        let profile_uid = rustix::process::getuid().as_raw();
        let service =
            Arc::new(PimService::open(&root.join("state"), "profile_A1", profile_uid).unwrap());
        let runtime = {
            let service = Arc::clone(&service);
            thread::spawn(move || {
                serve_profile_from_broker_uid(
                    service,
                    application_listener,
                    helper_listener,
                    Duration::from_millis(50),
                    rustix::process::getuid().as_raw(),
                )
                .unwrap();
            })
        };

        let application_control = connect_control(&application_path);
        let (application, service_endpoint) = client_channel_pair().unwrap();
        send_client_channel(
            &application_control,
            service_endpoint,
            &ClientGrant::new("grant_A1", profile_uid, PimClient::Settings),
        )
        .unwrap();
        let mut application = UnixStream::from(application);
        application
            .write_all(
                b"{\"v\":1,\"id\":\"status-1\",\"method\":\"service.status\",\"params\":{}}\n\
                  {\"v\":1,\"id\":\"setup-1\",\"method\":\"accounts.begin_connect\",\"params\":{\"provider_type\":\"open_protocols\"}}\n",
            )
            .unwrap();
        application.shutdown(std::net::Shutdown::Write).unwrap();
        let mut reader = BufReader::new(application);
        let mut status_response = String::new();
        reader.read_line(&mut status_response).unwrap();
        let status_response: Value = serde_json::from_str(&status_response).unwrap();
        assert_eq!(status_response["result"]["accounts"], 0);
        let mut setup_response = String::new();
        reader.read_line(&mut setup_response).unwrap();
        let setup_response: Value = serde_json::from_str(&setup_response).unwrap();
        let setup_id = setup_response["result"]["setup_id"]
            .as_str()
            .unwrap()
            .to_string();

        let helper_control = connect_control(&helper_path);
        send_account_helper_claim(
            &helper_control,
            &AccountHelperClaim::new(&setup_id, profile_uid),
        )
        .unwrap();
        let helper =
            receive_account_helper_channel(&helper_control, &setup_id, profile_uid).unwrap();
        drop(helper);
        runtime.join().unwrap();
        let _ = fs::remove_dir_all(root);
    }
}
