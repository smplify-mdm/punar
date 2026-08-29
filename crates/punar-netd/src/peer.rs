//! Kernel-attested identity for the netd Unix socket.

use std::io;
use std::os::unix::net::UnixStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<i32>,
}

impl Peer {
    pub const fn root() -> Self {
        Self {
            uid: 0,
            gid: 0,
            pid: None,
        }
    }

    pub const fn user(uid: u32) -> Self {
        Self {
            uid,
            gid: uid,
            pid: None,
        }
    }

    pub const fn is_root(self) -> bool {
        self.uid == 0
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PeerSource {
    SoPeercred,
    Fixed(Peer),
}

impl PeerSource {
    pub fn peer_of(self, stream: &UnixStream) -> io::Result<Peer> {
        match self {
            Self::SoPeercred => peercred(stream),
            Self::Fixed(peer) => Ok(peer),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peercred(stream: &UnixStream) -> io::Result<Peer> {
    let credentials = rustix::net::sockopt::socket_peercred(stream)?;
    Ok(Peer {
        uid: credentials.uid.as_raw(),
        gid: credentials.gid.as_raw(),
        pid: Some(credentials.pid.as_raw_nonzero().get()),
    })
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn peercred(_stream: &UnixStream) -> io::Result<Peer> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SO_PEERCRED is available only on Linux; tests must use a fixed peer",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_and_user_are_distinct() {
        assert!(Peer::root().is_root());
        assert!(!Peer::user(1000).is_root());
    }
}
