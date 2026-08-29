//! Cgroup ownership for live Internet sockets from Linux `sock_diag`.
//!
//! The kernel emits `INET_DIAG_CGROUP_ID` with every TCP diagnostic row when
//! cgroup socket data is enabled. Joining that id to the inode of a known
//! cgroup-v2 directory attributes a socket without reading another user's
//! `/proc/<pid>/fd`, holding `CAP_SYS_PTRACE`, or tracing the process.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::time::Duration;

use rustix::net::sockopt::{Timeout, set_socket_timeout};
use rustix::net::{
    AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, bind, netlink, recv, sendto,
    socket_with,
};
use thiserror::Error;

const NLMSG_HEADER_LEN: usize = 16;
const INET_DIAG_MSG_LEN: usize = 72;
const INET_DIAG_REQ_V2_LEN: usize = 56;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLM_F_DUMP: u16 = 0x300;
const INET_DIAG_CGROUP_ID: u16 = 21;
const NLA_TYPE_MASK: u16 = 0x3fff;
const IPPROTO_TCP: u8 = 6;
const RESPONSE_CAPACITY: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum DiagError {
    #[error("sock_diag I/O failed: {0}")]
    Io(#[from] rustix::io::Errno),
    #[error("sock_diag sent a short request ({sent} of {expected} bytes)")]
    ShortSend { sent: usize, expected: usize },
    #[error("sock_diag response exceeded the bounded receive buffer")]
    Truncated,
    #[error("sock_diag response is malformed: {0}")]
    Malformed(&'static str),
    #[error("sock_diag dump was interrupted by a kernel table change")]
    Interrupted,
    #[error("sock_diag kernel error {0}")]
    Kernel(i32),
}

/// Return TCP socket inode -> kernel cgroup-v2 id for IPv4 and IPv6.
pub fn tcp_cgroup_ids() -> Result<BTreeMap<u64, u64>, DiagError> {
    let socket = socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        Some(netlink::SOCK_DIAG),
    )?;
    bind(&socket, &netlink::SocketAddrNetlink::new(0, 0))?;
    set_socket_timeout(&socket, Timeout::Recv, Some(Duration::from_secs(2)))?;

    let kernel = netlink::SocketAddrNetlink::new(0, 0);
    let mut ids = BTreeMap::new();
    dump_family(&socket, &kernel, 2, 1, &mut ids)?; // AF_INET
    dump_family(&socket, &kernel, 10, 2, &mut ids)?; // AF_INET6
    Ok(ids)
}

fn dump_family(
    socket: &impl std::os::fd::AsFd,
    kernel: &netlink::SocketAddrNetlink,
    family: u8,
    sequence: u32,
    ids: &mut BTreeMap<u64, u64>,
) -> Result<(), DiagError> {
    let request = request(family, sequence);
    let sent = sendto(socket, &request, SendFlags::empty(), kernel)?;
    if sent != request.len() {
        return Err(DiagError::ShortSend {
            sent,
            expected: request.len(),
        });
    }

    let mut storage = [0_u8; RESPONSE_CAPACITY];
    loop {
        let (initialized, reported) = match recv(socket, &mut storage, RecvFlags::TRUNC) {
            Ok(result) => result,
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        };
        if reported > initialized {
            return Err(DiagError::Truncated);
        }
        let packet = &storage[..initialized];
        if parse_packet(packet, sequence, ids)? {
            return Ok(());
        }
    }
}

fn request(family: u8, sequence: u32) -> [u8; NLMSG_HEADER_LEN + INET_DIAG_REQ_V2_LEN] {
    let mut request = [0_u8; NLMSG_HEADER_LEN + INET_DIAG_REQ_V2_LEN];
    put_u32(
        &mut request,
        0,
        (NLMSG_HEADER_LEN + INET_DIAG_REQ_V2_LEN) as u32,
    );
    put_u16(&mut request, 4, SOCK_DIAG_BY_FAMILY);
    put_u16(&mut request, 6, NLM_F_REQUEST | NLM_F_DUMP);
    put_u32(&mut request, 8, sequence);
    // nlmsg_pid remains zero. inet_diag_req_v2 starts at byte 16.
    request[16] = family;
    request[17] = IPPROTO_TCP;
    // idiag_ext is zero. INET_DIAG_CGROUP_ID is a response-only attribute.
    put_u32(&mut request, 20, u32::MAX); // every TCP state
    request
}

/// Parse one netlink datagram. `true` means this dump reached NLMSG_DONE.
fn parse_packet(
    packet: &[u8],
    sequence: u32,
    ids: &mut BTreeMap<u64, u64>,
) -> Result<bool, DiagError> {
    let mut offset = 0usize;
    while offset < packet.len() {
        if packet.len() - offset < NLMSG_HEADER_LEN {
            return Err(DiagError::Malformed("short netlink header"));
        }
        let length = read_u32(packet, offset)? as usize;
        if length < NLMSG_HEADER_LEN || length > packet.len() - offset {
            return Err(DiagError::Malformed("invalid netlink message length"));
        }
        let message_type = read_u16(packet, offset + 4)?;
        let flags = read_u16(packet, offset + 6)?;
        let message_sequence = read_u32(packet, offset + 8)?;
        if message_sequence == sequence {
            if flags & NLM_F_DUMP_INTR != 0 {
                return Err(DiagError::Interrupted);
            }
            let body = &packet[offset + NLMSG_HEADER_LEN..offset + length];
            match message_type {
                NLMSG_DONE => return Ok(true),
                NLMSG_ERROR => {
                    if body.len() < 4 {
                        return Err(DiagError::Malformed("short NLMSG_ERROR"));
                    }
                    let error = i32::from_ne_bytes(body[..4].try_into().expect("length checked"));
                    if error != 0 {
                        return Err(DiagError::Kernel(error));
                    }
                }
                SOCK_DIAG_BY_FAMILY => parse_diag_message(body, ids)?,
                _ => {}
            }
        }
        offset = offset
            .checked_add(align4(length))
            .ok_or(DiagError::Malformed("netlink offset overflow"))?;
    }
    Ok(false)
}

fn parse_diag_message(body: &[u8], ids: &mut BTreeMap<u64, u64>) -> Result<(), DiagError> {
    if body.len() < INET_DIAG_MSG_LEN {
        return Err(DiagError::Malformed("short inet_diag_msg"));
    }
    let inode = read_u32(body, 68)? as u64;
    if inode == 0 {
        return Ok(());
    }
    let mut offset = INET_DIAG_MSG_LEN;
    while offset < body.len() {
        if body.len() - offset < 4 {
            return Err(DiagError::Malformed("short netlink attribute header"));
        }
        let length = read_u16(body, offset)? as usize;
        let kind = read_u16(body, offset + 2)? & NLA_TYPE_MASK;
        if length < 4 || length > body.len() - offset {
            return Err(DiagError::Malformed("invalid netlink attribute length"));
        }
        if kind == INET_DIAG_CGROUP_ID {
            if length < 12 {
                return Err(DiagError::Malformed("short INET_DIAG_CGROUP_ID"));
            }
            let id = read_u64(body, offset + 4)?;
            if id != 0 {
                ids.insert(inode, id);
            }
        }
        offset = offset
            .checked_add(align4(length))
            .ok_or(DiagError::Malformed("attribute offset overflow"))?;
    }
    Ok(())
}

const fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DiagError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(DiagError::Malformed("u16 outside message"))?;
    Ok(u16::from_ne_bytes(
        value.try_into().expect("slice length is fixed"),
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, DiagError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(DiagError::Malformed("u32 outside message"))?;
    Ok(u32::from_ne_bytes(
        value.try_into().expect("slice length is fixed"),
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, DiagError> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or(DiagError::Malformed("u64 outside message"))?;
    Ok(u64::from_ne_bytes(
        value.try_into().expect("slice length is fixed"),
    ))
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    use super::*;

    #[test]
    fn response_parser_reads_only_the_cgroup_attribute() {
        let mut packet = vec![0_u8; NLMSG_HEADER_LEN + INET_DIAG_MSG_LEN + 12];
        let packet_len = packet.len();
        put_u32(&mut packet, 0, packet_len as u32);
        put_u16(&mut packet, 4, SOCK_DIAG_BY_FAMILY);
        put_u32(&mut packet, 8, 7);
        put_u32(&mut packet, NLMSG_HEADER_LEN + 68, 4242);
        let attribute = NLMSG_HEADER_LEN + INET_DIAG_MSG_LEN;
        put_u16(&mut packet, attribute, 12);
        put_u16(&mut packet, attribute + 2, INET_DIAG_CGROUP_ID);
        packet[attribute + 4..attribute + 12].copy_from_slice(&31337_u64.to_ne_bytes());

        let mut ids = BTreeMap::new();
        assert!(!parse_packet(&packet, 7, &mut ids).unwrap());
        assert_eq!(ids, BTreeMap::from([(4242, 31337)]));
    }

    #[test]
    fn response_parser_fails_closed_on_a_short_cgroup_attribute() {
        let mut packet = vec![0_u8; NLMSG_HEADER_LEN + INET_DIAG_MSG_LEN + 8];
        let packet_len = packet.len();
        put_u32(&mut packet, 0, packet_len as u32);
        put_u16(&mut packet, 4, SOCK_DIAG_BY_FAMILY);
        put_u32(&mut packet, 8, 9);
        put_u32(&mut packet, NLMSG_HEADER_LEN + 68, 4242);
        let attribute = NLMSG_HEADER_LEN + INET_DIAG_MSG_LEN;
        put_u16(&mut packet, attribute, 8);
        put_u16(&mut packet, attribute + 2, INET_DIAG_CGROUP_ID);

        let mut ids = BTreeMap::new();
        assert!(matches!(
            parse_packet(&packet, 9, &mut ids),
            Err(DiagError::Malformed("short INET_DIAG_CGROUP_ID"))
        ));
    }

    #[test]
    fn live_dump_joins_its_socket_to_the_cgroup_filesystem_inode() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_server, _) = listener.accept().unwrap();
        let target = fs::read_link(format!("/proc/self/fd/{}", client.as_raw_fd())).unwrap();
        let inode = target
            .to_string_lossy()
            .strip_prefix("socket:[")
            .and_then(|value| value.strip_suffix(']'))
            .and_then(|value| value.parse::<u64>().ok())
            .expect("the connected stream has a socket inode");
        let cgroup_file = fs::read_to_string("/proc/self/cgroup").unwrap();
        let cgroup_path = cgroup_file
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .expect("unified cgroup path");
        let cgroup_inode = fs::metadata(
            std::path::Path::new("/sys/fs/cgroup").join(cgroup_path.trim_start_matches('/')),
        )
        .unwrap()
        .ino();

        let ids = tcp_cgroup_ids().unwrap();
        assert_eq!(ids.get(&inode), Some(&cgroup_inode));
    }
}
