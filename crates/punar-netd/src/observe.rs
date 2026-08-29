//! On-demand TCP observation from kernel-owned procfs files.
//!
//! This is intentionally not a tracer: no eBPF, packet capture, DNS log,
//! SNI inspection, conntrack walk, or command-output scraping. A pass reads
//! `/proc/net/tcp{,6}`, resolves candidate socket inodes through
//! `/proc/<pid>/fd` when ordinary permissions allow it. On the real Linux
//! runtime, `NETLINK_SOCK_DIAG` supplies the kernel cgroup id independently;
//! that is the authoritative managed-session join when another user's fd
//! links are intentionally hidden. Ports and local addresses are parsing
//! details and are absent from the serializable result by construction.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ObserveError {
    #[error("could not read {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("invalid {family} socket row {line}: {reason}")]
    InvalidRow {
        family: &'static str,
        line: usize,
        reason: String,
    },
    #[error("kernel socket attribution failed: {0}")]
    KernelAttribution(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpState {
    Established,
    SynSent,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    Closing,
}

impl TcpState {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "01" => Some(Self::Established),
            "02" => Some(Self::SynSent),
            "04" => Some(Self::FinWait1),
            "05" => Some(Self::FinWait2),
            "08" => Some(Self::CloseWait),
            "09" => Some(Self::LastAck),
            "0B" => Some(Self::Closing),
            // 03 SYN_RECV, 06 TIME_WAIT, 07 CLOSE, 0A LISTEN and unknown
            // future states are deliberately not rendered.
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveSocket {
    destination: IpAddr,
    state: TcpState,
    uid: u32,
    inode: u64,
    cgroup_id: Option<u64>,
    // Parsed to validate the kernel row and identify a real peer, but never
    // copied into any serializable type (M12 privacy contract).
    _local_port: u16,
    _remote_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Connection {
    pub destination: IpAddr,
    pub state: TcpState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessConnections {
    pub name: String,
    pub pid: Option<u32>,
    pub uid: u32,
    pub cgroup_path: Option<String>,
    pub cgroup_id: Option<u64>,
    pub connections: Vec<Connection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub scanned_at: String,
    pub transport: &'static str,
    pub limitations: Vec<&'static str>,
    pub processes: Vec<ProcessConnections>,
}

#[derive(Debug)]
struct Owner {
    pid: u32,
    name: String,
    cgroup_path: Option<String>,
}

pub fn observe(proc_root: &Path) -> Result<Observation, ObserveError> {
    observe_inner(
        proc_root,
        punar_common::time::utc_now_rfc3339(),
        proc_root == Path::new("/proc"),
    )
}

pub fn observe_at(proc_root: &Path, scanned_at: String) -> Result<Observation, ObserveError> {
    observe_inner(proc_root, scanned_at, false)
}

fn observe_inner(
    proc_root: &Path,
    scanned_at: String,
    use_kernel_cgroups: bool,
) -> Result<Observation, ObserveError> {
    let mut sockets = Vec::new();
    sockets.extend(parse_table(
        &read_required(&proc_root.join("net/tcp"))?,
        AddressFamily::V4,
    )?);
    sockets.extend(parse_table(
        &read_required(&proc_root.join("net/tcp6"))?,
        AddressFamily::V6,
    )?);
    sockets.sort_by_key(|socket| (socket.uid, socket.inode));

    #[cfg(target_os = "linux")]
    if use_kernel_cgroups {
        let cgroups = crate::socket_diag::tcp_cgroup_ids()
            .map_err(|error| ObserveError::KernelAttribution(error.to_string()))?;
        for socket in &mut sockets {
            socket.cgroup_id = cgroups.get(&socket.inode).copied();
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = use_kernel_cgroups;

    let candidates: BTreeSet<u64> = sockets.iter().map(|socket| socket.inode).collect();
    let owners = resolve_owners(proc_root, &candidates);
    let mut grouped: BTreeMap<(Option<u32>, u32, Option<u64>), ProcessConnections> =
        BTreeMap::new();
    for socket in sockets {
        let owner = owners.get(&socket.inode);
        let key = (owner.map(|owner| owner.pid), socket.uid, socket.cgroup_id);
        let row = grouped.entry(key).or_insert_with(|| ProcessConnections {
            name: owner
                .map(|owner| owner.name.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            pid: owner.map(|owner| owner.pid),
            uid: socket.uid,
            cgroup_path: owner.and_then(|owner| owner.cgroup_path.clone()),
            cgroup_id: socket.cgroup_id,
            connections: Vec::new(),
        });
        row.connections.push(Connection {
            destination: socket.destination,
            state: socket.state,
        });
    }
    for process in grouped.values_mut() {
        process
            .connections
            .sort_by_key(|connection| (connection.destination, connection.state as u8));
        process.connections.dedup();
    }

    Ok(Observation {
        scanned_at,
        transport: "tcp",
        limitations: vec![
            "udp_quic_not_observed",
            "hostnames_only_from_local_zone_data",
            "payloads_never_inspected",
        ],
        processes: grouped.into_values().collect(),
    })
}

fn read_required(path: &Path) -> Result<String, ObserveError> {
    fs::read_to_string(path).map_err(|source| ObserveError::Read {
        path: path.to_path_buf(),
        source,
    })
}

#[derive(Debug, Clone, Copy)]
enum AddressFamily {
    V4,
    V6,
}

impl AddressFamily {
    const fn name(self) -> &'static str {
        match self {
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        }
    }
}

fn parse_table(input: &str, family: AddressFamily) -> Result<Vec<LiveSocket>, ObserveError> {
    let mut sockets = Vec::new();
    for (index, line) in input.lines().enumerate().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 10 {
            return Err(invalid_row(family, index + 1, "fewer than ten fields"));
        }
        let Some(state) = TcpState::parse(fields[3]) else {
            continue;
        };
        let (_local, local_port) = parse_endpoint(fields[1], family)
            .map_err(|reason| invalid_row(family, index + 1, reason))?;
        let (destination, remote_port) = parse_endpoint(fields[2], family)
            .map_err(|reason| invalid_row(family, index + 1, reason))?;
        if remote_port == 0 || destination.is_unspecified() {
            continue;
        }
        let uid = fields[7]
            .parse::<u32>()
            .map_err(|_| invalid_row(family, index + 1, "invalid uid"))?;
        let inode = fields[9]
            .parse::<u64>()
            .map_err(|_| invalid_row(family, index + 1, "invalid inode"))?;
        if inode == 0 {
            continue;
        }
        sockets.push(LiveSocket {
            destination,
            state,
            uid,
            inode,
            cgroup_id: None,
            _local_port: local_port,
            _remote_port: remote_port,
        });
    }
    Ok(sockets)
}

fn invalid_row(family: AddressFamily, line: usize, reason: impl Into<String>) -> ObserveError {
    ObserveError::InvalidRow {
        family: family.name(),
        line,
        reason: reason.into(),
    }
}

fn parse_endpoint(value: &str, family: AddressFamily) -> Result<(IpAddr, u16), String> {
    let (address, port) = value
        .split_once(':')
        .ok_or_else(|| "endpoint has no port separator".to_string())?;
    let port = u16::from_str_radix(port, 16).map_err(|_| "invalid port".to_string())?;
    let address = match family {
        AddressFamily::V4 => {
            if address.len() != 8 || address.bytes().any(|b| !b.is_ascii_hexdigit()) {
                return Err("invalid IPv4 address".to_string());
            }
            let raw =
                u32::from_str_radix(address, 16).map_err(|_| "invalid IPv4 address".to_string())?;
            IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes()))
        }
        AddressFamily::V6 => {
            if address.len() != 32 || address.bytes().any(|b| !b.is_ascii_hexdigit()) {
                return Err("invalid IPv6 address".to_string());
            }
            let mut bytes = [0_u8; 16];
            for word in 0..4 {
                let start = word * 8;
                let raw = u32::from_str_radix(&address[start..start + 8], 16)
                    .map_err(|_| "invalid IPv6 address".to_string())?;
                bytes[start / 2..start / 2 + 4].copy_from_slice(&raw.to_le_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
    };
    Ok((address, port))
}

fn resolve_owners(proc_root: &Path, candidates: &BTreeSet<u64>) -> BTreeMap<u64, Owner> {
    let mut unresolved = candidates.clone();
    let mut owners = BTreeMap::new();
    let Ok(entries) = fs::read_dir(proc_root) else {
        return owners;
    };
    let mut pids: Vec<u32> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
        .collect();
    pids.sort_unstable();
    for pid in pids {
        if unresolved.is_empty() {
            break;
        }
        let pid_dir = proc_root.join(pid.to_string());
        let Ok(fds) = fs::read_dir(pid_dir.join("fd")) else {
            continue;
        };
        let mut matched = Vec::new();
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let Some(inode) = socket_inode(&target) else {
                continue;
            };
            if unresolved.contains(&inode) {
                matched.push(inode);
            }
        }
        if matched.is_empty() {
            continue;
        }
        let name = safe_process_name(
            &fs::read_to_string(pid_dir.join("comm")).unwrap_or_else(|_| "unknown".into()),
        );
        let cgroup_path = read_cgroup_path(&pid_dir.join("cgroup"));
        for inode in matched {
            unresolved.remove(&inode);
            owners.insert(
                inode,
                Owner {
                    pid,
                    name: name.clone(),
                    cgroup_path: cgroup_path.clone(),
                },
            );
        }
    }
    owners
}

fn socket_inode(target: &Path) -> Option<u64> {
    let text = target.to_string_lossy();
    text.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn safe_process_name(value: &str) -> String {
    let cleaned: String = value
        .trim()
        .chars()
        .filter(|character| !character.is_control())
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "unknown".to_string()
    } else {
        cleaned
    }
}

fn read_cgroup_path(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("0::"))
        .filter(|value| crate::model::validate_cgroup_path(value).is_ok())
        .map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn temp_root() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "punar-netd-observe-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(path.join("net")).unwrap();
        path
    }

    const HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";

    #[test]
    fn ipv4_and_ipv6_kernel_endianness_are_decoded() {
        let v4 = parse_endpoint("0100007F:24CA", AddressFamily::V4).unwrap();
        assert_eq!(v4, ("127.0.0.1".parse().unwrap(), 9418));
        let v6 =
            parse_endpoint("00000000000000000000000001000000:01BB", AddressFamily::V6).unwrap();
        assert_eq!(v6, ("::1".parse().unwrap(), 443));
    }

    #[test]
    fn pass_maps_live_socket_to_pid_without_serializing_ports_or_local_address() {
        let root = temp_root();
        fs::write(
            root.join("net/tcp"),
            format!(
                "{HEADER}\n   0: 0100007F:9C40 0900007F:24CA 01 00000000:00000000 00:00000000 00000000 1000 0 4242\n   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 5555\n"
            ),
        )
        .unwrap();
        fs::write(root.join("net/tcp6"), format!("{HEADER}\n")).unwrap();
        let pid = root.join("123/fd");
        fs::create_dir_all(&pid).unwrap();
        symlink("socket:[4242]", pid.join("7")).unwrap();
        fs::write(root.join("123/comm"), "punar-mock-agent\n").unwrap();
        fs::write(
            root.join("123/cgroup"),
            "0::/user.slice/punar-agent-4f21.scope\n",
        )
        .unwrap();

        let observation = observe_at(&root, "2026-08-29T00:00:00Z".into()).unwrap();
        assert_eq!(observation.processes.len(), 1);
        assert_eq!(observation.processes[0].pid, Some(123));
        assert_eq!(
            observation.processes[0].connections[0]
                .destination
                .to_string(),
            "127.0.0.9"
        );
        let wire = serde_json::to_string(&observation.processes[0].connections).unwrap();
        for forbidden in [
            "9418",
            "40000",
            "local_address",
            "local_port",
            "remote_port",
        ] {
            assert!(!wire.contains(forbidden), "{forbidden} leaked in {wire}");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unattributed_socket_is_visible_instead_of_silently_dropped() {
        let root = temp_root();
        fs::write(
            root.join("net/tcp"),
            format!(
                "{HEADER}\n   0: 0100007F:9C40 0700007F:24CA 02 00000000:00000000 00:00000000 00000000 1000 0 7777\n"
            ),
        )
        .unwrap();
        fs::write(root.join("net/tcp6"), format!("{HEADER}\n")).unwrap();
        let observation = observe_at(&root, "2026-08-29T00:00:00Z".into()).unwrap();
        assert_eq!(observation.processes[0].name, "unknown");
        assert_eq!(observation.processes[0].pid, None);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_candidate_row_fails_the_whole_pass() {
        let root = temp_root();
        fs::write(root.join("net/tcp"), format!("{HEADER}\n  bad row\n")).unwrap();
        fs::write(root.join("net/tcp6"), format!("{HEADER}\n")).unwrap();
        assert!(matches!(
            observe_at(&root, "2026-08-29T00:00:00Z".into()),
            Err(ObserveError::InvalidRow { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }
}
