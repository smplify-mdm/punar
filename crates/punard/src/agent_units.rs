//! The management chain's own systemd units, as systemd has them loaded
//! (docs/development/smplify-enrollment.md section 3.4).
//!
//! WHY. punard's liveness call proves that something on the agent's socket
//! answers as this device's agent. It cannot prove what that something is:
//! a runtime drop-in can replace the agent's `ExecStart=`, lift its
//! `RefuseManualStop=`, move its state directory or preload a library into
//! it, and a drop-in on punard's own unit can point punard at another socket
//! altogether. None of that stops a single call, so without this check none
//! of it would ever be noticed. On every pass while enrolled punard asks
//! systemd for the units it depends on — the agent's socket and service,
//! punard itself, and the reconcile timer and service that drive every pass
//! — and holds each to what the image ships: loaded (not masked), its
//! fragment in the image's unit directory, and no drop-in outside it. The
//! agent's running process must be the image's agent binary, and its socket
//! must listen where punard dials. Anything else is management interrupted
//! (`unit_modified`), audited like every other way the agent stops serving.
//!
//! The image's unit directory is the boundary: administrator and runtime
//! configuration (`/etc`, `/run`, `systemctl edit`, `set-property`, a mask)
//! is checked, while a change to `/usr` itself is a change to the operating
//! system image, which no check running from that image can vouch for.
//!
//! One `systemctl show` per pass while enrolled, with a bounded wait and
//! output; nothing on a device that never enrolled.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::enroll::DEFAULT_CONTROL_PLANE_SOCKET;
use crate::util::run_bounded;

/// The agent's socket unit.
pub const AGENT_SOCKET_UNIT: &str = "punar-smplifyd.socket";
/// The agent's service unit.
pub const AGENT_SERVICE_UNIT: &str = "punar-smplifyd.service";

/// Every unit management depends on: the agent's two, punard's own (its
/// environment chooses the socket punard dials), and the timer and service
/// that make every reconcile pass.
pub const MANAGEMENT_UNITS: [&str; 5] = [
    AGENT_SOCKET_UNIT,
    AGENT_SERVICE_UNIT,
    "punard.service",
    "punard-reconcile.timer",
    "punard-reconcile.service",
];

/// Where the image ships its units, and its drop-ins for them.
pub const VENDOR_UNIT_DIR: &str = "/usr/lib/systemd/system/";

/// The image's agent binary.
pub const AGENT_EXECUTABLE: &str = "/usr/bin/punar-smplifyd";

/// How long `systemctl show` may take, and how much it may print.
const SHOW_TIMEOUT: Duration = Duration::from_secs(5);
const SHOW_MAX_BYTES: usize = 256 * 1024;

/// How punard asks systemd about the management units, and whether every
/// connection to the agent must reach systemd's own listener
/// ([`crate::enroll::listener_is_systemds`]). Only on a device whose punard
/// dials the built-in agent's own socket (`main.rs`); the development
/// image's mock control plane has none, and tests set what they exercise.
#[derive(Debug, Clone)]
pub struct AgentIntegrity {
    pub systemctl: PathBuf,
    pub proc_root: PathBuf,
    pub require_systemd_listener: bool,
}

impl Default for AgentIntegrity {
    fn default() -> Self {
        AgentIntegrity {
            systemctl: PathBuf::from("/usr/bin/systemctl"),
            proc_root: PathBuf::from("/proc"),
            require_systemd_listener: true,
        }
    }
}

/// What the check found that is not as the image ships it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitFinding {
    /// systemd could not be asked, or its answer could not be read.
    Unreadable(String),
    /// `unit` is not as the image ships it: `what` says how, for the
    /// journal (paths and systemd's own words, never a secret).
    Modified { unit: String, what: String },
}

impl std::fmt::Display for UnitFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnitFinding::Unreadable(why) => write!(f, "systemd could not be asked ({why})"),
            UnitFinding::Modified { unit, what } => write!(f, "{unit}: {what}"),
        }
    }
}

impl AgentIntegrity {
    /// Ask systemd, and judge its answer ([`judge`]).
    pub fn check(&self) -> Result<(), UnitFinding> {
        let mut args = vec![
            "show",
            "--property=Id,LoadState,FragmentPath,DropInPaths,Listen,MainPID",
        ];
        args.extend(MANAGEMENT_UNITS);
        let shown = run_bounded(&self.systemctl, &args, SHOW_TIMEOUT, SHOW_MAX_BYTES)
            .map_err(|e| UnitFinding::Unreadable(e.to_string()))?;
        if !shown.success {
            return Err(UnitFinding::Unreadable(
                shown.stderr.lines().next().unwrap_or("failed").to_string(),
            ));
        }
        judge(&shown.stdout, |pid| {
            std::fs::read_link(self.proc_root.join(pid.to_string()).join("exe")).ok()
        })
    }

    /// Start the agent's socket again after it failed or was stopped: the
    /// agent cannot be reached until it listens, and punard's `Wants=` on it
    /// acts only when punard itself starts. Without waiting; a masked socket
    /// stays stopped, and the episode says so.
    pub fn start_socket(&self) {
        match run_bounded(
            &self.systemctl,
            &["start", "--no-block", AGENT_SOCKET_UNIT],
            SHOW_TIMEOUT,
            SHOW_MAX_BYTES,
        ) {
            Ok(done) if done.success => {
                eprintln!("punard: asked systemd to start {AGENT_SOCKET_UNIT} again");
            }
            Ok(done) => eprintln!(
                "punard: {AGENT_SOCKET_UNIT} could not be started again: {}",
                done.stderr.lines().next().unwrap_or("failed")
            ),
            Err(e) => eprintln!("punard: {AGENT_SOCKET_UNIT} could not be started again: {e}"),
        }
    }
}

/// Hold `systemctl show`'s answer for [`MANAGEMENT_UNITS`] to what the image
/// ships. `exe_of` reads a process's executable.
pub fn judge(shown: &str, exe_of: impl Fn(u32) -> Option<PathBuf>) -> Result<(), UnitFinding> {
    let blocks = parse_show(shown);
    let modified = |unit: &str, what: String| UnitFinding::Modified {
        unit: unit.to_string(),
        what,
    };
    for unit in MANAGEMENT_UNITS {
        let Some(block) = blocks
            .iter()
            .find(|block| block.get("Id").map(String::as_str) == Some(unit))
        else {
            return Err(modified(unit, "not in systemd's answer".to_string()));
        };
        let property = |key: &str| block.get(key).map(String::as_str).unwrap_or("");
        if property("LoadState") != "loaded" {
            return Err(modified(
                unit,
                format!("LoadState={}", property("LoadState")),
            ));
        }
        let fragment = format!("{VENDOR_UNIT_DIR}{unit}");
        if property("FragmentPath") != fragment {
            return Err(modified(
                unit,
                format!("loaded from {}", property("FragmentPath")),
            ));
        }
        if let Some(drop_in) = property("DropInPaths")
            .split_whitespace()
            .find(|path| !path.starts_with(VENDOR_UNIT_DIR))
        {
            return Err(modified(unit, format!("drop-in {drop_in}")));
        }
    }
    let socket = blocks
        .iter()
        .find(|block| block.get("Id").map(String::as_str) == Some(AGENT_SOCKET_UNIT))
        .and_then(|block| block.get("Listen"))
        .map(String::as_str)
        .unwrap_or("");
    if socket != format!("{DEFAULT_CONTROL_PLANE_SOCKET} (Stream)") {
        return Err(modified(AGENT_SOCKET_UNIT, format!("Listen={socket}")));
    }
    let main_pid = blocks
        .iter()
        .find(|block| block.get("Id").map(String::as_str) == Some(AGENT_SERVICE_UNIT))
        .and_then(|block| block.get("MainPID"))
        .and_then(|pid| pid.parse::<u32>().ok())
        .unwrap_or(0);
    if main_pid != 0 {
        let exe = exe_of(main_pid);
        if exe.as_deref() != Some(Path::new(AGENT_EXECUTABLE)) {
            return Err(modified(
                AGENT_SERVICE_UNIT,
                format!(
                    "its process runs {}",
                    exe.map_or_else(
                        || "(unreadable)".to_string(),
                        |exe| exe.display().to_string()
                    )
                ),
            ));
        }
    }
    Ok(())
}

/// `systemctl show` for several units: one block of `Key=Value` lines per
/// unit, blank lines between.
fn parse_show(shown: &str) -> Vec<BTreeMap<String, String>> {
    let mut blocks = Vec::new();
    let mut block = BTreeMap::new();
    for line in shown.lines() {
        if line.trim().is_empty() {
            if !block.is_empty() {
                blocks.push(std::mem::take(&mut block));
            }
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            block.insert(key.to_string(), value.to_string());
        }
    }
    if !block.is_empty() {
        blocks.push(block);
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What systemd shows for the image's units, as shipped, the agent
    /// running.
    pub(crate) fn shipped() -> String {
        format!(
            "Id=punar-smplifyd.socket\nLoadState=loaded\n\
             FragmentPath=/usr/lib/systemd/system/punar-smplifyd.socket\nDropInPaths=\n\
             Listen={DEFAULT_CONTROL_PLANE_SOCKET} (Stream)\n\n\
             MainPID=4242\nId=punar-smplifyd.service\nLoadState=loaded\n\
             FragmentPath=/usr/lib/systemd/system/punar-smplifyd.service\nDropInPaths=\n\n\
             MainPID=812\nId=punard.service\nLoadState=loaded\n\
             FragmentPath=/usr/lib/systemd/system/punard.service\n\
             DropInPaths=/usr/lib/systemd/system/punard.service.d/10-mock-control-plane.conf\n\n\
             Id=punard-reconcile.timer\nLoadState=loaded\n\
             FragmentPath=/usr/lib/systemd/system/punard-reconcile.timer\nDropInPaths=\n\n\
             MainPID=0\nId=punard-reconcile.service\nLoadState=loaded\n\
             FragmentPath=/usr/lib/systemd/system/punard-reconcile.service\nDropInPaths=\n"
        )
    }

    fn agent_exe(pid: u32) -> Option<PathBuf> {
        (pid == 4242).then(|| PathBuf::from(AGENT_EXECUTABLE))
    }

    fn unit_of(finding: Result<(), UnitFinding>) -> String {
        match finding {
            Err(UnitFinding::Modified { unit, .. }) => unit,
            other => panic!("expected a modified unit, got {other:?}"),
        }
    }

    /// The units as the image ships them pass, vendor drop-ins included.
    #[test]
    fn the_shipped_units_pass() {
        assert_eq!(judge(&shipped(), agent_exe), Ok(()));
        // Not running (dormant between calls) is not a modification.
        let idle = shipped().replace("MainPID=4242", "MainPID=0");
        assert_eq!(judge(&idle, |_| None), Ok(()));
    }

    /// Every administrator or runtime layer is caught: a drop-in in /etc or
    /// /run (an `ExecStart=` override, a lifted `RefuseManualStop=`, an
    /// `Environment=` pointing punard elsewhere, a `set-property`), a mask, a
    /// fragment overridden in /etc, a socket listening elsewhere, a process
    /// that is not the image's agent, and a unit systemd does not show.
    #[test]
    fn every_override_of_a_management_unit_is_caught() {
        let cases = [
            (
                "DropInPaths=\nListen",
                "DropInPaths=/run/systemd/system.control/punar-smplifyd.socket.d/50-x.conf\nListen",
                AGENT_SOCKET_UNIT,
            ),
            (
                "punar-smplifyd.service\nDropInPaths=",
                "punar-smplifyd.service\nDropInPaths=/etc/systemd/system/punar-smplifyd.service.d/override.conf",
                AGENT_SERVICE_UNIT,
            ),
            (
                "10-mock-control-plane.conf",
                "10-mock-control-plane.conf /etc/systemd/system/punard.service.d/route.conf",
                "punard.service",
            ),
            (
                "Id=punard-reconcile.timer\nLoadState=loaded",
                "Id=punard-reconcile.timer\nLoadState=masked",
                "punard-reconcile.timer",
            ),
            (
                "FragmentPath=/usr/lib/systemd/system/punard-reconcile.service",
                "FragmentPath=/etc/systemd/system/punard-reconcile.service",
                "punard-reconcile.service",
            ),
            (
                "api.sock (Stream)",
                "api.sock (Stream) /run/x.sock (Stream)",
                AGENT_SOCKET_UNIT,
            ),
        ];
        for (from, to, unit) in cases {
            let shown = shipped().replace(from, to);
            assert_ne!(shown, shipped(), "{from}");
            assert_eq!(unit_of(judge(&shown, agent_exe)), unit, "{to}");
        }
        assert_eq!(
            unit_of(judge(&shipped(), |_| Some(PathBuf::from("/tmp/impostor")))),
            AGENT_SERVICE_UNIT
        );
        assert_eq!(
            unit_of(judge(&shipped(), |_| None)),
            AGENT_SERVICE_UNIT,
            "an executable that cannot be read is not the agent's"
        );
        let without_timer = shipped().replace("Id=punard-reconcile.timer", "Id=other.timer");
        assert_eq!(
            unit_of(judge(&without_timer, agent_exe)),
            "punard-reconcile.timer"
        );
    }
}
