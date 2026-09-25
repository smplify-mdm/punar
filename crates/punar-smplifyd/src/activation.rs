//! How the agent's lifetime follows enrollment (docs/development/
//! smplify-enrollment.md section 3.4). systemd owns the listening socket
//! (`punar-smplifyd.socket`), and the agent runs only while it is needed: a
//! device that never enrolled runs no Smplify code at all, because nothing
//! connects to the socket until `punarctl enroll start`.
//!
//! Once started, the agent stays resident while anything of an identity is
//! in its state directory, and exits with [`DORMANT_EXIT_STATUS`] after
//! [`IDLE_BEFORE_DORMANT`] without a call when nothing is, or at once after
//! answering an `enroll.unregister` that wiped it. The unit treats that
//! status as a clean exit it does not restart (`SuccessExitStatus=` and
//! `RestartPreventExitStatus=`), and the socket starts the agent again on
//! the next call. Every other exit, a kill included, is restarted
//! (`Restart=always`). tests/images/smplifyd-activation-contract-test.sh
//! holds the unit to these constants.
use std::time::Duration;

/// The exit status of an agent that has gone dormant: `EX_TEMPFAIL`, which
/// nothing else in the agent exits with.
pub const DORMANT_EXIT_STATUS: u8 = 75;

/// How long an agent that holds no identity waits for a call before it goes
/// dormant. Long enough that `enroll.start`'s calls, and a person retrying a
/// mistyped code, find it still running; a device that declined enrollment
/// runs no agent half a minute later.
pub const IDLE_BEFORE_DORMANT: Duration = Duration::from_secs(30);

/// The name systemd gives the one descriptor it passes
/// (`FileDescriptorName=` in `punar-smplifyd.socket`).
pub const LISTENER_NAME: &str = "api";
