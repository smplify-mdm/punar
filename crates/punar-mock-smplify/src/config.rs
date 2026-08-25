//! Startup configuration: socket, fixture dir, state dir.
//!
//! Resolution order per knob: CLI flag → environment variable → compiled
//! default. The defaults match `punar-mock-smplify.service`
//! (`RuntimeDirectory`/`StateDirectory`, milestone-5.md section 4.6) and
//! the fixture tree `container-build.sh` stages; the env seams exist for
//! host tests and dev runs, exactly like `PUNAR_CONTROL_PLANE_SOCKET` on
//! `punard`'s client side.

use std::path::PathBuf;

/// Default socket path — the compiled-in endpoint `punard` dials
/// (milestone-5.md section 4.2).
pub const DEFAULT_SOCKET_PATH: &str = "/run/punar-mock-smplify/api.sock";

/// Default fixture directory (Acme tree staged by `container-build.sh`).
pub const DEFAULT_FIXTURES_DIR: &str = "/usr/share/punar/fixtures/acme";

/// Default received-state directory (`StateDirectory=punar-mock-smplify`).
pub const DEFAULT_STATE_DIR: &str = "/var/lib/punar-mock-smplify";

/// Environment override for the socket path.
pub const ENV_SOCKET: &str = "PUNAR_MOCK_SMPLIFY_SOCKET";

/// Environment override for the fixture directory.
pub const ENV_FIXTURES: &str = "PUNAR_MOCK_SMPLIFY_FIXTURES";

/// Environment override for the state directory.
pub const ENV_STATE_DIR: &str = "PUNAR_MOCK_SMPLIFY_STATE_DIR";

/// Resolved runtime configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockConfig {
    /// Unix socket to serve on (created `0600` root before `listen()`).
    pub socket: PathBuf,
    /// Directory holding `org.json` + policy-source + desired-state
    /// fixtures, served verbatim.
    pub fixtures_dir: PathBuf,
    /// Directory for `devices.json` and the `received-*.jsonl` logs.
    pub state_dir: PathBuf,
}

impl MockConfig {
    /// Resolve flags → process environment → defaults.
    pub fn resolve(
        socket: Option<PathBuf>,
        fixtures_dir: Option<PathBuf>,
        state_dir: Option<PathBuf>,
    ) -> MockConfig {
        Self::resolve_with(socket, fixtures_dir, state_dir, |name| {
            std::env::var(name).ok()
        })
    }

    /// [`MockConfig::resolve`] with an injectable environment (tests supply
    /// a closure instead of mutating the process env, which is `unsafe` in
    /// edition 2024).
    pub fn resolve_with(
        socket: Option<PathBuf>,
        fixtures_dir: Option<PathBuf>,
        state_dir: Option<PathBuf>,
        env: impl Fn(&str) -> Option<String>,
    ) -> MockConfig {
        let pick = |flag: Option<PathBuf>, var: &str, default: &str| {
            flag.or_else(|| env(var).map(PathBuf::from))
                .unwrap_or_else(|| PathBuf::from(default))
        };
        MockConfig {
            socket: pick(socket, ENV_SOCKET, DEFAULT_SOCKET_PATH),
            fixtures_dir: pick(fixtures_dir, ENV_FIXTURES, DEFAULT_FIXTURES_DIR),
            state_dir: pick(state_dir, ENV_STATE_DIR, DEFAULT_STATE_DIR),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_apply_when_nothing_is_given() {
        let cfg = MockConfig::resolve_with(None, None, None, |_| None);
        assert_eq!(cfg.socket, PathBuf::from(DEFAULT_SOCKET_PATH));
        assert_eq!(cfg.fixtures_dir, PathBuf::from(DEFAULT_FIXTURES_DIR));
        assert_eq!(cfg.state_dir, PathBuf::from(DEFAULT_STATE_DIR));
    }

    #[test]
    fn env_beats_default_and_flag_beats_env() {
        let env = |name: &str| match name {
            ENV_SOCKET => Some("/env/api.sock".to_string()),
            ENV_FIXTURES => Some("/env/fixtures".to_string()),
            _ => None,
        };
        let cfg = MockConfig::resolve_with(Some(PathBuf::from("/flag/api.sock")), None, None, env);
        assert_eq!(cfg.socket, PathBuf::from("/flag/api.sock"));
        assert_eq!(cfg.fixtures_dir, PathBuf::from("/env/fixtures"));
        assert_eq!(cfg.state_dir, PathBuf::from(DEFAULT_STATE_DIR));
    }
}
