//! Fixture builders for the crate's tests: a fake `/proc` tree and the
//! staged adapter/signature data files, so every test drives the shipping
//! code paths against injected roots instead of the host's real `/proc`.
//!
//! Kept in the library (not behind `cfg(test)`) so the external integration
//! test binary can build the same fixtures — the `punard`
//! `capability::mock` precedent. Nothing in the shipped daemon wiring calls
//! any of it; `punar-agentd run` never touches this module.

use std::path::{Path, PathBuf};

/// A fresh, uniquely named temp directory.
pub fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("punar-agentd-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A fixture `/proc` root.
pub fn fixture_proc(tag: &str) -> PathBuf {
    temp_dir(&format!("proc-{tag}"))
}

/// Write one fake process into a fixture `/proc` root: the same five files
/// [`crate::proc::ProcRoot`] reads on a real kernel.
pub fn fake_process(
    root: &Path,
    pid: u32,
    comm: &str,
    exe: &str,
    args: &[&str],
    uid: u32,
    cgroup: &str,
) {
    let dir = root.join(pid.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("comm"), format!("{comm}\n")).unwrap();
    // read_link works on a dangling symlink, so a fixture never has to
    // create the target binary.
    let _ = std::fs::remove_file(dir.join("exe"));
    std::os::unix::fs::symlink(exe, dir.join("exe")).unwrap();
    let mut cmdline = Vec::new();
    for arg in args {
        cmdline.extend_from_slice(arg.as_bytes());
        cmdline.push(0);
    }
    std::fs::write(dir.join("cmdline"), cmdline).unwrap();
    std::fs::write(
        dir.join("status"),
        format!("Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
    )
    .unwrap();
    std::fs::write(dir.join("cgroup"), format!("0::{cgroup}\n")).unwrap();
}

/// Remove a fake process — how a test makes a pid "die" between passes.
pub fn kill_process(root: &Path, pid: u32) {
    let _ = std::fs::remove_dir_all(root.join(pid.to_string()));
}

/// The cgroup line of a managed session's scope.
pub fn managed_cgroup(session_id: &str) -> String {
    format!(
        "/user.slice/user-1000.slice/user@1000.service/app.slice/{}",
        crate::proc::scope_unit_name(session_id)
    )
}

/// Stage the two shipped adapter definitions (the runtime copies of
/// `fixtures/agents/claude-code.json` plus the generic second adapter) into
/// a directory, and return it.
pub fn fixture_adapters(dir: &Path) -> PathBuf {
    let adapters = dir.join("adapters");
    std::fs::create_dir_all(&adapters).unwrap();
    std::fs::write(
        adapters.join("claude-code.json"),
        r#"{
  "name": "claude-code",
  "adapter": "claude_code",
  "launch": { "method": "managed", "command": "punar-env agent claude-code" },
  "adapter_config": {
    "command": ["claude"],
    "version_command": ["claude", "--version"],
    "signature": { "comm": ["claude"], "exe_glob": ["*/claude"] },
    "mock_command": ["/usr/lib/punar/punar-mock-agent"]
  }
}
"#,
    )
    .unwrap();
    std::fs::write(
        adapters.join("generic.json"),
        r#"{
  "name": "generic-shell",
  "adapter": "generic",
  "launch": { "method": "managed", "command": "punar-env agent generic-shell" },
  "adapter_config": {
    "command": ["/bin/sh"],
    "signature": { "comm": [], "exe_glob": [] },
    "mock_command": ["/usr/lib/punar/punar-mock-agent"]
  }
}
"#,
    )
    .unwrap();
    adapters
}

/// Stage the suspected-signature heuristic input and return its path.
pub fn fixture_suspected(dir: &Path) -> PathBuf {
    let path = dir.join("suspected.json");
    std::fs::write(
        &path,
        r#"{
  "v": 1,
  "patterns": [
    { "id": "downloads-foo-agent", "exe_glob": "*/Downloads/foo-agent",
      "note": "hero-demo fixture signature" },
    { "id": "downloads-agent-like", "exe_glob": "*/Downloads/*-agent",
      "note": "agent-named executable run from Downloads" }
  ]
}
"#,
    )
    .unwrap();
    path
}

/// `/etc/passwd` and `/etc/group` substitutes so identity resolution is
/// deterministic regardless of the host running the tests.
pub fn fixture_nss(dir: &Path) -> (PathBuf, PathBuf) {
    let group_file = dir.join("group");
    std::fs::write(&group_file, "root:x:0:\npunar:x:970:\n").unwrap();
    let passwd_file = dir.join("passwd");
    std::fs::write(
        &passwd_file,
        "root:x:0:0::/root:/bin/bash\npunar:x:1000:1000::/home/punar:/bin/bash\n",
    )
    .unwrap();
    (group_file, passwd_file)
}
