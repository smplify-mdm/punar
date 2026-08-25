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

/// The fixture kernel boot id — one of the two fields that make pid
/// reuse unable to collide with a live detection identity
/// (milestone-10.md section 4.1).
pub const FIXTURE_BOOT_ID: &str = "6f2c6b1e-0e2a-4c37-9f4e-6b6f2a1d9c31";

/// The fixture `btime` (2026-08-25T00:00:00Z), the base a detection's own
/// `started_at` is derived from.
pub const FIXTURE_BTIME: u64 = 1_787_616_000;

/// A fixture `/proc` root, carrying the two **system-wide** files M10
/// reads once per pass: `sys/kernel/random/boot_id` and the `btime` line
/// of `stat`.
pub fn fixture_proc(tag: &str) -> PathBuf {
    let root = temp_dir(&format!("proc-{tag}"));
    fixture_proc_system(&root, FIXTURE_BOOT_ID, FIXTURE_BTIME);
    root
}

/// Write the system-wide `/proc` files into an existing fixture root, so
/// a test that built its own root (the integration harness) gets the same
/// kernel facts.
pub fn fixture_proc_system(root: &Path, boot_id: &str, btime: u64) {
    let random = root.join("sys/kernel/random");
    std::fs::create_dir_all(&random).unwrap();
    std::fs::write(random.join("boot_id"), format!("{boot_id}\n")).unwrap();
    std::fs::write(
        root.join("stat"),
        format!("cpu  1 2 3 4 5 6 7 8 9 10\nbtime {btime}\nprocesses 1234\n"),
    )
    .unwrap();
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
    // `stat` fields 3..=22, with field 22 (`starttime`) derived from the
    // pid so every fixture process has a distinct, non-zero dedup key —
    // the same shape `ProcRoot::starttime_of` parses on a real kernel.
    let fields: Vec<String> = (3..=22)
        .map(|n| {
            if n == 22 {
                (900_000 + u64::from(pid)).to_string()
            } else {
                n.to_string()
            }
        })
        .collect();
    std::fs::write(
        dir.join("stat"),
        format!("{pid} ({comm}) {}\n", fields.join(" ")),
    )
    .unwrap();
}

/// Stage one fixture cgroup scope under `root`: the `cgroup.procs` and
/// `pids.peak` files [`crate::ledger::classes::CgroupRoot`] reads on a
/// real kernel. Returns the *relative* cgroup path, exactly as it appears
/// in `/proc/<pid>/cgroup`.
pub fn fixture_cgroup_scope(
    root: &Path,
    session_id: &str,
    pids: &[u32],
    peak: Option<u64>,
) -> String {
    let relative = managed_cgroup(session_id);
    let dir = root.join(relative.trim_start_matches('/'));
    std::fs::create_dir_all(&dir).unwrap();
    let mut procs = String::new();
    for pid in pids {
        procs.push_str(&format!("{pid}\n"));
    }
    std::fs::write(dir.join("cgroup.procs"), procs).unwrap();
    if let Some(peak) = peak {
        std::fs::write(dir.join("pids.peak"), format!("{peak}\n")).unwrap();
    }
    relative
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
  ],
  "provenance": [
    { "id": "unmanaged-path-agentlike",
      "unmanaged_path_prefixes": ["~/Downloads/", "/tmp/", "~/.local/bin/"],
      "name_tokens": ["agent", "-ai", "llm", "copilot", "mcp"],
      "require": "both",
      "note": "path provenance + agent-like name; either alone is not a signal" }
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
