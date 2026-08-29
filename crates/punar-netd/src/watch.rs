//! Event-only wakeup for managed-session changes.
//!
//! `/run/punar/agents.json` is deliberately not parsed here. It is a
//! world-readable display file and therefore only a doorbell: an inotify
//! event causes the daemon to fetch authoritative state from punar-agentd's
//! authenticated Unix socket.

use std::path::Path;

pub const WAKE_DIR_NAME: &str = ".wake";

/// Wake a blocking watcher during daemon shutdown.
pub fn wake(wake_root: &Path) {
    let directory = wake_root.join(WAKE_DIR_NAME);
    if std::fs::create_dir_all(&directory).is_err() {
        return;
    }
    let marker = directory.join("stop");
    let _ = std::fs::write(&marker, b"");
    let _ = std::fs::remove_file(marker);
}

/// Start one blocking inotify reader. There is no timer and no polling loop.
///
/// The parent directory is also watched because agentd publishes its summary
/// with an atomic rename. The file watch is refreshed after every event so a
/// replaced inode continues to act as a doorbell.
#[cfg(target_os = "linux")]
pub fn spawn_watch(
    doorbell: &Path,
    wake_root: &Path,
    should_stop: impl Fn() -> bool + Send + 'static,
    on_change: impl Fn() + Send + 'static,
) -> Option<std::thread::JoinHandle<()>> {
    use std::mem::MaybeUninit;
    use std::os::unix::ffi::OsStrExt;

    use rustix::fs::inotify::{self, CreateFlags, WatchFlags};

    let wake_directory = wake_root.join(WAKE_DIR_NAME);
    let _ = std::fs::create_dir_all(&wake_directory);
    let fd = inotify::init(CreateFlags::empty()).ok()?;
    let mut file_watch = add_file_watch(&fd, doorbell);
    let parent_watch = if let Some(parent) = doorbell.parent() {
        inotify::add_watch(
            &fd,
            parent,
            WatchFlags::CREATE | WatchFlags::MOVED_TO | WatchFlags::DELETE,
        )
        .ok()
    } else {
        None
    };
    let wake_watch = inotify::add_watch(&fd, &wake_directory, WatchFlags::CREATE).ok();
    if file_watch.is_none() && parent_watch.is_none() && wake_watch.is_none() {
        return None;
    }

    let doorbell = doorbell.to_path_buf();
    let doorbell_name = doorbell.file_name()?.as_bytes().to_vec();
    std::thread::Builder::new()
        .name("punar-netd-watch".to_string())
        .spawn(move || {
            let mut buffer = [MaybeUninit::uninit(); 4096];
            let mut reader = inotify::Reader::new(&fd, &mut buffer);
            loop {
                if should_stop() {
                    break;
                }
                let event = match reader.next() {
                    Ok(event) => event,
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(_) => break,
                };
                if should_stop() {
                    break;
                }
                // The parent watch exists only so an atomic rename can replace
                // the watched inode. `/run/punar` also contains screenshots,
                // reports and other side files; treating those names as agent
                // state churn would rebuild nftables for unrelated UI work.
                // A nameless event is from the inode watch (or a queue-overflow
                // fail-safe); a named parent event matters only for agents.json.
                let relevant = event.events().contains(inotify::ReadFlags::QUEUE_OVERFLOW)
                    || (file_watch == Some(event.wd()) && event.file_name().is_none())
                    || (parent_watch == Some(event.wd())
                        && event
                            .file_name()
                            .is_some_and(|name| name.to_bytes() == doorbell_name));
                if !relevant {
                    continue;
                }
                // Atomic replacement invalidates the inode watch. Re-adding is
                // idempotent and the filtered parent watch covers the interval
                // before the new inode exists.
                file_watch = add_file_watch(&fd, &doorbell).or(file_watch);
                on_change();
            }
        })
        .ok()
}

#[cfg(target_os = "linux")]
fn add_file_watch(fd: &impl std::os::fd::AsFd, doorbell: &Path) -> Option<i32> {
    use rustix::fs::inotify::{self, WatchFlags};

    inotify::add_watch(
        fd,
        doorbell,
        WatchFlags::MODIFY
            | WatchFlags::CLOSE_WRITE
            | WatchFlags::MOVE_SELF
            | WatchFlags::DELETE_SELF,
    )
    .ok()
}

/// Punar ships on Linux. This stub keeps workspace checks useful on macOS;
/// explicit requests still reconcile through the authoritative socket there.
#[cfg(not(target_os = "linux"))]
pub fn spawn_watch(
    _doorbell: &Path,
    _wake_root: &Path,
    _should_stop: impl Fn() -> bool + Send + 'static,
    _on_change: impl Fn() + Send + 'static,
) -> Option<std::thread::JoinHandle<()>> {
    None
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    #[test]
    fn atomic_publish_is_a_wakeup_not_a_data_source() {
        let root = std::env::temp_dir().join(format!(
            "punar-netd-watch-{}-{}",
            std::process::id(),
            punar_common::time::unix_now_millis()
        ));
        let run = root.join("run");
        std::fs::create_dir_all(&run).unwrap();
        let doorbell = run.join("agents.json");
        let stopped = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let watch_stopped = Arc::clone(&stopped);
        let thread = spawn_watch(
            &doorbell,
            &root,
            move || watch_stopped.load(Ordering::SeqCst),
            move || {
                let _ = tx.send(());
            },
        )
        .expect("parent and shutdown watches are available");

        let temporary = run.join(".agents.tmp");
        std::fs::write(&temporary, br#"{"untrusted":"ignored"}"#).unwrap();
        std::fs::rename(temporary, &doorbell).unwrap();
        rx.recv_timeout(Duration::from_secs(2))
            .expect("atomic publish wakes the watcher");

        stopped.store(true, Ordering::SeqCst);
        wake(&root);
        thread.join().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unrelated_runtime_files_do_not_reconcile_network_policy() {
        let root = std::env::temp_dir().join(format!(
            "punar-netd-watch-filter-{}-{}",
            std::process::id(),
            punar_common::time::unix_now_millis()
        ));
        let run = root.join("run");
        std::fs::create_dir_all(&run).unwrap();
        let doorbell = run.join("agents.json");
        std::fs::write(&doorbell, br#"{"sessions":[]}"#).unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let watch_stopped = Arc::clone(&stopped);
        let thread = spawn_watch(
            &doorbell,
            &root,
            move || watch_stopped.load(Ordering::SeqCst),
            move || {
                let _ = tx.send(());
            },
        )
        .expect("parent and shutdown watches are available");

        std::fs::write(run.join("screenshot.png"), b"unrelated").unwrap();
        assert!(
            rx.recv_timeout(Duration::from_millis(150)).is_err(),
            "an unrelated side file must not rebuild nftables"
        );

        let temporary = run.join(".agents.next");
        std::fs::write(&temporary, br#"{"sessions":[{"id":"agt_test"}]}"#).unwrap();
        std::fs::rename(temporary, &doorbell).unwrap();
        rx.recv_timeout(Duration::from_secs(2))
            .expect("the actual doorbell still wakes the watcher");

        stopped.store(true, Ordering::SeqCst);
        wake(&root);
        thread.join().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
