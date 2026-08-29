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
    use std::io::Read;

    use rustix::fs::inotify::{self, CreateFlags, WatchFlags};

    let wake_directory = wake_root.join(WAKE_DIR_NAME);
    let _ = std::fs::create_dir_all(&wake_directory);
    let fd = inotify::init(CreateFlags::empty()).ok()?;
    let mut watches = 0usize;
    if add_file_watch(&fd, doorbell) {
        watches += 1;
    }
    if let Some(parent) = doorbell.parent()
        && inotify::add_watch(
            &fd,
            parent,
            WatchFlags::CREATE | WatchFlags::MOVED_TO | WatchFlags::DELETE,
        )
        .is_ok()
    {
        watches += 1;
    }
    if inotify::add_watch(&fd, &wake_directory, WatchFlags::CREATE).is_ok() {
        watches += 1;
    }
    if watches == 0 {
        return None;
    }

    let doorbell = doorbell.to_path_buf();
    let mut file = std::fs::File::from(fd);
    std::thread::Builder::new()
        .name("punar-netd-watch".to_string())
        .spawn(move || {
            let mut buffer = [0u8; 4096];
            loop {
                if should_stop() {
                    break;
                }
                match file.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(_) => {
                        if should_stop() {
                            break;
                        }
                        // Atomic replacement invalidates the inode watch.
                        // Re-adding is idempotent and the parent watch covers
                        // the interval before the new inode exists.
                        let _ = add_file_watch(&file, &doorbell);
                        on_change();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        })
        .ok()
}

#[cfg(target_os = "linux")]
fn add_file_watch(fd: &impl std::os::fd::AsFd, doorbell: &Path) -> bool {
    use rustix::fs::inotify::{self, WatchFlags};

    inotify::add_watch(
        fd,
        doorbell,
        WatchFlags::MODIFY
            | WatchFlags::CLOSE_WRITE
            | WatchFlags::MOVE_SELF
            | WatchFlags::DELETE_SELF,
    )
    .is_ok()
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
}
