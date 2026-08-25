//! A bounded, event-driven wait on one file — the client half of
//! `punarctl approvals wait` (milestone-9.md section 4.3).
//!
//! **Waiting is a client concern.** `capabilities.set` and
//! `credential.request` answer `approval_required` immediately and never
//! block: contract section 2 gives every method a 10 s processing bound
//! and processes one call per connection at a time, so parking a
//! connection for the 300 s an approval may live would blow the bound,
//! pin the daemon, and couple a human's decision to the requester still
//! being alive. So the daemon returns, and this module does the waiting.
//!
//! **Watch for the wake, socket for the truth.** An inotify watch says
//! *something changed*; the answer always comes from one authoritative
//! `approvals.get` on the socket. `/run/punard/approvals.json` is
//! display data (contract section 15) and is never the basis of a
//! verdict here.
//!
//! **No polling loop** (SPEC section 6.3). The watch is on the
//! **directory**, not the file, because punard rewrites the summary
//! atomically (tmp + `fsync` + `rename`) and a rename replaces the
//! inode a file watch is bound to. The 1 Hz wake is the countdown's own
//! redraw — a UI clock with a visible consumer, the same standing this
//! milestone gives the overlay's timer and M1 gives the bar clock — and
//! it costs no IPC: a tick that saw no inotify event redraws the clock
//! and calls nothing.
//!
//! **The caller cannot hang.** The deadline is
//! `min(--timeout, expires_at)` and an approval lives at most 300 s, so
//! the hard ceiling is the approval TTL whatever the flags say.

use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::time::Duration;

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::inotify;

/// Read buffer for one drain of the inotify queue. Events are fixed
/// headers plus an optional name; the queue is drained to empty on every
/// wake, so this only bounds how many are read per `read(2)`.
const EVENT_BUF: usize = 4096;

/// How often the watchless fallback re-asks the socket. Only reached on
/// a machine where the summary directory cannot be watched at all (no
/// punard, or no read permission on `/run/punard`); the normal path
/// makes **zero** extra calls between events.
pub const FALLBACK_RECHECK: Duration = Duration::from_secs(5);

/// An inotify watch on the directory that holds one file.
pub struct DirWatch {
    fd: OwnedFd,
    /// The file name inside the watched directory; every other name in
    /// that directory (the control socket, a tmp file mid-rename) is
    /// ignored so an unrelated write never spends an IPC call.
    file_name: String,
}

impl DirWatch {
    /// Watch the directory containing `path` for changes to `path`
    /// itself. `Err` when there is nothing to watch (the file's directory
    /// does not exist, or this user may not read it) — the caller then
    /// degrades to [`FALLBACK_RECHECK`] rather than failing: a missing
    /// summary file is a calm state, not an error surface.
    pub fn on(path: &Path) -> io::Result<Self> {
        let dir = path
            .parent()
            .ok_or_else(|| io::Error::other("the watched path has no directory"))?;
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| io::Error::other("the watched path has no file name"))?
            .to_string();
        let fd = inotify::init(inotify::CreateFlags::NONBLOCK | inotify::CreateFlags::CLOEXEC)?;
        // MOVED_TO is the one that matters: punard's atomic rewrite lands
        // as a rename into this directory. CREATE and CLOSE_WRITE cover a
        // first appearance and a non-atomic writer; DELETE covers removal.
        inotify::add_watch(
            &fd,
            dir,
            inotify::WatchFlags::MOVED_TO
                | inotify::WatchFlags::CREATE
                | inotify::WatchFlags::CLOSE_WRITE
                | inotify::WatchFlags::DELETE,
        )?;
        Ok(DirWatch { fd, file_name })
    }

    /// Block until the watched file changes or `timeout` elapses.
    /// Returns `true` when a change was seen — the caller's cue to make
    /// one authoritative call.
    pub fn wait(&self, timeout: Duration) -> io::Result<bool> {
        let spec = Timespec {
            tv_sec: timeout.as_secs() as _,
            tv_nsec: timeout.subsec_nanos() as _,
        };
        let borrowed = self.fd.as_fd();
        let mut fds = [PollFd::new(&borrowed, PollFlags::IN)];
        let ready = match poll(&mut fds, Some(&spec)) {
            Ok(n) => n,
            // A signal during the wait is a wake, not a failure: return
            // "nothing seen" and let the caller redraw and re-check its
            // own deadline.
            Err(rustix::io::Errno::INTR) => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        if ready == 0 {
            return Ok(false);
        }
        Ok(self.drain())
    }

    /// Read every queued event, returning whether any of them named the
    /// watched file. The queue is always drained to empty so a burst of
    /// unrelated events cannot leave the fd permanently readable and turn
    /// the wait into a spin.
    fn drain(&self) -> bool {
        let mut buf = [MaybeUninit::<u8>::uninit(); EVENT_BUF];
        let mut hit = false;
        let mut reader = inotify::Reader::new(&self.fd, &mut buf);
        // Ends on the first Err — queue empty (NONBLOCK) or nothing more
        // to read.
        while let Ok(event) = reader.next() {
            if event
                .file_name()
                .and_then(|n| n.to_str().ok())
                .is_some_and(|n| n == self.file_name)
            {
                hit = true;
            }
        }
        hit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A path with no parent directory is refused rather than silently
    /// watching the wrong thing.
    #[test]
    fn a_rootless_path_is_refused() {
        assert!(DirWatch::on(Path::new("/")).is_err());
    }

    /// The fallback interval exists so a machine without a readable
    /// summary directory still answers — and it is deliberately slower
    /// than the redraw, so degrading costs one call per five seconds and
    /// not one per frame.
    #[test]
    fn the_fallback_is_slower_than_the_redraw() {
        assert!(FALLBACK_RECHECK > Duration::from_secs(1));
    }
}
