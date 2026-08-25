//! The local alert engine (milestone-10.md section 5; spec sections 12.1,
//! 23, 73; Plate D-009).
//!
//! # The rule, in one line
//!
//! **One alert per `signature_id`** — not per scan, and not per process.
//!
//! - First sighting of a signature with no live alert record → **raise**.
//! - Any further detection carrying that signature → update the record's
//!   `last_seen`, `live` count and most recent `detection_id`. Never
//!   re-raise, never re-toast.
//! - When the last live detection of the signature clears, the record
//!   moves to `cleared` and starts a **24 h quiet window**. A sighting
//!   inside the window updates the record silently; the first sighting
//!   *after* it raises a fresh alert.
//!
//! Why a window at all: a cron-driven or crash-looping agent would
//! otherwise produce one alert per restart, and the tenth alert teaches
//! the user to ignore the first. Why 24 h and not forever: a binary that
//! reappears next week after a quiet fortnight is genuinely new
//! information, and permanently suppressing it would make the feature
//! silently degrade over the life of the device.
//!
//! **Dismissal does not change suppression.** Dismissing *files* the
//! card, and the card was already never going to be raised twice. There
//! is therefore no snooze, no per-alert mute, and no user-facing
//! suppression state to explain — which is the point.
//!
//! # The file is a change log; the socket is the authority
//!
//! `/run/punar-agentd/alerts.json` is written **only when the alert set
//! changes** — a raise, a clear, a dismissal, or a fresh raise after the
//! window expires. Counters and timestamps moving is not a set change, so
//! a pass that finds the same processes still running writes **nothing**
//! (spec 6.4; milestone-10.md decision 4). The consequence, stated
//! because it looks like a bug otherwise: the file's `last_seen` means
//! *as of the last set change*, exactly as `agents.json`'s `scanned_at`
//! does. Live values come from `alerts.list` on the socket.
//!
//! # Why the file is root-owned
//!
//! `0640 root:punar` in the **root-owned** `/run/punar-agentd`. M9 §8.1
//! moved `approvals.json` out of `/run/punar` because a file that tells a
//! human what to believe must not be replaceable by an unprivileged
//! process; the argument is at least as strong here. A forged card
//! reading *"Unknown AI activity suspected · your-bank-helper"* with an
//! `Inspect` action is a phishing primitive, and `/run/punar` is
//! `0755 punar:punar`.
//!
//! # What the engine does not do
//!
//! It does not block, kill, quarantine, or throttle anything (law 4 of
//! milestone-10.md). A red card that cannot act is honest; a red card
//! that silently acts is not. It also holds no do-not-disturb state: DND
//! is shell-local in M10 (§5.6), so nothing here can know about it, and
//! nothing here writes a `quiet` flag it would have to invent.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use punar_common::agent::{
    ALERT_QUIET_WINDOW_SECS, ALERTS_FILE_VERSION, AlertRow, AlertState, AlertsFile, ListedAlert,
    MAX_RETAINED_ALERTS,
};
use punar_common::time::{rfc3339_utc_from_unix_seconds, unix_seconds_from_rfc3339};

use crate::identity::alert_id;

/// One live detection, as the alert engine needs it. Deliberately not the
/// whole [`crate::registry::Detection`]: the engine sees an identity, a
/// name, one path and an owner, and there is no field here for anything
/// else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub signature_id: String,
    pub signature: String,
    pub detection_id: String,
    pub agent: String,
    pub executable: String,
    pub owner: String,
    pub owner_uid: Option<u32>,
}

/// One alert in the register: the display row plus the lifecycle facts
/// the display file has no reason to carry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    row: AlertRow,
    raised_at: String,
    cleared_at: Option<String>,
    dismissed_at: Option<String>,
    /// When a fresh sighting of this signature would raise again.
    quiet_until: Option<String>,
    /// Owner uid of the detection that raised it — the `alerts.dismiss`
    /// authorization. Not in the file: the file's field list is fixed by
    /// milestone-10.md section 5.3, and a uid is not display data.
    owner_uid: Option<u32>,
}

impl Entry {
    fn listed(&self) -> ListedAlert {
        ListedAlert {
            row: self.row.clone(),
            raised_at: self.raised_at.clone(),
            cleared_at: self.cleared_at.clone(),
            dismissed_at: self.dismissed_at.clone(),
            quiet_until: self.quiet_until.clone(),
        }
    }
}

/// What one reconcile changed — the caller's cue to write the file and to
/// audit, and nothing more.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AlertChange {
    /// The alert **set** changed: a raise, a clear, or a re-raise. Only
    /// this justifies rewriting the file.
    pub changed: bool,
    /// Alerts raised by this reconcile, oldest first — one
    /// `agents.alert_raise` audit event each, and never more.
    pub raised: Vec<AlertRow>,
}

/// Why a dismissal could not be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DismissError {
    NotFound,
}

/// The outcome of a dismissal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dismissal {
    pub row: AlertRow,
    pub dismissed_at: String,
    /// `false` when the card was already filed — the call is idempotent,
    /// and a second dismissal is not a second event.
    pub newly_dismissed: bool,
}

#[derive(Debug, Default)]
struct Register {
    /// Raise order, oldest first.
    entries: Vec<Entry>,
}

impl Register {
    /// The alert that currently represents a signature: the most recent
    /// one raised for it. Older ones are filed history.
    fn current_index(&self, signature_id: &str) -> Option<usize> {
        self.entries
            .iter()
            .rposition(|entry| entry.row.signature_id == signature_id)
    }
}

/// Where the alert file lives and how the register is bounded.
#[derive(Debug, Clone)]
pub struct AlertConfig {
    /// `/run/punar-agentd/alerts.json` in production.
    pub path: PathBuf,
    /// Group that may read it (`punar`), resolved once.
    pub gid: Option<u32>,
    pub quiet_window_secs: u64,
    pub max_retained: usize,
}

impl AlertConfig {
    pub fn new(path: impl Into<PathBuf>, gid: Option<u32>) -> AlertConfig {
        AlertConfig {
            path: path.into(),
            gid,
            quiet_window_secs: ALERT_QUIET_WINDOW_SECS,
            max_retained: MAX_RETAINED_ALERTS,
        }
    }
}

/// The engine. One `Mutex` around the register; it is never held across a
/// call into the registry or the ledger, so it cannot deadlock against
/// either.
#[derive(Debug)]
pub struct AlertEngine {
    cfg: AlertConfig,
    register: Mutex<Register>,
}

impl AlertEngine {
    pub fn new(cfg: AlertConfig) -> AlertEngine {
        AlertEngine {
            cfg,
            register: Mutex::new(Register::default()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.cfg.path
    }

    /// Rebuild the register from the file this daemon last wrote.
    ///
    /// Without this, restarting `punar-agentd` (a package update, say)
    /// would re-raise every standing alert — precisely the nagging the
    /// anti-nag rule exists to prevent. The file is root-owned and
    /// `0640`, so nothing unprivileged can seed the register through it.
    ///
    /// The file does not carry `quiet_until` (it is not display data), so
    /// a `cleared` alert's window is re-derived as
    /// `last_seen + quiet_window`. That is **at most** the true deadline
    /// and never longer, so the only possible error is raising a card
    /// slightly early — honest in the direction of telling the user.
    pub fn resume(&self) {
        let Ok(text) = std::fs::read_to_string(&self.cfg.path) else {
            return;
        };
        let Ok(file) = serde_json::from_str::<AlertsFile>(&text) else {
            eprintln!(
                "punar-agentd: {} could not be parsed; starting with an empty alert \
                 register (a standing alert may be raised once more)",
                self.cfg.path.display()
            );
            return;
        };
        let mut register = self.register.lock().unwrap();
        for row in file.alerts {
            let quiet_until = (row.state == AlertState::Cleared)
                .then(|| self.deadline(&row.last_seen))
                .flatten();
            register.entries.push(Entry {
                raised_at: row.first_seen.clone(),
                cleared_at: (row.state == AlertState::Cleared).then(|| row.last_seen.clone()),
                dismissed_at: (row.state == AlertState::Dismissed).then(|| row.last_seen.clone()),
                quiet_until,
                // Not carried in the file, and deliberately not guessed:
                // a resumed alert is dismissable by root until the next
                // sighting re-attaches the owner. Fail closed.
                owner_uid: None,
                row,
            });
        }
    }

    /// Apply one detection pass. `live` is the **whole** current
    /// detection set, not the diff — the anti-nag rule is a statement
    /// about the set, and deriving it from a diff would need the engine
    /// to keep a second copy of the same truth.
    pub fn reconcile(&self, live: &[Observation], policy_citation: &str, now: &str) -> AlertChange {
        let mut change = AlertChange::default();
        let mut register = self.register.lock().unwrap();

        // Group the live set by signature. `BTreeMap` for a deterministic
        // raise order, so two identical passes audit identically.
        let mut by_signature: std::collections::BTreeMap<&str, (u64, &Observation)> =
            std::collections::BTreeMap::new();
        for observation in live {
            let slot = by_signature
                .entry(observation.signature_id.as_str())
                .or_insert((0, observation));
            slot.0 += 1;
            slot.1 = observation;
        }

        for (signature_id, (count, observation)) in &by_signature {
            match register.current_index(signature_id) {
                Some(index) => {
                    let expired = {
                        let entry = &register.entries[index];
                        entry.row.state == AlertState::Cleared
                            && entry
                                .quiet_until
                                .as_deref()
                                .is_none_or(|until| now >= until)
                    };
                    if expired {
                        // The window ran out and the thing is back: that
                        // is genuinely new information, so a fresh card.
                        // The old one stays filed in the register.
                        let entry = new_entry(observation, *count, policy_citation, now);
                        change.raised.push(entry.row.clone());
                        register.entries.push(entry);
                        change.changed = true;
                        continue;
                    }
                    let entry = &mut register.entries[index];
                    // A silent update: counters and timestamps move, the
                    // set does not, and nothing is written.
                    entry.row.last_seen = now.to_string();
                    entry.row.live = *count;
                    entry.row.detection_id = observation.detection_id.clone();
                    entry.row.executable = observation.executable.clone();
                    entry.row.signature = observation.signature.clone();
                    entry.row.policy_citation = policy_citation.to_string();
                    if entry.owner_uid.is_none() {
                        entry.owner_uid = observation.owner_uid;
                    }
                }
                None => {
                    let entry = new_entry(observation, *count, policy_citation, now);
                    change.raised.push(entry.row.clone());
                    register.entries.push(entry);
                    change.changed = true;
                }
            }
        }

        // Signatures with no live detection left: the card clears and the
        // quiet window starts (or restarts — a crash-looping agent never
        // escapes it, which is the intent).
        let live_signatures: std::collections::BTreeSet<&str> =
            by_signature.keys().copied().collect();
        let deadline = self.deadline(now);
        let mut cleared_any = false;
        for index in 0..register.entries.len() {
            let is_current = {
                let signature = register.entries[index].row.signature_id.clone();
                register.current_index(&signature) == Some(index)
            };
            let entry = &mut register.entries[index];
            if !is_current || live_signatures.contains(entry.row.signature_id.as_str()) {
                continue;
            }
            if entry.row.live == 0 && entry.cleared_at.is_some() {
                continue;
            }
            entry.row.live = 0;
            entry.cleared_at = Some(now.to_string());
            entry.quiet_until = deadline.clone();
            // A filed card stays filed: dismissal is a display state, and
            // the user does not need to watch a card they put away change
            // colour. The suppression window starts either way.
            if entry.row.state == AlertState::Live {
                entry.row.state = AlertState::Cleared;
                entry.row.last_seen = now.to_string();
                cleared_any = true;
            }
        }
        change.changed |= cleared_any;

        if self.evict(&mut register) {
            change.changed = true;
        }
        change
    }

    /// File one card. It is never destroyed, and suppression does not
    /// move — the two sentences the CLI prints.
    pub fn dismiss(&self, alert_id: &str, now: &str) -> Result<Dismissal, DismissError> {
        let mut register = self.register.lock().unwrap();
        let entry = register
            .entries
            .iter_mut()
            .find(|entry| entry.row.alert_id == alert_id)
            .ok_or(DismissError::NotFound)?;
        if let Some(at) = entry.dismissed_at.clone() {
            return Ok(Dismissal {
                row: entry.row.clone(),
                dismissed_at: at,
                newly_dismissed: false,
            });
        }
        entry.dismissed_at = Some(now.to_string());
        entry.row.state = AlertState::Dismissed;
        Ok(Dismissal {
            row: entry.row.clone(),
            dismissed_at: now.to_string(),
            newly_dismissed: true,
        })
    }

    /// The owner uid of an alert, for the dismissal authorization.
    /// `None` — unknown owner — is root-only via
    /// [`crate::authz::may_act_on_session`]: fail closed.
    pub fn owner_uid_of(&self, alert_id: &str) -> Option<u32> {
        self.register
            .lock()
            .unwrap()
            .entries
            .iter()
            .find(|entry| entry.row.alert_id == alert_id)
            .and_then(|entry| entry.owner_uid)
    }

    pub fn knows(&self, alert_id: &str) -> bool {
        self.register
            .lock()
            .unwrap()
            .entries
            .iter()
            .any(|entry| entry.row.alert_id == alert_id)
    }

    /// The register as `alerts.list` returns it — newest first, because
    /// that is the order a human reads a notification list in.
    pub fn list(&self, include_dismissed: bool) -> Vec<ListedAlert> {
        let register = self.register.lock().unwrap();
        register
            .entries
            .iter()
            .rev()
            .filter(|entry| include_dismissed || entry.dismissed_at.is_none())
            .map(Entry::listed)
            .collect()
    }

    /// The document as it would be written — the display rows, newest
    /// first.
    pub fn file(&self, now: &str) -> AlertsFile {
        let register = self.register.lock().unwrap();
        AlertsFile {
            v: ALERTS_FILE_VERSION,
            updated_at: now.to_string(),
            alerts: register
                .entries
                .iter()
                .rev()
                .map(|entry| entry.row.clone())
                .collect(),
        }
    }

    /// Write `alerts.json`: atomic `tmp` + `fsync` + `rename`, `0640
    /// root:punar`. Called **only** on an alert-set change.
    pub fn write(&self, now: &str) {
        let file = self.file(now);
        let Ok(mut bytes) = serde_json::to_vec(&file) else {
            return;
        };
        bytes.push(b'\n');
        if let Some(parent) = self.cfg.path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("punar-agentd: could not create {}: {e}", parent.display());
                return;
            }
        }
        if let Err(e) = crate::util::write_atomic_synced(&self.cfg.path, &bytes, 0o640) {
            eprintln!(
                "punar-agentd: could not write {}: {e} (no alert card will be shown; \
                 `punarctl agents alerts` still answers from the socket)",
                self.cfg.path.display()
            );
            return;
        }
        if let Some(gid) = self.cfg.gid {
            // root:punar — meaningful only as root, harmless otherwise.
            let _ = std::os::unix::fs::chown(&self.cfg.path, Some(0), Some(gid));
        }
    }

    fn deadline(&self, from: &str) -> Option<String> {
        let base = unix_seconds_from_rfc3339(from)?;
        Some(rfc3339_utc_from_unix_seconds(
            base + self.cfg.quiet_window_secs,
        ))
    }

    /// Keep the register bounded. A **live** alert is never evicted; the
    /// oldest filed or cleared one goes first.
    fn evict(&self, register: &mut Register) -> bool {
        let mut evicted = false;
        while register.entries.len() > self.cfg.max_retained {
            let Some(index) = register
                .entries
                .iter()
                .position(|entry| entry.row.state != AlertState::Live)
            else {
                break;
            };
            register.entries.remove(index);
            evicted = true;
        }
        evicted
    }
}

fn new_entry(observation: &Observation, live: u64, policy_citation: &str, now: &str) -> Entry {
    Entry {
        row: AlertRow {
            alert_id: alert_id(&observation.signature_id, now),
            signature_id: observation.signature_id.clone(),
            agent: observation.agent.clone(),
            executable: observation.executable.clone(),
            owner: observation.owner.clone(),
            first_seen: now.to_string(),
            last_seen: now.to_string(),
            live,
            detection_id: observation.detection_id.clone(),
            signature: observation.signature.clone(),
            policy_citation: policy_citation.to_string(),
            state: AlertState::Live,
        },
        raised_at: now.to_string(),
        cleared_at: None,
        dismissed_at: None,
        quiet_until: None,
        owner_uid: observation.owner_uid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::temp_dir;

    const CITATION: &str = "personal-defaults";

    fn engine(tag: &str) -> (AlertEngine, PathBuf) {
        let dir = temp_dir(&format!("alerts-{tag}"));
        let path = dir.join("alerts.json");
        (AlertEngine::new(AlertConfig::new(&path, None)), dir)
    }

    fn observation(signature_id: &str, detection_id: &str) -> Observation {
        Observation {
            signature_id: signature_id.to_string(),
            signature: "downloads-foo-agent".to_string(),
            detection_id: detection_id.to_string(),
            agent: "foo-agent".to_string(),
            executable: "/home/punar/Downloads/foo-agent".to_string(),
            owner: "punar".to_string(),
            owner_uid: Some(1000),
        }
    }

    const SIG: &str = "sig_a1b2c3d4e5f6";

    /// The whole anti-nag rule, as one narrative: raise once, stay quiet
    /// while it lives, clear, stay quiet inside the window, re-raise
    /// after it.
    #[test]
    fn one_alert_per_signature_across_raise_clear_window_and_reraise() {
        let (engine, dir) = engine("antinag");
        let live = [observation(SIG, "agt_000000000001")];

        // 1. First sighting raises exactly one card.
        let first = engine.reconcile(&live, CITATION, "2026-08-25T14:31:00Z");
        assert!(first.changed);
        assert_eq!(first.raised.len(), 1);
        assert_eq!(first.raised[0].state, AlertState::Live);
        let alert_id = first.raised[0].alert_id.clone();

        // 2. The same process, three more passes: no raise, no set
        //    change, and therefore nothing to write.
        for at in [
            "2026-08-25T14:35:00Z",
            "2026-08-25T14:39:00Z",
            "2026-08-25T14:43:00Z",
        ] {
            let again = engine.reconcile(&live, CITATION, at);
            assert!(!again.changed, "a persisting detection is not news");
            assert!(again.raised.is_empty());
        }
        assert_eq!(engine.list(false).len(), 1);
        // The live value moved on the socket even though nothing was
        // written: the socket is the authority.
        assert_eq!(engine.list(false)[0].row.last_seen, "2026-08-25T14:43:00Z");

        // 3. A restart of the same binary is the same thing seen — a new
        //    process, a new detection_id, still one card.
        let restarted = [observation(SIG, "agt_000000000002")];
        let again = engine.reconcile(&restarted, CITATION, "2026-08-25T14:47:00Z");
        assert!(!again.changed);
        assert_eq!(engine.list(false)[0].row.detection_id, "agt_000000000002");

        // 4. It goes away: the card clears and the window opens.
        let cleared = engine.reconcile(&[], CITATION, "2026-08-25T15:00:00Z");
        assert!(cleared.changed, "clearing is a set change");
        assert!(cleared.raised.is_empty());
        let listed = engine.list(false);
        assert_eq!(listed[0].row.state, AlertState::Cleared);
        assert_eq!(listed[0].row.live, 0);
        assert_eq!(
            listed[0].quiet_until.as_deref(),
            Some("2026-08-26T15:00:00Z")
        );

        // 5. It comes back inside the window — the crash-loop case. The
        //    record updates; the user is not told again.
        let inside = engine.reconcile(&live, CITATION, "2026-08-26T09:00:00Z");
        assert!(!inside.changed, "no second card inside the quiet window");
        assert!(inside.raised.is_empty());
        assert_eq!(engine.list(false).len(), 1);
        assert_eq!(engine.list(false)[0].row.alert_id, alert_id);

        // 6. It clears again — the window restarts from the new clear.
        engine.reconcile(&[], CITATION, "2026-08-26T09:30:00Z");
        assert_eq!(
            engine.list(false)[0].quiet_until.as_deref(),
            Some("2026-08-27T09:30:00Z")
        );

        // 7. And after the window: genuinely new information, fresh card.
        let after = engine.reconcile(&live, CITATION, "2026-08-27T09:30:00Z");
        assert!(after.changed);
        assert_eq!(after.raised.len(), 1);
        assert_ne!(
            after.raised[0].alert_id, alert_id,
            "a fresh alert, fresh id"
        );
        assert_eq!(
            engine.list(false).len(),
            2,
            "the old card is history, not deleted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two live processes of the same signature are one alert with
    /// `live: 2` — not two alerts.
    #[test]
    fn concurrent_processes_of_one_signature_share_one_card() {
        let (engine, dir) = engine("concurrent");
        let live = [
            observation(SIG, "agt_000000000001"),
            observation(SIG, "agt_000000000002"),
        ];
        let change = engine.reconcile(&live, CITATION, "2026-08-25T14:31:00Z");
        assert_eq!(change.raised.len(), 1);
        assert_eq!(engine.list(false).len(), 1);
        assert_eq!(engine.list(false)[0].row.live, 2);

        // One of the two exits: still one card, still live.
        let half = engine.reconcile(&live[..1], CITATION, "2026-08-25T14:35:00Z");
        assert!(!half.changed);
        assert_eq!(engine.list(false)[0].row.live, 1);
        assert_eq!(engine.list(false)[0].row.state, AlertState::Live);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two different signatures are two cards. The key is the signature,
    /// not "an unknown agent exists".
    #[test]
    fn different_signatures_get_their_own_cards() {
        let (engine, dir) = engine("two-sigs");
        let live = [
            observation(SIG, "agt_000000000001"),
            observation("sig_ffffffffffff", "agt_000000000002"),
        ];
        let change = engine.reconcile(&live, CITATION, "2026-08-25T14:31:00Z");
        assert_eq!(change.raised.len(), 2);
        assert_eq!(engine.list(false).len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Dismissal files rather than destroys, and it does **not** move
    /// suppression — the card was never going to be raised twice anyway.
    #[test]
    fn dismissal_files_the_card_and_changes_no_suppression() {
        let (engine, dir) = engine("dismiss");
        let live = [observation(SIG, "agt_000000000001")];
        let raised = engine.reconcile(&live, CITATION, "2026-08-25T14:31:00Z");
        let alert_id = raised.raised[0].alert_id.clone();

        let filed = engine.dismiss(&alert_id, "2026-08-25T14:32:00Z").unwrap();
        assert!(filed.newly_dismissed);
        assert_eq!(filed.row.state, AlertState::Dismissed);

        // Filed, not deleted: it is still in the register when asked for.
        assert!(
            engine.list(false).is_empty(),
            "the card leaves the live view"
        );
        assert_eq!(engine.list(true).len(), 1, "and stays in the record");
        assert!(engine.knows(&alert_id));

        // A second dismissal is idempotent and is not a second event.
        let again = engine.dismiss(&alert_id, "2026-08-25T14:40:00Z").unwrap();
        assert!(!again.newly_dismissed);
        assert_eq!(again.dismissed_at, "2026-08-25T14:32:00Z");

        // The process keeps running: no re-raise, because dismissal is
        // not suppression and suppression was already in force.
        let after = engine.reconcile(&live, CITATION, "2026-08-25T14:45:00Z");
        assert!(!after.changed);
        assert!(after.raised.is_empty());
        assert_eq!(engine.list(true).len(), 1);

        // It clears while filed: the window still opens, so a restart
        // inside 24 h does not produce a card either.
        engine.reconcile(&[], CITATION, "2026-08-25T15:00:00Z");
        let back = engine.reconcile(&live, CITATION, "2026-08-25T20:00:00Z");
        assert!(back.raised.is_empty());
        assert_eq!(engine.list(true).len(), 1);

        assert_eq!(
            engine.dismiss("alr_000000000000", "now"),
            Err(DismissError::NotFound)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The write rule: the file appears on a set change and does not move
    /// on a pass that only advances counters.
    #[test]
    fn the_file_is_written_only_on_a_set_change() {
        let (engine, dir) = engine("write");
        let live = [observation(SIG, "agt_000000000001")];

        let raise = engine.reconcile(&live, CITATION, "2026-08-25T14:31:00Z");
        assert!(raise.changed);
        engine.write("2026-08-25T14:31:00Z");
        let after_raise = std::fs::read(engine.path()).unwrap();

        let quiet = engine.reconcile(&live, CITATION, "2026-08-25T14:35:00Z");
        assert!(!quiet.changed);
        // The caller writes only when `changed`, so the bytes stand.
        assert_eq!(std::fs::read(engine.path()).unwrap(), after_raise);

        let file: AlertsFile = serde_json::from_slice(&after_raise).unwrap();
        assert_eq!(file.v, ALERTS_FILE_VERSION);
        assert_eq!(file.alerts.len(), 1);
        assert_eq!(file.alerts[0].last_seen, "2026-08-25T14:31:00Z");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Restarting the daemon must not re-raise a standing card.
    #[test]
    fn a_restart_resumes_the_register_instead_of_nagging() {
        let (engine, dir) = engine("resume");
        let live = [observation(SIG, "agt_000000000001")];
        engine.reconcile(&live, CITATION, "2026-08-25T14:31:00Z");
        engine.write("2026-08-25T14:31:00Z");
        let path = engine.path().to_path_buf();
        drop(engine);

        let restarted = AlertEngine::new(AlertConfig::new(&path, None));
        restarted.resume();
        assert_eq!(restarted.list(false).len(), 1);
        let after = restarted.reconcile(&live, CITATION, "2026-08-25T14:39:00Z");
        assert!(!after.changed, "a restart is not a new sighting");
        assert!(after.raised.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A resumed `cleared` card keeps a window derived from `last_seen` —
    /// never longer than the true one, so the error can only be telling
    /// the user slightly early.
    #[test]
    fn a_resumed_quiet_window_is_never_longer_than_the_real_one() {
        let (engine, dir) = engine("resume-window");
        let live = [observation(SIG, "agt_000000000001")];
        engine.reconcile(&live, CITATION, "2026-08-25T14:31:00Z");
        engine.reconcile(&[], CITATION, "2026-08-25T15:00:00Z");
        engine.write("2026-08-25T15:00:00Z");
        let path = engine.path().to_path_buf();
        drop(engine);

        let restarted = AlertEngine::new(AlertConfig::new(&path, None));
        restarted.resume();
        let listed = restarted.list(false);
        assert_eq!(listed[0].row.state, AlertState::Cleared);
        assert_eq!(
            listed[0].quiet_until.as_deref(),
            Some("2026-08-26T15:00:00Z")
        );
        // Inside the resumed window: quiet.
        assert!(
            !restarted
                .reconcile(&live, CITATION, "2026-08-26T09:00:00Z")
                .changed
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The register is bounded, and a live card is never the one evicted.
    #[test]
    fn eviction_never_drops_a_live_card() {
        let dir = temp_dir("alerts-evict");
        let mut cfg = AlertConfig::new(dir.join("alerts.json"), None);
        cfg.max_retained = 2;
        let engine = AlertEngine::new(cfg);

        // Two cards; clear the first so it is evictable.
        engine.reconcile(
            &[observation("sig_000000000001", "agt_000000000001")],
            CITATION,
            "2026-08-25T10:00:00Z",
        );
        engine.reconcile(&[], CITATION, "2026-08-25T10:05:00Z");
        engine.reconcile(
            &[observation("sig_000000000002", "agt_000000000002")],
            CITATION,
            "2026-08-25T10:10:00Z",
        );
        engine.reconcile(
            &[
                observation("sig_000000000002", "agt_000000000002"),
                observation("sig_000000000003", "agt_000000000003"),
            ],
            CITATION,
            "2026-08-25T10:15:00Z",
        );
        let ids: Vec<String> = engine
            .list(true)
            .into_iter()
            .map(|a| a.row.signature_id)
            .collect();
        assert_eq!(ids.len(), 2);
        assert!(!ids.contains(&"sig_000000000001".to_string()), "{ids:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The privacy regression (spec 21.2, 24.2): the file carries exactly
    /// the twelve fields milestone-10.md section 5.3 names, and the only
    /// path in it is the executable the card is built around.
    #[test]
    fn the_alert_file_carries_no_pid_no_argv_and_no_comm() {
        let (engine, dir) = engine("privacy");
        engine.reconcile(
            &[observation(SIG, "agt_000000000001")],
            CITATION,
            "2026-08-25T14:31:00Z",
        );
        engine.write("2026-08-25T14:31:00Z");
        let text = std::fs::read_to_string(engine.path()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();

        let mut envelope: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        envelope.sort_unstable();
        assert_eq!(envelope, vec!["alerts", "updated_at", "v"]);

        let alert = &value["alerts"][0];
        let mut keys: Vec<&str> = alert
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "agent",
                "alert_id",
                "detection_id",
                "executable",
                "first_seen",
                "last_seen",
                "live",
                "owner",
                "policy_citation",
                "signature",
                "signature_id",
                "state",
            ],
            "exactly the milestone-10.md section 5.3 field list"
        );
        for forbidden in [
            "pid",
            "process_id",
            "cmdline",
            "argv",
            "comm",
            "cwd",
            "cgroup",
            "env",
            "token",
            "secret",
            "prompt",
        ] {
            assert!(
                !keys.contains(&forbidden),
                "{forbidden} must not be representable in alerts.json"
            );
        }
        // The single path is the matched executable, and nothing else in
        // the document looks like a filesystem path.
        let paths: Vec<&str> = alert
            .as_object()
            .unwrap()
            .iter()
            .filter_map(|(_, v)| v.as_str())
            .filter(|s| s.starts_with('/'))
            .collect();
        assert_eq!(paths, vec!["/home/punar/Downloads/foo-agent"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
