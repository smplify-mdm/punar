//! The AI Access Ledger engine (spec sections 21, 24; Milestone 8).
//!
//! Design rationale: `docs/development/milestone-8.md`. Wire contract:
//! `docs/api/ipc.md` sections 12–13. Document schema:
//! `schemas/ai-agent/ledger-summary.json`, **shipped unchanged**.
//!
//! # The architectural law of this milestone (spec 1.14 + 21)
//!
//! The ledger is **derived from mediation points Punar already owns**.
//! There is no eBPF, no fanotify, no ptrace, no `LD_PRELOAD`, no
//! audit-subsystem rule, and no filesystem or network interception
//! anywhere in this module tree. Four sources, and nothing else:
//!
//! | | Source | Category it feeds |
//! |---|---|---|
//! | **A** | the session's `punar-agent-<id>.scope` cgroup ([`classes`]) | `process_classes` |
//! | **B** | audit events tagged with this `agent_session_id` ([`tail`]) | Level-4 event references |
//! | **C** | the managed launch's realized workspace grant | `repositories`, `directory_zones` |
//! | **D** | adapter / registry metadata | identity, the session's own root process |
//!
//! `network_destinations`, `mcp_servers` and `credential_classes` have
//! **no producer in M8** and are reported as empty arrays *plus* a
//! [`punar_common::ledger::not_yet_observed`] row naming the milestone
//! that ships the producer. Inventing them would be spec 1.22 fraud; the
//! honest empty is the deliverable.
//!
//! # No timers, anywhere (spec 6.3)
//!
//! Every update point is an event: a registration, a scan pass, a session
//! ending, an audit append (one thread blocking in `read(2)` on an
//! `inotify` fd), a ledger read, or daemon startup. There is no interval,
//! no polling loop, and no background work between them. Writes are
//! batched — at most one atomic `tmp`+`rename` per session per batch — so
//! the idle write rate is exactly **0 B/s** (spec 6.4).
//!
//! # Privacy is in the types (spec 21.2)
//!
//! Everything persisted here is a
//! [`punar_common::ledger::ResourceClass`], a count, and a timestamp. A
//! path, a URL, an argv, a `comm`, a prompt or a secret is
//! *unrepresentable*: there is no field for one, and the class newtype
//! refuses any string containing a separator or whitespace however it is
//! constructed. The `comm` this module reads is mapped through the class
//! table and dropped; an unmapped one becomes the literal class
//! `unknown`, never itself.

pub mod classes;
pub mod store;
pub mod tail;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use punar_common::agent::{AgentClassification, AgentStatus};
use punar_common::ledger::{
    AgentsAccessResult, Evidence, LEDGER_RECORD_VERSION, LEDGER_RETENTION_DAYS, LedgerFingerprint,
    LedgerIndex, LedgerPurgeResult, LedgerRecord, LedgerRuntimeFile, PROCESS_CLASSES_PATH,
    ResourceCategory, ResourceClass, TailPosition, ZONE_WORKSPACE,
};

use crate::ledger::classes::{CgroupRoot, ClassTable, sample_scope};
use crate::ledger::store::{LedgerStore, PruneOutcome, index_row, plus_days, tombstone_row};
use crate::ledger::tail::AuditTail;
use crate::proc::ProcRoot;

/// The M7 sentinel a session carries when no project could be resolved
/// (milestone-7.md section 4.4). It is a syntactically valid class name,
/// so the ledger must exclude it deliberately rather than by accident.
pub const PROJECT_UNRESOLVED: &str = "unknown";

/// Where the engine reads and writes. Every path is injectable, so the
/// whole engine runs inside a tempdir in tests — including `/proc` and
/// `/sys/fs/cgroup`, which is what makes aggregation testable at all.
#[derive(Debug, Clone)]
pub struct LedgerConfig {
    /// `/var/lib/punar/agents/ledger` in production.
    pub dir: PathBuf,
    /// `/run/punar-agentd/ledger.json` — the panel's view.
    pub runtime_file: PathBuf,
    /// The shared audit trail (source B).
    pub audit_path: PathBuf,
    /// `comm` → class table.
    pub process_classes_path: PathBuf,
    /// `/sys/fs/cgroup` in production.
    pub cgroup_root: PathBuf,
    /// Days after `ended_at` a ledger is kept.
    pub retention_days: u64,
}

impl LedgerConfig {
    /// Defaults derived from an agentd state directory, so an embedded
    /// daemon never writes outside its tempdir.
    pub fn under(state_dir: &Path, runtime_file: PathBuf, audit_path: PathBuf) -> LedgerConfig {
        LedgerConfig {
            dir: state_dir.join("agents/ledger"),
            runtime_file,
            audit_path,
            process_classes_path: PathBuf::from(PROCESS_CLASSES_PATH),
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            retention_days: LEDGER_RETENTION_DAYS,
        }
    }
}

/// What the registry knows about a session, as the ledger needs it. A
/// struct rather than seven positional arguments so a call site cannot
/// silently swap `agent` and `project`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionFacts {
    pub session_id: String,
    pub agent: String,
    pub user: String,
    pub project: String,
    pub classification: AgentClassification,
    /// The session's root pid — source D, used once to classify the
    /// agent's own process.
    pub process_id: u32,
    /// The scope's cgroup path as `/proc/<pid>/cgroup` reported it
    /// (`/user.slice/…/punar-agent-<id>.scope`), when the session is
    /// managed.
    pub scope_path: Option<String>,
    pub started_at: String,
}

/// An active session's in-memory aggregate. Only **active** sessions live
/// in RAM; an ended record lives on disk and is loaded on demand.
#[derive(Debug)]
struct ActiveLedger {
    record: LedgerRecord,
    /// `(pid, starttime)` pairs already counted. Memory only, dropped at
    /// compaction: a pid is not ledger data.
    seen: BTreeSet<(u32, u64)>,
    scope_path: Option<String>,
    /// Something worth persisting changed since the last write: a new
    /// process, a higher peak, or a new security-event reference.
    ///
    /// A sample that only *re-observes* what it already knows advances
    /// `last_seen` in memory without marking the record dirty — a read
    /// still gets the fresh value, and the disk is spared a write that
    /// says nothing new. This is the batching rule of spec 6.4 made
    /// concrete: writes follow facts, not passes.
    dirty: bool,
}

#[derive(Debug, Default)]
struct State {
    index: LedgerIndex,
    active: BTreeMap<String, ActiveLedger>,
}

/// The engine. One `Mutex` around all mutable ledger state; it is never
/// held across a call back into the registry, so it cannot deadlock
/// against the daemon's own lock.
pub struct LedgerEngine {
    cfg: LedgerConfig,
    table: ClassTable,
    cgroups: CgroupRoot,
    proc: ProcRoot,
    tail: AuditTail,
    store: LedgerStore,
    state: Mutex<State>,
    /// Group that may read the runtime view (`punar`), resolved once.
    runtime_gid: Option<u32>,
    /// Non-fatal load problems, printed once by the daemon at startup.
    pub warnings: Vec<String>,
}

impl LedgerEngine {
    /// Open the ledger: stage the directory, load the class table and the
    /// index. Never fails the daemon — a broken index costs the tail
    /// position (idempotence absorbs it), not the boot.
    pub fn open(cfg: LedgerConfig, proc: ProcRoot, runtime_gid: Option<u32>) -> LedgerEngine {
        let store = LedgerStore::new(&cfg.dir);
        let mut warnings = Vec::new();
        if let Err(e) = store.ensure_dir() {
            warnings.push(format!(
                "could not create the ledger directory {}: {e}",
                cfg.dir.display()
            ));
        }
        let table = ClassTable::load(&cfg.process_classes_path);
        warnings.extend(table.warnings.iter().cloned());
        let index = store.load_index();
        LedgerEngine {
            cgroups: CgroupRoot::new(&cfg.cgroup_root),
            tail: AuditTail::new(&cfg.audit_path),
            proc,
            store,
            state: Mutex::new(State {
                index,
                active: BTreeMap::new(),
            }),
            table,
            runtime_gid,
            warnings,
            cfg,
        }
    }

    pub fn dir(&self) -> &Path {
        self.store.dir()
    }

    pub fn audit_path(&self) -> &Path {
        self.tail.path()
    }

    // -- lifecycle -----------------------------------------------------

    /// Start a ledger for a session that has just registered.
    ///
    /// Seeds source **C** (the realized workspace grant: the project
    /// identity and the `workspace` zone) and source **D** (the class of
    /// the session's own root process), then takes the first cgroup
    /// sample. The zone is the *grant*, not a read: Punar records no
    /// per-read events, and declared-but-unrealized zones (`home`,
    /// `ssh`, `aws`) are **authority**, not ledger, and never appear
    /// here.
    pub fn begin_session(&self, facts: &SessionFacts, now: &str) {
        // C — the workspace grant. A session whose project did not
        // resolve gets neither row: the M7 `"unknown"` sentinel is a
        // *valid* class string, so it has to be excluded on purpose —
        // an unresolved project is not a repository the session reached,
        // and rendering it as one would be a small lie.
        //
        // This is also the ledger's project boundary. `agents.register`
        // does not pattern-check `project` (the registry-record schema
        // leaves it unpatterned), so a caller may send
        // `project: "/home/punar/clients/acme"`. It gets exactly one
        // chance to become a `ResourceClass`; if it cannot, nothing about
        // it — not a repository row, not the record's own `project`
        // field — reaches ledger storage.
        let resolved = (facts.project != PROJECT_UNRESOLVED)
            .then(|| ResourceClass::new(ResourceCategory::Repositories, &facts.project).ok())
            .flatten();

        let mut record = LedgerRecord::new(
            &facts.session_id,
            &facts.agent,
            &facts.user,
            resolved.clone(),
            facts.classification,
            &facts.started_at,
        );
        record.updated_at = now.to_string();

        if let Some(repository) = resolved {
            record.observe(
                ResourceCategory::Repositories,
                repository,
                1,
                Evidence::WorkspaceBind,
                now,
            );
            if let Ok(zone) = ResourceClass::new(ResourceCategory::DirectoryZones, ZONE_WORKSPACE) {
                record.observe(
                    ResourceCategory::DirectoryZones,
                    zone,
                    1,
                    Evidence::WorkspaceBind,
                    now,
                );
            }
        }

        let mut active = ActiveLedger {
            record,
            seen: BTreeSet::new(),
            scope_path: facts.scope_path.clone(),
            dirty: true,
        };

        // D — the agent's own root process, known from the registry
        // record rather than from a sample. Counted here and remembered,
        // so the first cgroup sample does not count it twice.
        if let Some(comm) = self.proc.comm_of(facts.process_id) {
            let starttime = self.proc.starttime_of(facts.process_id).unwrap_or(0);
            if active.seen.insert((facts.process_id, starttime)) {
                if let Ok(class) =
                    ResourceClass::new(ResourceCategory::ProcessClasses, self.table.class_of(&comm))
                {
                    active.record.observe(
                        ResourceCategory::ProcessClasses,
                        class,
                        1,
                        Evidence::AdapterMetadata,
                        now,
                    );
                }
            }
        }

        {
            let mut state = self.state.lock().unwrap();
            state.active.insert(facts.session_id.clone(), active);
        }
        self.sample_active(std::slice::from_ref(facts), now);
        self.flush(std::slice::from_ref(&facts.session_id), now);
    }

    /// Sample every named active session's scope cgroup, then drain the
    /// audit tail, then write once per changed session. The single
    /// refresh path — used by `agents.scan`, by every ledger read, and at
    /// startup, so no surface can show a staler view than another.
    /// Returns whether anything was persisted — the caller's cue to
    /// republish the panel's side file, and nothing more.
    pub fn refresh(&self, active: &[SessionFacts], now: &str) -> bool {
        self.sample_active(active, now);
        let drained = self.drain_audit(now);
        let ids: Vec<String> = active.iter().map(|f| f.session_id.clone()).collect();
        self.flush(&ids, now) || drained
    }

    /// Drain only — the cheap path a ledger read takes when it does not
    /// need a fresh cgroup sample.
    pub fn drain_audit(&self, now: &str) -> bool {
        let position = self.state.lock().unwrap().index.tail;
        let drained = self.tail.drain(position);
        if drained.references.is_empty() && drained.classes.is_empty() {
            // Still remember where we got to, so the next drain does not
            // re-read what it already skipped.
            let mut state = self.state.lock().unwrap();
            state.index.tail = drained.position;
            return false;
        }

        let mut ingested = false;
        let mut touched_on_disk: BTreeSet<String> = BTreeSet::new();
        {
            let mut state = self.state.lock().unwrap();
            state.index.tail = drained.position;
            for (session_id, reference) in drained.references {
                // The purge floor: a tombstoned session never ingests
                // again, so re-reading the same audit bytes can never
                // resurrect what the user deleted (milestone-8.md
                // section 10, guarantee 3).
                if state
                    .index
                    .row(&session_id)
                    .is_some_and(|row| row.is_tombstone())
                {
                    continue;
                }
                match state.active.get_mut(&session_id) {
                    Some(active) => {
                        if active.record.observe_security_event(reference) {
                            active.record.updated_at = now.to_string();
                            active.dirty = true;
                            ingested = true;
                        }
                    }
                    None => {
                        // An ended session can still be named by an event
                        // that landed after it ended; load, apply, write.
                        let Some(mut record) = self.store.load_record(&session_id) else {
                            continue;
                        };
                        if record.observe_security_event(reference) {
                            record.updated_at = now.to_string();
                            if let Err(e) = self.store.write_record(&record) {
                                eprintln!(
                                    "punar-agentd: could not update the ledger for \
                                     {session_id}: {e}"
                                );
                                continue;
                            }
                            state.index.upsert(index_row(&record));
                            touched_on_disk.insert(session_id);
                            ingested = true;
                        }
                    }
                }
            }

            // The Level-3 half (milestone-9.md section 9.2). M8 wired this
            // drain for Level-4 references only and left the
            // `Evidence::AuditEvent` variant declared-but-unused; an
            // allowed `credential.request` is the first — and in M9 the
            // only — audit event that names a *resource class* rather
            // than a security event. Same tombstone floor, same
            // active/ended split, same "write only if something changed"
            // rule as the loop above.
            for (session_id, class) in drained.classes {
                if state
                    .index
                    .row(&session_id)
                    .is_some_and(|row| row.is_tombstone())
                {
                    continue;
                }
                match state.active.get_mut(&session_id) {
                    Some(active) => {
                        if active.record.observe(
                            ResourceCategory::CredentialClasses,
                            class,
                            1,
                            Evidence::AuditEvent,
                            now,
                        ) {
                            active.record.updated_at = now.to_string();
                            active.dirty = true;
                            ingested = true;
                        }
                    }
                    None => {
                        let Some(mut record) = self.store.load_record(&session_id) else {
                            continue;
                        };
                        if record.observe(
                            ResourceCategory::CredentialClasses,
                            class,
                            1,
                            Evidence::AuditEvent,
                            now,
                        ) {
                            record.updated_at = now.to_string();
                            if let Err(e) = self.store.write_record(&record) {
                                eprintln!(
                                    "punar-agentd: could not update the ledger for \
                                     {session_id}: {e}"
                                );
                                continue;
                            }
                            state.index.upsert(index_row(&record));
                            touched_on_disk.insert(session_id);
                            ingested = true;
                        }
                    }
                }
            }
        }
        if !touched_on_disk.is_empty() {
            self.write_index(now);
        }
        ingested
    }

    /// One cgroup sample per named active session (source A).
    fn sample_active(&self, active: &[SessionFacts], now: &str) {
        for facts in active {
            let scope_path = {
                let state = self.state.lock().unwrap();
                state
                    .active
                    .get(&facts.session_id)
                    .and_then(|entry| entry.scope_path.clone())
                    .or_else(|| facts.scope_path.clone())
            };
            let sample = sample_scope(
                &self.cgroups,
                &self.proc,
                &self.table,
                scope_path.as_deref(),
                &facts.session_id,
            );
            let concurrent = sample.processes.len() as u64;

            let mut state = self.state.lock().unwrap();
            let Some(entry) = state.active.get_mut(&facts.session_id) else {
                continue;
            };
            for (index, key) in sample.processes.iter().enumerate() {
                if !entry.seen.insert(*key) {
                    // Already counted: refresh the window, never the
                    // count. Sampling the same process twice is not a
                    // second process.
                    let class = &sample.classes[index];
                    if let Ok(class) = ResourceClass::new(ResourceCategory::ProcessClasses, class) {
                        entry.record.observe(
                            ResourceCategory::ProcessClasses,
                            class,
                            0,
                            Evidence::CgroupScope,
                            now,
                        );
                    }
                    continue;
                }
                let Ok(class) =
                    ResourceClass::new(ResourceCategory::ProcessClasses, &sample.classes[index])
                else {
                    continue;
                };
                entry.record.observe(
                    ResourceCategory::ProcessClasses,
                    class,
                    1,
                    Evidence::CgroupScope,
                    now,
                );
                entry.dirty = true;
            }
            // `pids.peak` when the kernel exposes it; otherwise the
            // largest concurrency actually observed, which is an honest
            // lower bound rather than an invented number.
            let peak = sample.peak.unwrap_or(concurrent);
            if peak > entry.record.process_peak {
                entry.record.process_peak = peak;
                entry.dirty = true;
            }
            entry.record.updated_at = now.to_string();
        }
    }

    /// Compact and close a session's ledger (milestone-8.md section 6.2).
    ///
    /// Last sample, last drain, then: drop the pid dedup set, sort the
    /// entries for stable rendering, stamp `ended_at` and
    /// `retention_expires_at = ended_at + 14 days`, write once, and leave
    /// memory. An ended record is never rewritten again except by purge
    /// or prune.
    pub fn end_session(&self, facts: &SessionFacts, now: &str) {
        self.sample_active(std::slice::from_ref(facts), now);
        self.drain_audit(now);

        let record = {
            let mut state = self.state.lock().unwrap();
            let Some(mut entry) = state.active.remove(&facts.session_id) else {
                return;
            };
            entry.seen.clear();
            entry.record.status = AgentStatus::Ended;
            entry.record.ended_at = Some(now.to_string());
            entry.record.updated_at = now.to_string();
            entry.record.retention_expires_at = plus_days(now, self.cfg.retention_days);
            entry.record.sort_entries();
            entry.record
        };
        if let Err(e) = self.store.write_record(&record) {
            eprintln!(
                "punar-agentd: could not write the final ledger for {}: {e}",
                record.session_id
            );
            return;
        }
        {
            let mut state = self.state.lock().unwrap();
            state.index.upsert(index_row(&record));
        }
        self.write_index(now);
    }

    /// One retention prune batch. Event-driven only: startup, every
    /// `agents.scan` pass, and `agents.end`.
    pub fn prune(&self, now: &str, active_ids: &[String]) -> PruneOutcome {
        let outcome = {
            let mut state = self.state.lock().unwrap();
            crate::ledger::store::prune(&self.store, &mut state.index, now, active_ids)
        };
        if !outcome.is_empty() {
            self.write_index(now);
        }
        outcome
    }

    // -- reads ---------------------------------------------------------

    /// The record for a session: from memory when it is active, from disk
    /// when it has ended, and a **purged** shell when the user deleted it
    /// — never `None` for a session the index remembers, because "purged"
    /// and "nothing recorded" must not look alike.
    pub fn record_of(&self, session_id: &str) -> Option<LedgerRecord> {
        {
            let state = self.state.lock().unwrap();
            if let Some(entry) = state.active.get(session_id) {
                return Some(entry.record.clone());
            }
            if let Some(row) = state.index.row(session_id) {
                if let Some(purged_at) = row.purged_at.clone() {
                    let record = LedgerRecord {
                        v: LEDGER_RECORD_VERSION,
                        session_id: session_id.to_string(),
                        agent: String::new(),
                        user: row.user.clone(),
                        project: None,
                        classification: row.classification,
                        status: AgentStatus::Ended,
                        started_at: row.first_seen.clone(),
                        ended_at: None,
                        updated_at: row.updated_at.clone(),
                        purged_at: Some(purged_at),
                        retention_expires_at: row.retention_expires_at.clone(),
                        process_peak: 0,
                        truncated: false,
                        entries: Vec::new(),
                        security_events: Vec::new(),
                    };
                    return Some(record);
                }
            }
        }
        self.store.load_record(session_id)
    }

    /// The username that owns a session's ledger, for the owner-or-root
    /// authorization of `agents.access` and `ledger.purge`. Read from the
    /// index so a session from a previous boot is still answerable.
    pub fn owner_of(&self, session_id: &str) -> Option<String> {
        let state = self.state.lock().unwrap();
        state
            .active
            .get(session_id)
            .map(|entry| entry.record.user.clone())
            .or_else(|| state.index.row(session_id).map(|row| row.user.clone()))
    }

    /// Whether the ledger knows this session at all (including as a
    /// tombstone).
    pub fn knows(&self, session_id: &str) -> bool {
        let state = self.state.lock().unwrap();
        state.active.contains_key(session_id) || state.index.row(session_id).is_some()
    }

    /// The counts-only fingerprints `agents.list` serves (section 12.4).
    pub fn fingerprints(&self) -> BTreeMap<String, LedgerFingerprint> {
        let state = self.state.lock().unwrap();
        let mut out: BTreeMap<String, LedgerFingerprint> = state
            .index
            .sessions
            .iter()
            .filter(|row| !row.is_tombstone())
            .map(|row| {
                (
                    row.session_id.clone(),
                    LedgerFingerprint {
                        counts: row.counts,
                        updated_at: row.updated_at.clone(),
                    },
                )
            })
            .collect();
        // Active sessions are fresher in memory than in the index.
        for (session_id, entry) in &state.active {
            out.insert(session_id.clone(), entry.record.fingerprint());
        }
        out
    }

    /// Session ids owned by `user`, for a non-root `ledger.purge --all`.
    pub fn sessions_of(&self, user: &str) -> Vec<String> {
        let state = self.state.lock().unwrap();
        state
            .index
            .sessions
            .iter()
            .filter(|row| !row.is_tombstone() && row.user == user)
            .map(|row| row.session_id.clone())
            .collect()
    }

    /// Every non-tombstoned session the ledger holds (root's `--all`).
    pub fn all_sessions(&self) -> Vec<String> {
        let state = self.state.lock().unwrap();
        state
            .index
            .sessions
            .iter()
            .filter(|row| !row.is_tombstone())
            .map(|row| row.session_id.clone())
            .collect()
    }

    // -- deletion ------------------------------------------------------

    /// Delete the named ledgers.
    ///
    /// The file is unlinked and the index row becomes a tombstone. The
    /// audit trail is **not** touched: spec section 53's log is the
    /// record of decisions the system made and is outside a user's delete
    /// authority; the ledger, derived from it, is not. Every purge
    /// surface prints that boundary in one sentence.
    pub fn purge(&self, session_ids: &[String], now: &str) -> LedgerPurgeResult {
        let mut result = LedgerPurgeResult {
            purged: 0,
            resource_classes: 0,
            security_events: 0,
        };
        {
            let mut state = self.state.lock().unwrap();
            for session_id in session_ids {
                let counts = state
                    .active
                    .get(session_id)
                    .map(|entry| entry.record.counts())
                    .or_else(|| state.index.row(session_id).map(|row| row.counts));
                let Some(counts) = counts else {
                    continue;
                };
                if state
                    .index
                    .row(session_id)
                    .is_some_and(|row| row.is_tombstone())
                {
                    continue;
                }
                state.active.remove(session_id);
                if let Err(e) = self.store.remove_record(session_id) {
                    eprintln!("punar-agentd: could not delete the ledger for {session_id}: {e}");
                    continue;
                }
                let row = match state.index.row(session_id) {
                    Some(row) => tombstone_row(row, now),
                    None => tombstone_row(
                        &punar_common::ledger::LedgerIndexRow {
                            session_id: session_id.clone(),
                            agent: None,
                            project: None,
                            user: String::new(),
                            classification: AgentClassification::Managed,
                            status: AgentStatus::Ended,
                            first_seen: now.to_string(),
                            last_seen: now.to_string(),
                            updated_at: now.to_string(),
                            retention_expires_at: None,
                            purged_at: None,
                            counts,
                        },
                        now,
                    ),
                };
                state.index.upsert(row);
                result.purged += 1;
                result.resource_classes += counts.resources;
                result.security_events += counts.security_events;
            }
        }
        if result.purged > 0 {
            self.write_index(now);
        }
        result
    }

    // -- publication ---------------------------------------------------

    /// Rewrite `/run/punar-agentd/ledger.json` for the sessions the panel
    /// currently shows (docs/api/ipc.md section 13.2).
    ///
    /// `0640 root:punar` inside the **root-owned** agentd runtime
    /// directory: only the socket's own admission set may read a ledger,
    /// and because the directory is root-owned a local user cannot unlink
    /// the file and substitute a forgery. Best effort by contract — the
    /// panel fails closed on a missing file, and a failure here never
    /// fails a request.
    pub fn write_runtime_view(&self, session_ids: &[String], now: &str) {
        let sessions: Vec<AgentsAccessResult> = session_ids
            .iter()
            .filter_map(|id| self.record_of(id))
            .map(|record| AgentsAccessResult::from_record(&record, now))
            .collect();
        let file = LedgerRuntimeFile {
            v: LEDGER_RECORD_VERSION,
            ts: now.to_string(),
            sessions,
        };
        let Ok(mut bytes) = serde_json::to_vec(&file) else {
            return;
        };
        bytes.push(b'\n');
        if let Some(parent) = self.cfg.runtime_file.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("punar-agentd: could not create {}: {e}", parent.display());
                return;
            }
        }
        if let Err(e) = crate::util::write_atomic(&self.cfg.runtime_file, &bytes, 0o640) {
            eprintln!(
                "punar-agentd: could not write {}: {e} (the AI panel will render its \
                 last known state, or none)",
                self.cfg.runtime_file.display()
            );
            return;
        }
        if let Some(gid) = self.runtime_gid {
            // root:punar — meaningful only as root, harmless otherwise.
            let _ = std::os::unix::fs::chown(&self.cfg.runtime_file, Some(0), Some(gid));
        }
    }

    // -- persistence ---------------------------------------------------

    /// Write the named sessions' records **once** and then the index
    /// once: the batching rule (spec 6.4) lives here, and nowhere else
    /// writes a record file.
    fn flush(&self, session_ids: &[String], now: &str) -> bool {
        let mut wrote = false;
        {
            let mut state = self.state.lock().unwrap();
            let records: Vec<LedgerRecord> = session_ids
                .iter()
                .filter_map(|id| {
                    state
                        .active
                        .get(id)
                        .filter(|entry| entry.dirty)
                        .map(|entry| entry.record.clone())
                })
                .collect();
            for record in records {
                if let Err(e) = self.store.write_record(&record) {
                    eprintln!(
                        "punar-agentd: could not write the ledger for {}: {e}",
                        record.session_id
                    );
                    continue;
                }
                if let Some(entry) = state.active.get_mut(&record.session_id) {
                    entry.dirty = false;
                }
                state.index.upsert(index_row(&record));
                wrote = true;
            }
        }
        if wrote {
            self.write_index(now);
        }
        wrote
    }

    fn write_index(&self, now: &str) {
        let index = {
            let mut state = self.state.lock().unwrap();
            state.index.updated_at = now.to_string();
            state.index.clone()
        };
        if let Err(e) = self.store.write_index(&index) {
            eprintln!("punar-agentd: could not write the ledger index: {e}");
        }
    }

    /// Restore the in-memory aggregates for sessions the registry
    /// replayed as still active, so a restarted daemon keeps aggregating
    /// into the same records rather than starting a second one.
    pub fn resume(&self, active: &[SessionFacts]) {
        let mut state = self.state.lock().unwrap();
        for facts in active {
            if state.active.contains_key(&facts.session_id) {
                continue;
            }
            if state
                .index
                .row(&facts.session_id)
                .is_some_and(|row| row.is_tombstone())
            {
                continue;
            }
            let Some(record) = self.store.load_record(&facts.session_id) else {
                continue;
            };
            state.active.insert(
                facts.session_id.clone(),
                ActiveLedger {
                    record,
                    // The pid dedup set is memory only and did not
                    // survive the restart. Counts therefore resume from
                    // the current sample; the alternative — persisting
                    // pids — would put process ids in the ledger, which
                    // spec 21.2 does not allow.
                    seen: BTreeSet::new(),
                    scope_path: facts.scope_path.clone(),
                    dirty: false,
                },
            );
        }
    }

    /// The current audit tail position (diagnostics and tests).
    pub fn tail_position(&self) -> TailPosition {
        self.state.lock().unwrap().index.tail
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::{
        fake_process, fixture_cgroup_scope, fixture_proc, kill_process, managed_cgroup, temp_dir,
    };
    use punar_common::audit::AuditWriter;
    use punar_common::ledger::{LedgerSummary, SecurityEventType};
    use punar_common::{AuditEvent, Decision, PrincipalKind};

    const SESSION: &str = "agt_4f21c09ab3e1";

    struct Harness {
        dir: PathBuf,
        proc_root: PathBuf,
        engine: LedgerEngine,
        audit: PathBuf,
    }

    fn harness(tag: &str) -> Harness {
        let dir = temp_dir(tag);
        let proc_root = fixture_proc(&format!("{tag}-proc"));
        let audit = dir.join("audit.jsonl");
        let cfg = LedgerConfig {
            dir: dir.join("ledger"),
            runtime_file: dir.join("run/ledger.json"),
            audit_path: audit.clone(),
            process_classes_path: dir.join("absent-classes.json"),
            cgroup_root: dir.join("cgroup"),
            retention_days: LEDGER_RETENTION_DAYS,
        };
        let engine = LedgerEngine::open(cfg, ProcRoot::new(&proc_root), None);
        Harness {
            dir,
            proc_root,
            engine,
            audit,
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
            let _ = std::fs::remove_dir_all(&self.proc_root);
        }
    }

    fn facts(scope_path: Option<String>) -> SessionFacts {
        SessionFacts {
            session_id: SESSION.to_string(),
            agent: "claude-code".to_string(),
            user: "punar".to_string(),
            project: "atlas".to_string(),
            classification: AgentClassification::Managed,
            process_id: 2143,
            scope_path,
            started_at: "2026-08-27T09:58:40Z".to_string(),
        }
    }

    fn spawn(root: &Path, pid: u32, comm: &str) {
        fake_process(
            root,
            pid,
            comm,
            "/usr/lib/punar/punar-mock-agent",
            &["/usr/lib/punar/punar-mock-agent"],
            1000,
            &managed_cgroup(SESSION),
        );
    }

    fn audit_event(id: &str, session: &str, action: &str, decision: Decision) -> AuditEvent {
        AuditEvent {
            event_id: id.to_string(),
            timestamp: "2026-08-27T09:59:12Z".to_string(),
            device_id: "dev_test".to_string(),
            user_id: Some("punar".to_string()),
            agent_session_id: Some(session.to_string()),
            project_id: Some("atlas".to_string()),
            source: PrincipalKind::AiAgent,
            action: action.to_string(),
            resource: Some("security.firewall".to_string()),
            decision,
            policy_ids: vec!["personal-defaults".to_string()],
            result: "denied".to_string(),
        }
    }

    #[test]
    fn a_session_ledger_aggregates_the_four_owned_sources() {
        let h = harness("ledger-aggregate");
        spawn(&h.proc_root, 2143, "punar-mock-agent");
        spawn(&h.proc_root, 2200, "git");
        spawn(&h.proc_root, 2201, "bash");
        let scope =
            fixture_cgroup_scope(&h.dir.join("cgroup"), SESSION, &[2143, 2200, 2201], Some(6));
        let facts = facts(Some(scope));

        h.engine.begin_session(&facts, "2026-08-27T09:58:40Z");

        // B — a denial attributed to this session by punard.
        let mut writer = AuditWriter::open(&h.audit).unwrap();
        writer
            .append(&audit_event(
                "evt_502",
                SESSION,
                "capabilities.set",
                Decision::Deny,
            ))
            .unwrap();
        // …and one that belongs to nobody.
        writer
            .append(&audit_event(
                "evt_503",
                punar_common::audit::AGENT_SESSION_NONE,
                "capabilities.set",
                Decision::Deny,
            ))
            .unwrap();
        h.engine
            .refresh(std::slice::from_ref(&facts), "2026-08-27T10:00:02Z");

        let record = h.engine.record_of(SESSION).unwrap();
        let classes: Vec<&str> = record
            .entries
            .iter()
            .filter(|e| e.category == ResourceCategory::ProcessClasses)
            .map(|e| e.resource_class.as_str())
            .collect();
        assert!(classes.contains(&"git"), "{classes:?}");
        assert!(classes.contains(&"shell"), "{classes:?}");
        assert!(classes.contains(&"agent"), "{classes:?}");
        assert_eq!(record.process_peak, 6, "pids.peak, not a spawn count");

        // C — the workspace grant, as a zone and a project identity.
        let summary: LedgerSummary = record.summary("2026-08-27T10:00:02Z");
        assert_eq!(
            summary
                .resources
                .repositories
                .iter()
                .map(ResourceClass::as_str)
                .collect::<Vec<_>>(),
            vec!["atlas"]
        );
        assert_eq!(
            summary
                .resources
                .directory_zones
                .iter()
                .map(ResourceClass::as_str)
                .collect::<Vec<_>>(),
            vec!["workspace"]
        );
        // The three categories with no producer stay honestly empty.
        assert!(summary.resources.network_destinations.is_empty());
        assert!(summary.resources.mcp_servers.is_empty());
        assert!(summary.resources.credential_classes.is_empty());

        // B — the reference, and only the reference.
        assert_eq!(summary.security_events.len(), 1);
        assert_eq!(summary.security_events[0].event_id, "evt_502");
        assert_eq!(
            summary.security_events[0].event_type,
            SecurityEventType::DeniedAccess
        );

        // Every evidence value is one of the four owned mediation points.
        for entry in &record.entries {
            assert!(Evidence::ALL.contains(&entry.evidence));
        }
    }

    /// The count is *distinct processes observed alive*, not a sample
    /// count: sampling the same three processes twice must not report
    /// six.
    #[test]
    fn resampling_the_same_processes_does_not_inflate_the_count() {
        let h = harness("ledger-resample");
        spawn(&h.proc_root, 2143, "punar-mock-agent");
        spawn(&h.proc_root, 2200, "git");
        let scope = fixture_cgroup_scope(&h.dir.join("cgroup"), SESSION, &[2143, 2200], Some(2));
        let facts = facts(Some(scope.clone()));
        h.engine.begin_session(&facts, "2026-08-27T09:58:40Z");
        for _ in 0..5 {
            h.engine
                .refresh(std::slice::from_ref(&facts), "2026-08-27T10:00:02Z");
        }
        let record = h.engine.record_of(SESSION).unwrap();
        let git = record
            .entries
            .iter()
            .find(|e| e.resource_class.as_str() == "git")
            .unwrap();
        assert_eq!(git.count, 1, "one git process was seen, five times");
        assert_eq!(git.first_seen, "2026-08-27T09:58:40Z");
        assert_eq!(git.last_seen, "2026-08-27T10:00:02Z");

        // A *different* git process (new pid) does count.
        spawn(&h.proc_root, 2300, "git");
        fixture_cgroup_scope(&h.dir.join("cgroup"), SESSION, &[2143, 2200, 2300], Some(3));
        h.engine
            .refresh(std::slice::from_ref(&facts), "2026-08-27T10:01:00Z");
        let record = h.engine.record_of(SESSION).unwrap();
        let git = record
            .entries
            .iter()
            .find(|e| e.resource_class.as_str() == "git")
            .unwrap();
        assert_eq!(git.count, 2);
    }

    #[test]
    fn ending_a_session_compacts_and_stamps_the_retention_deadline() {
        let h = harness("ledger-end");
        spawn(&h.proc_root, 2143, "punar-mock-agent");
        let scope = fixture_cgroup_scope(&h.dir.join("cgroup"), SESSION, &[2143], Some(1));
        let facts = facts(Some(scope));
        h.engine.begin_session(&facts, "2026-08-27T09:58:40Z");
        h.engine.end_session(&facts, "2026-08-27T10:30:00Z");

        let record = h.engine.record_of(SESSION).unwrap();
        assert_eq!(record.status, AgentStatus::Ended);
        assert_eq!(record.ended_at.as_deref(), Some("2026-08-27T10:30:00Z"));
        assert_eq!(
            record.retention_expires_at.as_deref(),
            Some("2026-09-10T10:30:00Z"),
            "14 days after ended_at, to the second"
        );
        // Entries are in stable rendering order.
        let categories: Vec<&str> = record.entries.iter().map(|e| e.category.as_str()).collect();
        let mut sorted = categories.clone();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            categories.iter().collect::<BTreeSet<_>>().len()
        );
    }

    #[test]
    fn retention_prunes_a_backdated_ledger_and_spares_the_active_one() {
        let h = harness("ledger-retention");
        spawn(&h.proc_root, 2143, "punar-mock-agent");
        let scope = fixture_cgroup_scope(&h.dir.join("cgroup"), SESSION, &[2143], Some(1));
        let facts = facts(Some(scope));
        h.engine.begin_session(&facts, "2026-08-27T09:58:40Z");

        // A second, long-ended session, backdated 30 days.
        let old = SessionFacts {
            session_id: "agt_old000000001".into(),
            ..facts.clone()
        };
        h.engine.begin_session(&old, "2026-07-28T09:00:00Z");
        h.engine.end_session(&old, "2026-07-28T09:30:00Z");

        let outcome = h
            .engine
            .prune("2026-08-27T10:00:00Z", &[SESSION.to_string()]);
        assert_eq!(outcome.expired, vec!["agt_old000000001".to_string()]);
        assert!(h.engine.record_of("agt_old000000001").is_none());
        assert!(h.engine.record_of(SESSION).is_some());
        assert_eq!(outcome.batches(), vec![("expired", 1)]);
    }

    #[test]
    fn purge_deletes_the_file_leaves_a_tombstone_and_cannot_be_undone() {
        let h = harness("ledger-purge");
        spawn(&h.proc_root, 2143, "punar-mock-agent");
        let scope = fixture_cgroup_scope(&h.dir.join("cgroup"), SESSION, &[2143], Some(1));
        let facts = facts(Some(scope));
        h.engine.begin_session(&facts, "2026-08-27T09:58:40Z");

        let mut writer = AuditWriter::open(&h.audit).unwrap();
        writer
            .append(&audit_event(
                "evt_502",
                SESSION,
                "capabilities.set",
                Decision::Deny,
            ))
            .unwrap();
        h.engine
            .refresh(std::slice::from_ref(&facts), "2026-08-27T10:00:02Z");
        assert_eq!(
            h.engine.record_of(SESSION).unwrap().security_events.len(),
            1
        );

        let audit_before = std::fs::read_to_string(&h.audit).unwrap();
        let result = h
            .engine
            .purge(&[SESSION.to_string()], "2026-08-27T11:00:00Z");
        assert_eq!(result.purged, 1);
        assert!(result.resource_classes >= 3);
        assert_eq!(result.security_events, 1);

        // The file is gone…
        assert!(
            !h.engine.dir().join(format!("{SESSION}.json")).exists(),
            "the record file was not unlinked"
        );
        // …the answer says *purged*, not "nothing recorded"…
        let record = h.engine.record_of(SESSION).unwrap();
        assert!(record.is_purged());
        assert!(record.entries.is_empty());
        // …the tombstone carries no resource data…
        let index_text = std::fs::read_to_string(h.engine.dir().join("index.json")).unwrap();
        assert!(!index_text.contains("atlas"), "{index_text}");
        assert!(!index_text.contains("evt_502"), "{index_text}");
        // …the audit trail is untouched (spec 53 — not the user's to
        // delete)…
        assert_eq!(std::fs::read_to_string(&h.audit).unwrap(), audit_before);
        assert!(audit_before.contains("evt_502"));

        // …and a later drain that re-reads the same bytes cannot
        // resurrect it.
        {
            let mut state = h.engine.state.lock().unwrap();
            state.index.tail = TailPosition::default();
        }
        h.engine.drain_audit("2026-08-27T11:05:00Z");
        assert!(!h.engine.dir().join(format!("{SESSION}.json")).exists());
        assert!(h.engine.record_of(SESSION).unwrap().is_purged());
    }

    #[test]
    fn purge_scoping_answers_per_user() {
        let h = harness("ledger-purge-scope");
        spawn(&h.proc_root, 2143, "punar-mock-agent");
        let mine = facts(None);
        let theirs = SessionFacts {
            session_id: "agt_other000001".into(),
            user: "root".into(),
            ..facts(None)
        };
        h.engine.begin_session(&mine, "2026-08-27T09:58:40Z");
        h.engine.begin_session(&theirs, "2026-08-27T09:58:40Z");

        assert_eq!(h.engine.sessions_of("punar"), vec![SESSION.to_string()]);
        assert_eq!(h.engine.all_sessions().len(), 2);
        assert_eq!(h.engine.owner_of(SESSION).as_deref(), Some("punar"));
        assert_eq!(
            h.engine.owner_of("agt_other000001").as_deref(),
            Some("root")
        );
        assert_eq!(h.engine.owner_of("agt_absent00001"), None);
    }

    #[test]
    fn the_fingerprint_is_counts_only_and_tracks_the_live_aggregate() {
        let h = harness("ledger-fingerprint");
        spawn(&h.proc_root, 2143, "punar-mock-agent");
        spawn(&h.proc_root, 2200, "git");
        let scope = fixture_cgroup_scope(&h.dir.join("cgroup"), SESSION, &[2143, 2200], Some(2));
        let facts = facts(Some(scope));
        h.engine.begin_session(&facts, "2026-08-27T09:58:40Z");

        let prints = h.engine.fingerprints();
        let print = prints.get(SESSION).unwrap();
        assert_eq!(print.counts.process_classes, 2);
        assert_eq!(print.counts.resources, 4);
        assert_eq!(print.counts.security_events, 0);
        let text = serde_json::to_string(&prints).unwrap();
        for leak in ["git", "atlas", "workspace", "agent\"", "evt_"] {
            assert!(
                !text.contains(leak),
                "{leak} leaked into the fingerprint: {text}"
            );
        }
    }

    #[test]
    fn the_runtime_view_is_root_owned_and_carries_the_same_rows_as_the_socket() {
        let h = harness("ledger-runtime");
        spawn(&h.proc_root, 2143, "punar-mock-agent");
        let scope = fixture_cgroup_scope(&h.dir.join("cgroup"), SESSION, &[2143], Some(1));
        let facts = facts(Some(scope));
        h.engine.begin_session(&facts, "2026-08-27T09:58:40Z");
        h.engine
            .write_runtime_view(&[SESSION.to_string()], "2026-08-27T10:00:02Z");

        let path = h.dir.join("run/ledger.json");
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&path).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o640, "a ledger is not world-readable");
        let file: LedgerRuntimeFile =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(file.sessions.len(), 1);
        let view = &file.sessions[0];
        assert_eq!(view.summary.session_id, SESSION);
        assert_eq!(
            view.not_yet_observed.len(),
            punar_common::ledger::not_yet_observed().len(),
            "the honesty rows travel too"
        );
        assert!(view.privacy.local_only);
        assert_eq!(view.retention.days, LEDGER_RETENTION_DAYS);
    }

    #[test]
    fn a_session_whose_project_did_not_resolve_claims_no_repository() {
        let h = harness("ledger-unknown-project");
        spawn(&h.proc_root, 2143, "punar-mock-agent");
        let facts = SessionFacts {
            project: PROJECT_UNRESOLVED.into(),
            ..facts(None)
        };
        h.engine.begin_session(&facts, "2026-08-27T09:58:40Z");
        let record = h.engine.record_of(SESSION).unwrap();
        // "unknown" is a syntactically valid class string, so a naive
        // check would happily record it as a repository named "unknown".
        assert!(
            !record
                .entries
                .iter()
                .any(|e| e.category == ResourceCategory::Repositories),
            "an unresolved project is not a repository"
        );
        assert!(
            !record
                .entries
                .iter()
                .any(|e| e.category == ResourceCategory::DirectoryZones),
            "no resolved project means no realized workspace grant"
        );
    }

    #[test]
    fn a_dead_scope_degrades_to_the_proc_walk_without_inventing_a_peak() {
        let h = harness("ledger-noscope");
        spawn(&h.proc_root, 2143, "punar-mock-agent");
        spawn(&h.proc_root, 2200, "git");
        let facts = facts(None); // no cgroup path at all
        h.engine.begin_session(&facts, "2026-08-27T09:58:40Z");
        let record = h.engine.record_of(SESSION).unwrap();
        let classes: BTreeSet<&str> = record
            .entries
            .iter()
            .filter(|e| e.category == ResourceCategory::ProcessClasses)
            .map(|e| e.resource_class.as_str())
            .collect();
        assert!(classes.contains("git"), "{classes:?}");
        assert_eq!(record.process_peak, 2, "the observed lower bound, honestly");

        // The processes go away; the record keeps what it saw.
        kill_process(&h.proc_root, 2200);
        h.engine
            .refresh(std::slice::from_ref(&facts), "2026-08-27T10:00:02Z");
        let record = h.engine.record_of(SESSION).unwrap();
        assert!(
            record
                .entries
                .iter()
                .any(|e| e.resource_class.as_str() == "git")
        );
    }

    #[test]
    fn a_restarted_daemon_resumes_the_same_record() {
        let h = harness("ledger-resume");
        spawn(&h.proc_root, 2143, "punar-mock-agent");
        let facts = facts(None);
        h.engine.begin_session(&facts, "2026-08-27T09:58:40Z");

        // A second engine over the same directory is the restart.
        let cfg = LedgerConfig {
            dir: h.dir.join("ledger"),
            runtime_file: h.dir.join("run/ledger.json"),
            audit_path: h.audit.clone(),
            process_classes_path: h.dir.join("absent-classes.json"),
            cgroup_root: h.dir.join("cgroup"),
            retention_days: LEDGER_RETENTION_DAYS,
        };
        let restarted = LedgerEngine::open(cfg, ProcRoot::new(&h.proc_root), None);
        restarted.resume(std::slice::from_ref(&facts));
        let record = restarted.record_of(SESSION).unwrap();
        assert_eq!(record.started_at, "2026-08-27T09:58:40Z");
        assert!(
            record
                .entries
                .iter()
                .any(|e| e.category == ResourceCategory::Repositories)
        );
        assert!(restarted.knows(SESSION));
    }
}
