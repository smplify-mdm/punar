//! Live organization-policy refresh (docs/api/ipc.md sections 5.6 and 5.10;
//! docs/development/milestone-5.md section 5.1).
//!
//! Every `reconcile` call while enrolled — the two-minute timer's and a
//! root administrator's — first asks the control plane for the
//! organization's policy, and a changed set is enforced by that same pass
//! (SPEC section 42: load desired state, then diff). Not at boot, where the
//! network and the agent may not be up yet and the socket must not wait,
//! and not in `enroll.start`'s or `enroll.stop`'s own pass.
//!
//! What it may never do:
//!
//! - **partially apply.** A set is checked whole and swapped in whole
//!   ([`crate::policy_set`]); anything short of that leaves `policy.d`, the
//!   rendered browser document, the in-memory layers and the effective
//!   document exactly as they were (SPEC section 55: the last valid policy
//!   stays enforceable).
//! - **withdraw on anything but an explicit answer.** An empty list takes the
//!   organization's policy away only when the control plane says
//!   `assignment: "none"`; unreachable, refused, unusable or unstated keeps
//!   the last good set.
//! - **change the enrollment's terms.** Only the fields
//!   [`crate::enroll::PolicyFields`] names are written, and `org.discover` is
//!   never called: removability, ownership and the remote-query grant are the
//!   ones the person agreed to at enrollment.
//!
//! A child module of [`super`], like `m9`: the refresh is `Inner` work — the
//! enrollment slot, the policy layers, the effective document and the audit
//! writer are the daemon's private state.

use crate::browser_policy::CAPABILITY_ID as BROWSER_POLICY_CAPABILITY;
use crate::enroll::{
    Assignment, FetchedPolicy, PendingPolicyChange, PolicyFields, apply_policy_fields,
};

use super::*;

/// What a policy refresh did: `enroll.status`'s `policy.last_refresh.result`
/// and the `enroll.policy` audit event's `result`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RefreshResult {
    /// The fetched set is the one the device enforces.
    Unchanged,
    /// A new non-empty set is enforced.
    Applied,
    /// The organization assigned nothing (`assignment: none`), and the set it
    /// had is gone.
    Withdrawn,
    /// The organization's set failed a check; the last good one is enforced.
    Rejected,
    /// The answer carried nothing the device may act on (an empty list the
    /// control plane could not vouch for); the last good set is enforced.
    Held,
    /// The control plane did not answer.
    Unreachable,
    /// The control plane answered with an error.
    Refused,
    /// The set may be fine, and this device could not install it.
    Failed,
}

impl RefreshResult {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            RefreshResult::Unchanged => "unchanged",
            RefreshResult::Applied => "applied",
            RefreshResult::Withdrawn => "withdrawn",
            RefreshResult::Rejected => "rejected",
            RefreshResult::Held => "held",
            RefreshResult::Unreachable => "unreachable",
            RefreshResult::Refused => "refused",
            RefreshResult::Failed => "failed",
        }
    }
}

/// What one refresh opportunity recorded, and whether the next ones back
/// off ([`RefreshBackoff`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Refreshed {
    pub(super) result: RefreshResult,
    backs_off: bool,
}

impl Refreshed {
    /// Only a failure that may clear by itself backs off: an I/O error on
    /// this device, or a root drop changed while the set was installed.
    fn of(result: RefreshResult, reason: Option<&str>) -> Refreshed {
        Refreshed {
            result,
            backs_off: result == RefreshResult::Failed
                && matches!(reason, Some("io" | "local_files_changed")),
        }
    }
}

/// The three results that mean "enforcing what the organization serves".
fn is_current(result: &str) -> bool {
    matches!(result, "unchanged" | "applied" | "withdrawn")
}

/// `held`: the control plane says something is assigned that it could not
/// turn into Punar policy.
pub(super) const REASON_UNUSABLE_ASSIGNMENT: &str = "unusable_assignment";

/// `rejected`: the answer carrying the set was longer than punard reads
/// (`crate::enroll::MAX_ANSWER_BYTES`). The control plane is up, and serves a
/// set no device will take.
pub(super) const REASON_ANSWER_TOO_LARGE: &str = "answer_too_large";

/// `held`: an empty list from a control plane that does not say what it
/// means. It may be "nothing assigned"; it may be a bundle it could not read.
const REASON_UNSTATED_EMPTY: &str = "unstated_empty";

/// `held`: an empty list marked `policies`. Only `none` withdraws; an empty
/// "here is the policy" is more likely a fault than a decision.
const REASON_EMPTY_POLICIES: &str = "empty_policies";

/// A refusal's code, folded into a closed set: the control plane chooses the
/// code, and `enroll.status` repeats only words this build knows.
fn refused_reason(code: &str) -> &'static str {
    match code {
        "unauthorized" => "unauthorized",
        "not_found" => "not_found",
        "internal" => "internal",
        _ => "other",
    }
}

/// The most passes a failing fetch is skipped for: with the timer's two
/// minutes, about half an hour between attempts.
const MAX_REFRESH_SKIP: u32 = 15;

/// How often a failing fetch is retried (SPEC section 42 "retry/backoff").
/// Counted in refresh opportunities rather than wall time, so it is
/// deterministic and the timer's jitter cannot shorten it; in memory, so a
/// restart tries at once. After the n-th consecutive failure the next
/// `2^(n-1) - 1` opportunities are skipped, at most [`MAX_REFRESH_SKIP`]:
/// 0, 1, 3, 7, 15, 15, … Any answer resets it, a refused set included —
/// the control plane is up, and the set is what failed — except one this
/// device could not install for a reason that may clear by itself (`failed`
/// with `io` or `local_files_changed`), which counts as a failure too. A
/// refusal remembered with what policy.d holds ([`LocalRefusal`]) is not
/// staged again until policy.d or the offer changes, so asking again costs
/// one fetch and nothing else, and must not wait: the organization's
/// correction, or its withdrawal, is what ends it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct RefreshBackoff {
    failures: u32,
    skip: u32,
}

impl RefreshBackoff {
    /// Whether this opportunity is skipped; each skip counts one down.
    fn skips(&mut self) -> bool {
        if self.skip == 0 {
            return false;
        }
        self.skip -= 1;
        true
    }

    fn failed(&mut self) {
        self.failures = self.failures.saturating_add(1);
        self.skip = 1u32
            .checked_shl(self.failures - 1)
            .unwrap_or(u32::MAX)
            .saturating_sub(1)
            .min(MAX_REFRESH_SKIP);
    }

    fn answered(&mut self) {
        *self = RefreshBackoff::default();
    }
}

/// A refresh that left what is enforced alone, as it is recorded.
struct Outcome<'a> {
    result: RefreshResult,
    reason: Option<&'a str>,
    /// For `rejected`: which set.
    offered_hash: Option<String>,
    /// For the journal: the loader's, the renderer's or the transport's own
    /// words. Never audited.
    detail: Option<String>,
}

impl<'a> Outcome<'a> {
    fn new(result: RefreshResult, reason: Option<&'a str>) -> Self {
        Outcome {
            result,
            reason,
            offered_hash: None,
            detail: None,
        }
    }
}

/// Whether an outcome is news the audit trail records (docs/api/ipc.md
/// section 6): a commit always; a refused set once per set; `held`,
/// `unreachable`, `refused` and `failed` when the result or its reason
/// changes; `unchanged` only as the recovery from one of those. Anything
/// more would be an event every two minutes saying nothing new.
fn is_news(
    previous: Option<&PolicyRefreshRecord>,
    result: RefreshResult,
    reason: Option<&str>,
    offered_hash: Option<&str>,
) -> bool {
    match result {
        RefreshResult::Applied | RefreshResult::Withdrawn => true,
        RefreshResult::Unchanged => previous.is_some_and(|p| !is_current(&p.result)),
        RefreshResult::Rejected => previous.is_none_or(|p| {
            p.result != result.as_str() || p.offered_hash.as_deref() != offered_hash
        }),
        _ => previous.is_none_or(|p| p.result != result.as_str() || p.reason.as_deref() != reason),
    }
}

/// A digest of a list that was refused before it could be put in canonical
/// form, so the same list is audited once. Hashed as it is written, never
/// held: a list refused for its size is not copied whole to be named.
fn offered_list_hash(policies: &[Value]) -> String {
    use sha2::{Digest, Sha256};
    struct Digesting(Sha256);
    impl std::io::Write for Digesting {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.update(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut digest = Digesting(Sha256::new());
    serde_json::to_writer(&mut digest, policies).expect("fetched envelopes re-serialize");
    format!("sha256:{:x}", digest.0.finalize())
}

/// A refusal that depended on this device's own files as well as on the
/// set offered ([`Inner`]'s `policy_local_refusal`), and what it depended on:
/// the enrollment, the offer, and `policy.d` itself
/// ([`policy_set::local_fingerprint`]).
#[derive(Debug, Clone)]
pub(super) struct LocalRefusal {
    epoch: u64,
    offered: String,
    local: String,
    result: RefreshResult,
    reason: &'static str,
}

/// Whether a local failure follows from what policy.d holds and the set
/// offered alone, so that trying again before either changes can only fail
/// the same way. An I/O error may clear by itself, and a file changed during
/// the swap is gone by the next pass; those are retried, under the backoff.
fn depends_on_local_files(failure: &policy_set::LocalFailure) -> bool {
    use policy_set::LocalFailure;
    matches!(
        failure,
        LocalFailure::UnsupportedEntry(_)
            | LocalFailure::ConflictsWithLocalPolicy(_)
            | LocalFailure::SwapUnsupported
    )
}

/// What a committed set changed, for the journal and the in-memory swap.
struct Committed {
    result: RefreshResult,
    ids: Vec<String>,
    rendered_changed: bool,
}

/// How [`Inner::commit_set`] ended.
enum Commit {
    /// Enforced on disk: directory, browser document, record, audit.
    Done(Committed),
    /// The enrollment ended or changed first; nothing was touched.
    Abandoned,
    /// Undone: disk, record and memory are as they were.
    Failed(policy_set::LocalFailure),
    /// Could not be undone: the rollback was not verified, so policy.d may
    /// hold the new set. Nothing more was removed or shrunk.
    Stuck(policy_set::LocalFailure),
}

impl Inner {
    /// One refresh opportunity. See the module documentation.
    pub(super) fn refresh_policy_if_enrolled(&self, actor: &AuditActor, budget: &CallBudget) {
        let epoch = {
            let slot = self.enrollment.lock().unwrap();
            if slot.is_none() {
                return;
            }
            self.enrollment_epoch.load(Ordering::SeqCst)
        };
        let Some(token) = self.device_token.lock().unwrap().clone() else {
            return;
        };
        if self.policy_refresh_backoff.lock().unwrap().skips() {
            return;
        }

        // The network call holds no lock and no guard: an enrollment change
        // may run meanwhile, and is caught below by its epoch.
        let client = self.control_plane().within(budget.clone());
        let failed = match client.policy_fetch(&token) {
            Ok(fetched) => {
                // Checking and committing hold the enrollment guard, and
                // never wait for it: an enroll.start or enroll.stop in
                // progress will leave nothing this answer is for, and the
                // next pass asks again.
                let Some(_guard) = EnrollGuard::acquire(&self.enroll_in_progress) else {
                    self.policy_refresh_backoff.lock().unwrap().answered();
                    return;
                };
                let refreshed = self.refresh_under_guard(actor, epoch, fetched);
                // A set this device could not install for a reason that may
                // clear by itself backs off like a failed fetch: the next
                // pass would only repeat the same local failure, on a device
                // that may be short of space. One remembered with policy.d
                // is not staged again, and is asked about on every pass.
                let mut backoff = self.policy_refresh_backoff.lock().unwrap();
                if refreshed.is_some_and(|refreshed| refreshed.backs_off) {
                    backoff.failed();
                } else {
                    backoff.answered();
                }
                return;
            }
            // An answer, and the organization's to fix: recorded once, like
            // any refused set, and asked for again on the next pass without
            // backing off, because nothing about the link is wrong.
            Err(UpstreamError::TooLarge) => {
                self.policy_refresh_backoff.lock().unwrap().answered();
                let mut outcome =
                    Outcome::new(RefreshResult::Rejected, Some(REASON_ANSWER_TOO_LARGE));
                outcome.detail = Some(format!(
                    "an answer larger than {} MiB",
                    crate::enroll::MAX_ANSWER_BYTES / (1024 * 1024)
                ));
                self.record_refresh(actor, epoch, outcome);
                return;
            }
            Err(UpstreamError::Unreachable(why)) => {
                let mut outcome = Outcome::new(RefreshResult::Unreachable, None);
                outcome.detail = Some(why);
                outcome
            }
            // The agent itself, which the pass's liveness call found
            // answering and which failed since: management interrupted, the
            // enroll.agent episode, and never the network's. The fetch says
            // nothing about the organization's policy or the link to it, so
            // nothing is recorded for the policy and nothing backs off.
            Err(UpstreamError::AgentUnavailable(fault)) => {
                self.note_agent(actor, epoch, super::Liveness::Unavailable(fault));
                return;
            }
            Err(UpstreamError::Refused { code, message }) => {
                let mut outcome = Outcome::new(RefreshResult::Refused, Some(refused_reason(&code)));
                outcome.detail = Some(format!("{code}: {message}"));
                outcome
            }
        };
        self.policy_refresh_backoff.lock().unwrap().failed();
        let mut outcome = failed;
        outcome.detail = outcome
            .detail
            .map(|detail| format!("{detail}; the next attempt is backed off to spare the server"));
        self.record_refresh(actor, epoch, outcome);
    }

    /// Check and, when it differs, commit a fetched set. What it recorded,
    /// or `None` when the enrollment changed first.
    fn refresh_under_guard(
        &self,
        actor: &AuditActor,
        epoch: u64,
        fetched: FetchedPolicy,
    ) -> Option<Refreshed> {
        // The enrollment the fetch was made for, still the one in the slot.
        let owned_files = {
            let slot = self.enrollment.lock().unwrap();
            match slot.as_ref() {
                Some(current) if self.enrollment_epoch.load(Ordering::SeqCst) == epoch => {
                    current.policy_files.clone()
                }
                _ => return None,
            }
        };

        // An empty list withdraws the organization's policy only when the
        // control plane says, in so many words, that nothing is assigned.
        if fetched.policies.is_empty() {
            let held = match fetched.assignment {
                Assignment::NoneAssigned => None,
                Assignment::Unusable => Some(REASON_UNUSABLE_ASSIGNMENT),
                Assignment::Unstated => Some(REASON_UNSTATED_EMPTY),
                Assignment::Policies => Some(REASON_EMPTY_POLICIES),
            };
            if let Some(reason) = held {
                return self.recorded(
                    actor,
                    epoch,
                    Outcome::new(RefreshResult::Held, Some(reason)),
                );
            }
        }
        let set = match CanonicalSet::from_envelopes(&fetched.policies, fetched.assignment) {
            Ok(set) => set,
            Err(rejection) => {
                let mut outcome = Outcome::new(RefreshResult::Rejected, Some(rejection.reason()));
                outcome.offered_hash = Some(offered_list_hash(&fetched.policies));
                outcome.detail = Some(rejection.describe());
                return self.recorded(actor, epoch, outcome);
            }
        };

        // Disk is the truth: the fetched set is compared with the files
        // themselves, so a missing or edited file is written again, and a
        // stale recorded revision can never hide a change.
        let policy_dir = self.cfg.state_dir.join(policy_set::POLICY_DIR);
        let owned_now = match CanonicalSet::read_owned(&policy_dir, &owned_files) {
            Ok(owned_now) => owned_now,
            Err(e) => {
                let mut outcome = Outcome::new(RefreshResult::Failed, Some("io"));
                outcome.detail = Some(format!("reading policy.d: {e}"));
                return self.recorded(actor, epoch, outcome);
            }
        };
        self.settle_revision(epoch, &owned_now);
        let offered = set.revision();
        // Unchanged only when all three agree with the set: the files, the
        // record that owns them (a file it names can be gone, and then an
        // empty set would compare equal to what is left while its layers
        // stayed enforced), and what the in-memory layers and the browser
        // document were made from. Anything else goes through the commit,
        // which rewrites all three.
        let recorded: BTreeSet<&String> = owned_files.iter().collect();
        let record_agrees =
            recorded.len() == owned_files.len() && recorded.into_iter().eq(set.files().keys());
        let memory_agrees =
            self.org_policy_loaded.lock().unwrap().as_deref() == Some(offered.as_str());
        if set == owned_now && record_agrees && memory_agrees {
            return self.recorded(actor, epoch, Outcome::new(RefreshResult::Unchanged, None));
        }

        // The very set this daemon already refused, for a reason that cannot
        // have changed since: not checked again.
        let memo = self.policy_rejected_offer.lock().unwrap().clone();
        if let Some((memo_epoch, memo_offer, reason)) = memo {
            if memo_epoch == epoch && memo_offer == offered {
                let mut outcome = Outcome::new(RefreshResult::Rejected, Some(reason));
                outcome.offered_hash = Some(offered);
                return self.recorded(actor, epoch, outcome);
            }
        }

        // A refusal that also depended on this device's own files — a set
        // that names a root drop, or that cannot be carried, loaded or
        // installed beside what policy.d holds — is not staged again, file
        // by file and fsync by fsync, while neither the offer nor policy.d
        // has changed: only root can clear it, and an SD card would
        // otherwise pay for it every two minutes.
        let local = policy_set::local_fingerprint(&self.cfg.state_dir, &owned_files).ok();
        let refusal = self.policy_local_refusal.lock().unwrap().clone();
        if let (Some(refusal), Some(local)) = (refusal, local.as_deref()) {
            if refusal.epoch == epoch && refusal.offered == offered && refusal.local == local {
                let mut outcome = Outcome::new(refusal.result, Some(refusal.reason));
                if refusal.result == RefreshResult::Rejected {
                    outcome.offered_hash = Some(offered);
                }
                return self.recorded(actor, epoch, outcome);
            }
        }
        let remember = |result: RefreshResult, reason: &'static str| {
            if let Some(local) = &local {
                *self.policy_local_refusal.lock().unwrap() = Some(LocalRefusal {
                    epoch,
                    offered: offered.clone(),
                    local: local.clone(),
                    result,
                    reason,
                });
            }
        };

        let prepared = match policy_set::prepare(&self.cfg.state_dir, &set, &owned_files) {
            Ok(prepared) => prepared,
            Err(error) => {
                policy_set::discard_staging(&self.cfg.state_dir);
                let outcome = match error {
                    PrepareError::Rejected(rejection) => {
                        // A collision depends on this device's own files,
                        // which root may change at any time: remembered
                        // with them, not with the offer alone.
                        if matches!(rejection, Rejection::ForeignFileCollision(_)) {
                            remember(RefreshResult::Rejected, rejection.reason());
                        } else {
                            *self.policy_rejected_offer.lock().unwrap() =
                                Some((epoch, offered.clone(), rejection.reason()));
                        }
                        let mut outcome =
                            Outcome::new(RefreshResult::Rejected, Some(rejection.reason()));
                        outcome.offered_hash = Some(offered);
                        outcome.detail = Some(match rejection.detail() {
                            Some(detail) => format!("{}: {detail}", rejection.describe()),
                            None => rejection.describe(),
                        });
                        outcome
                    }
                    PrepareError::Local(failure) => {
                        if depends_on_local_files(&failure) {
                            remember(RefreshResult::Failed, failure.reason());
                        }
                        let mut outcome =
                            Outcome::new(RefreshResult::Failed, Some(failure.reason()));
                        outcome.detail = Some(failure.to_string());
                        outcome
                    }
                };
                return self.recorded(actor, epoch, outcome);
            }
        };

        let committed = match self.commit_set(actor, epoch, &set, &prepared) {
            Commit::Done(committed) => committed,
            // The enrollment ended or changed while the set was checked.
            Commit::Abandoned => {
                policy_set::discard_staging(&self.cfg.state_dir);
                return None;
            }
            Commit::Failed(failure) => {
                if depends_on_local_files(&failure) {
                    remember(RefreshResult::Failed, failure.reason());
                }
                let mut outcome = Outcome::new(RefreshResult::Failed, Some(failure.reason()));
                outcome.detail = Some(failure.to_string());
                return self.recorded(actor, epoch, outcome);
            }
            Commit::Stuck(failure) => {
                // policy.d may hold the new set, which passed every check:
                // this daemon enforces it as the next start would find it,
                // and names nothing as loaded, so the next pass commits
                // again from what policy.d holds then.
                let loaded = prepared.loaded;
                *self.org_layers.lock().unwrap() = loaded.layers;
                *self.local_admin.lock().unwrap() = loaded.local_admin;
                *self.application_policy.lock().unwrap() = loaded.applications;
                *self.org_policy_loaded.lock().unwrap() = None;
                self.reload_ai_authority();
                self.recompute_effective();
                let mut outcome = Outcome::new(RefreshResult::Failed, Some(failure.reason()));
                outcome.detail = Some(failure.to_string());
                return self.recorded(actor, epoch, outcome);
            }
        };

        // The new layers, in the order a restart would load them, then the
        // AI authority and the effective document. A capability whose value
        // changed leaves remediation suppression in recompute_effective;
        // browser.policy stays "managed" when only its document changes, so
        // it is released here.
        // The paths are the organization's own keys: escaped, like every
        // other string from it that reaches the journal.
        let loaded = prepared.loaded;
        for unmapped in &loaded.unmapped {
            eprintln!(
                "punard: organization policy {offered}: no registered capability for \
                 {}; ignored (its capability lands in a later milestone)",
                journal_detail(unmapped)
            );
        }
        *self.org_layers.lock().unwrap() = loaded.layers;
        *self.local_admin.lock().unwrap() = loaded.local_admin;
        *self.application_policy.lock().unwrap() = loaded.applications;
        *self.org_policy_loaded.lock().unwrap() = Some(offered.clone());
        self.reload_ai_authority();
        self.recompute_effective();
        if committed.rendered_changed {
            self.tracker
                .lock()
                .unwrap()
                .fail_counts
                .remove(BROWSER_POLICY_CAPABILITY);
        }
        *self.policy_rejected_offer.lock().unwrap() = None;
        *self.policy_local_refusal.lock().unwrap() = None;

        eprintln!(
            "punard: the organization's policy was {} ({offered}): {}",
            committed.result.as_str(),
            if committed.ids.is_empty() {
                "no policies".to_string()
            } else {
                committed.ids.join(", ")
            }
        );
        Some(Refreshed::of(committed.result, None))
    }

    /// [`Inner::record_refresh`], answering what was recorded.
    fn recorded(&self, actor: &AuditActor, epoch: u64, outcome: Outcome<'_>) -> Option<Refreshed> {
        let refreshed = Refreshed::of(outcome.result, outcome.reason);
        self.record_refresh(actor, epoch, outcome);
        Some(refreshed)
    }

    /// Make a prepared set the enforced one, on disk. In order, each step
    /// undoing the ones before it on failure:
    ///
    /// 1. the record, durably, owning the old and new files together with
    ///    the change pending, so a crash never leaves a file in policy.d that
    ///    no record owns, and the next start can tell whether the change
    ///    landed ([`policy_set::settle`]);
    /// 2. policy.d still holds what was carried out of it;
    /// 3. the swap, then the directory it replaced holds nothing that was
    ///    not carried;
    /// 4. the browser document;
    /// 5. the `enroll.policy` audit event, under the id the pending change
    ///    fixed, so a start that finds the change landed writes it only if
    ///    this did not;
    /// 6. the record that says what is enforced;
    /// 7. the replaced directory removed.
    ///
    /// A rollback that cannot be verified undoes nothing more
    /// ([`Commit::Stuck`]).
    fn commit_set(
        &self,
        actor: &AuditActor,
        epoch: u64,
        set: &CanonicalSet,
        prepared: &policy_set::Prepared,
    ) -> Commit {
        use policy_set::{LocalFailure, Step, step};
        let record_path = self.cfg.state_dir.join("enrollment.json");
        let policy_dir = self.cfg.state_dir.join(policy_set::POLICY_DIR);
        let now = utc_now_rfc3339();

        // Only file work and the audit writer under this lock, which is the
        // order record_refresh takes them in too.
        let mut slot = self.enrollment.lock().unwrap();
        let Some(current) = slot
            .as_mut()
            .filter(|_| self.enrollment_epoch.load(Ordering::SeqCst) == epoch)
        else {
            return Commit::Abandoned;
        };
        let before = current.policy_fields();
        let withdrawn = set.is_empty();
        let result = if withdrawn {
            RefreshResult::Withdrawn
        } else {
            RefreshResult::Applied
        };
        // Withdrawn cites what was taken away; applied, what is now enforced.
        let ids = if withdrawn {
            before
                .files
                .iter()
                .map(|file| file.trim_end_matches(".json").to_string())
                .collect()
        } else {
            set.ids()
        };
        let pending = PendingPolicyChange {
            revision: set.revision(),
            result: result.as_str().to_string(),
            policy_ids: ids.clone(),
            at: now.clone(),
            event_id: next_event_id(),
        };
        let undo_record = |current: &mut Enrollment| {
            apply_policy_fields(current, before.clone());
            if let Err(e) = save_enrollment_durable(&record_path, current) {
                eprintln!(
                    "punard: could not restore the policy record ({e}); the next start \
                     settles it from policy.d"
                );
            }
        };

        let mut both = before.clone();
        both.files = before
            .files
            .iter()
            .cloned()
            .chain(set.names())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        both.pending = Some(pending.clone());
        apply_policy_fields(current, both);
        if let Err(e) =
            step(Step::RecordBoth).and_then(|()| save_enrollment_durable(&record_path, current))
        {
            apply_policy_fields(current, before.clone());
            policy_set::discard_staging(&self.cfg.state_dir);
            return Commit::Failed(LocalFailure::Io(e));
        }

        if let Err(failure) = prepared.still_current(&policy_dir, &before.files) {
            undo_record(current);
            policy_set::discard_staging(&self.cfg.state_dir);
            return Commit::Failed(failure);
        }
        let previous_rendered = read_if_present(&self.cfg.browser_policy_source);
        let swapped = match step(Step::Swap)
            .map_err(LocalFailure::Io)
            .and_then(|()| policy_set::swap_in(prepared.staging(), &policy_dir))
        {
            Ok(swapped) => swapped,
            Err(failure) => {
                undo_record(current);
                policy_set::discard_staging(&self.cfg.state_dir);
                return Commit::Failed(failure);
            }
        };
        let failed = match swapped.replaced_only_what_was_carried(prepared, &before.files) {
            Err(failure) => Some(failure),
            Ok(()) => step(Step::Render)
                .and_then(|()| {
                    persist_rendered_browser_policy(
                        &self.cfg.browser_policy_source,
                        &prepared.loaded.applications,
                        &prepared.loaded.browsers,
                    )
                })
                .err()
                .map(LocalFailure::Io),
        };
        if let Some(failure) = failed {
            return match swapped.roll_back() {
                Ok(()) => {
                    restore_rendered(&self.cfg.browser_policy_source, previous_rendered);
                    undo_record(current);
                    Commit::Failed(failure)
                }
                Err(stuck) => {
                    // Neither the previous directory nor the record is
                    // touched: the record owns both sets' files with the
                    // change pending, and the next start settles it from
                    // whichever policy.d holds.
                    eprintln!(
                        "punard: could not put policy.d back after a failed refresh \
                         ({failure}; {stuck}); both sets stay owned and the previous one \
                         stays beside it until the change is settled, which keeps \
                         anything in it found nowhere else"
                    );
                    Commit::Stuck(failure)
                }
            };
        }
        let rendered_changed =
            read_if_present(&self.cfg.browser_policy_source) != previous_rendered;

        let mut event = self.enroll_event(
            actor,
            "enroll.policy",
            RESOURCE_CONTROL_PLANE,
            result.as_str(),
            ids.clone(),
        );
        event.event_id = pending.event_id;
        self.log_audit(event);

        apply_policy_fields(
            current,
            PolicyFields {
                files: set.names(),
                hash: Some(set.revision()),
                fetched_at: Some(now.clone()),
                changed_at: Some(now.clone()),
                refresh: Some(PolicyRefreshRecord {
                    at: now,
                    result: result.as_str().to_string(),
                    reason: None,
                    offered_hash: None,
                }),
                pending: None,
            },
        );
        if let Err(e) =
            step(Step::RecordFinal).and_then(|()| save_enrollment_durable(&record_path, current))
        {
            // The record on disk still owns both sets' files with the change
            // pending, which is safe: the next start finds it landed, and
            // audited under its id already.
            eprintln!("punard: could not save the refreshed policy record: {e}");
        }
        drop(slot);
        if let Err(e) = swapped.finish() {
            eprintln!("punard: could not remove the replaced policy.d ({e}); removed at start");
        }
        Commit::Done(Committed {
            result,
            ids,
            rendered_changed,
        })
    }

    /// The recorded revision is what the owned files hash to, whatever this
    /// refresh ends in: an enrollment recorded before revisions existed
    /// learns the one it enforces, and one a crash left stale is corrected.
    /// For `enroll.status` only, in memory until the next save.
    fn settle_revision(&self, epoch: u64, owned_now: &CanonicalSet) {
        let mut slot = self.enrollment.lock().unwrap();
        let Some(current) = slot
            .as_mut()
            .filter(|_| self.enrollment_epoch.load(Ordering::SeqCst) == epoch)
        else {
            return;
        };
        let revision = owned_now.revision();
        if current.policy_hash.as_deref() != Some(revision.as_str()) {
            let mut fields = current.policy_fields();
            fields.hash = Some(revision);
            apply_policy_fields(current, fields);
        }
    }

    /// Record an outcome that left what is enforced alone, for the enrollment
    /// the refresh began with only, and audit it when it is news
    /// ([`is_news`]). The decision is made under the slot lock with the
    /// update, so two passes cannot both audit one transition. The record is
    /// saved when it is news; otherwise the next sync's save carries it.
    fn record_refresh(&self, actor: &AuditActor, epoch: u64, outcome: Outcome<'_>) {
        let now = utc_now_rfc3339();
        let mut slot = self.enrollment.lock().unwrap();
        let Some(current) = slot
            .as_mut()
            .filter(|_| self.enrollment_epoch.load(Ordering::SeqCst) == epoch)
        else {
            return;
        };
        let mut fields = current.policy_fields();
        let news = is_news(
            fields.refresh.as_ref(),
            outcome.result,
            outcome.reason,
            outcome.offered_hash.as_deref(),
        );
        if outcome.result == RefreshResult::Unchanged {
            fields.fetched_at = Some(now.clone());
        }
        fields.refresh = Some(PolicyRefreshRecord {
            at: now,
            result: outcome.result.as_str().to_string(),
            reason: outcome.reason.map(str::to_string),
            offered_hash: outcome.offered_hash,
        });
        apply_policy_fields(current, fields);
        if !news {
            return;
        }
        let reason = outcome
            .reason
            .map(|reason| format!(" ({reason})"))
            .unwrap_or_default();
        let detail = outcome
            .detail
            .as_deref()
            .map(|detail| format!(": {}", journal_detail(detail)))
            .unwrap_or_default();
        let enforcing = current
            .policy_hash
            .as_deref()
            .unwrap_or("the enrolled policy");
        eprintln!(
            "punard: organization policy refresh {}{reason}{detail}; enforcing {enforcing}",
            outcome.result.as_str()
        );
        self.log_audit(self.enroll_event(
            actor,
            "enroll.policy",
            RESOURCE_CONTROL_PLANE,
            outcome.result.as_str(),
            current.policy_ids(),
        ));
        if let Err(e) =
            save_enrollment_durable(&self.cfg.state_dir.join("enrollment.json"), current)
        {
            eprintln!("punard: could not save the policy refresh record: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;
    use crate::capability::mock::MockCapability;
    use crate::policy_set::{Step, faults};

    const ACME_ENVELOPE: &str =
        include_str!("../../../../fixtures/organizations/acme/policy-source-eng-baseline-v12.json");
    const ACME_DESIRED: &str =
        include_str!("../../../../fixtures/organizations/acme/desired-state-eng-baseline-v12.json");
    const BASELINE: &str = "eng-baseline-v12.json";

    fn root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "punard-refresh-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The Acme baseline with its firewall rule set to `enabled`.
    fn baseline(enabled: bool) -> Value {
        let mut envelope: Value = serde_json::from_str(ACME_ENVELOPE).unwrap();
        let mut desired: Value = serde_json::from_str(ACME_DESIRED).unwrap();
        desired["spec"]["security"]["firewall"]["enabled"] = json!(enabled);
        envelope["policy"] = desired;
        envelope
    }

    fn canonical(envelopes: &[Value]) -> CanonicalSet {
        CanonicalSet::from_envelopes(envelopes, Assignment::Policies).unwrap()
    }

    /// What enroll.start leaves on disk for `envelopes`, and nothing else.
    fn enrolled_on_disk(root: &Path, envelopes: &[Value]) {
        let set = canonical(envelopes);
        let policy_d = root.join("state").join(policy_set::POLICY_DIR);
        std::fs::create_dir_all(&policy_d).unwrap();
        for (name, bytes) in set.files() {
            std::fs::write(policy_d.join(name), bytes).unwrap();
        }
        let record = json!({
            "version": 1,
            "org": {"id": "acme", "name": "Acme", "display_name": "Acme", "domain": "acme.com"},
            "enrolled_at": "2026-09-24T00:00:00Z",
            "attestation": "simulated",
            "policy_files": set.names(),
            "last_sync": {"at": null, "result": null},
            "last_inventory_hash": null,
            "policy_hash": set.revision(),
        });
        std::fs::write(
            root.join("state/enrollment.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
    }

    fn start(root: &Path) -> Daemon {
        let cfg = DaemonConfig::new(
            root.join("punard.sock"),
            root.join("state"),
            root.join("audit.jsonl"),
        );
        let firewall = MockCapability::new("security.firewall", json!("enabled"));
        Daemon::new(cfg, Registry::new(vec![Box::new(firewall)])).unwrap()
    }

    fn refresh(daemon: &Daemon, envelopes: Vec<Value>) {
        daemon.inner.refresh_under_guard(
            &AuditActor::daemon(),
            0,
            FetchedPolicy {
                policies: envelopes,
                assignment: Assignment::Policies,
            },
        );
    }

    fn saved(root: &Path) -> Value {
        serde_json::from_slice(&std::fs::read(root.join("state/enrollment.json")).unwrap()).unwrap()
    }

    fn policy_events(root: &Path) -> Vec<Value> {
        std::fs::read_to_string(root.join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|event| event["action"] == "enroll.policy")
            .collect()
    }

    fn enforced_firewall(daemon: &Daemon) -> Value {
        daemon.inner.effective.lock().unwrap().entries["security.firewall"]
            .value
            .clone()
    }

    fn live_baseline(root: &Path) -> Vec<u8> {
        std::fs::read(root.join("state/policy.d").join(BASELINE)).unwrap()
    }

    fn staging(root: &Path) -> PathBuf {
        root.join("state").join(policy_set::STAGING_DIR)
    }

    fn copy_tree(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for entry in std::fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let target = to.join(entry.file_name());
            let meta = std::fs::symlink_metadata(entry.path()).unwrap();
            if meta.is_dir() {
                copy_tree(&entry.path(), &target);
            } else if meta.file_type().is_symlink() {
                std::os::unix::fs::symlink(std::fs::read_link(entry.path()).unwrap(), target)
                    .unwrap();
            } else {
                std::fs::copy(entry.path(), target).unwrap();
            }
        }
    }

    /// The state directory and audit log exactly as they are now, at `to`:
    /// what a crash at this moment would leave for the next start.
    fn crash_copy(root: &Path, to: &Path) {
        let _ = std::fs::remove_dir_all(to);
        copy_tree(&root.join("state"), &to.join("state"));
        if root.join("audit.jsonl").exists() {
            std::fs::copy(root.join("audit.jsonl"), to.join("audit.jsonl")).unwrap();
        }
    }

    /// A crash at any step of a refresh leaves a device that the next start
    /// settles to one whole set: the old one up to the swap, the new one from
    /// it on. The record then owns exactly that set's files and names its
    /// revision, nothing is left pending or beside policy.d, the set is what
    /// is enforced, and a change that landed is audited exactly once —
    /// whether the refresh wrote its event before the crash or not, and
    /// however often the device restarts.
    #[test]
    fn a_crash_at_any_step_of_a_refresh_settles_to_one_set_audited_once() {
        let root = root("crash");
        enrolled_on_disk(&root, &[baseline(true)]);
        let old = canonical(&[baseline(true)]);
        let new = canonical(&[baseline(false)]);
        let daemon = start(&root);
        let seen = Rc::new(RefCell::new(Vec::new()));
        {
            let seen = Rc::clone(&seen);
            let at = root.clone();
            let _hook = faults::install(move |step| {
                crash_copy(&at, &at.join(format!("crash-{step:?}")));
                seen.borrow_mut().push(step);
                Ok(())
            });
            refresh(&daemon, vec![baseline(false)]);
        }
        assert_eq!(
            *seen.borrow(),
            [
                Step::Stage,
                Step::RecordBoth,
                Step::Swap,
                Step::Render,
                Step::RecordFinal,
                Step::Finish
            ]
        );
        assert_eq!(policy_events(&root).len(), 1);
        assert_eq!(enforced_firewall(&daemon), json!("disabled"));
        crash_copy(&root, &root.join("crash-after"));

        let landed_from = [Step::Render, Step::RecordFinal, Step::Finish];
        for (name, landed) in seen
            .borrow()
            .iter()
            .map(|step| (format!("crash-{step:?}"), landed_from.contains(step)))
            .chain([("crash-after".to_string(), true)])
        {
            let crashed = root.join(&name);
            let (expected, firewall) = if landed {
                (&new, "disabled")
            } else {
                (&old, "enabled")
            };
            for _restart in 0..2 {
                let restarted = start(&crashed);
                assert_eq!(
                    live_baseline(&crashed),
                    expected.files()[BASELINE],
                    "{name}"
                );
                let written = saved(&crashed);
                assert_eq!(written["policy_files"], json!([BASELINE]), "{name}");
                assert_eq!(written["policy_hash"], expected.revision(), "{name}");
                assert!(written.get("policy_pending").is_none(), "{name}: {written}");
                assert!(!staging(&crashed).exists(), "{name}");
                assert_eq!(enforced_firewall(&restarted), json!(firewall), "{name}");
                let events = policy_events(&crashed);
                assert_eq!(events.len(), usize::from(landed), "{name}: {events:?}");
                if landed {
                    assert_eq!(events[0]["result"], "applied", "{name}");
                    assert_eq!(written["policy_refresh"]["result"], "applied", "{name}");
                    assert!(written["policy_changed_at"].is_string(), "{name}");
                }
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A browser document that cannot be written undoes the change, and a
    /// rollback that then cannot be verified undoes nothing more: policy.d
    /// keeps whichever set it holds, the last good one stays beside it, the
    /// record keeps owning both sets' files with the change pending, and the
    /// daemon enforces the set policy.d holds. Both a restart and the next
    /// pass settle it to the new set, audited once.
    #[test]
    fn a_rollback_that_fails_deletes_nothing_and_leaves_nothing_unowned() {
        let root = root("stuck");
        enrolled_on_disk(&root, &[baseline(true)]);
        let old = canonical(&[baseline(true)]);
        let new = canonical(&[baseline(false)]);
        let daemon = start(&root);

        // Undone: exactly as it was.
        {
            let _hook = faults::install(|step| match step {
                Step::Render => Err(io::Error::other("no space left on device")),
                _ => Ok(()),
            });
            refresh(&daemon, vec![baseline(false)]);
        }
        assert_eq!(live_baseline(&root), old.files()[BASELINE]);
        assert!(!staging(&root).exists());
        assert_eq!(saved(&root)["policy_hash"], old.revision());
        assert!(saved(&root).get("policy_pending").is_none());
        assert_eq!(enforced_firewall(&daemon), json!("enabled"));
        assert!(
            policy_events(&root)
                .iter()
                .all(|e| e["result"] != "applied")
        );

        // Not undone.
        {
            let _hook = faults::install(|step| match step {
                Step::Render => Err(io::Error::other("no space left on device")),
                Step::RollBack => Err(io::Error::other("no space left on device")),
                _ => Ok(()),
            });
            refresh(&daemon, vec![baseline(false)]);
        }
        assert_eq!(live_baseline(&root), new.files()[BASELINE]);
        assert_eq!(
            std::fs::read(staging(&root).join(BASELINE)).unwrap(),
            old.files()[BASELINE],
            "the last good set is not deleted"
        );
        let written = saved(&root);
        assert_eq!(written["policy_files"], json!([BASELINE]));
        assert_eq!(written["policy_pending"]["revision"], new.revision());
        assert_eq!(enforced_firewall(&daemon), json!("disabled"));
        let refresh_record = daemon
            .inner
            .enrollment
            .lock()
            .unwrap()
            .clone()
            .unwrap()
            .policy_refresh
            .unwrap();
        assert_eq!(refresh_record.result, "failed");
        assert!(
            policy_events(&root)
                .iter()
                .all(|e| e["result"] != "applied")
        );

        // A start from here settles it.
        crash_copy(&root, &root.join("restarted"));
        let restarted = start(&root.join("restarted"));
        let written = saved(&root.join("restarted"));
        assert_eq!(written["policy_hash"], new.revision());
        assert!(written.get("policy_pending").is_none());
        assert!(!staging(&root.join("restarted")).exists());
        assert_eq!(enforced_firewall(&restarted), json!("disabled"));
        let applied = |at: &Path| {
            policy_events(at)
                .into_iter()
                .filter(|e| e["result"] == "applied")
                .count()
        };
        assert_eq!(applied(&root.join("restarted")), 1);

        // So does the next pass, without one: the set commits again.
        refresh(&daemon, vec![baseline(false)]);
        let written = saved(&root);
        assert_eq!(written["policy_hash"], new.revision());
        assert!(written.get("policy_pending").is_none());
        assert_eq!(written["policy_refresh"]["result"], "applied");
        assert!(!staging(&root).exists());
        assert_eq!(applied(&root), 1);
        assert_eq!(enforced_firewall(&daemon), json!("disabled"));
        refresh(&daemon, vec![baseline(false)]);
        assert_eq!(applied(&root), 1, "then unchanged");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A change that landed before a crash is audited by the next start
    /// even when the record settled from policy.d cannot be saved then. The
    /// daemon runs on with the settled record in memory, and the next sync
    /// pass saves it without the pending change, so an event left for "the
    /// next start" would never be written once the disk recovers. A later
    /// start that settles it again finds it written and adds none.
    #[test]
    fn a_landed_change_is_audited_at_start_even_when_its_record_cannot_be_saved() {
        let root = root("landed-unsaved");
        enrolled_on_disk(&root, &[baseline(true)]);
        let daemon = start(&root);
        {
            let at = root.clone();
            let _hook = faults::install(move |step| {
                if step == Step::Render {
                    crash_copy(&at, &at.join("crashed"));
                }
                Ok(())
            });
            refresh(&daemon, vec![baseline(false)]);
        }
        let crashed = root.join("crashed");
        assert!(
            policy_events(&crashed).is_empty(),
            "crashed before its event"
        );
        assert!(saved(&crashed).get("policy_pending").is_some());
        let applied = |at: &Path| {
            policy_events(at)
                .into_iter()
                .filter(|e| e["result"] == "applied")
                .count()
        };
        {
            let _hook = faults::install(|step| match step {
                Step::RecordSettled => Err(io::Error::other("no space left on device")),
                _ => Ok(()),
            });
            let restarted = start(&crashed);
            assert_eq!(enforced_firewall(&restarted), json!("disabled"));
        }
        assert!(
            saved(&crashed).get("policy_pending").is_some(),
            "the settled record was not saved"
        );
        assert_eq!(applied(&crashed), 1, "audited all the same");
        let _restarted = start(&crashed);
        assert!(saved(&crashed).get("policy_pending").is_none());
        assert_eq!(applied(&crashed), 1, "and only once");
        let _ = std::fs::remove_dir_all(&root);
    }

    fn last_result(daemon: &Daemon) -> (String, Option<String>) {
        let refresh = daemon
            .inner
            .enrollment
            .lock()
            .unwrap()
            .clone()
            .unwrap()
            .policy_refresh
            .unwrap();
        (refresh.result, refresh.reason)
    }

    /// A refusal that depends on this device's own files as well as on the
    /// set offered is staged once, not on every pass: a conflict with a root
    /// drop that only shows once the set is loaded beside it is remembered
    /// with the offer and what policy.d holds, and staged again only when
    /// either changes; a collision with a root drop's name and an entry that
    /// cannot be carried are found by reading the directory, before anything
    /// is written.
    #[test]
    fn a_local_refusal_is_not_staged_again_until_policy_d_or_the_offer_changes() {
        let root = root("local-refusal");
        enrolled_on_disk(&root, &[baseline(true)]);
        let daemon = start(&root);
        let policy_d = root.join("state/policy.d");
        let staged = Rc::new(RefCell::new(0));
        let _hook = {
            let staged = Rc::clone(&staged);
            faults::install(move |step| {
                if step == Step::Stage {
                    *staged.borrow_mut() += 1;
                }
                Ok(())
            })
        };
        let clash = |name: &str| {
            json!({"policy_id": "eng-baseline-v12", "source_kind": "organization_role_policy",
                   "precedence_rank": 3, "source_name": name})
            .to_string()
        };
        std::fs::write(policy_d.join("clash.json"), clash("first")).unwrap();

        refresh(&daemon, vec![baseline(false)]);
        let conflict = (
            "failed".to_string(),
            Some("conflicts_with_local_policy".to_string()),
        );
        assert_eq!(last_result(&daemon), conflict);
        assert_eq!(*staged.borrow(), 1);
        refresh(&daemon, vec![baseline(false)]);
        refresh(&daemon, vec![baseline(false)]);
        assert_eq!(last_result(&daemon), conflict);
        assert_eq!(
            *staged.borrow(),
            1,
            "the same offer and files: not staged again"
        );

        // Root edits the drop: staged again.
        std::fs::write(
            policy_d.join("clash.json"),
            clash("second, edited in place"),
        )
        .unwrap();
        refresh(&daemon, vec![baseline(false)]);
        assert_eq!(*staged.borrow(), 2);
        // The organization changes its offer: staged again.
        let mut other = baseline(false);
        other["source_name"] = json!("Engineering baseline, revised");
        refresh(&daemon, vec![other]);
        assert_eq!(*staged.borrow(), 3);
        std::fs::remove_file(policy_d.join("clash.json")).unwrap();

        // Found before anything is staged.
        std::fs::write(policy_d.join("eng-role-sre.json"), clash("root's")).unwrap();
        let mut named_like_it = baseline(false);
        named_like_it["policy_id"] = json!("eng-role-sre");
        named_like_it["source_kind"] = json!("organization_role_policy");
        named_like_it["precedence_rank"] = json!(3);
        refresh(&daemon, vec![baseline(false), named_like_it]);
        assert_eq!(
            last_result(&daemon).1.as_deref(),
            Some("foreign_file_collision")
        );
        std::fs::remove_file(policy_d.join("eng-role-sre.json")).unwrap();
        std::fs::create_dir_all(policy_d.join("ai")).unwrap();
        std::fs::write(policy_d.join("ai/stale.yaml"), b"x").unwrap();
        refresh(&daemon, vec![baseline(false)]);
        assert_eq!(last_result(&daemon).1.as_deref(), Some("unsupported_entry"));
        assert_eq!(*staged.borrow(), 3, "neither was staged");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A root drop kept outside policy.d behind a symlink is read through
    /// the link, so editing the file it points at changes what a remembered
    /// refusal depended on: the set is staged again, as for a drop edited in
    /// place.
    #[test]
    fn a_refusal_is_staged_again_when_a_symlinked_drops_target_changes() {
        let root = root("symlinked-refusal");
        enrolled_on_disk(&root, &[baseline(true)]);
        let daemon = start(&root);
        let outside = root.join("drops");
        std::fs::create_dir_all(&outside).unwrap();
        let clash = |name: &str| {
            json!({"policy_id": "eng-baseline-v12", "source_kind": "organization_role_policy",
                   "precedence_rank": 3, "source_name": name})
            .to_string()
        };
        std::fs::write(outside.join("clash.json"), clash("first")).unwrap();
        std::os::unix::fs::symlink(
            outside.join("clash.json"),
            root.join("state/policy.d/clash.json"),
        )
        .unwrap();
        let staged = Rc::new(RefCell::new(0));
        let _hook = {
            let staged = Rc::clone(&staged);
            faults::install(move |step| {
                if step == Step::Stage {
                    *staged.borrow_mut() += 1;
                }
                Ok(())
            })
        };
        refresh(&daemon, vec![baseline(false)]);
        assert_eq!(
            last_result(&daemon),
            (
                "failed".to_string(),
                Some("conflicts_with_local_policy".to_string())
            )
        );
        refresh(&daemon, vec![baseline(false)]);
        assert_eq!(*staged.borrow(), 1, "nothing changed: not staged again");
        std::fs::write(
            outside.join("clash.json"),
            clash("second, edited where the link points"),
        )
        .unwrap();
        refresh(&daemon, vec![baseline(false)]);
        assert_eq!(*staged.borrow(), 2, "the file the loader reads changed");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The double fault: a root drop written just before the exchange stops
    /// the change, and the rollback then fails too. The drop is then only in
    /// the directory the exchange replaced, at the staging path. Neither the
    /// next pass, which stages there again, nor the next start, which clears
    /// what a change left there, deletes it: it is kept beside policy.d.
    #[test]
    fn a_root_drop_caught_by_a_rollback_that_fails_is_kept() {
        let root = root("double-fault");
        enrolled_on_disk(&root, &[baseline(true)]);
        let daemon = start(&root);
        let policy_d = root.join("state/policy.d");
        {
            let policy_d = policy_d.clone();
            let _hook = faults::install(move |step| match step {
                Step::Swap => {
                    std::fs::write(policy_d.join("late.note"), b"root's").unwrap();
                    Ok(())
                }
                Step::RollBack => Err(io::Error::other("no space left on device")),
                _ => Ok(()),
            });
            refresh(&daemon, vec![baseline(false)]);
        }
        assert_eq!(
            std::fs::read(staging(&root).join("late.note")).unwrap(),
            b"root's",
            "only in the directory the exchange replaced"
        );
        let kept = |at: &Path| -> Vec<Vec<u8>> {
            std::fs::read_dir(at.join("state"))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(policy_set::KEPT_PREFIX))
                })
                .filter_map(|path| std::fs::read(path.join("late.note")).ok())
                .collect()
        };

        // The next start clears the staging path and keeps the drop.
        crash_copy(&root, &root.join("restarted"));
        let _restarted = start(&root.join("restarted"));
        assert!(!staging(&root.join("restarted")).exists());
        assert_eq!(kept(&root.join("restarted")), [b"root's".to_vec()]);

        // So does the next pass, which stages there again.
        refresh(&daemon, vec![baseline(false)]);
        assert_eq!(saved(&root)["policy_refresh"]["result"], "applied");
        assert_eq!(kept(&root), [b"root's".to_vec()]);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A root administrator's file written into policy.d while a set is
    /// being installed — before the record is saved, or just before the
    /// exchange — stops the change instead of being deleted with the
    /// directory it went into; the next pass carries it.
    #[test]
    fn a_root_drop_written_during_a_refresh_is_never_lost() {
        use std::os::unix::fs::MetadataExt;
        for at in [Step::RecordBoth, Step::Swap] {
            let root = root(&format!("drop-{at:?}"));
            enrolled_on_disk(&root, &[baseline(true)]);
            let policy_d = root.join("state/policy.d");
            std::fs::write(policy_d.join("local.note"), b"kept").unwrap();
            let old = canonical(&[baseline(true)]);
            let daemon = start(&root);
            {
                let policy_d = policy_d.clone();
                let _hook = faults::install(move |step| {
                    if step == at {
                        std::fs::write(policy_d.join("added.note"), b"added").unwrap();
                        // An editor's save: renamed over the old name.
                        std::fs::write(policy_d.join(".local.note.tmp"), b"edited").unwrap();
                        std::fs::rename(
                            policy_d.join(".local.note.tmp"),
                            policy_d.join("local.note"),
                        )
                        .unwrap();
                    }
                    Ok(())
                });
                refresh(&daemon, vec![baseline(false)]);
            }
            let last = daemon
                .inner
                .enrollment
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .policy_refresh
                .unwrap();
            assert_eq!(last.result, "failed", "{at:?}");
            assert_eq!(
                last.reason.as_deref(),
                Some("local_files_changed"),
                "{at:?}"
            );
            assert_eq!(live_baseline(&root), old.files()[BASELINE], "{at:?}");
            assert_eq!(
                std::fs::read(policy_d.join("added.note")).unwrap(),
                b"added"
            );
            assert_eq!(
                std::fs::read(policy_d.join("local.note")).unwrap(),
                b"edited"
            );
            assert!(!staging(&root).exists(), "{at:?}");
            assert!(saved(&root).get("policy_pending").is_none(), "{at:?}");

            let inode = |name: &str| std::fs::metadata(policy_d.join(name)).unwrap().ino();
            let before = (inode("added.note"), inode("local.note"));
            refresh(&daemon, vec![baseline(false)]);
            assert_eq!(saved(&root)["policy_refresh"]["result"], "applied");
            assert_eq!((inode("added.note"), inode("local.note")), before, "{at:?}");
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn a_failing_fetch_waits_longer_each_time_up_to_a_cap() {
        let mut backoff = RefreshBackoff::default();
        let mut waits = Vec::new();
        for _ in 0..7 {
            assert!(!backoff.skips(), "an attempt is made");
            backoff.failed();
            let mut skipped = 0;
            while backoff.skips() {
                skipped += 1;
            }
            waits.push(skipped);
        }
        assert_eq!(waits, [0, 1, 3, 7, 15, 15, 15]);
        backoff.failed();
        backoff.answered();
        assert!(!backoff.skips(), "any answer resets it");
        backoff.failed();
        assert!(!backoff.skips(), "and the count starts again");
    }

    fn record(result: &str, reason: Option<&str>, offered: Option<&str>) -> PolicyRefreshRecord {
        PolicyRefreshRecord {
            at: "2026-09-24T00:00:00Z".into(),
            result: result.into(),
            reason: reason.map(str::to_string),
            offered_hash: offered.map(str::to_string),
        }
    }

    #[test]
    fn only_transitions_are_audited() {
        use RefreshResult::*;
        let unreachable = record("unreachable", None, None);
        assert!(is_news(None, Unreachable, None, None));
        assert!(!is_news(Some(&unreachable), Unreachable, None, None));
        assert!(is_news(Some(&unreachable), Refused, Some("other"), None));
        let refused = record("refused", Some("other"), None);
        assert!(is_news(Some(&refused), Refused, Some("internal"), None));
        assert!(!is_news(Some(&refused), Refused, Some("other"), None));

        let rejected = record("rejected", Some("duplicate_policy_id"), Some("sha256:a"));
        assert!(!is_news(
            Some(&rejected),
            Rejected,
            Some("invalid_envelope"),
            Some("sha256:a")
        ));
        assert!(is_news(
            Some(&rejected),
            Rejected,
            Some("duplicate_policy_id"),
            Some("sha256:b")
        ));

        assert!(
            !is_news(None, Unchanged, None, None),
            "nothing to recover from"
        );
        for current in ["unchanged", "applied", "withdrawn"] {
            assert!(!is_news(
                Some(&record(current, None, None)),
                Unchanged,
                None,
                None
            ));
        }
        for failing in [
            &unreachable,
            &refused,
            &rejected,
            &record("held", Some("unstated_empty"), None),
        ] {
            assert!(is_news(Some(failing), Unchanged, None, None), "{failing:?}");
        }
        assert!(is_news(
            Some(&record("applied", None, None)),
            Applied,
            None,
            None
        ));
        assert!(is_news(
            Some(&record("applied", None, None)),
            Withdrawn,
            None,
            None
        ));
    }

    #[test]
    fn journal_detail_is_one_bounded_escaped_line() {
        let hostile = format!("bad\npunard: forged line\u{1b}[2J{}", "x".repeat(2000));
        let line = journal_detail(&hostile);
        assert!(!line.contains('\n'), "{line}");
        assert!(!line.contains('\u{1b}'), "{line}");
        assert!(
            line.chars().count() < JOURNAL_DETAIL_CHARS + 64,
            "{}",
            line.len()
        );
    }

    #[test]
    fn a_refusals_code_is_one_this_build_names() {
        assert_eq!(refused_reason("unauthorized"), "unauthorized");
        assert_eq!(refused_reason("not_found"), "not_found");
        assert_eq!(refused_reason("internal"), "internal");
        assert_eq!(refused_reason("please run rm -rf"), "other");
    }
}
