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
use crate::enroll::{Assignment, FetchedPolicy, PolicyFields, apply_policy_fields};

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
/// the control plane is up, and the set is what failed.
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

/// The longest control-plane or loader text the journal repeats.
const JOURNAL_DETAIL_CHARS: usize = 512;

/// Text the device did not write, fit for one journal line: cut to
/// [`JOURNAL_DETAIL_CHARS`] and escaped, so it cannot forge a line of its own.
fn journal_detail(text: &str) -> String {
    let cut: String = text.chars().take(JOURNAL_DETAIL_CHARS).collect();
    format!("{cut:?}")
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

/// What a committed set changed, for the audit and the in-memory swap.
struct Committed {
    result: RefreshResult,
    ids: Vec<String>,
    rendered_changed: bool,
}

impl Inner {
    /// One refresh opportunity. See the module documentation.
    pub(super) fn refresh_policy_if_enrolled(&self, actor: &AuditActor) {
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
        let client = ControlPlaneClient::new(&self.cfg.control_plane_socket);
        let failed = match client.policy_fetch(&token) {
            Ok(fetched) => {
                self.policy_refresh_backoff.lock().unwrap().answered();
                // Checking and committing hold the enrollment guard, and
                // never wait for it: an enroll.start or enroll.stop in
                // progress will leave nothing this answer is for, and the
                // next pass asks again.
                let Some(_guard) = EnrollGuard::acquire(&self.enroll_in_progress) else {
                    return;
                };
                self.refresh_under_guard(actor, epoch, fetched);
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

    fn refresh_under_guard(&self, actor: &AuditActor, epoch: u64, fetched: FetchedPolicy) {
        // The enrollment the fetch was made for, still the one in the slot.
        let owned_files = {
            let slot = self.enrollment.lock().unwrap();
            match slot.as_ref() {
                Some(current) if self.enrollment_epoch.load(Ordering::SeqCst) == epoch => {
                    current.policy_files.clone()
                }
                _ => return,
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
                self.record_refresh(
                    actor,
                    epoch,
                    Outcome::new(RefreshResult::Held, Some(reason)),
                );
                return;
            }
        }
        let set = match CanonicalSet::from_envelopes(&fetched.policies, fetched.assignment) {
            Ok(set) => set,
            Err(rejection) => {
                let mut outcome = Outcome::new(RefreshResult::Rejected, Some(rejection.reason()));
                outcome.offered_hash = Some(offered_list_hash(&fetched.policies));
                outcome.detail = Some(rejection.describe());
                self.record_refresh(actor, epoch, outcome);
                return;
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
                self.record_refresh(actor, epoch, outcome);
                return;
            }
        };
        self.backfill_revision(epoch, &owned_now);
        if set == owned_now {
            self.record_refresh(actor, epoch, Outcome::new(RefreshResult::Unchanged, None));
            return;
        }
        let offered = set.revision();

        // The very set this daemon already refused, for a reason that cannot
        // have changed since: not checked again.
        let memo = self.policy_rejected_offer.lock().unwrap().clone();
        if let Some((memo_epoch, memo_offer, reason)) = memo {
            if memo_epoch == epoch && memo_offer == offered {
                let mut outcome = Outcome::new(RefreshResult::Rejected, Some(reason));
                outcome.offered_hash = Some(offered);
                self.record_refresh(actor, epoch, outcome);
                return;
            }
        }

        let prepared = match policy_set::prepare(&self.cfg.state_dir, &set, &owned_files) {
            Ok(prepared) => prepared,
            Err(error) => {
                policy_set::discard_staging(&self.cfg.state_dir);
                let outcome = match error {
                    PrepareError::Rejected(rejection) => {
                        // A collision depends on this device's own files,
                        // which root may change at any time: checked again.
                        if !matches!(rejection, Rejection::ForeignFileCollision(_)) {
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
                        let mut outcome =
                            Outcome::new(RefreshResult::Failed, Some(failure.reason()));
                        outcome.detail = Some(failure.to_string());
                        outcome
                    }
                };
                self.record_refresh(actor, epoch, outcome);
                return;
            }
        };
        let staging = prepared.staging().to_path_buf();
        let loaded = prepared.loaded;

        let committed = match self.commit_set(epoch, &set, &staging, &loaded) {
            Ok(Some(committed)) => committed,
            Ok(None) => {
                // The enrollment ended or changed while the set was checked.
                policy_set::discard_staging(&self.cfg.state_dir);
                return;
            }
            Err(failure) => {
                policy_set::discard_staging(&self.cfg.state_dir);
                let mut outcome = Outcome::new(RefreshResult::Failed, Some(failure.reason()));
                outcome.detail = Some(failure.to_string());
                self.record_refresh(actor, epoch, outcome);
                return;
            }
        };

        // The new layers, in the order a restart would load them, then the
        // AI authority and the effective document. A capability whose value
        // changed leaves remediation suppression in recompute_effective;
        // browser.policy stays "managed" when only its document changes, so
        // it is released here.
        // The paths are the organization's own keys: escaped, like every
        // other string from it that reaches the journal.
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

        eprintln!(
            "punard: the organization's policy was {} ({offered}): {}",
            committed.result.as_str(),
            if committed.ids.is_empty() {
                "no policies".to_string()
            } else {
                committed.ids.join(", ")
            }
        );
        self.log_audit(self.enroll_event(
            actor,
            "enroll.policy",
            RESOURCE_CONTROL_PLANE,
            committed.result.as_str(),
            committed.ids,
        ));
    }

    /// Make a prepared set the enforced one, on disk. The record is written
    /// first with the old and new files together, so a crash never leaves a
    /// file in policy.d that no record owns ([`policy_set::settle`] trims it
    /// at the next start); then policy.d is swapped whole; then the browser
    /// document; then the record says what is enforced. A failure undoes
    /// every step before it. `None`: the enrollment is no longer the one the
    /// set was fetched for, and nothing was touched.
    fn commit_set(
        &self,
        epoch: u64,
        set: &CanonicalSet,
        staging: &Path,
        loaded: &crate::policy::LoadedPolicies,
    ) -> Result<Option<Committed>, policy_set::LocalFailure> {
        use policy_set::LocalFailure;
        let record_path = self.cfg.state_dir.join("enrollment.json");
        let policy_dir = self.cfg.state_dir.join(policy_set::POLICY_DIR);
        let now = utc_now_rfc3339();

        // Only file work under this lock, and no other lock taken inside it.
        let mut slot = self.enrollment.lock().unwrap();
        let Some(current) = slot
            .as_mut()
            .filter(|_| self.enrollment_epoch.load(Ordering::SeqCst) == epoch)
        else {
            return Ok(None);
        };
        let before = current.policy_fields();
        let undo_record = |current: &mut Enrollment| {
            apply_policy_fields(current, before.clone());
            if let Err(e) = save_enrollment_durable(&record_path, current) {
                eprintln!("punard: could not restore the policy record ({e}); settled at start");
            }
        };

        let mut both: BTreeSet<String> = before.files.iter().cloned().collect();
        both.extend(set.names());
        let mut union = before.clone();
        union.files = both.into_iter().collect();
        apply_policy_fields(current, union);
        if let Err(e) = save_enrollment_durable(&record_path, current) {
            apply_policy_fields(current, before.clone());
            return Err(LocalFailure::Io(e));
        }

        let previous_rendered = read_if_present(&self.cfg.browser_policy_source);
        let swapped = match policy_set::swap_in(staging, &policy_dir) {
            Ok(swapped) => swapped,
            Err(failure) => {
                undo_record(current);
                return Err(failure);
            }
        };
        if let Err(e) = persist_rendered_browser_policy(
            &self.cfg.browser_policy_source,
            &loaded.applications,
            &loaded.browsers,
        ) {
            if let Err(undo) = swapped.roll_back() {
                eprintln!("punard: could not restore policy.d after a failed refresh: {undo}");
            }
            restore_rendered(&self.cfg.browser_policy_source, previous_rendered);
            undo_record(current);
            return Err(LocalFailure::Io(e));
        }
        let rendered_changed =
            read_if_present(&self.cfg.browser_policy_source) != previous_rendered;

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
            },
        );
        if let Err(e) = save_enrollment_durable(&record_path, current) {
            // The record on disk still owns both sets' files, which is safe:
            // the next start trims it to what policy.d holds.
            eprintln!("punard: could not save the refreshed policy record: {e}");
        }
        drop(slot);
        if let Err(e) = swapped.finish() {
            eprintln!("punard: could not remove the replaced policy.d ({e}); removed at start");
        }
        Ok(Some(Committed {
            result,
            ids,
            rendered_changed,
        }))
    }

    /// An enrollment recorded before revisions existed learns the one it
    /// enforces, derived from its files, whatever this refresh ends in: for
    /// `enroll.status` only, in memory until the next save.
    fn backfill_revision(&self, epoch: u64, owned_now: &CanonicalSet) {
        let mut slot = self.enrollment.lock().unwrap();
        let Some(current) = slot
            .as_mut()
            .filter(|_| self.enrollment_epoch.load(Ordering::SeqCst) == epoch)
        else {
            return;
        };
        if current.policy_hash.is_none() {
            let mut fields = current.policy_fields();
            fields.hash = Some(owned_now.revision());
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
    use super::*;

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
