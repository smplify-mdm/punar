//! The approval store and the privilege-grant store (SPEC sections 28, 48;
//! docs/api/ipc.md sections 14–15).
//!
//! **One store, one lock, one expiry sweep.** Approvals gate punard
//! capabilities, broker issuance and human elevation, and grants are what an
//! approved elevation becomes. Splitting them would mean two lock orders and
//! two truths about `pending`; here they share a mutex, so there is exactly
//! one order in which punard ever takes them and no way to deadlock against
//! itself.
//!
//! # What lives on disk, and why root owns all of it
//!
//! ```text
//! /var/lib/punar/approvals/            0700 root:root
//! /var/lib/punar/approvals/<apr>.json  0600 root:root
//! /var/lib/punar/approvals/index.json  0600 root:root
//! /var/lib/punar/grants/               0700 root:root
//! /var/lib/punar/grants/<gnt>.json     0600 root:root
//! ```
//!
//! An approval a peer can rewrite is an authorization forgery, and a grant a
//! peer can write is a root shell with extra steps. Every write is atomic
//! and `fsync`ed ([`crate::util::write_atomic_synced`]): the dangerous
//! direction is asymmetric, and losing a *revocation* to a crash would
//! resurrect privilege the user handed back.
//!
//! # Expiry is lazy, and the cost is written down
//!
//! There is **no timer** (SPEC section 6.3). [`ApprovalStore::sweep`] runs on
//! every read, at resolve, at consume, and on each reconcile pass — which
//! reuses the existing `punard-reconcile.timer`. The honest consequence: an
//! `approval.expire` event's `timestamp` is when the lapse was *observed*,
//! while the record's `expires_at` is when it *occurred*. Both are in the
//! trail, so the instant is always recoverable, and no consumer may treat
//! the sweep as the authority on whether something has expired —
//! [`ApprovalEnvelope::has_lapsed`] against the clock is.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use punar_common::approval::{
    APPROVAL_RECORD_MAX_BYTES, APPROVALS_DIR_NAME, ApprovalEnvelope, ApprovalStatus,
    ApprovalsSummary, GRANTS_DIR_NAME, Grant, MAX_APPROVAL_RECORDS, SummaryApproval, SummaryGrant,
    SummaryRequester, validate_approval_schema,
};
use punar_common::time::{unix_seconds_from_rfc3339, utc_now_rfc3339};
use serde::{Deserialize, Serialize};

use crate::util::{remove_synced, write_atomic_synced};

/// Mode for every record and for the two directories.
const RECORD_MODE: u32 = 0o600;
const DIR_MODE: u32 = 0o700;
/// The summary file is group-readable so the shell (user `punar`) can watch
/// it; the *directory* above it is root-owned, which is the part that makes
/// it unspoofable (docs/api/ipc.md section 15).
const SUMMARY_MODE: u32 = 0o640;

/// The crash-recovery / quick-read index (design plan section 4.1). The
/// per-record files stay authoritative: this is a derived view, rebuilt from
/// them at every transition and at startup, so a damaged index costs a
/// rewrite and never a wrong answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Index {
    v: u64,
    updated_at: String,
    approvals: Vec<IndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexEntry {
    approval_id: String,
    kind: String,
    status: String,
    requester: String,
    capability: String,
    resource: String,
    created_at: String,
    expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resolved_at: Option<String>,
}

/// Approvals and grants, in memory and on disk.
#[derive(Debug)]
pub struct ApprovalStore {
    dir: PathBuf,
    grants_dir: PathBuf,
    summary_path: PathBuf,
    summary_gid: Option<u32>,
    records: BTreeMap<String, ApprovalEnvelope>,
    grants: BTreeMap<String, Grant>,
}

impl ApprovalStore {
    /// Open (creating) the stores under `state_dir` and load what is there.
    ///
    /// A record that will not parse is **quarantined, not fatal**: it is
    /// dropped from memory and left on disk with the reason logged. Refusing
    /// to boot over one damaged approval would take the whole device's
    /// policy engine down; forgetting a pending approval is fail-closed
    /// (nothing executes without a fresh, well-formed record).
    pub fn load(
        state_dir: &Path,
        summary_path: PathBuf,
        summary_gid: Option<u32>,
    ) -> io::Result<Self> {
        let dir = state_dir.join(APPROVALS_DIR_NAME);
        let grants_dir = state_dir.join(GRANTS_DIR_NAME);
        create_private_dir(&dir)?;
        create_private_dir(&grants_dir)?;

        let mut store = ApprovalStore {
            dir,
            grants_dir,
            summary_path,
            summary_gid,
            records: BTreeMap::new(),
            grants: BTreeMap::new(),
        };
        for (path, text) in read_json_files(&store.dir)? {
            if path.file_name().is_some_and(|n| n == "index.json") {
                continue;
            }
            match serde_json::from_str::<ApprovalEnvelope>(&text) {
                Ok(env) => {
                    store.records.insert(env.approval.approval_id.clone(), env);
                }
                Err(e) => eprintln!(
                    "punard: {} is not a readable approval record ({e}); ignored",
                    path.display()
                ),
            }
        }
        for (path, text) in read_json_files(&store.grants_dir)? {
            match serde_json::from_str::<Grant>(&text) {
                Ok(grant) => {
                    store.grants.insert(grant.grant_id.clone(), grant);
                }
                Err(e) => eprintln!(
                    "punard: {} is not a readable grant ({e}); ignored",
                    path.display()
                ),
            }
        }
        Ok(store)
    }

    /// Record file path for an approval id.
    fn record_path(&self, approval_id: &str) -> PathBuf {
        self.dir.join(format!("{approval_id}.json"))
    }

    fn grant_path(&self, grant_id: &str) -> PathBuf {
        self.grants_dir.join(format!("{grant_id}.json"))
    }

    /// One approval by id.
    pub fn get(&self, approval_id: &str) -> Option<&ApprovalEnvelope> {
        self.records.get(approval_id)
    }

    /// Every approval, pending first (soonest expiry first), then resolved
    /// newest-first — the reading order Plate D-003 and `punarctl approvals
    /// list` both want.
    pub fn list(&self) -> Vec<ApprovalEnvelope> {
        let mut pending: Vec<&ApprovalEnvelope> = Vec::new();
        let mut resolved: Vec<&ApprovalEnvelope> = Vec::new();
        for env in self.records.values() {
            if env.approval.status == ApprovalStatus::Pending {
                pending.push(env);
            } else {
                resolved.push(env);
            }
        }
        pending.sort_by(|a, b| a.approval.expires_at.cmp(&b.approval.expires_at));
        resolved.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        pending.into_iter().chain(resolved).cloned().collect()
    }

    /// Pending, unlapsed approvals device-wide.
    pub fn pending_count(&self, now: u64) -> usize {
        self.records
            .values()
            .filter(|env| env.is_answerable(now))
            .count()
    }

    /// Pending, unlapsed approvals raised by one requester id.
    pub fn pending_for_requester(&self, requester_id: &str, now: u64) -> usize {
        self.records
            .values()
            .filter(|env| env.is_answerable(now) && env.approval.requester.id == requester_id)
            .count()
    }

    /// Persist a new or updated record.
    ///
    /// Validates against the shipped schema first, so a non-conformant
    /// approval can never reach disk, the wire, or the overlay — and bounds
    /// the serialized size, because a record is read by a human under time
    /// pressure and an unbounded one is a denial-of-attention attack.
    pub fn put(&mut self, env: ApprovalEnvelope) -> io::Result<()> {
        if let Err(violations) = validate_approval_schema(&env.approval) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("approval does not conform to the schema: {violations:?}"),
            ));
        }
        let bytes = serde_json::to_vec_pretty(&env)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if bytes.len() > APPROVAL_RECORD_MAX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "approval record is {} bytes, over the {APPROVAL_RECORD_MAX_BYTES}-byte bound",
                    bytes.len()
                ),
            ));
        }
        write_atomic_synced(
            &self.record_path(&env.approval.approval_id),
            &bytes,
            RECORD_MODE,
        )?;
        self.records.insert(env.approval.approval_id.clone(), env);
        self.evict_if_needed()?;
        self.write_index()?;
        Ok(())
    }

    /// Keep at most [`MAX_APPROVAL_RECORDS`], evicting the oldest **resolved
    /// or expired** record first. A pending approval is never evicted: it is
    /// a live question, and the bound that stops those accumulating is
    /// `MAX_PENDING_APPROVALS` at creation time, not silent forgetting.
    fn evict_if_needed(&mut self) -> io::Result<()> {
        while self.records.len() > MAX_APPROVAL_RECORDS {
            let victim = self
                .records
                .values()
                .filter(|env| env.approval.status.is_terminal())
                .min_by(|a, b| a.created_at.cmp(&b.created_at))
                .map(|env| env.approval.approval_id.clone());
            let Some(id) = victim else { break };
            remove_synced(&self.record_path(&id))?;
            self.records.remove(&id);
        }
        Ok(())
    }

    /// Expire every pending record whose `expires_at` has passed, persist
    /// them, and return the newly expired ones so the caller can audit each
    /// (one `approval.expire` event apiece, never a batch).
    pub fn sweep(&mut self, now: u64) -> Vec<ApprovalEnvelope> {
        let lapsed: Vec<String> = self
            .records
            .values()
            .filter(|env| env.approval.status == ApprovalStatus::Pending && env.has_lapsed(now))
            .map(|env| env.approval.approval_id.clone())
            .collect();
        let mut expired = Vec::new();
        for id in lapsed {
            let Some(env) = self.records.get(&id) else {
                continue;
            };
            let mut env = env.clone();
            env.approval.status = ApprovalStatus::Expired;
            match self.put(env.clone()) {
                Ok(()) => expired.push(env),
                Err(e) => eprintln!("punard: could not persist the expiry of {id}: {e}"),
            }
        }
        expired
    }

    // -- grants -------------------------------------------------------------

    /// Persist a grant.
    pub fn put_grant(&mut self, grant: Grant) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(&grant)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_atomic_synced(&self.grant_path(&grant.grant_id), &bytes, RECORD_MODE)?;
        self.grants.insert(grant.grant_id.clone(), grant);
        Ok(())
    }

    /// The live grant authorizing `uid` to set `capability`, if any.
    ///
    /// Exact capability match only. There is no wildcard grant, no prefix
    /// match, and no "grants imply related capabilities" rule — SPEC section
    /// 48's whole point is that elevation is narrow.
    pub fn live_grant(&self, uid: u32, capability: &str, now: u64) -> Option<&Grant> {
        self.grants
            .values()
            .filter(|g| g.uid == uid && g.capability == capability && g.is_live(now))
            .max_by(|a, b| a.expires_at.cmp(&b.expires_at))
    }

    /// Live grants for one uid, or every live grant when `uid` is `None`
    /// (root's view).
    pub fn live_grants(&self, uid: Option<u32>, now: u64) -> Vec<Grant> {
        let mut grants: Vec<Grant> = self
            .grants
            .values()
            .filter(|g| g.is_live(now) && uid.is_none_or(|uid| g.uid == uid))
            .cloned()
            .collect();
        grants.sort_by(|a, b| a.expires_at.cmp(&b.expires_at));
        grants
    }

    /// Any grant by id, live or not.
    pub fn grant(&self, grant_id: &str) -> Option<&Grant> {
        self.grants.get(grant_id)
    }

    /// Drop a grant: unlink the record and forget it.
    ///
    /// Revocation **deletes** rather than tombstoning. The audit trail
    /// already carries `privilege.grant` and `privilege.revoke` events, so
    /// history is not lost; keeping a revoked grant on disk would only widen
    /// the window in which a bug could treat it as live.
    pub fn drop_grant(&mut self, grant_id: &str) -> io::Result<Option<Grant>> {
        let Some(grant) = self.grants.remove(grant_id) else {
            return Ok(None);
        };
        remove_synced(&self.grant_path(grant_id))?;
        Ok(Some(grant))
    }

    /// Remove every lapsed grant and return them, so the caller can audit
    /// one `privilege.expire` event apiece.
    pub fn sweep_grants(&mut self, now: u64) -> Vec<Grant> {
        let lapsed: Vec<String> = self
            .grants
            .values()
            .filter(|g| !g.is_live(now))
            .map(|g| g.grant_id.clone())
            .collect();
        let mut expired = Vec::new();
        for id in lapsed {
            match self.drop_grant(&id) {
                Ok(Some(grant)) => expired.push(grant),
                Ok(None) => {}
                Err(e) => eprintln!("punard: could not unlink the lapsed grant {id}: {e}"),
            }
        }
        expired
    }

    // -- published views ----------------------------------------------------

    fn write_index(&self) -> io::Result<()> {
        let index = Index {
            v: 1,
            updated_at: utc_now_rfc3339(),
            approvals: self
                .list()
                .iter()
                .map(|env| IndexEntry {
                    approval_id: env.approval.approval_id.clone(),
                    kind: env.kind.as_str().to_string(),
                    status: env.approval.status.as_str().to_string(),
                    requester: env.approval.requester.id.clone(),
                    capability: env.approval.capability.clone(),
                    resource: env.approval.resource.clone(),
                    created_at: env.created_at.clone(),
                    expires_at: env.approval.expires_at.clone(),
                    resolved_at: env.resolved_at.clone(),
                })
                .collect(),
        };
        let bytes = serde_json::to_vec_pretty(&index)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_atomic_synced(&self.dir.join("index.json"), &bytes, RECORD_MODE)
    }

    /// The shell's view (docs/api/ipc.md section 15): every pending approval
    /// plus recently resolved ones, and every live grant.
    ///
    /// Non-authoritative by contract. The overlay's Approve sends only an
    /// `approval_id` and punard re-derives everything from its own record —
    /// so the worst a stale summary can do is show a card that is already
    /// answered, which the daemon then refuses with `conflict`.
    pub fn publish_summary(&self, now: u64) -> io::Result<()> {
        if let Some(parent) = self.summary_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let summary = ApprovalsSummary {
            v: 1,
            updated_at: utc_now_rfc3339(),
            approvals: self
                .list()
                .into_iter()
                .take(MAX_SUMMARY_APPROVALS)
                .map(summary_row)
                .collect(),
            grants: self
                .live_grants(None, now)
                .into_iter()
                .map(|g| SummaryGrant {
                    grant_id: g.grant_id,
                    capability: g.capability,
                    expires_at: g.expires_at,
                })
                .collect(),
        };
        let bytes = serde_json::to_vec(&summary)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_atomic_synced(&self.summary_path, &bytes, SUMMARY_MODE)?;
        if let Some(gid) = self.summary_gid {
            // Meaningful only as root; harmless EPERM otherwise (tests).
            let _ = std::os::unix::fs::chown(&self.summary_path, Some(0), Some(gid));
        }
        Ok(())
    }
}

/// How many approvals the shell view carries. The overlay renders pending
/// ones and a short tail of recent verdicts; the socket is there for anyone
/// who wants the rest.
const MAX_SUMMARY_APPROVALS: usize = 20;

fn summary_row(env: ApprovalEnvelope) -> SummaryApproval {
    SummaryApproval {
        approval_id: env.approval.approval_id,
        kind: env.kind,
        status: env.approval.status,
        requester: SummaryRequester {
            kind: env.approval.requester.kind,
            id: env.approval.requester.id,
            // Always None in M9, deliberately: see `SummaryRequester`.
            agent_name: None,
        },
        user: env.approval.user,
        capability: env.approval.capability,
        resource: env.approval.resource,
        risk: env.approval.risk,
        reason: env.approval.reason,
        contract: env.contract,
        policy: env.policy,
        created_at: env.created_at,
        expires_at: env.approval.expires_at,
        execution: env.execution,
    }
}

/// `mkdir -p` with `0700`, and tighten an existing directory that is looser.
fn create_private_dir(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(DIR_MODE))
}

/// Every `*.json` in `dir` as `(path, contents)`, ascending by name.
fn read_json_files(dir: &Path) -> io::Result<Vec<(PathBuf, String)>> {
    let mut paths: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
            .collect(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    paths.sort();
    let mut out = Vec::new();
    for path in paths {
        match std::fs::read_to_string(&path) {
            Ok(text) => out.push((path, text)),
            Err(e) => eprintln!("punard: could not read {}: {e}", path.display()),
        }
    }
    Ok(out)
}

/// Seconds since the epoch, for the expiry comparisons. A clock before the
/// epoch reads as 0, which expires everything — fail closed, like every
/// other unreadable-time path in this module.
pub fn now_secs() -> u64 {
    unix_seconds_from_rfc3339(&utc_now_rfc3339()).unwrap_or(0)
}

/// `now + secs` as an RFC 3339 string.
pub fn rfc3339_in(secs: u64) -> String {
    punar_common::time::rfc3339_utc_from_unix_seconds(now_secs().saturating_add(secs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use punar_common::PrincipalKind;
    use punar_common::Risk;
    use punar_common::approval::{
        Approval, ApprovalKind, ApprovalRequest, PolicyCitation, Requester,
    };
    use serde_json::json;

    fn dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "punard-approvals-{tag}-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn store(tag: &str) -> (PathBuf, ApprovalStore) {
        let dir = dir(tag);
        let store = ApprovalStore::load(&dir, dir.join("approvals.json"), None).unwrap();
        (dir, store)
    }

    fn envelope(id: &str, requester: &str, expires_in: i64) -> ApprovalEnvelope {
        let expires = (now_secs() as i64 + expires_in).max(0) as u64;
        ApprovalEnvelope {
            v: 1,
            approval: Approval {
                approval_id: id.to_string(),
                requester: Requester {
                    kind: PrincipalKind::AiAgent,
                    id: requester.to_string(),
                },
                user: "punar".to_string(),
                capability: "security.firewall".to_string(),
                resource: "disabled".to_string(),
                reason: "Atlas integration test".to_string(),
                risk: Risk::High,
                status: ApprovalStatus::Pending,
                expires_at: punar_common::time::rfc3339_utc_from_unix_seconds(expires),
            },
            kind: ApprovalKind::CapabilitySet,
            created_at: utc_now_rfc3339(),
            request: ApprovalRequest {
                method: "capabilities.set".to_string(),
                params: json!({"capability": "security.firewall", "desired_state": "disabled"}),
            },
            requester_peer: None,
            policy: PolicyCitation {
                name: "Personal defaults".to_string(),
                policy_id: "personal-defaults".to_string(),
            },
            contract: "SetFirewall(disabled)".to_string(),
            resolved_at: None,
            resolved_by: None,
            consumed_at: None,
            execution: None,
        }
    }

    fn grant(id: &str, uid: u32, capability: &str, expires_in: i64) -> Grant {
        let expires = (now_secs() as i64 + expires_in).max(0) as u64;
        Grant {
            v: 1,
            grant_id: id.to_string(),
            approval_id: "apr_00000001".to_string(),
            uid,
            user: "punar".to_string(),
            capability: capability.to_string(),
            reason: "Reproducing the Atlas net bug".to_string(),
            granted_at: utc_now_rfc3339(),
            expires_at: punar_common::time::rfc3339_utc_from_unix_seconds(expires),
            revoked_at: None,
        }
    }

    #[test]
    fn records_round_trip_through_disk_and_the_directory_is_private() {
        let (dir, mut store) = store("roundtrip");
        store.put(envelope("apr_0000aa01", "agt_one", 300)).unwrap();
        store.publish_summary(now_secs()).unwrap();

        let mode = |p: &Path| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(p).unwrap().permissions().mode() & 0o777
        };
        assert_eq!(mode(&dir.join("approvals")), 0o700);
        assert_eq!(mode(&dir.join("approvals/apr_0000aa01.json")), 0o600);
        assert_eq!(mode(&dir.join("approvals.json")), 0o640);

        // A fresh store sees exactly what the old one wrote.
        let reopened = ApprovalStore::load(&dir, dir.join("approvals.json"), None).unwrap();
        let env = reopened.get("apr_0000aa01").unwrap();
        assert_eq!(env.approval.status, ApprovalStatus::Pending);
        assert_eq!(env.contract, "SetFirewall(disabled)");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The persisted record's `approval` member is the shipped schema
    /// document and nothing else — the assertion `m9-check` mirrors in-VM.
    #[test]
    fn the_persisted_record_keeps_the_document_and_the_siblings_apart() {
        let (dir, mut store) = store("shape");
        store.put(envelope("apr_0000aa02", "agt_one", 300)).unwrap();
        let text = std::fs::read_to_string(dir.join("approvals/apr_0000aa02.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let document = value["approval"].as_object().unwrap();
        assert_eq!(document.len(), 9);
        for sibling in ["kind", "created_at", "request", "policy", "contract"] {
            assert!(!document.contains_key(sibling));
            assert!(value.get(sibling).is_some());
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A record that does not conform never reaches disk — the store is the
    /// last place the schema can still be defended.
    #[test]
    fn a_nonconformant_record_is_refused_before_it_is_written() {
        let (dir, mut store) = store("bad");
        let mut env = envelope("apr_0000aa03", "agt_one", 300);
        env.approval.reason = "line one\nline two".to_string();
        assert!(store.put(env).is_err());
        assert!(!dir.join("approvals/apr_0000aa03.json").exists());

        let mut env = envelope("not-an-id", "agt_one", 300);
        env.approval.approval_id = "not-an-id".to_string();
        assert!(store.put(env).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_sweep_expires_lapsed_pending_records_only_once() {
        let (dir, mut store) = store("sweep");
        store.put(envelope("apr_0000bb01", "agt_one", -1)).unwrap();
        store.put(envelope("apr_0000bb02", "agt_one", 300)).unwrap();

        let expired = store.sweep(now_secs());
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].approval.approval_id, "apr_0000bb01");
        assert_eq!(expired[0].approval.status, ApprovalStatus::Expired);
        // Idempotent: a second sweep has nothing left to expire, so the
        // trail gets exactly one `approval.expire` event per approval.
        assert!(store.sweep(now_secs()).is_empty());
        assert_eq!(store.pending_count(now_secs()), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pending_counts_drive_the_flood_bounds() {
        let (dir, mut store) = store("counts");
        store.put(envelope("apr_0000cc01", "agt_one", 300)).unwrap();
        store.put(envelope("apr_0000cc02", "agt_one", 300)).unwrap();
        store.put(envelope("apr_0000cc03", "agt_two", 300)).unwrap();
        // A lapsed approval is not pending, even before anyone sweeps.
        store.put(envelope("apr_0000cc04", "agt_two", -5)).unwrap();

        let now = now_secs();
        assert_eq!(store.pending_count(now), 3);
        assert_eq!(store.pending_for_requester("agt_one", now), 2);
        assert_eq!(store.pending_for_requester("agt_two", now), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn listing_puts_pending_first_by_soonest_expiry() {
        let (dir, mut store) = store("order");
        store.put(envelope("apr_0000dd01", "agt_one", 300)).unwrap();
        store.put(envelope("apr_0000dd02", "agt_one", 60)).unwrap();
        let mut resolved = envelope("apr_0000dd03", "agt_one", 300);
        resolved.approval.status = ApprovalStatus::Denied;
        store.put(resolved).unwrap();

        let ids: Vec<String> = store
            .list()
            .into_iter()
            .map(|e| e.approval.approval_id)
            .collect();
        assert_eq!(ids, ["apr_0000dd02", "apr_0000dd01", "apr_0000dd03"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn grants_are_exact_matches_and_expire_for_real() {
        let (dir, mut store) = store("grants");
        store
            .put_grant(grant("gnt_0000aa01", 1000, "time.timezone", 60))
            .unwrap();
        let now = now_secs();
        assert!(store.live_grant(1000, "time.timezone", now).is_some());
        // Wrong uid, wrong capability, no prefix magic: all refused.
        assert!(store.live_grant(1001, "time.timezone", now).is_none());
        assert!(store.live_grant(1000, "security.firewall", now).is_none());
        assert!(store.live_grant(1000, "time", now).is_none());
        // Past its window it authorizes nothing, sweep or no sweep.
        assert!(store.live_grant(1000, "time.timezone", now + 61).is_none());

        let expired = store.sweep_grants(now + 61);
        assert_eq!(expired.len(), 1);
        assert!(!dir.join("grants/gnt_0000aa01.json").exists());
        assert!(store.sweep_grants(now + 61).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn revoking_a_grant_unlinks_it_and_is_idempotent() {
        let (dir, mut store) = store("revoke");
        store
            .put_grant(grant("gnt_0000bb01", 1000, "time.timezone", 600))
            .unwrap();
        assert!(store.drop_grant("gnt_0000bb01").unwrap().is_some());
        assert!(store.drop_grant("gnt_0000bb01").unwrap().is_none());
        assert!(store.live_grants(None, now_secs()).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_summary_carries_the_overlay_fields_and_no_agent_name() {
        let (dir, mut store) = store("summary");
        store.put(envelope("apr_0000ee01", "agt_one", 300)).unwrap();
        store
            .put_grant(grant("gnt_0000cc01", 1000, "time.timezone", 600))
            .unwrap();
        store.publish_summary(now_secs()).unwrap();

        let text = std::fs::read_to_string(dir.join("approvals.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["v"], 1);
        let row = &value["approvals"][0];
        assert_eq!(row["approval_id"], "apr_0000ee01");
        assert_eq!(row["contract"], "SetFirewall(disabled)");
        assert_eq!(row["policy"]["policy_id"], "personal-defaults");
        assert_eq!(row["risk"], "high");
        assert_eq!(row["requester"]["type"], "ai_agent");
        assert!(row["requester"].get("agent_name").is_none());
        assert_eq!(value["grants"][0]["grant_id"], "gnt_0000cc01");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A damaged record must not take the daemon down with it.
    #[test]
    fn an_unreadable_record_is_quarantined_not_fatal() {
        let (dir, mut store) = store("quarantine");
        store.put(envelope("apr_0000ff01", "agt_one", 300)).unwrap();
        std::fs::write(dir.join("approvals/apr_0000ff02.json"), "{not json").unwrap();

        let reopened = ApprovalStore::load(&dir, dir.join("approvals.json"), None).unwrap();
        assert!(reopened.get("apr_0000ff01").is_some());
        assert!(reopened.get("apr_0000ff02").is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
