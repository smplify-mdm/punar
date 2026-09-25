//! The organization's policy set as punard receives, checks and installs it
//! (docs/api/ipc.md section 5.9). `enroll.start` and the live policy refresh
//! share every rule here, so a set a refresh would refuse can never arrive
//! by enrolling, nor the reverse.
//!
//! The one property all of it serves: **`policy.d` never holds a set that
//! fails to load.** punard refuses to start on one (a corrupt policy layer is
//! not something to guess around), and punar-secrets reads the same
//! directory independently. So a new set is written, loaded and rendered in
//! a staging directory beside `policy.d`, and only a set that passed all of
//! it replaces `policy.d`, whole, in one `renameat2(RENAME_EXCHANGE)`. There
//! is no moment, crash included, at which the directory holds part of an old
//! set and part of a new one, and nothing a failed check touched is live.
//!
//! What stays with the device, whatever the organization serves:
//!
//! - files a root administrator dropped into `policy.d` (an AI authority
//!   `.yaml`, a local envelope): carried into the new directory as hard links
//!   to the same inode, never overwritten, never taken over. A set that names
//!   one of them is refused.
//! - the ladder's non-organizational rungs. The organization may publish only
//!   organization kinds, so a control plane cannot label its layer a hard OS
//!   safety constraint, a person's own preference or the OS default.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::browser_policy::{render_effective_browser_policy, validate_rendered_policy};
use crate::enroll::{Assignment, Enrollment, apply_policy_fields};
use crate::policy::{LoadedPolicies, load_policy_dir};
use crate::util::{sha256_hex, write_atomic_synced};

/// The organization layer directory inside the state directory.
pub const POLICY_DIR: &str = "policy.d";

/// Where a set is prepared before it replaces [`POLICY_DIR`]. One name for
/// `enroll.start` and refresh alike, so whatever a crash leaves behind is
/// found by one sweep ([`settle`]). The leading dot keeps it apart from any
/// name a policy id can produce.
pub const STAGING_DIR: &str = ".policy.d.next";

/// The staging directory of builds before the live refresh.
const LEGACY_STAGING_DIR: &str = ".policy.d.enroll-staging";

/// At most this many envelopes in one set.
pub const MAX_POLICIES: usize = 64;

/// A policy id is at most this many characters.
pub const MAX_POLICY_ID_CHARS: usize = 128;

/// One canonical envelope is at most this many bytes. With
/// [`MAX_POLICIES`], it bounds a set well inside the client's answer bound
/// (`crate::enroll::MAX_ANSWER_BYTES`).
pub const MAX_ENVELOPE_BYTES: usize = 256 * 1024;

/// The source kinds an organization may publish (SPEC section 39). The other
/// three rungs belong to the OS and the person: an `os_hard_safety_constraint`
/// from a control plane would outrank every guarantee the OS makes, and a
/// `local_user_preference` would speak for the person.
pub const ORGANIZATIONAL_SOURCE_KINDS: [&str; 4] = [
    "organization_baseline",
    "organization_role_policy",
    "temporary_approved_exception",
    "device_specific_override",
];

/// The best (lowest) rank an organization's `device_specific_override` may
/// claim: the organization baseline's rung. That kind's rank is stored data
/// rather than fixed by the ladder, and rank 1 would place it with the OS's
/// hard safety constraints, which the kind allowlist alone would not stop.
pub const MIN_ORGANIZATIONAL_RANK: u64 = 2;

/// Why the organization's set was refused. Its fault, not the device's: the
/// same set is refused again wherever it is offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    TooManyPolicies,
    NotAnObject,
    UnusablePolicyId,
    DuplicatePolicyId,
    EnvelopeTooLarge,
    SourceKindNotOrganizational,
    RankNotOrganizational,
    /// `assignment: none` or `unusable` alongside a non-empty list.
    InconsistentAssignment,
    /// The loader refused it; its message.
    InvalidEnvelope(String),
    /// It names a file a root administrator dropped into `policy.d`.
    ForeignFileCollision(String),
    /// Its browser policy did not render into an allowlisted document.
    BrowserPolicyRefused(String),
}

impl Rejection {
    /// The closed reason code `enroll.status` and the journal carry.
    pub fn reason(&self) -> &'static str {
        match self {
            Rejection::TooManyPolicies => "too_many_policies",
            Rejection::NotAnObject => "envelope_not_an_object",
            Rejection::UnusablePolicyId => "unusable_policy_id",
            Rejection::DuplicatePolicyId => "duplicate_policy_id",
            Rejection::EnvelopeTooLarge => "envelope_too_large",
            Rejection::SourceKindNotOrganizational => "source_kind_not_organizational",
            Rejection::RankNotOrganizational => "rank_not_organizational",
            Rejection::InconsistentAssignment => "inconsistent_assignment",
            Rejection::InvalidEnvelope(_) => "invalid_envelope",
            Rejection::ForeignFileCollision(_) => "foreign_file_collision",
            Rejection::BrowserPolicyRefused(_) => "browser_policy_refused",
        }
    }

    /// What was wrong, in words, for the journal and `enroll.start`'s
    /// refusal: fixed text, plus the colliding file's name, which passed the
    /// policy-id rules.
    pub fn describe(&self) -> String {
        match self {
            Rejection::TooManyPolicies => format!("more than {MAX_POLICIES} policies"),
            Rejection::NotAnObject => "an envelope that is not a JSON object".to_string(),
            Rejection::UnusablePolicyId => "an envelope without a usable policy_id".to_string(),
            Rejection::DuplicatePolicyId => "two envelopes with the same policy_id".to_string(),
            Rejection::EnvelopeTooLarge => {
                format!("an envelope larger than {} KiB", MAX_ENVELOPE_BYTES / 1024)
            }
            Rejection::SourceKindNotOrganizational => {
                "a policy whose source kind is not one an organization may publish".to_string()
            }
            Rejection::RankNotOrganizational => {
                "a device-specific override ranked with the OS's hard safety constraints"
                    .to_string()
            }
            Rejection::InconsistentAssignment => {
                "policies alongside an answer saying none are usable or assigned".to_string()
            }
            Rejection::InvalidEnvelope(_) => "an envelope the policy loader refuses".to_string(),
            Rejection::ForeignFileCollision(name) => {
                format!("a policy named like the local file policy.d/{name}")
            }
            Rejection::BrowserPolicyRefused(_) => {
                "browser policy that does not render safely".to_string()
            }
        }
    }

    /// The loader's or renderer's own words, or the colliding file, when
    /// there are any. For the journal and `enroll.start`'s refusal only: the
    /// audit trail has no free-text field.
    pub fn detail(&self) -> Option<&str> {
        match self {
            Rejection::InvalidEnvelope(detail)
            | Rejection::ForeignFileCollision(detail)
            | Rejection::BrowserPolicyRefused(detail) => Some(detail),
            _ => None,
        }
    }
}

/// Why a set that may be perfectly good could not be installed on this
/// device. Never blamed on the organization.
#[derive(Debug)]
pub enum LocalFailure {
    Io(io::Error),
    /// `policy.d` holds something that cannot be carried into a new
    /// directory unchanged (a non-empty subdirectory, a FIFO, …).
    UnsupportedEntry(String),
    /// The organization's set loads alone but not beside the files a root
    /// administrator dropped (a policy id both use, say).
    ConflictsWithLocalPolicy(String),
    /// The filesystem cannot exchange two directories atomically. There is no
    /// non-atomic fallback: a half-replaced `policy.d` is the one outcome
    /// this module exists to prevent.
    SwapUnsupported,
}

impl LocalFailure {
    /// The closed reason code `enroll.status` and the journal carry.
    pub fn reason(&self) -> &'static str {
        match self {
            LocalFailure::Io(_) => "io",
            LocalFailure::UnsupportedEntry(_) => "unsupported_entry",
            LocalFailure::ConflictsWithLocalPolicy(_) => "conflicts_with_local_policy",
            LocalFailure::SwapUnsupported => "swap_unsupported",
        }
    }
}

impl std::fmt::Display for LocalFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocalFailure::Io(e) => write!(f, "{e}"),
            LocalFailure::UnsupportedEntry(name) => {
                write!(f, "policy.d holds {name:?}, which cannot be carried over")
            }
            LocalFailure::ConflictsWithLocalPolicy(e) => {
                write!(f, "it conflicts with a file in policy.d: {e}")
            }
            LocalFailure::SwapUnsupported => {
                write!(f, "this filesystem cannot exchange directories atomically")
            }
        }
    }
}

/// What [`prepare`] can end in.
#[derive(Debug)]
pub enum PrepareError {
    Rejected(Rejection),
    Local(LocalFailure),
}

impl From<io::Error> for PrepareError {
    fn from(e: io::Error) -> Self {
        PrepareError::Local(LocalFailure::Io(e))
    }
}

/// A set of policy-source envelopes in the exact bytes `policy.d` holds:
/// file name (`<policy_id>.json`) → pretty JSON with sorted keys. Two
/// fetches of the same policy compare equal byte for byte, whatever order
/// the control plane listed them in or spelled their keys in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CanonicalSet {
    files: BTreeMap<String, Vec<u8>>,
}

impl CanonicalSet {
    /// Check a fetched list and put it in canonical form. The rules run in
    /// this order, and the first that fails refuses the whole set.
    pub fn from_envelopes(
        envelopes: &[Value],
        assignment: Assignment,
    ) -> Result<CanonicalSet, Rejection> {
        if envelopes.len() > MAX_POLICIES {
            return Err(Rejection::TooManyPolicies);
        }
        let mut files = BTreeMap::new();
        for envelope in envelopes {
            let Some(object) = envelope.as_object() else {
                return Err(Rejection::NotAnObject);
            };
            let Some(policy_id) = object
                .get("policy_id")
                .and_then(Value::as_str)
                .filter(|id| policy_id_ok(id))
            else {
                return Err(Rejection::UnusablePolicyId);
            };
            let name = format!("{policy_id}.json");
            if files.contains_key(&name) {
                return Err(Rejection::DuplicatePolicyId);
            }
            // serde_json's map is ordered by key unless its `preserve_order`
            // feature is on, which no workspace manifest enables; a unit test
            // pins it, because a dependency switching it on would make every
            // fetch look like a change.
            let bytes =
                serde_json::to_vec_pretty(envelope).expect("fetched envelopes re-serialize");
            if bytes.len() > MAX_ENVELOPE_BYTES {
                return Err(Rejection::EnvelopeTooLarge);
            }
            let kind = object.get("source_kind").and_then(Value::as_str);
            if !kind.is_some_and(|kind| ORGANIZATIONAL_SOURCE_KINDS.contains(&kind)) {
                return Err(Rejection::SourceKindNotOrganizational);
            }
            let rank = object.get("precedence_rank").and_then(Value::as_u64);
            if kind == Some("device_specific_override")
                && rank.is_some_and(|rank| rank < MIN_ORGANIZATIONAL_RANK)
            {
                return Err(Rejection::RankNotOrganizational);
            }
            files.insert(name, bytes);
        }
        if !files.is_empty()
            && matches!(assignment, Assignment::NoneAssigned | Assignment::Unusable)
        {
            return Err(Rejection::InconsistentAssignment);
        }
        Ok(CanonicalSet { files })
    }

    /// Read back the files an enrollment owns, as they are now. A file that
    /// is missing is simply absent from the set, so it compares unequal to
    /// the fetched one and is written again.
    pub fn read_owned(policy_dir: &Path, owned: &[String]) -> io::Result<CanonicalSet> {
        let mut files = BTreeMap::new();
        for name in owned {
            // The record is punard's own, but a name that is not one this
            // module could have written is never joined onto a path.
            if !owned_name_ok(name) {
                continue;
            }
            match fs::read(policy_dir.join(name)) {
                Ok(bytes) => {
                    files.insert(name.clone(), bytes);
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(CanonicalSet { files })
    }

    pub fn files(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.files
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// The file names, sorted.
    pub fn names(&self) -> Vec<String> {
        self.files.keys().cloned().collect()
    }

    /// The policy ids, sorted by file name.
    pub fn ids(&self) -> Vec<String> {
        self.files
            .keys()
            .map(|name| name.trim_end_matches(".json").to_string())
            .collect()
    }

    /// `sha256:` over every file, name and length first, in name order: the
    /// same set always has the same revision, and it can be recomputed from
    /// `policy.d` alone.
    pub fn revision(&self) -> String {
        let mut framed = Vec::new();
        for (name, bytes) in &self.files {
            framed.extend_from_slice(name.as_bytes());
            framed.push(0);
            framed.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            framed.extend_from_slice(bytes);
        }
        format!("sha256:{}", sha256_hex(&framed))
    }
}

/// `[A-Za-z0-9._-]`, 1–128 characters, and no leading dot: a file name that
/// can never be `.`/`..`, a hidden name, or the temporary name `write_atomic`
/// gives a file while writing it (`.<name>.punard-tmp.<pid>`).
fn policy_id_ok(id: &str) -> bool {
    !id.is_empty()
        && id.chars().count() <= MAX_POLICY_ID_CHARS
        && !id.starts_with('.')
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn owned_name_ok(name: &str) -> bool {
    name.strip_suffix(".json").is_some_and(policy_id_ok)
}

/// A set staged beside `policy.d` that loads and renders, alone and together
/// with what a root administrator dropped there. After [`prepare`] only I/O
/// can fail.
#[derive(Debug)]
pub struct Prepared {
    /// Exactly what the next boot would load from the new `policy.d`.
    pub loaded: LoadedPolicies,
    staging: PathBuf,
}

impl Prepared {
    pub fn staging(&self) -> &Path {
        &self.staging
    }
}

/// Stage `set` in [`STAGING_DIR`] as the next `policy.d`, and check it the
/// way startup would: the organization's files alone through the loader and
/// the browser-policy renderer (a failure is a [`Rejection`]), then with
/// every file of `policy.d` that `owned_now` does not name carried over
/// (a failure is the device's, [`LocalFailure`]). The live directory is only
/// read. The caller removes the staging directory on an error
/// ([`discard_staging`]).
pub fn prepare(
    state_dir: &Path,
    set: &CanonicalSet,
    owned_now: &[String],
) -> Result<Prepared, PrepareError> {
    let staging = state_dir.join(STAGING_DIR);
    remove_dir_if_present(&staging)?;
    fs::DirBuilder::new().mode(0o700).create(&staging)?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))?;
    for (name, bytes) in &set.files {
        write_atomic_synced(&staging.join(name), bytes, 0o600)?;
    }

    // The organization's files alone: whatever fails here is the set's own.
    let organization_only = load_policy_dir(&staging)
        .map_err(|e| PrepareError::Rejected(Rejection::InvalidEnvelope(e.to_string())))?;
    render_checked(&organization_only)
        .map_err(|e| PrepareError::Rejected(Rejection::BrowserPolicyRefused(e.to_string())))?;

    // Everything else in policy.d comes along untouched.
    let live = state_dir.join(POLICY_DIR);
    let entries = match fs::read_dir(&live) {
        Ok(entries) => entries.collect::<Result<Vec<_>, _>>()?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    let mut carried = false;
    for entry in entries {
        let name = entry.file_name();
        let text = name.to_str();
        if text.is_some_and(|text| owned_now.iter().any(|owned| owned == text)) {
            continue;
        }
        if let Some(text) = text.filter(|text| set.files.contains_key(*text)) {
            return Err(PrepareError::Rejected(Rejection::ForeignFileCollision(
                text.to_string(),
            )));
        }
        let meta = fs::symlink_metadata(entry.path())?;
        let target = staging.join(&name);
        if meta.is_file() || meta.file_type().is_symlink() {
            // Same inode, mode and owner; a symlink is linked, not followed.
            fs::hard_link(entry.path(), &target)?;
        } else if meta.is_dir() && fs::read_dir(entry.path())?.next().is_none() {
            let mode = meta.permissions().mode() & 0o7777;
            fs::DirBuilder::new().mode(mode).create(&target)?;
            fs::set_permissions(&target, fs::Permissions::from_mode(mode))?;
        } else {
            return Err(PrepareError::Local(LocalFailure::UnsupportedEntry(
                name.to_string_lossy().into_owned(),
            )));
        }
        carried = true;
    }
    sync_dir(&staging);

    let loaded = if carried {
        let combined = load_policy_dir(&staging).map_err(|e| {
            PrepareError::Local(LocalFailure::ConflictsWithLocalPolicy(e.to_string()))
        })?;
        render_checked(&combined).map_err(|e| {
            PrepareError::Local(LocalFailure::ConflictsWithLocalPolicy(e.to_string()))
        })?;
        combined
    } else {
        organization_only
    };
    Ok(Prepared { loaded, staging })
}

/// Render the managed browser document the way the backend will write it,
/// and hold it to the allowlist the backend enforces.
fn render_checked(loaded: &LoadedPolicies) -> io::Result<()> {
    if let Some(value) = render_effective_browser_policy(&loaded.applications, &loaded.browsers)? {
        validate_rendered_policy(&value)?;
    }
    Ok(())
}

/// Remove the staging directory, whatever state it is in.
pub fn discard_staging(state_dir: &Path) {
    if let Err(e) = remove_dir_if_present(&state_dir.join(STAGING_DIR)) {
        eprintln!("punard: could not remove {STAGING_DIR}: {e}");
    }
}

/// A staged set now live. Until [`Swapped::finish`], the staging path holds
/// the directory it replaced, and [`Swapped::roll_back`] puts it back.
#[derive(Debug)]
#[must_use = "a swapped policy.d is finished or rolled back"]
pub struct Swapped {
    staging: PathBuf,
    live: PathBuf,
    /// Whether a previous `policy.d` was exchanged (else there was none).
    exchanged: bool,
}

/// Make `staging` the live `policy.d` in one step: an atomic exchange with
/// the current directory, or, when there is none, a rename that refuses to
/// replace one that appeared meanwhile.
pub fn swap_in(staging: &Path, live: &Path) -> Result<Swapped, LocalFailure> {
    use rustix::fs::RenameFlags;
    let exchanged = match fs::symlink_metadata(live) {
        Ok(_) => true,
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(e) => return Err(LocalFailure::Io(e)),
    };
    let flags = if exchanged {
        RenameFlags::EXCHANGE
    } else {
        RenameFlags::NOREPLACE
    };
    rustix::fs::renameat_with(rustix::fs::CWD, staging, rustix::fs::CWD, live, flags)
        .map_err(swap_error)?;
    sync_parent(live);
    Ok(Swapped {
        staging: staging.to_path_buf(),
        live: live.to_path_buf(),
        exchanged,
    })
}

fn swap_error(errno: rustix::io::Errno) -> LocalFailure {
    use rustix::io::Errno;
    match errno {
        Errno::INVAL | Errno::NOSYS | Errno::XDEV => LocalFailure::SwapUnsupported,
        other => LocalFailure::Io(other.into()),
    }
}

impl Swapped {
    /// Put the previous directory back and discard the new one.
    pub fn roll_back(self) -> io::Result<()> {
        use rustix::fs::RenameFlags;
        let (from, to, flags) = if self.exchanged {
            (&self.staging, &self.live, RenameFlags::EXCHANGE)
        } else {
            (&self.live, &self.staging, RenameFlags::NOREPLACE)
        };
        rustix::fs::renameat_with(rustix::fs::CWD, from, rustix::fs::CWD, to, flags)?;
        sync_parent(&self.live);
        remove_dir_if_present(&self.staging)
    }

    /// Keep the new directory; remove the one it replaced.
    pub fn finish(self) -> io::Result<()> {
        remove_dir_if_present(&self.staging)
    }
}

/// At startup, before anything reads the enrollment: remove what an
/// interrupted `enroll.start` or refresh left beside `policy.d`, and make the
/// record own exactly the files `policy.d` holds of it. A refresh records the
/// old and new names together before it swaps (so a crash never leaves a file
/// no record owns); whichever directory the crash left live, its files are
/// the ones kept. Returns whether the record changed, for the caller to save.
/// Running it twice changes nothing the second time.
pub fn settle(state_dir: &Path, enrollment: Option<&mut Enrollment>) -> io::Result<bool> {
    for leftover in [STAGING_DIR, LEGACY_STAGING_DIR] {
        remove_dir_if_present(&state_dir.join(leftover))?;
    }
    let Some(enrollment) = enrollment else {
        return Ok(false);
    };
    let live = state_dir.join(POLICY_DIR);
    let mut fields = enrollment.policy_fields();
    let before = fields.files.len();
    fields.files.retain(|name| {
        owned_name_ok(name) && fs::symlink_metadata(live.join(name)).is_ok_and(|m| m.is_file())
    });
    if fields.files.len() == before {
        return Ok(false);
    }
    // The revision described a set that is no longer what policy.d holds;
    // the next refresh derives it again from the files.
    fields.hash = None;
    apply_policy_fields(enrollment, fields);
    Ok(true)
}

fn remove_dir_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_dir_all(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// `fsync` a directory, best effort, as `write_atomic_synced` does: a
/// filesystem that will not open one read-only must not fail a completed
/// change.
fn sync_dir(dir: &Path) {
    if let Ok(dir) = File::open(dir) {
        let _ = dir.sync_all();
    }
}

fn sync_parent(path: &Path) {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        sync_dir(parent);
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use serde_json::json;

    use super::*;

    const ACME_ENVELOPE: &str =
        include_str!("../../../fixtures/organizations/acme/policy-source-eng-baseline-v12.json");
    const ACME_DESIRED: &str =
        include_str!("../../../fixtures/organizations/acme/desired-state-eng-baseline-v12.json");

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "punard-policy-set-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn acme() -> Value {
        let mut envelope: Value = serde_json::from_str(ACME_ENVELOPE).unwrap();
        envelope["policy"] = serde_json::from_str(ACME_DESIRED).unwrap();
        envelope
    }

    fn envelope(id: &str, kind: &str, rank: u64) -> Value {
        json!({"policy_id": id, "source_kind": kind, "precedence_rank": rank})
    }

    fn set(envelopes: &[Value]) -> CanonicalSet {
        CanonicalSet::from_envelopes(envelopes, Assignment::Policies).unwrap()
    }

    fn rejection(envelopes: &[Value], assignment: Assignment) -> &'static str {
        CanonicalSet::from_envelopes(envelopes, assignment)
            .unwrap_err()
            .reason()
    }

    #[test]
    fn canonical_bytes_sort_keys_and_the_revision_ignores_list_order() {
        let spelled = serde_json::from_str::<Value>(
            r#"{"source_kind":"organization_role_policy","precedence_rank":3,"policy_id":"b"}"#,
        )
        .unwrap();
        let one = set(&[acme(), spelled.clone()]);
        let text = String::from_utf8(one.files()["b.json"].clone()).unwrap();
        let positions: Vec<usize> = ["policy_id", "precedence_rank", "source_kind"]
            .iter()
            .map(|key| text.find(key).unwrap())
            .collect();
        assert!(positions.windows(2).all(|w| w[0] < w[1]), "{text}");
        // What enroll.start wrote before this module existed, so a device
        // enrolled by an older build reads its files as unchanged.
        assert_eq!(
            one.files()["eng-baseline-v12.json"],
            serde_json::to_vec_pretty(&acme()).unwrap()
        );

        let other = set(&[spelled, acme()]);
        assert_eq!(one, other);
        assert_eq!(one.revision(), other.revision());
        assert!(one.revision().starts_with("sha256:"), "{}", one.revision());
        assert_ne!(one.revision(), set(&[acme()]).revision());
        assert_ne!(set(&[]).revision(), set(&[acme()]).revision());
        assert_eq!(one.ids(), ["b", "eng-baseline-v12"]);
    }

    #[test]
    fn every_rule_refuses_the_whole_set_with_its_own_reason() {
        let ok = envelope("p", "organization_baseline", 2);
        let many: Vec<Value> = (0..=MAX_POLICIES)
            .map(|i| envelope(&format!("p{i}"), "organization_baseline", 2))
            .collect();
        assert_eq!(rejection(&many, Assignment::Policies), "too_many_policies");
        assert!(CanonicalSet::from_envelopes(&many[..MAX_POLICIES], Assignment::Policies).is_ok());
        assert_eq!(
            rejection(&[ok.clone(), json!(["p"])], Assignment::Policies),
            "envelope_not_an_object"
        );
        for id in [
            json!(""),
            json!(".hidden"),
            json!(".."),
            json!("a/b"),
            json!("a b"),
            json!("x".repeat(MAX_POLICY_ID_CHARS + 1)),
            json!(7),
            Value::Null,
        ] {
            let mut bad = ok.clone();
            bad["policy_id"] = id.clone();
            assert_eq!(
                rejection(&[bad], Assignment::Policies),
                "unusable_policy_id",
                "{id}"
            );
        }
        let mut longest = ok.clone();
        longest["policy_id"] = json!("x".repeat(MAX_POLICY_ID_CHARS));
        assert!(CanonicalSet::from_envelopes(&[longest], Assignment::Policies).is_ok());
        assert_eq!(
            rejection(&[ok.clone(), ok.clone()], Assignment::Policies),
            "duplicate_policy_id"
        );
        let mut large = ok.clone();
        large["source_name"] = json!("x".repeat(MAX_ENVELOPE_BYTES));
        assert_eq!(
            rejection(&[large], Assignment::Policies),
            "envelope_too_large"
        );
        for kind in [
            json!("os_hard_safety_constraint"),
            json!("local_user_preference"),
            json!("os_secure_default"),
            json!("something_else"),
            Value::Null,
        ] {
            let mut bad = ok.clone();
            bad["source_kind"] = kind.clone();
            assert_eq!(
                rejection(&[bad], Assignment::Policies),
                "source_kind_not_organizational",
                "{kind}"
            );
        }
        for rank in [0, 1] {
            assert_eq!(
                rejection(
                    &[envelope("o", "device_specific_override", rank)],
                    Assignment::Policies
                ),
                "rank_not_organizational"
            );
        }
        for kind in ORGANIZATIONAL_SOURCE_KINDS {
            let rank = if kind == "device_specific_override" {
                2
            } else {
                9
            };
            assert!(
                CanonicalSet::from_envelopes(&[envelope("k", kind, rank)], Assignment::Unstated)
                    .is_ok(),
                "{kind}"
            );
        }
        for assignment in [Assignment::NoneAssigned, Assignment::Unusable] {
            assert_eq!(
                rejection(std::slice::from_ref(&ok), assignment),
                "inconsistent_assignment"
            );
            assert!(CanonicalSet::from_envelopes(&[], assignment).is_ok());
        }
    }

    fn write(path: &Path, bytes: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn prepare_loads_the_set_and_refuses_what_startup_would() {
        let dir = tmp("prepare-load");
        let prepared = prepare(&dir, &set(&[acme()]), &[]).unwrap();
        assert_eq!(prepared.staging(), dir.join(STAGING_DIR));
        assert_eq!(
            fs::metadata(prepared.staging()).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(prepared.staging().join("eng-baseline-v12.json"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        assert!(!prepared.loaded.layers.is_empty());
        assert!(!dir.join(POLICY_DIR).exists(), "the live dir is only read");

        let mut contradicted = acme();
        contradicted["precedence_rank"] = json!(5);
        match prepare(&dir, &set(&[contradicted]), &[]) {
            Err(PrepareError::Rejected(Rejection::InvalidEnvelope(why))) => {
                assert!(why.contains("fixed precedence rank"), "{why}");
            }
            other => panic!("expected an invalid envelope, got {other:?}"),
        }
        // A security-weakening browser value is the organization's to fix,
        // whichever of the loader and the renderer catches it first.
        let mut weakening = acme();
        weakening["policy"]["spec"]["browser"]["RemoteDebuggingAllowed"] = json!(true);
        match prepare(&dir, &set(&[weakening]), &[]) {
            Err(PrepareError::Rejected(rejection)) => {
                assert!(
                    rejection
                        .detail()
                        .is_some_and(|why| why.contains("security-weakening")),
                    "{rejection:?}"
                );
            }
            other => panic!("expected a rejection, got {other:?}"),
        }
        discard_staging(&dir);
        assert!(!dir.join(STAGING_DIR).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A root administrator's files come along as the same inodes, an empty
    /// legacy directory as an empty directory; anything else refuses, and a
    /// set that names one of them is the organization's collision.
    #[test]
    fn prepare_carries_foreign_files_and_refuses_what_it_cannot() {
        let dir = tmp("prepare-foreign");
        let live = dir.join(POLICY_DIR);
        write(&live.join("eng-baseline-v12.json"), b"the old org file");
        write(&live.join("local.yaml"), b"policy: local\n");
        write(
            &live.join("local.json"),
            envelope("local", "organization_baseline", 2)
                .to_string()
                .as_bytes(),
        );
        std::os::unix::fs::symlink("local.yaml", live.join("linked.yaml")).unwrap();
        fs::DirBuilder::new()
            .mode(0o750)
            .create(live.join("ai"))
            .unwrap();
        fs::set_permissions(live.join("ai"), fs::Permissions::from_mode(0o750)).unwrap();

        let owned = vec!["eng-baseline-v12.json".to_string()];
        let prepared = prepare(&dir, &set(&[acme()]), &owned).unwrap();
        let staging = prepared.staging().to_path_buf();
        for name in ["local.yaml", "local.json"] {
            assert_eq!(
                fs::metadata(staging.join(name)).unwrap().ino(),
                fs::metadata(live.join(name)).unwrap().ino(),
                "{name} is the same inode"
            );
        }
        assert!(
            fs::symlink_metadata(staging.join("linked.yaml"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::metadata(staging.join("ai")).unwrap().mode() & 0o7777,
            0o750
        );
        assert_ne!(
            fs::read(staging.join("eng-baseline-v12.json")).unwrap(),
            b"the old org file",
            "the owned file is replaced"
        );
        // The combined load is what the next boot reads: both layers.
        let ids: Vec<&str> = prepared
            .loaded
            .layers
            .iter()
            .map(|(_, layer)| layer.provenance.policy_id.as_str())
            .collect();
        assert!(ids.contains(&"eng-baseline-v12"), "{ids:?}");

        // A set that names a root drop is refused as a collision.
        match prepare(
            &dir,
            &set(&[acme(), envelope("local", "organization_baseline", 2)]),
            &owned,
        ) {
            Err(PrepareError::Rejected(Rejection::ForeignFileCollision(name))) => {
                assert_eq!(name, "local.json");
            }
            other => panic!("expected a collision, got {other:?}"),
        }
        // Not owned any more: the old org file is now a root drop too.
        match prepare(&dir, &set(&[acme()]), &[]) {
            Err(PrepareError::Rejected(Rejection::ForeignFileCollision(name))) => {
                assert_eq!(name, "eng-baseline-v12.json");
            }
            other => panic!("expected a collision, got {other:?}"),
        }
        // A root drop that does not load beside the set is the device's.
        write(
            &live.join("clash.json"),
            envelope("eng-baseline-v12", "organization_baseline", 2)
                .to_string()
                .as_bytes(),
        );
        match prepare(&dir, &set(&[acme()]), &owned) {
            Err(PrepareError::Local(LocalFailure::ConflictsWithLocalPolicy(why))) => {
                assert!(why.contains("duplicate policy_id"), "{why}");
            }
            other => panic!("expected a local conflict, got {other:?}"),
        }
        fs::remove_file(live.join("clash.json")).unwrap();
        // A directory with something in it cannot be carried unchanged.
        write(&live.join("ai/stale.yaml"), b"x");
        match prepare(&dir, &set(&[acme()]), &owned) {
            Err(PrepareError::Local(LocalFailure::UnsupportedEntry(name))) => {
                assert_eq!(name, "ai");
            }
            other => panic!("expected an unsupported entry, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn swap_in_exchanges_whole_directories_and_rolls_back() {
        let dir = tmp("swap");
        let live = dir.join(POLICY_DIR);
        let staging = dir.join(STAGING_DIR);

        // No policy.d yet: the staged directory is renamed into place.
        write(&staging.join("new.json"), b"new");
        let swapped = swap_in(&staging, &live).unwrap();
        assert_eq!(fs::read(live.join("new.json")).unwrap(), b"new");
        assert!(!staging.exists());
        swapped.roll_back().unwrap();
        assert!(!live.exists(), "rolled back to no directory");
        assert!(!staging.exists());

        write(&staging.join("new.json"), b"new");
        swap_in(&staging, &live).unwrap().finish().unwrap();
        assert_eq!(fs::read(live.join("new.json")).unwrap(), b"new");

        // An existing policy.d is exchanged: the old one waits at the
        // staging path until finish or roll_back.
        write(&staging.join("newer.json"), b"newer");
        let swapped = swap_in(&staging, &live).unwrap();
        assert_eq!(fs::read(live.join("newer.json")).unwrap(), b"newer");
        assert!(!live.join("new.json").exists(), "never a mix of the two");
        assert_eq!(fs::read(staging.join("new.json")).unwrap(), b"new");
        swapped.roll_back().unwrap();
        assert_eq!(fs::read(live.join("new.json")).unwrap(), b"new");
        assert!(!live.join("newer.json").exists());
        assert!(!staging.exists());

        write(&staging.join("newer.json"), b"newer");
        swap_in(&staging, &live).unwrap().finish().unwrap();
        assert_eq!(fs::read(live.join("newer.json")).unwrap(), b"newer");
        assert!(!live.join("new.json").exists());
        assert!(!staging.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    fn enrollment(files: &[&str]) -> Enrollment {
        serde_json::from_value(json!({
            "version": 1,
            "org": {"id": "acme", "name": "Acme", "display_name": "Acme", "domain": "acme.com"},
            "enrolled_at": "2026-09-24T00:00:00Z",
            "attestation": "simulated",
            "policy_files": files,
            "last_sync": {"at": null, "result": null},
            "last_inventory_hash": null,
            "policy_hash": "sha256:old",
        }))
        .unwrap()
    }

    #[test]
    fn settle_removes_leftovers_and_owns_exactly_what_policy_d_holds() {
        let dir = tmp("settle");
        let live = dir.join(POLICY_DIR);
        write(&dir.join(STAGING_DIR).join("old.json"), b"old");
        write(&dir.join(LEGACY_STAGING_DIR).join("x.json"), b"x");
        write(&live.join("new.json"), b"new");
        write(&live.join("kept.json"), b"kept");

        // A crash after the union was recorded and the new set swapped in.
        let mut record = enrollment(&["kept.json", "new.json", "old.json"]);
        assert!(settle(&dir, Some(&mut record)).unwrap());
        assert_eq!(record.policy_files, ["kept.json", "new.json"]);
        assert_eq!(record.policy_hash, None, "derived again from the files");
        assert!(!dir.join(STAGING_DIR).exists());
        assert!(!dir.join(LEGACY_STAGING_DIR).exists());
        assert_eq!(record.removable, enrollment(&[]).removable, "no term moves");

        let settled = record.clone();
        assert!(!settle(&dir, Some(&mut record)).unwrap(), "idempotent");
        assert_eq!(record, settled);
        let mut untouched = enrollment(&["kept.json", "new.json"]);
        assert!(!settle(&dir, Some(&mut untouched)).unwrap());
        assert_eq!(untouched.policy_hash.as_deref(), Some("sha256:old"));
        assert!(!settle(&dir, None).unwrap());
        let _ = fs::remove_dir_all(&dir);
    }
}
