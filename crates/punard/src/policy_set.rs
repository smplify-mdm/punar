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
//! A change is recorded before it is made and verified after: the
//! enrollment's record owns the files of both sets, with the change marked
//! pending, before the swap; the directory the swap replaced is kept until
//! the record says what is enforced; and whether a rollback put it back is
//! read from `policy.d` itself, never inferred from what the exchange
//! returned. So a record never owns less than `policy.d` holds of the
//! organization, the last good set is never deleted while it may still be
//! the one to go back to, and a start after a crash ([`settle`]) decides
//! from the directory alone which set is live.
//!
//! What stays with the device, whatever the organization serves:
//!
//! - files a root administrator dropped into `policy.d` (an AI authority
//!   `.yaml`, a local envelope): carried into the new directory as hard links
//!   to the same inode, never overwritten, never taken over. A set that names
//!   one of them is refused, and one added, replaced or removed while a set
//!   was being installed stops the change (it is checked again on both sides
//!   of the swap) rather than being lost with the directory it was put in.
//! - the ladder's non-organizational rungs. The organization may publish only
//!   organization kinds, so a control plane cannot label its layer a hard OS
//!   safety constraint, a person's own preference or the OS default.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use punar_common::ipc::{MAX_ORGANIZATION_TEXT_CHARS, organization_text};
use serde_json::Value;

use crate::browser_policy::{render_effective_browser_policy, validate_rendered_policy};
use crate::enroll::{
    Assignment, Enrollment, PendingPolicyChange, PolicyRefreshRecord, apply_policy_fields,
};
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

/// One canonical envelope is at most this many bytes.
pub const MAX_ENVELOPE_BYTES: usize = 256 * 1024;

/// A whole set, its canonical envelopes together, is at most this many
/// bytes. Sixty-four envelopes of [`MAX_ENVELOPE_BYTES`] would be 16 MiB,
/// four times the client's answer bound (`crate::enroll::MAX_ANSWER_BYTES`),
/// so a set the rules allowed could still never arrive, and would read as an
/// unreachable control plane. The answer bound is four times this one: a set
/// within the rules fits in an answer however its control plane spaces and
/// escapes the JSON, short of writing most of its characters as `\u`
/// escapes, since canonical form (pretty, sorted keys) is never shorter than
/// the same JSON written compactly.
pub const MAX_SET_BYTES: usize = 1024 * 1024;

/// An envelope nests objects and arrays at most this deep. The loader's own
/// documents go about ten deep; the bound keeps a payload made of nesting
/// alone (a few bytes per level, and one indented line per level in
/// canonical form) from costing more than it is worth to check.
pub const MAX_ENVELOPE_DEPTH: usize = 32;

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
    EnvelopeTooDeep,
    SetTooLarge,
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
            Rejection::EnvelopeTooDeep => "envelope_too_deep",
            Rejection::SetTooLarge => "set_too_large",
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
            Rejection::EnvelopeTooDeep => {
                format!("an envelope nested more than {MAX_ENVELOPE_DEPTH} deep")
            }
            Rejection::SetTooLarge => {
                format!("policies larger than {} KiB together", MAX_SET_BYTES / 1024)
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

    /// The loader's or renderer's own words, cleaned and bounded where
    /// [`prepare`] read them, or the colliding file, when there are any. For
    /// the journal and `enroll.start`'s refusal only: the audit trail has no
    /// free-text field.
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
    /// A root administrator added, replaced or removed this entry of
    /// `policy.d` after the set was prepared. Installing it anyway would
    /// lose the change with the directory it was made in, so the next pass
    /// prepares again from what is there then.
    LocalFilesChanged(String),
}

impl LocalFailure {
    /// The closed reason code `enroll.status` and the journal carry.
    pub fn reason(&self) -> &'static str {
        match self {
            LocalFailure::Io(_) => "io",
            LocalFailure::UnsupportedEntry(_) => "unsupported_entry",
            LocalFailure::ConflictsWithLocalPolicy(_) => "conflicts_with_local_policy",
            LocalFailure::SwapUnsupported => "swap_unsupported",
            LocalFailure::LocalFilesChanged(_) => "local_files_changed",
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
            LocalFailure::LocalFilesChanged(name) => write!(
                f,
                "policy.d/{name:?} changed while the new set was being installed; it is \
                 prepared again from what policy.d holds then"
            ),
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
        let mut total = 0usize;
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
            // The size is measured before anything is built from it:
            // canonical form indents every nested line, so an envelope of a
            // few megabytes of nested zeros would otherwise grow to hundreds
            // of megabytes in a root daemon before it could be refused. The
            // compact form is counted without being kept, then the canonical
            // bytes are written into a buffer that refuses to grow past the
            // bound.
            if nested_deeper_than(envelope, MAX_ENVELOPE_DEPTH) {
                return Err(Rejection::EnvelopeTooDeep);
            }
            let mut compact = Bounded::counting(MAX_ENVELOPE_BYTES);
            if serde_json::to_writer(&mut compact, envelope).is_err() {
                return Err(Rejection::EnvelopeTooLarge);
            }
            // serde_json's map is ordered by key unless its `preserve_order`
            // feature is on, which no workspace manifest enables; a unit test
            // pins it, because a dependency switching it on would make every
            // fetch look like a change.
            let mut canonical = Bounded::keeping(MAX_ENVELOPE_BYTES);
            if serde_json::to_writer_pretty(&mut canonical, envelope).is_err() {
                return Err(Rejection::EnvelopeTooLarge);
            }
            let bytes = canonical.bytes;
            total += bytes.len();
            if total > MAX_SET_BYTES {
                return Err(Rejection::SetTooLarge);
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

/// Whether `value` nests objects and arrays more than `limit` deep (the
/// envelope itself is the first level). serde_json already stopped parsing at
/// 128 levels, so the recursion is bounded.
fn nested_deeper_than(value: &Value, limit: usize) -> bool {
    let deeper = |child: &Value| nested_deeper_than(child, limit - 1);
    match value {
        Value::Array(items) => limit == 0 || items.iter().any(deeper),
        Value::Object(map) => limit == 0 || map.values().any(deeper),
        _ => false,
    }
}

/// A writer that fails, rather than grow, once more than `limit` bytes have
/// been written to it; it keeps them, or only counts them.
struct Bounded {
    bytes: Vec<u8>,
    written: usize,
    limit: usize,
    keep: bool,
}

impl Bounded {
    fn counting(limit: usize) -> Bounded {
        Bounded {
            bytes: Vec::new(),
            written: 0,
            limit,
            keep: false,
        }
    }

    fn keeping(limit: usize) -> Bounded {
        Bounded {
            keep: true,
            ..Bounded::counting(limit)
        }
    }
}

impl io::Write for Bounded {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written = self.written.saturating_add(buf.len());
        if self.written > self.limit {
            return Err(io::Error::other("past the bound"));
        }
        if self.keep {
            self.bytes.extend_from_slice(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
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
/// with what a root administrator dropped there. After [`prepare`] only I/O,
/// or a root administrator changing `policy.d` meanwhile, can fail.
#[derive(Debug)]
pub struct Prepared {
    /// Exactly what the next boot would load from the new `policy.d`.
    pub loaded: LoadedPolicies,
    staging: PathBuf,
    /// Every entry of `policy.d` the set does not own, as it was carried.
    carried: BTreeMap<OsString, Carried>,
}

/// One entry of `policy.d` carried into the staged directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Carried {
    /// A file or a symlink, hard-linked: the same inode on both sides.
    Linked { dev: u64, ino: u64 },
    /// An empty directory, made again empty.
    EmptyDir,
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
/// read. What only the live directory decides — a set that names a root
/// drop, an entry that cannot be carried — is found by one read of it,
/// before anything is written. The caller removes the staging directory on
/// an error ([`discard_staging`]).
pub fn prepare(
    state_dir: &Path,
    set: &CanonicalSet,
    owned_now: &[String],
) -> Result<Prepared, PrepareError> {
    let live = state_dir.join(POLICY_DIR);
    let mut foreign = Vec::new();
    for (name, meta) in read_entries(&live)? {
        let text = name.to_str();
        if text.is_some_and(|text| owned_now.iter().any(|owned| owned == text)) {
            continue;
        }
        if let Some(text) = text.filter(|text| set.files.contains_key(*text)) {
            return Err(PrepareError::Rejected(Rejection::ForeignFileCollision(
                text.to_string(),
            )));
        }
        let carried = if meta.is_file() || meta.file_type().is_symlink() {
            Carried::Linked {
                dev: meta.dev(),
                ino: meta.ino(),
            }
        } else if meta.is_dir() && dir_is_empty(&live.join(&name))? {
            Carried::EmptyDir
        } else {
            return Err(PrepareError::Local(LocalFailure::UnsupportedEntry(
                name.to_string_lossy().into_owned(),
            )));
        };
        foreign.push((name, meta, carried));
    }

    step(Step::Stage)?;
    let staging = state_dir.join(STAGING_DIR);
    remove_dir_if_present(&staging)?;
    fs::DirBuilder::new().mode(0o700).create(&staging)?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))?;
    for (name, bytes) in &set.files {
        write_atomic_synced(&staging.join(name), bytes, 0o600)?;
    }

    // The organization's files alone: whatever fails here is the set's own.
    let organization_only = load_policy_dir(&staging)
        .map_err(|e| PrepareError::Rejected(Rejection::InvalidEnvelope(cleaned(&e))))?;
    render_checked(&organization_only)
        .map_err(|e| PrepareError::Rejected(Rejection::BrowserPolicyRefused(cleaned(&e))))?;

    // Everything else in policy.d comes along untouched. What is recorded is
    // what the staged directory holds, read after linking: a file replaced
    // since the listing above is then told apart from the one carried.
    let mut carried = BTreeMap::new();
    for (name, meta, kind) in foreign {
        let target = staging.join(&name);
        let kind = match kind {
            Carried::Linked { .. } => {
                // Same inode, mode and owner; a symlink is linked, not
                // followed.
                fs::hard_link(live.join(&name), &target)?;
                let linked = fs::symlink_metadata(&target)?;
                Carried::Linked {
                    dev: linked.dev(),
                    ino: linked.ino(),
                }
            }
            Carried::EmptyDir => {
                let mode = meta.permissions().mode() & 0o7777;
                fs::DirBuilder::new().mode(mode).create(&target)?;
                fs::set_permissions(&target, fs::Permissions::from_mode(mode))?;
                Carried::EmptyDir
            }
        };
        carried.insert(name, kind);
    }
    sync_dir(&staging);

    let loaded = if carried.is_empty() {
        organization_only
    } else {
        let combined = load_policy_dir(&staging).map_err(|e| {
            PrepareError::Local(LocalFailure::ConflictsWithLocalPolicy(cleaned(&e)))
        })?;
        render_checked(&combined).map_err(|e| {
            PrepareError::Local(LocalFailure::ConflictsWithLocalPolicy(cleaned(&e)))
        })?;
        combined
    };
    Ok(Prepared {
        loaded,
        staging,
        carried,
    })
}

/// Every entry of `dir` by name, as `lstat` sees it; none when it is absent.
fn read_entries(dir: &Path) -> io::Result<Vec<(OsString, fs::Metadata)>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut named = Vec::new();
    for entry in entries {
        let entry = entry?;
        named.push((entry.file_name(), fs::symlink_metadata(entry.path())?));
    }
    named.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(named)
}

/// A digest of what `policy.d` holds, as far as a local refusal depends on
/// it: which files the record owns, and every entry's name, inode, mode,
/// size and modification time. Any file a root administrator adds, removes,
/// replaces or edits changes it; a refusal that depends only on these and on
/// the set offered is not worth staging again until one of them changes.
/// Not the inode change time: carrying a file into the staged directory is a
/// new link to it, which moves that time on every attempt.
pub fn local_fingerprint(state_dir: &Path, owned: &[String]) -> io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    for name in owned {
        digest.update(name.as_bytes());
        digest.update([0]);
    }
    digest.update([1]);
    for (name, meta) in read_entries(&state_dir.join(POLICY_DIR))? {
        digest.update(name.as_encoded_bytes());
        digest.update([0]);
        for number in [
            meta.dev(),
            meta.ino(),
            u64::from(meta.mode()),
            meta.len(),
            meta.mtime() as u64,
            meta.mtime_nsec() as u64,
        ] {
            digest.update(number.to_be_bytes());
        }
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn dir_is_empty(dir: &Path) -> io::Result<bool> {
    Ok(fs::read_dir(dir)?.next().is_none())
}

/// Whether `dir` holds, beside the organization files `owned` names, exactly
/// the entries [`prepare`] carried: the same files and symlinks (same inode),
/// the same directories, still empty. `Err` names the first that differs. A
/// file edited in place is the carried inode and needs nothing.
fn holds_what_was_carried(
    dir: &Path,
    owned: &[String],
    carried: &BTreeMap<OsString, Carried>,
) -> Result<(), LocalFailure> {
    let changed = |name: &OsString| LocalFailure::LocalFilesChanged(name.to_string_lossy().into());
    let mut found = BTreeMap::new();
    for (name, meta) in read_entries(dir).map_err(LocalFailure::Io)? {
        if name
            .to_str()
            .is_some_and(|text| owned.iter().any(|owned| owned == text))
        {
            continue;
        }
        let kind = if meta.is_dir() {
            if !dir_is_empty(&dir.join(&name)).map_err(LocalFailure::Io)? {
                return Err(changed(&name));
            }
            Carried::EmptyDir
        } else {
            Carried::Linked {
                dev: meta.dev(),
                ino: meta.ino(),
            }
        };
        found.insert(name, kind);
    }
    let differs = found
        .iter()
        .find(|(name, kind)| carried.get(*name) != Some(*kind))
        .or_else(|| carried.iter().find(|(name, _)| !found.contains_key(*name)));
    match differs {
        Some((name, _)) => Err(changed(name)),
        None => Ok(()),
    }
}

impl Prepared {
    /// Before the swap: `policy.d` still holds exactly what was carried out
    /// of it, beside the organization files `owned` names.
    pub fn still_current(&self, live: &Path, owned: &[String]) -> Result<(), LocalFailure> {
        holds_what_was_carried(live, owned, &self.carried)
    }
}

/// The loader's or the renderer's words about a set. They quote the
/// envelopes' own keys and values ("unknown field `…`"), which the
/// organization chose, and go on into `enroll.start`'s refusal and the
/// journal: cleaned and bounded here, where punard first holds them, by the
/// rules the organization's name gets.
fn cleaned(error: &io::Error) -> String {
    organization_text(&error.to_string(), MAX_ORGANIZATION_TEXT_CHARS)
        .unwrap_or_else(|| "no detail".to_string())
}

/// Render the managed browser document the way the backend will write it,
/// and hold it to the allowlist the backend enforces.
fn render_checked(loaded: &LoadedPolicies) -> io::Result<()> {
    if let Some(value) = render_effective_browser_policy(&loaded.applications, &loaded.browsers)? {
        validate_rendered_policy(&value)?;
    }
    Ok(())
}

/// Remove a staged set that was never swapped in, whatever state it is in.
/// Once [`swap_in`] succeeded, the staging path may hold the previous
/// `policy.d`, and only [`Swapped`] removes it.
pub fn discard_staging(state_dir: &Path) {
    if let Err(e) = remove_dir_if_present(&state_dir.join(STAGING_DIR)) {
        eprintln!("punard: could not remove {STAGING_DIR}: {e}");
    }
}

/// A staged set now live. Until [`Swapped::finish`] or
/// [`Swapped::roll_back`], the staging path holds the directory it replaced,
/// and only these two remove anything: [`discard_staging`] is for a set that
/// was never swapped in.
#[derive(Debug)]
#[must_use = "a swapped policy.d is finished or rolled back"]
pub struct Swapped {
    staging: PathBuf,
    live: PathBuf,
    /// Whether a previous `policy.d` was exchanged (else there was none).
    exchanged: bool,
    /// The new directory's device and inode: how `policy.d` is told to hold
    /// it or not, whatever an exchange returned.
    new_dir: (u64, u64),
}

/// A rollback that could not be verified: `policy.d` may still hold the new
/// set, and nothing was removed.
#[derive(Debug)]
pub struct RollBackFailed(pub io::Error);

impl std::fmt::Display for RollBackFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Make `staging` the live `policy.d` in one step: an atomic exchange with
/// the current directory, or, when there is none, a rename that refuses to
/// replace one that appeared meanwhile.
pub fn swap_in(staging: &Path, live: &Path) -> Result<Swapped, LocalFailure> {
    use rustix::fs::RenameFlags;
    let new_dir = fs::symlink_metadata(staging)
        .map(|meta| (meta.dev(), meta.ino()))
        .map_err(LocalFailure::Io)?;
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
        new_dir,
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
    /// After the swap: the directory it replaced holds, beside the
    /// organization files `owned` names, exactly what `prepared` carried out
    /// of it. Anything else a root administrator put there before the
    /// exchange would be lost with it.
    pub fn replaced_only_what_was_carried(
        &self,
        prepared: &Prepared,
        owned: &[String],
    ) -> Result<(), LocalFailure> {
        if !self.exchanged {
            return Ok(());
        }
        holds_what_was_carried(&self.staging, owned, &prepared.carried)
    }

    /// Put the previous directory back and remove the new one. Which one is
    /// live afterwards is read from `policy.d` itself, not inferred from what
    /// the exchange returned, and only a verified return removes anything:
    /// on `Err` the new set may still be live, both directories are where
    /// they were, and the caller must keep owning both sets' files.
    pub fn roll_back(self) -> Result<(), RollBackFailed> {
        use rustix::fs::RenameFlags;
        let (from, to, flags) = if self.exchanged {
            (&self.staging, &self.live, RenameFlags::EXCHANGE)
        } else {
            (&self.live, &self.staging, RenameFlags::NOREPLACE)
        };
        let renamed = step(Step::RollBack).and_then(|()| {
            rustix::fs::renameat_with(rustix::fs::CWD, from, rustix::fs::CWD, to, flags)
                .map_err(io::Error::from)
        });
        match self.live_is_new() {
            Ok(false) => {
                sync_parent(&self.live);
                if let Err(e) = remove_dir_if_present(&self.staging) {
                    eprintln!(
                        "punard: could not remove the set that was rolled back ({e}); \
                         removed at start"
                    );
                }
                Ok(())
            }
            Ok(true) => Err(RollBackFailed(renamed.err().unwrap_or_else(|| {
                io::Error::other("the exchange back left the new set in policy.d")
            }))),
            Err(e) => Err(RollBackFailed(e)),
        }
    }

    /// Whether `policy.d` is the new directory.
    fn live_is_new(&self) -> io::Result<bool> {
        match fs::symlink_metadata(&self.live) {
            Ok(meta) => Ok((meta.dev(), meta.ino()) == self.new_dir),
            Err(e) if e.kind() == io::ErrorKind::NotFound && !self.exchanged => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Keep the new directory; remove the one it replaced. For after the
    /// record says what is enforced.
    pub fn finish(self) -> io::Result<()> {
        step(Step::Finish)?;
        remove_dir_if_present(&self.staging)
    }
}

/// What [`settle`] found.
#[derive(Debug, Default)]
pub struct Settled {
    /// The record changed, for the caller to save.
    pub changed: bool,
    /// A change the record said was under way, which `policy.d` shows
    /// landed. The caller audits it by its event id, unless the audit log
    /// already holds that event: once, whether the change finished before
    /// the crash or not.
    pub landed: Option<PendingPolicyChange>,
}

/// At startup, before anything reads the enrollment: remove what an
/// interrupted `enroll.start` or refresh left beside `policy.d`, and make the
/// record agree with the directory. A change records the old and new names
/// together, marked pending, before it swaps (so a crash never leaves a file
/// no record owns); whichever directory the crash left live, its files are
/// the ones kept, and when that is the pending set the change landed and is
/// recorded as made. A recorded revision that is not what the owned files
/// hash to is replaced by theirs (one recorded before revisions existed stays
/// absent until the first refresh). Running it twice changes nothing the
/// second time.
pub fn settle(state_dir: &Path, enrollment: Option<&mut Enrollment>) -> io::Result<Settled> {
    for leftover in [STAGING_DIR, LEGACY_STAGING_DIR] {
        remove_dir_if_present(&state_dir.join(leftover))?;
    }
    let Some(enrollment) = enrollment else {
        return Ok(Settled::default());
    };
    let live = state_dir.join(POLICY_DIR);
    let before = enrollment.policy_fields();
    let mut fields = before.clone();
    fields.files.retain(|name| {
        owned_name_ok(name) && fs::symlink_metadata(live.join(name)).is_ok_and(|m| m.is_file())
    });
    let on_disk = CanonicalSet::read_owned(&live, &fields.files)?.revision();
    let mut landed = None;
    if let Some(pending) = fields.pending.take() {
        if on_disk == pending.revision {
            fields.hash = Some(on_disk.clone());
            fields.fetched_at = Some(pending.at.clone());
            fields.changed_at = Some(pending.at.clone());
            fields.refresh = Some(PolicyRefreshRecord {
                at: pending.at.clone(),
                result: pending.result.clone(),
                reason: None,
                offered_hash: None,
            });
            landed = Some(pending);
        }
    }
    if fields.hash.as_ref().is_some_and(|hash| *hash != on_disk) {
        fields.hash = Some(on_disk);
    }
    let changed = fields != before;
    if changed {
        apply_policy_fields(enrollment, fields);
    }
    Ok(Settled { changed, landed })
}

/// The steps of a policy change on disk that a failure or a crash can come
/// between, named for the tests that fail or stop one there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// Writing the staged set ([`prepare`]).
    Stage,
    /// Saving the record that owns both sets' files, the change pending.
    RecordBoth,
    /// Exchanging the staged directory with `policy.d`.
    Swap,
    /// Writing the rendered browser document.
    Render,
    /// Exchanging the previous directory back.
    RollBack,
    /// Saving the record that says what is enforced.
    RecordFinal,
    /// Removing the directory the swap replaced.
    Finish,
}

/// Each step of a change passes here first. Production never fails one.
#[cfg(not(test))]
#[inline]
pub(crate) fn step(_step: Step) -> io::Result<()> {
    Ok(())
}

/// Each step of a change passes here first: a test's hook may fail it, or
/// copy the state directory as a crash just before it would leave it.
#[cfg(test)]
pub(crate) fn step(step: Step) -> io::Result<()> {
    faults::at(step)
}

/// A hook, per test thread, called at every [`Step`] of a change.
#[cfg(test)]
pub(crate) mod faults {
    use std::cell::RefCell;
    use std::io;

    use super::Step;

    type Hook = Box<dyn FnMut(Step) -> io::Result<()>>;

    thread_local! {
        static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }

    /// Removes the hook when dropped.
    pub(crate) struct Installed;

    impl Drop for Installed {
        fn drop(&mut self) {
            HOOK.with(|hook| *hook.borrow_mut() = None);
        }
    }

    /// Call `hook` at every step on this thread until the guard drops.
    pub(crate) fn install(hook: impl FnMut(Step) -> io::Result<()> + 'static) -> Installed {
        HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        Installed
    }

    pub(super) fn at(step: Step) -> io::Result<()> {
        HOOK.with(|hook| match hook.borrow_mut().as_mut() {
            Some(hook) => hook(step),
            None => Ok(()),
        })
    }
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

    /// An envelope `depth` levels deep, itself the first: `inner`, a number,
    /// under `depth - 1` levels of arrays.
    fn nested(depth: usize, inner: Value) -> Value {
        let mut value = inner;
        for _ in 1..depth {
            value = json!([value]);
        }
        let mut envelope = envelope("deep", "organization_baseline", 2);
        envelope["x"] = value;
        envelope
    }

    /// Nesting is measured before anything is rendered: in canonical form
    /// every level indents every line inside it, so a payload of nesting
    /// alone would cost far more to render than it is worth to check.
    #[test]
    fn an_envelope_nested_past_the_bound_is_refused_before_it_is_rendered() {
        let deepest = nested(MAX_ENVELOPE_DEPTH, json!(0));
        assert!(CanonicalSet::from_envelopes(&[deepest], Assignment::Policies).is_ok());
        let deeper = nested(MAX_ENVELOPE_DEPTH + 1, json!(0));
        assert_eq!(
            rejection(&[deeper], Assignment::Policies),
            "envelope_too_deep"
        );
        // Well inside every size rule, and 120 levels deep: accepted before.
        assert_eq!(
            rejection(&[nested(120, json!([0, 0, 0]))], Assignment::Policies),
            "envelope_too_deep"
        );
    }

    /// The canonical bytes are written into a buffer that refuses to grow
    /// past the bound, however much the indentation multiplies a compact
    /// envelope that fits.
    #[test]
    fn canonical_form_is_never_held_past_its_bound() {
        let mut bounded = Bounded::keeping(8);
        use std::io::Write;
        assert!(bounded.write_all(b"12345678").is_ok());
        assert!(bounded.write_all(b"9").is_err());
        assert_eq!(bounded.bytes, b"12345678");
        let mut counting = Bounded::counting(8);
        assert!(counting.write_all(&[0; 9]).is_err());
        assert!(counting.bytes.is_empty(), "counted, not kept");

        // 60 000 zeros are about 120 KiB compact, and each is a line of its
        // own some 60 spaces in when rendered.
        let wide = nested(MAX_ENVELOPE_DEPTH - 1, json!(vec![0; 60_000]));
        assert!(!nested_deeper_than(&wide, MAX_ENVELOPE_DEPTH));
        assert!(serde_json::to_vec(&wide).unwrap().len() < MAX_ENVELOPE_BYTES);
        assert_eq!(
            rejection(&[wide], Assignment::Policies),
            "envelope_too_large"
        );
    }

    /// Every set the rules allow fits in an answer punard reads, so a valid
    /// set can never read as an unreachable control plane: the envelopes
    /// together are bounded, not only each one.
    #[test]
    fn a_set_the_rules_allow_fits_in_an_answer() {
        assert!(MAX_SET_BYTES * 4 <= crate::enroll::MAX_ANSWER_BYTES as usize);
        let sized = |id: &str, bytes: usize| {
            let mut sized = envelope(id, "organization_baseline", 2);
            sized["source_name"] = json!("x".repeat(bytes));
            sized
        };
        // Twenty envelopes each well inside its own bound: 4.3 MiB together.
        let many: Vec<Value> = (0..20)
            .map(|i| sized(&format!("p{i}"), 220 * 1024))
            .collect();
        assert_eq!(rejection(&many, Assignment::Policies), "set_too_large");

        // The largest set the rules allow, as a control plane answers it.
        let per = MAX_SET_BYTES / 5 - 200;
        let largest: Vec<Value> = (0..5).map(|i| sized(&format!("q{i}"), per)).collect();
        let set = CanonicalSet::from_envelopes(&largest, Assignment::Policies).unwrap();
        let canonical: usize = set.files().values().map(Vec::len).sum();
        assert!(canonical > MAX_SET_BYTES - 1024, "{canonical}");
        let answer = json!({"v": 1, "id": "punard-1", "result": {
            "policies": largest, "assignment": "policies"}})
        .to_string();
        assert!(answer.len() < crate::enroll::MAX_ANSWER_BYTES as usize);
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

    /// A root drop added, replaced or removed after the set was prepared is
    /// found on either side of the swap, never lost with the directory it
    /// was changed in; one edited in place is the carried file itself.
    #[test]
    fn a_root_drop_changed_after_prepare_stops_the_change() {
        let dir = tmp("carried");
        let live = dir.join(POLICY_DIR);
        write(&live.join("eng-baseline-v12.json"), b"the old org file");
        write(&live.join("local.note"), b"kept");
        fs::create_dir_all(live.join("ai")).unwrap();
        let owned = vec!["eng-baseline-v12.json".to_string()];
        let changed = |failure: LocalFailure| match failure {
            LocalFailure::LocalFilesChanged(name) => name,
            other => panic!("expected a local change, got {other:?}"),
        };

        let prepared = prepare(&dir, &set(&[acme()]), &owned).unwrap();
        assert!(prepared.still_current(&live, &owned).is_ok());
        write(&live.join("local.note"), b"edited in place");
        assert!(prepared.still_current(&live, &owned).is_ok());
        write(&live.join("added.note"), b"added");
        assert_eq!(
            changed(prepared.still_current(&live, &owned).unwrap_err()),
            "added.note"
        );
        fs::remove_file(live.join("added.note")).unwrap();
        // An editor's save: a new file renamed over the old name.
        write(&dir.join("replacement"), b"replaced");
        fs::rename(dir.join("replacement"), live.join("local.note")).unwrap();
        assert_eq!(
            changed(prepared.still_current(&live, &owned).unwrap_err()),
            "local.note"
        );
        fs::remove_file(live.join("local.note")).unwrap();
        assert_eq!(
            changed(prepared.still_current(&live, &owned).unwrap_err()),
            "local.note"
        );
        write(&live.join("local.note"), b"kept");
        // An empty directory that is no longer empty.
        let prepared = prepare(&dir, &set(&[acme()]), &owned).unwrap();
        write(&live.join("ai/stale.yaml"), b"x");
        assert_eq!(
            changed(prepared.still_current(&live, &owned).unwrap_err()),
            "ai"
        );
        fs::remove_file(live.join("ai/stale.yaml")).unwrap();

        // Written just before the exchange: found in the directory it
        // replaced, and the rollback puts it back live.
        let swapped = swap_in(prepared.staging(), &live).unwrap();
        assert!(
            swapped
                .replaced_only_what_was_carried(&prepared, &owned)
                .is_ok()
        );
        swapped.roll_back().unwrap();
        let prepared = prepare(&dir, &set(&[acme()]), &owned).unwrap();
        write(&live.join("late.note"), b"late");
        let swapped = swap_in(prepared.staging(), &live).unwrap();
        assert_eq!(
            changed(
                swapped
                    .replaced_only_what_was_carried(&prepared, &owned)
                    .unwrap_err()
            ),
            "late.note"
        );
        swapped.roll_back().unwrap();
        assert_eq!(fs::read(live.join("late.note")).unwrap(), b"late");
        assert_eq!(
            fs::read(live.join("eng-baseline-v12.json")).unwrap(),
            b"the old org file"
        );
        assert!(!dir.join(STAGING_DIR).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// Whether a rollback put the previous directory back is read from
    /// policy.d: one whose exchange failed leaves both directories where
    /// they are, the previous one included, and says so.
    #[test]
    fn a_rollback_is_verified_and_a_failed_one_removes_nothing() {
        let dir = tmp("rollback");
        let live = dir.join(POLICY_DIR);
        let staging = dir.join(STAGING_DIR);
        write(&live.join("old.json"), b"old");
        write(&staging.join("new.json"), b"new");
        let swapped = swap_in(&staging, &live).unwrap();
        let failed = {
            let _hook = faults::install(|step| match step {
                Step::RollBack => Err(io::Error::other("the exchange was refused")),
                _ => Ok(()),
            });
            swapped.roll_back().unwrap_err()
        };
        assert!(failed.to_string().contains("refused"), "{failed}");
        assert_eq!(fs::read(live.join("new.json")).unwrap(), b"new");
        assert_eq!(
            fs::read(staging.join("old.json")).unwrap(),
            b"old",
            "the last good set is still there"
        );
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

    fn revision_of(dir: &Path, names: &[&str]) -> String {
        let names: Vec<String> = names.iter().map(|name| name.to_string()).collect();
        CanonicalSet::read_owned(&dir.join(POLICY_DIR), &names)
            .unwrap()
            .revision()
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
        let settled = settle(&dir, Some(&mut record)).unwrap();
        assert!(settled.changed);
        assert!(settled.landed.is_none(), "nothing was pending");
        assert_eq!(record.policy_files, ["kept.json", "new.json"]);
        assert_eq!(
            record.policy_hash,
            Some(revision_of(&dir, &["kept.json", "new.json"])),
            "derived again from the files"
        );
        assert!(!dir.join(STAGING_DIR).exists());
        assert!(!dir.join(LEGACY_STAGING_DIR).exists());
        assert_eq!(record.removable, enrollment(&[]).removable, "no term moves");

        let settled = record.clone();
        assert!(
            !settle(&dir, Some(&mut record)).unwrap().changed,
            "idempotent"
        );
        assert_eq!(record, settled);
        // A record that agrees with the directory is left alone; one whose
        // revision a crash left behind the files is corrected.
        let mut untouched = enrollment(&["kept.json", "new.json"]);
        untouched.policy_hash = Some(revision_of(&dir, &["kept.json", "new.json"]));
        assert!(!settle(&dir, Some(&mut untouched)).unwrap().changed);
        let mut stale = enrollment(&["kept.json", "new.json"]);
        assert!(settle(&dir, Some(&mut stale)).unwrap().changed);
        assert_eq!(stale.policy_hash, untouched.policy_hash);
        // One recorded before revisions existed learns it at its first
        // refresh, as enroll.status says.
        let mut older = enrollment(&["kept.json", "new.json"]);
        older.policy_hash = None;
        assert!(!settle(&dir, Some(&mut older)).unwrap().changed);
        assert!(!settle(&dir, None).unwrap().changed);
        let _ = fs::remove_dir_all(&dir);
    }

    fn pending(revision: String, result: &str) -> PendingPolicyChange {
        PendingPolicyChange {
            revision,
            result: result.to_string(),
            policy_ids: vec!["new".to_string()],
            at: "2026-09-24T12:00:00Z".to_string(),
            event_id: "evt_1x1".to_string(),
        }
    }

    /// A change recorded as pending is found landed exactly when policy.d
    /// holds its set: then the record says it was made, when, and hands it
    /// back to be audited; otherwise the record keeps what was enforced.
    /// Either way nothing stays pending.
    #[test]
    fn settle_decides_from_the_directory_whether_a_pending_change_landed() {
        let dir = tmp("settle-pending");
        let live = dir.join(POLICY_DIR);
        write(&live.join("old.json"), b"old");
        let old = revision_of(&dir, &["old.json"]);
        write(&live.join("new.json"), b"new");
        let both = revision_of(&dir, &["new.json", "old.json"]);
        fs::remove_file(live.join("new.json")).unwrap();

        // The swap never happened: the old set is live.
        let mut record = enrollment(&["new.json", "old.json"]);
        record.policy_hash = Some(old.clone());
        record.policy_pending = Some(pending(both.clone(), "applied"));
        let settled = settle(&dir, Some(&mut record)).unwrap();
        assert!(settled.changed && settled.landed.is_none());
        assert_eq!(record.policy_files, ["old.json"]);
        assert_eq!(record.policy_hash.as_deref(), Some(old.as_str()));
        assert_eq!(record.policy_pending, None);
        assert_eq!(record.policy_changed_at, None, "unchanged");

        // It did: the new set (both files) is live.
        write(&live.join("new.json"), b"new");
        let mut record = enrollment(&["new.json", "old.json"]);
        record.policy_hash = Some(old.clone());
        record.policy_pending = Some(pending(both.clone(), "applied"));
        let settled = settle(&dir, Some(&mut record)).unwrap();
        assert!(settled.changed);
        assert_eq!(settled.landed, Some(pending(both.clone(), "applied")));
        assert_eq!(record.policy_files, ["new.json", "old.json"]);
        assert_eq!(record.policy_hash.as_deref(), Some(both.as_str()));
        assert_eq!(
            record.policy_changed_at.as_deref(),
            Some("2026-09-24T12:00:00Z")
        );
        let refresh = record.policy_refresh.clone().unwrap();
        assert_eq!(refresh.result, "applied");
        assert_eq!(record.policy_pending, None);
        assert!(settle(&dir, Some(&mut record)).unwrap().landed.is_none());

        // A withdrawal lands when none of the old files is left.
        let empty = CanonicalSet::default().revision();
        let mut record = enrollment(&["new.json", "old.json"]);
        record.policy_pending = Some(pending(empty.clone(), "withdrawn"));
        assert!(settle(&dir, Some(&mut record)).unwrap().landed.is_none());
        fs::remove_file(live.join("new.json")).unwrap();
        fs::remove_file(live.join("old.json")).unwrap();
        let mut record = enrollment(&["new.json", "old.json"]);
        record.policy_pending = Some(pending(empty.clone(), "withdrawn"));
        let settled = settle(&dir, Some(&mut record)).unwrap();
        assert_eq!(settled.landed.unwrap().result, "withdrawn");
        assert!(record.policy_files.is_empty());
        assert_eq!(record.policy_hash, Some(empty));
        let _ = fs::remove_dir_all(&dir);
    }
}
