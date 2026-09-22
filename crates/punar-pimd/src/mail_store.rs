//! Crash-durable, descriptor-bound Mail storage.
//!
//! The Calendar/Reminders JSON store intentionally stays small. Mail uses a
//! separate copy-on-write database opened from a pre-validated `O_NOFOLLOW`
//! file descriptor so message volume never turns every synchronization batch
//! into a whole-file rewrite. Only bounded, parsed Punar records enter this
//! store; raw MIME, HTML and attachment payloads are not representable here.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use punar_common::time::is_rfc3339_timestamp;
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{MailMessage, MailSummary, ParsedMail};

const MAIL_STORE_VERSION: &str = "1";
const MAX_MAIL_STORE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_BATCH_MESSAGES: usize = 200;
const MAX_STORED_MESSAGES: u64 = 500_000;
const MAX_SUMMARY_PAGE: usize = 100;
const MAX_THREAD_PAGE: usize = 100;
const MAX_RECORD_BYTES: usize = 2 * 1024 * 1024;
const MAIL_CACHE_BYTES: usize = 8 * 1024 * 1024;
const PRIVATE_DIR_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

const META: TableDefinition<&str, &str> = TableDefinition::new("meta");
const MESSAGES: TableDefinition<&str, &[u8]> = TableDefinition::new("messages");
const MESSAGE_META: TableDefinition<&str, &[u8]> = TableDefinition::new("message_meta");
const THREADS: TableDefinition<&str, &[u8]> = TableDefinition::new("threads");
const THREAD_ORDER: TableDefinition<&str, &str> = TableDefinition::new("thread_order");
const SYNC_CURSORS: TableDefinition<&str, &[u8]> = TableDefinition::new("sync_cursors");

#[derive(Debug, Error)]
pub enum MailStoreError {
    #[error("Mail store I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("Mail store database failed")]
    Database,
    #[error("Mail store is corrupt: {0}")]
    Corrupt(String),
    #[error("Mail store belongs to a different profile")]
    ProfileMismatch,
    #[error("invalid Mail value: {0}")]
    Invalid(String),
    #[error("Mail record was not found")]
    NotFound,
}

#[derive(Debug, Clone)]
pub struct MailBatchItem {
    pub uid: u32,
    pub parsed: ParsedMail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailSummaryPage {
    pub summaries: Vec<MailSummary>,
    /// Internal stable key. The application-facing layer must integrity-protect
    /// and bind it through the existing cursor signer before returning it.
    pub next_before: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailThreadPage {
    pub thread_id: String,
    pub account_id: String,
    pub subject: String,
    pub messages: Vec<MailMessage>,
    pub next_offset: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailSyncCursor {
    pub account_id: String,
    pub mailbox_id: String,
    pub uid_validity: u32,
    pub last_uid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredMessageMeta {
    account_id: String,
    mailbox_id: String,
    uid_validity: u32,
    uid: u32,
    message_id: String,
    summary: MailSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredThread {
    summary: MailSummary,
    message_ids: Vec<String>,
}

pub struct MailStore {
    path: PathBuf,
    identity: File,
    database: Database,
}

impl MailStore {
    /// Opens one profile's Mail database from a descriptor that was acquired
    /// with `O_NOFOLLOW`. The retained descriptor is checked before every
    /// operation so path replacement and later hard-linking fail closed.
    pub fn open(path: &Path, profile_id: &str, profile_uid: u32) -> Result<Self, MailStoreError> {
        validate_profile_id(profile_id)?;
        prepare_private_parent(path)?;
        let (file, created) = open_private_database(path)?;
        let identity = file.try_clone()?;
        let mut builder = Database::builder();
        builder.set_cache_size(MAIL_CACHE_BYTES);
        let database = match builder.create_file(file) {
            Ok(database) => database,
            Err(error) => {
                if created {
                    let _ = fs::remove_file(path);
                    sync_parent(path);
                }
                return Err(database_error(error));
            }
        };
        let store = Self {
            path: path.to_path_buf(),
            identity,
            database,
        };
        let initialized = store
            .validate_identity()
            .and_then(|()| store.initialize_or_validate(profile_id, profile_uid, created));
        if let Err(error) = initialized {
            drop(store);
            if created {
                let _ = fs::remove_file(path);
                sync_parent(path);
            }
            return Err(error);
        }
        Ok(store)
    }

    pub fn sync_cursor(
        &self,
        account_id: &str,
        mailbox_id: &str,
    ) -> Result<Option<MailSyncCursor>, MailStoreError> {
        self.validate_identity()?;
        validate_account_id(account_id)?;
        validate_mailbox_id(mailbox_id)?;
        let transaction = self.database.begin_read().map_err(database_error)?;
        let table = transaction
            .open_table(SYNC_CURSORS)
            .map_err(database_error)?;
        let key = mailbox_key(account_id, mailbox_id);
        table
            .get(key.as_str())
            .map_err(database_error)?
            .map(|value| decode(value.value()))
            .transpose()
    }

    /// Atomically stores one bounded synchronization batch and advances its
    /// cursor. A UIDVALIDITY change removes only that mailbox's older
    /// generation in the same transaction before the new generation appears.
    pub fn store_batch(
        &self,
        account_id: &str,
        mailbox_id: &str,
        uid_validity: u32,
        items: Vec<MailBatchItem>,
        last_uid: u32,
    ) -> Result<MailSyncCursor, MailStoreError> {
        self.validate_identity()?;
        validate_batch(account_id, mailbox_id, uid_validity, &items, last_uid)?;
        let mut encoded = Vec::with_capacity(items.len());
        for item in items {
            let metadata = StoredMessageMeta {
                account_id: account_id.to_string(),
                mailbox_id: mailbox_id.to_string(),
                uid_validity,
                uid: item.uid,
                message_id: item.parsed.message.message_id.clone(),
                summary: item.parsed.summary,
            };
            let message = encode(&item.parsed.message)?;
            let metadata_bytes = encode(&metadata)?;
            if message.len() > MAX_RECORD_BYTES || metadata_bytes.len() > MAX_RECORD_BYTES {
                return Err(MailStoreError::Invalid(
                    "parsed Mail record exceeds its storage bound".into(),
                ));
            }
            encoded.push((metadata, metadata_bytes, message));
        }

        let transaction = self.database.begin_write().map_err(database_error)?;
        let cursor_key = mailbox_key(account_id, mailbox_id);
        let previous_cursor = {
            let table = transaction
                .open_table(SYNC_CURSORS)
                .map_err(database_error)?;
            table
                .get(cursor_key.as_str())
                .map_err(database_error)?
                .map(|value| decode::<MailSyncCursor>(value.value()))
                .transpose()?
        };
        if let Some(previous) = &previous_cursor {
            if previous.uid_validity == uid_validity && last_uid < previous.last_uid {
                return Err(MailStoreError::Invalid(
                    "Mail synchronization cursor cannot move backwards".into(),
                ));
            }
        }

        let mut touched_threads = BTreeSet::new();
        if previous_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.uid_validity != uid_validity)
        {
            let removed = remove_mailbox_generation(&transaction, account_id, mailbox_id)?;
            touched_threads.extend(removed);
        }

        {
            let metadata_table = transaction
                .open_table(MESSAGE_META)
                .map_err(database_error)?;
            for (metadata, _, _) in &encoded {
                if let Some(old) = metadata_table
                    .get(metadata.message_id.as_str())
                    .map_err(database_error)?
                {
                    let old: StoredMessageMeta = decode(old.value())?;
                    touched_threads.insert(old.summary.thread_id);
                }
            }
        }
        {
            let mut messages = transaction.open_table(MESSAGES).map_err(database_error)?;
            let mut metadata_table = transaction
                .open_table(MESSAGE_META)
                .map_err(database_error)?;
            for (metadata, metadata_bytes, message) in &encoded {
                messages
                    .insert(metadata.message_id.as_str(), message.as_slice())
                    .map_err(database_error)?;
                metadata_table
                    .insert(metadata.message_id.as_str(), metadata_bytes.as_slice())
                    .map_err(database_error)?;
                touched_threads.insert(metadata.summary.thread_id.clone());
            }
            if metadata_table.len().map_err(database_error)? > MAX_STORED_MESSAGES {
                return Err(MailStoreError::Invalid(
                    "Mail store reached its fixed message-count limit".into(),
                ));
            }
        }

        rebuild_threads(&transaction, &touched_threads)?;
        let cursor = MailSyncCursor {
            account_id: account_id.to_string(),
            mailbox_id: mailbox_id.to_string(),
            uid_validity,
            last_uid,
        };
        let cursor_bytes = encode(&cursor)?;
        {
            let mut cursors = transaction
                .open_table(SYNC_CURSORS)
                .map_err(database_error)?;
            cursors
                .insert(cursor_key.as_str(), cursor_bytes.as_slice())
                .map_err(database_error)?;
        }
        transaction.commit().map_err(database_error)?;
        self.validate_identity()?;
        Ok(cursor)
    }

    pub fn list_summaries(
        &self,
        account_id: &str,
        before: Option<&str>,
        limit: usize,
    ) -> Result<MailSummaryPage, MailStoreError> {
        self.validate_identity()?;
        validate_account_id(account_id)?;
        if limit == 0 || limit > MAX_SUMMARY_PAGE {
            return Err(MailStoreError::Invalid(format!(
                "Mail summary page limit must be 1..={MAX_SUMMARY_PAGE}"
            )));
        }
        let prefix = account_prefix(account_id);
        let upper = format!("{account_id}\u{1}");
        let end = before.unwrap_or(upper.as_str());
        if !end.starts_with(prefix.as_str()) && end != upper {
            return Err(MailStoreError::Invalid(
                "Mail page cursor belongs to another account".into(),
            ));
        }

        let transaction = self.database.begin_read().map_err(database_error)?;
        let order = transaction
            .open_table(THREAD_ORDER)
            .map_err(database_error)?;
        let threads = transaction.open_table(THREADS).map_err(database_error)?;
        let mut summaries = Vec::with_capacity(limit);
        let mut keys = Vec::with_capacity(limit + 1);
        let range = order.range(prefix.as_str()..end).map_err(database_error)?;
        for entry in range.rev().take(limit + 1) {
            let (key, thread_id) = entry.map_err(database_error)?;
            let thread = threads
                .get(thread_id.value())
                .map_err(database_error)?
                .ok_or_else(|| MailStoreError::Corrupt("Mail order index is stale".into()))?;
            let thread: StoredThread = decode(thread.value())?;
            keys.push(key.value().to_string());
            summaries.push(thread.summary);
        }
        let has_more = summaries.len() > limit;
        if has_more {
            summaries.truncate(limit);
            keys.truncate(limit);
        }
        let next_before = has_more.then(|| keys.last().cloned()).flatten();
        Ok(MailSummaryPage {
            summaries,
            next_before,
        })
    }

    pub fn thread(
        &self,
        account_id: &str,
        thread_id: &str,
        offset: usize,
        limit: usize,
    ) -> Result<MailThreadPage, MailStoreError> {
        self.validate_identity()?;
        validate_account_id(account_id)?;
        validate_opaque_id(thread_id, "thread_")?;
        if limit == 0 || limit > MAX_THREAD_PAGE {
            return Err(MailStoreError::Invalid(format!(
                "Mail thread page limit must be 1..={MAX_THREAD_PAGE}"
            )));
        }
        let transaction = self.database.begin_read().map_err(database_error)?;
        let threads = transaction.open_table(THREADS).map_err(database_error)?;
        let thread = threads
            .get(thread_id)
            .map_err(database_error)?
            .ok_or(MailStoreError::NotFound)?;
        let thread: StoredThread = decode(thread.value())?;
        if thread.summary.account_id != account_id {
            return Err(MailStoreError::NotFound);
        }
        if offset > thread.message_ids.len() {
            return Err(MailStoreError::Invalid(
                "Mail thread offset is outside the snapshot".into(),
            ));
        }
        let messages_table = transaction.open_table(MESSAGES).map_err(database_error)?;
        let end = offset.saturating_add(limit).min(thread.message_ids.len());
        let mut messages = Vec::with_capacity(end.saturating_sub(offset));
        for message_id in &thread.message_ids[offset..end] {
            let value = messages_table
                .get(message_id.as_str())
                .map_err(database_error)?
                .ok_or_else(|| MailStoreError::Corrupt("Mail thread member is absent".into()))?;
            messages.push(decode(value.value())?);
        }
        let next_offset = (end < thread.message_ids.len()).then_some(end);
        Ok(MailThreadPage {
            thread_id: thread.summary.thread_id,
            account_id: thread.summary.account_id,
            subject: thread.summary.subject,
            messages,
            next_offset,
        })
    }

    pub fn remove_account(&self, account_id: &str) -> Result<(), MailStoreError> {
        self.validate_identity()?;
        validate_account_id(account_id)?;
        let transaction = self.database.begin_write().map_err(database_error)?;
        let mut touched_threads = BTreeSet::new();
        let mut message_ids = Vec::new();
        {
            let metadata = transaction
                .open_table(MESSAGE_META)
                .map_err(database_error)?;
            for entry in metadata.iter().map_err(database_error)? {
                let (key, value) = entry.map_err(database_error)?;
                let value: StoredMessageMeta = decode(value.value())?;
                if value.account_id == account_id {
                    message_ids.push(key.value().to_string());
                    touched_threads.insert(value.summary.thread_id);
                }
            }
        }
        {
            let mut metadata = transaction
                .open_table(MESSAGE_META)
                .map_err(database_error)?;
            let mut messages = transaction.open_table(MESSAGES).map_err(database_error)?;
            for message_id in message_ids {
                metadata
                    .remove(message_id.as_str())
                    .map_err(database_error)?;
                messages
                    .remove(message_id.as_str())
                    .map_err(database_error)?;
            }
        }
        {
            let mut cursors = transaction
                .open_table(SYNC_CURSORS)
                .map_err(database_error)?;
            let prefix = account_prefix(account_id);
            let keys = cursors
                .iter()
                .map_err(database_error)?
                .filter_map(|entry| entry.ok())
                .map(|(key, _)| key.value().to_string())
                .filter(|key| key.starts_with(prefix.as_str()))
                .collect::<Vec<_>>();
            for key in keys {
                cursors.remove(key.as_str()).map_err(database_error)?;
            }
        }
        rebuild_threads(&transaction, &touched_threads)?;
        transaction.commit().map_err(database_error)?;
        self.validate_identity()
    }

    fn initialize_or_validate(
        &self,
        profile_id: &str,
        profile_uid: u32,
        created: bool,
    ) -> Result<(), MailStoreError> {
        let transaction = self.database.begin_write().map_err(database_error)?;
        {
            let mut meta = transaction.open_table(META).map_err(database_error)?;
            let version = meta
                .get("schema_version")
                .map_err(database_error)?
                .map(|value| value.value().to_string());
            match version {
                None if created => {
                    let profile_uid = profile_uid.to_string();
                    meta.insert("schema_version", MAIL_STORE_VERSION)
                        .map_err(database_error)?;
                    meta.insert("profile_id", profile_id)
                        .map_err(database_error)?;
                    meta.insert("profile_uid", profile_uid.as_str())
                        .map_err(database_error)?;
                }
                None => {
                    return Err(MailStoreError::Corrupt(
                        "existing Mail store has no schema identity".into(),
                    ));
                }
                Some(version) if version != MAIL_STORE_VERSION => {
                    return Err(MailStoreError::Corrupt(
                        "Mail store schema version is unsupported".into(),
                    ));
                }
                Some(_) => {
                    let stored_profile = meta
                        .get("profile_id")
                        .map_err(database_error)?
                        .map(|value| value.value().to_string());
                    let stored_uid = meta
                        .get("profile_uid")
                        .map_err(database_error)?
                        .map(|value| value.value().to_string());
                    if stored_profile.as_deref() != Some(profile_id)
                        || stored_uid.as_deref() != Some(profile_uid.to_string().as_str())
                    {
                        return Err(MailStoreError::ProfileMismatch);
                    }
                }
            }
        }
        transaction.commit().map_err(database_error)?;
        sync_parent(&self.path);
        Ok(())
    }

    fn validate_identity(&self) -> Result<(), MailStoreError> {
        let held = self.identity.metadata()?;
        validate_private_file(&held)?;
        if held.len() > MAX_MAIL_STORE_BYTES {
            return Err(MailStoreError::Corrupt(
                "Mail store exceeds its fixed size limit".into(),
            ));
        }
        let path = fs::symlink_metadata(&self.path)?;
        validate_private_file(&path)?;
        if held.dev() != path.dev() || held.ino() != path.ino() {
            return Err(MailStoreError::Corrupt(
                "Mail store path was replaced after open".into(),
            ));
        }
        Ok(())
    }
}

fn remove_mailbox_generation(
    transaction: &redb::WriteTransaction,
    account_id: &str,
    mailbox_id: &str,
) -> Result<BTreeSet<String>, MailStoreError> {
    let mut ids = Vec::new();
    let mut threads = BTreeSet::new();
    {
        let metadata = transaction
            .open_table(MESSAGE_META)
            .map_err(database_error)?;
        for entry in metadata.iter().map_err(database_error)? {
            let (key, value) = entry.map_err(database_error)?;
            let value: StoredMessageMeta = decode(value.value())?;
            if value.account_id == account_id && value.mailbox_id == mailbox_id {
                ids.push(key.value().to_string());
                threads.insert(value.summary.thread_id);
            }
        }
    }
    {
        let mut metadata = transaction
            .open_table(MESSAGE_META)
            .map_err(database_error)?;
        let mut messages = transaction.open_table(MESSAGES).map_err(database_error)?;
        for id in ids {
            metadata.remove(id.as_str()).map_err(database_error)?;
            messages.remove(id.as_str()).map_err(database_error)?;
        }
    }
    Ok(threads)
}

fn rebuild_threads(
    transaction: &redb::WriteTransaction,
    touched: &BTreeSet<String>,
) -> Result<(), MailStoreError> {
    if touched.is_empty() {
        return Ok(());
    }
    let mut grouped: BTreeMap<String, Vec<StoredMessageMeta>> = touched
        .iter()
        .cloned()
        .map(|thread_id| (thread_id, Vec::new()))
        .collect();
    {
        let metadata = transaction
            .open_table(MESSAGE_META)
            .map_err(database_error)?;
        for entry in metadata.iter().map_err(database_error)? {
            let (_, value) = entry.map_err(database_error)?;
            let value: StoredMessageMeta = decode(value.value())?;
            if let Some(group) = grouped.get_mut(&value.summary.thread_id) {
                group.push(value);
            }
        }
    }

    let mut threads = transaction.open_table(THREADS).map_err(database_error)?;
    let mut order = transaction
        .open_table(THREAD_ORDER)
        .map_err(database_error)?;
    for (thread_id, mut members) in grouped {
        if let Some(old) = threads.get(thread_id.as_str()).map_err(database_error)? {
            let old: StoredThread = decode(old.value())?;
            order
                .remove(order_key(&old.summary).as_str())
                .map_err(database_error)?;
        }
        if members.is_empty() {
            threads.remove(thread_id.as_str()).map_err(database_error)?;
            continue;
        }
        members.sort_by(|left, right| {
            left.summary
                .received_at
                .cmp(&right.summary.received_at)
                .then(left.message_id.cmp(&right.message_id))
        });
        let mut summary = members.last().unwrap().summary.clone();
        summary.unread = members.iter().any(|member| member.summary.unread);
        summary.starred = members.iter().any(|member| member.summary.starred);
        summary.attachments_count = members.iter().fold(0_u32, |total, member| {
            total.saturating_add(member.summary.attachments_count)
        });
        summary.labels = members
            .iter()
            .flat_map(|member| member.summary.labels.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let thread = StoredThread {
            summary,
            message_ids: members
                .into_iter()
                .map(|member| member.message_id)
                .collect(),
        };
        let bytes = encode(&thread)?;
        let key = order_key(&thread.summary);
        order
            .insert(key.as_str(), thread_id.as_str())
            .map_err(database_error)?;
        threads
            .insert(thread_id.as_str(), bytes.as_slice())
            .map_err(database_error)?;
    }
    Ok(())
}

fn validate_batch(
    account_id: &str,
    mailbox_id: &str,
    uid_validity: u32,
    items: &[MailBatchItem],
    last_uid: u32,
) -> Result<(), MailStoreError> {
    validate_account_id(account_id)?;
    validate_mailbox_id(mailbox_id)?;
    if uid_validity == 0 || (last_uid == 0 && !items.is_empty()) || items.len() > MAX_BATCH_MESSAGES
    {
        return Err(MailStoreError::Invalid(
            "Mail synchronization identity is invalid".into(),
        ));
    }
    let mut seen = BTreeSet::new();
    for item in items {
        if item.uid == 0 || item.uid > last_uid || !seen.insert(item.uid) {
            return Err(MailStoreError::Invalid(
                "Mail batch UID set is invalid".into(),
            ));
        }
        if item.parsed.summary.account_id != account_id
            || item.parsed.summary.thread_id.is_empty()
            || item.parsed.message.message_id.is_empty()
            || !is_rfc3339_timestamp(&item.parsed.summary.received_at)
            || !is_rfc3339_timestamp(&item.parsed.message.sent_at)
        {
            return Err(MailStoreError::Invalid(
                "parsed Mail record identity is inconsistent".into(),
            ));
        }
        validate_opaque_id(&item.parsed.summary.thread_id, "thread_")?;
        validate_opaque_id(&item.parsed.message.message_id, "message_")?;
    }
    Ok(())
}

fn open_private_database(path: &Path) -> Result<(File, bool), MailStoreError> {
    let flags =
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;
    let (descriptor, created) = match rustix::fs::open(path, flags, rustix::fs::Mode::empty()) {
        Ok(descriptor) => (descriptor, false),
        Err(rustix::io::Errno::NOENT) => (
            rustix::fs::open(
                path,
                flags | rustix::fs::OFlags::CREATE | rustix::fs::OFlags::EXCL,
                rustix::fs::Mode::from_raw_mode(PRIVATE_FILE_MODE),
            )
            .map_err(io::Error::from)?,
            true,
        ),
        Err(rustix::io::Errno::LOOP) => {
            return Err(MailStoreError::Corrupt(
                "Mail store path must not be a symbolic link".into(),
            ));
        }
        Err(error) => return Err(io::Error::from(error).into()),
    };
    let file = File::from(descriptor);
    validate_private_file(&file.metadata()?)?;
    Ok((file, created))
}

fn prepare_private_parent(path: &Path) -> Result<(), MailStoreError> {
    let parent = path
        .parent()
        .ok_or_else(|| MailStoreError::Invalid("Mail store path has no parent".into()))?;
    if !parent.exists() {
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(PRIVATE_DIR_MODE))?;
    }
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o777 != PRIVATE_DIR_MODE
    {
        return Err(MailStoreError::Corrupt(
            "Mail store parent permissions are not private".into(),
        ));
    }
    Ok(())
}

fn validate_private_file(metadata: &fs::Metadata) -> Result<(), MailStoreError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != PRIVATE_FILE_MODE
    {
        return Err(MailStoreError::Corrupt(
            "Mail store is not a private owned regular file".into(),
        ));
    }
    Ok(())
}

fn validate_profile_id(value: &str) -> Result<(), MailStoreError> {
    let suffix = value
        .strip_prefix("profile_")
        .ok_or_else(|| MailStoreError::Invalid("profile id has invalid prefix".into()))?;
    if suffix.is_empty()
        || suffix.len() > 64
        || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(MailStoreError::Invalid(
            "profile id has invalid characters".into(),
        ));
    }
    Ok(())
}

fn validate_account_id(value: &str) -> Result<(), MailStoreError> {
    let suffix = value
        .strip_prefix("acct_")
        .ok_or_else(|| MailStoreError::Invalid("account id has invalid prefix".into()))?;
    if value.len() > 80
        || suffix.is_empty()
        || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(MailStoreError::Invalid(
            "account id has invalid shape".into(),
        ));
    }
    Ok(())
}

fn validate_mailbox_id(value: &str) -> Result<(), MailStoreError> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(MailStoreError::Invalid(
            "mailbox id has invalid shape".into(),
        ));
    }
    Ok(())
}

fn validate_opaque_id(value: &str, expected_prefix: &str) -> Result<(), MailStoreError> {
    let suffix = value
        .strip_prefix(expected_prefix)
        .ok_or_else(|| MailStoreError::Invalid("Mail record id has invalid prefix".into()))?;
    if value.len() > 128
        || suffix.is_empty()
        || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(MailStoreError::Invalid(
            "Mail record id has invalid shape".into(),
        ));
    }
    Ok(())
}

fn mailbox_key(account_id: &str, mailbox_id: &str) -> String {
    format!("{account_id}\0{mailbox_id}")
}

fn account_prefix(account_id: &str) -> String {
    format!("{account_id}\0")
}

fn order_key(summary: &MailSummary) -> String {
    format!(
        "{}\0{}\0{}",
        summary.account_id, summary.received_at, summary.thread_id
    )
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, MailStoreError> {
    serde_json::to_vec(value).map_err(|_| MailStoreError::Database)
}

fn decode<T: for<'de> Deserialize<'de>>(value: &[u8]) -> Result<T, MailStoreError> {
    serde_json::from_slice(value)
        .map_err(|_| MailStoreError::Corrupt("Mail record failed strict decoding".into()))
}

fn database_error<E>(_error: E) -> MailStoreError {
    MailStoreError::Database
}

fn sync_parent(path: &Path) {
    if let Some(parent) = path.parent()
        && let Ok(directory) = File::open(parent)
    {
        let _ = directory.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{MailIngestInput, ingest_message};

    const RECEIVED: &str = "2026-09-22T16:00:00Z";

    fn temp_store(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!(
                "punar-mail-store-{name}-{}-{nonce}",
                std::process::id()
            ))
            .join("mail.redb")
    }

    fn open(path: &Path) -> MailStore {
        MailStore::open(path, "profile_alice", rustix::process::getuid().as_raw()).unwrap()
    }

    fn parsed(uid: u32, subject: &str, body: &str) -> ParsedMail {
        let raw = format!(
            "From: Alice <alice@example.com>\r\nTo: Bob <bob@example.com>\r\nMessage-ID: <m{uid}@example.com>\r\nDate: Mon, 22 Sep 2026 16:00:00 +0000\r\nSubject: {subject}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}"
        );
        ingest_message(MailIngestInput {
            account_id: "acct_A1",
            mailbox_id: "INBOX",
            uid_validity: 7,
            uid,
            received_at: RECEIVED,
            unread: true,
            starred: false,
            labels: &["Inbox".to_string()],
            raw_message: raw.as_bytes(),
        })
        .unwrap()
    }

    fn batch(uid: u32, subject: &str, body: &str) -> MailBatchItem {
        MailBatchItem {
            uid,
            parsed: parsed(uid, subject, body),
        }
    }

    #[test]
    fn parsed_mail_survives_restart_without_raw_or_html_payload() {
        let path = temp_store("restart");
        let store = open(&path);
        store
            .store_batch(
                "acct_A1",
                "INBOX",
                7,
                vec![batch(1, "Hello", "Real body")],
                1,
            )
            .unwrap();
        drop(store);

        let reopened = open(&path);
        let page = reopened.list_summaries("acct_A1", None, 20).unwrap();
        assert_eq!(page.summaries.len(), 1);
        assert_eq!(page.summaries[0].subject, "Hello");
        let thread = reopened
            .thread("acct_A1", &page.summaries[0].thread_id, 0, 20)
            .unwrap();
        assert_eq!(thread.messages[0].plain_text, "Real body");
        let bytes = fs::read(&path).unwrap();
        assert!(!bytes.windows(14).any(|value| value == b"Content-Type:"));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn repeated_delivery_is_idempotent_and_cursor_survives_restart() {
        let path = temp_store("idempotent");
        let store = open(&path);
        let first = batch(1, "Hello", "Body");
        let second = first.clone();
        store
            .store_batch("acct_A1", "INBOX", 7, vec![first], 1)
            .unwrap();
        store
            .store_batch("acct_A1", "INBOX", 7, vec![second], 1)
            .unwrap();
        assert_eq!(
            store
                .list_summaries("acct_A1", None, 20)
                .unwrap()
                .summaries
                .len(),
            1
        );
        drop(store);
        assert_eq!(
            open(&path)
                .sync_cursor("acct_A1", "INBOX")
                .unwrap()
                .unwrap()
                .last_uid,
            1
        );
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn uid_validity_change_replaces_only_that_mailbox_generation() {
        let path = temp_store("uidvalidity");
        let store = open(&path);
        store
            .store_batch("acct_A1", "INBOX", 7, vec![batch(1, "Old", "Old")], 1)
            .unwrap();
        let replacement = ingest_message(MailIngestInput {
            account_id: "acct_A1",
            mailbox_id: "INBOX",
            uid_validity: 8,
            uid: 1,
            received_at: RECEIVED,
            unread: false,
            starred: false,
            labels: &["Inbox".to_string()],
            raw_message: b"From: Carol <carol@example.com>\r\nTo: Bob <bob@example.com>\r\nMessage-ID: <replacement@example.com>\r\nDate: Mon, 22 Sep 2026 16:00:00 +0000\r\nSubject: New\r\n\r\nNew",
        }).unwrap();
        store
            .store_batch(
                "acct_A1",
                "INBOX",
                8,
                vec![MailBatchItem {
                    uid: 1,
                    parsed: replacement,
                }],
                1,
            )
            .unwrap();
        let page = store.list_summaries("acct_A1", None, 20).unwrap();
        assert_eq!(page.summaries.len(), 1);
        assert_eq!(page.summaries[0].subject, "New");
        assert_eq!(
            store
                .sync_cursor("acct_A1", "INBOX")
                .unwrap()
                .unwrap()
                .uid_validity,
            8
        );
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn account_removal_clears_messages_threads_and_cursors() {
        let path = temp_store("remove");
        let store = open(&path);
        store
            .store_batch("acct_A1", "INBOX", 7, vec![batch(1, "Hello", "Body")], 1)
            .unwrap();
        store.remove_account("acct_A1").unwrap();
        assert!(
            store
                .list_summaries("acct_A1", None, 20)
                .unwrap()
                .summaries
                .is_empty()
        );
        assert!(store.sync_cursor("acct_A1", "INBOX").unwrap().is_none());
        drop(store);
        assert!(
            open(&path)
                .list_summaries("acct_A1", None, 20)
                .unwrap()
                .summaries
                .is_empty()
        );
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn replaced_linked_or_cross_profile_store_fails_closed() {
        let path = temp_store("identity");
        let store = open(&path);
        let alias = path.with_file_name("mail-alias.redb");
        fs::hard_link(&path, &alias).unwrap();
        assert!(matches!(
            store.list_summaries("acct_A1", None, 20),
            Err(MailStoreError::Corrupt(_))
        ));
        drop(store);
        fs::remove_file(&alias).unwrap();

        let target = path.with_file_name("mail-target.redb");
        fs::rename(&path, &target).unwrap();
        symlink(&target, &path).unwrap();
        assert!(matches!(
            MailStore::open(&path, "profile_alice", rustix::process::getuid().as_raw()),
            Err(MailStoreError::Corrupt(_))
        ));
        fs::remove_file(&path).unwrap();
        fs::rename(&target, &path).unwrap();
        assert!(matches!(
            MailStore::open(&path, "profile_bob", rustix::process::getuid().as_raw()),
            Err(MailStoreError::ProfileMismatch)
        ));
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn summary_pagination_is_stable_and_account_bound() {
        let path = temp_store("page");
        let store = open(&path);
        store
            .store_batch(
                "acct_A1",
                "INBOX",
                7,
                vec![batch(1, "One", "1"), batch(2, "Two", "2")],
                2,
            )
            .unwrap();
        let first = store.list_summaries("acct_A1", None, 1).unwrap();
        assert_eq!(first.summaries.len(), 1);
        let cursor = first.next_before.unwrap();
        let second = store.list_summaries("acct_A1", Some(&cursor), 1).unwrap();
        assert_eq!(second.summaries.len(), 1);
        assert_ne!(first.summaries[0].thread_id, second.summaries[0].thread_id);
        assert!(matches!(
            store.list_summaries("acct_B2", Some(&cursor), 1),
            Err(MailStoreError::Invalid(_))
        ));
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}
