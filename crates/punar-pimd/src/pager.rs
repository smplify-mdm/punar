//! Stable, bounded in-memory snapshots for list pagination.
//!
//! A signed cursor alone cannot preserve a list while records change between
//! pages. This cache retains the exact provider-neutral values selected for a
//! first page, under strict per-snapshot, total-memory, count and lifetime
//! bounds. A process restart or eviction maps to `cursor_expired`; the caller
//! refreshes instead of receiving a mixed snapshot.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{CursorPosition, CursorSigner, PimMethod};

const MAX_PAGE_ITEMS: usize = 100;
const MAX_ACTIVE_SNAPSHOTS: usize = 16;
const MAX_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
const MAX_CACHE_BYTES: usize = 32 * 1024 * 1024;
const SNAPSHOT_TTL: Duration = Duration::from_secs(5 * 60);
const CHANGE_CURSOR_BINDING: &[u8] = b"pim-change-stream:v1";

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PageError {
    #[error("PIM page limit is invalid")]
    InvalidLimit,
    #[error("PIM page cursor is invalid")]
    InvalidCursor,
    #[error("PIM page cursor has expired")]
    CursorExpired,
    #[error("PIM query snapshot exceeds its private memory budget")]
    SnapshotTooLarge,
    #[error("PIM query snapshot could not be encoded")]
    Encode,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PagedValues {
    pub items: Vec<Value>,
    pub next_cursor: Option<String>,
    pub snapshot_cursor: String,
}

pub struct SnapshotPager {
    signer: CursorSigner,
    cache: Mutex<Cache>,
}

#[derive(Default)]
struct Cache {
    snapshots: HashMap<CacheKey, CachedSnapshot>,
    bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    method: PimMethod,
    binding: [u8; 32],
    snapshot: u64,
}

struct CachedSnapshot {
    items: Vec<Value>,
    encoded_bytes: usize,
    last_used: Instant,
}

impl SnapshotPager {
    #[must_use]
    pub fn new(signer: CursorSigner) -> Self {
        Self {
            signer,
            cache: Mutex::new(Cache::default()),
        }
    }

    /// Capture and return the first page from one consistent store snapshot.
    /// The cache is populated only when another page exists.
    pub fn start<T: Serialize>(
        &self,
        method: PimMethod,
        filter_binding: &[u8],
        snapshot: u64,
        items: &[T],
        limit: usize,
    ) -> Result<PagedValues, PageError> {
        self.start_at(
            method,
            filter_binding,
            snapshot,
            items,
            limit,
            Instant::now(),
        )
    }

    /// Continue an existing stable snapshot. Missing state is an expiry, never
    /// an instruction to page through the latest mutable store contents.
    pub fn next(
        &self,
        method: PimMethod,
        filter_binding: &[u8],
        cursor: &str,
        limit: usize,
    ) -> Result<PagedValues, PageError> {
        self.next_at(method, filter_binding, cursor, limit, Instant::now())
    }

    fn start_at<T: Serialize>(
        &self,
        method: PimMethod,
        filter_binding: &[u8],
        snapshot: u64,
        items: &[T],
        limit: usize,
        now: Instant,
    ) -> Result<PagedValues, PageError> {
        validate_limit(limit)?;
        let values = items
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| PageError::Encode)?;
        let snapshot_cursor = self.change_cursor(snapshot)?;
        let next_cursor = (values.len() > limit)
            .then(|| self.page_cursor(method, filter_binding, snapshot, limit))
            .transpose()?;
        let first = values.iter().take(limit).cloned().collect();

        if next_cursor.is_some() {
            let encoded_bytes = encoded_size(&values)?;
            if encoded_bytes > MAX_SNAPSHOT_BYTES {
                return Err(PageError::SnapshotTooLarge);
            }
            let key = cache_key(method, filter_binding, snapshot);
            let mut cache = self.cache.lock().unwrap();
            cache.purge_expired(now);
            cache.make_room(encoded_bytes);
            cache.insert(
                key,
                CachedSnapshot {
                    items: values,
                    encoded_bytes,
                    last_used: now,
                },
            );
        }

        Ok(PagedValues {
            items: first,
            next_cursor,
            snapshot_cursor,
        })
    }

    fn next_at(
        &self,
        method: PimMethod,
        filter_binding: &[u8],
        cursor: &str,
        limit: usize,
        now: Instant,
    ) -> Result<PagedValues, PageError> {
        validate_limit(limit)?;
        let position = self
            .signer
            .open(cursor, method, filter_binding)
            .map_err(|_| PageError::InvalidCursor)?;
        let start = usize::try_from(position.position).map_err(|_| PageError::InvalidCursor)?;
        let key = cache_key(method, filter_binding, position.snapshot);
        let mut cache = self.cache.lock().unwrap();
        cache.purge_expired(now);
        let cached = cache
            .snapshots
            .get_mut(&key)
            .ok_or(PageError::CursorExpired)?;
        if start >= cached.items.len() {
            return Err(PageError::InvalidCursor);
        }
        let end = start.saturating_add(limit).min(cached.items.len());
        let items = cached.items[start..end].to_vec();
        cached.last_used = now;
        let next_cursor = (end < cached.items.len())
            .then(|| self.page_cursor(method, filter_binding, position.snapshot, end))
            .transpose()?;
        Ok(PagedValues {
            items,
            next_cursor,
            snapshot_cursor: self.change_cursor(position.snapshot)?,
        })
    }

    fn page_cursor(
        &self,
        method: PimMethod,
        filter_binding: &[u8],
        snapshot: u64,
        position: usize,
    ) -> Result<String, PageError> {
        self.signer
            .seal(
                method,
                filter_binding,
                CursorPosition {
                    snapshot,
                    position: u64::try_from(position).map_err(|_| PageError::InvalidCursor)?,
                },
            )
            .map_err(|_| PageError::Encode)
    }

    fn change_cursor(&self, snapshot: u64) -> Result<String, PageError> {
        self.signer
            .seal(
                PimMethod::ChangesSince,
                CHANGE_CURSOR_BINDING,
                CursorPosition {
                    snapshot,
                    position: snapshot,
                },
            )
            .map_err(|_| PageError::Encode)
    }
}

impl Cache {
    fn purge_expired(&mut self, now: Instant) {
        let expired: Vec<_> = self
            .snapshots
            .iter()
            .filter(|(_, snapshot)| {
                now.checked_duration_since(snapshot.last_used)
                    .is_some_and(|age| age >= SNAPSHOT_TTL)
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            self.remove(&key);
        }
    }

    fn make_room(&mut self, incoming: usize) {
        while self.snapshots.len() >= MAX_ACTIVE_SNAPSHOTS
            || self.bytes.saturating_add(incoming) > MAX_CACHE_BYTES
        {
            let Some(oldest) = self
                .snapshots
                .iter()
                .min_by_key(|(_, snapshot)| snapshot.last_used)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.remove(&oldest);
        }
    }

    fn insert(&mut self, key: CacheKey, snapshot: CachedSnapshot) {
        self.remove(&key);
        self.bytes = self.bytes.saturating_add(snapshot.encoded_bytes);
        self.snapshots.insert(key, snapshot);
    }

    fn remove(&mut self, key: &CacheKey) {
        if let Some(removed) = self.snapshots.remove(key) {
            self.bytes = self.bytes.saturating_sub(removed.encoded_bytes);
        }
    }
}

fn validate_limit(limit: usize) -> Result<(), PageError> {
    if !(1..=MAX_PAGE_ITEMS).contains(&limit) {
        return Err(PageError::InvalidLimit);
    }
    Ok(())
}

fn cache_key(method: PimMethod, filter_binding: &[u8], snapshot: u64) -> CacheKey {
    CacheKey {
        method,
        binding: Sha256::digest(filter_binding).into(),
        snapshot,
    }
}

fn encoded_size(items: &[Value]) -> Result<usize, PageError> {
    serde_json::to_vec(items)
        .map(|bytes| bytes.len())
        .map_err(|_| PageError::Encode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pager() -> SnapshotPager {
        SnapshotPager::new(CursorSigner::from_key([7; 32], "profile_A1").unwrap())
    }

    #[test]
    fn later_pages_keep_the_original_values_after_the_source_changes() {
        let pager = pager();
        let mut source = vec![json!({"id":1}), json!({"id":2}), json!({"id":3})];
        let first = pager
            .start(PimMethod::MailList, b"inbox:newest", 9, &source, 1)
            .unwrap();
        source[1] = json!({"id":200});
        source.push(json!({"id":4}));

        let second = pager
            .next(
                PimMethod::MailList,
                b"inbox:newest",
                first.next_cursor.as_deref().unwrap(),
                1,
            )
            .unwrap();
        assert_eq!(second.items, vec![json!({"id":2})]);
        let third = pager
            .next(
                PimMethod::MailList,
                b"inbox:newest",
                second.next_cursor.as_deref().unwrap(),
                10,
            )
            .unwrap();
        assert_eq!(third.items, vec![json!({"id":3})]);
        assert!(third.next_cursor.is_none());
        assert_eq!(third.snapshot_cursor, first.snapshot_cursor);
    }

    #[test]
    fn cursor_cannot_cross_method_or_filter() {
        let pager = pager();
        let first = pager
            .start(PimMethod::CalendarList, b"all", 4, &[1, 2], 1)
            .unwrap();
        let cursor = first.next_cursor.as_deref().unwrap();
        assert_eq!(
            pager.next(PimMethod::ReminderListsList, b"all", cursor, 1),
            Err(PageError::InvalidCursor)
        );
        assert_eq!(
            pager.next(PimMethod::CalendarList, b"other", cursor, 1),
            Err(PageError::InvalidCursor)
        );
    }

    #[test]
    fn missing_or_expired_snapshot_never_falls_through_to_live_data() {
        let pager = pager();
        let now = Instant::now();
        let first = pager
            .start_at(PimMethod::EventsList, b"week", 11, &[1, 2], 1, now)
            .unwrap();
        let cursor = first.next_cursor.as_deref().unwrap();
        assert_eq!(
            pager.next_at(
                PimMethod::EventsList,
                b"week",
                cursor,
                1,
                now + SNAPSHOT_TTL,
            ),
            Err(PageError::CursorExpired)
        );
    }

    #[test]
    fn cache_count_is_bounded_and_evicts_the_oldest_snapshot() {
        let pager = pager();
        let now = Instant::now();
        let mut oldest = None;
        for snapshot in 1..=MAX_ACTIVE_SNAPSHOTS + 1 {
            let page = pager
                .start_at(
                    PimMethod::RemindersList,
                    format!("filter-{snapshot}").as_bytes(),
                    snapshot as u64,
                    &[1, 2],
                    1,
                    now + Duration::from_millis(snapshot as u64),
                )
                .unwrap();
            if snapshot == 1 {
                oldest = page.next_cursor;
            }
        }
        assert_eq!(
            pager.cache.lock().unwrap().snapshots.len(),
            MAX_ACTIVE_SNAPSHOTS
        );
        assert_eq!(
            pager.next(
                PimMethod::RemindersList,
                b"filter-1",
                oldest.as_deref().unwrap(),
                1,
            ),
            Err(PageError::CursorExpired)
        );
    }

    #[test]
    fn single_page_needs_no_cache_and_limits_are_closed() {
        let pager = pager();
        let page = pager
            .start(PimMethod::CalendarList, b"all", 1, &[1], 1)
            .unwrap();
        assert!(page.next_cursor.is_none());
        assert!(pager.cache.lock().unwrap().snapshots.is_empty());
        assert_eq!(
            pager.start(PimMethod::CalendarList, b"all", 1, &[1], 0),
            Err(PageError::InvalidLimit)
        );
    }
}
