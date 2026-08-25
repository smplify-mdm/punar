//! The local remote-query log — `/var/lib/punar/agents/queries.jsonl`
//! (`docs/development/milestone-10.md` §10.1, SPEC 51.1, 24.2).
//!
//! One line per administrator query **answered or refused**, written by the
//! daemon that decided it. The record carries the six SPEC 51.1 fields plus
//! the granted scope and the honesty flag on the admin identity; it carries
//! **no payload**, because one exported copy of a user's data is enough to
//! protect and the content is reproducible from the ledger plus the recorded
//! scope.
//!
//! Two boundaries live here and nowhere else:
//!
//! - **The user may read it.** `queries.list` is served to any peer the
//!   socket admitted (SPEC 24.2 — the employee never has less visibility
//!   than the administrator). The *file* stays `0600 root` because the
//!   daemon is the only writer; the socket is the read path.
//! - **`punarctl privacy purge` does not delete it.** It is a record of what
//!   the *organization* did, not data about the user's work, and a user
//!   deleting the evidence of a query would delete their own recourse. The
//!   same principle M8 already applies to the audit trail.
//!
//! Retention is bounded by age **and** size — 365 days or 10 000 records,
//! whichever binds first (`punar_common::query`). Longer than any data it
//! describes, on purpose: the record of *who asked about you* should outlive
//! the data they asked about.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use punar_common::query::{QUERY_LOG_MAX_RECORDS, QUERY_LOG_RETENTION_DAYS, QueryRecord};

/// `0600 root` — the daemon is the only writer, and the read path is the
/// socket, not the filesystem.
pub const QUERIES_MODE: u32 = 0o600;

/// The append-only query log and its bounded pruning.
#[derive(Debug, Clone)]
pub struct QueryLog {
    path: PathBuf,
}

impl QueryLog {
    pub fn new(path: impl Into<PathBuf>) -> QueryLog {
        QueryLog { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one decided query, then prune to the retention bounds.
    ///
    /// Single `write_all` of a complete line to an `O_APPEND` descriptor
    /// plus `sync_data` — the `AuditWriter` discipline, for the same
    /// reason: a concurrent reader must never see a torn line, and a
    /// record of an administrative query that evaporates on power loss is
    /// not a record.
    pub fn append(&self, record: &QueryRecord, now: &str) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut line = serde_json::to_string(record).map_err(io::Error::other)?;
        debug_assert!(!line.contains('\n'));
        line.push('\n');
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(QUERIES_MODE);
        }
        let mut file = options.open(&self.path)?;
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(QUERIES_MODE))?;
        }
        file.write_all(line.as_bytes())?;
        file.sync_data()?;
        drop(file);
        self.prune(now)
    }

    /// Every record in file order (oldest first — a log reads downward).
    /// Unparsable lines are skipped, never fatal: a torn write from a
    /// crash must not cost the user the rest of their query log.
    pub fn read_all(&self) -> Vec<QueryRecord> {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return Vec::new();
        };
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| serde_json::from_str::<QueryRecord>(line).ok())
            .collect()
    }

    /// `queries.list`'s filtered view: decided at or after `since`, most
    /// recent `limit` records. The filter runs **daemon-side** so a
    /// scripted consumer and the human renderer cannot disagree about what
    /// `--since` means.
    pub fn list(&self, since: Option<&str>, limit: Option<usize>) -> Vec<QueryRecord> {
        let mut records = self.read_all();
        if let Some(since) = since {
            records.retain(|record| record.answered_at.as_str() >= since);
        }
        if let Some(limit) = limit {
            if records.len() > limit {
                records.drain(..records.len() - limit);
            }
        }
        records
    }

    /// Enforce both bounds. Rewrites only when something actually leaves,
    /// so the steady state of a device nobody queries is zero writes
    /// (spec 6.4).
    fn prune(&self, now: &str) -> io::Result<()> {
        let records = self.read_all();
        let floor = retention_floor(now);
        let mut kept: Vec<&QueryRecord> = records
            .iter()
            .filter(|record| match floor.as_deref() {
                // A clock this daemon cannot parse is never a reason to
                // delete the record of who asked about you.
                None => true,
                Some(floor) => record.answered_at.as_str() >= floor,
            })
            .collect();
        if kept.len() > QUERY_LOG_MAX_RECORDS {
            kept.drain(..kept.len() - QUERY_LOG_MAX_RECORDS);
        }
        if kept.len() == records.len() {
            return Ok(());
        }
        let mut bytes = Vec::new();
        for record in kept {
            let mut line = serde_json::to_string(record).map_err(io::Error::other)?;
            line.push('\n');
            bytes.extend_from_slice(line.as_bytes());
        }
        crate::util::write_atomic_synced(&self.path, &bytes, QUERIES_MODE)
    }
}

/// The oldest `answered_at` a record may carry and still be kept.
///
/// Date arithmetic on the RFC 3339 *date* only, which is all the retention
/// bound needs and avoids a time crate the image does not have. Anything
/// unparsable yields `None`, which keeps every record — a bad clock must
/// never be a reason to delete the record of who asked about you.
fn retention_floor(now: &str) -> Option<String> {
    let date = now.get(..10)?;
    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    let days = civil_to_days(year, month, day) - i64::from(QUERY_LOG_RETENTION_DAYS);
    let (y, m, d) = days_to_civil(days);
    Some(format!("{y:04}-{m:02}-{d:02}"))
}

/// Howard Hinnant's `days_from_civil`, the shape M8's retention math
/// already uses: proleptic Gregorian, no leap seconds, no dependency.
fn civil_to_days(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_to_civil(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::temp_dir;
    use punar_common::query::{
        AuthorizationDecision, QueryScope, REFUSAL_OUT_OF_SCOPE, RecordCounts, ResultCategory,
    };

    fn record(id: &str, answered_at: &str, decision: AuthorizationDecision) -> QueryRecord {
        QueryRecord {
            query_id: id.to_string(),
            received_at: answered_at.to_string(),
            answered_at: answered_at.to_string(),
            requesting_admin: "cio@acme.com".to_string(),
            admin_identity_verified: false,
            organization: "acme.com".to_string(),
            device_id: "dev_test".to_string(),
            requested_scope: "inventory".to_string(),
            granted_scope: matches!(decision, AuthorizationDecision::Allow)
                .then_some(QueryScope::Inventory),
            authorization_decision: decision,
            refusal_reason: matches!(decision, AuthorizationDecision::Deny)
                .then(|| REFUSAL_OUT_OF_SCOPE.to_string()),
            result_category: match decision {
                AuthorizationDecision::Allow => ResultCategory::Answered,
                AuthorizationDecision::Deny => ResultCategory::Refused,
            },
            record_counts: RecordCounts::default(),
            audit_event_id: Some("evt_1".to_string()),
        }
    }

    #[test]
    fn records_append_in_order_and_survive_a_reopen() {
        let dir = temp_dir("querylog");
        let log = QueryLog::new(dir.join("queries.jsonl"));
        log.append(
            &record(
                "qry_1",
                "2026-08-25T14:00:00Z",
                AuthorizationDecision::Allow,
            ),
            "2026-08-25T14:00:00Z",
        )
        .unwrap();
        log.append(
            &record("qry_2", "2026-08-25T14:02:00Z", AuthorizationDecision::Deny),
            "2026-08-25T14:02:00Z",
        )
        .unwrap();

        let reopened = QueryLog::new(dir.join("queries.jsonl"));
        let all = reopened.read_all();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].query_id, "qry_1");
        assert_eq!(all[1].result_category, ResultCategory::Refused);
        // 0600: the daemon is the only writer.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(reopened.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, QUERIES_MODE);
    }

    #[test]
    fn since_and_limit_filter_daemon_side() {
        let dir = temp_dir("querylog");
        let log = QueryLog::new(dir.join("queries.jsonl"));
        for (i, at) in [
            "2026-08-25T10:00:00Z",
            "2026-08-25T12:00:00Z",
            "2026-08-25T14:00:00Z",
        ]
        .iter()
        .enumerate()
        {
            log.append(
                &record(&format!("qry_{i}"), at, AuthorizationDecision::Allow),
                at,
            )
            .unwrap();
        }
        assert_eq!(log.list(Some("2026-08-25T12:00:00Z"), None).len(), 2);
        assert_eq!(log.list(None, Some(1)).len(), 1);
        assert_eq!(log.list(None, Some(1))[0].query_id, "qry_2");
    }

    #[test]
    fn a_record_older_than_the_retention_window_is_pruned_but_a_recent_one_is_not() {
        let dir = temp_dir("querylog");
        let log = QueryLog::new(dir.join("queries.jsonl"));
        log.append(
            &record(
                "qry_old",
                "2024-01-01T00:00:00Z",
                AuthorizationDecision::Allow,
            ),
            "2026-08-25T14:00:00Z",
        )
        .unwrap();
        log.append(
            &record(
                "qry_new",
                "2026-08-25T14:00:00Z",
                AuthorizationDecision::Allow,
            ),
            "2026-08-25T14:00:00Z",
        )
        .unwrap();
        let ids: Vec<String> = log.read_all().into_iter().map(|r| r.query_id).collect();
        assert_eq!(ids, vec!["qry_new".to_string()]);
    }

    #[test]
    fn an_unparsable_clock_keeps_every_record() {
        assert!(retention_floor("not-a-timestamp").is_none());
        let floor = retention_floor("2026-08-25T14:00:00Z").unwrap();
        assert_eq!(floor, "2025-08-25");
    }
}
