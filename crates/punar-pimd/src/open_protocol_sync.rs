//! Bounded initial and incremental IMAP synchronization for the first
//! open-protocol Mail vertical slice.
//!
//! The adapter opens INBOX read-only, fetches at most twenty numerical UIDs in
//! one transaction, requests at most the MIME ingest ceiling plus one byte per
//! message, converts each response through `mail_ingest`, and atomically
//! commits records with the mailbox cursor. Malformed messages are isolated
//! and counted instead of blocking every later delivery.

use std::collections::BTreeSet;
use std::time::Duration;

use async_imap::Client;
use async_imap::types::{Flag, Mailbox};
use futures_util::StreamExt;
use thiserror::Error;
use tokio::runtime::Builder;
use tokio::time::timeout;

use crate::open_protocol_provider::map_imap_login_error;
use crate::{
    CredentialKind, CredentialVault, MailBatchItem, MailIngestInput, MailStore, MailStoreError,
    MailSyncCursor, NetworkOpenProtocolVerifier, OpenProtocolConfig, ProviderCheckError,
    VaultError, ingest_message,
};

const INBOX: &str = "INBOX";
const MAX_SYNC_MESSAGES: u32 = 20;
const MAX_RAW_MESSAGE_BYTES: usize = 32 * 1024 * 1024;
const MAX_FETCH_BYTES: usize = 64 * 1024 * 1024;
const MAX_CUSTOM_LABELS: usize = 60;
const MAX_LABEL_CHARS: usize = 128;

#[derive(Debug, Error)]
pub enum OpenProtocolSyncError {
    #[error("Mail account credential is unavailable")]
    Vault(#[from] VaultError),
    #[error("Mail provider verification failed: {0}")]
    Provider(#[from] ProviderCheckError),
    #[error("Mail provider returned unsupported mailbox state")]
    UnsupportedMailbox,
    #[error("Mail provider returned malformed synchronization data")]
    MalformedRemoteData,
    #[error("Mail store update failed: {0}")]
    Store(#[from] MailStoreError),
    #[error("Mail synchronization runtime could not start")]
    Runtime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailSyncReport {
    pub uid_validity: u32,
    pub last_uid: u32,
    pub fetched: usize,
    pub skipped_malformed: usize,
}

pub struct OpenProtocolMailSynchronizer<'a> {
    store: &'a MailStore,
    vault: &'a CredentialVault,
    network: NetworkOpenProtocolVerifier,
}

impl<'a> OpenProtocolMailSynchronizer<'a> {
    #[must_use]
    pub fn new(store: &'a MailStore, vault: &'a CredentialVault) -> Self {
        Self {
            store,
            vault,
            network: NetworkOpenProtocolVerifier::default(),
        }
    }

    #[must_use]
    pub fn with_deadline(
        store: &'a MailStore,
        vault: &'a CredentialVault,
        deadline: Duration,
    ) -> Self {
        Self {
            store,
            vault,
            network: NetworkOpenProtocolVerifier::with_deadline(deadline),
        }
    }

    /// Synchronize one bounded INBOX batch. The decrypted password exists only
    /// for the duration of the service-side callback and async runtime.
    pub fn sync_inbox(
        &self,
        account_id: &str,
        config: &OpenProtocolConfig,
    ) -> Result<MailSyncReport, OpenProtocolSyncError> {
        let previous = self.store.sync_cursor(account_id, INBOX)?;
        self.vault
            .with_secret(account_id, CredentialKind::IncomingPassword, |password| {
                let password = std::str::from_utf8(password)
                    .map_err(|_| ProviderCheckError::InvalidCredentials)?;
                let runtime = Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .map_err(|_| OpenProtocolSyncError::Runtime)?;
                runtime.block_on(self.sync_async(account_id, config, password, previous))
            })?
    }

    async fn sync_async(
        &self,
        account_id: &str,
        config: &OpenProtocolConfig,
        password: &str,
        previous: Option<MailSyncCursor>,
    ) -> Result<MailSyncReport, OpenProtocolSyncError> {
        let deadline = self.network.deadline();
        let (stream, needs_greeting) = self
            .network
            .connect_imap_bounded(&config.imap, MAX_FETCH_BYTES)
            .await?;
        let mut client = Client::new(stream);
        if needs_greeting {
            let greeting = timeout(deadline, client.read_response())
                .await
                .map_err(|_| ProviderCheckError::Unreachable)?
                .map_err(|_| ProviderCheckError::InvalidResponse)?;
            if greeting.is_none() {
                return Err(ProviderCheckError::InvalidResponse.into());
            }
        }
        let login = timeout(deadline, client.login(config.username.as_str(), password))
            .await
            .map_err(|_| ProviderCheckError::Unreachable)?;
        let mut session = login.map_err(|(error, _)| map_imap_login_error(error))?;
        let mailbox = timeout(deadline, session.examine(INBOX))
            .await
            .map_err(|_| ProviderCheckError::Unreachable)?
            .map_err(map_session_error)?;
        let uid_validity = mailbox
            .uid_validity
            .filter(|value| *value > 0)
            .ok_or(OpenProtocolSyncError::UnsupportedMailbox)?;
        let plan = plan_fetch(&mailbox, previous.as_ref())?;
        let mut items = Vec::new();
        let mut skipped = 0_usize;

        if let Some((first_uid, last_uid)) = plan.range {
            let uid_set = format!("{first_uid}:{last_uid}");
            let query = format!(
                "(UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[]<0.{}>)",
                MAX_RAW_MESSAGE_BYTES + 1
            );
            let mut fetches = timeout(deadline, session.uid_fetch(uid_set, query))
                .await
                .map_err(|_| ProviderCheckError::Unreachable)?
                .map_err(map_session_error)?;
            while let Some(response) = timeout(deadline, fetches.next())
                .await
                .map_err(|_| ProviderCheckError::Unreachable)?
            {
                let fetch = response.map_err(map_session_error)?;
                if items.len() >= MAX_SYNC_MESSAGES as usize {
                    return Err(OpenProtocolSyncError::MalformedRemoteData);
                }
                let Some(uid) = fetch.uid else {
                    skipped += 1;
                    continue;
                };
                let Some(received_at) = fetch.internal_date().map(|value| value.to_rfc3339())
                else {
                    skipped += 1;
                    continue;
                };
                let Some(raw_message) = fetch.body() else {
                    skipped += 1;
                    continue;
                };
                if fetch
                    .size
                    .is_some_and(|size| size as usize > MAX_RAW_MESSAGE_BYTES)
                    || raw_message.len() > MAX_RAW_MESSAGE_BYTES
                {
                    skipped += 1;
                    continue;
                }
                let flags = fetch.flags().collect::<Vec<_>>();
                let unread = !flags.iter().any(|flag| matches!(flag, Flag::Seen));
                let starred = flags.iter().any(|flag| matches!(flag, Flag::Flagged));
                let labels = labels_from_flags(&flags);
                match ingest_message(MailIngestInput {
                    account_id,
                    mailbox_id: INBOX,
                    uid_validity,
                    uid,
                    received_at: &received_at,
                    unread,
                    starred,
                    labels: &labels,
                    raw_message,
                }) {
                    Ok(parsed) => items.push(MailBatchItem { uid, parsed }),
                    Err(_) => skipped += 1,
                }
            }
            drop(fetches);
        }
        let _ = timeout(deadline, session.logout()).await;
        let fetched = items.len();
        let cursor =
            self.store
                .store_batch(account_id, INBOX, uid_validity, items, plan.commit_last_uid)?;
        Ok(MailSyncReport {
            uid_validity,
            last_uid: cursor.last_uid,
            fetched,
            skipped_malformed: skipped,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FetchPlan {
    range: Option<(u32, u32)>,
    commit_last_uid: u32,
    expected_count: usize,
}

fn plan_fetch(
    mailbox: &Mailbox,
    previous: Option<&MailSyncCursor>,
) -> Result<FetchPlan, OpenProtocolSyncError> {
    let uid_validity = mailbox
        .uid_validity
        .filter(|value| *value > 0)
        .ok_or(OpenProtocolSyncError::UnsupportedMailbox)?;
    if mailbox.exists == 0 {
        return Ok(FetchPlan {
            range: None,
            commit_last_uid: 0,
            expected_count: 0,
        });
    }
    let server_last = mailbox
        .uid_next
        .and_then(|next| next.checked_sub(1))
        .filter(|value| *value > 0)
        .ok_or(OpenProtocolSyncError::UnsupportedMailbox)?;
    let first = match previous {
        Some(cursor) if cursor.uid_validity == uid_validity => {
            if cursor.last_uid >= server_last {
                return Ok(FetchPlan {
                    range: None,
                    commit_last_uid: cursor.last_uid,
                    expected_count: 0,
                });
            }
            cursor.last_uid.saturating_add(1)
        }
        _ => server_last
            .saturating_sub(MAX_SYNC_MESSAGES.saturating_sub(1))
            .max(1),
    };
    let last = first
        .saturating_add(MAX_SYNC_MESSAGES.saturating_sub(1))
        .min(server_last);
    Ok(FetchPlan {
        range: Some((first, last)),
        commit_last_uid: last,
        expected_count: usize::try_from(last - first + 1).unwrap_or(MAX_SYNC_MESSAGES as usize),
    })
}

fn labels_from_flags(flags: &[Flag<'_>]) -> Vec<String> {
    let mut labels = BTreeSet::from(["Inbox".to_string()]);
    for flag in flags {
        let Flag::Custom(value) = flag else {
            continue;
        };
        let value = value.trim();
        if !value.is_empty()
            && value.chars().count() <= MAX_LABEL_CHARS
            && !value.chars().any(char::is_control)
            && labels.len() < MAX_CUSTOM_LABELS
        {
            labels.insert(value.to_string());
        }
    }
    labels.into_iter().collect()
}

fn map_session_error(error: async_imap::error::Error) -> ProviderCheckError {
    match error {
        async_imap::error::Error::Io(_) | async_imap::error::Error::ConnectionLost => {
            ProviderCheckError::Unreachable
        }
        _ => ProviderCheckError::InvalidResponse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mailbox(exists: u32, uid_validity: Option<u32>, uid_next: Option<u32>) -> Mailbox {
        Mailbox {
            exists,
            uid_validity,
            uid_next,
            ..Mailbox::default()
        }
    }

    #[test]
    fn initial_fetch_is_the_latest_bounded_uid_window() {
        let plan = plan_fetch(&mailbox(200, Some(7), Some(501)), None).unwrap();
        assert_eq!(plan.range, Some((481, 500)));
        assert_eq!(plan.commit_last_uid, 500);
        assert_eq!(plan.expected_count, 20);
    }

    #[test]
    fn incremental_fetch_advances_in_bounded_windows() {
        let cursor = MailSyncCursor {
            account_id: "acct_A1".into(),
            mailbox_id: INBOX.into(),
            uid_validity: 7,
            last_uid: 12,
        };
        let plan = plan_fetch(&mailbox(200, Some(7), Some(101)), Some(&cursor)).unwrap();
        assert_eq!(plan.range, Some((13, 32)));
        assert_eq!(plan.commit_last_uid, 32);
    }

    #[test]
    fn empty_mailbox_and_caught_up_cursor_issue_no_fetch() {
        assert_eq!(
            plan_fetch(&mailbox(0, Some(7), Some(1)), None).unwrap(),
            FetchPlan {
                range: None,
                commit_last_uid: 0,
                expected_count: 0,
            }
        );
        let cursor = MailSyncCursor {
            account_id: "acct_A1".into(),
            mailbox_id: INBOX.into(),
            uid_validity: 7,
            last_uid: 12,
        };
        assert_eq!(
            plan_fetch(&mailbox(12, Some(7), Some(13)), Some(&cursor))
                .unwrap()
                .range,
            None
        );
    }

    #[test]
    fn uid_validity_change_restarts_from_the_latest_window() {
        let cursor = MailSyncCursor {
            account_id: "acct_A1".into(),
            mailbox_id: INBOX.into(),
            uid_validity: 6,
            last_uid: 900,
        };
        let plan = plan_fetch(&mailbox(40, Some(7), Some(41)), Some(&cursor)).unwrap();
        assert_eq!(plan.range, Some((21, 40)));
    }

    #[test]
    fn labels_keep_inbox_and_only_bounded_custom_flags() {
        let long = "x".repeat(MAX_LABEL_CHARS + 1);
        let flags = vec![
            Flag::Seen,
            Flag::Custom("Project".into()),
            Flag::Custom(long.into()),
            Flag::Custom("bad\nflag".into()),
        ];
        assert_eq!(
            labels_from_flags(&flags),
            vec!["Inbox".to_string(), "Project".to_string()]
        );
    }
}
