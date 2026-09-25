//! Bounded conversion from an untrusted RFC 5322/MIME message into Punar's
//! provider-neutral, plain-text-only records.
//!
//! This module never returns the parser's borrowed tree or the raw message.
//! HTML is converted to bounded plain text, remote content remains blocked,
//! attachment payloads are discarded, and only stable metadata crosses into
//! the durable-store layer.

use std::collections::BTreeSet;

use mail_parser::{Address, HeaderValue, MessageParser, MimeHeaders, PartType};
use punar_common::time::is_rfc3339_timestamp;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    Attachment, AttachmentQuarantineState, EmailAddress, MailMessage, MailSummary, MailSummaryKind,
    SyncMetadata,
};

const MAX_RAW_MESSAGE_BYTES: usize = 32 * 1024 * 1024;
const MAX_BODY_CHARS: usize = 262_144;
const MAX_PREVIEW_CHARS: usize = 512;
const MAX_SUBJECT_CHARS: usize = 998;
const MAX_ADDRESS_NAME_CHARS: usize = 256;
const MAX_ADDRESS_BYTES: usize = 320;
const MAX_RECIPIENTS: usize = 500;
const MAX_CORRESPONDENTS: usize = 64;
const MAX_ATTACHMENTS: usize = 128;
const MAX_LABELS: usize = 64;
const MAX_LABEL_CHARS: usize = 128;
const MAX_FILENAME_CHARS: usize = 255;
const MAX_MEDIA_TYPE_CHARS: usize = 255;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MailIngestError {
    #[error("mail input exceeded its fixed size limit")]
    TooLarge,
    #[error("mail input identity is invalid")]
    InvalidIdentity,
    #[error("mail input timestamp is invalid")]
    InvalidTimestamp,
    #[error("mail input labels are invalid")]
    InvalidLabels,
    #[error("mail input could not be parsed")]
    Malformed,
    #[error("mail input has no valid sender")]
    MissingSender,
}

/// Adapter-owned metadata that IMAP supplies independently of the MIME bytes.
/// Credentials and server endpoints are intentionally not representable.
pub struct MailIngestInput<'a> {
    pub account_id: &'a str,
    pub mailbox_id: &'a str,
    pub uid_validity: u32,
    pub uid: u32,
    pub received_at: &'a str,
    pub unread: bool,
    pub starred: bool,
    pub labels: &'a [String],
    pub raw_message: &'a [u8],
}

/// Bounded records plus provider-only threading hints. The wire identifiers
/// are never exposed to applications and contain no credential material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMail {
    pub summary: MailSummary,
    pub message: MailMessage,
    pub wire_message_id: Option<String>,
    pub thread_anchor: Option<String>,
}

pub fn ingest_message(input: MailIngestInput<'_>) -> Result<ParsedMail, MailIngestError> {
    validate_input(&input)?;
    let parsed = MessageParser::default()
        .parse(input.raw_message)
        .ok_or(MailIngestError::Malformed)?;

    let sender = parsed
        .from()
        .and_then(Address::first)
        .and_then(convert_address)
        .ok_or(MailIngestError::MissingSender)?;
    let to = collect_addresses(parsed.to(), MAX_RECIPIENTS);
    let cc = collect_addresses(parsed.cc(), MAX_RECIPIENTS);
    let subject = truncate_chars(parsed.subject().unwrap_or_default(), MAX_SUBJECT_CHARS).0;
    let sent_at = parsed
        .date()
        .map(mail_parser::DateTime::to_rfc3339)
        .filter(|value| is_rfc3339_timestamp(value))
        .unwrap_or_else(|| input.received_at.to_string());

    let wire_message_id = clean_wire_id(parsed.message_id());
    let thread_anchor = first_wire_id(parsed.references())
        .or_else(|| first_wire_id(parsed.in_reply_to()))
        .or_else(|| wire_message_id.clone());
    let message_id = stable_id(
        "message",
        &[
            input.account_id,
            input.mailbox_id,
            &input.uid_validity.to_string(),
            &input.uid.to_string(),
        ],
    );
    let thread_id = stable_id(
        "thread",
        &[
            input.account_id,
            thread_anchor.as_deref().unwrap_or(&message_id),
        ],
    );

    let body = parsed.body_text(0).unwrap_or_default();
    let (plain_text, body_truncated) = truncate_chars(body.as_ref(), MAX_BODY_CHARS);
    let preview = preview(&plain_text);
    let attachment_count = parsed.attachment_count().min(1000) as u32;
    let attachments: Vec<_> = parsed
        .attachments()
        .take(MAX_ATTACHMENTS)
        .enumerate()
        .map(|(index, part)| {
            let filename = part
                .attachment_name()
                .filter(|name| !name.trim().is_empty())
                .map(|name| truncate_chars(name.trim(), MAX_FILENAME_CHARS).0)
                .unwrap_or_else(|| format!("unnamed-attachment-{}", index + 1));
            let media_type = part
                .content_type()
                .map(|content_type| {
                    format!(
                        "{}/{}",
                        content_type.ctype(),
                        content_type.subtype().unwrap_or("octet-stream")
                    )
                })
                .filter(|value| value.len() >= 3)
                .map(|value| truncate_chars(&value, MAX_MEDIA_TYPE_CHARS).0)
                .unwrap_or_else(|| "application/octet-stream".to_string());
            Attachment {
                attachment_id: stable_id("attachment", &[&message_id, &index.to_string()]),
                filename,
                media_type,
                size_bytes: part.contents().len() as u64,
                // Payload bytes are intentionally discarded at this boundary.
                // A later explicit open/download action must fetch and quarantine.
                quarantine_state: AttachmentQuarantineState::NotDownloaded,
            }
        })
        .collect();
    let body_complete = !body_truncated;
    let sync = SyncMetadata::synced(
        input.received_at,
        format!("imap:{}:{}", input.uid_validity, input.uid),
    );
    let labels = normalize_labels(input.labels)?;

    let message = MailMessage {
        message_id,
        sender: sender.clone(),
        to,
        cc,
        sent_at,
        plain_text,
        body_complete,
        remote_content_blocked: parsed
            .html_bodies()
            .any(|part| matches!(&part.body, PartType::Html(_))),
        attachments,
        attachments_complete: parsed.attachment_count() <= MAX_ATTACHMENTS,
        sync: sync.clone(),
    };
    let summary = MailSummary {
        kind: MailSummaryKind::MailSummary,
        thread_id,
        account_id: input.account_id.to_string(),
        subject,
        correspondents: vec![sender].into_iter().take(MAX_CORRESPONDENTS).collect(),
        preview,
        received_at: input.received_at.to_string(),
        unread: input.unread,
        starred: input.starred,
        attachments_count: attachment_count,
        labels,
        sync,
    };

    Ok(ParsedMail {
        summary,
        message,
        wire_message_id,
        thread_anchor,
    })
}

fn validate_input(input: &MailIngestInput<'_>) -> Result<(), MailIngestError> {
    if input.raw_message.is_empty() || input.raw_message.len() > MAX_RAW_MESSAGE_BYTES {
        return Err(MailIngestError::TooLarge);
    }
    if !valid_prefixed_id(input.account_id, "acct_")
        || input.mailbox_id.is_empty()
        || input.mailbox_id.len() > 512
        || input.uid_validity == 0
        || input.uid == 0
    {
        return Err(MailIngestError::InvalidIdentity);
    }
    if !is_rfc3339_timestamp(input.received_at) {
        return Err(MailIngestError::InvalidTimestamp);
    }
    Ok(())
}

fn valid_prefixed_id(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_alphanumeric())
    }) && value.len() <= 80
}

fn collect_addresses(addresses: Option<&Address<'_>>, limit: usize) -> Vec<EmailAddress> {
    addresses
        .into_iter()
        .flat_map(Address::iter)
        .filter_map(convert_address)
        .take(limit)
        .collect()
}

fn convert_address(address: &mail_parser::Addr<'_>) -> Option<EmailAddress> {
    let value = address.address.as_deref()?.trim();
    if value.len() < 3
        || value.len() > MAX_ADDRESS_BYTES
        || value.chars().any(char::is_whitespace)
        || !value
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && !domain.is_empty())
    {
        return None;
    }
    let name = address
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| truncate_chars(name, MAX_ADDRESS_NAME_CHARS).0);
    Some(EmailAddress {
        name,
        address: value.to_string(),
    })
}

fn normalize_labels(labels: &[String]) -> Result<Vec<String>, MailIngestError> {
    if labels.len() > MAX_LABELS {
        return Err(MailIngestError::InvalidLabels);
    }
    let mut unique = BTreeSet::new();
    for label in labels {
        let label = label.trim();
        if label.is_empty() || label.chars().count() > MAX_LABEL_CHARS {
            return Err(MailIngestError::InvalidLabels);
        }
        unique.insert(label.to_string());
    }
    Ok(unique.into_iter().collect())
}

fn first_wire_id(value: &HeaderValue<'_>) -> Option<String> {
    match value {
        HeaderValue::Text(value) => clean_wire_id(Some(value)),
        HeaderValue::TextList(values) => values.iter().find_map(|value| clean_wire_id(Some(value))),
        _ => None,
    }
}

fn clean_wire_id(value: Option<&str>) -> Option<String> {
    let value = value?.trim().trim_matches(['<', '>']).trim();
    if value.is_empty() || value.len() > 998 || value.chars().any(char::is_control) {
        None
    } else {
        Some(value.to_string())
    }
}

fn stable_id(prefix: &str, components: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for component in components {
        hasher.update((component.len() as u64).to_be_bytes());
        hasher.update(component.as_bytes());
    }
    let digest = hasher.finalize();
    let mut suffix = String::with_capacity(32);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest.iter().take(16) {
        suffix.push(HEX[(byte >> 4) as usize] as char);
        suffix.push(HEX[(byte & 0x0f) as usize] as char);
    }
    format!("{prefix}_{suffix}")
}

fn truncate_chars(value: &str, limit: usize) -> (String, bool) {
    let mut chars = value.chars();
    let output: String = chars.by_ref().take(limit).collect();
    (output, chars.next().is_some())
}

fn preview(body: &str) -> String {
    let collapsed = body.split_whitespace().collect::<Vec<_>>().join(" ");
    truncate_chars(&collapsed, MAX_PREVIEW_CHARS).0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(raw_message: &'a [u8], labels: &'a [String]) -> MailIngestInput<'a> {
        MailIngestInput {
            account_id: "acct_A1",
            mailbox_id: "INBOX",
            uid_validity: 7,
            uid: 42,
            received_at: "2026-09-22T19:00:00Z",
            unread: true,
            starred: false,
            labels,
            raw_message,
        }
    }

    #[test]
    fn plain_message_becomes_bounded_schema_shaped_records() {
        let raw = b"From: Alice Example <alice@example.com>\r\n\
To: Bob <bob@example.net>\r\n\
Date: Mon, 22 Sep 2026 14:58:00 -0400\r\n\
Message-ID: <message-42@example.com>\r\n\
Subject: Build report\r\n\
Content-Type: text/plain; charset=utf-8\r\n\r\n\
All checks passed.\r\n";
        let labels = vec!["work".to_string(), "inbox".to_string()];
        let parsed = ingest_message(input(raw, &labels)).unwrap();

        assert_eq!(parsed.summary.subject, "Build report");
        assert_eq!(
            parsed.summary.correspondents[0].address,
            "alice@example.com"
        );
        assert_eq!(parsed.summary.preview, "All checks passed.");
        assert_eq!(parsed.summary.labels, ["inbox", "work"]);
        assert_eq!(parsed.message.plain_text, "All checks passed.\r\n");
        assert!(!parsed.message.remote_content_blocked);
        assert_eq!(
            parsed.wire_message_id.as_deref(),
            Some("message-42@example.com")
        );
        assert!(parsed.summary.thread_id.starts_with("thread_"));
        assert!(parsed.message.message_id.starts_with("message_"));
        assert_eq!(
            serde_json::to_value(&parsed.summary).unwrap()["kind"],
            "mail_summary"
        );
    }

    #[test]
    fn html_is_never_returned_and_remote_content_stays_blocked() {
        let raw = b"From: Sender <sender@example.com>\r\n\
Date: Mon, 22 Sep 2026 19:00:00 +0000\r\n\
Subject: HTML\r\n\
Content-Type: text/html; charset=utf-8\r\n\r\n\
<html><body>Hello <b>there</b><img src=\"https://tracker.invalid/pixel\"></body></html>";
        let parsed = ingest_message(input(raw, &[])).unwrap();
        assert!(parsed.message.remote_content_blocked);
        assert!(!parsed.message.plain_text.contains("<img"));
        assert!(
            !parsed
                .message
                .plain_text
                .contains("https://tracker.invalid")
        );
    }

    #[test]
    fn attachment_payload_is_discarded_and_requires_later_quarantine() {
        let raw = b"From: Sender <sender@example.com>\r\n\
Date: Mon, 22 Sep 2026 19:00:00 +0000\r\n\
Subject: Attachment\r\n\
Content-Type: multipart/mixed; boundary=x\r\n\r\n\
--x\r\nContent-Type: text/plain\r\n\r\nSee file.\r\n\
--x\r\nContent-Type: application/octet-stream; name=payload.bin\r\n\
Content-Disposition: attachment; filename=payload.bin\r\n\
Content-Transfer-Encoding: base64\r\n\r\nU0VDUkVULUJZVEVT\r\n--x--\r\n";
        let parsed = ingest_message(input(raw, &[])).unwrap();
        assert_eq!(parsed.summary.attachments_count, 1);
        assert_eq!(parsed.message.attachments.len(), 1);
        assert_eq!(parsed.message.attachments[0].filename, "payload.bin");
        assert!(parsed.message.attachments_complete);
        assert_eq!(
            parsed.message.attachments[0].quarantine_state,
            AttachmentQuarantineState::NotDownloaded
        );
        let serialized = serde_json::to_vec(&(parsed.summary, parsed.message)).unwrap();
        assert!(
            !serialized
                .windows(12)
                .any(|window| window == b"SECRET-BYTES")
        );
    }

    #[test]
    fn oversized_input_is_refused_before_parsing() {
        let raw = vec![b'x'; MAX_RAW_MESSAGE_BYTES + 1];
        assert_eq!(
            ingest_message(input(&raw, &[])),
            Err(MailIngestError::TooLarge)
        );
    }

    #[test]
    fn missing_or_invalid_sender_is_not_replaced_with_demo_identity() {
        let raw = b"Subject: Missing sender\r\n\r\nBody";
        assert_eq!(
            ingest_message(input(raw, &[])),
            Err(MailIngestError::MissingSender)
        );
    }

    #[test]
    fn long_unicode_body_is_truncated_on_character_boundaries() {
        let body = "\u{1f642}".repeat(MAX_BODY_CHARS + 2);
        let raw = format!(
            "From: sender@example.com\r\nDate: Mon, 22 Sep 2026 19:00:00 +0000\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}"
        );
        let parsed = ingest_message(input(raw.as_bytes(), &[])).unwrap();
        assert_eq!(parsed.message.plain_text.chars().count(), MAX_BODY_CHARS);
        assert!(!parsed.message.body_complete);
    }
}
