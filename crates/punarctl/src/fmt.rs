//! The single Plate D-014 formatter (docs/design/mockups/cli-grammar.html).
//!
//! No command formats itself: every human view is composed from the four
//! grammar idioms drawn on the plate — tracked masthead + U+2500 rule,
//! middle-dot separators, aligned label/value/description columns, and a
//! verdict/note register. ANSI color is spent only on status words, mapped
//! to the terminal semantic slots (green ok / amber warn / red bad); labels
//! and notes sit in bright-black, exactly the plate's muted register.
//!
//! A terminal has no `letter-spacing`, so the plate's tracked uppercase
//! masthead is rendered as spaced capitals (`P U N A R · S T A T U S`).
//! Row labels stay plain uppercase — tracking them would destroy the
//! columns that make output greppable.
//!
//! Color is dropped whenever stdout is not a TTY or `NO_COLOR` is set
//! (non-empty), so pipes and scripts always see clean columns.

use std::env;
use std::io::IsTerminal;

/// Fixed masthead width in columns. Deterministic output (snapshot tests,
/// CI logs) beats adapting to the terminal here; 72 keeps the rule visible
/// on an 80-column terminal.
pub const WIDTH: usize = 72;

/// Semantic color slots per the design language section 6 / SPEC section 52
/// mapping: lime for allowed/compliant/ready, peach for pending, red for
/// denied/unknown. `Neutral` is deliberate calm — `DEVICE · PERSONAL` is
/// never colored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    Ok,
    Warn,
    Bad,
    Neutral,
}

/// Whether ANSI escapes are emitted. One instance is detected in `main` and
/// threaded through every renderer.
#[derive(Debug, Clone, Copy)]
pub struct Style {
    pub color: bool,
}

impl Style {
    /// Color only when stdout is a TTY and `NO_COLOR` is unset or empty
    /// (no-color.org convention).
    pub fn detect() -> Self {
        let no_color = env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        Style {
            color: std::io::stdout().is_terminal() && !no_color,
        }
    }

    /// A style that never emits ANSI (tests, non-human sinks).
    #[cfg(test)]
    pub const fn plain() -> Self {
        Style { color: false }
    }

    fn paint(&self, sgr: &str, text: &str) -> String {
        if self.color && !text.is_empty() {
            format!("\x1b[{sgr}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    /// Color `text` by semantic slot. Only status words go through this.
    pub fn slot(&self, slot: Slot, text: &str) -> String {
        match slot {
            Slot::Ok => self.paint("32", text),
            Slot::Warn => self.paint("33", text),
            Slot::Bad => self.paint("31", text),
            Slot::Neutral => text.to_string(),
        }
    }

    /// Bright-black: the plate's muted register (labels, notes, context).
    pub fn muted(&self, text: &str) -> String {
        self.paint("90", text)
    }

    /// Bold default foreground (masthead left side).
    pub fn strong(&self, text: &str) -> String {
        self.paint("1", text)
    }

    fn slot_strong(&self, slot: Slot, text: &str) -> String {
        match slot {
            Slot::Ok => self.paint("1;32", text),
            Slot::Warn => self.paint("1;33", text),
            Slot::Bad => self.paint("1;31", text),
            Slot::Neutral => self.paint("1", text),
        }
    }
}

/// Uppercase `text` and space out every character — the terminal spelling
/// of the plate's tracked masthead type.
pub fn tracked(text: &str) -> String {
    let upper = text.to_uppercase();
    let mut out = String::with_capacity(upper.len() * 2);
    for (i, c) in upper.chars().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// Masthead: `PUNAR · <VERB>` tracked on the left, uppercased context on
/// the right edge, closed by a heavy rule of U+2500 (the plate names the
/// codepoint explicitly).
pub fn masthead(style: &Style, verb: &str, context: &str) -> String {
    let left = tracked(&format!("Punar · {verb}"));
    let right = context.to_uppercase();
    let used = left.chars().count() + right.chars().count();
    let gap = if used + 2 > WIDTH { 2 } else { WIDTH - used };
    format!(
        "{}{}{}\n{}\n",
        style.strong(&left),
        " ".repeat(gap),
        style.muted(&right),
        "─".repeat(WIDTH),
    )
}

/// One label/value/description row. Labels render tracked-uppercase-free
/// (plain uppercase, muted); values render uppercase in their slot color;
/// descriptions stay as written.
pub struct Row {
    label: String,
    value: String,
    slot: Slot,
    desc: String,
}

impl Row {
    pub fn new(label: &str, value: &str, slot: Slot, desc: &str) -> Self {
        Row {
            label: label.to_string(),
            value: value.to_string(),
            slot,
            desc: desc.to_string(),
        }
    }
}

/// Render rows with columns aligned across the whole view: label column
/// sized to the longest label (min 12) + 2, value column to the longest
/// value (min 8) + 3. Reading straight down a column tells the story —
/// the D-005 rule, kept in monospace.
pub fn rows(style: &Style, rows: &[Row]) -> String {
    let label_w = rows
        .iter()
        .map(|r| r.label.chars().count())
        .max()
        .unwrap_or(0)
        .max(12)
        + 2;
    let widest_value = rows
        .iter()
        .map(|r| r.value.chars().count())
        .max()
        .unwrap_or(0);
    let value_w = if widest_value == 0 {
        0
    } else {
        widest_value.max(8) + 3
    };

    let mut out = String::new();
    for row in rows {
        let label = row.label.to_uppercase();
        let value = row.value.to_uppercase();
        let mut line = String::new();
        line.push_str(&style.muted(&label));
        line.push_str(&" ".repeat(label_w - label.chars().count()));
        if value_w > 0 {
            line.push_str(&style.slot(row.slot, &value));
            line.push_str(&" ".repeat(value_w - value.chars().count()));
        }
        line.push_str(&row.desc);
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// Section header: a muted uppercase label on the left with its question
/// or citation right-aligned at [`WIDTH`] — the plate's `tsec` idiom
/// (`Authority · what it may access` … `policy · personal defaults`).
/// Used where a view stacks two registers that must never be confused
/// (SPEC section 21: what it *may* access vs. what it *did*).
pub fn section(style: &Style, left: &str, right: &str) -> String {
    let left = left.to_uppercase();
    let right = right.to_uppercase();
    let used = left.chars().count() + right.chars().count();
    let gap = if used + 2 > WIDTH { 2 } else { WIDTH - used };
    format!(
        "{}{}{}\n",
        style.muted(&left),
        " ".repeat(gap),
        style.muted(&right)
    )
}

/// Closing note: uppercase, muted — the plate's `tnote` idiom.
pub fn note(style: &Style, text: &str) -> String {
    format!("{}\n", style.muted(&text.to_uppercase()))
}

/// Verdict line: uppercase, bold, colored by slot — the plate's `verdict`
/// idiom (`✓ APPROVED · … · AUDIT EVT_501`).
pub fn verdict(style: &Style, slot: Slot, text: &str) -> String {
    format!("{}\n", style.slot_strong(slot, &text.to_uppercase()))
}

/// Human spelling of an RFC 3339 timestamp: `2026-08-25T07:00:12Z` →
/// `2026-08-25 07:00:12`. Anything unexpected passes through untouched —
/// the formatter never invents data.
pub fn timestamp(ts: &str) -> String {
    let bytes = ts.as_bytes();
    if ts.is_ascii() && bytes.len() >= 20 && bytes[10] == b'T' {
        format!("{} {}", &ts[..10], &ts[11..19])
    } else {
        ts.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracked_spaces_capitals() {
        assert_eq!(tracked("Punar"), "P U N A R");
        assert_eq!(tracked("Punar · Status"), "P U N A R   ·   S T A T U S");
    }

    #[test]
    fn masthead_is_width_columns_with_right_aligned_context() {
        let style = Style::plain();
        let out = masthead(&style, "Status", "punar-m3 · Personal");
        let mut lines = out.lines();
        let head = lines.next().unwrap();
        assert_eq!(head.chars().count(), WIDTH);
        assert!(head.starts_with("P U N A R   ·   S T A T U S"));
        assert!(head.ends_with("PUNAR-M3 · PERSONAL"));
        let rule = lines.next().unwrap();
        assert_eq!(rule.chars().count(), WIDTH);
        assert!(rule.chars().all(|c| c == '─'));
    }

    #[test]
    fn masthead_never_collides_left_and_right() {
        let style = Style::plain();
        let long = "a-very-long-hostname-that-overflows-everything · Personal";
        let out = masthead(&style, "Capabilities", long);
        let head = out.lines().next().unwrap();
        assert!(head.contains("  ")); // minimum two-space gap survives
    }

    #[test]
    fn rows_align_columns_and_uppercase_label_and_value() {
        let style = Style::plain();
        let out = rows(
            &style,
            &[
                Row::new("Device", "Personal", Slot::Neutral, "punar-m3 · dev_1"),
                Row::new("Capabilities", "3 Tracked", Slot::Neutral, "registry local"),
            ],
        );
        assert_eq!(
            out,
            "DEVICE        PERSONAL    punar-m3 · dev_1\n\
             CAPABILITIES  3 TRACKED   registry local\n"
        );
    }

    #[test]
    fn rows_without_descriptions_have_no_trailing_spaces() {
        let style = Style::plain();
        let out = rows(&style, &[Row::new("Risk", "High", Slot::Neutral, "")]);
        assert_eq!(out, "RISK          HIGH\n");
    }

    #[test]
    fn section_headers_right_align_their_citation() {
        let style = Style::plain();
        let out = section(
            &style,
            "Authority · what it may access",
            "policy · personal defaults",
        );
        let line = out.lines().next().unwrap();
        assert_eq!(line.chars().count(), WIDTH);
        assert!(line.starts_with("AUTHORITY · WHAT IT MAY ACCESS"));
        assert!(line.ends_with("POLICY · PERSONAL DEFAULTS"));
    }

    #[test]
    fn plain_style_emits_no_ansi() {
        let style = Style::plain();
        let everything = format!(
            "{}{}{}{}{}",
            masthead(&style, "Status", "h · Personal"),
            section(&style, "Authority", "policy"),
            rows(&style, &[Row::new("A", "Ok", Slot::Ok, "d")]),
            note(&style, "note"),
            verdict(&style, Slot::Bad, "denied"),
        );
        assert!(!everything.contains('\x1b'));
    }

    #[test]
    fn color_style_paints_only_the_status_word_in_a_row() {
        let style = Style { color: true };
        let out = rows(
            &style,
            &[Row::new("Firewall", "Enabled", Slot::Ok, "inbound deny")],
        );
        assert!(out.contains("\x1b[32mENABLED\x1b[0m"));
        assert!(out.contains("\x1b[90mFIREWALL\x1b[0m"));
        assert!(!out.contains("\x1b[32mINBOUND"));
        assert!(out.contains("inbound deny"));
    }

    #[test]
    fn neutral_slot_is_never_colored() {
        let style = Style { color: true };
        assert_eq!(style.slot(Slot::Neutral, "PERSONAL"), "PERSONAL");
    }

    #[test]
    fn timestamp_humanizes_rfc3339_and_passes_junk_through() {
        assert_eq!(timestamp("2026-08-25T07:00:12Z"), "2026-08-25 07:00:12");
        assert_eq!(timestamp("not a time"), "not a time");
        assert_eq!(timestamp(""), "");
    }
}
