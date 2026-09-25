//! `punarctl theme` and `punarctl wallpaper` (docs/design/theme-system.md
//! §4.5, docs/design/wallpapers.md).
//!
//! **Theme: client-side, and the gate is the shell's gate.** The validator
//! is a port of `shell/punar-shell/Theme/ThemeContrast.qml`, which the spec
//! makes the contract: the §4.1 arithmetic at f64 precision, rounding only
//! for display and comparing the rounded value against the floor (so 4.497
//! fails 4.5); the 24 pairs of §4.2 in the same order; R1-R9 with the same
//! constants; and the §7.1 terminal derivation R8 measures. The unit tests
//! hold it to every figure §5.3, §5.4 and §7.1 publish for the shipped set.
//!
//! `theme set` writes the §3.3 pointer the shell watches, with the complete
//! receipt (the shell cannot compute its SHA-256 digest), then asks a running
//! shell to reload it. A refusal writes nothing and exits 6, deliberately
//! not 3: a contrast floor is not an authorization decision. No organization
//! pin exists yet (§8 is dashed), so none is read and none is shown.
//!
//! **Wallpaper: the shell's own catalog.** The catalog is compiled into the
//! shell (Services/WallpaperState.qml), so `punarctl wallpaper` asks the
//! shell over its IPC rather than keeping a second copy that could drift.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use clap::Subcommand;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::fmt::{self, Row, Slot, Style};

/// A theme refused for its contrast or shape (§4.5).
pub const EXIT_REFUSED: u8 = 6;

const INSTALLED_THEMES: &str = "/usr/share/punar/theme/themes";
const SITE_THEMES: &str = "/etc/punar/themes";
const SYSTEM_POINTER: &str = "/etc/punar/theme.json";
const INSTALLED_TOKENS: &str = "/usr/share/punar/theme/punar-tokens.json";
/// The grammar punarctl was built with: the shell's own tokens file.
const BUILT_TOKENS: &str = include_str!("../../../shell/theme/punar-tokens.json");
const MAX_DOC_BYTES: u64 = 64 * 1024;

#[derive(Subcommand)]
pub enum ThemeCommand {
    /// Every installed theme, whether it passes the contract, and which is
    /// active.
    List,
    /// One theme: its palette, all 24 measured pairs, and the derived
    /// terminal palette.
    Show { id: String },
    /// Run R1-R9 on an installed theme id or a theme file. Exit 6 on failure.
    Validate { target: String },
    /// Select a theme: validate, then record it as your preference.
    Set {
        id: String,
        /// Force a mood instead of the theme's own default.
        #[arg(long, value_parser = ["paper", "panel"])]
        mood: Option<String>,
    },
    /// Drop your preference; the system or shipped default applies.
    Reset,
    /// The active theme, its mood, where that decision came from, and
    /// whether its file changed since it was validated.
    Status,
    /// Print (or write with --out) an artefact derived from a theme.
    Render {
        id: String,
        #[arg(long, value_parser = ["foot", "hypr", "wallpaper", "portal"])]
        target: String,
        #[arg(long, value_parser = ["paper", "panel"])]
        mood: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum WallpaperCommand {
    /// The installed wallpapers and which one is active.
    List,
    /// Select a wallpaper by id.
    Set { id: String },
    /// Drop your preference; the shipped default applies.
    Reset,
    /// The active wallpaper and where that choice came from.
    Status,
}

// ---------------------------------------------------------------------------
// §4.1 arithmetic
// ---------------------------------------------------------------------------

fn is_hex(value: &str) -> bool {
    value.len() == 7
        && value.starts_with('#')
        && value[1..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}

fn channels(hex: &str) -> Option<[f64; 3]> {
    if !is_hex(hex) {
        return None;
    }
    let part = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).ok().map(f64::from);
    Some([part(1)?, part(3)?, part(5)?])
}

fn linearize(channel: f64) -> f64 {
    let c = channel / 255.0;
    if c <= 0.04045 {
        c / 12.92
    } else {
        ((c + 0.055) / 1.055).powf(2.4)
    }
}

fn luminance(hex: &str) -> f64 {
    match channels(hex) {
        Some([r, g, b]) => 0.2126 * linearize(r) + 0.7152 * linearize(g) + 0.0722 * linearize(b),
        None => -1.0,
    }
}

/// Full precision; -1 when either side is not a colour, so a malformed value
/// can never read as infinite contrast.
fn contrast(a: &str, b: &str) -> f64 {
    let (la, lb) = (luminance(a), luminance(b));
    if la < 0.0 || lb < 0.0 {
        return -1.0;
    }
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

/// The one rounding, for display.
fn rounded(ratio: f64) -> f64 {
    (ratio * 100.0).round() / 100.0
}

/// The one comparison, at full precision (§4.1): a pair measuring 4.497
/// fails a 4.5 floor even though it prints as 4.50. Rounding is for display
/// only and never passes a pair.
fn meets(ratio: f64, floor: f64) -> bool {
    ratio >= 0.0 && ratio >= floor
}

fn one_decimal(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

fn hue(hex: &str) -> f64 {
    let Some([r, g, b]) = channels(hex) else {
        return -1.0;
    };
    let (r, g, b) = (r / 255.0, g / 255.0, b / 255.0);
    let (mx, mn) = (r.max(g).max(b), r.min(g).min(b));
    let d = mx - mn;
    if d == 0.0 {
        return 0.0;
    }
    let h = if mx == r {
        ((g - b) / d) % 6.0
    } else if mx == g {
        (b - r) / d + 2.0
    } else {
        (r - g) / d + 4.0
    } * 60.0;
    if h < 0.0 { h + 360.0 } else { h }
}

fn saturation(hex: &str) -> f64 {
    let Some([r, g, b]) = channels(hex) else {
        return -1.0;
    };
    let (r, g, b) = (r / 255.0, g / 255.0, b / 255.0);
    let (mx, mn) = (r.max(g).max(b), r.min(g).min(b));
    let d = mx - mn;
    if d == 0.0 {
        return 0.0;
    }
    let l = (mx + mn) / 2.0;
    if l > 0.5 {
        d / (2.0 - mx - mn)
    } else {
        d / (mx + mn)
    }
}

const WHITE: [f64; 3] = [0.95047, 1.0, 1.08883];

fn lab(hex: &str) -> Option<[f64; 3]> {
    let [r, g, b] = channels(hex)?;
    let (r, g, b) = (linearize(r), linearize(g), linearize(b));
    let x = (0.4124564 * r + 0.3575761 * g + 0.1804375 * b) / WHITE[0];
    let y = (0.2126729 * r + 0.7151522 * g + 0.0721750 * b) / WHITE[1];
    let z = (0.0193339 * r + 0.1191920 * g + 0.9503041 * b) / WHITE[2];
    let f = |t: f64| {
        if t > 216.0 / 24389.0 {
            t.cbrt()
        } else {
            (841.0 / 108.0) * t + 4.0 / 29.0
        }
    };
    let (fx, fy, fz) = (f(x), f(y), f(z));
    Some([116.0 * fy - 16.0, 500.0 * (fx - fy), 200.0 * (fy - fz)])
}

fn delta_e(a: &str, b: &str) -> f64 {
    match (lab(a), lab(b)) {
        (Some(la), Some(lb)) => {
            ((la[0] - lb[0]).powi(2) + (la[1] - lb[1]).powi(2) + (la[2] - lb[2]).powi(2)).sqrt()
        }
        _ => -1.0,
    }
}

fn chroma(hex: &str) -> f64 {
    lab(hex).map_or(-1.0, |l| (l[1] * l[1] + l[2] * l[2]).sqrt())
}

fn to_hex(r: f64, g: f64, b: f64) -> String {
    let pair = |v: f64| v.round().clamp(0.0, 255.0) as u8;
    format!("#{:02X}{:02X}{:02X}", pair(r), pair(g), pair(b))
}

fn lab_to_hex(l_star: f64, a_star: f64, b_star: f64) -> String {
    let fy = (l_star + 16.0) / 116.0;
    let fx = fy + a_star / 500.0;
    let fz = fy - b_star / 200.0;
    let g = |t: f64| {
        let t3 = t * t * t;
        if t3 > 216.0 / 24389.0 {
            t3
        } else {
            (108.0 / 841.0) * (t - 4.0 / 29.0)
        }
    };
    let (x, y, z) = (g(fx) * WHITE[0], g(fy) * WHITE[1], g(fz) * WHITE[2]);
    let r = 3.2404542 * x - 1.5371385 * y - 0.4985314 * z;
    let gr = -0.9692660 * x + 1.8760108 * y + 0.0415560 * z;
    let b = 0.0556434 * x - 0.2040259 * y + 1.0572252 * z;
    let encode = |c: f64| {
        let v = c.clamp(0.0, 1.0);
        let v = if v <= 0.0031308 {
            12.92 * v
        } else {
            1.055 * v.powf(1.0 / 2.4) - 0.055
        };
        v * 255.0
    };
    to_hex(encode(r), encode(gr), encode(b))
}

fn lch_to_hex(l_star: f64, c_star: f64, hue_deg: f64) -> String {
    let rad = hue_deg.to_radians();
    lab_to_hex(l_star, c_star * rad.cos(), c_star * rad.sin())
}

/// Linear interpolation in sRGB (§7.1 bright slots, §7.3 panel hairline).
fn mix(a: &str, b: &str, t: f64) -> String {
    match (channels(a), channels(b)) {
        (Some(ca), Some(cb)) => to_hex(
            ca[0] + (cb[0] - ca[0]) * t,
            ca[1] + (cb[1] - ca[1]) * t,
            ca[2] + (cb[2] - ca[2]) * t,
        ),
        _ => a.to_string(),
    }
}

// ---------------------------------------------------------------------------
// The palette, the pairs and the derived terminal
// ---------------------------------------------------------------------------

fn tok<'a>(block: &'a Value, key: &str) -> &'a str {
    block.get(key).and_then(Value::as_str).unwrap_or("")
}

fn status_tok<'a>(block: &'a Value, key: &str) -> &'a str {
    block
        .get("status")
        .and_then(|s| s.get(key))
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// The §7.1 terminal palette, slots 0-15.
fn ansi_slots(panel: &Value) -> Option<Vec<String>> {
    let fg = tok(panel, "fg");
    let l2 = lab(tok(panel, "ink2"))?[0];
    let mut slots: Vec<String> = vec![
        tok(panel, "edge").to_string(),
        status_tok(panel, "bad").to_string(),
        status_tok(panel, "ok").to_string(),
        status_tok(panel, "warn").to_string(),
        lch_to_hex(l2, 18.0, 271.0),
        lch_to_hex(l2, 18.0, 302.0),
        lch_to_hex(l2, 18.0, 214.0),
        fg.to_string(),
    ];
    slots.push(tok(panel, "ink3").to_string());
    for i in 1..=6 {
        let bright = mix(&slots[i], fg, 0.28);
        slots.push(bright);
    }
    slots.push("#FFFFFF".to_string());
    Some(slots)
}

struct Pair {
    name: &'static str,
    fg: String,
    bg: String,
    floor: f64,
    text: bool,
}

/// The 24 pairs of §4.2, in ThemeContrast.qml's order.
fn measured_pairs(paper: &Value, panel: &Value) -> Vec<Pair> {
    let p = |key: &str| tok(paper, key).to_string();
    let ps = |key: &str| status_tok(paper, key).to_string();
    let n = |key: &str| tok(panel, key).to_string();
    let ns = |key: &str| status_tok(panel, key).to_string();
    let pair = |name, fg: String, bg: String, floor, text| Pair {
        name,
        fg,
        bg,
        floor,
        text,
    };
    vec![
        pair("paper · ink on surface", p("ink"), p("surface"), 7.0, true),
        pair("paper · ink on raise2", p("ink"), p("raise2"), 7.0, true),
        pair(
            "paper · ink2 on surface",
            p("ink2"),
            p("surface"),
            4.5,
            true,
        ),
        pair("paper · ink2 on muted", p("ink2"), p("muted"), 4.5, true),
        pair(
            "paper · ink3 on surface",
            p("ink3"),
            p("surface"),
            4.5,
            true,
        ),
        pair("paper · ink3 on muted", p("ink3"), p("muted"), 4.5, true),
        pair("paper · ink3 on raise2", p("ink3"), p("raise2"), 4.5, true),
        pair(
            "paper · status.ok on surface",
            ps("ok"),
            p("surface"),
            4.5,
            true,
        ),
        pair(
            "paper · status.ok on raise2",
            ps("ok"),
            p("raise2"),
            4.5,
            true,
        ),
        pair(
            "paper · status.warn on surface",
            ps("warn"),
            p("surface"),
            4.5,
            true,
        ),
        pair(
            "paper · status.warn on raise2",
            ps("warn"),
            p("raise2"),
            4.5,
            true,
        ),
        pair(
            "paper · status.bad on surface",
            ps("bad"),
            p("surface"),
            4.5,
            true,
        ),
        pair(
            "paper · status.bad on raise2",
            ps("bad"),
            p("raise2"),
            4.5,
            true,
        ),
        pair(
            "paper · action fg on action bg",
            p("surface"),
            ps("ok"),
            4.5,
            true,
        ),
        pair(
            "paper · inputBorder on surface",
            p("inputBorder"),
            p("surface"),
            3.0,
            false,
        ),
        pair(
            "paper · focus ring on surface",
            p("ink"),
            p("surface"),
            3.0,
            false,
        ),
        pair("panel · fg on surface", n("fg"), n("surface"), 7.0, true),
        pair(
            "panel · ink2 on surface",
            n("ink2"),
            n("surface"),
            4.5,
            true,
        ),
        pair(
            "panel · ink3 on surface",
            n("ink3"),
            n("surface"),
            4.5,
            true,
        ),
        pair(
            "panel · status.ok on surface",
            ns("ok"),
            n("surface"),
            4.5,
            true,
        ),
        pair(
            "panel · status.warn on surface",
            ns("warn"),
            n("surface"),
            4.5,
            true,
        ),
        pair(
            "panel · status.bad on surface",
            ns("bad"),
            n("surface"),
            4.5,
            true,
        ),
        pair(
            "panel · action fg on action bg",
            n("surface"),
            ns("ok"),
            4.5,
            true,
        ),
        pair(
            "panel · focus ring on surface",
            n("fg"),
            n("surface"),
            3.0,
            false,
        ),
    ]
}

// ---------------------------------------------------------------------------
// R1-R9
// ---------------------------------------------------------------------------

const PAPER_KEYS: [&str; 9] = [
    "surface",
    "ink",
    "ink2",
    "ink3",
    "muted",
    "raise2",
    "border",
    "inputBorder",
    "status",
];
const PANEL_KEYS: [&str; 6] = ["surface", "fg", "ink2", "ink3", "edge", "status"];
const STATUS_KEYS: [&str; 3] = ["ok", "warn", "bad"];
const META_REQUIRED: [&str; 4] = ["id", "name", "intent", "defaultMood"];
const META_OPTIONAL: [&str; 3] = ["author", "version", "grammar"];

pub struct Validation {
    pub pass: bool,
    pub failures: Vec<Value>,
    pub pairs: Vec<Value>,
    pub summary: Value,
}

fn failure(rule: &str, detail: String, measured: Option<f64>, floor: Option<f64>) -> Value {
    json!({ "rule": rule, "detail": detail, "measured": measured, "floor": floor })
}

fn valid_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 24
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        && bytes[0] != b'-'
        && bytes[bytes.len() - 1] != b'-'
}

fn check_block(name: &str, block: &Value, keys: &[&str], failures: &mut Vec<Value>) -> bool {
    let Some(map) = block.as_object() else {
        failures.push(failure(
            "R1",
            format!("color.{name} is not an object"),
            None,
            None,
        ));
        return false;
    };
    let mut ok = true;
    for key in map.keys() {
        if !keys.contains(&key.as_str()) {
            failures.push(failure(
                "R1",
                format!("unknown key color.{name}.{key}"),
                None,
                None,
            ));
            ok = false;
        }
    }
    for key in keys.iter().filter(|k| **k != "status") {
        match map.get(*key) {
            None | Some(Value::Null) => {
                failures.push(failure(
                    "R1",
                    format!("missing color.{name}.{key}"),
                    None,
                    None,
                ));
                ok = false;
            }
            Some(value) if !value.as_str().is_some_and(is_hex) => {
                failures.push(failure(
                    "R2",
                    format!("color.{name}.{key} = {value} is not #RRGGBB uppercase sRGB"),
                    None,
                    None,
                ));
                ok = false;
            }
            Some(_) => {}
        }
    }
    let Some(status) = map.get("status").and_then(Value::as_object) else {
        failures.push(failure(
            "R1",
            format!("missing color.{name}.status"),
            None,
            None,
        ));
        return false;
    };
    for key in status.keys() {
        if !STATUS_KEYS.contains(&key.as_str()) {
            failures.push(failure(
                "R1",
                format!("unknown key color.{name}.status.{key} — a theme picks WHICH green, never what green says"),
                None,
                None,
            ));
            ok = false;
        }
    }
    for key in STATUS_KEYS {
        match status.get(key) {
            None | Some(Value::Null) => {
                failures.push(failure(
                    "R1",
                    format!("missing color.{name}.status.{key}"),
                    None,
                    None,
                ));
                ok = false;
            }
            Some(value) if !value.as_str().is_some_and(is_hex) => {
                failures.push(failure(
                    "R2",
                    format!("color.{name}.status.{key} = {value} is not #RRGGBB uppercase sRGB"),
                    None,
                    None,
                ));
                ok = false;
            }
            Some(_) => {}
        }
    }
    ok
}

/// R1 shape and R2 format: unknown keys are refused, not ignored.
fn check_shape(doc: &Value, failures: &mut Vec<Value>) -> bool {
    let Some(root) = doc.as_object() else {
        failures.push(failure("R1", "a theme is a JSON object".into(), None, None));
        return false;
    };
    for key in root.keys() {
        if !["$schema", "kind", "meta", "color"].contains(&key.as_str()) {
            failures.push(failure(
                "R1",
                format!(
                    "unknown top-level key \"{key}\" — a theme is nineteen colours and four strings"
                ),
                None,
                None,
            ));
        }
    }
    if root.get("kind").and_then(Value::as_str) != Some("PunarTheme") {
        failures.push(failure(
            "R1",
            "kind must be \"PunarTheme\"".into(),
            None,
            None,
        ));
    }
    let Some(meta) = root.get("meta").and_then(Value::as_object) else {
        failures.push(failure("R1", "missing meta block".into(), None, None));
        return false;
    };
    for key in meta.keys() {
        if !META_REQUIRED.contains(&key.as_str()) && !META_OPTIONAL.contains(&key.as_str()) {
            failures.push(failure(
                "R1",
                format!("unknown meta key \"{key}\""),
                None,
                None,
            ));
        }
    }
    for key in META_REQUIRED {
        if meta
            .get(key)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            failures.push(failure("R1", format!("missing meta.{key}"), None, None));
        }
    }
    let text = |key: &str| meta.get(key).and_then(Value::as_str);
    if let Some(id) = text("id") {
        if !valid_id(id) {
            failures.push(failure(
                "R1",
                format!("meta.id \"{id}\" is not a lowercase slug of 24 chars or fewer"),
                None,
                None,
            ));
        }
    }
    if text("name").is_some_and(|name| name.chars().count() > 24) {
        failures.push(failure(
            "R1",
            "meta.name is longer than 24 characters".into(),
            None,
            None,
        ));
    }
    if text("intent").is_some_and(|intent| intent.chars().count() > 96) {
        failures.push(failure(
            "R1",
            "meta.intent is longer than 96 characters".into(),
            None,
            None,
        ));
    }
    if text("defaultMood").is_some_and(|mood| mood != "paper" && mood != "panel") {
        failures.push(failure(
            "R1",
            "meta.defaultMood must be \"paper\" or \"panel\"".into(),
            None,
            None,
        ));
    }
    let Some(color) = root.get("color").and_then(Value::as_object) else {
        failures.push(failure(
            "R1",
            "missing color.paper and/or color.panel — no inheritance, no cascade, no partial themes".into(),
            None,
            None,
        ));
        return false;
    };
    let (Some(paper), Some(panel)) = (color.get("paper"), color.get("panel")) else {
        failures.push(failure(
            "R1",
            "missing color.paper and/or color.panel — no inheritance, no cascade, no partial themes".into(),
            None,
            None,
        ));
        return false;
    };
    for key in color.keys() {
        if key != "paper" && key != "panel" {
            failures.push(failure(
                "R1",
                format!("unknown color block \"{key}\""),
                None,
                None,
            ));
        }
    }
    let paper_ok = check_block("paper", paper, &PAPER_KEYS, failures);
    let panel_ok = check_block("panel", panel, &PANEL_KEYS, failures);
    paper_ok && panel_ok
}

fn in_window(h: f64, low: f64, high: f64) -> bool {
    if low <= high {
        h >= low && h < high
    } else {
        h >= low || h < high
    }
}

/// The whole gate, R1-R9 (§4.2).
pub fn validate(doc: &Value, grammar_major: u64) -> Validation {
    let mut failures = Vec::new();
    if !check_shape(doc, &mut failures) {
        return Validation {
            pass: false,
            failures,
            pairs: Vec::new(),
            summary: Value::Null,
        };
    }
    let paper = &doc["color"]["paper"];
    let panel = &doc["color"]["panel"];

    // R3 · the twenty-four measured pairs.
    let mut pairs = Vec::new();
    let (mut min_text, mut min_non_text) = (f64::INFINITY, f64::INFINITY);
    for pair in measured_pairs(paper, panel) {
        let ratio = contrast(&pair.fg, &pair.bg);
        let pass = meets(ratio, pair.floor);
        if !pass {
            let mut f = failure(
                "R3",
                pair.name.to_string(),
                Some(rounded(ratio)),
                Some(pair.floor),
            );
            f["pair"] = json!(pair.name);
            f["fg"] = json!(pair.fg);
            f["bg"] = json!(pair.bg);
            failures.push(f);
        }
        if pair.text {
            min_text = min_text.min(ratio);
        } else {
            min_non_text = min_non_text.min(ratio);
        }
        pairs.push(json!({
            "name": pair.name, "fg": pair.fg, "bg": pair.bg,
            "measured": rounded(ratio), "floor": pair.floor, "pass": pass,
            "kind": if pair.text { "text" } else { "nontext" },
        }));
    }

    let blocks = [("paper", paper), ("panel", panel)];
    // R4 · status hue windows and saturation, on both blocks.
    let windows = [
        ("ok", 70.0, 170.0),
        ("warn", 20.0, 70.0),
        ("bad", 330.0, 20.0),
    ];
    for (name, block) in blocks {
        for (role, low, high) in windows {
            let hex = status_tok(block, role);
            let h = hue(hex);
            if !in_window(h, low, high) {
                failures.push(failure(
                    "R4",
                    format!(
                        "{name} · status.{role} hue {}° outside {low}°-{high}°",
                        h.round()
                    ),
                    Some(h.round()),
                    None,
                ));
            }
            let s = saturation(hex);
            if s < 0.25 {
                failures.push(failure(
                    "R4",
                    format!(
                        "{name} · status.{role} saturation {}% — a greyed status stops reading as a decision",
                        (s * 100.0).round()
                    ),
                    Some((s * 100.0).round()),
                    Some(25.0),
                ));
            }
        }
    }

    // R5 · perceptual separation.
    let (mut min_de, mut min_ink_de) = (f64::INFINITY, f64::INFINITY);
    for (name, block) in blocks {
        for (a, b) in [("ok", "warn"), ("ok", "bad"), ("warn", "bad")] {
            let de = delta_e(status_tok(block, a), status_tok(block, b));
            min_de = min_de.min(de);
            if de < 25.0 {
                failures.push(failure(
                    "R5",
                    format!("{name} · status.{a} vs status.{b} ΔE*76 {de:.1}"),
                    Some(one_decimal(de)),
                    Some(25.0),
                ));
            }
        }
        for role in STATUS_KEYS {
            let de = delta_e(status_tok(block, role), tok(block, "ink3"));
            min_ink_de = min_ink_de.min(de);
            if de < 20.0 {
                failures.push(failure(
                    "R5",
                    format!("{name} · status.{role} vs ink3 ΔE*76 {de:.1}"),
                    Some(one_decimal(de)),
                    Some(20.0),
                ));
            }
        }
    }

    // R6 · neutral chroma cap.
    let mut max_c: f64 = 0.0;
    for (name, block) in blocks {
        for (key, value) in block.as_object().into_iter().flatten() {
            if key == "status" {
                continue;
            }
            let c = chroma(value.as_str().unwrap_or(""));
            max_c = max_c.max(c);
            if c > 14.0 {
                failures.push(failure(
                    "R6",
                    format!("{name} · {key} C* {c:.1}"),
                    Some(one_decimal(c)),
                    Some(14.0),
                ));
            }
        }
    }

    // R7 · elevation order.
    let c_muted = contrast(tok(paper, "muted"), tok(paper, "surface"));
    let c_raise = contrast(tok(paper, "raise2"), tok(paper, "surface"));
    let c_border = contrast(tok(paper, "border"), tok(paper, "surface"));
    if c_raise < c_muted {
        failures.push(failure(
            "R7",
            format!("paper · raise2 ({c_raise:.3}) is quieter than muted ({c_muted:.3})"),
            None,
            None,
        ));
    }
    if c_border <= c_raise || c_border <= c_muted {
        failures.push(failure(
            "R7",
            format!(
                "paper · border {c_border:.3} must strictly exceed both raises — a wallpaper mark may never out-rank a window border"
            ),
            None,
            None,
        ));
    }
    if c_border < 1.15 {
        failures.push(failure(
            "R7",
            format!("paper · border on surface {c_border:.3}"),
            Some((c_border * 1000.0).round() / 1000.0),
            Some(1.15),
        ));
    }
    let c_edge = contrast(tok(panel, "edge"), tok(panel, "surface"));
    if c_edge < 1.15 {
        failures.push(failure(
            "R7",
            format!("panel · edge on surface {c_edge:.3}"),
            Some((c_edge * 1000.0).round() / 1000.0),
            Some(1.15),
        ));
    }

    // R8 · derived terminal legibility; slot 0 is exempt.
    let mut min_ansi = f64::INFINITY;
    if let Some(slots) = ansi_slots(panel) {
        for (i, slot) in slots.iter().enumerate().skip(1) {
            let ratio = contrast(slot, tok(panel, "surface"));
            min_ansi = min_ansi.min(ratio);
            if !meets(ratio, 4.5) {
                failures.push(failure(
                    "R8",
                    format!("derived ANSI slot {i} ({slot}) on panel.surface"),
                    Some(rounded(ratio)),
                    Some(4.5),
                ));
            }
        }
    }

    // R9 · grammar compatibility.
    if let Some(grammar) = doc["meta"]
        .get("grammar")
        .and_then(Value::as_str)
        .filter(|g| !g.is_empty())
    {
        let major = grammar
            .split('.')
            .next()
            .and_then(|m| m.parse::<u64>().ok());
        if major != Some(grammar_major) {
            failures.push(failure(
                "R9",
                format!("meta.grammar {grammar} is not compatible with the installed grammar major {grammar_major}"),
                None,
                None,
            ));
        }
    }

    Validation {
        pass: failures.is_empty(),
        summary: json!({
            "pairCount": pairs.len(),
            "minText": rounded(min_text),
            "minNonText": rounded(min_non_text),
            "maxChroma": one_decimal(max_c),
            "minStatusDeltaE": one_decimal(min_de),
            "minStatusInkDeltaE": one_decimal(min_ink_de),
            "minAnsi": if min_ansi.is_finite() { json!(rounded(min_ansi)) } else { Value::Null },
        }),
        failures,
        pairs,
    }
}

impl Validation {
    fn to_json(&self) -> Value {
        json!({
            "pass": self.pass,
            "failures": self.failures,
            "pairs": self.pairs,
            "summary": self.summary,
        })
    }
}

// ---------------------------------------------------------------------------
// Files: the search path, the pointer, the grammar
// ---------------------------------------------------------------------------

fn home() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
}

fn user_pointer() -> Option<PathBuf> {
    home().map(|home| home.join(".config/punar/theme.json"))
}

/// §3.4: user, then site, then shipped. No org pin exists yet (§8 is
/// dashed), so the user directory is always searched.
fn search_dirs() -> Vec<(PathBuf, &'static str)> {
    let mut dirs = Vec::new();
    if let Some(home) = home() {
        dirs.push((home.join(".config/punar/themes"), "user"));
    }
    dirs.push((PathBuf::from(SITE_THEMES), "site"));
    dirs.push((PathBuf::from(INSTALLED_THEMES), "shipped"));
    dirs
}

fn read_doc(path: &Path) -> Result<(Value, Vec<u8>), String> {
    let meta = fs::metadata(path)
        .map_err(|error| format!("{} could not be read ({error})", path.display()))?;
    if meta.len() > MAX_DOC_BYTES {
        return Err(format!("{} is larger than any theme", path.display()));
    }
    let bytes = fs::read(path)
        .map_err(|error| format!("{} could not be read ({error})", path.display()))?;
    let doc = serde_json::from_slice(&bytes)
        .map_err(|error| format!("{} is not JSON ({error})", path.display()))?;
    Ok((doc, bytes))
}

/// The first document for an id on the search path.
fn resolve(id: &str) -> Option<(PathBuf, &'static str)> {
    if !valid_id(id) {
        return None;
    }
    search_dirs()
        .into_iter()
        .map(|(dir, source)| (dir.join(format!("{id}.theme.json")), source))
        .find(|(path, _)| path.is_file())
}

fn digest(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    format!(
        "sha256:{}",
        hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

/// The installed grammar version, or the one punarctl was built with.
fn grammar_version() -> String {
    let from = |text: &str| {
        serde_json::from_str::<Value>(text)
            .ok()
            .and_then(|doc| doc["meta"]["version"].as_str().map(str::to_string))
    };
    fs::read_to_string(INSTALLED_TOKENS)
        .ok()
        .and_then(|text| from(&text))
        .or_else(|| from(BUILT_TOKENS))
        .unwrap_or_else(|| "0.1.0".to_string())
}

fn grammar_major() -> u64 {
    grammar_version()
        .split('.')
        .next()
        .and_then(|m| m.parse().ok())
        .unwrap_or(0)
}

/// The active pointer and where it came from (§3.4 ranks 2-5).
fn active_pointer() -> (Option<Value>, &'static str, Option<PathBuf>) {
    let pointer = |path: &Path| {
        read_doc(path)
            .ok()
            .map(|(doc, _)| doc)
            .filter(|doc| doc["kind"] == "PunarThemePointer")
    };
    if let Some(path) = user_pointer() {
        if let Some(doc) = pointer(&path) {
            return (Some(doc), "user preference", Some(path));
        }
    }
    for path in [
        PathBuf::from(SYSTEM_POINTER),
        Path::new(INSTALLED_THEMES).join("default.json"),
    ] {
        if let Some(doc) = pointer(&path) {
            return (Some(doc), "system pointer", Some(path));
        }
    }
    (None, "built-in fallback", None)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("the path has no directory")?;
    if !parent.exists() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("{} could not be created ({error})", parent.display()))?;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }
    let temp = parent.join(format!(".punarctl-{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|error| format!("{} could not be created ({error})", temp.display()))?;
        file.write_all(bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        fs::rename(&temp, path)
            .map_err(|error| format!("{} could not be written ({error})", path.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Ask a running shell to re-read its pointer (Theme.qml's own note: an
/// inotify watch cannot be relied on to see a file's first creation). A
/// shell that is not running reads the file when it starts.
fn tell_shell(target: &str, function: &str) {
    let _ = Command::new("qs")
        .args([
            "-p",
            "/usr/share/punar/shell",
            "ipc",
            "call",
            target,
            function,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

// ---------------------------------------------------------------------------
// The verbs
// ---------------------------------------------------------------------------

fn refuse(message: &str, code: u8) -> ExitCode {
    eprintln!("{message}");
    ExitCode::from(code)
}

fn not_installed(id: &str) -> ExitCode {
    refuse(
        &format!(
            "No theme named {id:?} is installed, so nothing was changed.\n\
             Next step: `punarctl theme list` shows the installed themes."
        ),
        1,
    )
}

/// The §4.6 refusal table.
fn refusal(style: &Style, id: &str, result: &Validation, selected: bool) -> String {
    let mut out = fmt::masthead(style, "Theme", &format!("Refused · {id}"));
    out.push_str(&format!(
        "{id} does not meet the theme contract.{}\n\n",
        if selected {
            " It was not selected; the active theme is unchanged."
        } else {
            ""
        }
    ));
    let rows: Vec<Row> = result
        .failures
        .iter()
        .map(|f| {
            let number = |key: &str| {
                f[key]
                    .as_f64()
                    .map_or("—".to_string(), |v| format!("{v:.2}"))
            };
            Row::new(
                f["rule"].as_str().unwrap_or(""),
                &number("measured"),
                Slot::Bad,
                &format!(
                    "{} · floor {}",
                    f["detail"].as_str().unwrap_or(""),
                    number("floor")
                ),
            )
        })
        .collect();
    out.push_str(&fmt::rows(style, &rows));
    out.push_str(
        "Policy: theme contract — docs/design/theme-system.md §4 (not an organization policy; \
         this floor applies on every Punar device).\n",
    );
    out
}

fn mood_of(doc: &Value, requested: Option<&str>) -> String {
    requested
        .map(str::to_string)
        .or_else(|| doc["meta"]["defaultMood"].as_str().map(str::to_string))
        .unwrap_or_else(|| "paper".to_string())
}

pub fn theme(command: ThemeCommand, style: &Style, json_output: bool) -> ExitCode {
    let major = grammar_major();
    match command {
        ThemeCommand::List => {
            let (pointer, _, _) = active_pointer();
            let active = pointer
                .as_ref()
                .and_then(|p| p["active"].as_str().map(str::to_string))
                .unwrap_or_else(|| "paper".to_string());
            let mut seen = std::collections::BTreeSet::new();
            let mut rows = Vec::new();
            for (dir, source) in search_dirs() {
                let Ok(listing) = fs::read_dir(&dir) else {
                    continue;
                };
                let mut names: Vec<String> = listing
                    .flatten()
                    .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
                    .filter_map(|name| name.strip_suffix(".theme.json").map(str::to_string))
                    .collect();
                names.sort();
                for id in names {
                    if !valid_id(&id) || !seen.insert(id.clone()) {
                        continue;
                    }
                    let path = dir.join(format!("{id}.theme.json"));
                    let (state, name, mood, min_text) = match read_doc(&path) {
                        Ok((doc, _)) => {
                            let result = validate(&doc, major);
                            (
                                if result.pass {
                                    "ok".to_string()
                                } else {
                                    format!("refused · {}", result.failures.len())
                                },
                                doc["meta"]["name"].as_str().unwrap_or("").to_string(),
                                doc["meta"]["defaultMood"]
                                    .as_str()
                                    .unwrap_or("")
                                    .to_string(),
                                result.summary["minText"].as_f64(),
                            )
                        }
                        Err(_) => ("unreadable".to_string(), String::new(), String::new(), None),
                    };
                    rows.push(json!({
                        "id": id, "name": name, "mood": mood, "source": source,
                        "min_text": min_text, "state": state, "active": id == active,
                        "path": path,
                    }));
                }
            }
            if json_output {
                println!("{}", json!({ "themes": rows, "active": active }));
                return ExitCode::SUCCESS;
            }
            let mut out = fmt::masthead(style, "Themes", "this account");
            let table: Vec<Row> = rows
                .iter()
                .map(|r| {
                    let state = r["state"].as_str().unwrap_or("");
                    Row::new(
                        r["id"].as_str().unwrap_or(""),
                        if r["active"] == true { "active" } else { state },
                        if state == "ok" { Slot::Ok } else { Slot::Bad },
                        &format!(
                            "{} · {} · {} · min text {}",
                            crate::session::safe(r["name"].as_str().unwrap_or("")),
                            r["mood"].as_str().unwrap_or(""),
                            r["source"].as_str().unwrap_or(""),
                            r["min_text"]
                                .as_f64()
                                .map_or("—".to_string(), |v| format!("{v:.2}:1"))
                        ),
                    )
                })
                .collect();
            if table.is_empty() {
                out.push_str(&fmt::note(
                    style,
                    "No theme is installed · the built-in palette applies",
                ));
            } else {
                out.push_str(&fmt::rows(style, &table));
            }
            out.push_str(&fmt::note(
                style,
                "punarctl theme set <id> · punarctl theme show <id>",
            ));
            print!("{out}");
            ExitCode::SUCCESS
        }
        ThemeCommand::Show { id } => {
            let Some((path, source)) = resolve(&id) else {
                return not_installed(&id);
            };
            let (doc, bytes) = match read_doc(&path) {
                Ok(read) => read,
                Err(why) => return refuse(&why, 1),
            };
            let result = validate(&doc, major);
            let ansi = ansi_slots(&doc["color"]["panel"]).unwrap_or_default();
            if json_output {
                println!(
                    "{}",
                    json!({
                        "meta": doc["meta"], "color": doc["color"], "source": source,
                        "path": path, "digest": digest(&bytes),
                        "validation": result.to_json(), "ansi": ansi,
                    })
                );
                return ExitCode::SUCCESS;
            }
            let mut out = fmt::masthead(style, "Theme", &id);
            out.push_str(&format!(
                "{} · {}\n",
                crate::session::safe(doc["meta"]["name"].as_str().unwrap_or("")),
                crate::session::safe(doc["meta"]["intent"].as_str().unwrap_or(""))
            ));
            for block in ["paper", "panel"] {
                out.push('\n');
                out.push_str(&fmt::section(style, &format!("{block} palette"), source));
                let mut rows = Vec::new();
                for (key, value) in doc["color"][block].as_object().into_iter().flatten() {
                    if key == "status" {
                        for role in STATUS_KEYS {
                            rows.push(Row::new(
                                &format!("status.{role}"),
                                status_tok(&doc["color"][block], role),
                                Slot::Neutral,
                                "",
                            ));
                        }
                    } else {
                        rows.push(Row::new(
                            key,
                            value.as_str().unwrap_or(""),
                            Slot::Neutral,
                            "",
                        ));
                    }
                }
                out.push_str(&fmt::rows(style, &rows));
            }
            out.push('\n');
            out.push_str(&fmt::section(style, "Measured pairs", "WCAG 2.1 contrast"));
            let rows: Vec<Row> = result
                .pairs
                .iter()
                .map(|p| {
                    let pass = p["pass"] == true;
                    Row::new(
                        &format!("{:.2}:1", p["measured"].as_f64().unwrap_or(0.0)),
                        if pass { "pass" } else { "fail" },
                        if pass { Slot::Ok } else { Slot::Bad },
                        &format!(
                            "{} · {} on {} · floor {:.1}:1",
                            p["name"].as_str().unwrap_or(""),
                            p["fg"].as_str().unwrap_or(""),
                            p["bg"].as_str().unwrap_or(""),
                            p["floor"].as_f64().unwrap_or(0.0)
                        ),
                    )
                })
                .collect();
            out.push_str(&fmt::rows(style, &rows));
            out.push('\n');
            out.push_str(&fmt::section(style, "Derived terminal", "§7.1"));
            let rows: Vec<Row> = ansi
                .iter()
                .enumerate()
                .map(|(i, slot)| Row::new(&format!("slot {i}"), slot, Slot::Neutral, ""))
                .collect();
            out.push_str(&fmt::rows(style, &rows));
            out.push_str(&fmt::verdict(
                style,
                if result.pass { Slot::Ok } else { Slot::Bad },
                &if result.pass {
                    "Passes R1-R9".to_string()
                } else {
                    format!(
                        "Refused · {} failures · punarctl theme validate {id}",
                        result.failures.len()
                    )
                },
            ));
            print!("{out}");
            ExitCode::SUCCESS
        }
        ThemeCommand::Validate { target } => {
            let path = if target.contains('/') || target.ends_with(".json") {
                PathBuf::from(&target)
            } else {
                match resolve(&target) {
                    Some((path, _)) => path,
                    None => return not_installed(&target),
                }
            };
            let doc = match read_doc(&path) {
                Ok((doc, _)) => doc,
                Err(why) => return refuse(&why, 1),
            };
            let result = validate(&doc, major);
            let label = doc["meta"]["id"].as_str().unwrap_or(&target).to_string();
            if json_output {
                println!(
                    "{}",
                    json!({ "pass": result.pass, "failures": result.failures, "summary": result.summary })
                );
            } else if result.pass {
                print!(
                    "{}",
                    fmt::verdict(
                        style,
                        Slot::Ok,
                        &format!(
                            "{label} · passes R1-R9 · min text {:.2}:1 · min non-text {:.2}:1",
                            result.summary["minText"].as_f64().unwrap_or(0.0),
                            result.summary["minNonText"].as_f64().unwrap_or(0.0)
                        )
                    )
                );
            } else {
                print!("{}", refusal(style, &label, &result, false));
            }
            if result.pass {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(EXIT_REFUSED)
            }
        }
        ThemeCommand::Set { id, mood } => {
            let Some(pointer_path) = user_pointer() else {
                return refuse(
                    "HOME is not set, so there is nowhere to record a preference.",
                    1,
                );
            };
            let Some((path, _)) = resolve(&id) else {
                return not_installed(&id);
            };
            let (doc, bytes) = match read_doc(&path) {
                Ok(read) => read,
                Err(why) => return refuse(&why, 1),
            };
            let result = validate(&doc, major);
            if !result.pass {
                if json_output {
                    println!(
                        "{}",
                        json!({ "applied": false, "pass": false, "failures": result.failures })
                    );
                } else {
                    eprint!("{}", refusal(style, &id, &result, true));
                }
                return ExitCode::from(EXIT_REFUSED);
            }
            let pointer = json!({
                "$schema": "https://schemas.punar.dev/v1alpha1/theme/pointer.json",
                "kind": "PunarThemePointer",
                "active": id,
                "mood": mood.clone().unwrap_or_else(|| "default".to_string()),
                "validated": {
                    "at": punar_common::time::utc_now_rfc3339(),
                    "grammar": grammar_version(),
                    "digest": digest(&bytes),
                    "minText": result.summary["minText"],
                    "minNonText": result.summary["minNonText"],
                },
            });
            let text = serde_json::to_string_pretty(&pointer).unwrap_or_default() + "\n";
            if let Err(why) = write_private(&pointer_path, text.as_bytes()) {
                return refuse(&format!("The theme was not selected.\nWhy: {why}."), 1);
            }
            tell_shell("theme", "reload");
            if json_output {
                println!("{}", json!({ "applied": true, "pointer": pointer }));
            } else {
                print!(
                    "{}",
                    fmt::verdict(
                        style,
                        Slot::Ok,
                        &format!("Theme · {id} · {} mood", mood_of(&doc, mood.as_deref()))
                    )
                );
            }
            ExitCode::SUCCESS
        }
        ThemeCommand::Reset => {
            let Some(path) = user_pointer() else {
                return refuse("HOME is not set, so there is no preference to drop.", 1);
            };
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return refuse(
                        &format!("The preference could not be dropped ({error})."),
                        1,
                    );
                }
            }
            tell_shell("theme", "reload");
            let (pointer, source, _) = active_pointer();
            let active = pointer
                .as_ref()
                .and_then(|p| p["active"].as_str())
                .unwrap_or("paper")
                .to_string();
            if json_output {
                println!(
                    "{}",
                    json!({ "reset": true, "active": active, "source": source })
                );
            } else {
                print!(
                    "{}",
                    fmt::verdict(
                        style,
                        Slot::Ok,
                        &format!("Theme reset · {active} · {source}")
                    )
                );
            }
            ExitCode::SUCCESS
        }
        ThemeCommand::Status => {
            let (pointer, source, pointer_path) = active_pointer();
            let active = pointer
                .as_ref()
                .and_then(|p| p["active"].as_str())
                .unwrap_or("paper")
                .to_string();
            let requested = pointer
                .as_ref()
                .and_then(|p| p["mood"].as_str())
                .unwrap_or("default")
                .to_string();
            let resolved = resolve(&active);
            let document = resolved.as_ref().and_then(|(path, _)| read_doc(path).ok());
            let effective_mood = match (&requested[..], &document) {
                ("paper" | "panel", _) => requested.clone(),
                (_, Some((doc, _))) => mood_of(doc, None),
                _ => "paper".to_string(),
            };
            let recorded = pointer
                .as_ref()
                .and_then(|p| p["validated"]["digest"].as_str())
                .map(str::to_string);
            let current = document.as_ref().map(|(_, bytes)| digest(bytes));
            let integrity = match (&recorded, &current) {
                (Some(r), Some(c)) if r == c => "matches",
                (Some(_), Some(_)) => "modified since validated",
                (None, Some(_)) => "no digest recorded",
                (_, None) => "theme file not found",
            };
            if json_output {
                println!(
                    "{}",
                    json!({
                        "active": active, "mood": requested, "effective_mood": effective_mood,
                        "source": source, "pointer": pointer_path,
                        "theme_path": resolved.as_ref().map(|(p, _)| p.clone()),
                        "digest": { "recorded": recorded, "current": current, "state": integrity },
                        "validated": pointer.as_ref().map(|p| p["validated"].clone()),
                    })
                );
                return ExitCode::SUCCESS;
            }
            let mut out = fmt::masthead(style, "Theme", "this account");
            out.push_str(&fmt::rows(
                style,
                &[
                    Row::new("Active", &active, Slot::Ok, source),
                    Row::new(
                        "Mood",
                        &effective_mood,
                        Slot::Neutral,
                        &format!("pointer says {requested}"),
                    ),
                    Row::new(
                        "File",
                        integrity,
                        if integrity == "matches" {
                            Slot::Ok
                        } else {
                            Slot::Warn
                        },
                        &resolved
                            .as_ref()
                            .map(|(p, _)| p.display().to_string())
                            .unwrap_or_else(|| "built-in palette".to_string()),
                    ),
                ],
            ));
            print!("{out}");
            ExitCode::SUCCESS
        }
        ThemeCommand::Render {
            id,
            target,
            mood,
            out,
        } => {
            let doc = match resolve(&id).map(|(path, _)| read_doc(&path)) {
                Some(Ok((doc, _))) => doc,
                Some(Err(why)) => return refuse(&why, 1),
                None => return not_installed(&id),
            };
            if !validate(&doc, major).pass {
                return refuse(
                    &format!(
                        "{id} does not meet the theme contract, so nothing was rendered.\n\
                         Next step: `punarctl theme validate {id}` names each failure."
                    ),
                    EXIT_REFUSED,
                );
            }
            let artefact = render(&doc, &id, &target, &mood_of(&doc, mood.as_deref()));
            match out {
                Some(path) => match fs::write(&path, &artefact) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(error) => refuse(
                        &format!("{} could not be written ({error}).", path.display()),
                        1,
                    ),
                },
                None => {
                    print!("{artefact}");
                    ExitCode::SUCCESS
                }
            }
        }
    }
}

/// The §7 derived artefacts.
fn render(doc: &Value, id: &str, target: &str, mood: &str) -> String {
    let panel = &doc["color"]["panel"];
    let paper = &doc["color"]["paper"];
    let bare = |hex: &str| hex.trim_start_matches('#').to_string();
    match target {
        "foot" => {
            let slots = ansi_slots(panel).unwrap_or_default();
            let mut section = format!(
                "background={}\nforeground={}\ncursor={} {}\n",
                bare(tok(panel, "surface")),
                bare(tok(panel, "fg")),
                bare(tok(panel, "surface")),
                bare(status_tok(panel, "ok"))
            );
            for (i, slot) in slots.iter().enumerate() {
                let name = if i < 8 {
                    format!("regular{i}")
                } else {
                    format!("bright{}", i - 8)
                };
                section.push_str(&format!("{name}={}\n", bare(slot)));
            }
            format!(
                "# generated by punarctl theme render {id} --target foot — do not edit\n\
                 # The colour sections of foot.ini (theme-system.md §7.1).\n\
                 [colors-dark]\nalpha=1.0\n{section}\n[colors-light]\nalpha=1.0\n{section}"
            )
        }
        "hypr" => {
            let m = if mood == "panel" { panel } else { paper };
            let strong = if mood == "panel" {
                tok(m, "fg")
            } else {
                tok(m, "ink")
            };
            let quiet = if mood == "panel" {
                tok(m, "edge")
            } else {
                tok(m, "border")
            };
            let rgb = |hex: &str| format!("rgb({})", bare(hex));
            format!(
                "# generated by punarctl theme render {id} --target hypr — do not edit\n\
                 # Only the values a theme varies (theme-system.md §7.2), {mood} mood.\n\
                 general:col.active_border = {strong}\n\
                 general:col.inactive_border = {edge}\n\
                 group:col.border_active = {strong}\n\
                 group:col.border_inactive = {edge}\n\
                 group:col.border_locked_active = {ink2}\n\
                 groupbar:text_color = {strong}\n\
                 groupbar:text_color_inactive = {ink3}\n\
                 groupbar:col.active = {strong}\n\
                 groupbar:col.inactive = {quiet}\n\
                 misc:background_color = {surface}\n",
                strong = rgb(strong),
                edge = rgb(tok(panel, "edge")),
                ink2 = rgb(tok(m, "ink2")),
                ink3 = rgb(tok(m, "ink3")),
                quiet = rgb(quiet),
                surface = rgb(tok(m, "surface")),
            )
        }
        "wallpaper" => {
            let value = json!({
                "theme": id,
                "paper": {
                    "field": tok(paper, "surface"),
                    "hairline": tok(paper, "muted"),
                    "emphasis": tok(paper, "raise2"),
                },
                "panel": {
                    "field": tok(panel, "surface"),
                    "hairline": mix(tok(panel, "surface"), tok(panel, "edge"), 0.55),
                    "emphasis": tok(panel, "edge"),
                },
            });
            serde_json::to_string_pretty(&value).unwrap_or_default() + "\n"
        }
        _ => format!(
            "{}\n",
            if mood == "panel" {
                "prefer-dark"
            } else {
                "prefer-light"
            }
        ),
    }
}

// ---------------------------------------------------------------------------
// Wallpaper
// ---------------------------------------------------------------------------

fn shell_json(function: &str, args: &[&str]) -> Result<Value, String> {
    let output = Command::new("qs")
        .args([
            "-p",
            "/usr/share/punar/shell",
            "ipc",
            "call",
            "wallpaper",
            function,
        ])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("qs could not start ({error})"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|_| "the shell's answer was not JSON".to_string())
}

fn shell_unreachable(why: &str) -> ExitCode {
    refuse(
        &format!(
            "The desktop shell is not reachable.\nWhy: {}.\n\
             Next step: run this inside your desktop session, where punar-shell is running.",
            if why.is_empty() {
                "qs gave no reason"
            } else {
                why
            }
        ),
        crate::ipc::EXIT_UNREACHABLE,
    )
}

pub fn wallpaper(command: WallpaperCommand, style: &Style, json_output: bool) -> ExitCode {
    let result = match &command {
        WallpaperCommand::List => shell_json("list", &[]),
        WallpaperCommand::Set { id } => {
            if !valid_id(id) {
                return refuse(
                    &format!(
                        "{id:?} is not a wallpaper id, so nothing was changed.\n\
                         Next step: `punarctl wallpaper list` shows the installed ones."
                    ),
                    2,
                );
            }
            shell_json("set", &[id])
        }
        WallpaperCommand::Reset => shell_json("reset", &[]),
        WallpaperCommand::Status => shell_json("state", &[]),
    };
    let answer = match result {
        Ok(answer) => answer,
        Err(why) => return shell_unreachable(&why),
    };
    if matches!(
        command,
        WallpaperCommand::Set { .. } | WallpaperCommand::Reset
    ) && answer["applied"] != true
    {
        return refuse(
            &format!(
                "The wallpaper was not changed.\nWhy: {}.",
                answer["reason"].as_str().unwrap_or("the shell refused")
            ),
            1,
        );
    }
    if json_output {
        println!("{answer}");
        return ExitCode::SUCCESS;
    }
    let mut out = fmt::masthead(style, "Wallpaper", "this account");
    match command {
        WallpaperCommand::List => {
            let active = answer["active"].as_str().unwrap_or("");
            let rows: Vec<Row> = answer["wallpapers"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|w| {
                    let id = w["id"].as_str().unwrap_or("");
                    Row::new(
                        id,
                        if id == active {
                            "active"
                        } else if w["vector"] == true {
                            "vector"
                        } else {
                            "image"
                        },
                        if id == active {
                            Slot::Ok
                        } else {
                            Slot::Neutral
                        },
                        &format!(
                            "{} · {}",
                            crate::session::safe(w["name"].as_str().unwrap_or("")),
                            crate::session::safe(w["intent"].as_str().unwrap_or(""))
                        ),
                    )
                })
                .collect();
            out.push_str(&fmt::rows(style, &rows));
            out.push_str(&fmt::note(style, "punarctl wallpaper set <id>"));
        }
        _ => {
            out.push_str(&fmt::rows(
                style,
                &[Row::new(
                    "Active",
                    answer["active"].as_str().unwrap_or(""),
                    Slot::Ok,
                    answer["source"]
                        .as_str()
                        .or_else(|| answer["reason"].as_str())
                        .unwrap_or(""),
                )],
            ));
        }
    }
    print!("{out}");
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHIPPED: [(&str, &str); 7] = [
        (
            "paper",
            include_str!("../../../shell/theme/themes/paper.theme.json"),
        ),
        (
            "panel",
            include_str!("../../../shell/theme/themes/panel.theme.json"),
        ),
        (
            "graphite",
            include_str!("../../../shell/theme/themes/graphite.theme.json"),
        ),
        (
            "oxide",
            include_str!("../../../shell/theme/themes/oxide.theme.json"),
        ),
        (
            "nocturne",
            include_str!("../../../shell/theme/themes/nocturne.theme.json"),
        ),
        (
            "ember",
            include_str!("../../../shell/theme/themes/ember.theme.json"),
        ),
        (
            "contrast",
            include_str!("../../../shell/theme/themes/contrast.theme.json"),
        ),
    ];

    fn shipped(id: &str) -> Value {
        let (_, text) = SHIPPED.iter().find(|(name, _)| *name == id).unwrap();
        serde_json::from_str(text).unwrap()
    }

    /// §5.3: every shipped theme passes, with the published minimum text and
    /// non-text pairs, max C* and R5 separation, and §7.1's minimum ANSI.
    #[test]
    fn the_shipped_set_reproduces_the_published_table() {
        let table = [
            ("paper", 4.78, 3.35, 8.4, Some(5.16)),
            ("panel", 4.78, 3.35, 8.4, Some(5.16)),
            ("graphite", 4.79, 3.19, 6.8, Some(4.89)),
            ("oxide", 4.60, 3.27, 12.0, Some(4.60)),
            ("nocturne", 4.70, 3.16, 11.5, Some(4.91)),
            ("ember", 4.73, 3.27, 12.1, Some(5.04)),
            ("contrast", 7.57, 7.00, 0.0, Some(9.14)),
        ];
        for (id, text, non_text, chroma, ansi) in table {
            let result = validate(&shipped(id), 0);
            assert!(result.pass, "{id}: {:?}", result.failures);
            assert_eq!(result.pairs.len(), 24, "{id}");
            assert_eq!(result.summary["minText"].as_f64(), Some(text), "{id}");
            assert_eq!(
                result.summary["minNonText"].as_f64(),
                Some(non_text),
                "{id}"
            );
            assert_eq!(result.summary["maxChroma"].as_f64(), Some(chroma), "{id}");
            if let Some(ansi) = ansi {
                assert_eq!(result.summary["minAnsi"].as_f64(), Some(ansi), "{id}");
            }
        }
    }

    /// §5.4: the default theme's 24 pairs, measured.
    #[test]
    fn the_default_theme_pairs_match_the_published_rows() {
        let result = validate(&shipped("paper"), 0);
        let measured: Vec<f64> = result
            .pairs
            .iter()
            .map(|p| p["measured"].as_f64().unwrap())
            .collect();
        assert_eq!(
            measured,
            [
                19.95, 17.47, 12.00, 11.29, 5.45, 5.13, 4.78, 6.15, 5.39, 5.63, 4.93, 7.15, 6.26,
                6.15, 3.35, 19.95, 17.95, 8.84, 5.16, 12.63, 11.84, 7.89, 12.63, 17.95
            ]
        );
    }

    /// §7.1: the derived slots for the default theme.
    #[test]
    fn the_default_terminal_derivation_matches_the_published_slots() {
        let slots = ansi_slots(&shipped("paper")["color"]["panel"]).unwrap();
        assert_eq!(slots.len(), 16);
        assert_eq!(&slots[4..7], ["#9BAECD", "#B1A8C8", "#81B5BE"]);
        assert_eq!(&slots[9..12], ["#FB9C9C", "#B9E578", "#F2CDA4"]);
        assert_eq!(slots[0], "#26282E");
        assert_eq!(slots[15], "#FFFFFF");
    }

    /// The shipped pointer's receipt is the digest of the shipped file.
    #[test]
    fn the_shipped_pointer_digest_is_the_shipped_papers() {
        let pointer: Value =
            serde_json::from_str(include_str!("../../../shell/theme/themes/default.json")).unwrap();
        let paper = include_bytes!("../../../shell/theme/themes/paper.theme.json");
        assert_eq!(pointer["validated"]["digest"], digest(paper));
    }

    /// 4.497 fails a 4.5 floor and prints as 4.50; a rounded 4.50 passes.
    #[test]
    fn rounding_never_passes_a_pair() {
        assert!(!meets(4.497, 4.5));
        assert_eq!(rounded(4.497), 4.5);
        assert!(meets(4.5, 4.5));
        assert!(!meets(-1.0, 3.0));
    }

    /// Shape is refused, not ignored: an unknown key, a lower-case hex, a
    /// greyed status and a foreign grammar each name their rule.
    #[test]
    fn each_rule_names_itself() {
        let mut doc = shipped("paper");
        doc["font"] = json!("Comic Sans");
        doc["color"]["paper"]["ink"] = json!("#00000a");
        doc["color"]["panel"]["status"]["ok"] = json!("#808080");
        doc["meta"]["grammar"] = json!("1.0.0");
        let result = validate(&doc, 0);
        assert!(!result.pass);
        let rules: Vec<&str> = result
            .failures
            .iter()
            .map(|f| f["rule"].as_str().unwrap())
            .collect();
        assert!(rules.contains(&"R1") && rules.contains(&"R2"), "{rules:?}");

        let mut doc = shipped("paper");
        doc["color"]["panel"]["status"]["ok"] = json!("#808080");
        doc["meta"]["grammar"] = json!("1.0.0");
        doc["color"]["paper"]["ink3"] = json!("#9A9A9A");
        let result = validate(&doc, 0);
        let rules: Vec<&str> = result
            .failures
            .iter()
            .map(|f| f["rule"].as_str().unwrap())
            .collect();
        for rule in ["R3", "R4", "R9"] {
            assert!(rules.contains(&rule), "{rule} in {rules:?}");
        }
        let r3 = result.failures.iter().find(|f| f["rule"] == "R3").unwrap();
        assert!(r3["fg"].is_string() && r3["bg"].is_string(), "{r3}");
    }

    #[test]
    fn ids_cannot_leave_the_theme_directories() {
        assert!(valid_id("nocturne") && valid_id("a-1"));
        for bad in ["../etc", "a/b", "-x", "x-", "", "UPPER", "a.b"] {
            assert!(!valid_id(bad), "{bad}");
        }
    }
}
