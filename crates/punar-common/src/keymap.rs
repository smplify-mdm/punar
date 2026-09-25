//! Keyboard layouts: one grammar for the `system.keymap` capability, the
//! session's rendered input file and `punarctl keyboard` (SMP-1405 WP-02).
//!
//! A value names one to four XKB layouts, comma-separated, each optionally
//! with a variant after `+` (GNOME's spelling): `us`, `de+nodeadkeys`,
//! `us,ru`. Four is XKB's own limit, a keymap has four groups.
//!
//! **Validated twice, evaluated never.** The syntax check here admits only
//! `[A-Za-z0-9_-]` tokens, so no value can carry a quote, a backslash, a
//! newline or a comma into a file it is written to. The catalog check then
//! admits only layouts and variants the image's own XKB list names
//! ([`XKB_LIST`]), so a value that reaches `/etc/vconsole.conf` or the
//! session's input file is always one the keyboard stack can load. Neither
//! file is ever run: the compositor parses the input file with a pattern.
//!
//! **Latin letters must keep working.** Hyprland resolves key binds against
//! the first layout in `kb_layout`, not the active one, so a desktop whose
//! first layout cannot type Latin letters loses PUNAR+Return and every other
//! letter bind. [`session_input`] therefore leads the rendered list with a
//! Latin layout, the first one the person chose or `us`, and adds the switch
//! chord ([`SWITCH_OPTION`], both Alt keys) whenever there is more than one
//! layout to switch between. Omarchy's `input.lua` does the same (`us,` plus
//! `grp:alts_toggle`); the person's own choice is stored unchanged, and the
//! Latin lead is a rendering rule, not a rewrite of what they picked.

use std::collections::BTreeMap;
use std::fmt;

use thiserror::Error;

/// The capability that owns the device's keyboard layout.
pub const CAPABILITY_ID: &str = "system.keymap";
/// What a device uses before anyone chooses: the installer's default too.
pub const DEFAULT: &str = "us";
/// The image's XKB rules list (xkeyboard-config / xkb-data).
pub const XKB_LIST: &str = "/usr/share/X11/xkb/rules/evdev.lst";
/// The console's keyboard file, which punard owns through the capability.
pub const VCONSOLE: &str = "/etc/vconsole.conf";
/// An XKB keymap holds four groups.
pub const MAX_LAYOUTS: usize = 4;
/// The layout-switch chord, as an XKB option. It lives in the keymap, so it
/// works in the greeter, the desktop and on the lock screen alike, with no
/// compositor bind and no process.
pub const SWITCH_OPTION: &str = "grp:alts_toggle";
/// The same chord in words, for every surface that names it.
pub const SWITCH_CHORD: &str = "both Alt keys together";
/// The Latin layout a non-Latin choice is led by when it names none.
pub const LATIN_FALLBACK: &str = "us";
/// The longest layout or variant name accepted (the real list peaks at 26).
pub const MAX_TOKEN: usize = 32;

/// Layouts whose base group cannot type Latin letters.
///
/// Omarchy's list (`default/hypr/input.lua@v4.0.4`, kept in sync with its
/// initramfs hook), plus seven it misses that the XKB list also ships with a
/// non-Latin base group: `eg` and `ma` (Arabic), `pk` (Urdu), `bt`
/// (Dzongkha), `my` (Malay in Jawi), `uz` (Uzbek, Cyrillic by default) and
/// `brai` (Braille). A layout missing from this list and non-Latin in fact
/// would lose the letter binds, so the in-VM check asserts every entry is a
/// layout the image knows, and the list errs towards inclusion: a Latin
/// layout wrongly listed only gains a `us` first group and the switch chord.
pub const NON_LATIN: &[&str] = &[
    "af", "am", "ara", "bd", "bg", "brai", "bt", "by", "eg", "et", "ge", "gr", "il", "in", "iq",
    "ir", "kg", "kh", "kz", "la", "lk", "ma", "mk", "mm", "mn", "mv", "my", "np", "pk", "rs", "ru",
    "sy", "th", "tj", "ua", "uz",
];

/// One layout, with its variant or `""` for the layout's default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    pub layout: String,
    pub variant: String,
}

impl Layout {
    pub fn new(layout: &str, variant: &str) -> Layout {
        Layout {
            layout: layout.to_string(),
            variant: variant.to_string(),
        }
    }

    /// Whether this layout's base group types Latin letters.
    pub fn is_latin(&self) -> bool {
        !NON_LATIN.contains(&self.layout.as_str())
    }
}

impl fmt::Display for Layout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.variant.is_empty() {
            write!(f, "{}", self.layout)
        } else {
            write!(f, "{}+{}", self.layout, self.variant)
        }
    }
}

/// Why a value is not a keyboard layout this device can use. Every message
/// is a sentence a person can act on.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum KeymapError {
    #[error(
        "{0:?} is not a keyboard layout: name one to four layouts, comma-separated, \
         each optionally with a variant after `+`, like `us`, `de+nodeadkeys` or `us,ru`"
    )]
    Syntax(String),
    #[error(
        "{0:?} names more layouts than a keyboard can hold: at most four, and a first \
         layout that cannot type Latin letters takes one of them for `us`"
    )]
    TooMany(String),
    #[error("{0:?} is named twice")]
    Duplicate(String),
    #[error(
        "no keyboard layout called {0:?} is installed; `punarctl keyboard layout list` shows them"
    )]
    UnknownLayout(String),
    #[error(
        "the {layout} layout has no variant called {variant:?}; \
         `punarctl keyboard layout list {layout}` shows them"
    )]
    UnknownVariant { layout: String, variant: String },
}

fn token_ok(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        && !token.starts_with('-')
}

/// Parse a value's syntax. Checks nothing against the installed list; see
/// [`Catalog::check`].
pub fn parse(value: &str) -> Result<Vec<Layout>, KeymapError> {
    let syntax = || KeymapError::Syntax(value.to_string());
    if value.is_empty() || value.len() > (MAX_TOKEN * 2 + 1) * MAX_LAYOUTS + MAX_LAYOUTS {
        return Err(syntax());
    }
    let mut out: Vec<Layout> = Vec::new();
    for entry in value.split(',') {
        let (layout, variant) = match entry.split_once('+') {
            Some((layout, variant)) => (layout, variant),
            None => (entry, ""),
        };
        if !token_ok(layout) || (!variant.is_empty() && !token_ok(variant)) {
            return Err(syntax());
        }
        if entry.ends_with('+') {
            return Err(syntax());
        }
        let parsed = Layout::new(layout, variant);
        if out.contains(&parsed) {
            return Err(KeymapError::Duplicate(parsed.to_string()));
        }
        out.push(parsed);
    }
    if out.len() > MAX_LAYOUTS {
        return Err(KeymapError::TooMany(value.to_string()));
    }
    // The Latin lead must fit, too: it is the one group the person did not
    // choose, and a keymap that silently dropped their fourth layout to make
    // room would be a worse surprise than this refusal.
    if needs_latin_lead(&out) && out.len() == MAX_LAYOUTS {
        return Err(KeymapError::TooMany(value.to_string()));
    }
    Ok(out)
}

/// The value's canonical spelling.
pub fn format(layouts: &[Layout]) -> String {
    layouts
        .iter()
        .map(Layout::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn needs_latin_lead(layouts: &[Layout]) -> bool {
    layouts.first().is_some_and(|first| !first.is_latin())
}

/// What the image's XKB list names: every layout, and every variant of each.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Catalog {
    /// layout → its description.
    pub layouts: BTreeMap<String, String>,
    /// (layout, variant) → its description.
    pub variants: BTreeMap<(String, String), String>,
}

impl Catalog {
    /// Parse `evdev.lst`: `! layout` lines are `  <name>  <description>`,
    /// `! variant` lines are `  <name>  <layout>: <description>`. Anything
    /// else, including names the syntax check would refuse, is skipped.
    pub fn parse(text: &str) -> Catalog {
        let mut catalog = Catalog::default();
        let mut section = "";
        for line in text.lines() {
            if let Some(name) = line.strip_prefix('!') {
                section = match name.trim() {
                    "layout" => "layout",
                    "variant" => "variant",
                    _ => "",
                };
                continue;
            }
            let line = line.trim();
            let Some((name, rest)) = line.split_once(char::is_whitespace) else {
                continue;
            };
            let rest = rest.trim();
            if !token_ok(name) {
                continue;
            }
            match section {
                "layout" => {
                    catalog.layouts.insert(name.to_string(), rest.to_string());
                }
                "variant" => {
                    if let Some((layout, description)) = rest.split_once(':') {
                        let layout = layout.trim();
                        if token_ok(layout) {
                            catalog.variants.insert(
                                (layout.to_string(), name.to_string()),
                                description.trim().to_string(),
                            );
                        }
                    }
                }
                _ => {}
            }
        }
        catalog
    }

    pub fn load(path: &std::path::Path) -> std::io::Result<Catalog> {
        std::fs::read_to_string(path).map(|text| Catalog::parse(&text))
    }

    /// Every layout named is installed, with its variant when one is given.
    pub fn check(&self, layouts: &[Layout]) -> Result<(), KeymapError> {
        for entry in layouts {
            if !self.layouts.contains_key(&entry.layout) {
                return Err(KeymapError::UnknownLayout(entry.layout.clone()));
            }
            if !entry.variant.is_empty()
                && !self
                    .variants
                    .contains_key(&(entry.layout.clone(), entry.variant.clone()))
            {
                return Err(KeymapError::UnknownVariant {
                    layout: entry.layout.clone(),
                    variant: entry.variant.clone(),
                });
            }
        }
        Ok(())
    }

    /// Parse and check in one step: the whole validation.
    pub fn validate(&self, value: &str) -> Result<Vec<Layout>, KeymapError> {
        let layouts = parse(value)?;
        self.check(&layouts)?;
        Ok(layouts)
    }

    /// A person-facing name: `German (no dead keys)`, or the value itself.
    pub fn describe(&self, entry: &Layout) -> String {
        if entry.variant.is_empty() {
            return self
                .layouts
                .get(&entry.layout)
                .cloned()
                .unwrap_or_else(|| entry.layout.clone());
        }
        self.variants
            .get(&(entry.layout.clone(), entry.variant.clone()))
            .cloned()
            .unwrap_or_else(|| entry.to_string())
    }

    /// The variants of one layout, in list order of name.
    pub fn variants_of(&self, layout: &str) -> Vec<(String, String)> {
        self.variants
            .iter()
            .filter(|((owner, _), _)| owner == layout)
            .map(|((_, variant), description)| (variant.clone(), description.clone()))
            .collect()
    }
}

/// The three `input` keys the compositor is given.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionInput {
    pub kb_layout: String,
    pub kb_variant: String,
    pub kb_options: String,
}

/// The groups a session actually loads: Latin first, then the person's
/// choice in order; a Latin layout they chose later is moved to the front
/// rather than duplicated.
pub fn session_groups(chosen: &[Layout]) -> Vec<Layout> {
    if chosen.is_empty() {
        return vec![Layout::new(DEFAULT, "")];
    }
    if !needs_latin_lead(chosen) {
        return chosen.to_vec();
    }
    let mut groups: Vec<Layout> = Vec::with_capacity(chosen.len() + 1);
    match chosen.iter().position(Layout::is_latin) {
        Some(latin) => {
            groups.push(chosen[latin].clone());
            groups.extend(
                chosen
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| *index != latin)
                    .map(|(_, entry)| entry.clone()),
            );
        }
        None => {
            groups.push(Layout::new(LATIN_FALLBACK, ""));
            groups.extend(chosen.iter().cloned());
        }
    }
    groups.truncate(MAX_LAYOUTS);
    groups
}

/// The compositor's `input` values for a chosen value.
pub fn session_input(chosen: &[Layout]) -> SessionInput {
    let groups = session_groups(chosen);
    SessionInput {
        kb_layout: groups
            .iter()
            .map(|g| g.layout.as_str())
            .collect::<Vec<_>>()
            .join(","),
        kb_variant: if groups.iter().all(|g| g.variant.is_empty()) {
            String::new()
        } else {
            groups
                .iter()
                .map(|g| g.variant.as_str())
                .collect::<Vec<_>>()
                .join(",")
        },
        kb_options: if groups.len() > 1 {
            SWITCH_OPTION.to_string()
        } else {
            String::new()
        },
    }
}

/// Whether a rendered value may be written into the input file: the
/// characters the syntax check admits, plus the separators the rendering
/// adds. The compositor applies the same test before it uses a value.
pub fn rendered_value_ok(value: &str) -> bool {
    value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b',' | b':'))
}

/// The session input file: Lua-shaped so a person can read it as one, but
/// data only. `hyprland.lua` never runs it; it matches the three `key =
/// "value"` lines with a pattern and applies [`rendered_value_ok`]'s rule
/// again before using a value.
pub fn render_input_file(chosen: &str, input: &SessionInput) -> String {
    format!(
        "-- Rendered by `punarctl keyboard layout render` from the device's keyboard\n\
         -- layout ({chosen}). DATA ONLY: hyprland.lua reads the three values below\n\
         -- with a pattern and never runs this file. Change it with\n\
         -- `punarctl keyboard layout set`; this copy is rewritten each session.\n\
         return {{\n    kb_layout = \"{}\",\n    kb_variant = \"{}\",\n    kb_options = \"{}\",\n}}\n",
        input.kb_layout, input.kb_variant, input.kb_options
    )
}

/// Read the three values back, with the compositor's rule. Mirrors the Lua
/// reader in `hyprland.lua`, so a test can hold the two to one grammar.
pub fn parse_input_file(text: &str) -> Option<SessionInput> {
    let mut input = SessionInput::default();
    let mut seen = 0;
    for line in text.lines() {
        let line = line.trim();
        for (key, slot) in [
            ("kb_layout", &mut input.kb_layout),
            ("kb_variant", &mut input.kb_variant),
            ("kb_options", &mut input.kb_options),
        ] {
            let Some(rest) = line.strip_prefix(key) else {
                continue;
            };
            let Some(value) = rest
                .trim_start()
                .strip_prefix('=')
                .map(str::trim)
                .and_then(|v| v.strip_prefix('"'))
                .and_then(|v| v.strip_suffix("\","))
            else {
                continue;
            };
            if !rendered_value_ok(value) {
                return None;
            }
            *slot = value.to_string();
            seen += 1;
        }
    }
    (seen == 3 && !input.kb_layout.is_empty()).then_some(input)
}

// ---------------------------------------------------------------------------
// /etc/vconsole.conf
// ---------------------------------------------------------------------------

fn unquote(value: &str) -> &str {
    let value = value.trim();
    for quote in ['"', '\''] {
        if let Some(inner) = value
            .strip_prefix(quote)
            .and_then(|v| v.strip_suffix(quote))
        {
            return inner;
        }
    }
    value
}

/// The value `/etc/vconsole.conf` records, from its `XKBLAYOUT` and
/// `XKBVARIANT` lines. `Ok(None)` when it names no layout (the default
/// applies); `Err` when what it names is not a layout value at all.
pub fn from_vconsole(text: &str) -> Result<Option<String>, KeymapError> {
    let mut layout = None;
    let mut variant = "";
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some(value) = line.strip_prefix("XKBLAYOUT=") {
            layout = Some(unquote(value));
        } else if let Some(value) = line.strip_prefix("XKBVARIANT=") {
            variant = unquote(value);
        }
    }
    let Some(layout) = layout.filter(|l| !l.is_empty()) else {
        return Ok(None);
    };
    let variants: Vec<&str> = variant.split(',').collect();
    let entries: Vec<String> = layout
        .split(',')
        .enumerate()
        .map(|(index, name)| match variants.get(index) {
            Some(v) if !v.is_empty() => format!("{name}+{v}"),
            _ => name.to_string(),
        })
        .collect();
    let value = entries.join(",");
    parse(&value).map(|parsed| Some(format(&parsed)))
}

/// `/etc/vconsole.conf` with the layout lines replaced. Every other line is
/// kept (a console font, say), except `KEYMAP=` and `KEYMAP_TOGGLE=`: a
/// console keymap outranks the XKB lines in systemd-vconsole-setup, and a
/// stale one would leave the text console on a layout nobody chose.
pub fn render_vconsole(existing: &str, layouts: &[Layout]) -> String {
    let mut out = String::from(
        "# The keyboard layout, written by punard for the system.keymap capability.\n\
         # Change it with `punarctl keyboard layout set`; a hand edit is drift and\n\
         # is put back on the next reconcile.\n",
    );
    for line in existing.lines() {
        let trimmed = line.trim();
        let owned = ["XKBLAYOUT=", "XKBVARIANT=", "KEYMAP=", "KEYMAP_TOGGLE="]
            .iter()
            .any(|key| trimmed.starts_with(key));
        let ours = trimmed.starts_with("# The keyboard layout, written by punard")
            || trimmed.starts_with("# Change it with `punarctl keyboard layout set`")
            || trimmed.starts_with("# is put back on the next reconcile.");
        if !owned && !ours && !trimmed.is_empty() {
            out.push_str(line);
            out.push('\n');
        }
    }
    out.push_str(&format!(
        "XKBLAYOUT={}\n",
        layouts
            .iter()
            .map(|l| l.layout.as_str())
            .collect::<Vec<_>>()
            .join(",")
    ));
    if layouts.iter().any(|l| !l.variant.is_empty()) {
        out.push_str(&format!(
            "XKBVARIANT={}\n",
            layouts
                .iter()
                .map(|l| l.variant.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A slice of the real `evdev.lst` (xkb-data 2.48), in its own format.
    pub(crate) const FIXTURE: &str = "\
! model
  pc105           Generic 105-key PC

! layout
  us              English (US)
  gb              English (UK)
  de              German
  fr              French
  ru              Russian
  ua              Ukrainian
  gr              Greek
  jp              Japanese

! variant
  intl            us: English (US, intl., with dead keys)
  nodeadkeys      de: German (no dead keys)
  T3              de: German (T3)
  phonetic        ru: Russian (phonetic)

! option
  grp:alts_toggle      Both Alts together
";

    fn catalog() -> Catalog {
        Catalog::parse(FIXTURE)
    }

    #[test]
    fn values_parse_into_layouts_and_variants() {
        assert_eq!(parse("us").unwrap(), vec![Layout::new("us", "")]);
        assert_eq!(
            parse("de+nodeadkeys,us").unwrap(),
            vec![Layout::new("de", "nodeadkeys"), Layout::new("us", "")]
        );
        assert_eq!(format(&parse("de+T3,ru").unwrap()), "de+T3,ru");
        for bad in [
            "",
            "us,",
            ",us",
            "us+",
            "+intl",
            "us ru",
            "us;ru",
            "us\"",
            "us\n",
            "us\\",
            "-us",
            "us,de,fr,gb,ru",
            "u(s)",
            &"x".repeat(MAX_TOKEN + 1),
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        assert!(matches!(parse("us,us"), Err(KeymapError::Duplicate(_))));
    }

    /// A non-Latin first layout needs a free group for its Latin lead.
    #[test]
    fn a_full_non_latin_list_is_refused_rather_than_truncated() {
        assert!(parse("ru,ua,gr").is_ok());
        assert!(matches!(parse("ru,ua,gr,bg"), Err(KeymapError::TooMany(_))));
        // Latin first: all four groups are the person's.
        assert!(parse("us,ru,ua,gr").is_ok());
    }

    #[test]
    fn the_catalog_admits_only_installed_layouts_and_variants() {
        let catalog = catalog();
        assert_eq!(catalog.layouts.len(), 8);
        assert!(catalog.validate("de+nodeadkeys,us").is_ok());
        assert!(catalog.validate("de+T3").is_ok());
        assert!(matches!(
            catalog.validate("xx"),
            Err(KeymapError::UnknownLayout(_))
        ));
        assert!(matches!(
            catalog.validate("us+nodeadkeys"),
            Err(KeymapError::UnknownVariant { .. })
        ));
        // Model and option lines are not layouts.
        assert!(catalog.validate("pc105").is_err());
        assert_eq!(
            catalog.describe(&Layout::new("de", "nodeadkeys")),
            "German (no dead keys)"
        );
        assert_eq!(catalog.describe(&Layout::new("ru", "")), "Russian");
        assert_eq!(
            catalog.variants_of("de"),
            vec![
                ("T3".to_string(), "German (T3)".to_string()),
                (
                    "nodeadkeys".to_string(),
                    "German (no dead keys)".to_string()
                )
            ]
        );
    }

    /// The acceptance case: a Russian choice still leads with Latin letters,
    /// so PUNAR+Return keeps opening a terminal, and gains the switch chord.
    #[test]
    fn non_latin_layouts_render_with_a_latin_lead_and_the_switch_chord() {
        let ru = session_input(&parse("ru").unwrap());
        assert_eq!(ru.kb_layout, "us,ru");
        assert_eq!(ru.kb_variant, "");
        assert_eq!(ru.kb_options, SWITCH_OPTION);

        let phonetic = session_input(&parse("ru+phonetic").unwrap());
        assert_eq!(phonetic.kb_layout, "us,ru");
        assert_eq!(phonetic.kb_variant, ",phonetic");

        // A Latin layout the person also chose leads instead of a new `us`.
        let ru_de = session_input(&parse("ru,de+nodeadkeys").unwrap());
        assert_eq!(ru_de.kb_layout, "de,ru");
        assert_eq!(ru_de.kb_variant, "nodeadkeys,");

        let de = session_input(&parse("de").unwrap());
        assert_eq!(de.kb_layout, "de");
        assert_eq!(de.kb_options, "", "one layout needs no switch chord");

        let us_ru = session_input(&parse("us,ru").unwrap());
        assert_eq!(us_ru.kb_layout, "us,ru");
        assert_eq!(us_ru.kb_options, SWITCH_OPTION);
    }

    #[test]
    fn every_non_latin_entry_is_a_plausible_layout_name() {
        for layout in NON_LATIN {
            assert!(token_ok(layout), "{layout}");
            assert!(!Layout::new(layout, "").is_latin());
        }
        for latin in ["us", "gb", "de", "fr", "jp", "cn", "kr", "tr", "vn"] {
            assert!(Layout::new(latin, "").is_latin(), "{latin}");
        }
    }

    #[test]
    fn the_input_file_round_trips_and_refuses_anything_but_data() {
        let input = session_input(&parse("ru+phonetic").unwrap());
        let text = render_input_file("ru+phonetic", &input);
        assert_eq!(parse_input_file(&text), Some(input));
        assert!(parse_input_file("return {}").is_none());
        let hostile =
            "kb_layout = \"us\\\"; os.execute('x') --\",\nkb_variant = \"\",\nkb_options = \"\",\n";
        assert!(parse_input_file(hostile).is_none());
        assert!(!rendered_value_ok("us\"x"));
        assert!(!rendered_value_ok("us x"));
        assert!(rendered_value_ok("us,ru"));
        assert!(rendered_value_ok("grp:alts_toggle"));
        assert!(rendered_value_ok(""));
    }

    #[test]
    fn vconsole_round_trips_and_keeps_unrelated_lines() {
        assert_eq!(from_vconsole(""), Ok(None));
        assert_eq!(from_vconsole("FONT=ter-v16n\n"), Ok(None));
        assert_eq!(
            from_vconsole("XKBLAYOUT=\"de,us\"\nXKBVARIANT=nodeadkeys,\n"),
            Ok(Some("de+nodeadkeys,us".to_string()))
        );
        assert_eq!(from_vconsole("XKBLAYOUT=ru\n"), Ok(Some("ru".to_string())));
        assert!(from_vconsole("XKBLAYOUT=us;rm -rf\n").is_err());
        assert_eq!(
            from_vconsole("# XKBLAYOUT=de\nXKBLAYOUT=fr\n"),
            Ok(Some("fr".to_string()))
        );

        let written = render_vconsole(
            "FONT=ter-v16n\nKEYMAP=us\nXKBLAYOUT=us\nXKBMODEL=pc105\n",
            &parse("de+nodeadkeys,us").unwrap(),
        );
        assert!(written.contains("FONT=ter-v16n\n"));
        assert!(written.contains("XKBMODEL=pc105\n"));
        assert!(!written.contains("KEYMAP="));
        assert!(written.contains("XKBLAYOUT=de,us\n"));
        assert!(written.contains("XKBVARIANT=nodeadkeys,\n"));
        assert_eq!(
            from_vconsole(&written),
            Ok(Some("de+nodeadkeys,us".to_string()))
        );
        // Rewriting its own output is stable: the header is not duplicated.
        let again = render_vconsole(&written, &parse("fr").unwrap());
        assert_eq!(again.matches("written by punard").count(), 1);
        assert!(!again.contains("XKBVARIANT"));
        assert_eq!(from_vconsole(&again), Ok(Some("fr".to_string())));
    }
}
