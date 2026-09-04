//! Browser-context and user-created web-application wire types.
//!
//! Milestone 11 composes upstream Chromium; it does not patch or embed it.
//! These types deliberately carry application identity and browser state
//! selection, never a command line. The only executable vocabulary belongs
//! to `punarctl`'s closed Chromium argv builder.

use serde::{Deserialize, Serialize};

/// The single on-disk and wire format version shipped by M11.
pub const WEBAPP_VERSION: u64 = 1;
/// A web-app name or browser-context display name is intentionally compact.
pub const DISPLAY_NAME_MAX_CHARS: usize = 32;
/// URLs must fit comfortably inside the 4096-byte IPC request limit.
pub const START_URL_MAX_BYTES: usize = 2048;
/// A caller-supplied PNG is bounded before the privileged daemon reads it.
pub const MAX_ICON_BYTES: u64 = 64 * 1024;

/// The icon requested by an install manifest. File contents never travel in
/// the request frame; the daemon opens a regular file safely and returns the
/// verified bytes as a derived artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WebAppIconRequest {
    Generated,
    File { path: String },
}

/// User- or policy-supplied install document. Server-assigned provenance,
/// timestamps, policy citations and the final icon digest are absent by
/// construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebAppManifest {
    pub v: u64,
    pub id: String,
    pub name: String,
    pub start_url: String,
    pub context: String,
    pub workspace: String,
    pub icon: WebAppIconRequest,
}

/// How an app entered the root-owned inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebAppInstallSource {
    Cli,
    Policy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebAppInstalledBy {
    pub uid: u32,
    pub source: WebAppInstallSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebAppIconKind {
    Generated,
    File,
}

/// Verified icon identity in a complete app record. The path is relative to
/// `$XDG_DATA_HOME`, so root-owned state never records a user's home path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebAppIcon {
    pub kind: WebAppIconKind,
    pub sha256: String,
    pub path_rel: String,
}

/// Root-owned inventory record. User-home launchers and icons are derived
/// from this object and may be rebuilt without changing its identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebAppRecord {
    pub v: u64,
    pub id: String,
    pub name: String,
    pub start_url: String,
    pub origin: String,
    pub context: String,
    pub icon: WebAppIcon,
    pub workspace: String,
    pub installed_at: String,
    pub installed_by: WebAppInstalledBy,
    pub policy_ids: Vec<String>,
    pub managed: bool,
}

/// Browser storage context. This is state isolation within one Unix uid, not
/// a kernel security boundary; the API names the isolated categories rather
/// than applying an ambiguous `sandboxed` label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserContext {
    pub id: String,
    pub name: String,
    pub derived: bool,
    pub deletable: bool,
    pub isolates: Vec<String>,
    pub profile_path_rel: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub simulated: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_yet_observed: Vec<NotYetObserved>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotYetObserved {
    pub category: String,
    pub milestone: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebAppArtifacts {
    pub desktop_entry: String,
    pub desktop_path_rel: String,
    pub icon_png_b64: String,
    pub icon_path_rel: String,
    pub window_rule: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebAppEnforcement {
    pub point: String,
    pub managed: bool,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebAppInstallResult {
    pub app: WebAppRecord,
    pub artifacts: WebAppArtifacts,
    pub enforcement: WebAppEnforcement,
}

/// Validate the fields whose grammar is shared by client and daemon.
pub fn validate_manifest(manifest: &WebAppManifest) -> Result<(), String> {
    if manifest.v != WEBAPP_VERSION {
        return Err(format!(
            "web-app manifest version {} is unsupported; expected {WEBAPP_VERSION}",
            manifest.v
        ));
    }
    validate_id(&manifest.id, "web-app id")?;
    validate_display_name(&manifest.name, "web-app name")?;
    origin_from_start_url(&manifest.start_url)?;
    validate_context_id(&manifest.context)?;
    validate_workspace_name(&manifest.workspace)?;
    if let WebAppIconRequest::File { path } = &manifest.icon {
        validate_icon_path(path)?;
    }
    Ok(())
}

/// `^[a-z0-9][a-z0-9-]{0,31}$`, without pulling a regex engine into every
/// Punar process.
pub fn validate_id(value: &str, label: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return Err(format!("{label} must contain 1 to 32 ASCII characters"));
    }
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return Err(format!(
            "{label} must begin with a lowercase letter or digit"
        ));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        return Err(format!(
            "{label} may contain only lowercase letters, digits, and hyphens"
        ));
    }
    Ok(())
}

pub fn validate_context_id(value: &str) -> Result<(), String> {
    validate_id(value, "browser context id")
}

/// Display names and workspace names share the milestone-2 grammar.
pub fn validate_display_name(value: &str, label: &str) -> Result<(), String> {
    let chars: Vec<char> = value.chars().collect();
    if chars.is_empty() || chars.len() > DISPLAY_NAME_MAX_CHARS {
        return Err(format!(
            "{label} must contain 1 to {DISPLAY_NAME_MAX_CHARS} characters"
        ));
    }
    if !chars[0].is_ascii_alphanumeric() {
        return Err(format!("{label} must begin with a letter or digit"));
    }
    if !chars
        .iter()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-'))
    {
        return Err(format!(
            "{label} may contain only ASCII letters, digits, spaces, underscores, and hyphens"
        ));
    }
    Ok(())
}

pub fn validate_workspace_name(value: &str) -> Result<(), String> {
    validate_display_name(value, "workspace name")
}

/// Derive the origin while rejecting strings that could be interpreted as a
/// Chromium flag, contain credentials, or escape the offline fixture tree
/// through a parent component. M11 intentionally supports only HTTPS and
/// absolute local `file:///` URLs.
pub fn origin_from_start_url(value: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > START_URL_MAX_BYTES {
        return Err(format!(
            "start URL must contain 1 to {START_URL_MAX_BYTES} bytes"
        ));
    }
    if !value.is_ascii()
        || value
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        || value.contains('\0')
        || value.contains('\\')
        || value.contains("--")
    {
        return Err("start URL contains unsafe characters or a flag-like token".to_string());
    }
    if let Some(rest) = value.strip_prefix("https://") {
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        if authority.is_empty() || authority.contains('@') {
            return Err("HTTPS start URL must have a host and may not contain credentials".into());
        }
        validate_https_authority(authority)?;
        return Ok(format!("https://{}", authority.to_ascii_lowercase()));
    }
    if let Some(path) = value.strip_prefix("file://") {
        if !path.starts_with('/') || path == "/" {
            return Err("file start URL must name an absolute file".into());
        }
        let path_only = path.split(['?', '#']).next().unwrap_or(path);
        if path_only.split('/').any(|part| part == "..") {
            return Err("file start URL may not contain a parent path component".into());
        }
        return Ok("file://".to_string());
    }
    Err("start URL must use https:// or file:///".to_string())
}

/// Reproduce the native Wayland application id Chromium assigns to a
/// `--app=<url>` shortcut window on Linux.
///
/// Chromium does not use `--class` for these native Ozone/Wayland windows. It
/// derives the xdg app id from `{host}_{path}`, the executable name and the
/// default profile basename instead. Keeping this derivation beside the URL
/// validator lets the compositor rule target the identity the upstream browser
/// actually publishes, without launching Chromium or trusting page-controlled
/// titles.
pub fn chromium_wayland_app_id(value: &str) -> Result<String, String> {
    origin_from_start_url(value)?;

    let (host, path) = if let Some(rest) = value.strip_prefix("https://") {
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        let host = if authority.starts_with('[') {
            authority
                .find(']')
                .map(|end| &authority[..=end])
                .unwrap_or(authority)
        } else {
            authority
                .rsplit_once(':')
                .filter(|(_, port)| port.bytes().all(|byte| byte.is_ascii_digit()))
                .map(|(host, _)| host)
                .unwrap_or(authority)
        };
        let suffix = &rest[authority_end..];
        let path = if suffix.starts_with('/') {
            suffix.split(['?', '#']).next().unwrap_or("/")
        } else {
            "/"
        };
        (host.to_ascii_lowercase(), path)
    } else {
        let path = value
            .strip_prefix("file://")
            .expect("origin validation accepted only HTTPS or file URLs")
            .split(['?', '#'])
            .next()
            .unwrap_or("/");
        (String::new(), path)
    };

    let app_name = format!("{host}_{path}");
    // `ReplaceIllegalCharactersInPath` is the last upstream step before the
    // shortcut filename becomes the xdg app id. Punar's URL grammar is ASCII
    // and already rejects controls, formatting characters, whitespace and
    // backslashes, so this is the complete remaining intersection with
    // Chromium's filename-illegal set.
    let sanitized: String = app_name
        .chars()
        .map(|character| {
            if matches!(
                character,
                '"' | '*' | '/' | ':' | '<' | '>' | '?' | '\\' | '|'
            ) {
                '_'
            } else {
                character
            }
        })
        .collect();
    Ok(format!("chrome-{sanitized}-Default"))
}

fn validate_https_authority(authority: &str) -> Result<(), String> {
    if authority.starts_with('[') {
        let Some(close) = authority.find(']') else {
            return Err("HTTPS start URL has an invalid IPv6 host".into());
        };
        if close == 1 {
            return Err("HTTPS start URL has an empty IPv6 host".into());
        }
        if !authority[1..close]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b':')
        {
            return Err("HTTPS start URL has an invalid IPv6 host".into());
        }
        let suffix = &authority[close + 1..];
        return validate_optional_port(suffix);
    }
    let (host, suffix) = match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            (host, &authority[host.len()..])
        }
        Some(_) if authority.contains(':') => {
            return Err("HTTPS start URL has an invalid port".into());
        }
        Some(_) => (authority, ""),
        None => (authority, ""),
    };
    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
    {
        return Err("HTTPS start URL has an invalid host".into());
    }
    validate_optional_port(suffix)
}

fn validate_optional_port(suffix: &str) -> Result<(), String> {
    if suffix.is_empty() {
        return Ok(());
    }
    let Some(port) = suffix.strip_prefix(':') else {
        return Err("HTTPS start URL has invalid text after its host".into());
    };
    let number = port
        .parse::<u16>()
        .map_err(|_| "HTTPS start URL port must be between 1 and 65535".to_string())?;
    if number == 0 {
        return Err("HTTPS start URL port must be between 1 and 65535".into());
    }
    Ok(())
}

fn validate_icon_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') || path.len() > 1024 || path.contains('\0') {
        return Err("icon path must be an absolute path of at most 1024 bytes".into());
    }
    if path.split('/').any(|part| part == "..") {
        return Err("icon path may not contain a parent path component".into());
    }
    Ok(())
}

pub fn personal_context() -> BrowserContext {
    BrowserContext {
        id: "personal".into(),
        name: "Personal".into(),
        derived: false,
        deletable: false,
        isolates: vec![
            "cookies".into(),
            "storage".into(),
            "sign_ins".into(),
            "history".into(),
            "extensions".into(),
        ],
        profile_path_rel: "punar/browser/contexts/personal".into(),
        simulated: Vec::new(),
        not_yet_observed: Vec::new(),
        source: None,
    }
}

/// Render the deterministic 256×256 RGB8 monogram used when no local icon is
/// supplied. The encoder is deliberately self-contained: a zlib stream with
/// stored DEFLATE blocks plus PNG CRC/adler checksums, so M11 does not add an
/// image-processing supply-chain dependency.
pub fn render_monogram_png(name: &str, origin: &str) -> Vec<u8> {
    const WIDTH: usize = 256;
    const HEIGHT: usize = 256;
    const PAPER: [u8; 3] = [0xfa, 0xf9, 0xf6];
    const INK: [u8; 3] = [0x11, 0x13, 0x16];

    let mut pixels = vec![PAPER[0]; WIDTH * HEIGHT * 3];
    for pixel in pixels.chunks_exact_mut(3) {
        pixel.copy_from_slice(&PAPER);
    }
    fill_rect(&mut pixels, WIDTH, 24, 24, 232, 26, INK);

    let mut initials: Vec<char> = name
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter_map(|word| word.chars().next())
        .map(|c| c.to_ascii_uppercase())
        .take(2)
        .collect();
    if initials.is_empty() {
        initials = origin
            .bytes()
            .filter(|b| b.is_ascii_alphanumeric())
            .take(2)
            .map(|b| (b as char).to_ascii_uppercase())
            .collect();
    }
    if initials.is_empty() {
        initials.push('W');
    }
    if initials.len() == 1 {
        if let Some(second) = name.chars().skip(1).find(|c| c.is_ascii_alphanumeric()) {
            initials.push(second.to_ascii_uppercase());
        }
    }

    let scale = 18usize;
    let glyph_width = 5 * scale;
    let gap = 12usize;
    let total_width = initials.len() * glyph_width + initials.len().saturating_sub(1) * gap;
    let start_x = (WIDTH.saturating_sub(total_width)) / 2;
    let start_y = (HEIGHT - 7 * scale) / 2 + 8;
    for (index, initial) in initials.iter().enumerate() {
        draw_glyph(
            &mut pixels,
            WIDTH,
            start_x + index * (glyph_width + gap),
            start_y,
            scale,
            glyph(*initial),
            INK,
        );
    }

    let mut scanlines = Vec::with_capacity((WIDTH * 3 + 1) * HEIGHT);
    for row in pixels.chunks_exact(WIDTH * 3) {
        scanlines.push(0); // PNG filter: None
        scanlines.extend_from_slice(row);
    }
    let compressed = zlib_stored(&scanlines);

    let mut png = Vec::with_capacity(compressed.len() + 57);
    png.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&(WIDTH as u32).to_be_bytes());
    ihdr.extend_from_slice(&(HEIGHT as u32).to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // RGB8, deflate, adaptive filters
    png_chunk(&mut png, b"IHDR", &ihdr);
    png_chunk(&mut png, b"IDAT", &compressed);
    png_chunk(&mut png, b"IEND", &[]);
    png
}

fn fill_rect(
    pixels: &mut [u8],
    width: usize,
    x0: usize,
    y0: usize,
    x1: usize,
    y1: usize,
    color: [u8; 3],
) {
    for y in y0..y1 {
        for x in x0..x1 {
            let offset = (y * width + x) * 3;
            pixels[offset..offset + 3].copy_from_slice(&color);
        }
    }
}

fn draw_glyph(
    pixels: &mut [u8],
    width: usize,
    x: usize,
    y: usize,
    scale: usize,
    rows: [u8; 7],
    color: [u8; 3],
) {
    for (row, bits) in rows.into_iter().enumerate() {
        for col in 0..5 {
            if bits & (1 << (4 - col)) != 0 {
                fill_rect(
                    pixels,
                    width,
                    x + col * scale,
                    y + row * scale,
                    x + (col + 1) * scale,
                    y + (row + 1) * scale,
                    color,
                );
            }
        }
    }
}

#[rustfmt::skip]
fn glyph(c: char) -> [u8; 7] {
    match c {
        'A' => [0b01110,0b10001,0b10001,0b11111,0b10001,0b10001,0b10001],
        'B' => [0b11110,0b10001,0b10001,0b11110,0b10001,0b10001,0b11110],
        'C' => [0b01111,0b10000,0b10000,0b10000,0b10000,0b10000,0b01111],
        'D' => [0b11110,0b10001,0b10001,0b10001,0b10001,0b10001,0b11110],
        'E' => [0b11111,0b10000,0b10000,0b11110,0b10000,0b10000,0b11111],
        'F' => [0b11111,0b10000,0b10000,0b11110,0b10000,0b10000,0b10000],
        'G' => [0b01111,0b10000,0b10000,0b10111,0b10001,0b10001,0b01111],
        'H' => [0b10001,0b10001,0b10001,0b11111,0b10001,0b10001,0b10001],
        'I' => [0b11111,0b00100,0b00100,0b00100,0b00100,0b00100,0b11111],
        'J' => [0b00111,0b00010,0b00010,0b00010,0b10010,0b10010,0b01100],
        'K' => [0b10001,0b10010,0b10100,0b11000,0b10100,0b10010,0b10001],
        'L' => [0b10000,0b10000,0b10000,0b10000,0b10000,0b10000,0b11111],
        'M' => [0b10001,0b11011,0b10101,0b10101,0b10001,0b10001,0b10001],
        'N' => [0b10001,0b11001,0b11001,0b10101,0b10011,0b10011,0b10001],
        'O' => [0b01110,0b10001,0b10001,0b10001,0b10001,0b10001,0b01110],
        'P' => [0b11110,0b10001,0b10001,0b11110,0b10000,0b10000,0b10000],
        'Q' => [0b01110,0b10001,0b10001,0b10001,0b10101,0b10010,0b01101],
        'R' => [0b11110,0b10001,0b10001,0b11110,0b10100,0b10010,0b10001],
        'S' => [0b01111,0b10000,0b10000,0b01110,0b00001,0b00001,0b11110],
        'T' => [0b11111,0b00100,0b00100,0b00100,0b00100,0b00100,0b00100],
        'U' => [0b10001,0b10001,0b10001,0b10001,0b10001,0b10001,0b01110],
        'V' => [0b10001,0b10001,0b10001,0b10001,0b10001,0b01010,0b00100],
        'W' => [0b10001,0b10001,0b10001,0b10101,0b10101,0b10101,0b01010],
        'X' => [0b10001,0b10001,0b01010,0b00100,0b01010,0b10001,0b10001],
        'Y' => [0b10001,0b10001,0b01010,0b00100,0b00100,0b00100,0b00100],
        'Z' => [0b11111,0b00001,0b00010,0b00100,0b01000,0b10000,0b11111],
        '0' => [0b01110,0b10001,0b10011,0b10101,0b11001,0b10001,0b01110],
        '1' => [0b00100,0b01100,0b00100,0b00100,0b00100,0b00100,0b01110],
        '2' => [0b01110,0b10001,0b00001,0b00010,0b00100,0b01000,0b11111],
        '3' => [0b11110,0b00001,0b00001,0b01110,0b00001,0b00001,0b11110],
        '4' => [0b00010,0b00110,0b01010,0b10010,0b11111,0b00010,0b00010],
        '5' => [0b11111,0b10000,0b10000,0b11110,0b00001,0b00001,0b11110],
        '6' => [0b01110,0b10000,0b10000,0b11110,0b10001,0b10001,0b01110],
        '7' => [0b11111,0b00001,0b00010,0b00100,0b01000,0b01000,0b01000],
        '8' => [0b01110,0b10001,0b10001,0b01110,0b10001,0b10001,0b01110],
        '9' => [0b01110,0b10001,0b10001,0b01111,0b00001,0b00001,0b01110],
        _ =>   [0b11111,0b10001,0b00010,0b00100,0b00100,0b00000,0b00100],
    }
}

fn zlib_stored(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + input.len() / 65_535 * 5 + 16);
    out.extend_from_slice(&[0x78, 0x01]); // zlib, fastest/no compression
    for (index, block) in input.chunks(65_535).enumerate() {
        let final_block = index + 1 == input.len().div_ceil(65_535);
        out.push(u8::from(final_block)); // BFINAL + BTYPE=00, byte-aligned
        let len = block.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(block);
    }
    out.extend_from_slice(&adler32(input).to_be_bytes());
    out
}

fn adler32(bytes: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for byte in bytes {
        a = (a + u32::from(*byte)) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

fn png_chunk(output: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    output.extend_from_slice(&(data.len() as u32).to_be_bytes());
    output.extend_from_slice(kind);
    output.extend_from_slice(data);
    let mut checked = Vec::with_capacity(kind.len() + data.len());
    checked.extend_from_slice(kind);
    checked.extend_from_slice(data);
    output.extend_from_slice(&crc32(&checked).to_be_bytes());
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> WebAppManifest {
        WebAppManifest {
            v: 1,
            id: "linear".into(),
            name: "Linear".into(),
            start_url: "https://linear.app/inbox".into(),
            context: "atlas".into(),
            workspace: "atlas".into(),
            icon: WebAppIconRequest::Generated,
        }
    }

    #[test]
    fn manifest_and_origins_are_strict() {
        assert!(validate_manifest(&manifest()).is_ok());
        assert_eq!(
            origin_from_start_url("https://Linear.App:443/inbox?x=1").unwrap(),
            "https://linear.app:443"
        );
        assert_eq!(
            origin_from_start_url("file:///usr/share/punar/notes/index.html").unwrap(),
            "file://"
        );

        for bad in [
            "http://linear.app",
            "https://user@linear.app",
            "https://linear.app/--no-sandbox",
            "file://relative",
            "file:///tmp/../etc/shadow",
            "https://linear.app\\@evil.test",
        ] {
            assert!(origin_from_start_url(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn chromium_wayland_identity_matches_the_upstream_shortcut_algorithm() {
        assert_eq!(
            chromium_wayland_app_id("https://linear.app").unwrap(),
            "chrome-linear.app__-Default"
        );
        assert_eq!(
            chromium_wayland_app_id("https://Example.COM:8443/inbox/today?view=all").unwrap(),
            "chrome-example.com__inbox_today-Default"
        );
        assert_eq!(
            chromium_wayland_app_id("file:///usr/share/punar/fixtures/webapps/notes/index.html")
                .unwrap(),
            "chrome-__usr_share_punar_fixtures_webapps_notes_index.html-Default"
        );
        assert_eq!(
            chromium_wayland_app_id("https://example.com/a:b*c").unwrap(),
            "chrome-example.com__a_b_c-Default"
        );
        assert!(chromium_wayland_app_id("http://example.com").is_err());
    }

    #[test]
    fn identifiers_and_display_names_match_the_contract() {
        for valid in ["a", "notes", "org-acme", "x1"] {
            assert!(validate_id(valid, "id").is_ok(), "rejected {valid:?}");
        }
        for invalid in ["", "-notes", "Notes", "notes_app", "notes/app"] {
            assert!(validate_id(invalid, "id").is_err(), "accepted {invalid:?}");
        }
        assert!(validate_display_name("Acme Work_2", "name").is_ok());
        assert!(validate_display_name(" Acme", "name").is_err());
        assert!(validate_display_name("Acme!", "name").is_err());
    }

    #[test]
    fn request_types_reject_unknown_fields() {
        let value = serde_json::json!({
            "v": 1,
            "id": "notes",
            "name": "Notes",
            "start_url": "file:///usr/share/punar/notes.html",
            "context": "personal",
            "workspace": "notes",
            "icon": {"kind": "generated"},
            "command": "sh -c anything"
        });
        assert!(serde_json::from_value::<WebAppManifest>(value).is_err());
    }

    #[test]
    fn personal_context_names_state_isolation_without_overclaiming() {
        let context = personal_context();
        assert!(!context.deletable);
        assert!(context.isolates.contains(&"cookies".to_string()));
        let json = serde_json::to_string(&context).unwrap();
        assert!(!json.contains("sandbox"));
        assert!(!json.contains("security_boundary"));
    }

    #[test]
    fn generated_monogram_is_deterministic_rgb8_png() {
        let first = render_monogram_png("Linear", "https://linear.app");
        let second = render_monogram_png("Linear", "https://linear.app");
        let other = render_monogram_png("Notes", "file://");
        assert_eq!(first, second);
        assert_ne!(first, other);
        assert_eq!(&first[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(&first[12..16], b"IHDR");
        assert_eq!(u32::from_be_bytes(first[16..20].try_into().unwrap()), 256);
        assert_eq!(u32::from_be_bytes(first[20..24].try_into().unwrap()), 256);
        assert_eq!(first[24], 8);
        assert_eq!(first[25], 2);
        assert!(first.len() < 200_000, "unexpectedly large: {}", first.len());
    }
}
