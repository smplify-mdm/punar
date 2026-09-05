//! Small, bounded UKI semantic parser shared by install and update admission.
//!
//! A signed digest proves which bytes were supplied; it does not prove that
//! those bytes boot the slot selected by the transaction.  This module reads
//! the PE section table without executing an external tool and requires the
//! kernel command line to contain one, and only one, exact `root=` selector.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

const DOS_HEADER_BYTES: usize = 64;
const PE_HEADER_BYTES: usize = 24;
const PE_SECTION_BYTES: u64 = 40;
const PE_SECTIONS_MAX: u64 = 96;
const UKI_SECTION_MAX: u64 = 64 * 1024;

pub(crate) fn require_root_partuuid(
    file: &mut File,
    expected_partuuid: &str,
) -> Result<(), String> {
    let cmdline = pe_section(file, b".cmdline")?;
    let first_nul = cmdline
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(cmdline.len());
    if cmdline[first_nul..].iter().any(|byte| *byte != 0) {
        return Err("UKI command line has non-zero data after its terminator".into());
    }
    let text = std::str::from_utf8(&cmdline[..first_nul])
        .map_err(|_| "UKI command line is not UTF-8".to_string())?;
    let roots = text
        .split_ascii_whitespace()
        .filter(|token| token.starts_with("root="))
        .collect::<Vec<_>>();
    let expected = format!("root=PARTUUID={expected_partuuid}");
    if roots.as_slice() != [expected.as_str()] {
        return Err(format!(
            "UKI must contain exactly one root selector equal to {expected}"
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn pe_section(file: &mut File, wanted: &[u8]) -> Result<Vec<u8>, String> {
    let length = file.metadata().map_err(|error| error.to_string())?.len();
    file.seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    let mut dos = [0_u8; DOS_HEADER_BYTES];
    file.read_exact(&mut dos)
        .map_err(|_| "boot artifact has a truncated DOS/PE header".to_string())?;
    if &dos[..2] != b"MZ" {
        return Err("boot artifact has no DOS/PE header".into());
    }
    let pe_offset = u64::from(u32::from_le_bytes(dos[60..64].try_into().unwrap()));
    if pe_offset > length.saturating_sub(PE_HEADER_BYTES as u64) {
        return Err("PE header offset is outside the artifact".into());
    }
    file.seek(SeekFrom::Start(pe_offset))
        .map_err(|error| error.to_string())?;
    let mut header = [0_u8; PE_HEADER_BYTES];
    file.read_exact(&mut header)
        .map_err(|_| "PE header is truncated".to_string())?;
    if &header[..4] != b"PE\0\0" {
        return Err("boot artifact has no PE signature".into());
    }
    let sections = u64::from(u16::from_le_bytes(header[6..8].try_into().unwrap()));
    let optional = u64::from(u16::from_le_bytes(header[20..22].try_into().unwrap()));
    if sections == 0 || sections > PE_SECTIONS_MAX {
        return Err("PE section count is invalid".into());
    }
    let table = pe_offset
        .checked_add(PE_HEADER_BYTES as u64)
        .and_then(|offset| offset.checked_add(optional))
        .ok_or_else(|| "PE section table offset overflow".to_string())?;
    if table.saturating_add(sections * PE_SECTION_BYTES) > length {
        return Err("PE section table is truncated".into());
    }
    file.seek(SeekFrom::Start(table))
        .map_err(|error| error.to_string())?;
    for _ in 0..sections {
        let mut section = [0_u8; PE_SECTION_BYTES as usize];
        file.read_exact(&mut section)
            .map_err(|_| "PE section table changed while it was read".to_string())?;
        let name_end = section[..8].iter().position(|byte| *byte == 0).unwrap_or(8);
        if &section[..name_end] != wanted {
            continue;
        }
        let size = u64::from(u32::from_le_bytes(section[16..20].try_into().unwrap()));
        let offset = u64::from(u32::from_le_bytes(section[20..24].try_into().unwrap()));
        if size == 0 || size > UKI_SECTION_MAX || offset.saturating_add(size) > length {
            return Err("PE command-line section is invalid".into());
        }
        let mut bytes = vec![0_u8; size as usize];
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| error.to_string())?;
        file.read_exact(&mut bytes)
            .map_err(|_| "PE command-line section changed while it was read".to_string())?;
        return Ok(bytes);
    }
    Err("UKI has no .cmdline section".into())
}

#[cfg(test)]
pub(crate) fn fixture_uki(cmdline: &str) -> Vec<u8> {
    let section_offset = 512_u32;
    let mut bytes = vec![0_u8; section_offset as usize + cmdline.len() + 1];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[60..64].copy_from_slice(&64_u32.to_le_bytes());
    bytes[64..68].copy_from_slice(b"PE\0\0");
    bytes[70..72].copy_from_slice(&1_u16.to_le_bytes());
    bytes[84..86].copy_from_slice(&0_u16.to_le_bytes());
    bytes[88..96].copy_from_slice(b".cmdline");
    bytes[104..108].copy_from_slice(&(cmdline.len() as u32 + 1).to_le_bytes());
    bytes[108..112].copy_from_slice(&section_offset.to_le_bytes());
    bytes[section_offset as usize..section_offset as usize + cmdline.len()]
        .copy_from_slice(cmdline.as_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn open_fixture(bytes: &[u8]) -> File {
        let path = std::env::temp_dir().join(format!(
            "punar-uki-parser-{}-{}",
            std::process::id(),
            crate::util::sha256_hex(bytes)
        ));
        let mut file = File::create(&path).unwrap();
        file.write_all(bytes).unwrap();
        drop(file);
        let opened = File::open(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        opened
    }

    #[test]
    fn requires_one_exact_root_selector() {
        let expected = "1beabfe0-9cb8-4b49-91ef-d372b845e7ea";
        let mut good = open_fixture(&fixture_uki(&format!("quiet root=PARTUUID={expected} rw")));
        require_root_partuuid(&mut good, expected).unwrap();

        for cmdline in [
            "quiet root=/dev/vda2".to_string(),
            "quiet root=PARTUUID=wrong".to_string(),
            format!("root=PARTUUID={expected} root=/dev/vda3"),
        ] {
            let mut file = open_fixture(&fixture_uki(&cmdline));
            assert!(require_root_partuuid(&mut file, expected).is_err());
        }
    }
}
