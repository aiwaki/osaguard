//! Structural validation for already signature-verified macOS updater archives.
//!
//! A valid Tauri signature proves which updater key produced the bytes. It does
//! not bind an archive's embedded bundle version to the release metadata that
//! selected it. Inspect the bounded archive before the watcher is stopped and
//! before Tauri is allowed to extract or replace the installed application.

use flate2::bufread::GzDecoder;
use flate2::read::GzDecoder as ReadGzDecoder;
use plist::Value;
use std::collections::HashSet;
use std::fs;
use std::io::{BufReader, Cursor, Read};
use std::path::{Path, PathBuf};

const APP_ROOT: &[u8] = b"OsaGuard.app";
const INFO_PLIST_PATH: &[u8] = b"OsaGuard.app/Contents/Info.plist";
const EXPECTED_BUNDLE_IDENTIFIER: &str = "dev.aiwaki.osaguard";
const MAX_COMPRESSED_BYTES: usize = 128 * 1024 * 1024;
const MAX_UNCOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ENTRY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_INFO_PLIST_BYTES: u64 = 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 16_384;
const MAX_PATH_BYTES: usize = 1024;
const MAX_TAR_END_PADDING_BYTES: u64 = 64 * 1024;

#[derive(Default)]
struct ArchiveBudget {
    entries: usize,
    uncompressed_bytes: u64,
}

impl ArchiveBudget {
    fn observe(&mut self, size: u64) -> Result<(), String> {
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or_else(|| "update archive entry count overflow".to_owned())?;
        if self.entries > MAX_ARCHIVE_ENTRIES {
            return Err("update archive has too many entries".into());
        }
        if size > MAX_ENTRY_BYTES {
            return Err("update archive entry exceeds the size limit".into());
        }
        self.uncompressed_bytes = self
            .uncompressed_bytes
            .checked_add(size)
            .ok_or_else(|| "update archive size overflow".to_owned())?;
        if self.uncompressed_bytes > MAX_UNCOMPRESSED_BYTES {
            return Err("update archive exceeds the uncompressed size limit".into());
        }
        Ok(())
    }
}

fn validate_compressed_size(size: usize) -> Result<(), String> {
    if size == 0 || size > MAX_COMPRESSED_BYTES {
        return Err("update archive exceeds the compressed size limit".into());
    }
    Ok(())
}

fn canonical_archive_path(path: &[u8], is_directory: bool) -> Result<Vec<u8>, String> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || path.starts_with(b"/")
        || path.contains(&0)
        || path.contains(&b'\\')
    {
        return Err("update archive contains an unsafe path".into());
    }

    let mut parts = path.split(|byte| *byte == b'/').collect::<Vec<_>>();
    if is_directory && parts.last().is_some_and(|part| part.is_empty()) {
        parts.pop();
    }
    if parts.is_empty()
        || parts[0] != APP_ROOT
        || parts
            .iter()
            .any(|part| part.is_empty() || *part == b"." || *part == b"..")
    {
        return Err("update archive contains a path outside OsaGuard.app".into());
    }

    let mut canonical = Vec::with_capacity(path.len());
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            canonical.push(b'/');
        }
        canonical.extend_from_slice(part);
    }
    Ok(canonical)
}

fn validate_info_plist(bytes: &[u8], expected_version: &str) -> Result<(), String> {
    let value = Value::from_reader(Cursor::new(bytes))
        .map_err(|error| format!("update Info.plist is invalid: {error}"))?;
    let dictionary = value
        .as_dictionary()
        .ok_or_else(|| "update Info.plist is not a dictionary".to_owned())?;
    let identifier = dictionary
        .get("CFBundleIdentifier")
        .and_then(Value::as_string)
        .ok_or_else(|| "update Info.plist has no bundle identifier".to_owned())?;
    if identifier != EXPECTED_BUNDLE_IDENTIFIER {
        return Err("update archive bundle identifier mismatch".into());
    }
    let version = dictionary
        .get("CFBundleShortVersionString")
        .and_then(Value::as_string)
        .ok_or_else(|| "update Info.plist has no short version".to_owned())?;
    if version != expected_version {
        return Err("update archive version mismatch".into());
    }
    Ok(())
}

pub fn validate_update_archive(bytes: &[u8], expected_version: &str) -> Result<(), String> {
    validate_compressed_size(bytes.len())?;

    let cursor = Cursor::new(bytes);
    let buffered = BufReader::new(cursor);
    let decoder = GzDecoder::new(buffered);
    let mut archive = tar::Archive::new(decoder);
    let mut seen_paths = HashSet::new();
    let mut budget = ArchiveBudget::default();
    let mut info_plist_count = 0_usize;

    for entry in archive
        .entries()
        .map_err(|error| format!("read update archive: {error}"))?
    {
        let mut entry = entry.map_err(|error| format!("read update archive entry: {error}"))?;
        let entry_type = entry.header().entry_type();
        if !entry_type.is_file() && !entry_type.is_dir() {
            return Err("update archive contains an unsupported entry type".into());
        }
        let path = canonical_archive_path(&entry.path_bytes(), entry_type.is_dir())?;
        if !seen_paths.insert(path.clone()) {
            return Err("update archive contains a duplicate path".into());
        }

        let size = entry.size();
        budget.observe(size)?;
        if path == INFO_PLIST_PATH {
            if !entry_type.is_file() || size > MAX_INFO_PLIST_BYTES {
                return Err("update Info.plist has an invalid type or size".into());
            }
            let mut info_plist = Vec::with_capacity(size as usize);
            entry
                .read_to_end(&mut info_plist)
                .map_err(|error| format!("read update Info.plist: {error}"))?;
            if info_plist.len() as u64 != size {
                return Err("update Info.plist is truncated".into());
            }
            validate_info_plist(&info_plist, expected_version)?;
            info_plist_count += 1;
        }
    }

    if info_plist_count != 1 {
        return Err("update archive must contain exactly one OsaGuard Info.plist".into());
    }

    // Force the gzip checksum/trailer to be consumed, then reject concatenated
    // members or arbitrary compressed bytes following the single tar stream.
    let mut decoder = archive.into_inner();
    let mut trailing = Vec::new();
    decoder
        .by_ref()
        .take(MAX_TAR_END_PADDING_BYTES + 1)
        .read_to_end(&mut trailing)
        .map_err(|error| format!("finish update archive: {error}"))?;
    if trailing.len() as u64 > MAX_TAR_END_PADDING_BYTES || trailing.iter().any(|byte| *byte != 0) {
        return Err("update archive contains trailing uncompressed data".into());
    }
    let buffered = decoder.into_inner();
    let consumed = buffered
        .get_ref()
        .position()
        .checked_sub(buffered.buffer().len() as u64)
        .ok_or_else(|| "update archive compressed position is invalid".to_owned())?;
    if consumed != bytes.len() as u64 {
        return Err("update archive contains trailing compressed data".into());
    }
    Ok(())
}

/// Extract an archive only after the same immutable byte sequence has passed
/// the structural and release-version checks above. The destination must be a
/// newly-created, empty, non-symlink directory owned by this process.
pub fn extract_update_archive(
    bytes: &[u8],
    expected_version: &str,
    destination: &Path,
) -> Result<PathBuf, String> {
    validate_update_archive(bytes, expected_version)?;

    let metadata = fs::symlink_metadata(destination)
        .map_err(|error| format!("inspect update staging directory: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("update staging path is not a real directory".into());
    }
    if fs::read_dir(destination)
        .map_err(|error| format!("inspect update staging directory: {error}"))?
        .next()
        .is_some()
    {
        return Err("update staging directory is not empty".into());
    }

    let decoder = ReadGzDecoder::new(Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    archive
        .unpack(destination)
        .map_err(|error| format!("extract verified update archive: {error}"))?;

    let candidate = destination.join("OsaGuard.app");
    let candidate_metadata = fs::symlink_metadata(&candidate)
        .map_err(|error| format!("inspect extracted OsaGuard bundle: {error}"))?;
    if candidate_metadata.file_type().is_symlink() || !candidate_metadata.is_dir() {
        return Err("verified update did not extract a real OsaGuard.app directory".into());
    }
    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_archive_path, extract_update_archive, validate_compressed_size,
        validate_update_archive, ArchiveBudget, MAX_ARCHIVE_ENTRIES, MAX_COMPRESSED_BYTES,
        MAX_ENTRY_BYTES, MAX_UNCOMPRESSED_BYTES,
    };
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;

    fn info_plist(version: &str, identifier: &str) -> Vec<u8> {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>{identifier}</string>
<key>CFBundleShortVersionString</key><string>{version}</string>
</dict></plist>"#
        )
        .into_bytes()
    }

    fn archive_with_info_plists(plists: &[Vec<u8>]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for plist in plists {
            let mut header = tar::Header::new_gnu();
            header.set_size(plist.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(
                    &mut header,
                    "OsaGuard.app/Contents/Info.plist",
                    plist.as_slice(),
                )
                .unwrap();
        }
        let encoder = archive.into_inner().unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn accepts_exact_bundle_identity_and_selected_version() {
        let bytes =
            archive_with_info_plists(&[info_plist("0.1.3-preview.2", "dev.aiwaki.osaguard")]);
        validate_update_archive(&bytes, "0.1.3-preview.2").unwrap();

        let staging = tempfile::tempdir().unwrap();
        let candidate = extract_update_archive(&bytes, "0.1.3-preview.2", staging.path()).unwrap();
        assert!(candidate.join("Contents/Info.plist").is_file());
    }

    #[test]
    fn extraction_requires_a_new_empty_real_directory() {
        let bytes =
            archive_with_info_plists(&[info_plist("0.1.3-preview.2", "dev.aiwaki.osaguard")]);
        let staging = tempfile::tempdir().unwrap();
        std::fs::write(staging.path().join("occupied"), b"x").unwrap();
        assert_eq!(
            extract_update_archive(&bytes, "0.1.3-preview.2", staging.path()).unwrap_err(),
            "update staging directory is not empty"
        );
    }

    #[test]
    fn rejects_replayed_verified_archive_with_an_old_version() {
        // The caller has already verified this byte sequence with Tauri's
        // signing key; archive inspection must still bind it to metadata.
        let bytes =
            archive_with_info_plists(&[info_plist("0.1.3-preview.1", "dev.aiwaki.osaguard")]);
        assert_eq!(
            validate_update_archive(&bytes, "0.1.3-preview.2").unwrap_err(),
            "update archive version mismatch"
        );
    }

    #[test]
    fn rejects_wrong_bundle_identity_and_duplicate_info_plist() {
        let wrong = archive_with_info_plists(&[info_plist("0.1.3-preview.2", "example.invalid")]);
        assert_eq!(
            validate_update_archive(&wrong, "0.1.3-preview.2").unwrap_err(),
            "update archive bundle identifier mismatch"
        );

        let plist = info_plist("0.1.3-preview.2", "dev.aiwaki.osaguard");
        let duplicate = archive_with_info_plists(&[plist.clone(), plist]);
        assert_eq!(
            validate_update_archive(&duplicate, "0.1.3-preview.2").unwrap_err(),
            "update archive contains a duplicate path"
        );
    }

    #[test]
    fn archive_limits_and_paths_fail_closed() {
        assert!(validate_compressed_size(0).is_err());
        assert!(validate_compressed_size(MAX_COMPRESSED_BYTES + 1).is_err());

        let mut budget = ArchiveBudget::default();
        budget.entries = MAX_ARCHIVE_ENTRIES;
        assert!(budget.observe(0).is_err());
        let mut budget = ArchiveBudget::default();
        assert!(budget.observe(MAX_ENTRY_BYTES + 1).is_err());
        let mut budget = ArchiveBudget {
            entries: 0,
            uncompressed_bytes: MAX_UNCOMPRESSED_BYTES,
        };
        assert!(budget.observe(1).is_err());

        assert!(canonical_archive_path(b"../OsaGuard.app/Contents/Info.plist", false).is_err());
        assert!(canonical_archive_path(b"OsaGuard.app/../escape", false).is_err());
        assert!(canonical_archive_path(b"Other.app/Contents/Info.plist", false).is_err());
        assert!(canonical_archive_path(b"OsaGuard.app\\Contents\\Info.plist", false).is_err());
    }

    #[test]
    fn rejects_non_gzip_and_trailing_data() {
        assert!(validate_update_archive(b"not gzip", "0.1.3-preview.2").is_err());

        let mut bytes =
            archive_with_info_plists(&[info_plist("0.1.3-preview.2", "dev.aiwaki.osaguard")]);
        bytes.write_all(b"trailing").unwrap();
        assert!(validate_update_archive(&bytes, "0.1.3-preview.2").is_err());
    }
}
