//! Scheduled-backup housekeeping: retention pruning, compression of older
//! backups, and SHA-256-based diff detection between consecutive backups.
//!
//! This module is purely filesystem-driven — it does not know about
//! D-Bus, daemon state, or any vendor specifics. Drop a file in
//! `/etc/supermgrd/backups/` named `<safe_host>_<YYYYMMDD_HHMMSS>.<ext>` and
//! the helpers below treat it as a backup belonging to `<safe_host>`. Both
//! the FortiGate (`*.conf`) and OPNsense (`*.opnsense.xml`) extensions are
//! handled the same way; callers can add more extensions by extending
//! [`BackupExt::recognise`].
//!
//! # Files this module reads/writes
//!
//! - Reads: every file matching `<host>_<ts>.<ext>` or `<host>_<ts>.<ext>.gz`
//!   under the backup root.
//! - Writes (compress): rewrites `name.<ext>` → `name.<ext>.gz` in place.
//! - Writes (prune): unlinks the oldest files past the retention window.
//! - Reads (diff): SHA-256 of the most recent two backups for one host.

use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDateTime, Utc};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

/// Recognised backup file extensions. The leading dot is included so the
/// match is unambiguous against fragmentary filenames like `prod.opnsense`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupExt {
    /// FortiGate text/XML config (`<host>_<ts>.conf`).
    FortigateConf,
    /// OPNsense XML config (`<host>_<ts>.opnsense.xml`).
    OpnsenseXml,
}

impl BackupExt {
    /// Try to classify a filename's extension. Returns `None` for files
    /// that are not backups produced by this daemon.
    pub fn recognise(name: &str) -> Option<Self> {
        // Order matters: `.opnsense.xml` is a more-specific suffix than
        // `.xml` so test it first. Strip any trailing `.gz` first since we
        // treat compressed and uncompressed the same way for classification.
        let stem = name.strip_suffix(".gz").unwrap_or(name);
        if stem.ends_with(".opnsense.xml") {
            Some(Self::OpnsenseXml)
        } else if stem.ends_with(".conf") {
            Some(Self::FortigateConf)
        } else {
            None
        }
    }
}

/// One backup file located under the backup root, with the metadata we use
/// for retention/compression/diff decisions.
#[derive(Debug, Clone)]
pub struct BackupFile {
    /// Absolute path on disk.
    pub path: PathBuf,
    /// `<safe_host>` portion of the filename, before the first `_<ts>`.
    pub host: String,
    /// Timestamp parsed from the `_YYYYMMDD_HHMMSS` portion. UTC.
    pub timestamp: DateTime<Utc>,
    /// Whether the file currently has a `.gz` suffix.
    pub compressed: bool,
}

/// Parse `<host>_<YYYYMMDD>_<HHMMSS>.<ext>[.gz]` from the filename.
///
/// Returns `None` for any file that doesn't follow the pattern, including
/// files that match but whose timestamp segment is unparseable.
pub fn parse_backup_filename(name: &str) -> Option<(String, DateTime<Utc>, bool)> {
    let compressed = name.ends_with(".gz");
    let stripped = if compressed { &name[..name.len() - 3] } else { name };
    BackupExt::recognise(stripped)?;

    // Strip the recognised extension to leave `<host>_<YYYYMMDD>_<HHMMSS>`.
    let core = stripped
        .strip_suffix(".opnsense.xml")
        .or_else(|| stripped.strip_suffix(".conf"))?;

    // Split on the LAST `_<digits>` block — the timestamp suffix. We match
    // exactly 6 digits (HHMMSS) preceded by `_` and 8 digits (YYYYMMDD)
    // preceded by another `_`. The host name itself can contain underscores
    // (we sanitise to `_` from non-alnum chars at write time), so a naive
    // split would mis-attribute the host portion.
    let bytes = core.as_bytes();
    if bytes.len() < 16 {
        return None;
    }
    // Last 15 bytes must look like `_YYYYMMDD_HHMMSS`.
    let tail = &core[core.len() - 16..];
    if !tail.starts_with('_') || tail.as_bytes()[9] != b'_' {
        return None;
    }
    let date_str = &tail[1..9];
    let time_str = &tail[10..];
    if !date_str.bytes().all(|c| c.is_ascii_digit()) || !time_str.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let host = core[..core.len() - 16].to_owned();
    let combined = format!("{date_str}{time_str}");
    let naive = NaiveDateTime::parse_from_str(&combined, "%Y%m%d%H%M%S").ok()?;
    let ts: DateTime<Utc> = naive.and_utc();
    Some((host, ts, compressed))
}

/// Scan `dir` for every recognised backup file. Unrecognised files (READMEs,
/// stray notes, etc.) are silently skipped; unreadable directory entries log
/// a warning and are skipped.
pub fn scan_backups(dir: &Path) -> Vec<BackupFile> {
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            warn!("scan_backups: read_dir({}): {e}", dir.display());
            return Vec::new();
        }
    };

    let mut out = Vec::new();
    for entry in read.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if let Some((host, ts, compressed)) = parse_backup_filename(&name) {
            out.push(BackupFile {
                path,
                host,
                timestamp: ts,
                compressed,
            });
        }
    }
    out.sort_by(|a, b| {
        a.host.cmp(&b.host).then(a.timestamp.cmp(&b.timestamp))
    });
    out
}

/// Group backups by host (sorted oldest-first within each group).
///
/// This is the input shape the retention/compression helpers expect.
pub fn group_by_host(files: Vec<BackupFile>) -> std::collections::BTreeMap<String, Vec<BackupFile>> {
    let mut groups = std::collections::BTreeMap::<String, Vec<BackupFile>>::new();
    for f in files {
        groups.entry(f.host.clone()).or_default().push(f);
    }
    for v in groups.values_mut() {
        v.sort_by_key(|f| f.timestamp);
    }
    groups
}

/// Decide which files in a group should be unlinked given a `keep_last` cap.
///
/// The most-recent `keep_last` files survive; everything older is returned
/// for the caller to delete. Caller does the actual `unlink` so that this
/// function stays pure (and unit-testable on a synthetic file list).
pub fn select_to_prune(group: &[BackupFile], keep_last: usize) -> Vec<&BackupFile> {
    if group.len() <= keep_last {
        return Vec::new();
    }
    let cutoff = group.len() - keep_last;
    group.iter().take(cutoff).collect()
}

/// Decide which uncompressed files in a group are old enough to compress.
///
/// "Old enough" = `timestamp < now - older_than`. Already-compressed files
/// are excluded. Returns a list of mutable references so the caller can
/// update in place after re-writing the file path.
pub fn select_to_compress<'a>(
    group: &'a [BackupFile],
    now: DateTime<Utc>,
    older_than: chrono::Duration,
) -> Vec<&'a BackupFile> {
    let cutoff = now - older_than;
    group
        .iter()
        .filter(|f| !f.compressed && f.timestamp < cutoff)
        .collect()
}

/// Compress a file in place: rewrite `path` → `path.gz` and unlink `path`.
///
/// Returns the new path. The function is intentionally synchronous and uses
/// blocking I/O — gzip a config file is microseconds-scale and not worth
/// async machinery for a daily housekeeping pass.
pub fn compress_in_place(path: &Path) -> std::io::Result<PathBuf> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write as _;

    let bytes = std::fs::read(path)?;
    let mut new_path = path.as_os_str().to_os_string();
    new_path.push(".gz");
    let new_path = PathBuf::from(new_path);

    let f = std::fs::File::create(&new_path)?;
    let mut enc = GzEncoder::new(f, Compression::default());
    enc.write_all(&bytes)?;
    enc.finish()?;
    std::fs::remove_file(path)?;
    Ok(new_path)
}

/// Hash the contents of a backup file. Transparently decompresses `.gz`
/// before hashing so the digest reflects the *plaintext* config and is
/// stable across compress/decompress cycles.
pub fn hash_backup(path: &Path) -> std::io::Result<[u8; 32]> {
    let bytes = std::fs::read(path)?;
    let plaintext = if path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e == "gz")
    {
        use flate2::read::GzDecoder;
        use std::io::Read as _;
        let mut dec = GzDecoder::new(&bytes[..]);
        let mut out = Vec::with_capacity(bytes.len());
        dec.read_to_end(&mut out)?;
        out
    } else {
        bytes
    };
    let mut h = Sha256::new();
    h.update(&plaintext);
    Ok(h.finalize().into())
}

/// Pure-data summary of one daily housekeeping run, returned to the caller
/// for logging and webhook decisions.
#[derive(Debug, Default)]
pub struct HousekeepingReport {
    /// Files compressed during this run (path → new gz path).
    pub compressed: Vec<PathBuf>,
    /// Files deleted by retention.
    pub pruned: Vec<PathBuf>,
    /// Hosts whose newest backup has different SHA-256 than the prior one.
    pub diffed_hosts: Vec<String>,
}

/// Run a full housekeeping pass over `dir`:
///
/// 1. Compress files older than `compress_after`.
/// 2. Prune files past the `keep_last` per-host cap (newest survive).
/// 3. Identify hosts whose newest backup differs from the prior one
///    (caller can fire webhook on those).
///
/// Compression and pruning failures log a warning and continue — one bad
/// file doesn't block the rest of the run.
pub fn housekeep(
    dir: &Path,
    keep_last: usize,
    compress_after: chrono::Duration,
    now: DateTime<Utc>,
) -> HousekeepingReport {
    let mut report = HousekeepingReport::default();

    // Phase 1 — compression. Walk the pre-compression scan and rewrite
    // anything older than the threshold to .gz in place.
    let pre = scan_backups(dir);
    for f in &pre {
        if !f.compressed && f.timestamp < (now - compress_after) {
            match compress_in_place(&f.path) {
                Ok(new_path) => {
                    info!("housekeep: compressed {}", f.path.display());
                    report.compressed.push(new_path);
                }
                Err(e) => warn!("housekeep: compress {}: {e}", f.path.display()),
            }
        }
    }

    // Phase 2 — retention. Re-scan to pick up the renamed (.gz) paths so
    // the unlink targets are valid; group by host and prune anything past
    // the keep_last cap (newest files survive).
    let post_compress = scan_backups(dir);
    let groups = group_by_host(post_compress);
    for group in groups.values() {
        for f in select_to_prune(group, keep_last) {
            match std::fs::remove_file(&f.path) {
                Ok(()) => {
                    info!("housekeep: pruned {}", f.path.display());
                    report.pruned.push(f.path.clone());
                }
                Err(e) => warn!("housekeep: unlink {}: {e}", f.path.display()),
            }
        }
    }

    // Phase 3 — diff detection. Re-scan once more because retention just
    // unlinked files. For each host with ≥ 2 surviving backups, compare
    // SHA-256 of the newest two; record the host if they differ.
    let post_prune = scan_backups(dir);
    let post_groups = group_by_host(post_prune);
    for (host, group) in &post_groups {
        debug!("housekeep: host={host} backups_remaining={}", group.len());
        if group.len() < 2 {
            continue;
        }
        let newest = &group[group.len() - 1];
        let prev = &group[group.len() - 2];
        match (hash_backup(&newest.path), hash_backup(&prev.path)) {
            (Ok(a), Ok(b)) if a != b => {
                debug!("housekeep: {host} diff detected");
                report.diffed_hosts.push(host.clone());
            }
            (Err(e), _) | (_, Err(e)) => {
                warn!("housekeep: hash {host}: {e}");
            }
            _ => {}
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    #[test]
    fn parse_recognises_fortigate_conf() {
        let (host, ts, compressed) =
            parse_backup_filename("fw-edge_20260427_140530.conf").unwrap();
        assert_eq!(host, "fw-edge");
        assert!(!compressed);
        assert_eq!(ts, Utc.with_ymd_and_hms(2026, 4, 27, 14, 5, 30).unwrap());
    }

    #[test]
    fn parse_recognises_opnsense_xml() {
        let (host, ts, _) =
            parse_backup_filename("opnsense_tail_20260101_000000.opnsense.xml").unwrap();
        assert_eq!(host, "opnsense_tail");
        assert_eq!(ts, Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap());
    }

    #[test]
    fn parse_recognises_compressed_variant() {
        let (host, _, compressed) =
            parse_backup_filename("fw-edge_20260427_140530.conf.gz").unwrap();
        assert_eq!(host, "fw-edge");
        assert!(compressed);
    }

    #[test]
    fn parse_handles_host_with_underscores() {
        // `<safe_host>` may contain underscores because we sanitise non-alnum
        // chars to `_` at write time. The timestamp suffix is fixed-width.
        let (host, _, _) = parse_backup_filename("a_b_c_20260427_140530.conf").unwrap();
        assert_eq!(host, "a_b_c");
    }

    #[test]
    fn parse_rejects_non_backup_files() {
        assert!(parse_backup_filename("README.md").is_none());
        assert!(parse_backup_filename("notes.txt").is_none());
        assert!(parse_backup_filename("fw-edge.conf").is_none()); // no timestamp
    }

    #[test]
    fn parse_rejects_garbled_timestamp() {
        assert!(parse_backup_filename("fw_2026XXXX_140530.conf").is_none());
        assert!(parse_backup_filename("fw_20260427_XXXXXX.conf").is_none());
    }

    fn synthetic(host: &str, year: i32, month: u32, day: u32) -> BackupFile {
        BackupFile {
            path: PathBuf::from(format!(
                "/tmp/{host}_{year}{month:02}{day:02}_120000.conf"
            )),
            host: host.into(),
            timestamp: Utc.with_ymd_and_hms(year, month, day, 12, 0, 0).unwrap(),
            compressed: false,
        }
    }

    #[test]
    fn select_to_prune_keeps_last_n() {
        let group = vec![
            synthetic("h", 2026, 1, 1),
            synthetic("h", 2026, 1, 2),
            synthetic("h", 2026, 1, 3),
            synthetic("h", 2026, 1, 4),
            synthetic("h", 2026, 1, 5),
        ];
        let pruned = select_to_prune(&group, 3);
        assert_eq!(pruned.len(), 2);
        // The two oldest are the prune targets.
        assert_eq!(
            pruned[0].timestamp,
            Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap()
        );
        assert_eq!(
            pruned[1].timestamp,
            Utc.with_ymd_and_hms(2026, 1, 2, 12, 0, 0).unwrap()
        );
    }

    #[test]
    fn select_to_prune_returns_empty_when_under_cap() {
        let group = vec![synthetic("h", 2026, 1, 1), synthetic("h", 2026, 1, 2)];
        assert!(select_to_prune(&group, 5).is_empty());
        assert!(select_to_prune(&group, 2).is_empty());
    }

    #[test]
    fn select_to_compress_age_threshold() {
        let group = vec![
            synthetic("h", 2026, 1, 1),  // 28 days old
            synthetic("h", 2026, 1, 20), // 9 days old
            synthetic("h", 2026, 1, 28), // 1 day old
        ];
        let now = Utc.with_ymd_and_hms(2026, 1, 29, 12, 0, 0).unwrap();
        let to_compress = select_to_compress(&group, now, chrono::Duration::days(7));
        assert_eq!(to_compress.len(), 2, "the two oldest should be picked");
    }

    #[test]
    fn select_to_compress_skips_already_compressed() {
        let mut group = vec![synthetic("h", 2026, 1, 1)];
        group[0].compressed = true;
        let now = Utc.with_ymd_and_hms(2026, 1, 29, 12, 0, 0).unwrap();
        assert!(select_to_compress(&group, now, chrono::Duration::days(7)).is_empty());
    }

    #[test]
    fn compress_in_place_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h_20260101_120000.conf");
        std::fs::write(&path, b"hello world").unwrap();

        let new_path = compress_in_place(&path).unwrap();
        assert!(new_path.to_string_lossy().ends_with(".gz"));
        assert!(!path.exists(), "original should be deleted");

        // Decompress and verify.
        use flate2::read::GzDecoder;
        use std::io::Read as _;
        let bytes = std::fs::read(&new_path).unwrap();
        let mut dec = GzDecoder::new(&bytes[..]);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn hash_backup_compressed_matches_uncompressed() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("h_20260101_120000.conf");
        std::fs::write(&plain, b"important config").unwrap();
        let h_plain = hash_backup(&plain).unwrap();

        let compressed = compress_in_place(&plain).unwrap();
        let h_compressed = hash_backup(&compressed).unwrap();

        assert_eq!(
            h_plain, h_compressed,
            "compressed hash must match uncompressed plaintext hash"
        );
    }

    #[test]
    fn housekeep_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc.with_ymd_and_hms(2026, 1, 30, 0, 0, 0).unwrap();

        // Create five backups for host "fw" across the last 30 days, with
        // different content for each so diff-detection has something to find.
        for (i, day) in [1, 10, 20, 28, 29].iter().enumerate() {
            let name = format!("fw_202601{day:02}_120000.conf");
            std::fs::write(dir.path().join(name), format!("payload {i}")).unwrap();
        }
        let report = housekeep(dir.path(), 3, chrono::Duration::days(7), now);
        // Days 1, 10, 20 are all ≥ 7 days old on Jan 30, so three files
        // get compressed. Days 28 and 29 are too recent.
        assert_eq!(report.compressed.len(), 3, "{report:?}");
        // After compression we still have 5 files; retention=3 prunes the
        // two oldest.
        assert_eq!(report.pruned.len(), 2, "{report:?}");
        // Newest two differ → host shows up in diffed_hosts.
        assert_eq!(report.diffed_hosts, vec!["fw".to_string()]);

        // Final directory state: 3 files remain, the two oldest are gone.
        let remaining: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().into_string().unwrap())
            .collect();
        assert_eq!(remaining.len(), 3, "got: {remaining:?}");
    }

    #[test]
    fn housekeep_no_diff_when_content_identical() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc.with_ymd_and_hms(2026, 1, 30, 0, 0, 0).unwrap();
        std::fs::write(
            dir.path().join("fw_20260128_120000.conf"),
            b"unchanged",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("fw_20260129_120000.conf"),
            b"unchanged",
        )
        .unwrap();
        let report = housekeep(dir.path(), 30, chrono::Duration::days(7), now);
        assert!(
            report.diffed_hosts.is_empty(),
            "identical content shouldn't show as diff: {report:?}"
        );
    }
}
