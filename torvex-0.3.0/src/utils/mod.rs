//! File fingerprinting and display helpers.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use sha2::{Digest, Sha256};

/// Bytes captured for content-based file type detection.
const HEADER_SIZE: usize = 8 * 1024;
const READ_BUFFER_SIZE: usize = 32 * 1024;

/// Default cap on the number of bytes buffered for content engines.
///
/// Hashing always covers the whole file; only the detection buffer is capped,
/// so a multi-gigabyte file still gets a correct SHA-256 without being loaded
/// into memory.
pub const DEFAULT_SCAN_LIMIT: u64 = 64 * 1024 * 1024;

/// Hash, size, type and buffered content for one file, from a single read.
#[derive(Debug, Clone)]
pub struct FileFingerprint {
    /// Lowercase hexadecimal SHA-256 of every byte read.
    pub sha256: String,
    /// Number of bytes in the file.
    pub size: u64,
    /// MIME type from content sniffing, falling back to the file extension.
    pub file_type: Option<String>,
    /// The first `min(size, limit)` bytes, for content engines.
    pub content: Vec<u8>,
    /// True when `content` holds only a prefix of the file.
    pub truncated: bool,
}

/// Reads `path` once to calculate its SHA-256, size, estimated type and a
/// content buffer capped at [`DEFAULT_SCAN_LIMIT`].
pub fn fingerprint_file(path: &Path) -> Result<FileFingerprint> {
    fingerprint_file_with_limit(path, DEFAULT_SCAN_LIMIT)
}

/// Same as [`fingerprint_file`] with an explicit content cap.
///
/// The file may change while it is being read; results describe the bytes
/// Torvex observed during this scan.
pub fn fingerprint_file_with_limit(path: &Path, limit: u64) -> Result<FileFingerprint> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut header = Vec::with_capacity(HEADER_SIZE);
    let mut content = Vec::new();
    let mut buffer = [0_u8; READ_BUFFER_SIZE];
    let mut size = 0_u64;
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }

        if header.len() < HEADER_SIZE {
            let remaining = HEADER_SIZE - header.len();
            header.extend_from_slice(&buffer[..read.min(remaining)]);
        }

        if content.len() < limit {
            let remaining = limit - content.len();
            content.extend_from_slice(&buffer[..read.min(remaining)]);
        }

        hasher.update(&buffer[..read]);
        size += read as u64;
    }

    let file_type = infer::get(&header)
        .map(|file_type| file_type.mime_type().to_owned())
        .or_else(|| {
            mime_guess::from_path(path)
                .first()
                .map(|mime| mime.to_string())
        });

    Ok(FileFingerprint {
        sha256: hex::encode(hasher.finalize()),
        size,
        file_type,
        truncated: (content.len() as u64) < size,
        content,
    })
}

/// Formats a scan duration for display.
pub fn format_duration(duration: Duration) -> String {
    if duration.as_secs() >= 60 {
        format!(
            "{} min {:.0} s",
            duration.as_secs() / 60,
            duration.as_secs_f64() % 60.0
        )
    } else if duration.as_secs() >= 1 {
        format!("{:.2} s", duration.as_secs_f64())
    } else {
        format!("{} ms", duration.as_millis())
    }
}

/// Formats a byte count with binary units.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];

    if bytes < 1024 {
        return format!("{bytes} B");
    }

    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    if value >= 10.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ`, without pulling in a date crate.
pub fn utc_timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    format_utc(seconds)
}

/// Formats UNIX seconds as a compact UTC timestamp.
pub fn format_utc(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let remainder = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        remainder / 3600,
        (remainder % 3600) / 60,
        remainder % 60
    )
}

/// Howard Hinnant's civil-from-days algorithm, valid for the whole proleptic
/// Gregorian calendar.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = year + i64::from(month <= 2);
    (year, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn fingerprints_content_and_size() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let path = temp.path().join("sample.txt");
        fs::write(&path, "ordinary harmless text").expect("write fixture");

        let fingerprint = fingerprint_file(&path).expect("fingerprint fixture");
        assert_eq!(fingerprint.size, 22);
        assert_eq!(
            fingerprint.sha256,
            "7118ca6e073e8945cab7573c5e6a181c48bd95135403320fdd2cb52b98ef7cbb"
        );
        assert_eq!(fingerprint.file_type.as_deref(), Some("text/plain"));
        assert_eq!(fingerprint.content, b"ordinary harmless text");
        assert!(!fingerprint.truncated);
    }

    #[test]
    fn content_is_capped_but_the_hash_still_covers_every_byte() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let path = temp.path().join("large.bin");
        fs::write(&path, vec![b'a'; 100]).expect("write fixture");

        let fingerprint = fingerprint_file_with_limit(&path, 10).expect("fingerprint");
        assert_eq!(fingerprint.size, 100);
        assert_eq!(fingerprint.content.len(), 10);
        assert!(fingerprint.truncated);
        // Hash of 100 'a' bytes.
        assert_eq!(
            fingerprint.sha256,
            "2816597888e4a0d3a36b82b83316ab32680eb8f00f8cd3b904d681246d285a0e"
        );
    }

    #[test]
    fn content_sniffing_overrides_the_extension() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let path = temp.path().join("pretend.txt");
        let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        png.extend_from_slice(&[0_u8; 64]);
        fs::write(&path, png).expect("write fixture");

        let fingerprint = fingerprint_file(&path).expect("fingerprint fixture");
        assert_eq!(fingerprint.file_type.as_deref(), Some("image/png"));
    }

    #[test]
    fn falls_back_to_the_file_extension() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let path = temp.path().join("page.html");
        fs::write(&path, "ordinary harmless text").expect("write fixture");

        let fingerprint = fingerprint_file(&path).expect("fingerprint fixture");
        assert_eq!(fingerprint.file_type.as_deref(), Some("text/html"));
    }

    #[test]
    fn formats_durations() {
        assert_eq!(format_duration(Duration::from_millis(0)), "0 ms");
        assert_eq!(format_duration(Duration::from_millis(999)), "999 ms");
        assert_eq!(format_duration(Duration::from_millis(1500)), "1.50 s");
        assert_eq!(format_duration(Duration::from_secs(75)), "1 min 15 s");
    }

    #[test]
    fn formats_byte_counts() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(10 * 1024), "10 KiB");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MiB");
    }

    #[test]
    fn formats_utc_timestamps() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(format_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert!(utc_timestamp().ends_with('Z'));
    }
}
