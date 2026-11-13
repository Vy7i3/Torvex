//! File fingerprinting and display helpers.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use sha2::{Digest, Sha256};

/// Bytes captured for content-based file type detection.
const HEADER_SIZE: usize = 8 * 1024;
const READ_BUFFER_SIZE: usize = 32 * 1024;

/// Hash, size, and estimated type for one file, derived from a single read.
#[derive(Debug, Clone)]
pub struct FileFingerprint {
    /// Lowercase hexadecimal SHA-256.
    pub sha256: String,
    /// Number of bytes read.
    pub size: u64,
    /// MIME type from content sniffing, falling back to the file extension.
    pub file_type: Option<String>,
}

/// Reads `path` once to calculate its SHA-256, size, and estimated type.
///
/// Type detection uses the first 8 KiB of content and falls back to the file
/// extension. The file may change while it is being read; results describe the
/// bytes Torvex observed during this scan.
pub fn fingerprint_file(path: &Path) -> Result<FileFingerprint> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut header = Vec::with_capacity(HEADER_SIZE);
    let mut buffer = [0_u8; READ_BUFFER_SIZE];
    let mut size = 0_u64;

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }

        if header.len() < HEADER_SIZE {
            let remaining = HEADER_SIZE - header.len();
            header.extend_from_slice(&buffer[..read.min(remaining)]);
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
    })
}

/// Formats a scan duration for display.
pub fn format_duration(duration: Duration) -> String {
    if duration.as_secs() >= 1 {
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
}
