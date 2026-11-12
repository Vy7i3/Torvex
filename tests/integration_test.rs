use std::fs;
use std::process::Command;

use torvex::engine::Verdict;
use torvex::scanner::scan_path;

#[test]
fn scans_clean_and_example_marker_files() {
    let temp_dir = tempfile::tempdir().expect("create temporary scan directory");
    let clean_file = temp_dir.path().join("clean.txt");
    let marker_file = temp_dir.path().join("marker.txt");

    fs::write(&clean_file, "ordinary harmless text").expect("write clean fixture");
    fs::write(&marker_file, "TORVEX_YARA_EXAMPLE_TEXT").expect("write matching fixture");

    let results = scan_path(temp_dir.path()).expect("scan fixture directory");

    assert_eq!(results.len(), 2);

    let clean = results
        .iter()
        .find(|result| result.path == clean_file.to_string_lossy())
        .expect("clean result");
    assert_eq!(clean.status, Verdict::Clean);
    assert_eq!(clean.confidence, None);
    assert_eq!(clean.sha256.len(), 64);
    assert_eq!(clean.size, "ordinary harmless text".len() as u64);
    assert_eq!(clean.file_type.as_deref(), Some("text/plain"));
    assert!(clean.reason.is_none());

    let marker = results
        .iter()
        .find(|result| result.path == marker_file.to_string_lossy())
        .expect("marker result");
    assert_eq!(marker.status, Verdict::Suspicious);
    assert_eq!(marker.confidence, None);
    assert_eq!(marker.sha256.len(), 64);
    assert!(
        marker
            .reason
            .as_deref()
            .unwrap()
            .contains("torvex_example_text")
    );

    let output = Command::new(env!("CARGO_BIN_EXE_torvex"))
        .args(["scan", temp_dir.path().to_str().expect("UTF-8 temp path")])
        .output()
        .expect("run CLI scan command");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("CLI output is UTF-8");
    assert!(stdout.contains("Total files scanned: 2"));
    assert!(stdout.contains("Clean: 1"));
    assert!(stdout.contains("Suspicious: 1"));
    assert!(stdout.contains("Malicious: 0"));
    assert!(stdout.contains("Status: suspicious"));
    assert!(stdout.contains(&marker_file.to_string_lossy().to_string()));
    assert!(stdout.contains("SHA-256:"));
    assert!(stdout.contains("Confidence: not calibrated"));
}
