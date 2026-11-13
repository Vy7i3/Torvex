use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;
use torvex::engine::{FailureKind, Verdict};
use torvex::scanner::{ScanOptions, scan_path_with_options};

const RULES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/rules");
const CLEAN_TEXT: &str = "ordinary harmless text";
const CLEAN_TEXT_SHA256: &str = "7118ca6e073e8945cab7573c5e6a181c48bd95135403320fdd2cb52b98ef7cbb";

fn scan_options() -> ScanOptions {
    ScanOptions {
        rules_dir: Some(RULES_DIR.into()),
    }
}

fn write_fixture(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write fixture");
}

fn run_cli(args: &[&str], current_dir: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_torvex"));
    command.args(args);
    command.env_remove("TORVEX_RULES_DIR");
    if let Some(directory) = current_dir {
        command.current_dir(directory);
    }
    command.output().expect("run torvex CLI")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("CLI stdout is UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("CLI stderr is UTF-8")
}

#[test]
fn scans_clean_and_demo_marker_files() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let clean_file = temp.path().join("clean.txt");
    let marker_file = temp.path().join("marker.txt");
    write_fixture(&clean_file, CLEAN_TEXT);
    write_fixture(&marker_file, "TORVEX_YARA_EXAMPLE_TEXT");

    let report =
        scan_path_with_options(temp.path(), &scan_options()).expect("scan fixture directory");

    assert_eq!(report.results.len(), 2);
    assert!(report.failures.is_empty());
    assert!(report.is_complete());
    assert_eq!(report.skipped, 0);
    assert_eq!(report.rules.rule_count, 3);
    assert_eq!(report.rules.demo_rule_count, 3);
    assert!(report.rules.is_demo_only());
    assert!(report.has_findings());

    let clean = report
        .results
        .iter()
        .find(|result| result.path == clean_file.to_string_lossy())
        .expect("clean result");
    assert_eq!(clean.verdict, Verdict::Clean);
    assert_eq!(clean.sha256, CLEAN_TEXT_SHA256);
    assert_eq!(clean.size, CLEAN_TEXT.len() as u64);
    assert_eq!(clean.file_type.as_deref(), Some("text/plain"));
    assert!(clean.matches.is_empty());
    assert!(!clean.is_suspicious());

    let marker = report
        .results
        .iter()
        .find(|result| result.path == marker_file.to_string_lossy())
        .expect("marker result");
    assert_eq!(marker.verdict, Verdict::Suspicious);
    assert_eq!(marker.sha256.len(), 64);
    assert_eq!(marker.matches.len(), 1);
    assert_eq!(marker.matches[0].rule, "torvex_example_text");
    assert_eq!(marker.matches[0].namespace, "default");
    assert!(marker.matches[0].demo);
    assert!(marker.matches[0].tags.contains(&"demo".to_owned()));
    assert!(
        marker.matches[0]
            .description
            .as_deref()
            .unwrap_or_default()
            .contains("harmless")
    );

    let summary = report.summary();
    assert_eq!(summary.scanned, 2);
    assert_eq!(summary.clean, 1);
    assert_eq!(summary.suspicious, 1);
    assert_eq!(summary.errors, 0);
    assert_eq!(
        summary.bytes_scanned,
        (CLEAN_TEXT.len() + "TORVEX_YARA_EXAMPLE_TEXT".len()) as u64
    );
}

#[test]
fn detects_file_types_from_content_before_extension() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let disguised_png = temp.path().join("picture.txt");
    let html_file = temp.path().join("page.html");
    let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    png.extend_from_slice(&[0_u8; 32]);
    fs::write(&disguised_png, png).expect("write PNG fixture");
    write_fixture(&html_file, "ordinary harmless text");

    let report =
        scan_path_with_options(temp.path(), &scan_options()).expect("scan fixture directory");

    let png_result = report
        .results
        .iter()
        .find(|result| result.path == disguised_png.to_string_lossy())
        .expect("PNG result");
    assert_eq!(png_result.file_type.as_deref(), Some("image/png"));

    let html_result = report
        .results
        .iter()
        .find(|result| result.path == html_file.to_string_lossy())
        .expect("HTML result");
    assert_eq!(html_result.file_type.as_deref(), Some("text/html"));
}

#[test]
fn missing_scan_root_is_a_startup_error() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let missing = temp.path().join("does-not-exist");

    let error =
        scan_path_with_options(&missing, &scan_options()).expect_err("missing root must fail");
    assert!(format!("{error:#}").contains("cannot access"));
}

#[cfg(unix)]
#[test]
fn unreadable_files_are_reported_and_the_scan_continues() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("create temporary directory");
    let locked = temp.path().join("locked.txt");
    let readable = temp.path().join("readable.txt");
    write_fixture(&locked, CLEAN_TEXT);
    write_fixture(&readable, CLEAN_TEXT);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000))
        .expect("make fixture unreadable");

    if fs::File::open(&locked).is_ok() {
        // Privileged test runners can read mode 000 files.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o644))
            .expect("restore fixture permissions");
        return;
    }

    let report =
        scan_path_with_options(temp.path(), &scan_options()).expect("scan fixture directory");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o644))
        .expect("restore fixture permissions");

    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].path, readable.to_string_lossy());
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].path, locked.to_string_lossy());
    assert_eq!(report.failures[0].kind, FailureKind::Read);
    assert!(!report.failures[0].error.is_empty());
    assert!(!report.is_complete());
}

#[cfg(unix)]
#[test]
fn unreadable_directories_are_reported_and_the_walk_continues() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("create temporary directory");
    let readable = temp.path().join("readable.txt");
    let locked_dir = temp.path().join("locked-dir");
    write_fixture(&readable, CLEAN_TEXT);
    fs::create_dir(&locked_dir).expect("create locked directory");
    write_fixture(&locked_dir.join("inside.txt"), CLEAN_TEXT);
    fs::set_permissions(&locked_dir, fs::Permissions::from_mode(0o000))
        .expect("make directory unreadable");

    if fs::read_dir(&locked_dir).is_ok() {
        fs::set_permissions(&locked_dir, fs::Permissions::from_mode(0o755))
            .expect("restore directory permissions");
        return;
    }

    let report =
        scan_path_with_options(temp.path(), &scan_options()).expect("scan fixture directory");
    fs::set_permissions(&locked_dir, fs::Permissions::from_mode(0o755))
        .expect("restore directory permissions");

    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].path, readable.to_string_lossy());
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.kind == FailureKind::Walk
                && failure.path == locked_dir.to_string_lossy())
    );
    assert!(!report.is_complete());
}

#[cfg(unix)]
#[test]
fn directory_scans_skip_symlinks_but_explicit_symlinks_work() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("create temporary directory");
    let real = temp.path().join("real.txt");
    let link = temp.path().join("link.txt");
    write_fixture(&real, CLEAN_TEXT);
    symlink(&real, &link).expect("create symlink");

    let directory_report =
        scan_path_with_options(temp.path(), &scan_options()).expect("scan fixture directory");
    assert_eq!(directory_report.results.len(), 1);
    assert_eq!(directory_report.skipped, 1);
    assert_eq!(directory_report.results[0].path, real.to_string_lossy());

    let explicit_report =
        scan_path_with_options(&link, &scan_options()).expect("scan explicit symlink");
    assert_eq!(explicit_report.results.len(), 1);
    assert_eq!(explicit_report.results[0].path, link.to_string_lossy());
}

#[test]
fn cli_reports_findings_with_exit_status_one() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let clean_file = temp.path().join("clean.txt");
    let marker_file = temp.path().join("marker.txt");
    write_fixture(&clean_file, CLEAN_TEXT);
    write_fixture(&marker_file, "TORVEX_YARA_EXAMPLE_TEXT");

    let output = run_cli(
        &[
            "scan",
            temp.path().to_str().expect("UTF-8 temporary path"),
            "--rules",
            RULES_DIR,
        ],
        None,
    );

    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("Scanned: 2 files"));
    assert!(stdout.contains("Clean: 1"));
    assert!(stdout.contains("Suspicious: 1"));
    assert!(stdout.contains("Findings"));
    assert!(stdout.contains("torvex_example_text [demo fixture]"));
    assert!(stdout.contains("SHA-256:"));
    assert!(stdout.contains("demo fixtures are harmless test rules"));
}

#[test]
fn cli_returns_zero_for_a_clean_scan() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    write_fixture(&temp.path().join("clean.txt"), CLEAN_TEXT);

    let output = run_cli(
        &[
            "scan",
            temp.path().to_str().expect("UTF-8 temporary path"),
            "--rules",
            RULES_DIR,
        ],
        None,
    );

    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("No rule matches found."));
    assert!(stdout.contains("not proof that a file is safe"));
}

#[test]
fn cli_json_report_is_machine_readable() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let marker_file = temp.path().join("marker.txt");
    write_fixture(&marker_file, "TORVEX_YARA_EXAMPLE_TEXT");

    let output = run_cli(
        &[
            "scan",
            temp.path().to_str().expect("UTF-8 temporary path"),
            "--rules",
            RULES_DIR,
            "--json",
        ],
        None,
    );

    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(stderr(&output).contains("demo fixtures"));

    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is valid JSON");
    assert_eq!(report["tool"], "torvex");
    assert_eq!(report["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(report["summary"]["scanned"], 1);
    assert_eq!(report["summary"]["suspicious"], 1);
    assert_eq!(report["summary"]["errors"], 0);
    assert_eq!(report["failures"].as_array().unwrap().len(), 0);
    assert_eq!(report["rules"]["demo_rule_count"], 3);
    assert_eq!(report["results"][0]["verdict"], "suspicious");
    assert_eq!(
        report["results"][0]["matches"][0]["rule"],
        "torvex_example_text"
    );
    assert_eq!(report["results"][0]["matches"][0]["demo"], true);
    assert!(report["results"][0].get("confidence").is_none());
    assert!(report["results"][0].get("status").is_none());
}

#[cfg(unix)]
#[test]
fn cli_json_reports_unreadable_files_and_exit_status_two() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("create temporary directory");
    let locked = temp.path().join("locked.txt");
    let readable = temp.path().join("readable.txt");
    write_fixture(&locked, CLEAN_TEXT);
    write_fixture(&readable, CLEAN_TEXT);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000))
        .expect("make fixture unreadable");

    if fs::File::open(&locked).is_ok() {
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o644))
            .expect("restore fixture permissions");
        return;
    }

    let output = run_cli(
        &[
            "scan",
            temp.path().to_str().expect("UTF-8 temporary path"),
            "--rules",
            RULES_DIR,
            "--json",
        ],
        None,
    );
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o644))
        .expect("restore fixture permissions");

    assert_eq!(output.status.code(), Some(2), "stderr: {}", stderr(&output));
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is valid JSON");
    assert_eq!(report["summary"]["scanned"], 1);
    assert_eq!(report["summary"]["errors"], 1);
    assert_eq!(report["failures"][0]["kind"], "read");
    assert_eq!(
        report["failures"][0]["path"],
        locked.to_string_lossy().as_ref()
    );
    assert!(!report["failures"][0]["error"].as_str().unwrap().is_empty());
    assert_eq!(
        report["results"][0]["path"],
        readable.to_string_lossy().as_ref()
    );
}

#[test]
fn cli_loads_a_custom_rules_directory() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let rules_dir = temp.path().join("custom-rules");
    let scan_dir = temp.path().join("scan");
    fs::create_dir(&rules_dir).expect("create rules directory");
    fs::create_dir(&scan_dir).expect("create scan directory");
    write_fixture(
        &rules_dir.join("custom.yar"),
        r#"
rule torvex_test_custom
{
    meta:
        description = "Test-only custom marker"
    strings:
        $marker = "TORVEX_CUSTOM_TEST_MARKER"
    condition:
        $marker
}
"#,
    );
    write_fixture(&scan_dir.join("sample.txt"), "TORVEX_CUSTOM_TEST_MARKER");

    let output = run_cli(
        &[
            "scan",
            scan_dir.to_str().expect("UTF-8 temporary path"),
            "--rules",
            rules_dir.to_str().expect("UTF-8 temporary path"),
        ],
        None,
    );

    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("torvex_test_custom"));
    assert!(!stdout.contains("demo fixtures are harmless"));
}

#[test]
fn cli_falls_back_to_embedded_demo_rules() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    write_fixture(&temp.path().join("marker.txt"), "TORVEX_YARA_EXAMPLE_TEXT");

    let output = run_cli(
        &["scan", temp.path().to_str().expect("UTF-8 temporary path")],
        Some(temp.path()),
    );

    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("Rules: embedded demo rules"));
    assert!(stdout.contains("torvex_example_text"));
}

#[test]
fn cli_discovers_rules_in_the_current_directory() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let rules_dir = temp.path().join("rules");
    fs::create_dir(&rules_dir).expect("create rules directory");
    write_fixture(
        &rules_dir.join("custom.yar"),
        r#"
rule torvex_test_cwd
{
    strings:
        $marker = "TORVEX_CWD_RULE_MARKER"
    condition:
        $marker
}
"#,
    );
    write_fixture(&temp.path().join("sample.txt"), "TORVEX_CWD_RULE_MARKER");

    let output = run_cli(
        &["scan", temp.path().to_str().expect("UTF-8 temporary path")],
        Some(temp.path()),
    );

    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("Rules: rules"));
    assert!(stdout.contains("torvex_test_cwd"));
}

#[test]
fn cli_honors_the_rules_environment_variable() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let rules_dir = temp.path().join("env-rules");
    fs::create_dir(&rules_dir).expect("create rules directory");
    write_fixture(
        &rules_dir.join("custom.yar"),
        r#"
rule torvex_test_env
{
    strings:
        $marker = "TORVEX_ENV_RULE_MARKER"
    condition:
        $marker
}
"#,
    );
    let sample = temp.path().join("sample.txt");
    write_fixture(&sample, "TORVEX_ENV_RULE_MARKER");

    let output = Command::new(env!("CARGO_BIN_EXE_torvex"))
        .args(["scan", sample.to_str().expect("UTF-8 temporary path")])
        .env("TORVEX_RULES_DIR", &rules_dir)
        .current_dir(temp.path())
        .output()
        .expect("run torvex CLI");

    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains(rules_dir.to_str().expect("UTF-8 temporary path")));
    assert!(stdout.contains("torvex_test_env"));
}

#[test]
fn cli_missing_root_and_bad_rules_exit_with_code_two() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let missing = temp.path().join("missing");

    let output = run_cli(
        &[
            "scan",
            missing.to_str().expect("UTF-8 temporary path"),
            "--rules",
            RULES_DIR,
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("error:"));

    let empty_rules = temp.path().join("empty-rules");
    fs::create_dir(&empty_rules).expect("create empty rules directory");
    let output = run_cli(
        &[
            "scan",
            temp.path().to_str().expect("UTF-8 temporary path"),
            "--rules",
            empty_rules.to_str().expect("UTF-8 temporary path"),
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("no .yar or .yara rule files"));
}

#[test]
fn cli_version_prints_the_package_version() {
    let output = run_cli(&["version"], None);
    assert_eq!(output.status.code(), Some(0));
    assert!(stdout(&output).contains(env!("CARGO_PKG_VERSION")));
}
