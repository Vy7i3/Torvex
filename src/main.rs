#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use torvex::engine::{RuleSetInfo, ScanFailure, ScanReport, ScanResult, ScanSummary};
use torvex::scanner::{ScanOptions, scan_path_with_options};
use torvex::utils::{format_bytes, format_duration};

/// Exit status for a completed scan with no rule matches.
const EXIT_CLEAN: u8 = 0;
/// Exit status for a completed scan with at least one rule match.
const EXIT_FINDINGS: u8 = 1;
/// Exit status for an incomplete or failed scan.
const EXIT_ERROR: u8 = 2;

#[derive(Parser)]
#[command(
    name = "torvex",
    version,
    about = "Experimental local-first file scanner (not an antivirus)",
    long_about = "Torvex is an experimental local-first file scanner. It hashes files, \
                  estimates file types, and checks them against YARA-X rules. A rule match \
                  is reported as suspicious, not confirmed malware. Torvex is not a \
                  replacement for maintained security software."
)]
struct Cli {
    /// Directory containing .yar or .yara rules
    ///
    /// If omitted, Torvex checks TORVEX_RULES_DIR, a rules directory next to
    /// the executable, and ./rules, then falls back to embedded demo rules.
    #[arg(long, global = true, value_name = "DIR")]
    rules: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a file or directory and report matches
    Scan(ScanArgs),
    /// Open the graphical scanner
    Gui,
    /// Print version information
    Version,
}

#[derive(Args)]
struct ScanArgs {
    /// File or directory to scan
    path: PathBuf,

    /// Emit a machine-readable JSON report on stdout
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli) {
        Ok(status) => status,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    let Cli { rules, command } = cli;

    match command {
        Command::Scan(args) => run_scan(&args.path, rules.as_deref(), args.json),
        Command::Gui => {
            torvex::gui::run(rules).map_err(|error| anyhow!("GUI failed: {error}"))?;
            Ok(ExitCode::from(EXIT_CLEAN))
        }
        Command::Version => {
            println!("torvex {} (MIT OR Apache-2.0)", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::from(EXIT_CLEAN))
        }
    }
}

fn run_scan(path: &Path, rules: Option<&Path>, json: bool) -> Result<ExitCode> {
    let started = Instant::now();
    let options = ScanOptions {
        rules_dir: rules.map(Path::to_path_buf),
    };
    let report = scan_path_with_options(path, &options)?;
    let duration = started.elapsed();

    if json {
        write_json_report(&report, duration)?;
        if report.rules.demo_rule_count > 0 {
            eprintln!(
                "warning: {} of {} loaded rules are demo fixtures, not malware signatures",
                report.rules.demo_rule_count, report.rules.rule_count
            );
        }
    } else {
        write_human_report(&report, duration)?;
    }

    let status = if !report.is_complete() {
        EXIT_ERROR
    } else if report.has_findings() {
        EXIT_FINDINGS
    } else {
        EXIT_CLEAN
    };
    Ok(ExitCode::from(status))
}

#[derive(Serialize)]
struct JsonReport<'a> {
    tool: &'static str,
    version: &'static str,
    root: &'a str,
    rules: &'a RuleSetInfo,
    summary: ScanSummary,
    duration_ms: u64,
    results: &'a [ScanResult],
    failures: &'a [ScanFailure],
}

fn write_json_report(report: &ScanReport, duration: Duration) -> Result<()> {
    let output = JsonReport {
        tool: "torvex",
        version: env!("CARGO_PKG_VERSION"),
        root: &report.root,
        rules: &report.rules,
        summary: report.summary(),
        duration_ms: u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
        results: &report.results,
        failures: &report.failures,
    };

    let stdout = io::stdout();
    let mut writer = stdout.lock();
    serde_json::to_writer_pretty(&mut writer, &output).context("failed to write JSON report")?;
    writeln!(writer).context("failed to finish JSON report")?;
    Ok(())
}

fn write_human_report(report: &ScanReport, duration: Duration) -> Result<()> {
    let summary = report.summary();
    let mut output = String::new();

    writeln!(
        output,
        "Torvex {} - experimental file scanner (not an antivirus)",
        env!("CARGO_PKG_VERSION")
    )
    .expect("writing to a String cannot fail");
    writeln!(output).expect("writing to a String cannot fail");
    writeln!(output, "Scan: {}", report.root).expect("writing to a String cannot fail");
    writeln!(
        output,
        "Rules: {} ({})",
        report.rules.source,
        report.rules.describe()
    )
    .expect("writing to a String cannot fail");
    if report.rules.demo_rule_count > 0 {
        writeln!(
            output,
            "  Warning: demo fixtures are harmless test rules, not malware signatures."
        )
        .expect("writing to a String cannot fail");
    }

    writeln!(output).expect("writing to a String cannot fail");
    writeln!(output, "Summary").expect("writing to a String cannot fail");
    writeln!(
        output,
        "  Scanned: {} {} in {} ({})",
        summary.scanned,
        plural(summary.scanned, "file", "files"),
        format_duration(duration),
        format_bytes(summary.bytes_scanned)
    )
    .expect("writing to a String cannot fail");
    writeln!(output, "  Clean: {}", summary.clean).expect("writing to a String cannot fail");
    writeln!(output, "  Suspicious: {}", summary.suspicious)
        .expect("writing to a String cannot fail");
    if summary.errors > 0 {
        writeln!(output, "  Errors: {}", summary.errors).expect("writing to a String cannot fail");
    }
    if summary.skipped > 0 {
        writeln!(output, "  Skipped non-regular entries: {}", summary.skipped)
            .expect("writing to a String cannot fail");
    }

    if report.has_findings() {
        writeln!(output).expect("writing to a String cannot fail");
        writeln!(output, "Findings").expect("writing to a String cannot fail");
        for result in report
            .results
            .iter()
            .filter(|result| result.is_suspicious())
        {
            writeln!(output, "  [suspicious] {}", result.path)
                .expect("writing to a String cannot fail");
            writeln!(output, "    SHA-256: {}", result.sha256)
                .expect("writing to a String cannot fail");
            writeln!(output, "    Size: {}", format_bytes(result.size))
                .expect("writing to a String cannot fail");
            writeln!(
                output,
                "    Type: {}",
                result.file_type.as_deref().unwrap_or("unknown")
            )
            .expect("writing to a String cannot fail");
            for rule_match in &result.matches {
                writeln!(
                    output,
                    "    Rule: {}{}",
                    rule_match.rule,
                    if rule_match.demo {
                        " [demo fixture]"
                    } else {
                        ""
                    }
                )
                .expect("writing to a String cannot fail");
                writeln!(output, "      Namespace: {}", rule_match.namespace)
                    .expect("writing to a String cannot fail");
                if !rule_match.tags.is_empty() {
                    writeln!(output, "      Tags: {}", rule_match.tags.join(", "))
                        .expect("writing to a String cannot fail");
                }
                if let Some(description) = &rule_match.description {
                    writeln!(output, "      Description: {description}")
                        .expect("writing to a String cannot fail");
                }
            }
        }
    } else if summary.scanned == 0 {
        writeln!(output).expect("writing to a String cannot fail");
        writeln!(output, "No files were successfully scanned.")
            .expect("writing to a String cannot fail");
    } else {
        writeln!(output).expect("writing to a String cannot fail");
        writeln!(output, "No rule matches found.").expect("writing to a String cannot fail");
        writeln!(
            output,
            "A clean result only means that no loaded rule matched; it is not proof that a file is safe."
        )
        .expect("writing to a String cannot fail");
    }

    if !report.failures.is_empty() {
        writeln!(output).expect("writing to a String cannot fail");
        writeln!(output, "Scan errors").expect("writing to a String cannot fail");
        for failure in &report.failures {
            writeln!(output, "  [{}] {}", failure.kind, failure.path)
                .expect("writing to a String cannot fail");
            writeln!(output, "    {}", failure.error).expect("writing to a String cannot fail");
        }
        writeln!(
            output,
            "  The scan is incomplete; files listed above were not fully checked."
        )
        .expect("writing to a String cannot fail");
    }

    io::stdout()
        .write_all(output.as_bytes())
        .context("failed to write scan report")
}

fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}
