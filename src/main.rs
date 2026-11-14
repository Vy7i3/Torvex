#![deny(unsafe_code)]

use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use torvex::audit::{self, AuditOptions};
use torvex::detection::YaraEngine;
use torvex::engine::{RuleSetInfo, ScanReport};
use torvex::findings::Severity;
use torvex::report;
use torvex::scanner::{self, EngineSelection, ScanOptions, scan_path_with_options};
use torvex::utils::{DEFAULT_SCAN_LIMIT, format_bytes};
use torvex::web::{self, WebOptions};

/// Exit status for a completed scan with nothing at or above the fail level.
const EXIT_CLEAN: u8 = 0;
/// Exit status for a completed scan with blocking findings.
const EXIT_FINDINGS: u8 = 1;
/// Exit status for an incomplete or failed scan.
const EXIT_ERROR: u8 = 2;

#[derive(Parser)]
#[command(
    name = "torvex",
    version,
    about = "Local-first security scanner: content rules, native indicators and a host audit",
    long_about = "Torvex scans files with YARA-X and a native C++ indicator engine, audits a Linux \
                  host with a Python configuration assessment, correlates the results, and renders \
                  them as a terminal report, JSON or a self-contained dashboard.\n\n\
                  It is not an antivirus. A finding is evidence to review, not proof of malware, \
                  and a clean result only means no loaded rule matched.",
    after_help = "EXIT CODES\n  0  no blocking findings\n  1  findings at or above --fail-on\n  2  incomplete or failed scan\n\n\
                  EXAMPLES\n  torvex scan .                      scan the current directory\n  torvex scan /srv --audit           scan files and audit the host\n  torvex audit --root /              host configuration assessment\n  torvex scan . --format html        write torvex-report.html\n  torvex serve --root .              open the local dashboard\n  torvex rules list                  show the active rule set"
)]
struct Cli {
    /// Directory containing .yar or .yara rules
    ///
    /// If omitted, Torvex checks TORVEX_RULES_DIR, a rules directory next to
    /// the executable, and ./rules, then falls back to embedded demo rules.
    #[arg(long, global = true, value_name = "DIR")]
    rules: Option<PathBuf>,

    /// Disable ANSI colour in terminal output
    #[arg(long, global = true)]
    no_color: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan files or directories and report findings
    Scan(ScanArgs),
    /// Audit a Linux host's security configuration
    Audit(AuditArgs),
    /// Re-render a saved JSON report as a dashboard
    Report(ReportArgs),
    /// Serve the local dashboard and scan form
    Serve(ServeArgs),
    /// Inspect or validate the YARA rule set
    Rules(RulesArgs),
    /// Show engine versions and capabilities
    Info,
    /// Open the optional desktop GUI (build with --features gui)
    Gui,
    /// Print version information
    Version,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Human-readable terminal report
    Pretty,
    /// Machine-readable JSON report
    Json,
    /// Self-contained HTML dashboard
    Html,
}

#[derive(Args)]
struct ScanArgs {
    /// Files or directories to scan
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// Emit a machine-readable JSON report (alias for --format json)
    #[arg(long, conflicts_with = "format")]
    json: bool,

    /// Output format
    #[arg(long, value_enum, default_value = "pretty")]
    format: Format,

    /// Write the report to a file instead of stdout
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Skip YARA-X content rules
    #[arg(long)]
    no_yara: bool,

    /// Skip the native indicator engine
    #[arg(long)]
    no_native: bool,

    /// Run the host configuration audit as part of the scan
    #[arg(long)]
    audit: bool,

    /// Filesystem root for the audit (defaults to /)
    #[arg(long, value_name = "DIR")]
    audit_root: Option<PathBuf>,

    /// Audit policy JSON file
    #[arg(long, value_name = "FILE")]
    policy: Option<PathBuf>,

    /// Audit control id to skip (repeatable)
    #[arg(long = "skip", value_name = "ID")]
    skip: Vec<String>,

    /// Python interpreter for the audit
    #[arg(long, value_name = "PATH")]
    python: Option<PathBuf>,

    /// Disable finding correlation
    #[arg(long)]
    no_correlation: bool,

    /// Custom correlation rule file
    #[arg(long, value_name = "FILE")]
    correlation: Option<PathBuf>,

    /// Maximum bytes buffered per file for content engines
    #[arg(long, value_name = "BYTES", default_value_t = DEFAULT_SCAN_LIMIT)]
    max_file_size: u64,

    /// Also scan vendor and build directories (.git, node_modules, target, ...)
    #[arg(long)]
    include_vendor: bool,

    /// Findings at or above this severity fail the scan
    #[arg(long, value_name = "LEVEL", default_value = "any")]
    fail_on: String,
}

#[derive(Args)]
struct AuditArgs {
    /// Filesystem root to audit
    #[arg(long, value_name = "DIR", default_value = "/")]
    root: PathBuf,

    /// Audit policy JSON file
    #[arg(long, value_name = "FILE")]
    policy: Option<PathBuf>,

    /// Audit control id to skip (repeatable)
    #[arg(long = "skip", value_name = "ID")]
    skip: Vec<String>,

    /// Python interpreter for the audit
    #[arg(long, value_name = "PATH")]
    python: Option<PathBuf>,

    /// Output format
    #[arg(long, value_enum, default_value = "pretty")]
    format: Format,

    /// Emit JSON (alias for --format json)
    #[arg(long, conflicts_with = "format")]
    json: bool,

    /// Write the report to a file instead of stdout
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Warnings at or above this severity fail the command
    #[arg(long, value_name = "LEVEL", default_value = "medium")]
    fail_on: String,
}

#[derive(Args)]
struct ReportArgs {
    /// Saved JSON report from `torvex scan --json`
    input: PathBuf,

    /// Destination HTML file
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
}

#[derive(Args)]
struct ServeArgs {
    /// Interface to bind
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Port to listen on
    #[arg(long, default_value_t = 8787)]
    port: u16,

    /// Directory the dashboard may scan
    #[arg(long, value_name = "DIR", default_value = ".")]
    root: PathBuf,

    /// Allow scanning outside --root
    #[arg(long)]
    allow_outside_root: bool,

    /// Skip YARA-X content rules
    #[arg(long)]
    no_yara: bool,

    /// Skip the native indicator engine
    #[arg(long)]
    no_native: bool,

    /// Maximum bytes buffered per file
    #[arg(long, value_name = "BYTES", default_value_t = DEFAULT_SCAN_LIMIT)]
    max_file_size: u64,
}

#[derive(Args)]
struct RulesArgs {
    #[command(subcommand)]
    action: RulesAction,
}

#[derive(Subcommand)]
enum RulesAction {
    /// List every compiled rule
    List,
    /// Compile the rule set and report problems
    Validate,
}

fn main() -> ExitCode {
    match run() {
        Ok(status) => status,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let color =
        !cli.no_color && std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();

    match cli.command {
        Command::Scan(args) => run_scan(args, cli.rules, color),
        Command::Audit(args) => run_audit(args, color),
        Command::Report(args) => run_report(args),
        Command::Serve(args) => run_serve(args, cli.rules),
        Command::Rules(args) => run_rules(args, cli.rules),
        Command::Info => run_info(cli.rules),
        Command::Gui => run_gui(cli.rules),
        Command::Version => {
            println!(
                "torvex {} (report schema {})",
                env!("CARGO_PKG_VERSION"),
                torvex::engine::SCHEMA
            );
            println!(
                "native core {}",
                torvex::detection::NativeEngine::new()
                    .map(|engine| engine.version().to_owned())
                    .unwrap_or_else(|_| "unavailable".to_owned())
            );
            Ok(ExitCode::from(EXIT_CLEAN))
        }
    }
}

fn run_scan(args: ScanArgs, rules: Option<PathBuf>, color: bool) -> Result<ExitCode> {
    let format = if args.json { Format::Json } else { args.format };
    let fail_level = parse_fail_on(&args.fail_on)?;
    let audit_requested = args.audit;
    let multi = args.paths.len() > 1;

    let mut options = ScanOptions {
        rules_dir: rules,
        engines: EngineSelection {
            yara: !args.no_yara,
            native: !args.no_native,
            // For several roots, run the audit once at the end instead.
            audit: audit_requested && !multi,
        },
        audit_root: args.audit_root.clone(),
        audit_policy: args.policy.clone(),
        audit_skip: args.skip.clone(),
        python: args.python.clone(),
        correlation: !args.no_correlation,
        correlation_file: args.correlation.clone(),
        max_scan_bytes: args.max_file_size,
        ignore_dirs: if args.include_vendor {
            Vec::new()
        } else {
            ScanOptions::default().ignore_dirs
        },
    };

    let mut report = scan_many(&args.paths, &options)?;

    if audit_requested && multi {
        options.engines.audit = true;
        scanner::attach_audit(&mut report, &options);
        report
            .findings
            .sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
        report.refresh_summary();
    }

    emit_report(&report, format, args.output.as_deref(), color)?;

    if report.rules.demo_rule_count > 0 {
        eprintln!(
            "warning: {} of {} loaded rules are demo fixtures, not detection content",
            report.rules.demo_rule_count, report.rules.rule_count
        );
    }
    if let Some(error) = &report.audit_error {
        eprintln!("warning: host audit did not run: {error}");
    }

    Ok(ExitCode::from(exit_code(&report, fail_level)))
}

fn run_audit(args: AuditArgs, color: bool) -> Result<ExitCode> {
    let format = if args.json { Format::Json } else { args.format };
    let fail_level = parse_fail_on(&args.fail_on)?;

    let audit = audit::run(&AuditOptions {
        root: args.root.clone(),
        policy: args.policy,
        skip: args.skip,
        python: args.python,
    })?;

    let mut report = ScanReport::new(audit.root.clone(), RuleSetInfo::default());
    report.engines.audit = true;
    report.findings = audit.findings();
    report.audit = Some(audit);
    report.refresh_summary();

    emit_report(&report, format, args.output.as_deref(), color)?;
    Ok(ExitCode::from(exit_code(&report, fail_level)))
}

fn run_report(args: ReportArgs) -> Result<ExitCode> {
    let text = std::fs::read_to_string(&args.input)
        .with_context(|| format!("failed to read {}", args.input.display()))?;
    let report: ScanReport = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a Torvex JSON report", args.input.display()))?;
    let html = report::render_report(&report);
    let target = args
        .output
        .unwrap_or_else(|| PathBuf::from("torvex-report.html"));
    std::fs::write(&target, html)
        .with_context(|| format!("failed to write {}", target.display()))?;
    eprintln!("wrote {}", target.display());
    Ok(ExitCode::from(EXIT_CLEAN))
}

fn run_serve(args: ServeArgs, rules: Option<PathBuf>) -> Result<ExitCode> {
    let options = WebOptions {
        host: args.host,
        port: args.port,
        root: args.root,
        scan: ScanOptions {
            rules_dir: rules,
            engines: EngineSelection {
                yara: !args.no_yara,
                native: !args.no_native,
                audit: false,
            },
            max_scan_bytes: args.max_file_size,
            ..ScanOptions::default()
        },
        allow_outside_root: args.allow_outside_root,
    };
    web::serve(options)?;
    Ok(ExitCode::from(EXIT_CLEAN))
}

fn run_rules(args: RulesArgs, rules: Option<PathBuf>) -> Result<ExitCode> {
    let engine = YaraEngine::new(rules.as_deref())?;
    let info = engine.info();

    match args.action {
        RulesAction::List => {
            println!("Rules: {} ({})", info.source, info.describe());
            for (rule, namespace, demo) in engine.list_rules() {
                println!(
                    "  {rule:<40} {namespace:<10}{}",
                    if demo { " demo fixture" } else { "" }
                );
            }
        }
        RulesAction::Validate => {
            println!(
                "OK: {} compiled rule(s) from {} ({} demo fixture(s))",
                info.rule_count, info.source, info.demo_rule_count
            );
            let correlation = torvex::correlation::CorrelationSet::builtin();
            println!(
                "OK: {} correlation rule(s) in the built-in ruleset",
                correlation.rules.len()
            );
        }
    }
    Ok(ExitCode::from(EXIT_CLEAN))
}

fn run_info(rules: Option<PathBuf>) -> Result<ExitCode> {
    println!("Torvex {}", env!("CARGO_PKG_VERSION"));
    println!("Report schema: {}", torvex::engine::SCHEMA);

    match YaraEngine::new(rules.as_deref()) {
        Ok(engine) => println!(
            "YARA-X: {} ({})",
            engine.info().source,
            engine.info().describe()
        ),
        Err(error) => println!("YARA-X: unavailable ({error:#})"),
    }

    match torvex::detection::NativeEngine::new() {
        Ok(engine) => println!(
            "Native: {} with {} indicator rules",
            engine.version(),
            engine.rule_count()
        ),
        Err(error) => println!("Native: unavailable ({error:#})"),
    }

    let correlation = torvex::correlation::CorrelationSet::builtin();
    println!(
        "Correlation: {} rules (version {})",
        correlation.rules.len(),
        correlation.version
    );

    match audit::audit_script() {
        Ok(path) => println!("Audit engine: {} (Python)", path.display()),
        Err(error) => println!("Audit engine: unavailable ({error:#})"),
    }
    let python = audit::python_interpreter(None);
    match std::process::Command::new(&python)
        .arg("--version")
        .output()
    {
        Ok(output) => println!(
            "Python: {} ({})",
            String::from_utf8_lossy(&output.stdout).trim(),
            python.display()
        ),
        Err(_) => println!(
            "Python: not found at {}; the host audit will be unavailable",
            python.display()
        ),
    }
    println!(
        "Ignored directories: {}",
        scanner::DEFAULT_IGNORED_DIRS.join(", ")
    );
    Ok(ExitCode::from(EXIT_CLEAN))
}

#[cfg(feature = "gui")]
fn run_gui(rules: Option<PathBuf>) -> Result<ExitCode> {
    torvex::gui::run(rules).map_err(|error| anyhow::anyhow!("GUI failed: {error}"))?;
    Ok(ExitCode::from(EXIT_CLEAN))
}

#[cfg(not(feature = "gui"))]
fn run_gui(_rules: Option<PathBuf>) -> Result<ExitCode> {
    anyhow::bail!(
        "this build has no desktop GUI. Use `torvex serve` for the dashboard, or build with --features gui (requires X11/Wayland and OpenGL development headers)"
    )
}

fn scan_many(paths: &[PathBuf], options: &ScanOptions) -> Result<ScanReport> {
    let mut reports = Vec::with_capacity(paths.len());
    for path in paths {
        reports.push(scan_path_with_options(path, options)?);
    }

    let mut iter = reports.into_iter();
    let mut combined = iter.next().context("at least one path is required")?;
    combined.root = paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");

    for report in iter {
        combined.results.extend(report.results);
        combined.findings.extend(report.findings);
        combined.failures.extend(report.failures);
        combined.skipped += report.skipped;
        combined.correlated += report.correlated;
        combined.duration_ms += report.duration_ms;
        combined.engines.native |= report.engines.native;
        combined.engines.yara |= report.engines.yara;
        if combined.rules.rule_count == 0 {
            combined.rules = report.rules;
        }
    }

    combined
        .findings
        .sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    combined.refresh_summary();
    Ok(combined)
}

fn emit_report(
    report: &ScanReport,
    format: Format,
    output: Option<&Path>,
    color: bool,
) -> Result<()> {
    match format {
        Format::Pretty => {
            let text = report::render_pretty(report, color);
            write_output(output, text.as_bytes())?;
        }
        Format::Json => {
            let mut json = serde_json::to_string_pretty(report)?;
            json.push('\n');
            write_output(output, json.as_bytes())?;
        }
        Format::Html => {
            let html = report::render_report(report);
            match output {
                Some(path) => {
                    std::fs::write(path, html)
                        .with_context(|| format!("failed to write {}", path.display()))?;
                    eprintln!("wrote {}", path.display());
                }
                None => {
                    let path = PathBuf::from("torvex-report.html");
                    std::fs::write(&path, html).context("failed to write torvex-report.html")?;
                    eprintln!(
                        "wrote {} (use --output to choose a different path)",
                        path.display()
                    );
                }
            }
        }
    }
    Ok(())
}

fn write_output(path: Option<&Path>, bytes: &[u8]) -> Result<()> {
    match path {
        Some(path) => {
            std::fs::write(path, bytes)
                .with_context(|| format!("failed to write {}", path.display()))?;
            eprintln!(
                "wrote {} ({} bytes)",
                path.display(),
                format_bytes(bytes.len() as u64)
            );
            Ok(())
        }
        None => {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            handle.write_all(bytes)?;
            handle.flush()?;
            Ok(())
        }
    }
}

fn exit_code(report: &ScanReport, fail_level: Option<u8>) -> u8 {
    if !report.is_complete() {
        return EXIT_ERROR;
    }
    match fail_level {
        Some(level) if !report.findings_at_least(level).is_empty() => EXIT_FINDINGS,
        _ => EXIT_CLEAN,
    }
}

/// Parses `--fail-on`: `none`, `any`, or a severity name.
fn parse_fail_on(value: &str) -> Result<Option<u8>> {
    match value.trim().to_ascii_lowercase().as_str() {
        "none" | "never" | "off" => Ok(None),
        "any" | "all" => Ok(Some(1)),
        other => Severity::parse(other)
            .map(|severity| Some(severity.level()))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid --fail-on value {other:?}; expected none, any, info, low, medium, high or critical"
                )
            }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_on_parses_every_form() {
        assert_eq!(parse_fail_on("none").expect("none"), None);
        assert_eq!(parse_fail_on("any").expect("any"), Some(1));
        assert_eq!(parse_fail_on("low").expect("low"), Some(3));
        assert_eq!(parse_fail_on("HIGH").expect("high"), Some(8));
        assert_eq!(parse_fail_on("critical").expect("critical"), Some(10));
        assert!(parse_fail_on("nonsense").is_err());
    }

    #[test]
    fn exit_code_uses_the_fail_level() {
        let mut report = ScanReport::new("root".to_owned(), RuleSetInfo::default());
        report.findings.push(torvex::findings::Finding::new(
            "x",
            "x",
            Severity::Low,
            torvex::findings::Source::Yara,
            "f",
        ));
        report.refresh_summary();
        assert_eq!(exit_code(&report, None), EXIT_CLEAN);
        assert_eq!(exit_code(&report, Some(3)), EXIT_FINDINGS);
        assert_eq!(exit_code(&report, Some(8)), EXIT_CLEAN);
    }
}
