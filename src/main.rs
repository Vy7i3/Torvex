use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use torvex::engine::Verdict;

#[derive(Parser)]
#[command(name = "torvex", version, about = "Experimental local file scanner")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a file or directory
    Scan { path: PathBuf },
    /// Open the graphical scanner
    Gui,
    /// Show version
    Version,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan { path } => {
            run_scan(&path)?;
        }
        Command::Gui => {
            torvex::gui::run().map_err(|error| anyhow::anyhow!("GUI failed: {error}"))?;
        }
        Command::Version => {
            println!("{}", env!("CARGO_PKG_VERSION"));
        }
    }

    Ok(())
}

fn run_scan(path: &Path) -> anyhow::Result<()> {
    let results = torvex::scanner::scan_path(path)?;

    let clean = results
        .iter()
        .filter(|result| result.status == Verdict::Clean)
        .count();
    let suspicious = results
        .iter()
        .filter(|result| result.status == Verdict::Suspicious)
        .count();
    let malicious = results
        .iter()
        .filter(|result| result.status == Verdict::Malicious)
        .count();

    println!("Scan summary");
    println!("  Total files scanned: {}", results.len());
    println!("  Clean: {clean}");
    println!("  Suspicious: {suspicious}");
    println!("  Malicious: {malicious}");

    if suspicious + malicious > 0 {
        println!("\nFindings:");
        for result in results
            .iter()
            .filter(|result| matches!(result.status, Verdict::Suspicious | Verdict::Malicious))
        {
            println!("  Status: {}", result.status);
            println!("    Path: {}", result.path);
            println!("    SHA-256: {}", result.sha256);
            match result.confidence {
                Some(confidence) => println!("    Confidence: {confidence:.2}"),
                None => println!("    Confidence: not calibrated"),
            }
            if let Some(reason) = &result.reason {
                println!("    Reason: {reason}");
            }
        }
    }

    Ok(())
}
