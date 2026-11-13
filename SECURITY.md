# Security policy

Torvex is an early alpha and is not a replacement for maintained security
software. It does not currently provide real-time protection, quarantine,
automatic remediation, archive extraction, or a maintained malware signature
feed. A clean result does not prove that a file is safe.

## Supported versions

Only the latest `0.2.x` alpha release receives security fixes. Older releases and
unreleased source snapshots may not be supported.

## Scope

Reports are especially useful for:

- memory-safety or panic bugs triggered by crafted files, paths, or YARA rules;
- denial-of-service issues such as unbounded scanning, rule compilation, or
  timeout bypasses;
- path traversal or symlink behavior that escapes the requested scan root;
- unsafe handling of untrusted rule directories;
- leakage of scanned file contents or report data;
- dependency vulnerabilities with a practical impact on Torvex.

False positives, missing detections, and the limitations listed in the README
are not security vulnerabilities by themselves. Report them as normal issues
with a harmless reproducer and the rule name. Do not attach live malware.

## Reporting a vulnerability

Please do not publish exploit details, personal data, or malware samples in a
public issue. If GitHub private vulnerability reporting is enabled for this
repository, use its private reporting flow. Otherwise, contact the repository
owner through their GitHub profile to arrange a private report.

Include:

- affected version (`torvex version`);
- operating system and desktop session, if relevant;
- reproduction steps and a minimal safe reproducer;
- impact and any known workaround;
- whether the issue also affects the CLI, GUI, or library API.

Do not attach live malware. Use a synthetic reproducer or a hash and a
description instead. If a malicious rule is involved, share the smallest
non-destructive snippet that triggers the problem, with a clear warning about
its behavior.
