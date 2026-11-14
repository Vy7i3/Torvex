# Security policy

## Supported versions

Torvex is `0.x` software. Only the latest release receives fixes.

| Version | Supported |
| --- | --- |
| 0.3.x | Yes |
| 0.2.x and earlier | No |

## Reporting a vulnerability

Open a private security advisory on the repository, or contact the maintainer
directly. Do not open a public issue for a vulnerability before a fix is
available.

Please include:

- the Torvex version and platform;
- the smallest reproduction you can construct;
- whether the issue is a crash, a memory-safety problem in the native core, a
  bypass of a safety control, or a false negative/positive with security impact.

Do not include live malware. A synthetic fixture is enough.

## What Torvex promises

* **Read-only.** Scanning never writes to, deletes, quarantines or repairs a
  scanned file. The audit never modifies host configuration.
* **Local-first.** The scanner makes no network requests. Nothing is uploaded.
* **Bounded.** Per-file buffering is capped, YARA evaluation times out, the
  native core caps matches and the audit has a hard timeout.
* **Contained `unsafe`.** `unsafe` is denied crate-wide and allowed only in
  `detection::ffi`, the C ABI boundary. Its ownership rules are documented and
  tested.
* **Loopback dashboard.** `torvex serve` binds `127.0.0.1` by default, requires
  a per-process token for scans, confines scans to `--root`, and sends
  `no-store`, `nosniff`, `DENY` framing and a restrictive CSP.

## What Torvex does not promise

* That a clean scan means a file or host is safe.
* That a finding is proof of malware.
* Protection against a hostile rule pack or audit policy. Rules and policies are
  **trusted input**: a malicious YARA rule or Python plugin can consume
  resources or change results. Only load content you trust.
* Authentication for the dashboard. The token is a CSRF guard, not a login. Do
  not expose the dashboard to an untrusted network; `--host 0.0.0.0` prints a
  warning for that reason.
* Sandboxing of scanned files. Torvex reads bytes; it never executes a sample.

## Areas of interest for researchers

- The C ABI boundary: matcher lifetime, string ownership, needle validation.
- Bounds handling in the ELF/PE parsers on malformed or truncated headers.
- Resource exhaustion through crafted files, deep directory trees or rule packs.
- Path traversal or command injection through audit roots and control ids.
- Escaping in the HTML dashboard (JSON embedded in a script element) and in
  terminal output.
- Correlation rule semantics producing misleading compound findings.

## Disclosure

Fixes are released with a changelog entry and, where relevant, a regression test
that reproduces the issue without live malware.
