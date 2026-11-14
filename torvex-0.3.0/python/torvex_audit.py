#!/usr/bin/env python3
"""Torvex host audit engine.

A Lynis-style, read-only configuration assessment for Linux hosts, emitting the
JSON that the Rust core turns into findings.

Framework
---------
* Every control has a stable identifier: a category prefix and a number
  (``SSH-7401``), the way Lynis names its tests. The identifier is the handle
  users search for and suppress.
* Each control reports one status: ``passed``, ``failed``, ``suggestion``,
  ``skipped`` or ``manual``. Skipped controls are inapplicable, not passing.
* Points follow the Lynis hardening-index idea: each applicable control has a
  weight; passing earns all of it, a suggestion earns 60%, failing earns none.
  The index is ``earned / possible`` over applicable controls only. It is a
  relative progress indicator, never a grade.
* Severity, MITRE ATT&CK and compliance tags follow the Wazuh finding model so
  host findings and file findings can be correlated in one report.

Safety
------
The engine is strictly read-only. It never writes, never changes a setting and
never deletes anything. External commands are restricted to a small allowlist of
read-only probes and are only run against the live root filesystem; an audit of
a ``--root`` snapshot is fully hermetic. File reads are size-capped.
"""

from __future__ import annotations

import argparse
import glob as glob_module
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Optional

ENGINE_VERSION = "1.0.0"
SCHEMA = "torvex.audit.v1"
MAX_READ = 1 << 20  # 1 MiB cap for any configuration file

# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def level(self) -> int:
        """Wazuh-style 0-15 level used for sorting and fail thresholds."""
        return {
            "info": 1,
            "low": 3,
            "medium": 6,
            "high": 8,
            "critical": 10,
        }[self.value]


class Status(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    SUGGESTION = "suggestion"
    SKIPPED = "skipped"
    MANUAL = "manual"


#: Fraction of the weight a status earns.
CREDIT = {
    Status.PASSED: 1.0,
    Status.FAILED: 0.0,
    Status.SUGGESTION: 0.6,
    Status.MANUAL: 0.0,
}


@dataclass(frozen=True)
class Outcome:
    status: Status
    evidence: str
    target: str = ""
    detail: str = ""

    @classmethod
    def ok(cls, evidence: str, target: str = "") -> "Outcome":
        return cls(Status.PASSED, evidence, target)

    @classmethod
    def bad(cls, evidence: str, target: str = "", detail: str = "") -> "Outcome":
        return cls(Status.FAILED, evidence, target, detail)

    @classmethod
    def suggest(cls, evidence: str, target: str = "", detail: str = "") -> "Outcome":
        return cls(Status.SUGGESTION, evidence, target, detail)

    @classmethod
    def skip(cls, evidence: str) -> "Outcome":
        return cls(Status.SKIPPED, evidence)

    @classmethod
    def manual(cls, evidence: str) -> "Outcome":
        return cls(Status.MANUAL, evidence)


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    category: str
    severity: Severity
    rationale: str
    remediation: str
    run: Callable[["Context"], Outcome]
    compliance: tuple[str, ...] = ()
    mitre: tuple[str, ...] = ()
    weight: float = 1.0
    kind: str = "config"


CONTROLS: list[Control] = []


def control(
    control_id: str,
    title: str,
    category: str,
    severity: Severity,
    *,
    rationale: str,
    remediation: str,
    compliance: Iterable[str] = (),
    mitre: Iterable[str] = (),
    weight: float = 1.0,
    kind: str = "config",
) -> Callable[[Callable[["Context"], Outcome]], Callable[["Context"], Outcome]]:
    """Registers a control. Used as a decorator by every check below."""

    def register(function: Callable[["Context"], Outcome]) -> Callable[["Context"], Outcome]:
        CONTROLS.append(
            Control(
                id=control_id,
                title=title,
                category=category,
                severity=severity,
                rationale=rationale,
                remediation=remediation,
                run=function,
                compliance=tuple(compliance),
                mitre=tuple(mitre),
                weight=weight,
                kind=kind,
            )
        )
        return function

    return register


# ---------------------------------------------------------------------------
# Context: rooted, read-only filesystem access
# ---------------------------------------------------------------------------

ALLOWED_COMMANDS = (
    ("sysctl", "-n"),
    ("ss", "-lntu"),
    ("nft", "list"),
    ("ufw", "status"),
    ("ufw", "status", "verbose"),
    ("systemctl", "is-enabled"),
    ("systemctl", "is-active"),
    ("getenforce",),
    ("sestatus",),
    ("aa-status",),
    ("uname", "-s"),
)


class Context:
    """Read-only view of a filesystem root plus a policy."""

    def __init__(self, root: str = "/", policy: Optional[dict] = None) -> None:
        self.root = Path(root).resolve()
        self.policy = policy or {}
        self._live = str(self.root) == "/"
        self._sysctl: dict[str, str] = {}
        self._sysctl_loaded = False
        self._sshd: Optional[dict[str, str]] = None
        self._sshd_files: list[str] = []

    # -- paths ------------------------------------------------------------
    def path(self, relative: str) -> Optional[Path]:
        candidate = (self.root / relative.lstrip("/")).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError:
            return None
        return candidate

    def exists(self, relative: str) -> bool:
        candidate = self.path(relative)
        return candidate is not None and candidate.exists()

    def is_dir(self, relative: str) -> bool:
        candidate = self.path(relative)
        return candidate is not None and candidate.is_dir()

    def stat(self, relative: str):
        candidate = self.path(relative)
        if candidate is None:
            return None
        try:
            return candidate.stat()
        except OSError:
            return None

    def read(self, relative: str, limit: int = MAX_READ) -> Optional[str]:
        candidate = self.path(relative)
        if candidate is None:
            return None
        try:
            with open(candidate, "rb") as handle:
                raw = handle.read(limit)
        except OSError:
            return None
        return raw.decode("utf-8", errors="replace")

    def read_lines(self, relative: str) -> list[str]:
        text = self.read(relative)
        return text.splitlines() if text else []

    def listdir(self, relative: str) -> list[str]:
        candidate = self.path(relative)
        if candidate is None:
            return []
        try:
            return sorted(entry.name for entry in candidate.iterdir())
        except OSError:
            return []

    def glob(self, pattern: str) -> list[str]:
        base = self.path(".")
        if base is None:
            return []
        matches = []
        for match in glob_module.glob(str(base / pattern.lstrip("/"))):
            try:
                matches.append(str(Path(match).relative_to(base)))
            except ValueError:
                continue
        return sorted(matches)

    # -- configuration helpers -------------------------------------------
    def key_values(self, relative: str, separator: str = "=") -> dict[str, str]:
        """Parses `key<sep>value` lines. A space separator splits on any run of
        whitespace, which is how /etc/login.defs is actually formatted."""
        values: dict[str, str] = {}
        for line in self.read_lines(relative):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith(";"):
                continue
            if separator.isspace():
                parts = stripped.split(None, 1)
                if len(parts) < 2:
                    continue
                key, value = parts
            else:
                if separator not in stripped:
                    continue
                key, _, value = stripped.partition(separator)
            key = key.strip().lower().replace("-", "_")
            values[key] = value.strip().strip('"').strip("'")
        return values

    def sshd_option(self, name: str) -> Optional[str]:
        """Resolves sshd_config plus any Included files; first match wins."""
        if self._sshd is None:
            self._sshd = {}
            self._sshd_files = []
            self._load_sshd("etc/ssh/sshd_config", 0)
        return self._sshd.get(name.lower())

    def _load_sshd(self, relative: str, depth: int) -> None:
        if depth > 4:
            return
        candidate = self.path(relative)
        if candidate is None or not candidate.exists():
            return
        self._sshd_files.append(relative)
        for line in self.read_lines(relative):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split(None, 1)
            keyword = parts[0]
            value = parts[1].strip() if len(parts) > 1 else ""
            if keyword.lower() == "include":
                for pattern in value.split():
                    for included in self.glob(pattern.lstrip("/")):
                        self._load_sshd(included, depth + 1)
                continue
            self._sshd.setdefault(keyword.lower(), value)

    def sshd_files(self) -> list[str]:
        if self._sshd is None:
            self.sshd_option("permitrootlogin")
        return list(self._sshd_files)

    def sysctl(self, key: str) -> Optional[str]:
        if not self._sysctl_loaded:
            self._load_sysctl()
        return self._sysctl.get(key)

    def _load_sysctl(self) -> None:
        self._sysctl_loaded = True
        if self._live:
            for key in (
                "kernel.randomize_va_space",
                "kernel.dmesg_restrict",
                "kernel.kptr_restrict",
                "kernel.yama.ptrace_scope",
                "fs.suid_dumpable",
                "net.ipv4.ip_forward",
                "net.ipv4.tcp_syncookies",
                "net.ipv4.conf.all.rp_filter",
                "net.ipv4.conf.all.accept_redirects",
                "net.ipv4.conf.all.accept_source_route",
            ):
                candidate = Path("/proc/sys") / key.replace(".", "/")
                try:
                    self._sysctl[key] = candidate.read_text().strip()
                except OSError:
                    continue

        # Config files are parsed for both live and snapshot audits so a
        # persisted setting is reported even when the live value differs.
        for pattern in (
            "usr/lib/sysctl.d/*.conf",
            "lib/sysctl.d/*.conf",
            "etc/sysctl.d/*.conf",
            "etc/sysctl.conf",
        ):
            for relative in self.glob(pattern) if "*" in pattern else [pattern]:
                for line in self.read_lines(relative):
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    match = re.match(r"^([\w./-]+)\s*=\s*(\S+)", stripped)
                    if match:
                        key = match.group(1).replace("/", ".")
                        self._sysctl[key] = match.group(2)

    def listening_ports(self) -> dict[int, str]:
        ports: dict[int, str] = {}
        for table in ("proc/net/tcp", "proc/net/tcp6"):
            for line in self.read_lines(table)[1:]:
                fields = line.split()
                if len(fields) < 4:
                    continue
                if fields[3] != "0A":  # TCP_LISTEN
                    continue
                try:
                    port = int(fields[1].rsplit(":", 1)[1], 16)
                except (IndexError, ValueError):
                    continue
                ports[port] = table
        return ports

    # -- read-only external probes ---------------------------------------
    def command(self, argv: tuple[str, ...], timeout: int = 5) -> tuple[int, str]:
        if not self._live or argv not in ALLOWED_COMMANDS:
            return 127, ""
        if shutil.which(argv[0]) is None:
            return 127, ""
        try:
            completed = subprocess.run(
                list(argv),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
            )
        except (OSError, subprocess.SubprocessError):
            return 125, ""
        return completed.returncode, (completed.stdout or "") + (completed.stderr or "")

    @property
    def live(self) -> bool:
        return self._live


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

DEFAULT_CATEGORIES: dict[str, dict] = {
    "ACCT": {"title": "Accounts and identities", "weight": 1.3},
    "AUTH": {"title": "Authentication and sudo", "weight": 1.3},
    "SSH": {"title": "SSH server", "weight": 1.5},
    "FIRE": {"title": "Host firewall", "weight": 1.4},
    "KRNL": {"title": "Kernel hardening", "weight": 1.2},
    "FILE": {"title": "File permissions", "weight": 1.2},
    "LOGG": {"title": "Logging and audit trail", "weight": 1.1},
    "PKGS": {"title": "Packages and updates", "weight": 1.0},
    "SERV": {"title": "Network services", "weight": 1.0},
    "SCHD": {"title": "Scheduled tasks", "weight": 0.8},
    "CRYP": {"title": "Cryptography", "weight": 0.8},
    "MAND": {"title": "Mandatory access control", "weight": 1.0},
}

DEFAULT_POLICY: dict = {
    "policy": "linux-baseline",
    "version": "1.0.0",
    "description": "General-purpose Linux server baseline for Torvex.",
    "categories": DEFAULT_CATEGORIES,
    "disabled_checks": [],
    "severity_overrides": {},
    "min_score": 70,
}


def merge_policy(base: dict, overlay: Optional[dict]) -> dict:
    if not overlay:
        return base
    merged = json.loads(json.dumps(base))
    for key, value in overlay.items():
        if key == "categories" and isinstance(value, dict):
            for name, settings in value.items():
                merged["categories"].setdefault(name, {}).update(settings)
        elif key == "disabled_checks" and isinstance(value, list):
            merged["disabled_checks"] = sorted(
                set(merged.get("disabled_checks", [])) | set(value)
            )
        elif key in {"severity_overrides", "level_overrides"} and isinstance(value, dict):
            merged.setdefault(key, {}).update(value)
        else:
            merged[key] = value
    return merged


def load_policy(path: Optional[str], name: Optional[str]) -> dict:
    policy = json.loads(json.dumps(DEFAULT_POLICY))
    if name and name not in {"linux-baseline", "default"}:
        candidate = Path(name)
        if candidate.is_file():
            policy = merge_policy(policy, json.loads(candidate.read_text()))
        else:
            raise SystemExit(f"error: unknown policy {name!r} (expected a JSON file)")
    if path:
        candidate = Path(path)
        if not candidate.is_file():
            raise SystemExit(f"error: policy file {path} does not exist")
        policy = merge_policy(policy, json.loads(candidate.read_text()))
    return policy


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


def _number(value: Optional[str], default: float = 0.0) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def _is_disabled(value: Optional[str]) -> bool:
    return str(value or "").strip().lower() in {"no", "none", "off", "disabled", "false"}


def run_audit(context: Context) -> dict:
    policy = context.policy
    disabled = set(policy.get("disabled_checks", []))
    severity_overrides = policy.get("severity_overrides", {})

    # A directory without /etc is not a Unix root. Treating the absence of a
    # firewall or an sshd_config in it as a pass would award points for evidence
    # that was never there, so every control is skipped instead.
    etc_dir = context.path("etc")
    usable_root = etc_dir is not None and etc_dir.is_dir()

    results = []
    category_totals: dict[str, dict[str, float]] = {
        name: {"earned": 0.0, "possible": 0.0, "passed": 0, "failed": 0, "skipped": 0}
        for name in policy.get("categories", {})
    }

    for item in CONTROLS:
        settings = policy.get("categories", {}).get(item.category, {})
        if settings.get("enabled") is False:
            continue
        if item.id in disabled or item.category in disabled:
            continue

        severity = Severity(severity_overrides.get(item.id, item.severity.value))
        if not usable_root:
            outcome = Outcome.skip("root has no /etc directory: not a Unix filesystem root")
        else:
            try:
                outcome = item.run(context)
            except Exception as error:  # a broken control must not stop the audit
                outcome = Outcome.manual(
                    f"control error: {error.__class__.__name__}: {error}"
                )

        category_weight = float(settings.get("weight", 1.0))
        weight = item.weight * category_weight
        possible = weight if outcome.status in CREDIT else 0.0
        earned = possible * CREDIT.get(outcome.status, 0.0)

        bucket = category_totals.setdefault(
            item.category,
            {"earned": 0.0, "possible": 0.0, "passed": 0, "failed": 0, "skipped": 0},
        )
        bucket["earned"] += earned
        bucket["possible"] += possible
        if outcome.status is Status.PASSED:
            bucket["passed"] += 1
        elif outcome.status in {Status.FAILED, Status.SUGGESTION}:
            bucket["failed"] += 1
        elif outcome.status is Status.SKIPPED:
            bucket["skipped"] += 1

        results.append(
            {
                "id": item.id,
                "title": item.title,
                "category": item.category,
                "category_title": settings.get("title", item.category),
                "status": outcome.status.value,
                "severity": severity.value,
                "level": severity.level,
                "description": outcome.detail or item.title,
                "rationale": item.rationale,
                "remediation": item.remediation,
                "evidence": outcome.evidence,
                "target": outcome.target,
                "compliance": list(item.compliance),
                "mitre": list(item.mitre),
                "weight": round(weight, 3),
                "earned": round(earned, 3),
                "possible": round(possible, 3),
                "kind": item.kind,
            }
        )

    earned = sum(bucket["earned"] for bucket in category_totals.values())
    possible = sum(bucket["possible"] for bucket in category_totals.values())
    index = int(round(100 * earned / possible)) if possible > 0 else 0

    categories = []
    for name, bucket in sorted(category_totals.items()):
        if bucket["possible"] <= 0 and bucket["skipped"] == 0:
            continue
        category_score = (
            int(round(100 * bucket["earned"] / bucket["possible"]))
            if bucket["possible"] > 0
            else None
        )
        categories.append(
            {
                "id": name,
                "title": policy.get("categories", {}).get(name, {}).get("title", name),
                "score": category_score,
                "passed": bucket["passed"],
                "failed": bucket["failed"],
                "skipped": bucket["skipped"],
                "earned": round(bucket["earned"], 2),
                "possible": round(bucket["possible"], 2),
            }
        )

    counts = {status.value: 0 for status in Status}
    for result in results:
        counts[result["status"]] += 1

    grade = (
        "A" if index >= 90 else
        "B" if index >= 80 else
        "C" if index >= 70 else
        "D" if index >= 60 else
        "E"
    )

    return {
        "schema": SCHEMA,
        "engine": "torvex_audit",
        "engine_version": ENGINE_VERSION,
        "policy": policy.get("policy", "custom"),
        "policy_version": policy.get("version", ""),
        "root": str(context.root),
        "live": context.live,
        "host": {
            "hostname": platform.node() if context.live else "",
            "system": platform.system(),
            "release": platform.release() if context.live else "",
            "machine": platform.machine(),
        },
        "score": {
            "index": index,
            "earned": round(earned, 2),
            "possible": round(possible, 2),
            "grade": grade,
            "min_score": policy.get("min_score", 70),
            "below_policy": index < int(policy.get("min_score", 70)),
        },
        "categories": categories,
        "counts": counts,
        "warnings": counts["failed"],
        "suggestions": counts["suggestion"],
        "results": results,
    }


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------

# -- ACCT -------------------------------------------------------------------

@control(
    "ACCT-9001",
    "Only root has UID 0",
    "ACCT",
    Severity.CRITICAL,
    rationale="Every UID 0 account is root; a second one is a persistence path that survives password resets.",
    remediation="Remove or renumber the extra UID 0 account and audit how it was created.",
    compliance=["CIS 5.4.2", "NIST AC-6"],
    mitre=["T1078", "T1543"],
)
def acct_uid_zero(context: Context) -> Outcome:
    entries = context.read_lines("etc/passwd")
    if not entries:
        return Outcome.skip("/etc/passwd is not readable")
    roots = [line.split(":")[0] for line in entries if line.split(":")[2:3] == ["0"]]
    if len(roots) > 1:
        return Outcome.bad(
            f"UID 0 accounts: {', '.join(sorted(roots))}", "/etc/passwd"
        )
    return Outcome.ok(f"single UID 0 account: {roots[0] if roots else 'none'}", "/etc/passwd")


@control(
    "ACCT-9002",
    "No account has an empty password",
    "ACCT",
    Severity.CRITICAL,
    rationale="An empty password field lets anyone log in as that account without a credential.",
    remediation="Lock the account with `passwd -l` or set a password immediately.",
    compliance=["CIS 5.4.2", "PCI DSS 8.2"],
    mitre=["T1078", "T1110"],
)
def acct_empty_password(context: Context) -> Outcome:
    shadow = context.read_lines("etc/shadow")
    if not shadow:
        return Outcome.skip("/etc/shadow is not readable (run as root for full coverage)")
    empty = []
    for line in shadow:
        fields = line.split(":")
        if len(fields) > 1 and fields[1] == "":
            empty.append(fields[0])
    if empty:
        return Outcome.bad(f"accounts with empty passwords: {', '.join(empty)}", "/etc/shadow")
    return Outcome.ok("no empty password fields", "/etc/shadow")


@control(
    "ACCT-9003",
    "System accounts cannot log in interactively",
    "ACCT",
    Severity.MEDIUM,
    rationale="Service accounts with a real shell widen the attack surface if the service is compromised.",
    remediation="Set the shell of service accounts to /usr/sbin/nologin.",
    compliance=["CIS 5.4.2"],
    mitre=["T1078"],
)
def acct_system_shells(context: Context) -> Outcome:
    entries = context.read_lines("etc/passwd")
    if not entries:
        return Outcome.skip("/etc/passwd is not readable")
    shells = {"/bin/bash", "/bin/sh", "/bin/dash", "/usr/bin/bash", "/usr/bin/zsh", "/bin/zsh"}
    offenders = []
    for line in entries:
        fields = line.split(":")
        if len(fields) < 7:
            continue
        try:
            uid = int(fields[2])
        except ValueError:
            continue
        if 0 < uid < 1000 and fields[6] in shells:
            offenders.append(fields[0])
    if offenders:
        return Outcome.suggest(
            f"system accounts with interactive shells: {', '.join(offenders[:8])}", "/etc/passwd"
        )
    return Outcome.ok("no system account has an interactive shell", "/etc/passwd")


@control(
    "ACCT-9004",
    "Password ageing is bounded",
    "ACCT",
    Severity.LOW,
    rationale="Unbounded password lifetime keeps a leaked credential valid indefinitely.",
    remediation="Set PASS_MAX_DAYS to 365 or less in /etc/login.defs.",
    compliance=["CIS 5.5.1.1", "NIST IA-5"],
)
def acct_password_ageing(context: Context) -> Outcome:
    values = context.key_values("etc/login.defs", " ")
    max_days = values.get("pass_max_days")
    if max_days is None:
        return Outcome.suggest("PASS_MAX_DAYS is not set", "/etc/login.defs")
    if _number(max_days, 99999) > 365:
        return Outcome.suggest(f"PASS_MAX_DAYS {max_days}", "/etc/login.defs")
    return Outcome.ok(f"PASS_MAX_DAYS {max_days}", "/etc/login.defs")


@control(
    "ACCT-9005",
    "User names and UIDs are unique",
    "ACCT",
    Severity.HIGH,
    rationale="Duplicate UIDs or names make accountability and file ownership ambiguous.",
    remediation="Give each account a unique name and UID.",
    compliance=["CIS 5.4.2"],
    mitre=["T1078"],
)
def acct_duplicates(context: Context) -> Outcome:
    entries = context.read_lines("etc/passwd")
    if not entries:
        return Outcome.skip("/etc/passwd is not readable")
    names: dict[str, int] = {}
    uids: dict[str, int] = {}
    duplicates = []
    for line in entries:
        fields = line.split(":")
        if len(fields) < 4:
            continue
        names[fields[0]] = names.get(fields[0], 0) + 1
        uids[fields[2]] = uids.get(fields[2], 0) + 1
    for name, count in list(names.items()) + list(uids.items()):
        if count > 1:
            duplicates.append(name)
    if duplicates:
        return Outcome.bad(f"duplicate entries: {', '.join(sorted(set(duplicates)))}", "/etc/passwd")
    return Outcome.ok("all names and UIDs are unique", "/etc/passwd")


# -- AUTH -------------------------------------------------------------------

@control(
    "AUTH-9230",
    "Password hashing uses a modern algorithm",
    "AUTH",
    Severity.MEDIUM,
    rationale="Legacy DES or MD5 hashes are cheap to crack offline.",
    remediation="Set ENCRYPT_METHOD to SHA512 or YESCRYPT in /etc/login.defs.",
    compliance=["CIS 5.5.1.2", "PCI DSS 8.3.2"],
    mitre=["T1110"],
)
def auth_hash_algorithm(context: Context) -> Outcome:
    values = context.key_values("etc/login.defs", " ")
    method = values.get("encrypt_method", "").upper()
    if not method:
        return Outcome.suggest("ENCRYPT_METHOD is not set", "/etc/login.defs")
    if method in {"SHA512", "YESCRYPT", "SHA256"}:
        return Outcome.ok(f"ENCRYPT_METHOD {method}", "/etc/login.defs")
    return Outcome.bad(f"ENCRYPT_METHOD {method}", "/etc/login.defs")


@control(
    "AUTH-9231",
    "Password hashing rounds are sufficient",
    "AUTH",
    Severity.LOW,
    rationale="A low round count makes a stolen hash cheaper to brute force.",
    remediation="Set SHA_CRYPT_MIN_ROUNDS to at least 5000 (or 65536 with yescrypt).",
    compliance=["CIS 5.5.1.2"],
)
def auth_hash_rounds(context: Context) -> Outcome:
    values = context.key_values("etc/login.defs", " ")
    rounds = values.get("sha_crypt_min_rounds")
    if rounds is None:
        return Outcome.suggest("SHA_CRYPT_MIN_ROUNDS is not set", "/etc/login.defs")
    if _number(rounds) < 5000:
        return Outcome.suggest(f"SHA_CRYPT_MIN_ROUNDS {rounds}", "/etc/login.defs")
    return Outcome.ok(f"SHA_CRYPT_MIN_ROUNDS {rounds}", "/etc/login.defs")


@control(
    "AUTH-9232",
    "Default umask restricts new files",
    "AUTH",
    Severity.LOW,
    rationale="A permissive umask creates world-readable files by default.",
    remediation="Set UMASK 027 or stricter in /etc/login.defs and the shell profiles.",
    compliance=["CIS 5.5.4"],
)
def auth_umask(context: Context) -> Outcome:
    values = context.key_values("etc/login.defs", " ")
    umask = values.get("umask")
    if umask is None:
        return Outcome.suggest("UMASK is not set in /etc/login.defs", "/etc/login.defs")
    try:
        numeric = int(umask, 8)
    except ValueError:
        return Outcome.suggest(f"UMASK {umask} is not octal", "/etc/login.defs")
    if numeric & 0o007:
        return Outcome.bad(f"UMASK {umask:04o} allows world access", "/etc/login.defs")
    if numeric & 0o070:
        return Outcome.suggest(f"UMASK {umask:04o} allows group access", "/etc/login.defs")
    return Outcome.ok(f"UMASK {umask:04o}", "/etc/login.defs")


@control(
    "AUTH-9233",
    "Sudo does not grant passwordless escalation",
    "AUTH",
    Severity.HIGH,
    rationale="NOPASSWD lets anyone with the invoking account escalate without a credential.",
    remediation="Remove NOPASSWD and require authentication for sudo.",
    compliance=["CIS 1.3.1", "PCI DSS 7.2"],
    mitre=["T1548"],
)
def auth_sudo_nopasswd(context: Context) -> Outcome:
    files = ["etc/sudoers"] + context.glob("etc/sudoers.d/*")
    offenders = []
    for relative in files:
        for line in context.read_lines(relative):
            stripped = line.strip()
            if stripped.startswith("#") or "nopasswd" not in stripped.lower():
                continue
            offenders.append(f"{relative}: {stripped[:120]}")
    if offenders:
        return Outcome.bad(
            f"{len(offenders)} NOPASSWD rule(s): {offenders[0]}", "/etc/sudoers"
        )
    if not context.exists("etc/sudoers") and not context.exists("etc/sudoers.d"):
        return Outcome.skip("sudo is not configured on this system")
    return Outcome.ok("no NOPASSWD rule found", "/etc/sudoers")


@control(
    "AUTH-9234",
    "Sudoers is not group or world writable",
    "AUTH",
    Severity.CRITICAL,
    rationale="A writable sudoers file is an immediate root escalation.",
    remediation="chmod 0440 /etc/sudoers and 0440 on every file in /etc/sudoers.d.",
    compliance=["CIS 1.3.1"],
    mitre=["T1548"],
)
def auth_sudoers_permissions(context: Context) -> Outcome:
    files = ["etc/sudoers"] + context.glob("etc/sudoers.d/*")
    checked = 0
    for relative in files:
        info = context.stat(relative)
        if info is None or not hasattr(info, "st_mode"):
            continue
        checked += 1
        if info.st_mode & 0o022:
            return Outcome.bad(
                f"{relative} is group/world writable ({info.st_mode & 0o777:04o})", relative
            )
    if checked == 0:
        return Outcome.skip("no sudoers file present")
    return Outcome.ok(f"{checked} sudoers file(s) with safe permissions", "/etc/sudoers")


@control(
    "AUTH-9235",
    "A password quality module is configured",
    "AUTH",
    Severity.MEDIUM,
    rationale="Without a quality module, weak passwords are accepted.",
    remediation="Install and configure pam_pwquality (or pam_cracklib) in /etc/pam.d/common-password.",
    compliance=["CIS 5.3.1"],
    mitre=["T1110"],
)
def auth_pam_quality(context: Context) -> Outcome:
    candidates = context.glob("etc/pam.d/*")
    if not candidates:
        return Outcome.skip("/etc/pam.d is not present")
    for relative in candidates:
        text = context.read(relative) or ""
        if "pam_pwquality" in text or "pam_cracklib" in text:
            return Outcome.ok(f"password quality module referenced in {relative}", relative)
    return Outcome.suggest("no pam_pwquality or pam_cracklib reference found", "/etc/pam.d")


# -- SSH --------------------------------------------------------------------

SSH_CONFIG = "etc/ssh/sshd_config"


def _ssh_value(context: Context, name: str) -> Optional[str]:
    return context.sshd_option(name)


def _ssh_guard(context: Context) -> Optional[Outcome]:
    """Skips SSH controls when no sshd configuration exists.

    Report-level honesty: a control whose subject is absent is inapplicable,
    not passing. Without this guard a host with no SSH server would collect
    free points for `PermitEmptyPasswords` being unset.
    """
    if not context.exists(SSH_CONFIG):
        return Outcome.skip("OpenSSH server is not installed")
    return None


@control(
    "SSH-7400",
    "SSH configuration is present",
    "SSH",
    Severity.INFO,
    rationale="The SSH server is the most exposed management surface on a server.",
    remediation="Remove the OpenSSH server if it is not required.",
    compliance=["CIS 5.2.1"],
)
def ssh_present(context: Context) -> Outcome:
    if context.exists(SSH_CONFIG):
        return Outcome.ok(f"configuration found at /{SSH_CONFIG}", f"/{SSH_CONFIG}")
    return Outcome.skip("OpenSSH server configuration not found")


@control(
    "SSH-7401",
    "SSH root login is restricted",
    "SSH",
    Severity.HIGH,
    rationale="Direct root login removes the audit trail of per-user accountability and invites brute force.",
    remediation="Set `PermitRootLogin no` in /etc/ssh/sshd_config and restart sshd.",
    compliance=["CIS 5.2.8", "PCI DSS 2.2.4"],
    mitre=["T1078", "T1110"],
)
def ssh_root_login(context: Context) -> Outcome:
    if (skipped := _ssh_guard(context)) is not None:
        return skipped
    value = _ssh_value(context, "permitrootlogin")
    if value is None:
        return Outcome.bad("PermitRootLogin is not restricted (default is prohibit-password)", f"/{SSH_CONFIG}")
    lowered = value.lower()
    if lowered == "no" or lowered.startswith("prohibit-password") or lowered.startswith(
        "forced-commands-only"
    ):
        return Outcome.ok(f"PermitRootLogin {value}", f"/{SSH_CONFIG}")
    return Outcome.bad(f"PermitRootLogin {value}", f"/{SSH_CONFIG}")


@control(
    "SSH-7402",
    "SSH password authentication is disabled",
    "SSH",
    Severity.MEDIUM,
    rationale="Key-only authentication removes the most common credential-guessing path.",
    remediation="Set `PasswordAuthentication no` once key-based access works for every operator.",
    compliance=["CIS 5.2.10"],
    mitre=["T1110"],
)
def ssh_password_auth(context: Context) -> Outcome:
    if (skipped := _ssh_guard(context)) is not None:
        return skipped
    value = _ssh_value(context, "passwordauthentication")
    if value is not None and _is_disabled(value):
        return Outcome.ok(f"PasswordAuthentication {value}", f"/{SSH_CONFIG}")
    if value is None:
        return Outcome.suggest(
            "PasswordAuthentication is not set (default is yes)", f"/{SSH_CONFIG}"
        )
    return Outcome.bad(f"PasswordAuthentication {value}", f"/{SSH_CONFIG}")


@control(
    "SSH-7403",
    "SSH empty passwords are rejected",
    "SSH",
    Severity.CRITICAL,
    rationale="PermitEmptyPasswords allows a login with no credential at all.",
    remediation="Set `PermitEmptyPasswords no`.",
    compliance=["CIS 5.2.9"],
    mitre=["T1078"],
)
def ssh_empty_passwords(context: Context) -> Outcome:
    if (skipped := _ssh_guard(context)) is not None:
        return skipped
    value = _ssh_value(context, "permitemptypasswords")
    if value is not None and not _is_disabled(value):
        return Outcome.bad(f"PermitEmptyPasswords {value}", f"/{SSH_CONFIG}")
    return Outcome.ok("empty passwords are not permitted", f"/{SSH_CONFIG}")


@control(
    "SSH-7404",
    "SSH limits authentication attempts",
    "SSH",
    Severity.LOW,
    rationale="Unlimited attempts make online guessing cheaper for an attacker.",
    remediation="Set `MaxAuthTries 4` or lower.",
    compliance=["CIS 5.2.5"],
    mitre=["T1110"],
)
def ssh_max_auth_tries(context: Context) -> Outcome:
    if (skipped := _ssh_guard(context)) is not None:
        return skipped
    value = _ssh_value(context, "maxauthtries")
    if value is None:
        return Outcome.suggest("MaxAuthTries is not set (default is 6)", f"/{SSH_CONFIG}")
    if _number(value, 6) > 4:
        return Outcome.suggest(f"MaxAuthTries {value}", f"/{SSH_CONFIG}")
    return Outcome.ok(f"MaxAuthTries {value}", f"/{SSH_CONFIG}")


@control(
    "SSH-7405",
    "SSH X11 forwarding is disabled",
    "SSH",
    Severity.LOW,
    rationale="X11 forwarding exposes the local display to the remote host.",
    remediation="Set `X11Forwarding no`.",
    compliance=["CIS 5.2.6"],
)
def ssh_x11(context: Context) -> Outcome:
    if (skipped := _ssh_guard(context)) is not None:
        return skipped
    value = _ssh_value(context, "x11forwarding")
    if value is None or _is_disabled(value):
        return Outcome.ok("X11 forwarding is disabled", f"/{SSH_CONFIG}")
    return Outcome.suggest(f"X11Forwarding {value}", f"/{SSH_CONFIG}")


@control(
    "SSH-7406",
    "SSH uses strong ciphers and MACs",
    "SSH",
    Severity.MEDIUM,
    rationale="Weak ciphers and MACs allow traffic recovery or tampering.",
    remediation="Remove 3des, arcfour, blowfish and *-96 MACs from the Ciphers/MACs lists.",
    compliance=["CIS 5.2.11", "PCI DSS 4.1"],
    mitre=["T1040"],
)
def ssh_ciphers(context: Context) -> Outcome:
    if (skipped := _ssh_guard(context)) is not None:
        return skipped
    weak = ("3des", "arcfour", "blowfish", "cast128", "hmac-md5", "-96", "rijndael")
    offenders = []
    for option in ("ciphers", "macs"):
        value = _ssh_value(context, option)
        if value is None:
            continue
        lowered = value.lower()
        for marker in weak:
            if marker in lowered:
                offenders.append(f"{option}={value}")
    if offenders:
        return Outcome.bad(f"weak algorithms configured: {'; '.join(offenders)}", f"/{SSH_CONFIG}")
    return Outcome.ok("no weak cipher or MAC names configured", f"/{SSH_CONFIG}")


@control(
    "SSH-7407",
    "SSH protocol 1 is disabled",
    "SSH",
    Severity.CRITICAL,
    rationale="SSH protocol 1 is cryptographically broken.",
    remediation="Remove any `Protocol 1` line; modern OpenSSH only supports protocol 2.",
    compliance=["CIS 5.2.4"],
    mitre=["T1040"],
)
def ssh_protocol(context: Context) -> Outcome:
    if (skipped := _ssh_guard(context)) is not None:
        return skipped
    value = _ssh_value(context, "protocol")
    if value is None:
        return Outcome.ok("protocol 1 is not enabled", f"/{SSH_CONFIG}")
    if "1" in value.split(","):
        return Outcome.bad(f"Protocol {value}", f"/{SSH_CONFIG}")
    return Outcome.ok(f"Protocol {value}", f"/{SSH_CONFIG}")


@control(
    "SSH-7408",
    "SSH host keys are not world readable",
    "SSH",
    Severity.MEDIUM,
    rationale="A readable private host key allows impersonating the server.",
    remediation="chmod 600 /etc/ssh/ssh_host_*_key.",
    compliance=["CIS 5.2.3"],
    mitre=["T1552"],
)
def ssh_host_key_permissions(context: Context) -> Outcome:
    keys = [
        relative
        for relative in context.glob("etc/ssh/ssh_host_*_key")
        if not relative.endswith(".pub")
    ]
    if not keys:
        return Outcome.skip("no SSH host keys found")
    for relative in keys:
        info = context.stat(relative)
        if info is None or not hasattr(info, "st_mode"):
            continue
        mode = info.st_mode & 0o777
        if mode & 0o077:
            return Outcome.bad(f"{relative} mode {mode:04o}", relative)
    return Outcome.ok(f"{len(keys)} host key(s) are private", "/etc/ssh")


@control(
    "SSH-7409",
    "SSH session timeouts are bounded",
    "SSH",
    Severity.LOW,
    rationale="Idle sessions keep an authenticated channel open on unattended terminals.",
    remediation="Set ClientAliveInterval 300 and ClientAliveCountMax 3.",
    compliance=["CIS 5.2.16"],
)
def ssh_timeouts(context: Context) -> Outcome:
    if (skipped := _ssh_guard(context)) is not None:
        return skipped
    interval = _ssh_value(context, "clientaliveinterval")
    count = _ssh_value(context, "clientalivecountmax")
    if interval is None or _number(interval) <= 0 or _number(interval) > 900:
        return Outcome.suggest(
            f"ClientAliveInterval {interval or 'unset'}", f"/{SSH_CONFIG}"
        )
    if count is not None and _number(count, 3) > 3:
        return Outcome.suggest(f"ClientAliveCountMax {count}", f"/{SSH_CONFIG}")
    return Outcome.ok(f"ClientAliveInterval {interval}", f"/{SSH_CONFIG}")


# -- FIRE -------------------------------------------------------------------

FIREWALL_TOOLS = ("usr/sbin/ufw", "usr/sbin/firewalld", "usr/sbin/nft", "usr/sbin/iptables")


@control(
    "FIRE-4500",
    "A host firewall is installed",
    "FIRE",
    Severity.HIGH,
    rationale="Without a host firewall every listening service is reachable from any network that can route to it.",
    remediation="Install nftables or ufw and default to denying inbound traffic.",
    compliance=["CIS 3.5.1", "PCI DSS 1.2"],
    mitre=["T1562"],
)
def fire_present(context: Context) -> Outcome:
    present = [tool for tool in FIREWALL_TOOLS if context.exists(tool)]
    if present:
        return Outcome.ok(f"found: {', '.join(present)}", "/")
    return Outcome.bad("no ufw, firewalld, nftables or iptables binary found", "/")


@control(
    "FIRE-4501",
    "UFW is enabled",
    "FIRE",
    Severity.HIGH,
    rationale="An installed but disabled firewall provides no protection.",
    remediation="Run `ufw default deny incoming` and `ufw enable`.",
    compliance=["CIS 3.5.2"],
    mitre=["T1562"],
)
def fire_ufw(context: Context) -> Outcome:
    if not context.exists("etc/ufw/ufw.conf"):
        return Outcome.skip("ufw is not configured")
    values = context.key_values("etc/ufw/ufw.conf")
    if values.get("enabled", "").lower() == "yes":
        return Outcome.ok("ENABLED=yes", "/etc/ufw/ufw.conf")
    return Outcome.bad(
        f"ENABLED={values.get('enabled', 'unset')}", "/etc/ufw/ufw.conf"
    )


@control(
    "FIRE-4502",
    "Firewall default policy denies inbound traffic",
    "FIRE",
    Severity.HIGH,
    rationale="A permissive default policy silently exposes services added later.",
    remediation="Set the INPUT chain policy to DROP (iptables) or reject by default (nftables).",
    compliance=["CIS 3.5.2", "PCI DSS 1.2.1"],
    mitre=["T1562"],
)
def fire_default_policy(context: Context) -> Outcome:
    candidates = [
        "etc/iptables/rules.v4",
        "etc/sysconfig/iptables",
        "etc/nftables.conf",
        "etc/ufw/before.rules",
    ]
    found = False
    for relative in candidates:
        text = context.read(relative)
        if not text:
            continue
        found = True
        if re.search(r"^\s*:INPUT\s+DROP", text, re.MULTILINE):
            return Outcome.ok(f"INPUT policy DROP in {relative}", relative)
        if re.search(r"^\s*hook\s+input", text, re.MULTILINE) and re.search(
            r"\b(policy|drop)\b", text
        ):
            return Outcome.ok(f"nftables input hook with drop policy in {relative}", relative)
        if re.search(r"^\s*DEFAULT_INPUT_POLICY\s*=\s*\"?DROP", text, re.MULTILINE):
            return Outcome.ok(f"ufw default input policy DROP in {relative}", relative)
    if not found:
        return Outcome.skip("no firewall rule file found")
    return Outcome.bad("no default-deny inbound policy found", "/etc")


@control(
    "FIRE-4503",
    "Brute-force protection is present",
    "FIRE",
    Severity.LOW,
    rationale="Automated credential guessing is constant on internet-facing SSH.",
    remediation="Install fail2ban or configure sshd MaxStartups and per-source limits.",
    compliance=["CIS 3.5.4"],
    mitre=["T1110"],
)
def fire_fail2ban(context: Context) -> Outcome:
    if context.exists("etc/fail2ban/jail.conf") or context.exists("etc/fail2ban/jail.local"):
        return Outcome.ok("fail2ban configuration found", "/etc/fail2ban")
    return Outcome.suggest("fail2ban is not installed or not configured", "/etc/fail2ban")


# -- KRNL -------------------------------------------------------------------

SYSCTL_CHECKS = [
    (
        "KRNL-6000",
        "kernel.randomize_va_space",
        "2",
        Severity.HIGH,
        "ASLR is disabled, so memory corruption bugs become reliably exploitable.",
        "Set kernel.randomize_va_space=2.",
        ["CIS 1.5.1"],
        ["T1055"],
    ),
    (
        "KRNL-6001",
        "net.ipv4.ip_forward",
        "0",
        Severity.MEDIUM,
        "A forwarding host can be used to pivot traffic between networks.",
        "Set net.ipv4.ip_forward=0 unless the host is a router or container host.",
        ["CIS 3.1.1"],
        ["T1090"],
    ),
    (
        "KRNL-6002",
        "net.ipv4.tcp_syncookies",
        "1",
        Severity.MEDIUM,
        "Without SYN cookies a SYN flood can exhaust the backlog.",
        "Set net.ipv4.tcp_syncookies=1.",
        ["CIS 3.2.8"],
        ["T1499"],
    ),
    (
        "KRNL-6003",
        "net.ipv4.conf.all.rp_filter",
        "1",
        Severity.LOW,
        "Reverse path filtering drops spoofed source addresses.",
        "Set net.ipv4.conf.all.rp_filter=1.",
        ["CIS 3.2.7"],
        ["T1090"],
    ),
    (
        "KRNL-6004",
        "kernel.dmesg_restrict",
        "1",
        Severity.LOW,
        "An unprivileged user can read kernel pointers from the ring buffer.",
        "Set kernel.dmesg_restrict=1.",
        ["CIS 1.5.4"],
        ["T1082"],
    ),
    (
        "KRNL-6005",
        "kernel.kptr_restrict",
        "1",
        Severity.LOW,
        "Kernel pointers exposed in /proc help an attacker defeat KASLR.",
        "Set kernel.kptr_restrict=1 or 2.",
        ["CIS 1.5.3"],
        ["T1082"],
    ),
    (
        "KRNL-6006",
        "fs.suid_dumpable",
        "0",
        Severity.MEDIUM,
        "A core dump of a setuid process can leak privileged memory.",
        "Set fs.suid_dumpable=0.",
        ["CIS 1.5.5"],
        ["T1552"],
    ),
    (
        "KRNL-6007",
        "net.ipv4.conf.all.accept_redirects",
        "0",
        Severity.LOW,
        "Accepting ICMP redirects lets an attacker reroute traffic.",
        "Set net.ipv4.conf.all.accept_redirects=0.",
        ["CIS 3.2.2"],
        ["T1090"],
    ),
    (
        "KRNL-6008",
        "kernel.yama.ptrace_scope",
        "1",
        Severity.LOW,
        "Unrestricted ptrace lets one process read another's memory.",
        "Set kernel.yama.ptrace_scope=1.",
        ["CIS 1.5.6"],
        ["T1055"],
    ),
]


def _make_sysctl_control(key, expected, severity, rationale, remediation, compliance, mitre):
    def run(context: Context) -> Outcome:
        value = context.sysctl(key)
        if value is None:
            return Outcome.skip(f"{key} is not set")
        if key == "kernel.yama.ptrace_scope":
            passed = _number(value) >= 1
        elif key in {"kernel.kptr_restrict", "kernel.dmesg_restrict"}:
            passed = _number(value) >= _number(expected)
        else:
            passed = str(value).strip() == expected
        if passed:
            return Outcome.ok(f"{key} = {value}", "/proc/sys")
        return Outcome.suggest(
            f"{key} = {value} (recommended {expected})",
            "/proc/sys",
            detail=rationale,
        )

    run.__name__ = key.replace(".", "_")
    return run


for _id, _key, _expected, _sev, _why, _fix, _cis, _mitre in SYSCTL_CHECKS:
    control(
        _id,
        f"Kernel setting {_key}",
        "KRNL",
        _sev,
        rationale=_why,
        remediation=_fix,
        compliance=_cis,
        mitre=_mitre,
    )(_make_sysctl_control(_key, _expected, _sev, _why, _fix, _cis, _mitre))


# -- FILE -------------------------------------------------------------------

@control(
    "FILE-6310",
    "Shared temporary directories use the sticky bit",
    "FILE",
    Severity.HIGH,
    rationale="Without the sticky bit any user can delete or replace another user's temporary files.",
    remediation="chmod 1777 /tmp /var/tmp and mount them with nosuid,nodev.",
    compliance=["CIS 1.1.2", "PCI DSS 2.2"],
    mitre=["T1548"],
)
def file_sticky_bit(context: Context) -> Outcome:
    checked = 0
    for relative in ("tmp", "var/tmp"):
        info = context.stat(relative)
        if info is None or not hasattr(info, "st_mode"):
            continue
        checked += 1
        if not info.st_mode & 0o1000:
            return Outcome.bad(
                f"/{relative} mode {info.st_mode & 0o7777:04o} has no sticky bit", f"/{relative}"
            )
    if checked == 0:
        return Outcome.skip("temporary directories not found")
    return Outcome.ok("sticky bit present on shared temporary directories", "/tmp")


@control(
    "FILE-6311",
    "Shadow file is not world readable",
    "FILE",
    Severity.CRITICAL,
    rationale="A readable /etc/shadow exposes every password hash to offline cracking.",
    remediation="chmod 640 /etc/shadow and chown root:shadow /etc/shadow.",
    compliance=["CIS 6.1.3", "PCI DSS 8.3.2"],
    mitre=["T1552", "T1110"],
)
def file_shadow_permissions(context: Context) -> Outcome:
    info = context.stat("etc/shadow")
    if info is None or not hasattr(info, "st_mode"):
        return Outcome.skip("/etc/shadow is not readable (run as root for full coverage)")
    mode = info.st_mode & 0o777
    if mode & 0o007:
        return Outcome.bad(f"/etc/shadow mode {mode:04o}", "/etc/shadow")
    return Outcome.ok(f"/etc/shadow mode {mode:04o}", "/etc/shadow")


@control(
    "FILE-6312",
    "Passwd file is not group or world writable",
    "FILE",
    Severity.CRITICAL,
    rationale="A writable /etc/passwd allows creating a root-equivalent account.",
    remediation="chmod 644 /etc/passwd.",
    compliance=["CIS 6.1.2"],
    mitre=["T1548", "T1078"],
)
def file_passwd_permissions(context: Context) -> Outcome:
    info = context.stat("etc/passwd")
    if info is None or not hasattr(info, "st_mode"):
        return Outcome.skip("/etc/passwd is not readable")
    mode = info.st_mode & 0o777
    if mode & 0o022:
        return Outcome.bad(f"/etc/passwd mode {mode:04o}", "/etc/passwd")
    return Outcome.ok(f"/etc/passwd mode {mode:04o}", "/etc/passwd")


@control(
    "FILE-6313",
    "Temporary filesystems are mounted noexec",
    "FILE",
    Severity.MEDIUM,
    rationale="A noexec /tmp stops a dropper from running a payload it just wrote.",
    remediation="Add noexec,nosuid,nodev to the /tmp and /var/tmp fstab entries.",
    compliance=["CIS 1.1.3"],
    mitre=["T1059"],
)
def file_tmp_noexec(context: Context) -> Outcome:
    text = context.read("etc/fstab")
    if not text:
        return Outcome.skip("/etc/fstab is not readable")
    entries = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) >= 4 and fields[1] in {"/tmp", "/var/tmp"}:
            entries.append(fields[3])
    if not entries:
        return Outcome.skip("no separate /tmp or /var/tmp mount entry")
    for options in entries:
        if "noexec" not in options.split(","):
            return Outcome.suggest(f"mount options: {options}", "/etc/fstab")
    return Outcome.ok(f"noexec present: {'; '.join(entries)}", "/etc/fstab")


@control(
    "FILE-6314",
    "No world-writable files in /etc",
    "FILE",
    Severity.MEDIUM,
    rationale="A world-writable configuration file is a direct path to code execution or privilege escalation.",
    remediation="Remove the world-write bit and investigate how the file changed.",
    compliance=["CIS 6.1.1"],
    mitre=["T1548", "T1565"],
    kind="scan",
)
def file_world_writable_etc(context: Context) -> Outcome:
    base = context.path("etc")
    if base is None or not base.is_dir():
        return Outcome.skip("/etc is not readable")
    offenders = []
    scanned = 0
    for directory, _subdirs, files in os.walk(base):
        for name in files:
            scanned += 1
            if scanned > 5000:
                break
            candidate = Path(directory) / name
            try:
                info = candidate.lstat()
            except OSError:
                continue
            if info.st_mode & 0o002:
                try:
                    offenders.append(str(candidate.relative_to(base)))
                except ValueError:
                    continue
        if scanned > 5000:
            break
    if offenders:
        return Outcome.bad(
            f"world-writable: {', '.join(offenders[:6])}", "/etc"
        )
    return Outcome.ok(f"scanned {scanned} files under /etc", "/etc")


@control(
    "FILE-6315",
    "SSH server configuration is not world writable",
    "FILE",
    Severity.HIGH,
    rationale="A writable sshd_config lets an attacker enable root login or a backdoor key.",
    remediation="chmod 600 /etc/ssh/sshd_config and restrict ownership to root.",
    compliance=["CIS 5.2.1"],
    mitre=["T1565", "T1098"],
)
def file_sshd_config_permissions(context: Context) -> Outcome:
    info = context.stat(SSH_CONFIG)
    if info is None or not hasattr(info, "st_mode"):
        return Outcome.skip("sshd_config not present")
    mode = info.st_mode & 0o777
    if mode & 0o022:
        return Outcome.bad(f"/{SSH_CONFIG} mode {mode:04o}", f"/{SSH_CONFIG}")
    return Outcome.ok(f"/{SSH_CONFIG} mode {mode:04o}", f"/{SSH_CONFIG}")


# -- LOGG -------------------------------------------------------------------

@control(
    "LOGG-2138",
    "A system logger is installed",
    "LOGG",
    Severity.MEDIUM,
    rationale="Without a logger there is no record to investigate an incident.",
    remediation="Install systemd-journald or rsyslog and keep logs outside the host as well.",
    compliance=["CIS 4.2.1", "PCI DSS 10.2"],
    mitre=["T1070", "T1562"],
)
def logg_logger_present(context: Context) -> Outcome:
    if (
        context.exists("etc/systemd/journald.conf")
        or context.exists("etc/rsyslog.conf")
        or context.exists("etc/syslog-ng/syslog-ng.conf")
    ):
        return Outcome.ok("logger configuration found", "/etc")
    return Outcome.bad("no journald, rsyslog or syslog-ng configuration found", "/etc")


@control(
    "LOGG-2139",
    "auditd is enabled",
    "LOGG",
    Severity.HIGH,
    rationale="Without auditd there is no syscall-level record of privilege changes or exec.",
    remediation="Install auditd, enable it at boot and load a ruleset.",
    compliance=["CIS 4.1.1", "PCI DSS 10.2.6"],
    mitre=["T1070", "T1562"],
)
def logg_auditd(context: Context) -> Outcome:
    config = context.read("etc/audit/auditd.conf")
    rules = context.glob("etc/audit/rules.d/*.rules")
    if config is None:
        return Outcome.bad("auditd configuration is missing", "/etc/audit")
    if not rules and not context.exists("etc/audit/audit.rules"):
        return Outcome.suggest("auditd is configured but no ruleset is installed", "/etc/audit")
    return Outcome.ok(f"auditd configured with {len(rules)} rule file(s)", "/etc/audit")


@control(
    "LOGG-2140",
    "Log directories are not world writable",
    "LOGG",
    Severity.MEDIUM,
    rationale="A writable log directory lets an attacker erase or forge evidence.",
    remediation="chmod 750 /var/log and restrict ownership to root:syslog.",
    compliance=["CIS 4.2.3"],
    mitre=["T1070"],
)
def logg_log_permissions(context: Context) -> Outcome:
    info = context.stat("var/log")
    if info is None or not hasattr(info, "st_mode"):
        return Outcome.skip("/var/log is not readable")
    mode = info.st_mode & 0o777
    if mode & 0o002:
        return Outcome.bad(f"/var/log mode {mode:04o} is world writable", "/var/log")
    return Outcome.ok(f"/var/log mode {mode:04o}", "/var/log")


@control(
    "LOGG-2141",
    "Journald storage is persistent",
    "LOGG",
    Severity.LOW,
    rationale="Volatile journals vanish on reboot, taking the evidence with them.",
    remediation="Set Storage=persistent in /etc/systemd/journald.conf.",
    compliance=["CIS 4.2.1.2"],
    mitre=["T1070"],
)
def logg_journald_persistent(context: Context) -> Outcome:
    if not context.exists("etc/systemd/journald.conf"):
        return Outcome.skip("journald is not configured")
    values = context.key_values("etc/systemd/journald.conf")
    storage = values.get("storage", "").lower()
    if storage in {"persistent", "auto"}:
        return Outcome.ok(f"Storage={storage}", "/etc/systemd/journald.conf")
    return Outcome.suggest(
        f"Storage={storage or 'unset (default volatile)'}", "/etc/systemd/journald.conf"
    )


# -- PKGS -------------------------------------------------------------------

@control(
    "PKGS-7392",
    "Unattended security updates are configured",
    "PKGS",
    Severity.HIGH,
    rationale="Most breached hosts were missing a patch that had been available for weeks.",
    remediation="Enable unattended-upgrades (Debian) or dnf-automatic (RHEL) for security updates.",
    compliance=["CIS 1.9", "PCI DSS 6.3.3"],
    mitre=["T1190"],
)
def pkgs_auto_updates(context: Context) -> Outcome:
    candidates = [
        "etc/apt/apt.conf.d/20auto-upgrades",
        "etc/apt/apt.conf.d/50unattended-upgrades",
        "etc/dnf/automatic.conf",
        "etc/yum.conf",
    ]
    for relative in candidates:
        text = context.read(relative)
        if not text:
            continue
        if "unattended-upgrades" in text or "apply_updates" in text:
            if re.search(r'Unattended-Upgrade\s+"1"', text) or re.search(
                r"apply_updates\s*=\s*(yes|true|1)", text, re.IGNORECASE
            ):
                return Outcome.ok(f"automatic updates configured in {relative}", relative)
    return Outcome.suggest("no automatic security update configuration found", "/etc")


@control(
    "PKGS-7393",
    "Package metadata is present",
    "PKGS",
    Severity.INFO,
    rationale="Knowing the distribution and package set makes triage and patch verification possible.",
    remediation="No action; informational only.",
    compliance=["CIS 1.1"],
)
def pkgs_os_release(context: Context) -> Outcome:
    text = context.read("etc/os-release") or ""
    ident = re.search(r'^ID="?([\w.-]+)"?', text, re.MULTILINE)
    version = re.search(r'^VERSION_ID="?([\w.-]+)"?', text, re.MULTILINE)
    if not ident:
        return Outcome.skip("/etc/os-release is not readable")
    return Outcome.ok(
        f"{ident.group(1)} {version.group(1) if version else 'unknown version'}",
        "/etc/os-release",
    )


@control(
    "PKGS-7394",
    "Third-party package repositories are declared explicitly",
    "PKGS",
    Severity.LOW,
    rationale="Undeclared or unsigned repositories can deliver a malicious package update.",
    remediation="Remove unused repositories and require signed metadata for every source.",
    compliance=["CIS 1.2.1"],
    mitre=["T1195"],
)
def pkgs_repositories(context: Context) -> Outcome:
    sources = context.glob("etc/apt/sources.list.d/*")
    main = context.read("etc/apt/sources.list") or ""
    if not sources and not main.strip():
        return Outcome.skip("no APT sources configured")
    unsigned = [relative for relative in sources if "trusted=yes" in (context.read(relative) or "")]
    if unsigned or "trusted=yes" in main:
        return Outcome.bad("a repository is marked trusted without signature checks", "/etc/apt")
    return Outcome.ok(f"{len(sources)} additional source file(s), all signature-checked", "/etc/apt")


# -- SERV -------------------------------------------------------------------

RISKY_PORTS = {
    21: ("ftp", Severity.HIGH),
    23: ("telnet", Severity.CRITICAL),
    69: ("tftp", Severity.HIGH),
    111: ("rpcbind", Severity.MEDIUM),
    512: ("rexec", Severity.CRITICAL),
    513: ("rlogin", Severity.CRITICAL),
    514: ("rsh", Severity.CRITICAL),
}


@control(
    "SERV-3001",
    "No legacy plaintext services are listening",
    "SERV",
    Severity.HIGH,
    rationale="Telnet, ftp and r-services send credentials in clear text.",
    remediation="Disable the service and replace it with SSH or SFTP.",
    compliance=["CIS 2.1.7", "PCI DSS 2.3"],
    mitre=["T1040", "T1021"],
)
def serv_legacy_ports(context: Context) -> Outcome:
    ports = context.listening_ports()
    if not ports:
        return Outcome.skip("/proc/net/tcp is not readable")
    offenders = [
        f"{RISKY_PORTS[port][0]} ({port})" for port in sorted(ports) if port in RISKY_PORTS
    ]
    if offenders:
        return Outcome.bad(f"listening: {', '.join(offenders)}", "/proc/net/tcp")
    return Outcome.ok(f"{len(ports)} listening TCP port(s), none legacy", "/proc/net/tcp")


@control(
    "SERV-3002",
    "No inetd-style super server is enabled",
    "SERV",
    Severity.MEDIUM,
    rationale="inetd/xinetd can expose small services with weak authentication.",
    remediation="Remove inetd/xinetd and disable any service it launches.",
    compliance=["CIS 2.1.1"],
    mitre=["T1021"],
)
def serv_inetd(context: Context) -> Outcome:
    configs = context.glob("etc/xinetd.d/*") + ["etc/inetd.conf"]
    active = []
    for relative in configs:
        text = context.read(relative) or ""
        if "disable" in text and re.search(r"disable\s*=\s*no", text):
            active.append(relative)
    if context.exists("etc/xinetd.conf") or context.exists("etc/inetd.conf"):
        if active or context.exists("etc/inetd.conf"):
            return Outcome.suggest(
                f"super server present with {len(active)} enabled service(s)", "/etc"
            )
    return Outcome.ok("no enabled inetd service", "/etc")


@control(
    "SERV-3003",
    "Listening ports are reviewed",
    "SERV",
    Severity.INFO,
    rationale="Every listening port is attack surface; an unreviewed port is an unreviewed risk.",
    remediation="Review each listener and disable the ones the host does not need.",
    compliance=["CIS 2.1"],
)
def serv_review(context: Context) -> Outcome:
    ports = context.listening_ports()
    if not ports:
        return Outcome.skip("/proc/net/tcp is not readable")
    sample = ", ".join(str(port) for port in sorted(ports)[:12])
    return Outcome.manual(f"{len(ports)} listening port(s): {sample}")


# -- SCHD -------------------------------------------------------------------

@control(
    "SCHD-7700",
    "Cron configuration is not world writable",
    "SCHD",
    Severity.HIGH,
    rationale="A writable crontab entry runs attacker code as the cron user, often root.",
    remediation="chmod 600 /etc/crontab and 700 on /etc/cron.d, /etc/cron.hourly and friends.",
    compliance=["CIS 5.1.2"],
    mitre=["T1053"],
)
def schd_cron_permissions(context: Context) -> Outcome:
    paths = ["etc/crontab", "etc/cron.d", "etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly"]
    checked = 0
    for relative in paths:
        info = context.stat(relative)
        if info is None or not hasattr(info, "st_mode"):
            continue
        checked += 1
        if info.st_mode & 0o022:
            return Outcome.bad(
                f"/{relative} mode {info.st_mode & 0o7777:04o}", f"/{relative}"
            )
    if checked == 0:
        return Outcome.skip("no cron configuration found")
    return Outcome.ok(f"{checked} cron path(s) with safe permissions", "/etc")


@control(
    "SCHD-7701",
    "Cron is restricted to authorised users",
    "SCHD",
    Severity.LOW,
    rationale="cron.allow gives an explicit allowlist instead of relying on the default.",
    remediation="Create /etc/cron.allow listing the accounts that may schedule jobs.",
    compliance=["CIS 5.1.8"],
    mitre=["T1053"],
)
def schd_cron_allow(context: Context) -> Outcome:
    if context.exists("etc/cron.allow"):
        return Outcome.ok("/etc/cron.allow is present", "/etc/cron.allow")
    if context.exists("etc/cron.deny"):
        return Outcome.suggest(
            "/etc/cron.deny is used instead of an allowlist", "/etc/cron.deny"
        )
    return Outcome.suggest("no cron.allow or cron.deny file present", "/etc")


@control(
    "SCHD-7702",
    "Scheduled tasks are accounted for",
    "SCHD",
    Severity.INFO,
    rationale="Hidden scheduled jobs are a standard persistence mechanism.",
    remediation="Review cron and systemd timers regularly.",
    compliance=["CIS 5.1"],
    mitre=["T1053"],
)
def schd_inventory(context: Context) -> Outcome:
    timers = context.glob("etc/systemd/system/*.timer")
    jobs = context.glob("var/spool/cron/crontabs/*") + context.glob("var/spool/cron/*")
    if not timers and not jobs:
        return Outcome.skip("no timers or user crontabs found")
    return Outcome.manual(f"{len(timers)} systemd timer(s), {len(jobs)} user crontab(s)")


# -- CRYP -------------------------------------------------------------------

@control(
    "CRYP-8000",
    "OpenSSL enforces a modern TLS floor",
    "CRYP",
    Severity.MEDIUM,
    rationale="TLS 1.0/1.1 are deprecated and fail modern compliance baselines.",
    remediation="Set MinProtocol = TLSv1.2 in /etc/ssl/openssl.cnf.",
    compliance=["CIS 1.4", "PCI DSS 4.1"],
    mitre=["T1040"],
)
def cryp_tls_floor(context: Context) -> Outcome:
    text = context.read("etc/ssl/openssl.cnf")
    if text is None:
        return Outcome.skip("/etc/ssl/openssl.cnf is not present")
    match = re.search(r"^\s*MinProtocol\s*=\s*(\S+)", text, re.MULTILINE)
    if match and match.group(1).upper() in {"TLSV1.2", "TLSV1.3"}:
        return Outcome.ok(f"MinProtocol = {match.group(1)}", "/etc/ssl/openssl.cnf")
    return Outcome.suggest(
        f"MinProtocol = {match.group(1) if match else 'unset'}", "/etc/ssl/openssl.cnf"
    )


@control(
    "CRYP-8001",
    "No deprecated SSL protocol is enabled",
    "CRYP",
    Severity.HIGH,
    rationale="SSLv2/SSLv3 are broken and must never be enabled.",
    remediation="Remove SSLv2/SSLv3 from every configuration and restart the service.",
    compliance=["CIS 1.4"],
    mitre=["T1040"],
)
def cryp_ssl(context: Context) -> Outcome:
    offenders = []
    for relative in context.glob("etc/ssl/openssl.cnf") + context.glob("etc/nginx/**/*.conf"):
        text = context.read(relative) or ""
        if re.search(r"\bSSLv[23]\b", text):
            offenders.append(relative)
    if offenders:
        return Outcome.bad(f"SSLv2/SSLv3 referenced in {', '.join(offenders)}", "/etc")
    if not context.exists("etc/ssl/openssl.cnf"):
        return Outcome.skip("no TLS configuration found")
    return Outcome.ok("no SSLv2/SSLv3 reference found", "/etc/ssl")


# -- MAND -------------------------------------------------------------------

@control(
    "MAND-0100",
    "A mandatory access control framework is active",
    "MAND",
    Severity.HIGH,
    rationale="MAC confines a compromised service even when it runs as a privileged user.",
    remediation="Enable SELinux (enforcing) or AppArmor and load profiles for exposed services.",
    compliance=["CIS 1.6", "PCI DSS 2.2"],
    mitre=["T1562", "T1548"],
)
def mand_mac(context: Context) -> Outcome:
    selinux = context.key_values("etc/selinux/config")
    state = selinux.get("selinux", "").lower()
    if state == "enforcing":
        return Outcome.ok("SELinux is set to enforcing", "/etc/selinux/config")
    if context.exists("etc/apparmor.d") or context.exists("sys/kernel/security/apparmor"):
        return Outcome.ok("AppArmor is present", "/etc/apparmor.d")
    if context.live:
        code, output = context.command(("getenforce",))
        if code == 0 and output.strip().lower() == "enforcing":
            return Outcome.ok("SELinux is enforcing", "getenforce")
    if state and state != "enforcing":
        return Outcome.bad(f"SELinux is {state}", "/etc/selinux/config")
    return Outcome.bad("no active SELinux or AppArmor policy found", "/etc")


@control(
    "MAND-0101",
    "Kernel lockdown or module signing is considered",
    "MAND",
    Severity.INFO,
    rationale="Unsigned kernel modules let a root-level attacker persist below the OS.",
    remediation="Enable module signature enforcement or kernel lockdown where the platform supports it.",
    compliance=["CIS 1.6"],
    mitre=["T1547"],
)
def mand_modules(context: Context) -> Outcome:
    text = context.read("sys/kernel/security/lockdown")
    if text:
        return Outcome.ok(f"lockdown state: {text.strip()}", "sys/kernel/security/lockdown")
    modules = context.read("proc/sys/kernel/modules_disabled")
    if modules is not None:
        return Outcome.ok(f"modules_disabled = {modules.strip()}", "proc/sys/kernel")
    return Outcome.skip("kernel module controls are not exposed")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _print_pretty(report: dict) -> None:
    score = report["score"]
    counts = report["counts"]
    print(f"Torvex audit {report['engine_version']} - policy {report['policy']}")
    print(f"Target: {report['root']} ({'live' if report['live'] else 'snapshot'})")
    print()
    print(f"Hardening index: {score['index']}/100 (grade {score['grade']})")
    print(
        f"  {score['earned']:.1f} of {score['possible']:.1f} points | "
        f"{counts['passed']} passed, {counts['failed']} warnings, "
        f"{counts['suggestion']} suggestions, {counts['skipped']} skipped"
    )
    if score["below_policy"]:
        print(f"  Below the policy minimum of {score['min_score']}")
    print()

    for category in report["categories"]:
        value = "n/a" if category["score"] is None else f"{category['score']:3d}"
        print(
            f"  [{value}] {category['id']:<5} {category['title']} "
            f"({category['passed']} ok, {category['failed']} open)"
        )

    warnings = [item for item in report["results"] if item["status"] == "failed"]
    suggestions = [item for item in report["results"] if item["status"] == "suggestion"]
    if warnings:
        print()
        print(f"Warnings ({len(warnings)}):")
        for item in sorted(warnings, key=lambda entry: -entry["level"]):
            print(f"  ! {item['title']} [{item['id']}]")
            print(f"      {item['evidence']}")
            print(f"      fix: {item['remediation']}")
    if suggestions:
        print()
        print(f"Suggestions ({len(suggestions)}):")
        for item in suggestions:
            print(f"  * {item['title']} [{item['id']}]")
            print(f"      {item['evidence']}")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="torvex_audit",
        description="Read-only Linux configuration assessment used by Torvex.",
    )
    parser.add_argument("--root", default="/", help="filesystem root to audit")
    parser.add_argument("--policy", default=None, help="policy name or JSON file")
    parser.add_argument("--format", choices=["json", "pretty"], default="json")
    parser.add_argument("--output", default=None, help="write the report to this file")
    parser.add_argument("--skip", action="append", default=[], help="skip a control id")
    parser.add_argument("--plugin", action="append", default=[], help="load extra checks")
    parser.add_argument("--list", action="store_true", help="list controls and exit")
    parser.add_argument("--min-level", type=int, default=0, help="drop lower findings")
    args = parser.parse_args(argv)

    root_path = Path(args.root)
    if not root_path.exists():
        print(f"error: audit root {args.root} does not exist", file=sys.stderr)
        return 2
    if not root_path.is_dir():
        print(f"error: audit root {args.root} is not a directory", file=sys.stderr)
        return 2

    for plugin in args.plugin:
        path = Path(plugin).resolve()
        if not path.is_file():
            raise SystemExit(f"error: plugin {plugin} does not exist")
        namespace = {"__name__": f"torvex_plugin_{path.stem}", "control": control}
        exec(compile(path.read_text(), str(path), "exec"), namespace)  # noqa: S102
        # The plugin's decorator instances were registered in this process.

    if args.list:
        for item in sorted(CONTROLS, key=lambda entry: entry.id):
            print(f"{item.id}  {item.category:<5} {item.severity.value:<8} {item.title}")
        return 0

    policy = load_policy(args.policy, None)
    if args.skip:
        policy = merge_policy(policy, {"disabled_checks": args.skip})
    context = Context(args.root, policy)
    report = run_audit(context)

    if args.min_level:
        report["results"] = [
            item for item in report["results"] if item["level"] >= args.min_level
        ]

    if args.format == "json":
        payload = json.dumps(report, indent=2)
        if args.output:
            Path(args.output).write_text(payload + "\n")
        else:
            print(payload)
    else:
        _print_pretty(report)
        if args.output:
            Path(args.output).write_text(json.dumps(report, indent=2) + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
