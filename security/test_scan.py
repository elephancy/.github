import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("scan", Path(__file__).with_name("scan.py"))
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


class PolicyTests(unittest.TestCase):
    def test_download_url_scope_and_redirects(self):
        self.assertEqual(scan.checked_url("https://github.com/org/repo/asset"), "https://github.com/org/repo/asset")
        self.assertEqual(scan.checked_url("https://codeload.github.com/org/repo/tar.gz/commit"),
                         "https://codeload.github.com/org/repo/tar.gz/commit")
        for url in ("file:///etc/passwd", "http://github.com/asset", "https://github.com.evil.invalid/asset",
                    "https://user:password@github.com/asset", "https://github.com:8443/asset",
                    "https://github.com/asset#fragment", "https://github.com/asset?query=unexpected",
                    "https://raw.githubusercontent.com/asset", "https://127.0.0.1/asset"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                scan.checked_url(url)
        scan.checked_url("https://release-assets.githubusercontent.com/asset?signed=value", redirect=True)
        with self.assertRaises(ValueError):
            scan.checked_url("https://unapproved.invalid/asset", redirect=True)

    def test_all_tools_run_after_first_failure_and_final_gate_fails(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            (repo / ".git").mkdir()
            calls = []
            def fake(tool, *args):
                calls.append(tool)
                if tool == "semgrep":
                    raise ValueError("RAW_SECRET_ERROR")
                return {"tool": tool, "status": "findings" if tool == "trivy" else "clean"}
            output = io.StringIO()
            with patch.object(sys, "argv", ["scan.py", str(repo)]), patch.object(scan, "scan", fake), patch("sys.stdout", output):
                self.assertEqual(scan.main(), 1)
            self.assertEqual(calls, ["semgrep", "trivy", "gitleaks"])
            self.assertNotIn("RAW_SECRET_ERROR", output.getvalue())
            self.assertEqual(len(output.getvalue().splitlines()), 3)

    def test_summary_excludes_secret_snippets_and_identity(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "report"
            p.write_text(json.dumps([{"File": "config.py", "RuleID": "test", "StartLine": 7,
                                      "Secret": "RAW_SECRET", "Match": "RAW_MATCH", "Author": "PRIVATE_AUTHOR"}]))
            result = scan.findings("gitleaks", p)
            self.assertEqual(result, [{"path": "config.py", "rule": "test", "line": 7}])
            self.assertNotIn("RAW_", json.dumps(result))

    def test_parser_errors_are_not_clean(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "report"
            p.write_text('{"results":[],"errors":[{"message":"SECRET"}]}')
            with self.assertRaises(scan.ScannerFailure) as caught:
                scan.findings("semgrep", p)
            self.assertEqual(caught.exception.category, "incomplete-scan")

    def test_partial_semgrep_findings_and_safe_issue_locations_survive(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "report"
            p.write_text(json.dumps({"results": [{
                "path": "source.py", "check_id": "unsafe-call", "start": {"line": 2},
                "extra": {"lines": "RAW_SECRET_SOURCE"}}], "errors": [{
                "code": 3, "type": ["PartialParsing", [{"source": "RAW_SOURCE"}]],
                "path": "parse.tsx", "message": "RAW_SECRET_MESSAGE"}]}))
            with self.assertRaises(scan.ScannerFailure) as caught:
                scan.findings("semgrep", p)
            self.assertEqual(caught.exception.category, "incomplete-scan")
            diagnostic = caught.exception.diagnostics
            self.assertEqual(diagnostic["count"], 1)
            self.assertEqual(diagnostic["findings"], [{"path": "source.py", "rule": "unsafe-call", "line": 2}])
            self.assertEqual(diagnostic["scan_issues"], [{"type": "PartialParsing", "code": 3, "path": "parse.tsx"}])
            self.assertNotIn("RAW_", json.dumps(diagnostic))

    def test_scanner_exit_error_is_not_hidden_by_missing_report(self):
        with tempfile.TemporaryDirectory() as d:
            repo, work = Path(d) / "repo", Path(d) / "work"
            repo.mkdir()
            work.mkdir()
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w:gz") as tar:
                member = tarfile.TarInfo("gitleaks")
                member.size = 4
                tar.addfile(member, io.BytesIO(b"fake"))
            with patch.object(scan, "download", return_value=archive.getvalue()), \
                    patch.object(scan, "command", return_value=2), self.assertRaises(scan.ScannerFailure) as caught:
                scan.scan("gitleaks", repo, work)
            self.assertEqual((caught.exception.phase, caught.exception.category, caught.exception.exit_code),
                             ("scan", "scanner-failed", 2))

    def test_missing_report_fails_with_specific_category(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(scan.ScannerFailure) as caught:
            scan.findings("trivy", Path(d) / "absent")
        self.assertEqual(caught.exception.category, "report-missing")

    def test_rate_limit_backoff_respects_headers_and_ignores_other_errors(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "log"
            for text, expected in (
                ("HTTP429 Too Many Requests", (False, None)),
                ("429 Too Many Requests", (True, 5)),
                ("429 Too Many Requests Retry-After: 12", (True, 12)),
                ("429 Too Many Requests Retry-After: 120", (True, 120)),
                ("429 Too Many Requests Retry-After: Wed, 21 Oct 2026", (True, None)),
                ("403 Forbidden RAW_SECRET_BODY", (False, None)),
            ):
                log.write_text(text)
                with self.subTest(expected=expected):
                    self.assertEqual(scan.rate_limit_delay(log), expected)

    def test_trivy_retry_is_bounded_and_original_rate_limit_is_retained(self):
        with tempfile.TemporaryDirectory() as d:
            repo, work = Path(d) / "repo", Path(d) / "work"
            repo.mkdir()
            work.mkdir()
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w:gz") as tar:
                member = tarfile.TarInfo("trivy")
                member.size = 4
                tar.addfile(member, io.BytesIO(b"fake"))
            calls = []
            def failure(argv, cwd, log, seconds):
                calls.append(seconds)
                log.write_text("429 Too Many Requests Retry-After: 0 RAW_SECRET_RESPONSE")
                return 1
            with patch.object(scan, "download", return_value=archive.getvalue()), \
                    patch.object(scan, "command", failure), self.assertRaises(scan.ScannerFailure) as caught:
                scan.scan("trivy", repo, work)
            self.assertEqual(len(calls), 2)
            self.assertLessEqual(calls[1], calls[0])
            self.assertEqual(caught.exception.category, "upstream-rate-limit")
            self.assertEqual(caught.exception.diagnostics, {"http_status": 429, "retry_attempts": 1})
            self.assertNotIn("RAW_", json.dumps(caught.exception.diagnostics))

    def test_trivy_official_db_fallback_order_and_existing_bounds(self):
        with tempfile.TemporaryDirectory() as d:
            repo, work = Path(d) / "repo", Path(d) / "work"
            repo.mkdir()
            work.mkdir()
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w:gz") as tar:
                member = tarfile.TarInfo("trivy")
                member.size = 4
                tar.addfile(member, io.BytesIO(b"fake"))
            captured = []
            def success(argv, cwd, log, seconds):
                captured.append((argv, seconds))
                Path(argv[argv.index("--output") + 1]).write_text(json.dumps({
                    "SchemaVersion": 2, "ArtifactType": "repository", "Results": []}))
                return 0
            with patch.object(scan, "download", return_value=archive.getvalue()), \
                    patch.object(scan, "command", success):
                self.assertEqual(scan.scan("trivy", repo, work)["status"], "clean")
            self.assertEqual(len(captured), 1)
            argv, seconds = captured[0]
            for flag, expected in (
                ("--db-repository", ["mirror.gcr.io/aquasec/trivy-db:2",
                    "ghcr.io/aquasecurity/trivy-db:2", "public.ecr.aws/aquasecurity/trivy-db:2"]),
                ("--java-db-repository", ["mirror.gcr.io/aquasec/trivy-java-db:1",
                    "ghcr.io/aquasecurity/trivy-java-db:1", "public.ecr.aws/aquasecurity/trivy-java-db:1"]),
            ):
                self.assertEqual([argv[i + 1] for i, value in enumerate(argv) if value == flag], expected)
            for flag, expected in (("--timeout", "210s"), ("--parallel", "2"),
                    ("--scanners", "vuln,misconfig"), ("--severity", "HIGH,CRITICAL"), ("--exit-code", "1")):
                self.assertEqual(argv[argv.index(flag) + 1], expected)
            self.assertEqual(seconds, 240)
            self.assertFalse(set(argv) & {"--offline-scan", "--skip-db-update", "--skip-java-db-update",
                "--skip-check-update", "--ignore-unfixed"})
            self.assertEqual(json.loads(Path(argv[argv.index("--config") + 1]).read_text()), {
                "scan": {"maven": {"mirrors": [{
                    "source": "https://repo.maven.apache.org/maven2/",
                    "targets": ["https://maven-central.storage-download.googleapis.com/maven2/",
                                "https://repo1.maven.org/maven2/", "https://repo.maven.apache.org/maven2/"],
                }]}}})
            self.assertEqual(Path(argv[argv.index("--ignorefile") + 1]).read_text(), "")

    def test_trivy_503_without_a_report_is_not_clean(self):
        with tempfile.TemporaryDirectory() as d:
            repo, work = Path(d) / "repo", Path(d) / "work"
            repo.mkdir()
            work.mkdir()
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w:gz") as tar:
                member = tarfile.TarInfo("trivy")
                member.size = 4
                tar.addfile(member, io.BytesIO(b"fake"))
            def unavailable(argv, cwd, log, seconds):
                log.write_text("503 Service Unavailable PRIVATE_RESPONSE")
                return 1
            with patch.object(scan, "download", return_value=archive.getvalue()), \
                    patch.object(scan, "command", unavailable), self.assertRaises(scan.ScannerFailure):
                scan.scan("trivy", repo, work)

    def test_trivy_failure_presence_is_finite_and_does_not_claim_causality(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "log"
            log.write_text("Failed to download vulnerability DB from https://mirror.gcr.io/v2/private?token=PRIVATE "
                "then ghcr.io/aquasecurity/trivy-db and public.ecr.aws/aquasecurity/trivy-db "
                "PRIVATE_BODY /private/workspace/source.js")
            self.assertEqual(scan.trivy_log_presence(log), {
                "registry_presence": {"gcr": True, "ghcr": True, "ecr": True},
                "db_update_phase_presence": {"vulnerability_db": True, "java_db": False}})
            self.assertNotIn("PRIVATE", json.dumps(scan.trivy_log_presence(log)))
            log.write_text("429 Too Many Requests https://mirror.gcr.io.evil.invalid "
                "ghcr.io.evil.invalid evilpublic.ecr.aws Failed to download Java DB")
            self.assertEqual(scan.trivy_log_presence(log), {
                "registry_presence": {"gcr": False, "ghcr": False, "ecr": False},
                "db_update_phase_presence": {"vulnerability_db": False, "java_db": True}})
            log.unlink()
            self.assertEqual(scan.trivy_log_presence(log), {
                "registry_presence": {"gcr": False, "ghcr": False, "ecr": False},
                "db_update_phase_presence": {"vulnerability_db": False, "java_db": False}})

    def test_trivy_failure_summary_keeps_presence_only_and_other_tools_run(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            (repo / ".git").mkdir()
            calls = []
            def controlled(tool, repo, work):
                calls.append(tool)
                if tool == "trivy":
                    private = work / tool
                    private.mkdir()
                    (private / "log").write_text("Failed to download Java DB: "
                        "https://public.ecr.aws/v2/private?token=PRIVATE 429 Too Many Requests PRIVATE_BODY")
                    raise scan.ScannerFailure("scan", "upstream-rate-limit", 1,
                        diagnostics={"http_status": 429, "retry_attempts": 0})
                return {"tool": tool, "status": "clean"}
            output = io.StringIO()
            with patch.object(scan, "scan", controlled), patch.object(sys, "argv", ["scan.py", str(repo)]), \
                    patch("sys.stdout", output):
                self.assertEqual(scan.main(), 1)
            self.assertEqual(calls, ["semgrep", "trivy", "gitleaks"])
            result = json.loads(output.getvalue().splitlines()[1])
            self.assertEqual(result["registry_presence"], {"gcr": False, "ghcr": False, "ecr": True})
            self.assertEqual(result["db_update_phase_presence"], {"vulnerability_db": False, "java_db": True})
            self.assertEqual((result["http_status"], result["retry_attempts"]), (429, 0))
            for private in ("PRIVATE", "https://", "/v2/", "token="):
                self.assertNotIn(private, output.getvalue())

    def test_empty_or_wrong_kind_trivy_json_is_not_clean(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "report"
            for value in ({}, {"SchemaVersion": 2, "ArtifactType": "container_image"}):
                p.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    scan.findings("trivy", p)

    def test_trivy_null_optional_lists_and_malformed_lists(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "report"
            base = {"SchemaVersion": 2, "ArtifactType": "repository"}
            p.write_text(json.dumps(base | {"Results": [{
                "Target": "package-lock.json", "Vulnerabilities": None,
                "Misconfigurations": [{"ID": "AVD-TEST", "Severity": "HIGH"}],
            }]}))
            self.assertEqual(scan.findings("trivy", p), [{
                "path": "package-lock.json", "rule": "AVD-TEST", "severity": "HIGH"}])
            for bad in ({}, "invalid", 5, ["invalid"]):
                p.write_text(json.dumps(base | {"Results": [{"Vulnerabilities": bad}]}))
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    scan.findings("trivy", p)

    def test_tar_link_is_never_extracted(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as t:
            m = tarfile.TarInfo("gitleaks")
            m.type, m.linkname = tarfile.SYMTYPE, "/etc/passwd"
            t.addfile(m)
        with tempfile.TemporaryDirectory() as d, self.assertRaises(ValueError):
            scan.extract_selected(data.getvalue(), {"gitleaks": None}, Path(d))

    def test_real_child_timeout_is_private_and_reaped(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "log"
            with self.assertRaises(subprocess.TimeoutExpired):
                scan.command([sys.executable, "-c", "import time; print('PRIVATE_LOG',flush=True); time.sleep(30)"], Path(d), log, .1)
            self.assertIn("PRIVATE_LOG", log.read_text())

    def test_control_characters_in_filenames_are_withheld(self):
        self.assertEqual(scan.safe_text("evil\n::error::SECRET"), "withheld")

    def test_download_failure_has_fixed_diagnostic_without_body(self):
        def fail():
            raise ValueError("SECRET_RESPONSE_BODY")
        with self.assertRaises(scan.ScannerFailure) as caught:
            scan.phase("download", fail)
        self.assertEqual((caught.exception.phase, caught.exception.category),
                         ("download", "operation-failed"))
        self.assertNotIn("SECRET", str(caught.exception))

    def test_real_child_output_is_bounded_without_limiting_installed_files(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "log"
            with self.assertRaises(scan.ScannerFailure) as caught:
                scan.command([sys.executable, "-c", "import os; os.write(1,b'x'*(20*1024**2))"], Path(d), log, 10)
            self.assertEqual(caught.exception.category, "output-limit")
            self.assertLessEqual(log.stat().st_size, scan.REPORT_CAP)


@unittest.skipUnless(os.environ.get("REAL_SCANNERS") == "1", "explicit network scanner fixture")
class RealScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.work = Path(cls.temporary.name)
        cls.repo = cls.work / "repo"
        cls.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(cls.repo)], check=True)
        subprocess.run(["git", "-C", str(cls.repo), "config", "user.email", "fixture@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(cls.repo), "config", "user.name", "Fixture"], check=True)
        (cls.repo / "unsafe.py").write_text("import subprocess\nsubprocess.call(user_input, shell=True)\n")
        # Deliberately fake detector fixture; never a real issued credential.
        cls.fake = "ghp_" + "b367a9c812d45f0e72a61380c9fca395e9db"
        (cls.repo / "secret.txt").write_text("github_token=" + cls.fake + "\n")
        (cls.repo / "Dockerfile").write_text("FROM ubuntu:24.04\nUSER root\n")
        subprocess.run(["git", "-C", str(cls.repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(cls.repo), "commit", "-qm", "fake scanner fixture"], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_semgrep_pinned_pack_and_findings(self):
        result = scan.scan("semgrep", self.repo, self.work)
        self.assertEqual(result["status"], "findings")
        self.assertGreater(result["count"], 0)
        # The URL validation fix is accepted by the same full pinned audit pack.
        audit = self.work / "downloader-audit"
        audit.mkdir()
        (audit / "scan.py").write_bytes(Path(scan.__file__).read_bytes())
        private = self.work / "semgrep"
        report = private / "downloader-report.json"
        rc = scan.command([str(private / "venv/bin/semgrep"), "scan", "--oss-only", "--metrics=off",
                           "--disable-version-check", "--strict", "--error", "--jobs=2", "--max-memory=1024",
                           "--config", str(private / "rules"), "--json", "--output", str(report), "."],
                          audit, private / "log", 90)
        self.assertEqual(rc, 0)
        self.assertEqual(scan.findings("semgrep", report), [])
        self.assertEqual(len(json.loads(report.read_bytes())["paths"]["scanned"]), 1)

    def test_gitleaks_pinned_binary_full_history_and_redaction(self):
        result = scan.scan("gitleaks", self.repo, self.work)
        self.assertEqual(result["status"], "findings")
        self.assertNotIn(self.fake, json.dumps(result))

    def test_gitleaks_exact_fingerprint_only_and_default_ignore_lookup(self):
        private = self.work / "ignore-fixture"
        private.mkdir()
        scan.extract_selected(scan.download(
            f"https://github.com/gitleaks/gitleaks/releases/download/v{scan.GITLEAKS_VERSION}/gitleaks_{scan.GITLEAKS_VERSION}_linux_x64.tar.gz",
            scan.GITLEAKS_SHA), {"gitleaks": None}, private)
        binary = private / "gitleaks"
        binary.chmod(0o700)
        report, config = private / "report.json", private / "config.toml"
        config.write_text("[extend]\nuseDefault = true\n")
        argv = [str(binary), "git", "--config", str(config), "--redact=100", "--no-banner",
                "--report-format", "json", "--report-path", str(report), "--log-opts=--all", "."]
        self.assertEqual(scan.command(argv, self.repo, private / "log", 30), 1)
        original = json.loads(report.read_bytes())
        self.addCleanup((self.repo / ".gitleaksignore").unlink, missing_ok=True)
        (self.repo / ".gitleaksignore").write_text("\n".join(x["Fingerprint"] for x in original) + "\n")
        self.assertEqual(scan.command(argv, self.repo, private / "log", 30), 0)
        self.assertEqual(json.loads(report.read_bytes()), [])
        # A new fake credential in the same file is a new fingerprint and still fails.
        later_fake = "ghp_" + self.fake[4:][::-1]
        (self.repo / "secret.txt").write_text("github_token=" + self.fake + "\nanother_token=" + later_fake + "\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "secret.txt"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "move fake fixture"], check=True)
        self.assertEqual(scan.command(argv, self.repo, private / "log", 30), 1)
        self.assertGreater(len(json.loads(report.read_bytes())), 0)
        (self.repo / ".gitleaksignore").unlink()

    def test_trivy_pinned_binary_real_misconfig(self):
        private = self.work / "trivy-fixture"
        private.mkdir()
        url = f"https://github.com/aquasecurity/trivy/releases/download/v{scan.TRIVY_VERSION}/trivy_{scan.TRIVY_VERSION}_Linux-64bit.tar.gz"
        scan.extract_selected(scan.download(url, scan.TRIVY_SHA), {"trivy": None}, private)
        binary = private / "trivy"
        binary.chmod(0o700)
        report = private / "report.json"
        rc = scan.command([str(binary), "fs", "--scanners", "misconfig", "--skip-check-update",
                           "--parallel", "2", "--quiet", "--format", "json", "--output", str(report),
                           "--exit-code", "1", str(self.repo)], self.repo, private / "log", 120)
        self.assertEqual(rc, 1)
        metadata = json.loads(report.read_bytes())
        self.assertEqual(metadata.get("SchemaVersion"), 2)
        # Trivy identifies a filesystem target containing .git as a repository.
        self.assertEqual(metadata.get("ArtifactType"), "repository")
        self.assertGreater(len(scan.findings("trivy", report)), 0)


if __name__ == "__main__":
    unittest.main()
