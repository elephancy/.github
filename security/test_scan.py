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
            with self.assertRaises(ValueError):
                scan.findings("semgrep", p)

    def test_empty_or_wrong_kind_trivy_json_is_not_clean(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "report"
            for value in ({}, {"SchemaVersion": 2, "ArtifactType": "container_image"}):
                p.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
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

    def test_gitleaks_pinned_binary_full_history_and_redaction(self):
        result = scan.scan("gitleaks", self.repo, self.work)
        self.assertEqual(result["status"], "findings")
        self.assertNotIn(self.fake, json.dumps(result))

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
