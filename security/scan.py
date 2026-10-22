#!/usr/bin/env python3
"""Pinned scanner-only policy. Reports and tool logs never enter public artifacts."""
import hashlib
import io
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

HERE = Path(__file__).resolve().parent
TRIVY_VERSION = "0.76.1"
TRIVY_SHA = "c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0"
GITLEAKS_VERSION = "8.30.1"
GITLEAKS_SHA = "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
DOWNLOAD_CAP = 100 * 1024**2
REPORT_CAP = 16 * 1024**2
MEMBER_CAP = 256 * 1024**2
EXCLUDES = ["node_modules", ".venv", "venv", "Library", "Temp", "obj", ".git"]


class ScannerFailure(Exception):
    def __init__(self, phase, category, exit_code=None):
        self.phase, self.category, self.exit_code = phase, category, exit_code


def phase(name, function, *args):
    try:
        return function(*args)
    except ScannerFailure:
        raise
    except subprocess.TimeoutExpired:
        raise ScannerFailure(name, "timeout") from None
    except Exception:
        raise ScannerFailure(name, "operation-failed") from None


def download(url, expected, maximum=DOWNLOAD_CAP):
    with urllib.request.urlopen(url, timeout=45) as response:
        data = response.read(maximum + 1)
    if len(data) > maximum or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("download integrity")
    return data


def extract_selected(data, selected, target, prefix=""):
    """Read named regular members only; never extract tar paths or links."""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        found = set()
        for member in archive:
            name = member.name.removeprefix(prefix)
            if name not in selected:
                continue
            if name in found or not member.isfile() or member.size > MEMBER_CAP:
                raise ValueError("archive member")
            content = archive.extractfile(member).read(MEMBER_CAP + 1)
            expected = selected[name]
            if expected and hashlib.sha256(content).hexdigest() != expected:
                raise ValueError("member integrity")
            # selected is a trusted immutable manifest, still reject path traversal.
            if name.startswith("/") or any(x in ("", ".", "..") for x in name.split("/")):
                raise ValueError("member path")
            output = target / name
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(content)
            found.add(name)
        if found != set(selected):
            raise ValueError("missing member")


def command(argv, cwd, log, seconds):
    """Private bounded log and cooperative process-group deadline cleanup."""
    with log.open("ab", buffering=0) as output:
        process = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        deadline, written = time.monotonic() + seconds, 0
        try:
            with selectors.DefaultSelector() as reader:
                reader.register(process.stdout, selectors.EVENT_READ)
                while reader.get_map():
                    if time.monotonic() >= deadline:
                        raise subprocess.TimeoutExpired(argv[0], seconds)
                    for key, _ in reader.select(min(.2, max(0, deadline - time.monotonic()))):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            reader.unregister(key.fileobj)
                            continue
                        written += len(chunk)
                        if written > REPORT_CAP:
                            raise ScannerFailure("scan", "output-limit")
                        output.write(chunk)
            return process.wait(timeout=max(.001, deadline - time.monotonic()))
        finally:
            # Also reap ordinary descendants after success/failure of their parent.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            process.stdout.close()


def safe_text(value, maximum=240):
    if not isinstance(value, str) or len(value) > maximum or not value.isascii():
        return "withheld"
    if any(ord(c) < 32 or ord(c) > 126 for c in value):
        return "withheld"
    return value


def findings(tool, report):
    if report.stat().st_size > REPORT_CAP:
        raise ValueError("report bound")
    data = json.loads(report.read_bytes())
    if tool == "semgrep":
        if data.get("errors"):
            raise ValueError("incomplete semgrep scan")
        return [{"path": safe_text(x.get("path")), "rule": safe_text(x.get("check_id")),
                 "line": x.get("start", {}).get("line")} for x in data["results"]]
    if tool == "gitleaks":
        return [{"path": safe_text(x.get("File")), "rule": safe_text(x.get("RuleID")),
                 "line": x.get("StartLine")} for x in data]
    if (not isinstance(data, dict) or type(data.get("SchemaVersion")) is not int
            or data["SchemaVersion"] != 2 or data.get("ArtifactType") not in ("filesystem", "repository")):
        raise ValueError("invalid trivy report")
    result = []
    for target in data.get("Results", []):
        for item in target.get("Vulnerabilities", []) + target.get("Misconfigurations", []):
            result.append({"path": safe_text(target.get("Target")),
                           "rule": safe_text(item.get("VulnerabilityID", item.get("ID"))),
                           "severity": safe_text(item.get("Severity"))})
    return result


def scan(tool, repo, work):
    private = work / tool
    private.mkdir()
    log, report = private / "log", private / "report.json"
    if tool == "semgrep":
        rc = phase("install", command, [sys.executable, "-m", "venv", str(private / "venv")], repo, log, 60)
        if rc:
            raise ScannerFailure("install", "venv-failed", rc)
        python = private / "venv/bin/python"
        rc = phase("install", command, [str(python), "-m", "pip", "--isolated", "install", "--require-hashes",
                      "--only-binary=:all:", "-r", str(HERE / "requirements-semgrep.lock")],
                     repo, log, 180)
        if rc:
            raise ScannerFailure("install", "pip-failed", rc)
        spec = json.loads((HERE / "rules.json").read_bytes())
        rules = private / "rules"
        rules.mkdir()
        archive = phase("rule-download", download, spec["archive_url"], spec["archive_sha256"])
        phase("rule-validation", extract_selected, archive, spec["files"], rules,
              "semgrep-rules-" + spec["source_commit"] + "/")
        argv = [str(private / "venv/bin/semgrep"), "scan", "--oss-only", "--metrics=off",
                "--disable-version-check", "--strict", "--error", "--jobs=2", "--max-memory=1024",
                "--timeout=5", "--config", str(rules), "--json", "--output", str(report)]
        for exclude in EXCLUDES:
            argv += ["--exclude", exclude]
        argv += ["."]
        seconds = 240
    else:
        version, digest = (TRIVY_VERSION, TRIVY_SHA) if tool == "trivy" else (GITLEAKS_VERSION, GITLEAKS_SHA)
        asset = f"trivy_{version}_Linux-64bit.tar.gz" if tool == "trivy" else f"gitleaks_{version}_linux_x64.tar.gz"
        project = "aquasecurity/trivy" if tool == "trivy" else "gitleaks/gitleaks"
        data = phase("download", download, f"https://github.com/{project}/releases/download/v{version}/{asset}", digest)
        phase("install", extract_selected, data, {tool: None}, private)
        executable = private / tool
        executable.chmod(0o700)
        if tool == "trivy":
            config, ignore = private / "config.yaml", private / "ignore"
            config.write_text("{}\n")
            ignore.write_text("")
            argv = [str(executable), "fs", "--config", str(config), "--ignorefile", str(ignore),
                    "--scanners", "vuln,misconfig", "--severity", "HIGH,CRITICAL", "--exit-code", "1",
                    "--parallel", "2", "--timeout", "210s", "--skip-version-check", "--quiet",
                    "--cache-dir", str(private / "cache"), "--format", "json", "--output", str(report)]
            for exclude in EXCLUDES:
                argv += ["--skip-dirs", exclude]
            argv += ["."]
            seconds = 240
        else:
            config = private / "gitleaks.toml"
            config.write_text("[extend]\nuseDefault = true\n")
            argv = [str(executable), "git", "--config", str(config), "--redact=100", "--no-banner",
                    "--log-level", "error", "--report-format", "json", "--report-path", str(report),
                    "--exit-code", "1", "--timeout", "120", "--log-opts=--all", "."]
            seconds = 130
    rc = phase("scan", command, argv, repo, log, seconds)
    items = phase("report", findings, tool, report)
    if rc not in (0, 1) or (rc == 0 and items) or (rc == 1 and not items):
        raise ScannerFailure("report", "exit-report-disagreement", rc)
    return {"tool": tool, "status": "findings" if items else "clean", "count": len(items),
            "findings": items[:50], "additional_findings": max(0, len(items) - 50)}


def main():
    if len(sys.argv) != 2:
        return 2
    repo = Path(sys.argv[1]).resolve(strict=True)
    if not (repo / ".git").exists():
        return 2
    os.umask(0o077)
    os.environ.pop("SEMGREP_APP_TOKEN", None)
    os.environ.update(SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0",
                      PIP_DISABLE_PIP_VERSION_CHECK="1")
    results = []
    # Independent outcomes: a download/parser/finding failure never skips later tools.
    with tempfile.TemporaryDirectory(prefix="security-", dir=os.environ.get("RUNNER_TEMP")) as scratch:
        work = Path(scratch)
        for tool in ("semgrep", "trivy", "gitleaks"):
            try:
                result = scan(tool, repo, work)
            except ScannerFailure as failure:
                result = {"tool": tool, "status": "error", "phase": failure.phase,
                          "category": failure.category, "exit_code": failure.exit_code,
                          "private_output_withheld": True}
            except Exception:
                result = {"tool": tool, "status": "error", "phase": "internal",
                          "category": "unexpected-error", "private_output_withheld": True}
            results.append(result)
            print(json.dumps(result, ensure_ascii=True, separators=(",", ":")), flush=True)
    return int(any(x["status"] != "clean" for x in results))


def cancelled(signum, frame):
    # Let command() kill and reap its owned process group on runner cancellation.
    raise KeyboardInterrupt


if __name__ == "__main__":
    for received in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(received, cancelled)
    raise SystemExit(main())
