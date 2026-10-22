#!/usr/bin/env python3
"""Pinned scanner-only policy. Reports and tool logs never enter public artifacts."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
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
DOWNLOAD_HOSTS = frozenset({"github.com", "codeload.github.com"})
REDIRECT_HOSTS = DOWNLOAD_HOSTS | {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}
EXCEPTIONS_FILE = ".security-exceptions.json"
EXCEPTIONS_BYTES = 128 * 1024
EXCEPTIONS_MAX = 256
EXCEPTION_SOURCE_BYTES = 64 * 1024**2
EXCEPTION_TOTAL_BYTES = 256 * 1024**2


class ScannerFailure(Exception):
    def __init__(self, phase, category, exit_code=None, diagnostics=None):
        self.phase, self.category, self.exit_code = phase, category, exit_code
        self.diagnostics = diagnostics


def phase(name, function, *args):
    try:
        return function(*args)
    except ScannerFailure:
        raise
    except subprocess.TimeoutExpired:
        raise ScannerFailure(name, "timeout") from None
    except Exception:
        raise ScannerFailure(name, "operation-failed") from None


def checked_url(url, redirect=False):
    parsed = urllib.parse.urlsplit(url)
    allowed = REDIRECT_HOSTS if redirect else DOWNLOAD_HOSTS
    if (parsed.scheme != "https" or parsed.hostname not in allowed or parsed.port not in (None, 443)
            or parsed.username is not None or parsed.password is not None or parsed.fragment
            or (not redirect and parsed.query)):
        raise ValueError("download URL")
    return url


class DownloadRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return super().redirect_request(req, fp, code, msg, headers, checked_url(newurl, redirect=True))


def download(url, expected, maximum=DOWNLOAD_CAP):
    # HTTPS/hosts are closed above, including redirects; immutable bytes must match the reviewed SHA256.
    opener = urllib.request.build_opener(DownloadRedirect())
    with opener.open(checked_url(url), timeout=45) as response:
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


def _identity(row):
    return (row.st_dev, row.st_ino, row.st_mode, row.st_nlink, row.st_size,
            row.st_mtime_ns, row.st_ctime_ns)


def _regular_bytes(repo, name, maximum):
    """Read a bounded stable regular file; reject links in every path component."""
    path = repo
    parents = []
    for component in name.split("/")[:-1]:
        path = path / component
        row = path.lstat()
        if not stat.S_ISDIR(row.st_mode) or getattr(row, "st_file_attributes", 0) & 0x400:
            raise ValueError("source parent")
        parents.append((path, _identity(row)))
    path = repo / name
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or getattr(before, "st_file_attributes", 0) & 0x400 or before.st_size > maximum):
        raise ValueError("source file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if _identity(os.fstat(descriptor)) != _identity(before):
            raise ValueError("source identity")
        chunks, size = [], 0
        while True:
            block = os.read(descriptor, min(1024**2, maximum + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
            if size > maximum:
                raise ValueError("source size")
        if (_identity(os.fstat(descriptor)) != _identity(before)
                or _identity(path.lstat()) != _identity(before)
                or any(_identity(parent.lstat()) != identity for parent, identity in parents)):
            raise ValueError("source changed")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate exception key")
        result[key] = value
    return result


def load_exceptions(repo):
    try:
        (repo / EXCEPTIONS_FILE).lstat()
    except FileNotFoundError:
        return []
    value = json.loads(_regular_bytes(repo, EXCEPTIONS_FILE, EXCEPTIONS_BYTES), object_pairs_hook=_unique_object)
    if (type(value) is not dict or set(value) != {"version", "exceptions"}
            or type(value["version"]) is not int or value["version"] != 1
            or type(value["exceptions"]) is not list or len(value["exceptions"]) > EXCEPTIONS_MAX):
        raise ValueError("exception manifest")
    seen = set()
    for item in value["exceptions"]:
        if type(item) is not dict or set(item) != {
                "scanner", "rule_id", "path", "start_line", "end_line", "source_sha256", "reason"}:
            raise ValueError("exception entry")
        name, rule = item["path"], item["rule_id"]
        if (item["scanner"] not in ("semgrep", "trivy") or not isinstance(name, str)
                or safe_text(name) != name or not name or name.startswith("/")
                or name == "withheld" or rule == "withheld"
                or any(part in ("", ".", "..") for part in name.split("/"))
                or any(char in name for char in "\\:*?[]")
                or not isinstance(rule, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,239}", rule)
                or type(item["start_line"]) is not int or type(item["end_line"]) is not int
                or not 0 <= item["start_line"] <= item["end_line"] <= 10_000_000
                or (item["start_line"] == 0 and item["end_line"] != 0)
                or (item["scanner"] == "semgrep" and item["start_line"] == 0)
                or (item["start_line"] == 0 and item["rule_id"] != "DS-0002")
                or not isinstance(item["source_sha256"], str)
                or not re.fullmatch(r"[a-f0-9]{64}", item["source_sha256"])
                or not isinstance(item["reason"], str) or not 16 <= len(item["reason"].strip()) <= 500
                or safe_text(item["reason"], 500) != item["reason"]):
            raise ValueError("exception fields")
        key = item["scanner"], name, rule, item["start_line"], item["end_line"]
        if key in seen:
            raise ValueError("duplicate exception")
        seen.add(key)
    return value["exceptions"]


def exception_summary(tool, repo, items):
    summary = {"tool": tool, "status": "findings" if items else "clean", "count": len(items),
               "findings": items[:50], "additional_findings": max(0, len(items) - 50)}
    if tool not in ("semgrep", "trivy"):
        return summary
    try:
        entries = [item for item in load_exceptions(repo) if item["scanner"] == tool]
    except (ValueError, OSError, TypeError, UnicodeError, RecursionError):
        return summary | {"status": "error", "phase": "exceptions", "category": "invalid-manifest",
                          "private_output_withheld": True}
    accepted, stale, used, digests = [], [], set(), {}
    total_bytes = 0
    for entry in entries:
        projection = {"path": entry["path"], "rule": entry["rule_id"],
                      "line": entry["start_line"], "end_line": entry["end_line"]}
        try:
            if entry["path"] not in digests:
                remaining = min(EXCEPTION_SOURCE_BYTES, EXCEPTION_TOTAL_BYTES - total_bytes)
                if remaining < 1:
                    raise ValueError("source budget")
                data = _regular_bytes(repo, entry["path"], remaining)
                total_bytes += len(data)
                digests[entry["path"]] = hashlib.sha256(data).hexdigest()
            if digests[entry["path"]] != entry["source_sha256"]:
                stale.append(projection | {"category": "source-changed"})
                continue
        except (OSError, ValueError):
            stale.append(projection | {"category": "source-unavailable"})
            continue
        match = next((index for index, item in enumerate(items)
                      if index not in used and all(item.get(key) == value for key, value in projection.items())), None)
        if match is None:
            stale.append(projection | {"category": "unmatched-finding"})
        else:
            used.add(match)
            accepted.append(projection)
    unaccepted = len(items) - len(used)
    status = "findings" if unaccepted else "reviewed-exceptions" if accepted else "clean"
    if stale:
        status = "error"
        summary.update(phase="exceptions", category="stale-entries")
    return summary | {"status": status, "accepted_exception_count": len(accepted),
                      "accepted_exceptions": accepted[:20], "unaccepted_count": unaccepted,
                      "additional_accepted_exceptions": max(0, len(accepted) - 20),
                      "stale_exception_count": len(stale), "stale_exceptions": stale[:20],
                      "additional_stale_exceptions": max(0, len(stale) - 20)}


def report_list(mapping, name):
    # Trivy serializes optional Go slices as null as well as omitting them.
    value = mapping.get(name)
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError("invalid report list")
    return value


def rate_limit_delay(log):
    """Recognize a transient upstream response without publishing its body."""
    text = log.read_text(errors="replace").lower()
    if not re.search(r"\b429\b", text) or "too many requests" not in text:
        return False, None
    if "retry-after" not in text:
        return True, 5
    delay = re.search(r"retry-after[\s\"':=]+(\d+)\b", text)
    # If the logged header is not numeric, decline to retry early.
    return True, int(delay.group(1)) if delay else None


def findings(tool, report):
    if not report.is_file():
        raise ScannerFailure("report", "report-missing")
    if report.stat().st_size > REPORT_CAP:
        raise ValueError("report bound")
    data = json.loads(report.read_bytes())
    if tool == "semgrep":
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise ValueError("invalid semgrep report")
        items = []
        for finding in data["results"]:
            rule = finding.get("check_id")
            rule = safe_text(rule.split(".rules.", 1)[-1] if isinstance(rule, str) else None)
            line = finding.get("start", {}).get("line")
            item = {"path": safe_text(finding.get("path")), "rule": rule,
                    "line": line if type(line) is int else None}
            if type(finding.get("end", {}).get("line")) is int:
                item["end_line"] = finding["end"]["line"]
            items.append(item)
        errors = report_list(data, "errors")
        if errors:
            issues = []
            for error in errors[:20]:
                kind = error.get("type")
                if isinstance(kind, list):
                    kind = kind[0] if kind else None
                issues.append({"type": safe_text(kind, 64),
                               "code": error.get("code") if type(error.get("code")) is int else None,
                               "path": safe_text(error.get("path"))})
            # A partial scan is still a failure. Retain actionable findings and
            # issue locations without publishing source lines or error messages.
            raise ScannerFailure("report", "incomplete-scan", diagnostics={
                "count": len(items), "findings": items[:50],
                "additional_findings": max(0, len(items) - 50),
                "scan_issue_count": len(errors), "scan_issues": issues,
                "additional_scan_issues": max(0, len(errors) - 20)})
        return items
    if tool == "gitleaks":
        return [{"path": safe_text(x.get("File")), "rule": safe_text(x.get("RuleID")),
                 "line": x.get("StartLine")} for x in data]
    if (not isinstance(data, dict) or type(data.get("SchemaVersion")) is not int
            or data["SchemaVersion"] != 2 or data.get("ArtifactType") not in ("filesystem", "repository")):
        raise ValueError("invalid trivy report")
    result = []
    for target in report_list(data, "Results"):
        for item in report_list(target, "Vulnerabilities") + report_list(target, "Misconfigurations"):
            projection = {"path": safe_text(target.get("Target")),
                          "rule": safe_text(item.get("VulnerabilityID", item.get("ID"))),
                          "severity": safe_text(item.get("Severity"))}
            cause = item.get("CauseMetadata")
            if (isinstance(cause, dict) and type(cause.get("StartLine")) is int
                    and type(cause.get("EndLine")) is int
                    and 0 < cause["StartLine"] <= cause["EndLine"]):
                projection.update(line=cause["StartLine"], end_line=cause["EndLine"])
            elif (item.get("ID") == "DS-0002" and "VulnerabilityID" not in item
                  and target.get("Class") == "config" and target.get("Type") == "dockerfile"
                  and cause == {"Provider": "Dockerfile", "Service": "general"}):
                # Trivy0.76.1's final-USER rule has no source coordinates. This
                # single file-level rule uses explicit0/0, never a wildcard range.
                projection.update(line=0, end_line=0)
            result.append(projection)
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
                "--timeout=20", "--config", str(rules), "--json", "--output", str(report)]
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
    started = time.monotonic()
    rc = phase("scan", command, argv, repo, log, seconds)
    retried = False
    if tool == "trivy" and not report.is_file():
        limited, delay = rate_limit_delay(log)
        remaining = seconds - (time.monotonic() - started)
        if limited and delay is not None and 0 <= delay <= 30 and remaining > delay + 5:
            time.sleep(delay)
            retried = True
            try:
                rc = phase("scan", command, argv, repo, log, seconds - (time.monotonic() - started))
            except ScannerFailure as failure:
                failure.diagnostics = {"first_failure_http_status": 429, "retry_attempts": 1}
                raise
        if limited and not report.is_file():
            raise ScannerFailure("scan", "upstream-rate-limit", rc, diagnostics={
                "http_status": 429, "retry_attempts": int(retried)})
    if rc not in (0, 1) and not report.is_file():
        raise ScannerFailure("scan", "scanner-failed", rc)
    try:
        items = phase("report", findings, tool, report)
    except ScannerFailure as failure:
        failure.exit_code = rc
        raise
    if rc not in (0, 1):
        raise ScannerFailure("scan", "scanner-failed", rc)
    if (rc == 0 and items) or (rc == 1 and not items):
        raise ScannerFailure("report", "exit-report-disagreement", rc)
    return exception_summary(tool, repo, items)


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
                if failure.diagnostics is not None:
                    result.update(failure.diagnostics)
            except Exception:
                result = {"tool": tool, "status": "error", "phase": "internal",
                          "category": "unexpected-error", "private_output_withheld": True}
            results.append(result)
            print(json.dumps(result, ensure_ascii=True, separators=(",", ":")), flush=True)
    return int(any(x["status"] not in ("clean", "reviewed-exceptions") for x in results))


def cancelled(signum, frame):
    # Let command() kill and reap its owned process group on runner cancellation.
    raise KeyboardInterrupt


if __name__ == "__main__":
    for received in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(received, cancelled)
    raise SystemExit(main())
