# Source-bound security exceptions

All scanner rules continue to run. Semgrep and Trivy findings may be accepted only through a reviewed repository-root `.security-exceptions.json`. The scanner never generates an ignore file from it. Gitleaks retains its separate existing exact-fingerprint mechanism.

An exception is a repository-owned policy decision, reviewed with its source and security rationale through the normal PR process. This file does not cryptographically attest that a human approved the decision. It is not an automatic allowlist for root containers, `exec`, SHA1, URL access or serialization.

## Exact schema

The top object has exactly `version` and `exceptions`. Version is the integer `1`. Each array entry has exactly these seven fields:

| Field | Required value |
|---|---|
| `scanner` | `semgrep` or `trivy` |
| `rule_id` | Exact reported stable ID; ASCII letters/digits/underscore/dot/hyphen, 1–240 characters |
| `path` | Exact checkout-relative POSIX file path, 1–240 printable ASCII characters; no absolute path, empty/dot/dotdot component, backslash, drive colon or glob |
| `start_line`, `end_line` | Exact integer start and end of that one finding, inclusive; 1–10,000,000 and end≥start; booleans rejected |
| `source_sha256` | Exact 64-character lowercase SHA256 of the current file bytes |
| `reason` | Review rationale, 16–500 printable ASCII characters; retained in the manifest and not printed in scanner summaries |

The only line `0` exception is Trivy `DS-0002` at explicit `0/0`. Trivy 0.76.1 may emit that file-level Dockerfile check with no line fields. It is recognized only when `Class=config`, `Type=dockerfile`, `ID=DS-0002` and `CauseMetadata` is exactly `{"Provider":"Dockerfile","Service":"general"}`. Missing, partial or malformed coordinates in other report shapes never become wildcard locations. Positive source ranges still require exact equality, not containment.

Semgrep's temporary config-directory prefix through `.rules.` is removed; for example, the stable ID is `python.lang.security.audit.exec-detected`. Trivy uses `ID` exactly (`DS-0002`, not its documentation URL or a guessed `AVD-...` alias). The literal sanitizer sentinel `withheld` is reserved and cannot be an exception path or rule.

Example shape only; these deliberately nonmatching values do not authorize a real finding:

```json
{
  "version": 1,
  "exceptions": [
    {
      "scanner": "semgrep",
      "rule_id": "python.lang.security.audit.exec-detected",
      "path": "path/to/reviewed.py",
      "start_line": 42,
      "end_line": 42,
      "source_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "reason": "Documentation example only; review the real trust boundary and negative tests first."
    }
  ]
}
```

The manifest is optional. If present, its exact schema is mandatory: duplicate JSON keys, duplicate exception identities, unknown fields/scanners/versions and unsupported paths fail. Bounds are 128 KiB and 256 entries. Manifest and source paths must be regular single-link files with no symlink/reparse parent or final component. Each source read is bounded to 64 MiB; cumulative source hashing is bounded to 256 MiB per tool. Held file descriptors, stable metadata and name/parent identity checks reject observed source replacement during reading. Access time is deliberately excluded from identity comparisons.

## Gate and public output

Normal scanner exit/report checks and partial-parser failures happen before exception matching. Hashes are freshly read **after** the scanner exits. Each entry consumes exactly one matching finding index; a second identical finding is still unaccepted. Matching requires exact scanner, canonical rule, path, full line range and current byte hash. No exception spans a wildcard range or carries a command, path selector or scanner configuration.

Unchanged public `count` and `findings` retain all scanner results (with the existing first 50/remaining count bound). Additional fields are `accepted_exception_count`, `accepted_exceptions` (first 20), `additional_accepted_exceptions`, `unaccepted_count`, `stale_exception_count`, `stale_exceptions` (first 20) and `additional_stale_exceptions`. Only safe rule/path/location projections are printed; reasons, source snippets, raw reports and error bodies are not printed.

- No findings and no entries for that scanner: `status=clean`.
- Every finding exactly accepted, no stale entry: `status=reviewed-exceptions`; gate succeeds, findings remain visible.
- Any new/unaccepted finding: `status=findings`; gate fails.
- Any changed/missing/unsafe source or unused entry after a fix: `status=error`, phase `exceptions`, category `stale-entries`; gate fails even with zero findings.
- Malformed manifest: `status=error`, phase `exceptions`, category `invalid-manifest`; findings remain visible and the other scanners still run.

Removing or fixing a finding requires removing its old exception. Editing source, moving code or repinning rules requires a fresh review rather than silently retaining old acceptance. Genuine unsafe deserialization or untrusted execution must be fixed; this feature supplies no repository-specific dispositions.

## Verification

The policy workflow runs both the existing policy tests and the exception matcher tests:

```sh
python -B -m unittest -v test_scan.PolicyTests test_exceptions.ExceptionTests
```

The 37 Linux tests cover real symlinks and hardlinks, replacement during reads, exact identity mismatches, duplicate findings, stale entries, malformed schemas and independent scanner execution. Real pinned Trivy and Semgrep checks verify that a reviewed finding can be accepted while changed bytes, a new finding and a stale entry still fail.

Repository-specific exception manifests belong in their application repositories. Review the source, rationale and negative tests through the normal pull request process. Tool installation, downloads, timeouts, retries, redaction, existing Gitleaks behavior and scanner rule selection remain unchanged.

Trivy keeps its default GCR then GHCR order for both databases, with Aqua's official public ECR repository added last as an availability fallback. Database updates, deadlines and HIGH/CRITICAL gates remain enabled. On a Trivy failure, the summary may include fixed registry and database-update phrase presence booleans; these reveal no raw URLs or log text and do not establish which endpoint caused the failure.

Maven metadata uses [Google's documented public Central cache](https://docs.cloud.google.com/docs/buildpacks/java), then the canonical `repo1.maven.org` and original `repo.maven.apache.org` endpoints through Trivy's native ordered mirrors. Dependency resolution remains enabled; exhausted rate-limited mirrors still fail the scan, and vulnerability, misconfiguration, deadline and report gates remain unchanged.
