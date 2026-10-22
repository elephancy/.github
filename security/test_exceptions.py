import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('exceptions_policy', Path(__file__).with_name('scan.py'))
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


class ExceptionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        (self.repo / '.git').mkdir()
        (self.repo / 'source').mkdir()
        self.source = self.repo / 'source' / 'loader.py'
        self.source.write_text('captured = b"reviewed source"\nexec(captured)\n')
        self.dockerfile = self.repo / 'Dockerfile'
        self.dockerfile.write_text('FROM python:3.12-slim\nUSER root\n')
        self.entry = {
            'scanner': 'semgrep', 'rule_id': 'python.lang.security.audit.exec-detected',
            'path': 'source/loader.py', 'start_line': 2, 'end_line': 2,
            'source_sha256': hashlib.sha256(self.source.read_bytes()).hexdigest(),
            'reason': 'Synthetic reviewed fixture; never an application exception.',
        }

    def manifest(self, entries=None, **changes):
        value = {'version': 1, 'exceptions': [self.entry] if entries is None else entries}
        value.update(changes)
        (self.repo / scan.EXCEPTIONS_FILE).write_text(json.dumps(value))

    def semgrep(self, *, line=2, end=2, rule=None, path='source/loader.py', errors=None):
        report = self.repo / 'semgrep-report.json'
        report.write_text(json.dumps({'results': [{
            'path': path, 'check_id': '/tmp/private.rules.' + (rule or self.entry['rule_id']),
            'start': {'line': line}, 'end': {'line': end},
            'extra': {'lines': 'PRIVATE_SOURCE_SHOULD_NOT_BE_PUBLIC'},
        }], 'errors': errors or []}))
        return scan.findings('semgrep', report)

    def trivy(self, *, line=2, end=2, metadata=True):
        finding = {'ID': 'DS-0002', 'Severity': 'HIGH',
                   'Message': 'PRIVATE_REPORT_MESSAGE', 'Resolution': 'PRIVATE_REPORT_SOURCE'}
        if metadata:
            finding['CauseMetadata'] = {'StartLine': line, 'EndLine': end,
                                        'Code': {'Lines': [{'Number': 2, 'Content': 'PRIVATE_SOURCE'}]}}
        report = self.repo / 'trivy-report.json'
        report.write_text(json.dumps({'SchemaVersion': 2, 'ArtifactType': 'filesystem',
             'Results': [{'Target': 'Dockerfile', 'Class': 'config', 'Type': 'dockerfile',
                          'Misconfigurations': [finding], 'Vulnerabilities': None}]}))
        return scan.findings('trivy', report)

    def trivy_entry(self, *, line=2, end=2):
        return self.entry | {'scanner': 'trivy', 'rule_id': 'DS-0002', 'path': 'Dockerfile',
             'start_line': line, 'end_line': end,
             'source_sha256': hashlib.sha256(self.dockerfile.read_bytes()).hexdigest()}

    def test_report_shapes_keep_findings_visible_and_accept_exact_semgrep(self):
        self.manifest()
        result = scan.exception_summary('semgrep', self.repo, self.semgrep())
        self.assertEqual((result['status'], result['count'], result['accepted_exception_count'],
                          result['unaccepted_count'], result['stale_exception_count']),
                         ('reviewed-exceptions', 1, 1, 0, 0))
        self.assertEqual(result['findings'], result['accepted_exceptions'])
        self.assertNotIn('PRIVATE_', json.dumps(result))
        self.assertNotIn('Synthetic reviewed fixture', json.dumps(result))

    def test_actual_trivy_misconfiguration_shape_and_file_level_location(self):
        for line, end in ((2, 2), (1, 2)):
            with self.subTest(line=line, end=end):
                self.manifest([self.trivy_entry(line=line, end=end)])
                result = scan.exception_summary('trivy', self.repo, self.trivy(line=line, end=end))
                self.assertEqual(result['status'], 'reviewed-exceptions')
                self.assertEqual(result['count'], 1)
                self.assertEqual(result['accepted_exception_count'], 1)
                self.assertNotIn('PRIVATE_', json.dumps(result))

    def test_missing_trivy_location_is_not_an_implicit_wildcard(self):
        self.manifest([self.trivy_entry(line=0, end=0)])
        result = scan.exception_summary('trivy', self.repo, self.trivy(metadata=False))
        self.assertEqual((result['status'], result['accepted_exception_count'], result['unaccepted_count']),
                         ('error', 0, 1))

    def test_actual_ds0002_absent_location_shape_uses_finite_file_level_sentinel(self):
        self.manifest([self.trivy_entry(line=0, end=0)])
        report = self.repo / 'trivy-file-level.json'
        finding = {'ID': 'DS-0002', 'Severity': 'HIGH', 'CauseMetadata': {'Provider': 'Dockerfile', 'Service': 'general'}}
        value = {'SchemaVersion': 2, 'ArtifactType': 'filesystem', 'Results': [{
            'Target': 'Dockerfile', 'Class': 'config', 'Type': 'dockerfile', 'Misconfigurations': [finding]}]}
        report.write_text(json.dumps(value))
        result = scan.exception_summary('trivy', self.repo, scan.findings('trivy', report))
        self.assertEqual(result['status'], 'reviewed-exceptions')
        for mutation in ({'StartLine': 0}, {'EndLine': 0}, {'Resource': 'extra'}, {'Provider': 1}):
            changed = copy.deepcopy(value)
            changed['Results'][0]['Misconfigurations'][0]['CauseMetadata'].update(mutation)
            report.write_text(json.dumps(changed))
            self.assertEqual(scan.exception_summary('trivy', self.repo, scan.findings('trivy', report))['status'], 'error')

    def test_changed_rule_path_start_end_and_range_do_not_match(self):
        self.manifest()
        for change in ({'line': 3, 'end': 3}, {'line': 2, 'end': 3}, {'line': 1, 'end': 4},
                       {'rule': 'another-rule'}, {'path': 'source/other.py'}, {'line': True}, {'end': True}):
            with self.subTest(change=change):
                result = scan.exception_summary('semgrep', self.repo, self.semgrep(**change))
                self.assertEqual((result['status'], result['accepted_exception_count'], result['unaccepted_count']),
                                 ('error', 0, 1))
                self.assertEqual(result['stale_exception_count'], 1)

    def test_changed_bytes_even_without_line_change_refuse(self):
        self.manifest()
        self.source.write_text(self.source.read_text().replace('reviewed source', 'different source'))
        result = scan.exception_summary('semgrep', self.repo, self.semgrep())
        self.assertEqual((result['status'], result['accepted_exception_count']), ('error', 0))
        self.assertEqual(result['stale_exceptions'][0]['category'], 'source-changed')

    def test_new_finding_and_duplicate_finding_still_fail(self):
        self.manifest()
        items = self.semgrep()
        for added in (items[0], items[0] | {'rule': 'new-rule'}, items[0] | {'line': 3, 'end_line': 3}):
            with self.subTest(added=added):
                result = scan.exception_summary('semgrep', self.repo, items + [added])
                self.assertEqual((result['status'], result['accepted_exception_count'], result['unaccepted_count']),
                                 ('findings', 1, 1))

    def test_stale_entry_after_fix_is_failure_even_with_clean_report(self):
        self.manifest()
        result = scan.exception_summary('semgrep', self.repo, [])
        self.assertEqual((result['status'], result['stale_exception_count'], result['count']), ('error', 1, 0))

    def test_manifests_are_scanner_specific_and_gitleaks_is_unchanged(self):
        self.manifest([self.entry, self.trivy_entry()])
        self.assertEqual(scan.exception_summary('semgrep', self.repo, self.semgrep())['status'], 'reviewed-exceptions')
        self.assertEqual(scan.exception_summary('trivy', self.repo, self.trivy())['status'], 'reviewed-exceptions')
        gitleaks = [{'path': 'key.txt', 'rule': 'generic-api-key', 'line': 1}]
        result = scan.exception_summary('gitleaks', self.repo, gitleaks)
        self.assertEqual(result['status'], 'findings')
        self.assertNotIn('accepted_exception_count', result)

    def test_unsupported_schema_fields_and_duplicate_entries_fail(self):
        cases = [
            {'version': True, 'exceptions': []}, {'version': 2, 'exceptions': []},
            {'version': 1, 'exceptions': [], 'extra': True}, {'version': 1, 'exceptions': {}},
            {'version': 1, 'exceptions': [self.entry, self.entry]},
        ]
        for value in cases:
            with self.subTest(value=value):
                (self.repo / scan.EXCEPTIONS_FILE).write_text(json.dumps(value))
                result = scan.exception_summary('semgrep', self.repo, self.semgrep())
                self.assertEqual((result['status'], result['phase'], result['category']),
                                 ('error', 'exceptions', 'invalid-manifest'))
                self.assertEqual(result['count'], 1)

    def test_invalid_entry_fields_are_not_suppression_controls(self):
        changes = [
            {'scanner': 'gitleaks'}, {'scanner': 'unknown'}, {'rule_id': '*'},
            {'path': 'withheld'}, {'rule_id': 'withheld'},
            {'path': '../source/loader.py'}, {'path': '/source/loader.py'}, {'path': 'source//loader.py'},
            {'path': './source/loader.py'}, {'path': 'source/*.py'}, {'path': 'source/lo?der.py'},
            {'path': 'source/[loader].py'}, {'path': 'source\\loader.py'}, {'path': 'C:/loader.py'},
            {'path': 'source/../loader.py'}, {'path': 'source/loader.py\n::error::'},
            {'start_line': 0}, {'start_line': False}, {'start_line': 3}, {'end_line': -1},
            {'end_line': True}, {'source_sha256': 'A' * 64}, {'source_sha256': '0' * 63},
            {'reason': ''}, {'reason': 'PRIVATE\nRAW'}, {'reason': 'a' * 501}, {'unexpected': True},
        ]
        for change in changes:
            with self.subTest(change=change):
                self.manifest([self.entry | change])
                result = scan.exception_summary('semgrep', self.repo, self.semgrep())
                self.assertEqual((result['status'], result['category']), ('error', 'invalid-manifest'))

    def test_duplicate_json_keys_and_bounds_are_rejected(self):
        path = self.repo / scan.EXCEPTIONS_FILE
        for text in ('{"version":1,"version":1,"exceptions":[]}', 'x' * (scan.EXCEPTIONS_BYTES + 1)):
            path.write_text(text)
            self.assertEqual(scan.exception_summary('semgrep', self.repo, [])['status'], 'error')
        with patch.object(scan, 'EXCEPTIONS_MAX', 0):
            self.manifest()
            self.assertEqual(scan.exception_summary('semgrep', self.repo, [])['status'], 'error')
        self.manifest()
        with patch.object(scan, 'EXCEPTION_SOURCE_BYTES', 1):
            self.assertEqual(scan.exception_summary('semgrep', self.repo, self.semgrep())['status'], 'error')
        with patch.object(scan, 'EXCEPTION_TOTAL_BYTES', 1):
            self.assertEqual(scan.exception_summary('semgrep', self.repo, self.semgrep())['status'], 'error')

    def test_hardlinked_source_and_manifest_are_rejected(self):
        self.manifest()
        os.link(self.source, self.repo / 'source-alias')
        self.assertEqual(scan.exception_summary('semgrep', self.repo, self.semgrep())['status'], 'error')
        (self.repo / 'source-alias').unlink()
        os.link(self.repo / scan.EXCEPTIONS_FILE, self.repo / 'manifest-alias')
        self.assertEqual(scan.exception_summary('semgrep', self.repo, self.semgrep())['category'], 'invalid-manifest')

    def test_source_file_parent_and_manifest_symlinks_fail(self):
        self.manifest()
        target = self.repo / 'retained.py'
        self.source.rename(target)
        self.source.symlink_to(target)
        self.assertEqual(scan.exception_summary('semgrep', self.repo, self.semgrep())['status'], 'error')
        self.source.unlink()
        target.rename(self.source)
        directory = self.repo / 'retained-source'
        (self.repo / 'source').rename(directory)
        (self.repo / 'source').symlink_to(directory, target_is_directory=True)
        self.assertEqual(scan.exception_summary('semgrep', self.repo, self.semgrep())['status'], 'error')
        (self.repo / 'source').unlink()
        directory.rename(self.repo / 'source')
        manifest = self.repo / scan.EXCEPTIONS_FILE
        moved = self.repo / 'retained-manifest'
        manifest.rename(moved)
        manifest.symlink_to(moved)
        self.assertEqual(scan.exception_summary('semgrep', self.repo, self.semgrep())['category'], 'invalid-manifest')

    def test_file_changed_during_fd_read_is_not_accepted(self):
        self.manifest()
        real_read = os.read
        changed = False
        def mutate(fd, maximum):
            nonlocal changed
            block = real_read(fd, maximum)
            if not changed and block.startswith(b'captured'):
                changed = True
                self.source.write_text('different source\nexec(captured)\n')
            return block
        with patch.object(scan.os, 'read', mutate):
            result = scan.exception_summary('semgrep', self.repo, self.semgrep())
        self.assertTrue(changed)
        self.assertEqual((result['status'], result['accepted_exception_count']), ('error', 0))

    def test_incomplete_scan_cannot_be_accepted(self):
        self.manifest()
        with self.assertRaises(scan.ScannerFailure) as caught:
            self.semgrep(errors=[{'type': 'PartialParsing', 'path': 'source/loader.py', 'message': 'PRIVATE_ERROR'}])
        self.assertEqual(caught.exception.category, 'incomplete-scan')

    def test_final_gate_accepts_reviewed_only_but_all_tools_still_run(self):
        self.manifest()
        accepted = scan.exception_summary('semgrep', self.repo, self.semgrep())
        for status, expected in ((accepted, 0), (accepted | {'status': 'error'}, 1)):
            calls, output = [], io.StringIO()
            def controlled(tool, *_args):
                calls.append(tool)
                return status if tool == 'semgrep' else {'tool': tool, 'status': 'clean'}
            with patch.object(scan, 'scan', controlled), patch.object(sys, 'argv', ['scan.py', str(self.repo)]), \
                    patch('sys.stdout', output):
                self.assertEqual(scan.main(), expected)
            self.assertEqual(calls, ['semgrep', 'trivy', 'gitleaks'])
            self.assertEqual(len(output.getvalue().splitlines()), 3)


if __name__ == '__main__':
    unittest.main()
