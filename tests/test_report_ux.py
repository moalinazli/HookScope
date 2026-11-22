"""Evidence-oriented, offline report regression tests."""
import unittest
from hookscope.report import finalize, to_html


def sample_result(*, artifacts=None, issues=None, complete=True, stats=None):
    return finalize({
        "scan_type": "snapshot", "target": "/tmp/sample", "complete": complete,
        "stats": stats if stats is not None else {"site_directories": 1, "visited_files": 16},
        "environments": [{"site_directory": "venv/lib/python3.13/site-packages",
                          "venv_prefix": "venv", "startup_artifact_count": 0}],
        "artifacts": artifacts or [], "issues": issues or []
    })


class ReportUXTests(unittest.TestCase):
    def test_empty_incomplete_report_is_not_clean_verdict(self):
        result = sample_result(complete=False, issues=[
            {"code": "symlink_directory_skipped", "path": "terminfo", "detail": "not followed"},
            {"code": "internal_symlink_alias", "path": "clang/latest", "detail": "covered in tree"}
        ])
        html = to_html(result)
        self.assertIn("Coverage limited", html)
        self.assertIn("1 coverage gaps · 1 traversal notes", html)
        self.assertIn("Nothing to triage in this scope", html)
        self.assertNotIn("clean endpoint", html.lower())
        self.assertIn('Content-Security-Policy', html)
        self.assertNotIn('<script', html)
        self.assertNotIn('<link', html)
        self.assertNotIn('<img', html)

    def test_empty_complete_report_is_not_malware_verdict(self):
        result = sample_result()
        html = to_html(result)
        self.assertIn("No startup artifacts found", html)
        self.assertIn("not proof of a clean endpoint", html)

    def test_rich_finding_includes_imports_indicators_and_hash(self):
        artifact = {"path": "venv/lib/python3.13/site-packages/inject.pth",
                    "kind": "pth", "startup_status": "candidate_executable",
                    "sha256": "a" * 64, "python_version": "3.13", "environment": "venv",
                    "severity": "high", "filesystem": {"mode": "0644"}, "errors": [],
                    "indicators": [{"code": "known_sha256", "severity": "high",
                                    "detail": "Source-attributed IOC"}],
                    "resolved_imports": [{"module": "pkg.core", "status": "resolved_in_snapshot",
                                          "candidates": ["venv/lib/python3.13/site-packages/pkg/core.py"]}],
                    "ioc_matches": [{"Campaign": "Example"}]}
        result = sample_result(artifacts=[artifact])
        html = to_html(result)
        for target in ("High-priority review", "candidate_executable", "known_sha256",
                       "pkg.core", "resolved_in_snapshot", "a" * 64):
            self.assertIn(target, html)
        self.assertIn('<details class="finding" open>', html)

    def test_untrusted_fields_do_not_insert_markup(self):
        bad = '<img src=x onerror=alert(1)>'
        result = sample_result(issues=[{"code": "bad", "path": bad, "detail": bad}])
        result["target"] = bad
        html = to_html(result)
        self.assertNotIn(bad, html)
        self.assertIn('&lt;img', html)
        self.assertNotIn('<script', html)

    def test_missing_legacy_metrics_are_explicitly_unavailable(self):
        result = sample_result(stats={"visited_files": None,"site_directories": None})
        result["environments"] = []
        result["source_note"] = "Legacy 1.1.0; no rescan performed"
        html = to_html(result)
        self.assertIn("Site-directory inventory unavailable", html)
        self.assertIn("Legacy 1.1.0; no rescan performed", html)


if __name__ == '__main__':
    unittest.main()
