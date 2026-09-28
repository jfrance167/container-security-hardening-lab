import json
import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from container_policy import (
    PolicyInputError,
    image_is_pinned,
    main,
    render_report,
    scan_directory,
)


ROOT = Path(__file__).resolve().parents[1]
VULNERABLE = ROOT / "fixtures" / "vulnerable"
HARDENED = ROOT / "fixtures" / "hardened"


class ContainerPolicyTests(unittest.TestCase):
    def test_digest_validation(self):
        digest = "a" * 64
        self.assertTrue(image_is_pinned(f"registry.invalid/app@sha256:{digest}"))
        self.assertFalse(image_is_pinned("registry.invalid/app:latest"))

    def test_vulnerable_fixture_fails(self):
        findings = scan_directory(VULNERABLE)
        self.assertGreater(len(findings), 10)
        self.assertIn("DKR001", {finding.rule_id for finding in findings})
        self.assertIn("K8S011", {finding.rule_id for finding in findings})

    def test_hardened_fixture_passes(self):
        self.assertEqual(scan_directory(HARDENED), ())

    def test_vulnerable_fixture_detects_embedded_secret_pattern(self):
        matches = [finding for finding in scan_directory(VULNERABLE) if finding.rule_id == "DKR004"]
        self.assertEqual(len(matches), 1)

    def test_vulnerable_fixture_detects_privileged_mode(self):
        self.assertIn("K8S008", {finding.rule_id for finding in scan_directory(VULNERABLE)})

    def test_vulnerable_fixture_detects_missing_limits(self):
        self.assertIn("K8S010", {finding.rule_id for finding in scan_directory(VULNERABLE)})

    def test_report_marks_hardened_fixture_pass(self):
        report = render_report(scan_directory(HARDENED), "hardened")
        self.assertIn("Result: **PASS**", report)
        self.assertIn("No policy violations detected", report)

    def test_report_marks_vulnerable_fixture_fail(self):
        report = render_report(scan_directory(VULNERABLE), "vulnerable")
        self.assertIn("Result: **FAIL**", report)

    def test_non_directory_is_rejected(self):
        with self.assertRaises(PolicyInputError):
            scan_directory(ROOT / "missing")

    def test_invalid_json_is_rejected(self):
        path = Path(__file__).parent / "_invalid.json"
        path.write_text("{not-json", encoding="utf-8")
        self.addCleanup(path.unlink, missing_ok=True)
        with self.assertRaises(PolicyInputError):
            scan_directory(path.parent)

    def test_cli_fail_on_findings(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(VULNERABLE), "--fail-on-findings"]), 1)

    def test_cli_hardened_success(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(HARDENED), "--fail-on-findings"]), 0)

    def test_fixture_json_is_syntactically_valid(self):
        for path in (VULNERABLE.parent).rglob("*.json"):
            self.assertIsInstance(json.loads(path.read_text(encoding="utf-8")), dict)


if __name__ == "__main__":
    unittest.main()
