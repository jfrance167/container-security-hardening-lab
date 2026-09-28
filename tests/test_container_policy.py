import json
import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from container_policy import (
    PolicyInputError,
    Finding,
    image_is_pinned,
    main,
    render_report,
    scan_directory,
    scan_dockerfile,
    scan_workload,
    _is_default_deny,
)


ROOT = Path(__file__).resolve().parents[1]
VULNERABLE = ROOT / "fixtures" / "vulnerable"
HARDENED = ROOT / "fixtures" / "hardened"


class ContainerPolicyTests(unittest.TestCase):
    def dockerfile(self, name, content):
        path = Path(__file__).parent / name
        path.write_text(content, encoding="utf-8")
        self.addCleanup(path.unlink, missing_ok=True)
        return path

    def hardened_deployment(self):
        return json.loads((HARDENED / "deployment.json").read_text(encoding="utf-8"))

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

    def test_final_docker_stage_must_declare_non_root_user(self):
        digest = "a" * 64
        path = self.dockerfile(
            "_Dockerfile.multistage",
            f"FROM build@sha256:{digest}\nUSER 65532\nFROM runtime@sha256:{digest}\nHEALTHCHECK CMD true\n",
        )
        rules = {finding.rule_id for finding in scan_dockerfile(path, path.parent)}
        self.assertIn("DKR002", rules)

    def test_root_user_with_non_root_group_is_rejected(self):
        digest = "a" * 64
        path = self.dockerfile(
            "_Dockerfile.root-group",
            f"FROM runtime@sha256:{digest}\nUSER 0:65532\nHEALTHCHECK CMD true\n",
        )
        self.assertIn("DKR002", {finding.rule_id for finding in scan_dockerfile(path, path.parent)})

    def test_root_uid_alternate_spelling_is_rejected(self):
        digest = "a" * 64
        path = self.dockerfile(
            "_Dockerfile.zero-padded-root",
            f"FROM runtime@sha256:{digest}\nUSER 00:65532\nHEALTHCHECK CMD true\n",
        )
        self.assertIn("DKR002", {finding.rule_id for finding in scan_dockerfile(path, path.parent)})

    def test_variable_runtime_user_is_not_assumed_non_root(self):
        digest = "a" * 64
        path = self.dockerfile(
            "_Dockerfile.variable-user",
            f"FROM runtime@sha256:{digest}\nUSER ${{USER_ID}}\nHEALTHCHECK CMD true\n",
        )
        self.assertIn("DKR002", {finding.rule_id for finding in scan_dockerfile(path, path.parent)})

    def test_healthcheck_none_is_rejected(self):
        digest = "a" * 64
        path = self.dockerfile(
            "_Dockerfile.health-none",
            f"FROM runtime@sha256:{digest}\nUSER 65532\nHEALTHCHECK NONE\n",
        )
        self.assertIn("DKR003", {finding.rule_id for finding in scan_dockerfile(path, path.parent)})

    def test_continued_user_and_healthcheck_are_interpreted_logically(self):
        digest = "a" * 64
        continuation = "\\"
        path = self.dockerfile(
            "_Dockerfile.continued",
            f"FROM runtime@sha256:{digest}\nUSER {continuation}\n0\n"
            f"HEALTHCHECK  {continuation}\nNONE\n",
        )
        rules = {finding.rule_id for finding in scan_dockerfile(path, path.parent)}
        self.assertIn("DKR002", rules)
        self.assertIn("DKR003", rules)

    def test_healthcheck_none_with_extra_whitespace_is_rejected(self):
        digest = "a" * 64
        path = self.dockerfile(
            "_Dockerfile.health-spacing",
            f"FROM runtime@sha256:{digest}\nUSER 65532\nHEALTHCHECK  NONE\n",
        )
        self.assertIn("DKR003", {finding.rule_id for finding in scan_dockerfile(path, path.parent)})

    def test_all_env_assignment_forms_are_scanned(self):
        digest = "a" * 64
        path = self.dockerfile(
            "_Dockerfile.secrets",
            f"FROM runtime@sha256:{digest}\nENV SAFE=x API_TOKEN=hardcoded\nENV PASSWORD legacy-value\nUSER 65532\nHEALTHCHECK CMD true\n",
        )
        matches = [finding for finding in scan_dockerfile(path, path.parent) if finding.rule_id == "DKR004"]
        self.assertEqual(len(matches), 2)

    def test_continued_env_assignments_are_scanned(self):
        digest = "a" * 64
        continuation = "\\"
        path = self.dockerfile(
            "_Dockerfile.continued-env",
            f"FROM runtime@sha256:{digest}\nENV SAFE=x {continuation}\n"
            "API_TOKEN=hardcoded\nUSER 65532\nHEALTHCHECK CMD true\n",
        )
        self.assertIn("DKR004", {finding.rule_id for finding in scan_dockerfile(path, path.parent)})

    def test_container_security_overrides_cannot_defeat_pod_defaults(self):
        document = self.hardened_deployment()
        security = document["spec"]["template"]["spec"]["containers"][0]["securityContext"]
        security.update({"runAsNonRoot": False, "runAsUser": 0, "seccompProfile": {"type": "Unconfined"}})
        rules = {finding.rule_id for finding in scan_workload(document, "deployment.json")}
        self.assertIn("K8S001", rules)
        self.assertIn("K8S002", rules)

    def test_init_containers_receive_all_container_checks(self):
        document = self.hardened_deployment()
        pod_spec = document["spec"]["template"]["spec"]
        pod_spec["initContainers"] = [
            {
                "name": "setup",
                "image": "example.invalid/setup:latest",
                "securityContext": {
                    "privileged": True,
                    "runAsNonRoot": False,
                    "runAsUser": 0,
                    "seccompProfile": {"type": "Unconfined"},
                },
            }
        ]
        findings = scan_workload(document, "deployment.json")
        init_rules = {finding.rule_id for finding in findings if "initContainers/setup" in finding.artifact}
        self.assertTrue({"K8S001", "K8S002", "K8S005", "K8S006", "K8S007", "K8S008", "K8S009", "K8S010"}.issubset(init_rules))

    def test_ephemeral_containers_receive_all_container_checks(self):
        document = self.hardened_deployment()
        pod_spec = document["spec"]["template"]["spec"]
        pod_spec["ephemeralContainers"] = [
            {
                "name": "debug",
                "image": "example.invalid/debug:latest",
                "securityContext": {"privileged": True, "runAsUser": 0},
            }
        ]
        findings = scan_workload(document, "deployment.json")
        ephemeral_rules = {finding.rule_id for finding in findings if "ephemeralContainers/debug" in finding.artifact}
        self.assertTrue({"K8S001", "K8S005", "K8S006", "K8S007", "K8S008", "K8S009", "K8S010"}.issubset(ephemeral_rules))

    def test_container_level_secure_settings_can_supply_missing_pod_defaults(self):
        document = self.hardened_deployment()
        pod_spec = document["spec"]["template"]["spec"]
        pod_spec["securityContext"] = {}
        security = pod_spec["containers"][0]["securityContext"]
        security.update({"runAsNonRoot": True, "runAsUser": 65532, "seccompProfile": {"type": "RuntimeDefault"}})
        rules = {finding.rule_id for finding in scan_workload(document, "deployment.json")}
        self.assertNotIn("K8S001", rules)
        self.assertNotIn("K8S002", rules)

    def test_markdown_table_cells_are_escaped(self):
        finding = Finding("TEST", "high", "bad|cell\nnext", "message", "fix")
        report = render_report([finding], "target`name")
        self.assertIn("bad\\|cell next", report)
        self.assertIn("Target: `` target`name ``", report)

    def test_malformed_network_policy_does_not_count_as_default_deny(self):
        document = {
            "kind": "NetworkPolicy",
            "spec": {
                "podSelector": {},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": {},
                "egress": "",
            },
        }
        self.assertFalse(_is_default_deny(document))

    def test_root_scan_target_symlink_is_rejected(self):
        with patch("container_policy.Path.is_symlink", return_value=True):
            with self.assertRaises(PolicyInputError):
                scan_directory(HARDENED)

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
