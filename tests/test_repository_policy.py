import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
USE_PATTERN = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)


class RepositoryPolicyTests(unittest.TestCase):
    def test_actions_are_pinned_to_full_commit_shas(self):
        for path in WORKFLOWS.glob("*.yml"):
            text = path.read_text(encoding="utf-8")
            for action in USE_PATTERN.findall(text):
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$", f"unpinned action in {path.name}: {action}")

    def test_checkout_disables_persisted_credentials(self):
        for path in WORKFLOWS.glob("*.yml"):
            text = path.read_text(encoding="utf-8")
            if "actions/checkout@" in text:
                self.assertIn("persist-credentials: false", text, path.name)

    def test_workflows_declare_permissions(self):
        for path in WORKFLOWS.glob("*.yml"):
            self.assertIn("permissions:", path.read_text(encoding="utf-8"), path.name)

    def test_codeql_has_schedule_and_manual_dispatch(self):
        text = (WORKFLOWS / "codeql.yml").read_text(encoding="utf-8")
        self.assertIn("schedule:", text)
        self.assertIn("workflow_dispatch:", text)

    def test_bandit_has_manual_dispatch(self):
        text = (WORKFLOWS / "bandit.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", text)


if __name__ == "__main__":
    unittest.main()
