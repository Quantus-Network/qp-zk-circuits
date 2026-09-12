import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("release-version.sh").resolve()
PREFIX = "ci: Automate workspace version bump to "


class ReleaseVersionTests(unittest.TestCase):
    def run_title(self, title, draft="false"):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            result = subprocess.run(
                ["bash", str(SCRIPT)],
                cwd=directory,
                env=dict(os.environ, PR_TITLE=title, IS_DRAFT=draft, GITHUB_OUTPUT=str(output)),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertFalse((Path(directory) / "injected").exists())
            return result, output.read_text() if output.exists() else ""

    def test_valid_releases(self):
        for version in ("v0.0.0", "v4.4.1", "v123.456.789"):
            for draft in ("true", "false"):
                with self.subTest(version=version, draft=draft):
                    result, output = self.run_title(PREFIX + version, draft)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(output, f"version={version}\nis_draft={draft}\n")

    def test_rejects_invalid_and_executable_titles(self):
        for title in (
            "", "v4.4.1", PREFIX + "v04.4.1", PREFIX + "v4.4.1 v4.4.2",
            PREFIX + "v4.4.1\nversion=v9.9.9", PREFIX + "v4.4.1\n",
            PREFIX + "v4.4.1 $(touch injected)",
            PREFIX + "v4.4.1 `touch injected`",
            PREFIX + 'v4.4.1"; touch injected; #',
        ):
            with self.subTest(title=title):
                result, output = self.run_title(title)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Invalid release proposal title", result.stderr)
                self.assertEqual(output, "")

    def test_rejects_invalid_draft_flag(self):
        result, output = self.run_title(PREFIX + "v4.4.1", "true\nversion=v9.9.9")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid draft-release flag", result.stderr)
        self.assertEqual(output, "")


if __name__ == "__main__":
    unittest.main()
