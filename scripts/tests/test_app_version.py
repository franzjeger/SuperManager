"""scripts/app-version.sh against throwaway repositories: the version a Mac
build carries, which is what Sparkle compares with the latest release."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).parents[1] / "app-version.sh"


def git(cwd, *args):
    return subprocess.run(
        ["git", "-c", "user.name=test", "-c", "user.email=test@example.com", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


class AppVersionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        git(self.repo, "init", "-q", "-b", "main")
        self.commit("first")

    def tearDown(self):
        self.tmp.cleanup()

    def commit(self, message):
        git(self.repo, "commit", "-q", "--allow-empty", "-m", message)

    def version(self, **env):
        environ = {k: v for k, v in os.environ.items() if k != "SUPERMANAGER_VERSION"}
        environ.update(env)
        return subprocess.run(
            ["bash", str(SCRIPT), str(self.repo)],
            env=environ,
            capture_output=True,
            text=True,
        )

    def assertVersion(self, expected, **env):
        result = self.version(**env)
        self.assertEqual((result.returncode, result.stdout), (0, expected + "\n"), result.stderr)

    def test_a_tagged_release_is_its_tag(self):
        git(self.repo, "tag", "-a", "v1.8.13", "-m", "release")
        self.assertVersion("1.8.13")

    def test_a_build_past_a_release_counts_its_commits(self):
        # What `main` is right after a release: the tag, then the appcast
        # commit. 1.8.13.1 sorts after 1.8.13, so Sparkle leaves it alone.
        git(self.repo, "tag", "-a", "v1.8.13", "-m", "release")
        self.commit("publish appcast")
        self.commit("next fix")
        self.assertVersion("1.8.13.2")

    def test_lightweight_tags_count_too(self):
        git(self.repo, "tag", "v2.0.0")
        self.commit("after")
        self.assertVersion("2.0.0.1")

    def test_pre_release_and_archive_tags_are_not_releases(self):
        git(self.repo, "tag", "v1.8.12")
        self.commit("work")
        git(self.repo, "tag", "v1.9.0-rc1")
        git(self.repo, "tag", "archive/2026-09-19/old-branch")
        self.assertVersion("1.8.12.1")

    def test_an_explicit_version_wins(self):
        # release.sh builds before it tags; the version it releases is given.
        git(self.repo, "tag", "v1.8.12")
        self.commit("release commit")
        self.assertVersion("1.8.13", SUPERMANAGER_VERSION="1.8.13")

    def test_no_release_tag_says_nothing(self):
        # A shallow CI checkout: the caller keeps project.yml's version.
        result = self.version()
        self.assertEqual((result.returncode, result.stdout), (1, ""))

    def test_no_git_says_nothing(self):
        with tempfile.TemporaryDirectory() as plain:
            result = subprocess.run(
                ["bash", str(SCRIPT), plain],
                env={k: v for k, v in os.environ.items() if k != "SUPERMANAGER_VERSION"},
                capture_output=True,
                text=True,
            )
        self.assertEqual((result.returncode, result.stdout), (1, ""))


if __name__ == "__main__":
    unittest.main()
