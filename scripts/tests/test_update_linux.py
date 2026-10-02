"""scripts/update-linux.sh against a throwaway origin: a tag that origin has
moved must not stop an update, and a fetch that really fails must say why."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).parents[1] / "update-linux.sh"


def git(cwd, *args):
    return subprocess.run(
        ["git", "-c", "user.name=test", "-c", "user.email=test@example.com", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


class UpdateLinuxFetchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.seed = root / "seed"
        self.origin = root / "origin.git"
        self.checkout = root / "checkout"
        self.seed.mkdir()
        git(self.seed, "init", "-q", "-b", "main")
        (self.seed / "Cargo.toml").write_text("[workspace]\n")
        git(self.seed, "add", "Cargo.toml")
        git(self.seed, "commit", "-q", "-m", "first")
        git(self.seed, "tag", "v1.0")
        git(self.seed, "commit", "-q", "--allow-empty", "-m", "second")
        git(root, "clone", "-q", "--bare", str(self.seed), str(self.origin))
        git(self.seed, "remote", "add", "origin", str(self.origin))
        git(root, "clone", "-q", str(self.origin), str(self.checkout))

    def tearDown(self):
        self.tmp.cleanup()

    def check(self):
        env = dict(os.environ, SUPERMGR_CHECKOUT=str(self.checkout))
        return subprocess.run(
            ["bash", str(SCRIPT), "--check"], env=env, capture_output=True, text=True
        )

    def test_a_tag_origin_has_moved_does_not_stop_the_update(self):
        # Origin re-points v1.0, the way v1.8.0 was re-pointed four times, and
        # gains a commit. The checkout still holds the old v1.0.
        git(self.seed, "tag", "-f", "v1.0", "HEAD")
        git(self.seed, "commit", "-q", "--allow-empty", "-m", "third")
        git(self.seed, "push", "-q", "--force", "origin", "main", "v1.0")

        result = self.check()

        self.assertEqual(result.returncode, 10, result.stderr)  # behind: update available
        self.assertEqual(
            git(self.checkout, "rev-parse", "v1.0^{commit}"),
            git(self.seed, "rev-parse", "v1.0^{commit}"),
        )

    def test_more_than_ten_new_commits_lists_ten_and_carries_on(self):
        # The list was `git log | head -10`: head closed the pipe, git log died
        # of SIGPIPE, and pipefail ended the script with 141, silently.
        for i in range(40):
            git(self.seed, "commit", "-q", "--allow-empty", "-m", f"new {i}")
        git(self.seed, "push", "-q", "origin", "main")

        result = self.check()

        self.assertEqual(result.returncode, 10, result.stderr)
        self.assertIn("40 new commit(s)", result.stdout)
        self.assertIn("and 30 more", result.stdout)

    def test_a_fetch_that_fails_says_why_instead_of_guessing(self):
        git(self.checkout, "remote", "set-url", "origin", f"{self.origin}-missing")

        result = self.check()

        self.assertEqual(result.returncode, 1)
        self.assertIn("git fetch from origin failed", result.stderr)
        self.assertNotIn("no network", result.stderr)
        self.assertIn("-missing", result.stderr)  # git's own message, naming the remote


if __name__ == "__main__":
    unittest.main()
