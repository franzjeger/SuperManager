"""Tests for scripts/update-linux.sh: signed annotated release tags, untagged
branch commits ignored, moved/unsigned/wrong-signer tags rejected, and
tag-archived staging immune to working-tree tampering."""

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).parents[1] / "update-linux.sh"

ENV = dict(
    os.environ,
    GIT_CONFIG_COUNT="2",
    GIT_CONFIG_KEY_0="maintenance.auto",
    GIT_CONFIG_VALUE_0="false",
    GIT_CONFIG_KEY_1="gc.auto",
    GIT_CONFIG_VALUE_1="0",
)


def git(cwd, *args):
    return subprocess.run(
        ["git", "-c", "user.name=test", "-c", "user.email=test@example.com", *args],
        cwd=cwd,
        env=ENV,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


class UpdateLinuxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.root = root
        self.seed = root / "seed"
        self.origin = root / "origin.git"
        self.checkout = root / "checkout"

        self.signing_key = root / "release_ed25519"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.signing_key)],
            check=True,
        )
        pubkey = (root / "release_ed25519.pub").read_text().strip()
        self.signers = root / "release-signers"
        self.signers.write_text(f'test@example.com namespaces="git" {pubkey}\n')

        self.seed.mkdir()
        git(self.seed, "init", "-q", "-b", "main")
        (self.seed / "Cargo.toml").write_text("[workspace]\n")
        (self.seed / "scripts").mkdir()
        (self.seed / "scripts" / "install-linux.sh").write_text("#!/usr/bin/env bash\necho clean\n")
        (self.seed / "contrib").mkdir()
        (self.seed / "contrib" / "release-signers").write_text(self.signers.read_text())
        git(self.seed, "add", "Cargo.toml", "scripts/install-linux.sh", "contrib/release-signers")
        git(self.seed, "commit", "-q", "-m", "first")
        self.sign_tag(self.seed, "v1.0.0")

        git(root, "clone", "-q", "--bare", str(self.seed), str(self.origin))
        git(self.origin, "config", "receive.autogc", "false")
        git(self.seed, "remote", "add", "origin", str(self.origin))
        git(root, "clone", "-q", str(self.origin), str(self.checkout))

    def tearDown(self):
        self.tmp.cleanup()

    def sign_tag(self, repo, tag_name, key_path=None):
        key = key_path or self.signing_key
        git(
            repo,
            "-c",
            "gpg.format=ssh",
            "-c",
            f"user.signingkey={key}",
            "tag",
            "-s",
            "-m",
            f"release {tag_name}",
            tag_name,
        )

    def run_updater(self, *args, extra_env=None):
        env = dict(
            ENV,
            SUPERMGR_CHECKOUT=str(self.checkout),
            SUPERMGR_TAG_SIGNERS=str(self.signers),
        )
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            env=env,
            capture_output=True,
            text=True,
        )

    def test_signed_release_tag_reports_update_and_ignores_untagged_main_commits(self):
        git(self.seed, "commit", "-q", "--allow-empty", "-m", "release change")
        self.sign_tag(self.seed, "v1.1.0")
        git(self.seed, "commit", "-q", "--allow-empty", "-m", "untagged main commit")
        git(self.seed, "push", "-q", "origin", "main", "v1.1.0")

        result = self.run_updater("--check")

        self.assertEqual(result.returncode, 10, result.stderr)
        self.assertIn("1 new commit(s) in verified release v1.1.0", result.stdout)
        self.assertNotIn("untagged main commit", result.stdout)

    def test_untagged_commits_alone_do_not_trigger_update(self):
        git(self.seed, "commit", "-q", "--allow-empty", "-m", "untagged work")
        git(self.seed, "push", "-q", "origin", "main")

        result = self.run_updater("--check")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("up to date at verified release v1.0.0", result.stdout)

    def test_unsigned_annotated_release_tag_is_rejected(self):
        git(self.seed, "commit", "-q", "--allow-empty", "-m", "unsigned release")
        git(self.seed, "tag", "-a", "-m", "unsigned", "v1.2.0")
        git(self.seed, "push", "-q", "origin", "main", "v1.2.0")

        result = self.run_updater("--check")

        self.assertEqual(result.returncode, 1)
        self.assertIn("signature verification failed for release tag v1.2.0", result.stderr)

    def test_tag_signed_by_untrusted_key_is_rejected(self):
        rogue_key = self.root / "rogue_ed25519"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(rogue_key)],
            check=True,
        )
        git(self.seed, "commit", "-q", "--allow-empty", "-m", "rogue release")
        self.sign_tag(self.seed, "v1.2.0", key_path=rogue_key)
        git(self.seed, "push", "-q", "origin", "main", "v1.2.0")

        result = self.run_updater("--check")

        self.assertEqual(result.returncode, 1)
        self.assertIn("signature verification failed for release tag v1.2.0", result.stderr)

    def test_moved_release_tag_is_refused_unless_explicitly_allowed(self):
        git(self.seed, "commit", "-q", "--allow-empty", "-m", "retagged")
        git(self.seed, "tag", "-d", "v1.0.0")
        self.sign_tag(self.seed, "v1.0.0")
        git(self.seed, "push", "-q", "--force", "origin", "main", "v1.0.0")

        denied = self.run_updater("--check")
        self.assertEqual(denied.returncode, 1)
        self.assertIn("git fetch from origin failed", denied.stderr)

        allowed = self.run_updater("--check", "--allow-moved-tags")
        self.assertEqual(allowed.returncode, 10, allowed.stderr)

    def test_more_than_ten_new_commits_lists_ten_and_carries_on(self):
        for i in range(40):
            git(self.seed, "commit", "-q", "--allow-empty", "-m", f"new {i}")
        self.sign_tag(self.seed, "v1.1.0")
        git(self.seed, "push", "-q", "origin", "main", "v1.1.0")

        result = self.run_updater("--check")

        self.assertEqual(result.returncode, 10, result.stderr)
        self.assertIn("40 new commit(s)", result.stdout)
        self.assertIn("and 30 more", result.stdout)

    def test_a_fetch_that_fails_says_why_instead_of_guessing(self):
        git(self.checkout, "remote", "set-url", "origin", f"{self.origin}-missing")

        result = self.run_updater("--check")

        self.assertEqual(result.returncode, 1)
        self.assertIn("git fetch from origin failed", result.stderr)
        self.assertNotIn("no network", result.stderr)
        self.assertIn("-missing", result.stderr)

    def test_staging_extracts_verified_tag_archive_instead_of_dirty_working_tree(self):
        build_dir = self.root / "target"
        (build_dir / "release").mkdir(parents=True)
        for name in ("supermgrd", "supermgr", "supermgr-mcp"):
            bin_path = build_dir / "release" / name
            bin_path.write_text(f"binary-{name}\n")
            bin_path.chmod(0o755)

        # Tamper with the working tree's install script after checkout: staging
        # must extract scripts/install-linux.sh from the verified Git tag, not
        # copy the modified file from $CHECKOUT.
        (self.checkout / "scripts" / "install-linux.sh").write_text("#!/usr/bin/env bash\necho PWNED\n")

        stage_dest = self.root / "staged"
        result = self.run_updater(
            "--force",
            "--yes",
            extra_env={
                "CARGO_TARGET_DIR": str(build_dir),
                "SUPERMGR_TEST_SKIP_BUILD": "1",
                "SUPERMGR_TEST_STAGE_DEST": str(stage_dest),
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(stage_dest.stat().st_mode), 0o700)
        staged_installer = (stage_dest / "scripts" / "install-linux.sh").read_text()
        self.assertIn("echo clean", staged_installer)
        self.assertNotIn("PWNED", staged_installer)
        for name in ("supermgrd", "supermgr", "supermgr-mcp"):
            self.assertEqual(
                (stage_dest / "target" / "release" / name).read_text(),
                f"binary-{name}\n",
            )


if __name__ == "__main__":
    unittest.main()
