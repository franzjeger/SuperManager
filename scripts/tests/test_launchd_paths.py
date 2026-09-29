"""The boot-time DNS cleanup runs the privileged helper, so it must name
the path the app installs the helper at. A LaunchDaemon that names any
other path never runs, and nothing reports it."""

from pathlib import Path
import plistlib
import re
import unittest

ROOT = Path(__file__).parents[2]


def installed_helper():
    """`HelperInstaller.systemBinaryPath`: where the app puts the helper."""
    source = (ROOT / "SuperManagerMac/SuperManagerMac/Services/HelperInstaller.swift").read_text()
    match = re.search(r'systemBinaryPath\s*=\s*"([^"]+)"', source)
    assert match, "HelperInstaller.systemBinaryPath not found"
    return match.group(1)


class LaunchdPathTests(unittest.TestCase):
    def test_the_dns_cleanup_daemon_runs_the_installed_helper(self):
        plist = plistlib.loads(
            (ROOT / "supermanager-helper/resources/no.sybr.supermanager.vpn-dns-cleanup.plist").read_bytes()
        )
        self.assertEqual(plist["ProgramArguments"], [installed_helper(), "vpn-dns-cleanup"])

    def test_the_package_looks_for_the_same_helper(self):
        script = (ROOT / "installer/pkg/scripts/postinstall").read_text()
        self.assertIn(f'HELPER="{installed_helper()}"', script)


if __name__ == "__main__":
    unittest.main()
