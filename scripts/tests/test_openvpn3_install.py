"""An existing Homebrew OpenVPN 3 must not suppress a protected-runtime repair."""

import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class OpenVPN3InstallTests(unittest.TestCase):
    def test_explicit_repair_runs_even_with_openvpn3_on_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp)
            (checkout / "scripts").mkdir()
            (checkout / "contrib").mkdir()
            commands = checkout / "bin"
            commands.mkdir()
            shutil.copy2(ROOT / "scripts/install.sh", checkout / "scripts/install.sh")
            marker = checkout / "runtime-built"
            builder = checkout / "contrib/build-openvpn3-mac.sh"
            builder.write_text('#!/bin/bash\nprintf repaired > "$REPAIR_MARKER"\n')
            for name, body in {
                "uname": "echo Darwin",
                "id": "echo 501",
                "brew": "exit 0",
                "wg-quick": "exit 0",
                "swanctl": "exit 0",
                "openvpn": "exit 0",
                "openvpn3": "exit 0",
            }.items():
                command = commands / name
                command.write_text(f"#!/bin/sh\n{body}\n")
                command.chmod(0o755)
            env = dict(os.environ, PATH=f"{commands}:{os.environ['PATH']}",
                       REPAIR_MARKER=str(marker))
            result = subprocess.run(
                ["/bin/bash", str(checkout / "scripts/install.sh"),
                 "--yes", "--deps-only", "--with-openvpn3"],
                env=env, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(marker.is_file(), result.stdout + result.stderr)
            self.assertEqual(marker.read_text(), "repaired")

    def check_piped_repair(self, download_fails):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            commands = root / "bin"
            commands.mkdir()
            downloads = root / "downloads"
            downloads.mkdir()
            caller = root / "caller"
            (caller / "work").mkdir(parents=True)
            # This location was accidentally treated as a checkout when
            # BASH_SOURCE was empty. The piped installer must ignore it.
            (caller / "contrib").mkdir()
            (caller / "contrib/build-openvpn3-mac.sh").write_text(
                '#!/bin/bash\nprintf unrelated > "$REPAIR_MARKER"\n')
            remote_builder = root / "remote-builder.sh"
            remote_builder.write_text('#!/bin/bash\nprintf downloaded > "$REPAIR_MARKER"\n')
            archive = root / "remote.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(remote_builder, arcname="checkout/contrib/build-openvpn3-mac.sh")
            marker = root / "runtime-built"
            locations = root / "download-locations"
            for name, body in {
                "uname": "echo Darwin",
                "id": "echo 501",
                "brew": "exit 0",
                "wg-quick": "exit 0",
                "swanctl": "exit 0",
                "openvpn": "exit 0",
                "openvpn3": "exit 0",
                "curl": '''while [ "$#" -gt 0 ]; do
    if [ "$1" = -o ]; then shift; destination="$1"; fi
    shift
done
dirname "$destination" >> "$DOWNLOAD_LOCATIONS"
[ "$DOWNLOAD_FAILS" = 0 ] || exit 22
cp "$REPAIR_ARCHIVE" "$destination"''',
            }.items():
                command = commands / name
                command.write_text(f"#!/bin/sh\n{body}\n")
                command.chmod(0o755)
            env = dict(os.environ, PATH=f"{commands}:{os.environ['PATH']}",
                       TMPDIR=f"{downloads}/", REPAIR_MARKER=str(marker),
                       REPAIR_ARCHIVE=str(archive), DOWNLOAD_LOCATIONS=str(locations),
                       DOWNLOAD_FAILS=str(int(download_fails)))
            result = subprocess.run(
                ["/bin/bash", "-s", "--", "--yes", "--deps-only", "--with-openvpn3"],
                input=(ROOT / "scripts/install.sh").read_text(), cwd=caller / "work",
                env=env, capture_output=True, text=True, timeout=10,
            )
            self.assertTrue(locations.is_file(), result.stdout + result.stderr)
            for location in locations.read_text().splitlines():
                self.assertFalse(Path(location).exists(), f"temporary checkout remains: {location}")
            if download_fails:
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(marker.exists())
            else:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(marker.read_text(), "downloaded")

    def test_piped_repair_downloads_checkout_and_removes_it(self):
        self.check_piped_repair(download_fails=False)

    def test_failed_piped_download_stops_and_removes_checkout(self):
        self.check_piped_repair(download_fails=True)


if __name__ == "__main__":
    unittest.main()
