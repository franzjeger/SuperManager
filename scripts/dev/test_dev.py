import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from copy_data import copy_data
from prepare import transform, replace_once


class DevIsolationTests(unittest.TestCase):
    def test_namespace_replacements_do_not_cascade(self):
        self.assertEqual(transform('supermgrd-mac'), 'supermanager-dev-engine')
        self.assertEqual(transform('com.sybr.supermanager.helper'), 'com.sybr.supermanager.dev.helper')
        self.assertEqual(transform('/Library/Application Support/SuperManagerSystem'),
                         '/Library/Application Support/SuperManagerDevSystem')
        self.assertEqual(transform('/Users/test/Library/Application Support/SuperManager/profiles'),
                         '/Users/test/Library/Application Support/SuperManager Dev/profiles')

    def test_path_overload_and_interface_socket_namespace(self):
        self.assertEqual(transform('appendingPathComponent("SuperManager", isDirectory: true)'),
                         'appendingPathComponent("SuperManager Dev", isDirectory: true)')
        self.assertEqual(transform('/var/run/charon.vici'),
                         '/Library/PrivilegedHelperTools/SuperManagerDevIPSecState/charon.vici')

    def test_snapshot_is_private_independent_and_manual(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / 'stable', root / 'dev'
            source.mkdir()
            original = b'id = "same-id"\nauto_connect = true\nkill_switch = true\n'
            (source / 'profile.toml').write_bytes(original)
            (source / 'secrets.json').write_text('{"test":"c2VjcmV0"}')
            with contextlib.redirect_stdout(io.StringIO()):
                copy_data(source, destination)
            self.assertEqual((source / 'profile.toml').read_bytes(), original)
            self.assertIn('auto_connect = false', (destination / 'profile.toml').read_text())
            self.assertEqual((destination / 'secrets.json').stat().st_mode & 0o777, 0o600)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            self.assertEqual((destination / 'secrets.json').read_bytes(), (source / 'secrets.json').read_bytes())
            with self.assertRaises(ValueError):
                copy_data(source, destination)

    def test_symlink_cannot_escape_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'stable'; source.mkdir()
            (source / 'secret').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):
                copy_data(source, root / 'dev')
            self.assertFalse((root / 'dev').exists())

    def test_source_drift_fails_closed(self):
        for value in ['different', 'needle needle']:
            with self.assertRaises(ValueError):
                replace_once(value, 'needle', 'replacement')

if __name__ == '__main__':
    unittest.main()
