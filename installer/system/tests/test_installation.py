"""Exercise the actual transaction scripts with isolated paths and mocked launchd.
No root execution, system writes, signing or live networking occurs.
"""
import os
import hashlib
import platform
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'

class InstallationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sm-install-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.mock = self.root / 'mock'; self.mock.mkdir()
        self.base = self.root / 'Library/Application Support/SuperManagerSystem'
        self.payload = self.base / 'releases/20'; self.payload.mkdir(parents=True)
        self.helper = self.root / 'Library/PrivilegedHelperTools/com.sybr.supermanager.helper'
        self.runtime = self.helper.parent / 'SuperManagerVPN'
        self.plist = self.root / 'Library/LaunchDaemons/com.sybr.supermanager.helper.plist'
        self.helper.parent.mkdir(parents=True); self.plist.parent.mkdir(parents=True)
        self.write(self.payload / 'helper', 'new helper')
        self.write(self.payload / 'runtime/bin/wg', 'new runtime')
        self.write(self.payload / 'helper.plist', 'new plist')
        self.write(self.mock / 'codesign', '#!/bin/bash\nexit 0\n', 0o755)
        self.write(self.mock / 'launchctl', f'''#!/bin/bash
if [[ "$1" == bootstrap && -e '{self.root}/fail-once' ]]; then
    rm '{self.root}/fail-once'; exit 1
fi
if [[ "$1" == bootout && -e '{self.root}/kill-once' ]]; then
    rm '{self.root}/kill-once'; kill -KILL "$PPID"; exit 0
fi
[[ "$1" != print ]] || echo 'state = running'
exit 0
''', 0o755)
        self.socket_path = self.root / 'helper.sock'
        self.sock = socket.socket(socket.AF_UNIX); self.sock.bind(str(self.socket_path))
        self.addCleanup(self.sock.close)
        self.post = self.root / 'postinstall'
        self.write(self.post, self.render('postinstall'), 0o755)
        self.write(self.payload / 'recovery.sh', self.render('recovery.sh'), 0o755)
        entries = sorted(p for p in self.payload.rglob('*') if p.is_file())
        self.write(self.payload / 'payload.sha256', ''.join(
            hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.relative_to(self.payload).as_posix() + '\n'
            for p in entries))

    def render(self, name):
        s = (SCRIPTS / name).read_text().replace('@BUILD@', '20').replace('@ARCH@', platform.machine())
        s = s.replace('/Library/', str(self.root) + '/Library/')
        s = s.replace('/var/run/com.sybr.supermanager.helper.sock', str(self.socket_path))
        s = s.replace('export PATH=/usr/bin:/bin:/usr/sbin:/sbin', f'export PATH="{self.mock}:/usr/bin:/bin:/usr/sbin:/sbin"')
        s = s.replace('[[ "${3:-}" == / && $EUID == 0 ]] || exit 1', '[[ "${3:-}" == / ]] || exit 1')
        s = s.replace('[[ $EUID == 0 ]] || exit 1', ': # root identity mocked by unprivileged fixture')
        return s

    def write(self, path, text, mode=0o600):
        path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text); path.chmod(mode)

    def old_installation(self):
        self.write(self.helper, 'old helper')
        self.write(self.runtime / 'bin/wg', 'old runtime')
        self.write(self.plist, 'old plist')
        self.write(self.base / 'build', '10\n')

    def run_post(self):
        return subprocess.run(['/bin/bash', str(self.post), 'package', '/', '/'], capture_output=True, text=True, timeout=10)

    def assert_old(self):
        self.assertEqual(self.helper.read_text(), 'old helper')
        self.assertEqual((self.runtime / 'bin/wg').read_text(), 'old runtime')
        self.assertEqual(self.plist.read_text(), 'old plist')
        self.assertEqual((self.base / 'build').read_text(), '10\n')
        self.assertFalse((self.base / 'pending').exists())

    def test_fresh_install_commits_pair_and_counter(self):
        result = self.run_post(); self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.helper.read_text(), 'new helper')
        self.assertEqual((self.runtime / 'bin/wg').read_text(), 'new runtime')
        self.assertEqual((self.base / 'build').read_text(), '20\n')
        self.assertFalse((self.base / 'pending').exists())

    def test_activation_failure_restores_previous_pair(self):
        self.old_installation(); self.write(self.root / 'fail-once', '')
        self.assertNotEqual(self.run_post().returncode, 0)
        self.assert_old()

    def test_interrupted_install_has_recoverable_journal(self):
        self.old_installation(); self.write(self.root / 'kill-once', '')
        self.assertNotEqual(self.run_post().returncode, 0)
        self.assertTrue((self.base / 'pending').is_file())
        recovery = self.base / 'backup-20/recovery.sh'
        result = subprocess.run(['/bin/bash', str(recovery)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_old()

    def test_signature_failure_changes_no_installed_files(self):
        self.old_installation(); self.write(self.mock / 'codesign', '#!/bin/bash\nexit 1\n', 0o755)
        self.assertNotEqual(self.run_post().returncode, 0)
        self.assert_old()

    def test_concurrent_installer_and_late_downgrade_cannot_publish(self):
        self.old_installation()
        lock = self.base / 'install.lock'; lock.mkdir()
        self.assertNotEqual(self.run_post().returncode, 0)
        self.assert_old(); lock.rmdir()
        self.write(self.base / 'build', '25')
        self.assertNotEqual(self.run_post().returncode, 0)
        self.assertEqual(self.helper.read_text(), 'old helper')
        self.assertEqual((self.base / 'build').read_text(), '25')

    def test_payload_tampering_changes_no_installed_files(self):
        self.old_installation()
        self.write(self.payload / 'runtime/bin/wg', 'tampered')
        self.assertNotEqual(self.run_post().returncode, 0)
        self.assert_old()

    def run_pre(self):
        # Mock root identity and process inventory, retain actual mode/path checks.
        self.write(self.mock / 'stat', '#!/bin/bash\nif [[ "$2" == %u ]]; then echo 0; else exec /usr/bin/stat "$@"; fi\n', 0o755)
        self.write(self.mock / 'pgrep', '#!/bin/bash\nexit 1\n', 0o755)
        script = (SCRIPTS / 'preinstall').read_text().replace('@BUILD@', '20').replace('@ARCH@', platform.machine())
        script = script.replace('/Library', str(self.root) + '/Library')
        script = script.replace('export PATH=/usr/bin:/bin:/usr/sbin:/sbin', f'export PATH="{self.mock}:/usr/bin:/bin:/usr/sbin:/sbin"')
        script = script.replace('$EUID == 0', '1 == 1')
        pre = self.root / 'preinstall'; self.write(pre, script, 0o755)
        return subprocess.run(['/bin/bash', str(pre), 'package', '/', '/'], capture_output=True, text=True, timeout=10)

    def test_downgrade_and_same_build_are_rejected(self):
        self.old_installation()
        for number in ('20', '25'):
            self.write(self.base / 'build', number)
            result = self.run_pre()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Downgrade', result.stderr)
        self.write(self.base / 'build', '10')
        result = self.run_pre(); self.assertEqual(result.returncode, 0, result.stderr)

    def test_legacy_and_interrupted_state_cannot_be_silently_adopted(self):
        self.old_installation(); (self.base / 'build').unlink()
        result = self.run_pre(); self.assertNotEqual(result.returncode, 0)
        self.assertIn('Legacy', result.stderr)
        self.write(self.base / 'pending', 'interrupted')
        result = self.run_pre(); self.assertNotEqual(result.returncode, 0)
        self.assertIn('interrupted', result.stderr)

if __name__ == '__main__': unittest.main()
