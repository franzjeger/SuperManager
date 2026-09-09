import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from validate_runtime import validate, dependency_path, REQUIRED, PREFIX

class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'runtime'
        for name in REQUIRED:
            file = self.root / name
            file.parent.mkdir(parents=True, exist_ok=True)
            if name == 'bin/wg-quick':
                data = f'#!{PREFIX}/bin/bash\nexit 0\n'.encode()
            elif name == 'etc/strongswan.conf':
                data = b'charon {}\n'
            else:
                data = b'\xcf\xfa\xed\xfe' + b'test fixture only'
            file.write_bytes(data)
            file.chmod(0o644 if name.startswith('etc/') else 0o755)
        (self.root / 'lib/ipsec/plugins').mkdir(parents=True)
        self.manifest = Path(self.tmp.name) / 'manifest.json'
        self.refresh()

    def refresh(self):
        self.manifest.write_text(json.dumps({'schema': 1, 'sources': [{
            'url': 'https://example.invalid/source', 'version': 'test',
            'sha256': 'a' * 64, 'license': 'test fixture'}], 'files': {
                p.relative_to(self.root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.root.rglob('*') if p.is_file()}}))

    def test_complete_fixture(self):
        self.assertEqual(len(validate(self.root, self.manifest, False)), 6)

    def test_changed_bytes_and_added_file_are_rejected(self):
        (self.root / 'bin/wg').write_bytes(b'changed')
        with self.assertRaises(ValueError): validate(self.root, self.manifest, False)
        self.refresh()
        (self.root / 'extra').write_text('unreviewed')
        with self.assertRaises(ValueError): validate(self.root, self.manifest, False)

    def test_symlink_and_writable_runtime_rejected(self):
        (self.root / 'link').symlink_to('/usr/bin/true')
        with self.assertRaises(ValueError): validate(self.root, self.manifest, False)
        (self.root / 'link').unlink()
        (self.root / 'bin/wg').chmod(0o777)
        with self.assertRaises(ValueError): validate(self.root, self.manifest, False)

    def test_compiled_homebrew_paths_rejected_even_with_matching_hash(self):
        (self.root / 'bin/swanctl').write_bytes(b'\xcf\xfa\xed\xfe/opt/homebrew/lib/plugin.dylib')
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'Homebrew'): validate(self.root, self.manifest, False)

    def test_missing_component_and_path_traversal(self):
        (self.root / 'sbin/openvpn').unlink()
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'Missing'): validate(self.root, self.manifest, False)
        data = json.loads(self.manifest.read_text())
        data['files']['../escape'] = '0' * 64
        self.manifest.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'Invalid manifest path'): validate(self.root, self.manifest, False)

    def test_external_and_unresolved_libraries_rejected(self):
        binary = self.root / 'bin/wg'
        for dep in ('/opt/homebrew/lib/evil.dylib', '@rpath/lib.dylib', '/tmp/evil', '@executable_path/evil', '/usr/lib/../../tmp/evil'):
            with self.assertRaises(ValueError): dependency_path(dep, binary, self.root)
        self.assertIsNone(dependency_path('/usr/lib/libSystem.B.dylib', binary, self.root))
        self.assertEqual(dependency_path(PREFIX + '/bin/wg', binary, self.root), binary.resolve())

    def test_external_interpreter_rejected(self):
        (self.root / 'bin/wg-quick').write_text('#!/usr/bin/env bash\n')
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'interpreter'): validate(self.root, self.manifest, False)

if __name__ == '__main__': unittest.main()
