#!/usr/bin/env python3
"""Validate a prepared, self-contained macOS runtime. Never install or execute it."""
import hashlib
import json
import os
import posixpath
import platform
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

PREFIX = '/Library/PrivilegedHelperTools/SuperManagerVPN'
REQUIRED = ('bin/bash', 'bin/wg', 'bin/wg-quick', 'bin/wireguard-go',
            'sbin/openvpn', 'bin/swanctl', 'libexec/ipsec/charon',
            'etc/strongswan.conf')
MACHO = (b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf',
         b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca')


def relative_path(value):
    p = PurePosixPath(value)
    if not re.fullmatch(r'[A-Za-z0-9._/@-]+', value) or p.is_absolute() or '..' in p.parts or str(p) != value:
        raise ValueError(f'Invalid manifest path: {value!r}')
    return p


def dependency_path(value, binary, root):
    if value.startswith('/') and posixpath.normpath(value) != value:
        raise ValueError(f'Non-canonical dependency path: {value}')
    if value.startswith(('/usr/lib/', '/System/Library/')):
        return None
    if value.startswith(PREFIX + '/'):
        candidate = root / value[len(PREFIX) + 1:]
    elif value.startswith('@loader_path/'):
        candidate = binary.parent / value[len('@loader_path/'):]
    else:
        raise ValueError(f'Unresolved or external dependency: {value}')
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        raise ValueError(f'Dependency escapes runtime: {value}')
    return resolved


def validate(root, manifest, inspect_loads=True):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Runtime must be a real directory')
    if root.stat().st_mode & 0o022:
        raise ValueError('Group/world-writable runtime root')
    data = json.loads(Path(manifest).read_text())
    if data.get('schema') != 1 or not isinstance(data.get('files'), dict):
        raise ValueError('Unsupported runtime manifest')
    # This records provenance; reviewers must establish that the sources are trusted.
    if not data.get('sources'):
        raise ValueError('Source URLs, versions, archive hashes and licenses are required')
    for source in data['sources']:
        if (not all(source.get(k) for k in ('url', 'version', 'sha256', 'license'))
                or not source['url'].startswith('https://')
                or not re.fullmatch('[a-f0-9]{64}', source['sha256'])):
            raise ValueError('Invalid source provenance')
    expected = {str(relative_path(p)): digest for p, digest in data['files'].items()}
    found = {}
    binaries = []
    total = 0
    for p in root.rglob('*'):
        meta = p.lstat()
        if stat.S_ISLNK(meta.st_mode) or not (stat.S_ISDIR(meta.st_mode) or stat.S_ISREG(meta.st_mode)):
            raise ValueError(f'Symlink or special file: {p}')
        if meta.st_mode & 0o022:
            raise ValueError(f'Group/world-writable runtime entry: {p}')
        if p.is_dir():
            continue
        total += meta.st_size
        if total > 512 * 1024 * 1024 or len(found) >= 10000:
            raise ValueError('Runtime exceeds size/count limit')
        blob = p.read_bytes()
        rel = p.relative_to(root).as_posix()
        found[rel] = hashlib.sha256(blob).hexdigest()
        # Catch compiled plugin/config paths in addition to Mach-O load commands.
        if any(x in blob for x in (b'/opt/homebrew/', b'/usr/local/', b'/Cellar/')):
            raise ValueError(f'Runtime retains a Homebrew/local build path: {rel}; rebuild for {PREFIX}')
        if blob[:4] in MACHO:
            binaries.append(p)
            if inspect_loads:
                architectures = subprocess.check_output(['/usr/bin/lipo', '-archs', str(p)], text=True).split()
                if architectures != [platform.machine()]:
                    raise ValueError(f'Runtime architecture must match build host: {rel}')
                output = subprocess.check_output(['/usr/bin/otool', '-l', str(p)], text=True)
                command = ''
                for line in output.splitlines():
                    line = line.strip()
                    if line.startswith('cmd '):
                        command = line[4:]
                    if line.startswith('name ') and command in {
                            'LC_LOAD_DYLIB', 'LC_LOAD_WEAK_DYLIB', 'LC_REEXPORT_DYLIB',
                            'LC_LOAD_UPWARD_DYLIB', 'LC_LAZY_LOAD_DYLIB'}:
                        dependency_path(line[5:].rsplit(' (offset ', 1)[0], p, root)
                    if command == 'LC_RPATH' and line.startswith('path '):
                        raise ValueError(f'LC_RPATH is unsupported; use explicit protected load paths: {rel}')
        elif meta.st_mode & 0o111:
            if rel != 'bin/wg-quick' or not blob.startswith((f'#!{PREFIX}/bin/bash\n').encode()):
                raise ValueError(f'Unsupported executable script/interpreter: {rel}')
            if b'/usr/bin/env' in blob:
                raise ValueError('wg-quick must not select its interpreter through PATH')
    if found != expected:
        raise ValueError('Runtime file set or SHA-256 differs from reviewed manifest')
    for rel in REQUIRED:
        if rel not in found:
            raise ValueError(f'Missing runtime component: {rel}')
        if rel != 'etc/strongswan.conf' and not (root / rel).stat().st_mode & 0o111:
            raise ValueError(f'Runtime component is not executable: {rel}')
    if not (root / 'lib/ipsec/plugins').is_dir():
        raise ValueError('Missing strongSwan plugin directory')
    return binaries


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runtime', type=Path)
    parser.add_argument('manifest', type=Path)
    args = parser.parse_args()
    print(f'Validated {len(validate(args.runtime, args.manifest))} Mach-O files')
