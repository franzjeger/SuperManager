#!/usr/bin/env python3
"""Build the signed helper + VPN runtime package from reviewed build artifacts."""
import argparse
import hashlib
import re
import os
import platform
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
from validate_runtime import validate

TEAM = 'LY6LJ395B8'
HELPER = 'com.sybr.supermanager.helper'


def run(*args):
    subprocess.run(list(map(str, args)), check=True)


def build(args):
    if not (1 <= args.build <= 999999999999999):
        raise ValueError('Build must be a positive monotonic integer of at most 15 digits')
    for identity, kind in ((args.application_identity, 'Application'), (args.installer_identity, 'Installer')):
        if identity != f'Developer ID {kind}: Frank Lia ({TEAM})':
            raise ValueError(f'Expected the pinned Developer ID {kind} identity')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists():
        raise ValueError('Refusing to overwrite an existing package')
    with tempfile.TemporaryDirectory(prefix='supermanager-package-') as tmp:
        temp = Path(tmp)
        root = temp / 'root'
        payload = root / f'Library/Application Support/SuperManagerSystem/releases/{args.build}'
        payload.mkdir(parents=True)
        # Snapshot first. All checks and signatures apply to exactly this copy.
        shutil.copytree(args.runtime, payload / 'runtime', symlinks=True)
        binaries = validate(payload / 'runtime', args.manifest)
        if args.helper.is_symlink() or not args.helper.is_file():
            raise ValueError('Helper must be a regular non-symlink file')
        shutil.copyfile(args.helper, payload / 'helper')
        os.chmod(payload / 'helper', 0o755)
        for binary in binaries:
            relative = binary.relative_to(payload / 'runtime').as_posix()
            identifier = 'com.sybr.supermanager.vpn.' + relative.replace('/', '.')
            run('/usr/bin/codesign', '--force', '--options', 'runtime', '--timestamp',
                '--sign', args.application_identity, '--identifier', identifier, binary)
        # Helper must already carry its release signature. Never bless an arbitrary
        # user-supplied executable as the privileged helper in this packaging step.
        policy = f'anchor apple generic and certificate leaf[subject.OU] = "{TEAM}" and identifier "{HELPER}"'
        policy += ' and ! entitlement["com.apple.security.get-task-allow"] exists and ! entitlement["com.apple.security.cs.disable-library-validation"] exists and ! entitlement["com.apple.security.cs.allow-dyld-environment-variables"] exists'
        run('/usr/bin/codesign', '--verify', '--strict', '--all-architectures', '-R', '=' + policy, payload / 'helper')
        details = subprocess.run(['/usr/bin/codesign', '-dv', '--verbose=4', str(payload / 'helper')],
                                 check=True, capture_output=True, text=True).stderr
        flags = re.search(r'flags=0x([0-9a-fA-F]+)', details)
        if not flags or not int(flags.group(1), 16) & 0x10000:
            raise ValueError('Helper must use hardened runtime')
        shutil.copyfile(args.manifest, payload / 'source-manifest.json')
        plist = {
            'Label': HELPER, 'Program': '/Library/PrivilegedHelperTools/' + HELPER,
            'RunAtLoad': True, 'KeepAlive': {'SuccessfulExit': False, 'Crashed': True},
            'StandardOutPath': '/var/log/supermanager-helper.log',
            'StandardErrorPath': '/var/log/supermanager-helper.log',
            'EnvironmentVariables': {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'},
        }
        (payload / 'helper.plist').write_bytes(plistlib.dumps(plist))
        scripts = temp / 'scripts'
        scripts.mkdir()
        for name in ('preinstall', 'postinstall', 'recovery.sh'):
            source = Path(__file__).parent / 'scripts' / name
            destination = payload / name if name == 'recovery.sh' else scripts / name
            destination.write_text(source.read_text().replace('@BUILD@', str(args.build)).replace('@ARCH@', platform.machine()))
            destination.chmod(0o755)
            run('/bin/bash', '-n', destination)
        # Hash the final signed bytes, independently of source-manifest hashes.
        entries = sorted(p for p in payload.rglob('*') if p.is_file())
        (payload / 'payload.sha256').write_text(''.join(
            hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.relative_to(payload).as_posix() + '\n'
            for p in entries))
        for p in root.rglob('*'):
            if p.is_dir():
                p.chmod(0o755)
        run('/usr/bin/pkgbuild', '--root', root, '--scripts', scripts,
            '--identifier', 'com.sybr.supermanager.system', '--version', str(args.build),
            '--ownership', 'recommended', '--install-location', '/',
            '--sign', args.installer_identity, args.output)
        run('/usr/sbin/pkgutil', '--check-signature', args.output)
        print(f'Package built: {args.output}. Notarize and staple before distribution.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', required=True, type=Path)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--helper', required=True, type=Path)
    parser.add_argument('--build', required=True, type=int)
    parser.add_argument('--application-identity', required=True)
    parser.add_argument('--installer-identity', required=True)
    parser.add_argument('--output', required=True, type=Path)
    build(parser.parse_args())
