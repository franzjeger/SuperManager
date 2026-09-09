#!/usr/bin/env python3
"""Assemble and sign a separately named macOS Dev bundle from built artifacts."""
import argparse
import plistlib
from pathlib import Path
import shutil
import subprocess

IDENTITY = 'Developer ID Application: Frank Lia (LY6LJ395B8)'


def sign(path, identifier=None):
    args = ['/usr/bin/codesign', '--force', '--options', 'runtime', '--timestamp', '--sign', IDENTITY]
    if identifier:
        args += ['--identifier', identifier]
    subprocess.run(args + [str(path)], check=True)


def assemble(app, rust, output, tailscale=None, build="2026090903", version="1.8.0-dev.3"):
    if output.exists():
        raise ValueError('Refusing to replace an existing app')
    shutil.copytree(app, output, symlinks=True)
    plist = output / 'Contents/Info.plist'
    info = plistlib.loads(plist.read_bytes())
    if info['CFBundleIdentifier'] != 'com.sybr.supermanager.dev':
        raise ValueError('Input must be built from the isolated Dev source')
    old_executable = info['CFBundleExecutable']
    info['CFBundleExecutable'] = 'SuperManagerDev'
    (output / 'Contents/MacOS' / old_executable).rename(output / 'Contents/MacOS/SuperManagerDev')
    info.update(CFBundleName='SuperManager Dev', CFBundleDisplayName='SuperManager Dev',
                CFBundleVersion=build, CFBundleShortVersionString=version,
                SUEnableAutomaticChecks=False, SUAutomaticallyUpdate=False)
    info.pop('SUFeedURL', None)
    info.pop('SUPublicEDKey', None)
    plist.write_bytes(plistlib.dumps(info))
    macos = output / 'Contents/MacOS'
    shutil.copy2(rust / 'supermanager-dev-engine', macos / 'supermanager-dev-engine')
    helper = macos / 'com.sybr.supermanager.dev.helper'
    shutil.copy2(rust / 'supermanager-helper', helper)
    sign(helper, 'com.sybr.supermanager.dev.helper')
    sign(macos / 'supermanager-dev-engine', 'com.sybr.supermanager.dev.engine')
    if tailscale:
        target = output / 'Contents/Resources/tailscale-bin'
        shutil.copytree(tailscale, target, symlinks=True)
        for binary in target.iterdir():
            if binary.is_file() and binary.name in {'tailscale', 'tailscaled'}:
                sign(binary, 'com.sybr.supermanager.dev.' + binary.name)
    # Sign nested bundles from leaves to root, without signing arbitrary data files.
    frameworks = output / 'Contents/Frameworks'
    if frameworks.exists():
        nested = [p for p in frameworks.rglob('*') if p.suffix in {'.framework', '.xpc', '.app'}]
        for path in sorted(nested, key=lambda p: len(p.parts), reverse=True):
            sign(path)
    sign(output, 'com.sybr.supermanager.dev')
    subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(output)], check=True)
    print('Verified signed Dev app: ' + str(output))

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--app', required=True, type=Path)
    p.add_argument('--rust', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--tailscale', type=Path)
    p.add_argument('--build', default='2026090903')
    p.add_argument('--version', default='1.8.0-dev.3')
    a = p.parse_args()
    assemble(a.app, a.rust, a.output, a.tailscale, a.build, a.version)
