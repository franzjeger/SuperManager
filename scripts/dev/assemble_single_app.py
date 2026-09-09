#!/usr/bin/env python3
"""Sign a single-app UI with freshly built Rust components.

Retains Dev bundle/service/Keychain identities for the local consolidation.
Does not install, replace services, migrate data, or change update channels.
"""
import argparse
from pathlib import Path
import plistlib
import shutil
import subprocess
from assemble import sign


def assemble(app, rust, tailscale, output, build, version):
    if output.exists():
        raise ValueError('Output must not exist')
    for bundle in (app,):
        info = plistlib.loads((bundle / 'Contents/Info.plist').read_bytes())
        if info['CFBundleIdentifier'] != 'com.sybr.supermanager.dev':
            raise ValueError('Expected the preserved local bundle identity')
    shutil.copytree(app, output, symlinks=True)
    plist = output / 'Contents/Info.plist'
    info = plistlib.loads(plist.read_bytes())
    macos = output / 'Contents/MacOS'
    (macos / info['CFBundleExecutable']).rename(macos / 'SuperManager')
    info.update(CFBundleExecutable='SuperManager', CFBundleName='SuperManager',
                CFBundleDisplayName='SuperManager', CFBundleVersion=build,
                CFBundleShortVersionString=version, SUEnableAutomaticChecks=False,
                SUAutomaticallyUpdate=False)
    info.pop('SUFeedURL', None)
    info.pop('SUPublicEDKey', None)
    plist.write_bytes(plistlib.dumps(info))
    for source, destination, identifier in (
        ('supermanager-dev-engine', 'supermanager-dev-engine', 'com.sybr.supermanager.dev.engine'),
        ('supermanager-helper', 'com.sybr.supermanager.dev.helper', 'com.sybr.supermanager.dev.helper'),
    ):
        shutil.copy2(rust / source, macos / destination)
        sign(macos / destination, identifier)
    target = output / 'Contents/Resources/tailscale-bin'
    target.mkdir(parents=True, exist_ok=False)
    for name in ('tailscale', 'tailscaled'):
        shutil.copy2(tailscale / name, target / name)
        sign(target / name, 'com.sybr.supermanager.dev.' + name)
    nested = [p for p in (output / 'Contents/Frameworks').rglob('*')
              if p.suffix in {'.framework', '.xpc', '.app'}]
    for path in sorted(nested, key=lambda p: len(p.parts), reverse=True):
        sign(path)
    sign(output, 'com.sybr.supermanager.dev')
    subprocess.run(['codesign', '--verify', '--deep', '--strict', str(output)], check=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('app', 'rust', 'tailscale', 'output'):
        p.add_argument('--' + name, required=True, type=Path)
    p.add_argument('--build', required=True)
    p.add_argument('--version', required=True)
    a = p.parse_args()
    assemble(a.app, a.rust, a.tailscale, a.output, a.build, a.version)
