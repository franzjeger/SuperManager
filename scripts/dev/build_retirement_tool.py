#!/usr/bin/env python3
"""Build (but do not run) the fixed-service, signed legacy helper retirement tool."""
import argparse
from pathlib import Path
import plistlib
import shutil
import subprocess
from assemble import sign


def build(old_app, output):
    if output.exists():
        raise ValueError('Use a new output bundle path')
    identifier = 'com.sybr.supermanager'
    old = old_app / 'Contents'
    info = plistlib.loads((old / 'Info.plist').read_bytes())
    if info.get('CFBundleIdentifier') != identifier:
        raise ValueError('Supply the archived regular-channel application')
    plist = old / 'Library/LaunchDaemons/com.sybr.supermanager.helper.plist'
    if plistlib.loads(plist.read_bytes()).get('Label') != identifier + '.helper':
        raise ValueError('Unexpected helper service label')
    contents = output / 'Contents'
    (contents / 'MacOS').mkdir(parents=True)
    (contents / 'Library/LaunchDaemons').mkdir(parents=True)
    shutil.copy2(plist, contents / 'Library/LaunchDaemons' / plist.name)
    (contents / 'Info.plist').write_bytes(plistlib.dumps({
        'CFBundleIdentifier': identifier, 'CFBundleExecutable': 'retire',
        'CFBundleName': 'SuperManager Service Retirement',
        'CFBundleVersion': '1', 'CFBundlePackageType': 'APPL',
    }))
    subprocess.run(['xcrun', 'swiftc', str(Path(__file__).with_name('retire_regular_helper.swift')),
                    '-o', str(contents / 'MacOS/retire')], check=True)
    sign(output, identifier)
    subprocess.run(['codesign', '--verify', '--deep', '--strict', str(output)], check=True)
    print('Disconnect regular VPNs before running: ' + str(contents / 'MacOS/retire'))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--old-app', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    build(a.old_app, a.output)
