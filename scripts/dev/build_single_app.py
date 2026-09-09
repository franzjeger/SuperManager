#!/usr/bin/env python3
"""Build the local single-app channel from a clean commit; never install it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from assemble_single_app import assemble
from prepare_single_app import prepare_single_app


def output(command, cwd):
    return subprocess.check_output(command, cwd=cwd, text=True).strip()


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(source, destination, tailscale, build_number, version, cargo_target=None):
    source, destination, tailscale = source.resolve(), destination.resolve(), tailscale.resolve()
    if destination.exists() or destination.is_relative_to(source):
        raise ValueError('Use a new build directory outside the source checkout')
    if output(['git', 'status', '--porcelain', '--untracked-files=all'], source):
        raise ValueError('Commit or preserve outstanding changes before building')
    commit = output(['git', 'rev-parse', 'HEAD'], source)
    dependency_hashes = {}
    for name in ('tailscale', 'tailscaled'):
        binary = tailscale / name
        if not binary.is_file() or binary.is_symlink():
            raise ValueError('Supply regular reviewed Tailscale binaries')
        subprocess.run(['codesign', '--verify', '--strict', str(binary)], check=True)
        dependency_hashes[name] = sha256(binary)
    if not str(build_number).isdigit() or int(build_number) <= 0:
        raise ValueError('Build number must be a positive integer')
    destination.mkdir(parents=True)
    (destination / '.metadata_never_index').touch()
    snapshot = destination / 'snapshot'
    snapshot.mkdir()
    archive = destination / 'source.tar'
    subprocess.run(['git', 'archive', '--format=tar', '--output', str(archive), commit],
                   cwd=source, check=True)
    subprocess.run(['/usr/bin/tar', '-xf', str(archive), '-C', str(snapshot)], check=True)
    overlay = destination / 'source'
    prepare_single_app(snapshot, overlay)
    # Detect concurrent source edits before compilation.
    if output(['git', 'rev-parse', 'HEAD'], source) != commit or output(
            ['git', 'status', '--porcelain', '--untracked-files=all'], source):
        raise ValueError('Source changed while preparing the build')
    target = (cargo_target or destination / 'rust').resolve()
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    subprocess.run(['cargo', 'build', '--locked', '--release', '-p', 'supermgrd-mac',
                    '-p', 'supermanager-helper'], cwd=overlay, env=env, check=True)
    project = overlay / 'SuperManagerMac'
    subprocess.run(['xcodegen', 'generate'], cwd=project, check=True)
    resolved = project / 'SuperManager.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved'
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_bytes((snapshot / 'SuperManagerMac/Package.resolved').read_bytes())
    derived = destination / 'derived'
    xcode = ['xcodebuild', '-project', 'SuperManager.xcodeproj', '-scheme', 'SuperManagerMac',
             '-configuration', 'Release', '-derivedDataPath', str(derived)]
    subprocess.run(xcode + ['-resolvePackageDependencies', '-onlyUsePackageVersionsFromResolvedFile'],
                   cwd=project, check=True)
    subprocess.run(xcode + ['-disableAutomaticPackageResolution', 'CODE_SIGNING_ALLOWED=NO', 'build'],
                   cwd=project, check=True)
    for name, expected in dependency_hashes.items():
        if sha256(tailscale / name) != expected:
            raise ValueError('Tailscale input changed during the build')
    app = destination / 'SuperManager.app'
    assemble(derived / 'Build/Products/Release/SuperManagerMac.app', target / 'release',
             tailscale, app, str(build_number), version)
    record = {
        'source_commit': commit, 'version': version, 'build': str(build_number),
        'bundle_id': 'com.sybr.supermanager.dev', 'channel': 'local-single-app',
        'cargo_lock_sha256': sha256(snapshot / 'Cargo.lock'),
        'swift_pins': json.loads(resolved.read_text())['pins'],
        'tailscale_input_sha256': dependency_hashes,
        'rustc': output(['rustc', '--version'], source),
        'xcode': output(['xcodebuild', '-version'], source),
        'xcodegen': output(['xcodegen', '--version'], source),
        'files': {str(p.relative_to(app)): sha256(p) for p in app.rglob('*')
                  if p.is_file() and not p.is_symlink()},
    }
    (destination / 'build-provenance.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Built signed app and provenance in ' + str(destination))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[2])
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--tailscale', type=Path, required=True)
    p.add_argument('--build', required=True)
    p.add_argument('--version', required=True)
    p.add_argument('--cargo-target', type=Path)
    a = p.parse_args()
    build(a.source, a.output, a.tailscale, a.build, a.version, a.cargo_target)
