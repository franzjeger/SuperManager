#!/usr/bin/env python3
"""Opt-in macOS signing integration test; never starts privileged services.
Usage: python3 installer/system/tests/test_identity.py --run-signed
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-signed', action='store_true', required=True)
    parser.parse_args()
    repo = Path(__file__).resolve().parents[3]
    subprocess.run(['cargo', 'build', '--locked', '-p', 'supermanager-helper',
                    '--example', 'helper-auth-probe'], cwd=repo, check=True)
    server = repo / 'target/debug/examples/helper-auth-probe'
    with tempfile.TemporaryDirectory(prefix='sm-auth-', dir='/tmp') as directory:
        root = Path(directory)
        original = root / 'client'
        compiler = subprocess.check_output(['xcrun', '--find', 'swiftc'], text=True).strip()
        sdk = subprocess.check_output(['xcrun', '--sdk', 'macosx', '--show-sdk-path'], text=True).strip()
        subprocess.run([compiler, '-sdk', sdk, str(Path(__file__).with_name('auth-client.swift')),
                        '-o', str(original)], check=True)
        cases = [('allowed', 'com.sybr.supermanager', 'runtime'),
                 ('wrong-id', 'com.sybr.other', 'runtime'),
                 ('no-runtime', 'com.sybr.supermanager', '0')]
        for name, identifier, options in cases:
            client = root / name; shutil.copyfile(original, client); client.chmod(0o755)
            subprocess.run(['/usr/bin/codesign', '--force', '--timestamp=none', '--options', options,
                '--sign', 'Developer ID Application: Frank Lia (LY6LJ395B8)', '--identifier', identifier,
                str(client)], check=True)
            sock = root / (name + '.sock')
            process = subprocess.Popen([str(server), str(sock)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                for _ in range(100):
                    if sock.exists(): break
                    time.sleep(.02)
                result = subprocess.run([str(client), str(sock)], timeout=15)
                _, error = process.communicate(timeout=15)
                allowed = result.returncode == 0 and process.returncode == 0
                if allowed != (name == 'allowed'):
                    raise AssertionError(f'{name}: unexpected identity result: {error.decode()}')
                print(f'{name}: expected authorization result')
            finally:
                if process.poll() is None: process.kill(); process.wait()


if __name__ == '__main__': main()
