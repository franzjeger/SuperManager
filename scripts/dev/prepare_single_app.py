#!/usr/bin/env python3
"""Prepare the locally consolidated app, retaining existing Dev data/service IDs."""
import argparse
from pathlib import Path
import subprocess
from prepare import prepare


def prepare_single_app(source, output):
    prepare(source, output)
    patch = Path(__file__).with_name('single-app.patch').resolve()
    subprocess.run(['git', 'apply', '--check', str(patch)], cwd=output, check=True)
    subprocess.run(['git', 'apply', str(patch)], cwd=output, check=True)
    preinstall = output / 'installer/system/scripts/preinstall'
    text = preinstall.read_text()
    old = 'for process in SuperManagerDev; do'
    if text.count(old) != 1:
        raise ValueError('Installer process check changed; review the single-app overlay')
    preinstall.write_text(text.replace(old, 'for process in SuperManager SuperManagerDev; do'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    prepare_single_app(args.source, args.output)
