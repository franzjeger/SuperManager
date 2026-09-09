#!/usr/bin/env python3
"""One-time private Dev data snapshot; no overwrites, sockets, or symlinks."""
import argparse
import collections
import json
import os
from pathlib import Path
import re
import stat
import tempfile


def copy_data(source, destination):
    if destination.exists() or destination.is_symlink():
        raise ValueError('Dev data already exists; refusing to overwrite it')
    if source.is_symlink():
        raise ValueError('Source data must not be a symlink')
    os.umask(0o077)
    destination.parent.mkdir(parents=True, exist_ok=True)
    counts = collections.Counter()
    with tempfile.TemporaryDirectory(prefix='.supermanager-dev-', dir=destination.parent) as temporary:
        stage = Path(temporary) / 'data'
        stage.mkdir(mode=0o700)
        for path in source.rglob('*'):
            relative = path.relative_to(source)
            if path.is_symlink():
                raise ValueError('Data contains a symlink; review before copying')
            if relative.parts[0] in {'crashes', 'logs'} or path.name.startswith('.'):
                continue
            if path.is_dir():
                (stage / relative).mkdir(parents=True, exist_ok=True, mode=0o700)
                continue
            if not stat.S_ISREG(path.stat().st_mode) or path.suffix in {'.sock', '.lock', '.log', '.pid'}:
                continue
            data = path.read_bytes()
            if path.suffix in {'.toml', '.json', '.ovpn', '.conf', '.xml'}:
                try:
                    text = data.decode('utf-8')
                    text = text.replace(str(source), str(destination))
                    text = text.replace('Library/Application Support/SuperManager/',
                                        'Library/Application Support/SuperManager Dev/')
                    if path.suffix == '.toml':
                        text = re.sub(r'(?m)^(auto_connect|kill_switch)\s*=\s*true\s*$', r'\1 = false', text)
                    data = text.encode('utf-8')
                except UnicodeDecodeError:
                    pass
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with target.open('xb') as file:
                file.write(data)
            counts[relative.parts[0]] += 1
        (stage / 'DEV-SNAPSHOT.json').write_text(json.dumps({
            'files_by_area': counts, 'auto_connect': False, 'scheduled_jobs': False,
            'note': 'Independent snapshot. No changes sync back to the regular app.'}, indent=2))
        stage.rename(destination)
    print(json.dumps({'copied_files_by_area': counts, 'destination': str(destination)}))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--destination', required=True, type=Path)
    args = parser.parse_args()
    copy_data(args.source, args.destination)
