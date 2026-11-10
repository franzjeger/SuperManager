#!/usr/bin/env python3
"""Reject a Mach-O executable/archive whose objects need a newer macOS."""
import argparse
import pathlib
import re
import subprocess


def check(path, maximum):
    result = subprocess.run(["/usr/bin/otool", "-l", str(path)], text=True,
                            capture_output=True, check=True)
    versions = re.findall(r"\bminos\s+([\d.]+)", result.stdout)
    versions += re.findall(r"LC_VERSION_MIN_MACOSX\s+cmdsize\s+\d+\s+version\s+([\d.]+)",
                           result.stdout)
    if not versions:
        raise SystemExit(f"error: no macOS deployment version found in {path}")
    ceiling = tuple(map(int, maximum.split('.')))
    ceiling += (0,) * (3 - len(ceiling))
    for text in versions:
        version = tuple(map(int, text.split('.')))
        version += (0,) * (3 - len(version))
        if version > ceiling:
            raise SystemExit(f"error: {path} requires macOS {text}, newer than {maximum}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--maximum", required=True)
    parser.add_argument("paths", nargs="+", type=pathlib.Path)
    args = parser.parse_args()
    for item in args.paths:
        check(item, args.maximum)
    print(f"macOS deployment targets verified (<= {args.maximum})")
