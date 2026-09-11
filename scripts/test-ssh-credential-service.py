#!/usr/bin/env python3
"""Exercise the real Rust credential writer under the shipped systemd limits.

Usage: sudo -n python3 scripts/test-ssh-credential-service.py TEST_BINARY --caller-uid 1000
Uses synthetic bytes and a disposable service/directory; never contacts a host.
"""

import argparse
import configparser
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("test_binary", type=Path)
    parser.add_argument("--caller-uid", type=int, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or args.caller_uid <= 0:
        parser.error("run as root and choose a non-root caller UID")
    unit = configparser.ConfigParser(interpolation=None)
    unit.read(Path(__file__).resolve().parents[1] / "contrib/systemd/supermgrd.service")
    service = unit["Service"]
    caps = service["CapabilityBoundingSet"].split()
    assert "CAP_CHOWN" in caps, "the installed service needs credential ownership handoff"

    for handoff in (False, True):
        with tempfile.TemporaryDirectory(prefix="supermgr-credential-test-", dir="/run") as scratch:
            os.chmod(scratch, 0o711)
            key = Path(scratch) / "synthetic-key"
            bounded = " ".join(c for c in caps if handoff or c != "CAP_CHOWN")
            command = ["systemd-run", "--quiet", "--wait", "--pipe", "--collect"]
            for name, value in {
                "CapabilityBoundingSet": bounded,
                "AmbientCapabilities": service["AmbientCapabilities"],
                "ProtectSystem": service["ProtectSystem"],
                "ProtectHome": service["ProtectHome"],
                "PrivateTmp": service["PrivateTmp"],
                "NoNewPrivileges": service["NoNewPrivileges"],
                "ReadWritePaths": scratch,
            }.items():
                command.append(f"--property={name}={value}")
            for name, value in {
                "SUPERMGR_TEST_CREDENTIAL_PATH": str(key),
                "SUPERMGR_TEST_CALLER_UID": str(args.caller_uid),
                "SUPERMGR_TEST_EXPECT_HANDOFF": str(int(handoff)),
            }.items():
                command.append(f"--setenv={name}={value}")
            command += [str(args.test_binary.resolve()),
                        "secure_file::tests::bounded_service_credential_handoff",
                        "--exact", "--ignored", "--test-threads=1"]
            result = subprocess.run(command, capture_output=True, text=True)
            assert result.returncode == 0, result.stdout + result.stderr
            assert "1 passed" in result.stdout, result.stdout + result.stderr
            if handoff:
                # Separate unprivileged processes prove actual access, not
                # just the mode/owner bits. No file contents are printed.
                for uid, allowed in [(args.caller_uid, True),
                                     (65534 if args.caller_uid != 65534 else 65533, False)]:
                    reader = """
import os, pathlib, sys
os.setgroups([])
os.setgid(int(sys.argv[1]))
os.setuid(int(sys.argv[1]))
try:
    data = pathlib.Path(sys.argv[2]).read_bytes()
except PermissionError:
    assert sys.argv[3] == '0', 'caller could not read its credential'
else:
    assert sys.argv[3] == '1', 'another account could read the credential'
    assert data == b'synthetic test key'
"""
                    subprocess.run(["/usr/bin/python3", "-c", reader, str(uid),
                                    str(key), str(int(allowed))], check=True)
                print("PASS: shipped service hands off 0600 file; caller can read; other UID denied")
            else:
                assert not key.exists()
                print("PASS: previous capability limits reproduce EPERM; failed write leaves no file")


if __name__ == "__main__":
    main()
