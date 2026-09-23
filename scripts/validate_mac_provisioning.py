#!/usr/bin/env python3
"""Validate Developer ID DPK authorization and emit stable app entitlements."""
import argparse
import datetime
import plistlib
import subprocess
from pathlib import Path

BUNDLE_ID = "com.sybr.supermanager"
# Keep this stable across releases. Changing it strands existing credentials.
KEYCHAIN_GROUP = "LY6LJ395B8.com.sybr.supermanager"


def permits(pattern, value):
    return pattern == value or (
        isinstance(pattern, str) and pattern.endswith(".*")
        and value.startswith(pattern[:-1])
    )


def entitlements_for(profile, team, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    expiry = profile.get("ExpirationDate")
    if not expiry or expiry.replace(tzinfo=datetime.timezone.utc) <= now:
        raise ValueError("Provisioning profile is missing an expiration date or has expired")
    if profile.get("ProvisionsAllDevices") is not True or profile.get("ProvisionedDevices"):
        raise ValueError("A Developer ID distribution profile is required, not a development profile")
    allowed = profile.get("Entitlements", {})
    if allowed.get("get-task-allow") or allowed.get("com.apple.security.get-task-allow"):
        raise ValueError("Development/debug entitlements are not allowed for distribution")
    if team not in profile.get("TeamIdentifier", []) or allowed.get("com.apple.developer.team-identifier") != team:
        raise ValueError("Provisioning profile team does not match signing identity")
    app_id = KEYCHAIN_GROUP
    if not any(app_id == prefix + "." + BUNDLE_ID for prefix in profile.get("ApplicationIdentifierPrefix", [])):
        raise ValueError("Profile would change the existing application/keychain identity")
    if not permits(allowed.get("com.apple.application-identifier"), app_id):
        raise ValueError("Provisioning profile does not authorize this app identifier")
    if not any(permits(group, KEYCHAIN_GROUP) for group in allowed.get("keychain-access-groups", [])):
        raise ValueError("Provisioning profile does not authorize the stable VPN keychain group")
    return {
        "com.apple.security.app-sandbox": False,
        "com.apple.application-identifier": app_id,
        "com.apple.developer.team-identifier": team,
        "keychain-access-groups": [KEYCHAIN_GROUP],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path)
    parser.add_argument("team")
    parser.add_argument("output", type=Path)
    parser.add_argument("--app", type=Path, help="Verify the final signed app and its certificate")
    args = parser.parse_args()
    try:
        decoded = subprocess.check_output(["security", "cms", "-D", "-i", str(args.profile)], stderr=subprocess.DEVNULL)
        profile = plistlib.loads(decoded)
        expected = entitlements_for(profile, args.team)
        if args.app:
            actual = plistlib.loads(subprocess.check_output(
                ["codesign", "-d", "--entitlements", "-", "--xml", str(args.app)], stderr=subprocess.DEVNULL))
            if actual != expected:
                raise ValueError("Signed app entitlements differ from the validated distribution entitlements")
            import tempfile
            with tempfile.TemporaryDirectory() as directory:
                prefix = str(Path(directory) / "signer")
                subprocess.run(["codesign", "-d", "--extract-certificates=" + prefix, str(args.app)], check=True, stderr=subprocess.DEVNULL)
                if Path(prefix + "0").read_bytes() not in profile.get("DeveloperCertificates", []):
                    raise ValueError("Signing certificate is not authorized by the embedded profile")
        else:
            args.output.write_bytes(plistlib.dumps(expected))
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
