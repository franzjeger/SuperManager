import base64
import datetime as dt
import json
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1]))
import fetch_mac_provisioning as fetch

TEAM = "LY6LJ395B8"
NOW = dt.datetime(2026, 9, 23, tzinfo=dt.timezone.utc)
CERT = b"current-signing-certificate"


def resource(expiry=None, certificate=CERT, group=None):
    profile = {
        "ExpirationDate": (expiry or NOW + dt.timedelta(days=365)).replace(tzinfo=None),
        "ProvisionsAllDevices": True,
        "TeamIdentifier": [TEAM], "ApplicationIdentifierPrefix": [TEAM],
        "DeveloperCertificates": [certificate],
        "Entitlements": {
            "com.apple.application-identifier": TEAM + "." + fetch.BUNDLE_ID,
            "com.apple.developer.team-identifier": TEAM,
            "keychain-access-groups": [group or TEAM + ".*"],
        },
    }
    return {"id": "profile-id", "attributes": {
        "profileType": "MAC_APP_DIRECT", "profileState": "ACTIVE",
        "profileContent": base64.b64encode(plistlib.dumps(profile)).decode(),
    }, "relationships": {"bundleId": {"data": {"id": "bundle-id"}}}}


class FakeApple:
    def __init__(self, profiles=()):
        self.profiles = list(profiles)
        self.created = resource()
        self.writes = []
        self.certificates = [{"id": "certificate-id", "attributes": {
            "certificateType": "DEVELOPER_ID_APPLICATION_G2",
            "certificateContent": base64.b64encode(CERT).decode(),
        }}]

    def items(self, path, parameters=None):
        return iter({
            "/v1/bundleIds": [{"id": "bundle-id", "attributes": {"identifier": fetch.BUNDLE_ID}}],
            "/v1/certificates": self.certificates,
            "/v1/profiles": self.profiles,
        }[path])

    def request(self, method, path, body=None):
        self.writes.append((method, path, body))
        return {"data": self.created}


class AutomaticProvisioningTests(unittest.TestCase):
    def fetch(self, api):
        return fetch.ensure_profile(api, TEAM, CERT, now=NOW, decode=plistlib.loads)

    def test_valid_profile_is_reused_without_account_changes(self):
        existing = resource()
        api = FakeApple([existing])
        self.assertEqual(self.fetch(api), base64.b64decode(existing["attributes"]["profileContent"]))
        self.assertEqual(api.writes, [])

    def test_first_release_creates_correct_profile_with_exact_certificate(self):
        api = FakeApple()
        self.fetch(api)
        self.assertEqual(len(api.writes), 1)
        method, path, body = api.writes[0]
        self.assertEqual((method, path), ("POST", "/v1/profiles"))
        self.assertEqual(body["data"]["attributes"]["profileType"], "MAC_APP_DIRECT")
        self.assertEqual(body["data"]["relationships"], {
            "bundleId": {"data": {"type": "bundleIds", "id": "bundle-id"}},
            "certificates": {"data": [{"type": "certificates", "id": "certificate-id"}]},
        })

    def test_expired_soon_expiring_rotated_cert_and_wrong_group_are_renewed(self):
        for existing in [resource(NOW - dt.timedelta(days=1)),
                         resource(NOW + dt.timedelta(days=20)),
                         resource(certificate=b"previous-certificate"),
                         resource(group="OTHER.*")]:
            with self.subTest(profile=existing["id"]):
                api = FakeApple([existing])
                self.fetch(api)
                self.assertEqual([call[0] for call in api.writes], ["POST"])
                self.assertEqual(len(api.profiles), 1)  # No revocation or deletion.

    def test_invalid_and_other_app_profiles_are_not_used(self):
        invalid = resource()
        invalid["attributes"]["profileState"] = "INVALID"
        other = resource()
        other["relationships"]["bundleId"]["data"]["id"] = "another-app"
        development = resource()
        development["attributes"]["profileType"] = "MAC_APP_DEVELOPMENT"
        for existing in [invalid, other, development]:
            with self.subTest(profile=existing):
                api = FakeApple([existing])
                self.fetch(api)
                self.assertEqual(len(api.writes), 1)

    def test_newest_valid_profile_wins(self):
        newer = resource(NOW + dt.timedelta(days=500))
        api = FakeApple([resource(), newer])
        self.assertEqual(self.fetch(api), base64.b64decode(newer["attributes"]["profileContent"]))
        self.assertEqual(api.writes, [])

    def test_bad_new_profile_fails_without_returning_it(self):
        api = FakeApple()
        api.created = resource(group="wrong.group")
        with self.assertRaises(ValueError):
            self.fetch(api)

    def test_missing_signing_certificate_does_not_create_profile(self):
        api = FakeApple()
        api.certificates = []
        with self.assertRaisesRegex(ValueError, "certificate"):
            self.fetch(api)
        self.assertEqual(api.writes, [])

    def test_pagination_is_followed(self):
        api = fetch.AppleAPI("unused", "unused", "unused")
        with patch.object(api, "request", side_effect=[
            {"data": ["first"], "links": {"next": fetch.API + "/v1/profiles?cursor=next"}},
            {"data": ["second"], "links": {"next": None}},
        ]) as request:
            self.assertEqual(list(api.items("/v1/profiles")), ["first", "second"])
            self.assertEqual(request.call_count, 2)

    def test_pagination_cannot_send_credentials_to_another_host(self):
        api = fetch.AppleAPI("unused", "unused", "unused")
        with patch.object(fetch, "token") as token:
            with self.assertRaisesRegex(ValueError, "pagination"):
                api.request("GET", "https://example.com/profiles")
            token.assert_not_called()

    def test_generated_jwt_has_valid_es256_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            key, public, signature = (Path(directory) / name for name in ("key.pem", "public.pem", "signature"))
            subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key)], check=True, capture_output=True)
            subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public)], check=True, capture_output=True)
            encoded = fetch.token(key, "key-id", "issuer-id")
            header, claims, sig = encoded.split(".")
            decode = lambda data: base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
            self.assertEqual(json.loads(decode(header))["alg"], "ES256")
            self.assertEqual(json.loads(decode(claims))["iss"], "issuer-id")
            raw = decode(sig)
            self.assertEqual(len(raw), 64)
            integers = []
            for value in (raw[:32], raw[32:]):
                value = value.lstrip(b"\0") or b"\0"
                if value[0] & 0x80:
                    value = b"\0" + value
                integers.append(b"\x02" + bytes([len(value)]) + value)
            body = b"".join(integers)
            signature.write_bytes(b"\x30" + bytes([len(body)]) + body)
            subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(public), "-signature", str(signature)],
                           input=(header + "." + claims).encode(), check=True, capture_output=True)


if __name__ == "__main__":
    unittest.main()
