#!/usr/bin/env python3
"""Reuse or create Developer ID provisioning directly through Apple's API.

Uses the same AC_API_* credentials as notarization and the imported signing
identity. No profile secret, third-party Python packages, or Apple ID login.
"""
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from validate_mac_provisioning import BUNDLE_ID, entitlements_for

API = "https://api.appstoreconnect.apple.com"
RENEW_BEFORE = dt.timedelta(days=30)


def b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def raw_signature(der):
    """OpenSSL returns DER ECDSA; JWT ES256 requires fixed-width r || s."""
    if len(der) < 6 or der[0] != 0x30 or der[1] != len(der) - 2:
        raise ValueError("Expected a P-256 ECDSA signature from the Apple API key")
    offset, result = 2, b""
    for _ in range(2):
        if offset + 2 > len(der) or der[offset] != 2:
            raise ValueError("Invalid ECDSA signature")
        length = der[offset + 1]
        value = der[offset + 2:offset + 2 + length]
        if not value or len(value) != length or value[0] & 0x80:
            raise ValueError("Invalid ECDSA integer")
        value = value.lstrip(b"\0")
        if len(value) > 32:
            raise ValueError("Apple API key must use P-256")
        result += value.rjust(32, b"\0")
        offset += 2 + length
    if offset != len(der):
        raise ValueError("Unexpected ECDSA signature data")
    return result


def token(key_path, key_id, issuer):
    now = int(time.time())
    header = {"alg": "ES256", "kid": key_id, "typ": "JWT"}
    claims = {"iss": issuer, "iat": now - 10, "exp": now + 600, "aud": "appstoreconnect-v1"}
    message = b".".join(b64url(json.dumps(part, separators=(",", ":")).encode()) for part in (header, claims))
    signature = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(key_path)], input=message,
        capture_output=True, check=True).stdout
    return (message + b"." + b64url(raw_signature(signature))).decode()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward an Apple bearer token to another URL.


class AppleAPI:
    def __init__(self, key_path, key_id, issuer):
        self.credentials = (key_path, key_id, issuer)
        self.opener = urllib.request.build_opener(NoRedirect)

    def request(self, method, path, body=None):
        url = urllib.parse.urljoin(API, path)
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != "api.appstoreconnect.apple.com":
            raise ValueError("Unexpected Apple API pagination URL")
        for attempt in range(3):
            request = urllib.request.Request(url, method=method, headers={
                "Authorization": "Bearer " + token(*self.credentials),
                "Content-Type": "application/json", "Accept": "application/json",
            }, data=json.dumps(body).encode() if body is not None else None)
            try:
                with self.opener.open(request, timeout=30) as response:
                    return json.load(response)
            except urllib.error.HTTPError as error:
                if method == "GET" and error.code in (429, 500, 502, 503, 504) and attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
                reason = ""
                if error.code in (401, 403):
                    reason = "; AC_API_* must be a team API key with Certificates, Identifiers & Profiles access"
                raise RuntimeError(f"Apple API {method} {parsed.path}: HTTP {error.code}{reason}") from None
        raise RuntimeError("Apple API retry limit reached")

    def items(self, path, parameters=None):
        if parameters:
            path += "?" + urllib.parse.urlencode(parameters)
        while path:
            page = self.request("GET", path)
            yield from page["data"]
            path = page.get("links", {}).get("next")


def signing_certificate(identity):
    if not re.fullmatch(r"Developer ID Application: .+ \([A-Z0-9]{10}\)", identity):
        raise ValueError("DEVELOPER_ID_APP must be the full Developer ID Application identity name")
    identities = subprocess.check_output(["security", "find-identity", "-v", "-p", "codesigning"], text=True)
    matches = re.findall(r'\b([A-Fa-f0-9]{40})\s+"' + re.escape(identity) + r'"', identities)
    if len(set(matches)) != 1:
        raise ValueError("The configured Developer ID identity is missing or ambiguous in the signing keychain")
    pem = subprocess.check_output(["security", "find-certificate", "-a", "-p"])
    for encoded in re.findall(rb"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----", pem, re.S):
        certificate = base64.b64decode(encoded)
        if hashlib.sha1(certificate).hexdigest().upper() == matches[0].upper():
            return certificate
    raise ValueError("Cannot find the certificate for the imported signing identity")


def decode_profile(content):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "profile.provisionprofile"
        path.write_bytes(content)
        decoded = subprocess.check_output(["security", "cms", "-D", "-i", str(path)], stderr=subprocess.DEVNULL)
        return plistlib.loads(decoded)


def valid_profile(resource, team, certificate, now, decode):
    attributes = resource["attributes"]
    if attributes.get("profileType") != "MAC_APP_DIRECT" or attributes.get("profileState") != "ACTIVE":
        raise ValueError("Not an active Developer ID profile")
    content = base64.b64decode(attributes["profileContent"], validate=True)
    profile = decode(content)
    entitlements_for(profile, team, now=now)
    if certificate not in profile.get("DeveloperCertificates", []):
        raise ValueError("Profile does not authorize the current signing certificate")
    expiry = profile["ExpirationDate"].replace(tzinfo=dt.timezone.utc)
    if expiry <= now + RENEW_BEFORE:
        raise ValueError("Profile must be renewed before the next release")
    return content, expiry


def ensure_profile(api, team, certificate, now=None, decode=decode_profile):
    now = now or dt.datetime.now(dt.timezone.utc)
    bundles = list(api.items("/v1/bundleIds", {"filter[identifier]": BUNDLE_ID, "limit": 200}))
    bundles = [item for item in bundles if item["attributes"].get("identifier") == BUNDLE_ID]
    if len(bundles) != 1:
        raise ValueError(f"Expected one registered Apple bundle ID for {BUNDLE_ID}")
    bundle_id = bundles[0]["id"]
    # Match certificate BYTES, not the label or team: renewed certs may share both.
    certificates = list(api.items("/v1/certificates", {"limit": 200}))
    matching = [item for item in certificates if
        item["attributes"].get("certificateType") in ("DEVELOPER_ID_APPLICATION", "DEVELOPER_ID_APPLICATION_G2")
        and base64.b64decode(item["attributes"].get("certificateContent", "")) == certificate]
    if len(matching) != 1:
        raise ValueError("Apple API cannot find the imported Developer ID Application certificate")
    certificate_id = matching[0]["id"]
    candidates = []
    for resource in api.items("/v1/profiles", {
        "filter[profileType]": "MAC_APP_DIRECT", "filter[profileState]": "ACTIVE",
        "include": "bundleId", "limit": 200,
    }):
        if (resource.get("relationships", {}).get("bundleId", {}).get("data") or {}).get("id") != bundle_id:
            continue
        try:
            content, expiry = valid_profile(resource, team, certificate, now, decode)
        except (ValueError, KeyError, subprocess.CalledProcessError):
            continue
        candidates.append((expiry, content))
    if candidates:
        print("Reusing Apple's current Developer ID profile (certificate and Keychain group verified).")
        return max(candidates, key=lambda item: item[0])[1]

    # Do not revoke/delete old profiles: already installed releases may need them.
    resource = api.request("POST", "/v1/profiles", {"data": {
        "type": "profiles",
        "attributes": {"name": f"SuperManager Developer ID {now:%Y%m%d} {uuid.uuid4().hex[:8]}", "profileType": "MAC_APP_DIRECT"},
        "relationships": {
            "bundleId": {"data": {"type": "bundleIds", "id": bundle_id}},
            "certificates": {"data": [{"type": "certificates", "id": certificate_id}]},
        },
    }})["data"]
    content, _ = valid_profile(resource, team, certificate, now, decode)
    print("Created and validated a Developer ID profile through Apple; previous profiles retained.")
    return content


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: fetch_mac_provisioning.py <output.provisionprofile>")
    try:
        names = ("AC_API_KEY_PATH", "AC_API_KEY_ID", "AC_API_ISSUER_ID", "DEVELOPER_ID_APP")
        for name in names:
            if not os.environ.get(name):
                raise ValueError(f"{name} is required for automatic provisioning")
        identity = os.environ["DEVELOPER_ID_APP"]
        certificate = signing_certificate(identity)
        team = identity.rsplit("(", 1)[1].rstrip(")")
        api = AppleAPI(*(os.environ[name] for name in names[:3]))
        content = ensure_profile(api, team, certificate)
        output = Path(sys.argv[1]).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=output.parent, delete=False) as temporary:
            temporary.write(content)
            staged = Path(temporary.name)
        try:
            staged.replace(output)
        finally:
            staged.unlink(missing_ok=True)
    except (ValueError, KeyError, OSError, RuntimeError, subprocess.CalledProcessError) as error:
        sys.exit(f"error: automatic Developer ID provisioning failed: {error}")


if __name__ == "__main__":
    main()
