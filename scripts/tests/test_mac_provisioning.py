import copy
import datetime
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("validator", Path(__file__).parents[1] / "validate_mac_provisioning.py")
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class ProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.team = "LY6LJ395B8"
        self.profile = {
            "ExpirationDate": datetime.datetime(2099, 1, 1),
            "ProvisionsAllDevices": True,
            "TeamIdentifier": [self.team],
            "ApplicationIdentifierPrefix": [self.team],
            "Entitlements": {
                "com.apple.application-identifier": validator.KEYCHAIN_GROUP,
                "com.apple.developer.team-identifier": self.team,
                "keychain-access-groups": [self.team + ".*"],
            },
        }

    def test_valid_distribution_preserves_existing_group(self):
        ent = validator.entitlements_for(self.profile, self.team)
        self.assertEqual(ent["keychain-access-groups"], [validator.KEYCHAIN_GROUP])
        self.assertEqual(ent["com.apple.application-identifier"], validator.KEYCHAIN_GROUP)

    def test_exact_authorization_is_valid(self):
        self.profile["Entitlements"]["keychain-access-groups"] = [validator.KEYCHAIN_GROUP]
        validator.entitlements_for(self.profile, self.team)

    def test_invalid_profiles_are_rejected(self):
        changes = [
            {"ExpirationDate": datetime.datetime(2000, 1, 1)},
            {"ProvisionsAllDevices": False},
            {"ProvisionedDevices": ["local-mac"]},
            {"TeamIdentifier": ["OTHER"]},
            {"ApplicationIdentifierPrefix": ["OTHER"]},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                validator.entitlements_for(dict(self.profile, **change), self.team)

    def test_missing_wrong_or_debug_entitlements_are_rejected(self):
        changes = [
            {"keychain-access-groups": []},
            {"keychain-access-groups": ["OTHER.*"]},
            {"keychain-access-groups": [self.team + ".other"]},
            {"com.apple.application-identifier": self.team + ".other"},
            {"com.apple.application-identifier": None},
            {"com.apple.developer.team-identifier": "OTHER"},
            {"com.apple.security.get-task-allow": True},
            {"get-task-allow": True},
        ]
        for change in changes:
            profile = copy.deepcopy(self.profile)
            profile["Entitlements"].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                validator.entitlements_for(profile, self.team)


if __name__ == "__main__":
    unittest.main()
