from __future__ import annotations

import tempfile
import unittest
from datetime import date
from pathlib import Path

from app import profile_fields
from app.store import Store


class ProfileFieldRuleTests(unittest.TestCase):
    def test_trims_and_keeps_only_submitted_keys(self):
        self.assertEqual({"bio": "你好", "location": "上海"},
                         profile_fields.normalize({"bio": "  你好 ", "location": " 上海 "}))

    def test_bio_allows_line_breaks_but_not_other_controls(self):
        self.assertEqual("第一行\n\n第二行", profile_fields.normalize({"bio": "第一行\r\n\n\n\n第二行"})["bio"])
        with self.assertRaises(ValueError):
            profile_fields.normalize({"bio": "a\u0000b"})
        with self.assertRaises(ValueError):
            profile_fields.normalize({"location": "a\nb"})

    def test_length_limits(self):
        profile_fields.normalize({"bio": "字" * profile_fields.BIO_MAX})
        with self.assertRaises(ValueError):
            profile_fields.normalize({"bio": "字" * (profile_fields.BIO_MAX + 1)})
        with self.assertRaises(ValueError):
            profile_fields.normalize({"location": "x" * (profile_fields.LOCATION_MAX + 1)})

    def test_birthday(self):
        today = date(2026, 11, 15)
        self.assertEqual("2001-02-03", profile_fields.normalize({"birthday": "2001-02-03"}, today=today)["birthday"])
        self.assertIsNone(profile_fields.normalize({"birthday": ""})["birthday"])
        for bad in ("2001-2-3", "2001-02-30", "1899-12-31", "2026-11-16", 20010203):
            with self.assertRaises(ValueError, msg=bad):
                profile_fields.normalize({"birthday": bad}, today=today)

    def test_gender_and_unknown_keys(self):
        self.assertEqual("secret", profile_fields.normalize({"gender": "secret"})["gender"])
        with self.assertRaises(ValueError):
            profile_fields.normalize({"gender": "robot"})
        with self.assertRaises(ValueError):
            profile_fields.normalize({"email": "x@example.com"})


class ProfileStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="muxi-auth-")
        self.store = Store(Path(self.tmp.name) / "auth.db")
        ticket = self.store.create_external_signup(
            "qq", "czl:ProfileUser", "企鹅", "/account",
            raw_profile={"upstreams": []}, upstream_subject="openid:ProfileUser",
        )
        self.account, _ = self.store.complete_external_signup(ticket, "ProfileUser", "企鹅")

    def tearDown(self):
        self.tmp.cleanup()

    def test_new_account_has_empty_profile(self):
        profile = self.account.public()["profile"]
        self.assertEqual({"bio": "", "birthday": None, "gender": "", "location": ""}, profile)

    def test_partial_updates_merge_and_stay_out_of_claims(self):
        a = self.store.update_profile(self.account.id, "ProfileUser", "企鹅", {"bio": "hi", "birthday": "2000-01-02"})
        b = self.store.update_profile(self.account.id, "ProfileUser", "企鹅", {"location": "杭州"})
        self.assertEqual({"bio": "hi", "birthday": "2000-01-02", "gender": "", "location": "杭州"}, b.public()["profile"])
        self.assertEqual(a.public()["profile"]["bio"], "hi")
        self.assertNotIn("birthdate", b.claims())
        self.assertNotIn("profile", b.claims())
        reloaded = self.store.account_by_uid(self.account.uid)
        self.assertEqual("杭州", reloaded.location)

    def test_invalid_profile_does_not_change_username(self):
        with self.assertRaises(ValueError):
            self.store.update_profile(self.account.id, "Renamed", "企鹅", {"gender": "robot"})
        self.assertEqual("ProfileUser", self.store.account_by_uid(self.account.uid).username)


if __name__ == "__main__":
    unittest.main()
