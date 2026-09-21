from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.security import pkce_s256
from app.store import Store


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="muxi-auth-")
        self.store = Store(Path(self.tmp.name) / "auth.db")
        self.store.seed_client(
            "native",
            "Native Client",
            "public",
            ["http://127.0.0.1/oauth/callback"],
            ["openid", "profile", "email"],
        )

    def tearDown(self):
        self.tmp.cleanup()

    def verified_account(self):
        account, verify = self.store.register(
            "player@example.com", "Player_1", "玩家一号", "correct-horse-battery"
        )
        self.assertFalse(account.email_verified)
        verified = self.store.verify_email(verify)
        self.assertIsNotNone(verified)
        return verified

    def test_register_verify_login_and_web_session(self):
        account = self.verified_account()
        self.assertEqual(10000, account.uid)
        self.assertEqual("玩家一号", account.nickname)
        self.assertEqual("Player_1", account.game_name)
        self.assertEqual("Player_1", self.store.authenticate("player@example.com", "correct-horse-battery").username)
        self.assertEqual("Player_1", self.store.authenticate("10000", "correct-horse-battery").username)
        self.assertEqual("Player_1", self.store.authenticate("Player_1", "correct-horse-battery").username)
        self.assertIsNone(self.store.authenticate("player@example.com", "wrong-password"))
        token = self.store.create_web_session(account.id, 1)
        self.assertEqual(account.subject, self.store.web_session(token).subject)
        self.store.delete_web_session(token)
        self.assertIsNone(self.store.web_session(token))

    def test_username_can_change_without_changing_game_name(self):
        account = self.verified_account()
        updated = self.store.update_profile(account.id, "Player_New", "新昵称")
        self.assertEqual("Player_New", updated.username)
        self.assertEqual("新昵称", updated.nickname)
        self.assertEqual("Player_1", updated.game_name)
        self.assertEqual("Player_New", self.store.authenticate("Player_New", "correct-horse-battery").username)

    def test_uid_sequence_increments(self):
        first = self.verified_account()
        second, verify = self.store.register(
            "second@example.com", "Player_2", "玩家二号", "another-correct-password"
        )
        self.store.verify_email(verify)
        self.assertEqual(10000, first.uid)
        self.assertEqual(10001, second.uid)

    def test_external_signup_creates_passwordless_account_once(self):
        raw_profile = {
            "sub": "czl-user-1",
            "nickname": "QQ昵称",
            "upstreams": [{"provider": "qq", "openid": "qq-openid-1"}],
        }
        ticket = self.store.create_external_signup(
            "qq",
            "czl:czl-user-1",
            "QQ昵称",
            "/account",
            raw_profile=raw_profile,
            upstream_subject="openid:qq-openid-1",
        )
        signup = self.store.external_signup(ticket)
        self.assertEqual("QQ昵称", signup["provider_nickname"])
        account, continue_to = self.store.complete_external_signup(ticket, "QQPlayer", "QQ昵称")
        self.assertEqual(10000, account.uid)
        self.assertEqual("QQPlayer", account.game_name)
        self.assertIsNone(account.email)
        self.assertEqual("/account", continue_to)
        self.assertEqual(
            account.subject,
            self.store.external_account(
                "wechat",
                "czl:czl-user-1",
                raw_profile=raw_profile,
                upstream_subject="openid:qq-openid-1",
            ).subject,
        )
        with self.store.connect() as db:
            row = db.execute(
                "SELECT provider,upstream_subject,raw_profile FROM external_identities WHERE account_id=?",
                (account.id,),
            ).fetchone()
        self.assertEqual("czl", row["provider"])
        self.assertEqual("openid:qq-openid-1", row["upstream_subject"])
        self.assertIn('"upstreams"', row["raw_profile"])
        with self.assertRaises(ValueError):
            self.store.complete_external_signup(ticket, "OtherName", "Other")

    def test_pkce_authorization_code_is_one_time(self):
        account = self.verified_account()
        verifier = "a" * 64
        redirect = "http://127.0.0.1:45678/oauth/callback"
        client = self.store.client("native")
        self.assertTrue(self.store.redirect_allowed(client, redirect))
        code = self.store.create_authorization_code(
            "native", account.id, redirect, "openid profile email", pkce_s256(verifier), "nonce"
        )
        consumed = self.store.consume_authorization_code(code, "native", redirect, verifier)
        self.assertIsNotNone(consumed)
        self.assertEqual(account.subject, consumed[0].subject)
        self.assertIsNone(self.store.consume_authorization_code(code, "native", redirect, verifier))

    def test_wrong_pkce_does_not_consume_code(self):
        account = self.verified_account()
        verifier = "b" * 64
        redirect = "http://127.0.0.1:45678/oauth/callback"
        code = self.store.create_authorization_code(
            "native", account.id, redirect, "openid", pkce_s256(verifier), None
        )
        self.assertIsNone(self.store.consume_authorization_code(code, "native", redirect, "wrong" * 13))
        self.assertIsNotNone(self.store.consume_authorization_code(code, "native", redirect, verifier))

    def test_refresh_token_rotation(self):
        account = self.verified_account()
        refresh = self.store.issue_refresh_token(account.id, "native", "openid profile", 30)
        first = self.store.consume_refresh_token(refresh, "native")
        self.assertIsNotNone(first)
        self.assertIsNone(self.store.consume_refresh_token(refresh, "native"))

if __name__ == "__main__":
    unittest.main()
