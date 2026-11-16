from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from app.security import pkce_s256, token_hash
from app.store import Store, iso
from app.terminal_access import TerminalAccessStore
from app.terminal_sso import TerminalSsoStore


class PasswordResetStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="muxi-password-reset-")
        self.database = Path(self.tmp.name) / "auth.db"
        self.store = Store(self.database)
        self.now = datetime(2026, 11, 4, 12, tzinfo=timezone.utc)
        self.clock = patch("app.store.utc_now", return_value=self.now)
        self.mock_clock = self.clock.start()
        self.addCleanup(self.clock.stop)
        self.addCleanup(self.tmp.cleanup)
        self.store.seed_client("native", "Native", "public", ["http://127.0.0.1/callback"], ["openid", "profile", "email"])
        account, verify = self.store.register("player@example.com", "ResetPlayer", "Player", "original-password")
        self.account = self.store.verify_email(verify)
        self.client_hash = token_hash("synthetic-client")

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)
        self.mock_clock.return_value = self.now

    def request(self, email="player@example.com", client_hash=None, store=None):
        return (store or self.store).request_password_reset(email, client_hash or self.client_hash)

    def count(self, table, where="", params=()):
        with self.store.connect() as db:
            return db.execute(f"SELECT COUNT(*) FROM {table} {where}", params).fetchone()[0]

    def test_schema_upgrade_is_idempotent_and_preserves_existing_account(self):
        another = Store(self.database)
        self.assertEqual(self.account.subject, another.authenticate("ResetPlayer", "original-password").subject)
        self.assertEqual(0, self.count("password_resets"))
        self.assertEqual(0, self.count("password_reset_requests"))

    def test_ticket_is_hashed_short_lived_and_request_preserves_password_and_sessions(self):
        session = self.store.create_web_session(self.account.id, 1)
        account, raw = self.request("  PLAYER@example.com  ")
        self.assertEqual(self.account.id, account.id)
        self.assertRegex(raw, r"^[A-Za-z0-9_-]{43}$")
        with self.store.connect() as db:
            row = dict(db.execute("SELECT * FROM password_resets").fetchone())
            request = dict(db.execute("SELECT * FROM password_reset_requests").fetchone())
        self.assertEqual(token_hash(raw), row["token_hash"])
        self.assertNotIn(raw, row.values())
        self.assertEqual(token_hash("player@example.com"), row["email_hash"])
        self.assertEqual(iso(self.now + timedelta(minutes=15)), row["expires_at"])
        self.assertNotIn("player@example.com", request.values())
        self.assertEqual(self.client_hash, request["client_hash"])
        self.assertIsNotNone(self.store.authenticate("ResetPlayer", "original-password"))
        self.assertIsNotNone(self.store.web_session(session))

    def test_only_current_verified_primary_email_can_request_and_redeem(self):
        unverified, _ = self.store.register("unverified@example.com", "Unverified", "U", "original-password")
        self.assertIsNone(self.request("unverified@example.com"))
        self.assertIsNone(self.request("unknown@example.com"))
        self.assertEqual(2, self.count("password_reset_requests"))
        self.assertEqual(0, self.count("password_resets"))
        _, raw = self.request()
        with self.store.connect() as db:
            db.execute("UPDATE account_emails SET email='replacement@example.com' WHERE account_id=?", (self.account.id,))
        self.assertIsNone(self.store.consume_password_reset(raw, "replacement-password"))
        with self.store.connect() as db:
            db.execute("UPDATE account_emails SET email='player@example.com',verified=0 WHERE account_id=?", (self.account.id,))
        self.assertIsNone(self.store.consume_password_reset(raw, "replacement-password"))
        self.assertEqual(1, self.count("password_resets"))

    def test_verified_passwordless_account_can_set_password(self):
        with self.store.connect() as db:
            db.execute("UPDATE accounts SET password_hash=NULL WHERE id=?", (self.account.id,))
        _, raw = self.request()
        account = self.store.consume_password_reset(raw, "replacement-password")
        self.assertEqual(self.account.subject, account.subject)
        self.assertIsNotNone(self.store.authenticate("ResetPlayer", "replacement-password"))

    def test_invalid_expired_and_replayed_tickets_do_not_hash_or_mutate_password(self):
        _, raw = self.request()
        with patch("app.store.hash_password") as hashing:
            for invalid in ("", "short", "!" * 43, "x" * 43, "x" * 10000):
                self.assertIsNone(self.store.consume_password_reset(invalid, "replacement-password"))
            with self.assertRaises(ValueError):
                self.store.consume_password_reset(raw, "short")
            with self.assertRaises(ValueError):
                self.store.consume_password_reset(raw, "p" * 129)
            hashing.assert_not_called()
        self.advance(900)
        with patch("app.store.hash_password") as hashing:
            self.assertIsNone(self.store.consume_password_reset(raw, "replacement-password"))
            hashing.assert_not_called()
        self.assertIsNotNone(self.store.authenticate("ResetPlayer", "original-password"))
        self.advance(1)
        _, fresh = self.request()
        self.assertIsNotNone(self.store.consume_password_reset(fresh, "replacement-password"))
        self.assertIsNone(self.store.consume_password_reset(fresh, "another-password"))
        self.assertIsNone(self.store.authenticate("ResetPlayer", "original-password"))
        self.assertIsNotNone(self.store.authenticate("ResetPlayer", "replacement-password"))

    def test_new_ticket_replaces_old_and_cancel_cannot_delete_newer_ticket(self):
        _, old = self.request()
        self.advance(60)
        _, new = self.request()
        self.assertFalse(self.store.cancel_password_reset(old))
        self.assertIsNone(self.store.consume_password_reset(old, "replacement-password"))
        self.assertEqual(1, self.count("password_resets"))
        self.assertTrue(self.store.cancel_password_reset(new))
        self.assertIsNone(self.store.consume_password_reset(new, "replacement-password"))
        self.assertIsNotNone(self.store.authenticate("ResetPlayer", "original-password"))

    def _seed_authority(self, account, suffix):
        session = self.store.create_web_session(account.id, 1)
        access = self.store.issue_access_token(account.id, "native", "openid profile", 3600)
        refresh = self.store.issue_refresh_token(account.id, "native", "openid profile", 30)
        code = self.store.create_authorization_code("native", account.id, "http://127.0.0.1/callback", "openid", pkce_s256("v" * 43), None)
        expires = iso(self.now + timedelta(hours=1))
        with self.store.connect() as db:
            db.execute("INSERT INTO terminal_bootstraps VALUES(?,?,?,?)", (token_hash("bootstrap-" + suffix), account.id, token_hash(access), expires))
            db.execute("INSERT INTO terminal_proofs VALUES(?,?,?,?,?,?,?)", (token_hash("proof-" + suffix), token_hash("bootstrap-" + suffix), "challenge", "request", "purpose", "target", expires))
            db.execute("INSERT INTO terminal_tickets VALUES(?,?,?,?,?,?,?,?,?)", (token_hash("ticket-" + suffix), token_hash("bootstrap-" + suffix), "challenge", "request", "purpose", "target", "server", suffix, expires))
            db.execute("INSERT INTO terminal_access_requests VALUES(?,?,?,?,?,?)", (suffix, "server", suffix, account.id, token_hash(access), expires))
            db.execute("INSERT INTO terminal_access_connections VALUES(?,?,?,?)", ("server", suffix, account.id, token_hash(access)))
            db.execute("INSERT INTO external_binding_pending VALUES(?,?,?,?,?,?,?)", (token_hash("binding-" + suffix), account.id, token_hash(session), "qq", None, "{}", expires))
            db.execute("INSERT INTO external_oauth_states(state_hash,provider,code_verifier,continue_to,created_at,expires_at,account_id) VALUES(?,?,?,?,?,?,?)", (token_hash("state-" + suffix), "qq", "verifier", "/account", iso(self.now), expires, account.id))
        return session, access, refresh, code

    def test_consumption_atomically_revokes_all_authority_and_preserves_other_account(self):
        TerminalSsoStore(self.store)
        TerminalAccessStore(self.store)
        other, verify = self.store.register("other@example.com", "OtherPlayer", "Other", "other-original-password")
        other = self.store.verify_email(verify)
        mine = self._seed_authority(self.account, "mine")
        theirs = self._seed_authority(other, "theirs")
        _, raw = self.request()
        reset = self.store.consume_password_reset(raw, "replacement-password")
        self.assertEqual(self.account.id, reset.id)
        self.assertIsNone(self.store.web_session(mine[0]))
        self.assertIsNone(self.store.access_token(mine[1]))
        self.assertIsNone(self.store.consume_refresh_token(mine[2], "native"))
        self.assertIsNone(self.store.consume_authorization_code(mine[3], "native", "http://127.0.0.1/callback", "v" * 43))
        for table in ("password_resets", "web_sessions", "authorization_codes", "external_binding_pending", "external_oauth_states", "terminal_bootstraps", "terminal_access_requests", "terminal_access_connections"):
            self.assertEqual(0, self.count(table, "WHERE account_id=?", (self.account.id,)), table)
        for table in ("terminal_proofs", "terminal_tickets"):
            self.assertEqual(1, self.count(table), table)
        self.assertIsNotNone(self.store.web_session(theirs[0]))
        self.assertIsNotNone(self.store.access_token(theirs[1]))
        self.assertIsNotNone(self.store.consume_refresh_token(theirs[2], "native"))

    def test_failure_rolls_back_password_ticket_and_session_revocations(self):
        session = self.store.create_web_session(self.account.id, 1)
        _, raw = self.request()
        with patch.object(self.store, "_revoke_password_reset_sessions", side_effect=RuntimeError("synthetic database failure")):
            with self.assertRaises(RuntimeError):
                self.store.consume_password_reset(raw, "replacement-password")
        self.assertIsNotNone(self.store.authenticate("ResetPlayer", "original-password"))
        self.assertIsNotNone(self.store.web_session(session))
        self.assertEqual(1, self.count("password_resets"))
        self.assertIsNotNone(self.store.consume_password_reset(raw, "replacement-password"))

    def test_reset_revokes_existing_identity_signup_tickets_without_touching_other_channels(self):
        with self.store.connect() as db:
            db.execute("INSERT INTO external_identities(account_id,provider,provider_subject,upstream_subject,created_at) VALUES(?,?,?,?,?)",
                (self.account.id, "qq", "broker:original", "openid:original", iso(self.now)))
            db.execute("INSERT INTO external_identities(account_id,provider,provider_subject,upstream_subject,created_at) VALUES(?,?,?,?,?)",
                (self.account.id, "wechat", "broker:empty", "", iso(self.now)))
        by_broker = self.store.create_external_signup("qq", "broker:original", "Player", "/account", upstream_subject="openid:original")
        by_upstream = self.store.create_external_signup("qq", "broker:changed", "Player", "/account", upstream_subject="openid:original")
        same_broker_channel = self.store.create_external_signup("wechat", "broker:original", "Player", "/account", upstream_subject="openid:another")
        unrelated = self.store.create_external_signup("wechat", "broker:unrelated", "Other", "/account", upstream_subject="openid:original")
        unrelated_empty = self.store.create_external_signup("wechat", "broker:empty-other", "Other", "/account", upstream_subject="")
        _, raw = self.request()
        self.assertIsNotNone(self.store.consume_password_reset(raw, "replacement-password"))
        for ticket in (by_broker, by_upstream, same_broker_channel):
            self.assertIsNone(self.store.external_signup(ticket))
            with self.assertRaises(ValueError):
                self.store.complete_external_signup(ticket, "MustNotResume", "Player")
        self.assertIsNotNone(self.store.external_signup(unrelated))
        self.assertIsNotNone(self.store.external_signup(unrelated_empty))

    def test_persistent_email_cooldown_and_hour_limit_do_not_depend_on_account_existence(self):
        second = Store(self.database)
        self.assertIsNotNone(self.request())
        self.assertIsNone(self.request(store=second, client_hash=token_hash("another-client")))
        for seconds in (60, 60):
            self.advance(seconds)
            self.assertIsNotNone(self.request())
        self.advance(60)
        self.assertIsNone(self.request())
        self.assertEqual(3, self.count("password_reset_requests"))
        self.assertIsNone(self.request("unknown@example.com"))
        self.assertEqual(4, self.count("password_reset_requests"))
        self.assertIsNone(self.request("UNKNOWN@example.com", client_hash=token_hash("third-client")))
        self.assertEqual(4, self.count("password_reset_requests"))

    def test_client_limit_global_bound_and_ttl_cleanup(self):
        for number in range(10):
            self.assertIsNone(self.request(f"unknown{number}@example.com"))
        self.assertIsNone(self.request("player@example.com"))
        self.assertEqual(10, self.count("password_reset_requests"))
        for number in range(90):
            self.request(f"global{number}@example.com", token_hash(f"client-{number}"))
        self.assertEqual(100, self.count("password_reset_requests"))
        self.assertIsNone(self.request(client_hash=token_hash("fresh-client")))
        self.assertEqual(100, self.count("password_reset_requests"))
        self.advance(3600)
        self.assertIsNotNone(self.request(client_hash=token_hash("fresh-client")))
        self.assertEqual(1, self.count("password_reset_requests"))

    def test_parallel_workers_issue_only_one_ticket_and_consume_once(self):
        second = Store(self.database)
        barrier = threading.Barrier(2)
        def request(store, client):
            barrier.wait(timeout=5)
            return store.request_password_reset("player@example.com", token_hash(client))
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda pair: request(*pair), ((self.store, "one"), (second, "two"))))
        issued = [item for item in results if item]
        self.assertEqual(1, len(issued))
        self.assertEqual(1, self.count("password_reset_requests"))
        raw = issued[0][1]
        barrier = threading.Barrier(2)
        def consume(store):
            barrier.wait(timeout=5)
            return store.consume_password_reset(raw, "replacement-password")
        with ThreadPoolExecutor(max_workers=2) as pool:
            consumed = list(pool.map(consume, (self.store, second)))
        self.assertEqual(1, sum(item is not None for item in consumed))

    def test_login_session_issuance_is_serialized_with_reset(self):
        _, raw = self.request()
        second = Store(self.database)
        entered, release = threading.Event(), threading.Event()
        original = self.store._authenticate_in_transaction
        def pause_after_password(*args):
            account = original(*args)
            entered.set()
            if not release.wait(timeout=5):
                raise RuntimeError("test did not release password check")
            return account
        with patch.object(self.store, "_authenticate_in_transaction", side_effect=pause_after_password):
            with ThreadPoolExecutor(max_workers=2) as pool:
                login = pool.submit(self.store.authenticate_web_session, "ResetPlayer", "original-password", 1)
                self.assertTrue(entered.wait(timeout=5))
                reset = pool.submit(second.consume_password_reset, raw, "replacement-password")
                release.set()
                account, session = login.result(timeout=10)
                self.assertIsNotNone(reset.result(timeout=10))
        self.assertIsNone(self.store.web_session(session))
        self.assertIsNone(self.store.authenticate_web_session("ResetPlayer", "original-password", 1))
        self.assertIsNotNone(self.store.authenticate_web_session(" ResetPlayer ", "replacement-password", 1))

    def test_session_checked_code_issuance_rejects_session_revoked_by_reset(self):
        session = self.store.create_web_session(self.account.id, 1)
        _, raw = self.request()
        self.store.consume_password_reset(raw, "replacement-password")
        with self.assertRaisesRegex(ValueError, "login_required"):
            self.store.create_authorization_code("native", self.account.id, "http://127.0.0.1/callback", "openid", pkce_s256("v" * 43), None, session=session)
        self.assertEqual(0, self.count("authorization_codes"))

    def test_atomic_oauth_exchange_rotation_scope_and_reset(self):
        session = self.store.create_web_session(self.account.id, 1)
        code = self.store.create_authorization_code("native", self.account.id, "http://127.0.0.1/callback", "openid profile", pkce_s256("v" * 43), "nonce", session=session)
        args = (code, "native", "http://127.0.0.1/callback")
        self.assertIsNone(self.store.exchange_authorization_code(*args, "wrong", 3600, 30))
        exchanged = self.store.exchange_authorization_code(*args, "v" * 43, 3600, 30)
        account, scope, nonce, access, refresh = exchanged
        self.assertEqual((self.account.id, "openid profile", "nonce"), (account.id, scope, nonce))
        self.assertIsNotNone(self.store.access_token(access))
        self.assertIsNone(self.store.exchange_authorization_code(*args, "v" * 43, 3600, 30))
        with self.assertRaisesRegex(ValueError, "invalid_scope"):
            self.store.rotate_refresh_token(refresh, "native", "openid admin", 3600, 30)
        rotated = self.store.rotate_refresh_token(refresh, "native", "profile", 3600, 30)
        self.assertEqual("profile", rotated[1])
        self.assertIsNone(self.store.rotate_refresh_token(refresh, "native", None, 3600, 30))
        _, raw = self.request()
        self.store.consume_password_reset(raw, "replacement-password")
        self.assertIsNone(self.store.access_token(rotated[2]))
        self.assertIsNone(self.store.rotate_refresh_token(rotated[3], "native", None, 3600, 30))


if __name__ == "__main__":
    unittest.main()
