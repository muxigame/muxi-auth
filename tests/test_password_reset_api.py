from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from app.password_reset import MESSAGE, password_reset_router, reset_issuer, send_email
from app.security import token_hash
from app.store import Store


class PasswordResetApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="muxi-reset-api-")
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "auth.db")
        self.account, verify = self.store.register("recovery@example.com", "RecoveryOne", "恢复测试", "original-password-123")
        self.store.verify_email(verify)
        self.settings = replace(Settings(), issuer="https://account.muxigame.com", smtp_host="smtp.example.com", smtp_username="test-user", smtp_password="test-smtp-password", dev_verify=False)
        self.app = FastAPI()
        self.app.include_router(password_reset_router(lambda: self.settings, lambda: self.store))
        self.client = TestClient(self.app, base_url="https://account.muxigame.com")
        self.addCleanup(self.client.close)
        self.headers = {"Origin": self.settings.issuer, "X-Muxi-Account-Action": "1", "X-Real-IP": "192.0.2.8"}

    def request_mail(self, email="recovery@example.com"):
        return self.client.post("/api/account/password-reset/request", json={"email": email}, headers=self.headers)

    def confirm(self, token, password="new-password-456", confirm=None):
        return self.client.post("/api/account/password-reset/confirm", headers=self.headers, json={
            "token": token, "password": password, "password_confirm": password if confirm is None else confirm,
        })

    def test_delivery_uses_fixed_https_fragment_and_uniform_response(self):
        messages = []
        with patch("app.password_reset.send_email", side_effect=lambda *args: messages.append(args)):
            response = self.request_mail()
        self.assertEqual(202, response.status_code)
        self.assertEqual({"ok": True, "message": MESSAGE}, response.json())
        self.assertEqual(1, len(messages))
        _, recipient, subject, body = messages[0]
        self.assertEqual("recovery@example.com", recipient)
        link = next(line for line in body.splitlines() if line.startswith("https://"))
        parsed = urlsplit(link)
        self.assertEqual("account.muxigame.com", parsed.netloc)
        self.assertEqual("/reset-password", parsed.path)
        self.assertEqual("", parsed.query)
        raw = parse_qs(parsed.fragment)["token"][0]
        self.assertEqual(43, len(raw))
        self.assertNotIn(raw, response.text)
        self.assertNotIn("original-password-123", body)
        with self.store.connect() as db:
            self.assertIsNotNone(db.execute("SELECT 1 FROM password_resets WHERE token_hash=?", (token_hash(raw),)).fetchone())

    def test_unknown_and_throttled_addresses_have_same_response(self):
        with patch("app.password_reset.send_email") as send:
            known = self.request_mail()
            throttled = self.request_mail()
            unknown = self.request_mail("unknown@example.com")
        self.assertEqual(known.status_code, unknown.status_code)
        self.assertEqual(known.content, unknown.content)
        self.assertEqual(known.content, throttled.content)
        self.assertEqual(1, send.call_count)

    def test_mail_failure_cancels_only_issued_link_and_hides_exception(self):
        with patch("app.password_reset.send_email", side_effect=RuntimeError("secret-token smtp-password recipient@example.com")):
            with self.assertLogs("app.password_reset", level="WARNING") as logs:
                response = self.request_mail()
        self.assertEqual(202, response.status_code)
        self.assertEqual(MESSAGE, response.json()["message"])
        output = " ".join(logs.output) + response.text
        self.assertNotIn("smtp-password", output)
        self.assertNotIn("recipient@example.com", output)
        self.assertNotIn("secret-token", output)
        with self.store.connect() as db:
            self.assertEqual(0, db.execute("SELECT COUNT(*) FROM password_resets").fetchone()[0])
        self.assertIsNotNone(self.store.authenticate("RecoveryOne", "original-password-123"))

    def test_valid_reset_changes_password_revokes_session_and_notifies(self):
        session = self.store.create_web_session(self.account.id, 30)
        _, raw = self.store.request_password_reset("recovery@example.com", "f" * 64)
        with patch("app.password_reset.send_email") as send:
            response = self.confirm(raw)
        self.assertEqual(200, response.status_code)
        self.assertIsNone(self.store.authenticate("RecoveryOne", "original-password-123"))
        self.assertIsNotNone(self.store.authenticate("RecoveryOne", "new-password-456"))
        self.assertIsNone(self.store.web_session(session))
        self.assertIn("Max-Age=0", response.headers["set-cookie"])
        self.assertNotIn(raw, response.text)
        self.assertNotIn("new-password-456", send.call_args.args[-1])
        self.assertNotIn(raw, send.call_args.args[-1])
        self.assertEqual(400, self.confirm(raw).status_code)

    def test_notification_failure_does_not_undo_success_or_log_secret(self):
        _, raw = self.store.request_password_reset("recovery@example.com", "e" * 64)
        with patch("app.password_reset.send_email", side_effect=RuntimeError("smtp-secret")):
            with self.assertLogs("app.password_reset", level="WARNING") as logs:
                response = self.confirm(raw)
        self.assertEqual(200, response.status_code)
        self.assertNotIn("smtp-secret", " ".join(logs.output))
        self.assertEqual(400, self.confirm(raw).status_code)

    def test_same_origin_and_action_header_are_required(self):
        for headers in ({}, {"Origin": self.settings.issuer}, {"Origin": "https://attacker.example", "X-Muxi-Account-Action": "1"}):
            for route, data in (("request", {"email": "recovery@example.com"}), ("confirm", {"token": "a" * 43, "password": "new-password-456", "password_confirm": "new-password-456"})):
                response = self.client.post("/api/account/password-reset/" + route, headers=headers, json=data)
                self.assertEqual(403, response.status_code)

    def test_validation_does_not_echo_secret_inputs(self):
        response = self.confirm("sensitive-token", "tiny")
        self.assertEqual(422, response.status_code)
        self.assertNotIn("sensitive-token", response.text)
        self.assertNotIn("tiny", response.text)
        response = self.confirm("a" * 43, "new-password-456", "different-password")
        self.assertEqual(422, response.status_code)
        self.assertEqual(413, self.client.post("/api/account/password-reset/request", content=b"x" * 4097, headers={**self.headers, "Content-Type": "application/json"}).status_code)

    def test_recovery_pages_are_private_and_external_queries_do_not_change_origin(self):
        for path in ("/forgot-password", "/reset-password?continue=https://attacker.example"):
            response = self.client.get(path)
            self.assertEqual(200, response.status_code)
            self.assertEqual("no-store", response.headers["cache-control"])
            self.assertEqual("no-referrer", response.headers["referrer-policy"])
        for issuer in ("https://attacker.example", "https://account.muxigame.com@attacker.example", "https://account.muxigame.com/path", "http://account.muxigame.com"):
            with self.assertRaises(ValueError):
                reset_issuer(replace(self.settings, issuer=issuer))

    def test_smtp_transport_verifies_tls_for_ssl_and_starttls(self):
        for implicit_tls in (True, False):
            factory_name = "SMTP_SSL" if implicit_tls else "SMTP"
            smtp = Mock()
            connection = Mock()
            connection.__enter__ = Mock(return_value=smtp)
            connection.__exit__ = Mock(return_value=False)
            with patch("app.password_reset.smtplib." + factory_name, return_value=connection) as factory:
                send_email(replace(self.settings, smtp_ssl=implicit_tls), "recovery@example.com", "test", "test body")
            context = factory.call_args.kwargs["context"] if implicit_tls else smtp.starttls.call_args.kwargs["context"]
            self.assertTrue(context.check_hostname)
            self.assertEqual(2, context.verify_mode)
            smtp.login.assert_called_once_with("test-user", "test-smtp-password")
            smtp.send_message.assert_called_once()


if __name__ == "__main__":
    unittest.main()
