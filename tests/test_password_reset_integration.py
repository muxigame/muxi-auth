"""HTTP integration checks with synthetic identities, temporary state and no WAN.

Import-time account state is isolated too: never read a repository .env or reuse
the developer's database/signing key. Mail is captured in memory, not delivered.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import tempfile
import unittest
from contextlib import ExitStack
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit


_BOOTSTRAP = tempfile.TemporaryDirectory(prefix="muxi-reset-http-import-")
_BOOTSTRAP_ROOT = Path(_BOOTSTRAP.name)
_REAL_IS_FILE = Path.is_file
_REAL_CONNECT = socket.socket.connect
_REAL_CONNECT_EX = socket.socket.connect_ex
_REAL_GETADDRINFO = socket.getaddrinfo


def _without_dotenv(path):
    return False if path.name == ".env" else _REAL_IS_FILE(path)


def _loopback_only(address):
    if not isinstance(address, tuple) or not address:
        return False
    try:
        return ipaddress.ip_address(address[0]).is_loopback
    except ValueError:
        return address[0] == "localhost"


def _no_wan_connect(sock, address):
    if not _loopback_only(address):
        raise AssertionError("External network is disabled in recovery integration tests")
    return _REAL_CONNECT(sock, address)


def _no_wan_connect_ex(sock, address):
    if not _loopback_only(address):
        raise AssertionError("External network is disabled in recovery integration tests")
    return _REAL_CONNECT_EX(sock, address)


def _no_wan_dns(host, *args, **kwargs):
    if host is not None and not _loopback_only((host, 0)):
        raise AssertionError("External DNS is disabled in recovery integration tests")
    return _REAL_GETADDRINFO(host, *args, **kwargs)


_IMPORT_ENV = {name: os.environ[name] for name in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP") if name in os.environ}
_IMPORT_ENV.update({
    "MUXI_ISSUER": "https://account.muxigame.com",
    "MUXI_DATABASE_PATH": str(_BOOTSTRAP_ROOT / "auth.db"),
    "MUXI_SIGNING_KEY_PATH": str(_BOOTSTRAP_ROOT / "signing.pem"),
    "MUXI_AUTH_DEV_VERIFY": "0",
    "MUXI_TERMINAL_SSO_ENABLED": "0",
    "MUXI_SMTP_HOST": "",
})
with patch.dict(os.environ, _IMPORT_ENV, clear=True), patch.object(Path, "is_file", _without_dotenv), \
        patch.object(socket.socket, "connect", _no_wan_connect), \
        patch.object(socket.socket, "connect_ex", _no_wan_connect_ex), \
        patch.object(socket, "getaddrinfo", _no_wan_dns):
    from fastapi.testclient import TestClient
    from app import main
    from app.security import OidcSigner, pkce_s256, utc_now
    from app.store import Store, iso


class PasswordResetHttpIntegrationTests(unittest.TestCase):
    ORIGIN = "https://account.muxigame.com"
    CLIENT_ID = "isolated-recovery-native"
    REDIRECT = "http://127.0.0.1/callback"
    VERIFIER = "integration-proof-" + "v" * 43
    OLD_PASSWORD = "synthetic-original-password"
    NEW_PASSWORD = "synthetic-replacement-password"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="muxi-reset-http-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.store = Store(root / "auth.db")
        account, verify = self.store.register("integration@example.com", "HttpRecovery", "HTTP fixture", self.OLD_PASSWORD)
        self.account = self.store.verify_email(verify)
        self.assertEqual(account.subject, self.account.subject)
        self.store.seed_client(self.CLIENT_ID, "Isolated recovery fixture", "public", [self.REDIRECT], ["openid", "profile", "email"])
        self.messages = []
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(Path, "is_file", _without_dotenv))
        self.stack.enter_context(patch.object(socket.socket, "connect", _no_wan_connect))
        self.stack.enter_context(patch.object(socket.socket, "connect_ex", _no_wan_connect_ex))
        self.stack.enter_context(patch.object(socket, "getaddrinfo", _no_wan_dns))
        self.stack.enter_context(patch.object(main, "store", self.store))
        settings = replace(main.settings, issuer=self.ORIGIN, database_path=root / "auth.db",
            signing_key_path=root / "signing.pem", terminal_sso_enabled=False,
            smtp_host="smtp.invalid", smtp_username="isolated-fixture", smtp_password="synthetic-mail-password",
            smtp_from="fixture@example.invalid", dev_verify=False)
        self.stack.enter_context(patch.object(main, "settings", settings))
        self.stack.enter_context(patch.object(main, "signer", OidcSigner(root / "signing.pem")))
        self.stack.enter_context(patch("app.password_reset.send_email", side_effect=lambda *args: self.messages.append(args)))
        self.client = TestClient(main.app, base_url=self.ORIGIN)
        self.addCleanup(self.client.close)
        self.action_headers = {"Origin": self.ORIGIN, "X-Muxi-Account-Action": "1", "X-Real-IP": "192.0.2.55"}

    def login(self, password=None):
        return self.client.post("/api/account/login", json={"identity": "HttpRecovery", "password": password or self.OLD_PASSWORD})

    def authorization_parameters(self):
        return {"client_id": self.CLIENT_ID, "redirect_uri": self.REDIRECT, "response_type": "code",
            "scope": "openid profile email", "state": "synthetic-state", "nonce": "synthetic-nonce",
            "code_challenge": pkce_s256(self.VERIFIER), "code_challenge_method": "S256"}

    def authorize(self, **kwargs):
        return self.client.get("/oauth/authorize", params=self.authorization_parameters(), follow_redirects=False, **kwargs)

    def code(self):
        response = self.authorize()
        self.assertEqual(303, response.status_code)
        location = urlsplit(response.headers["location"])
        self.assertEqual("127.0.0.1", location.hostname)
        query = parse_qs(location.query)
        self.assertEqual(["synthetic-state"], query["state"])
        return query["code"][0]

    def exchange(self, code, verifier=None):
        return self.client.post("/oauth/token", data={"client_id": self.CLIENT_ID,
            "grant_type": "authorization_code", "redirect_uri": self.REDIRECT, "code": code,
            "code_verifier": self.VERIFIER if verifier is None else verifier})

    def refresh(self, token, scope=None):
        data = {"client_id": self.CLIENT_ID, "grant_type": "refresh_token", "refresh_token": token}
        if scope is not None:
            data["scope"] = scope
        return self.client.post("/oauth/token", data=data)

    def request_and_confirm_reset(self):
        requested = self.client.post("/api/account/password-reset/request", headers=self.action_headers,
            json={"email": "integration@example.com"})
        self.assertEqual(202, requested.status_code)
        self.assertEqual(1, len(self.messages))
        link = next(line for line in self.messages[0][-1].splitlines() if line.startswith("https://"))
        parsed = urlsplit(link)
        self.assertEqual(self.ORIGIN + "/reset-password", parsed.scheme + "://" + parsed.netloc + parsed.path)
        self.assertEqual("", parsed.query)
        token = parse_qs(parsed.fragment)["token"][0]
        response = self.client.post("/api/account/password-reset/confirm", headers=self.action_headers,
            json={"token": token, "password": self.NEW_PASSWORD, "password_confirm": self.NEW_PASSWORD})
        self.assertEqual(200, response.status_code)
        self.assertNotIn(token, response.text)
        self.assertEqual(2, len(self.messages))
        self.assertNotIn(self.NEW_PASSWORD, self.messages[-1][-1])
        return response

    def test_reset_rejects_old_http_session_code_access_refresh_and_password(self):
        self.assertEqual(200, self.login().status_code)
        old_session = self.client.cookies.get("muxi_session")
        minted = self.exchange(self.code())
        self.assertEqual(200, minted.status_code)
        credentials = minted.json()
        unused_code = self.code()
        self.request_and_confirm_reset()
        self.assertEqual(401, self.client.get("/api/account/me", headers={"Cookie": "muxi_session=" + old_session}).status_code)
        userinfo = self.client.get("/oauth/userinfo", headers={"Authorization": "Bearer " + credentials["access_token"]})
        self.assertEqual(401, userinfo.status_code)
        self.assertEqual("invalid_token", userinfo.json()["error"])
        for response in (self.refresh(credentials["refresh_token"]), self.exchange(unused_code)):
            self.assertEqual(400, response.status_code)
            self.assertEqual("invalid_grant", response.json()["error"])
        self.assertEqual(401, self.login(self.OLD_PASSWORD).status_code)
        self.assertEqual(200, self.login(self.NEW_PASSWORD).status_code)
        self.assertEqual(200, self.exchange(self.code()).status_code)

    def test_login_uses_the_atomic_session_method(self):
        with patch.object(self.store, "authenticate", side_effect=AssertionError("Legacy split login must not be called")), \
                patch.object(self.store, "create_web_session", side_effect=AssertionError("Legacy split issuance must not be called")):
            response = self.login()
        self.assertEqual(200, response.status_code)
        self.assertEqual(self.account.uid, response.json()["user"]["uid"])
        self.assertIsNotNone(self.client.cookies.get("muxi_session"))

    def test_pkce_code_is_one_use_and_does_not_call_legacy_minting(self):
        self.assertEqual(200, self.login().status_code)
        code = self.code()
        with patch.object(self.store, "consume_authorization_code", side_effect=AssertionError("Legacy code consumption must not be called")), \
                patch.object(self.store, "issue_access_token", side_effect=AssertionError("Split access issuance must not be called")), \
                patch.object(self.store, "issue_refresh_token", side_effect=AssertionError("Split refresh issuance must not be called")):
            wrong = self.exchange(code, "wrong-verifier")
            self.assertEqual(400, wrong.status_code)
            self.assertEqual("invalid_grant", wrong.json()["error"])
            valid = self.exchange(code)
        self.assertEqual(200, valid.status_code)
        self.assertEqual("no-store", valid.headers["cache-control"])
        self.assertEqual("Bearer", valid.json()["token_type"])
        self.assertIn("id_token", valid.json())
        self.assertEqual(400, self.exchange(code).status_code)

    def test_refresh_rejects_scope_escalation_without_consuming_original(self):
        self.assertEqual(200, self.login().status_code)
        tokens = self.exchange(self.code()).json()
        with patch.object(self.store, "consume_refresh_token", side_effect=AssertionError("Legacy refresh consumption must not be called")), \
                patch.object(self.store, "issue_access_token", side_effect=AssertionError("Split access issuance must not be called")), \
                patch.object(self.store, "issue_refresh_token", side_effect=AssertionError("Split refresh issuance must not be called")):
            invalid = self.refresh(tokens["refresh_token"], "openid admin")
            self.assertEqual(400, invalid.status_code)
            self.assertEqual("invalid_scope", invalid.json()["error"])
            narrowed = self.refresh(tokens["refresh_token"], "openid profile")
        self.assertEqual(200, narrowed.status_code)
        self.assertEqual({"openid", "profile"}, set(narrowed.json()["scope"].split()))
        self.assertEqual(400, self.refresh(tokens["refresh_token"]).status_code)
        retained = self.refresh(narrowed.json()["refresh_token"], "   ")
        self.assertEqual(200, retained.status_code)
        self.assertEqual({"openid", "profile"}, set(retained.json()["scope"].split()))

    def test_expired_web_session_redirects_authorize_to_login(self):
        self.assertEqual(200, self.login().status_code)
        with self.store.connect() as db:
            db.execute("UPDATE web_sessions SET expires_at=?", (iso(utc_now() - timedelta(seconds=1)),))
        response = self.authorize()
        self.assertEqual(303, response.status_code)
        location = urlsplit(response.headers["location"])
        self.assertEqual("/login", location.path)
        self.assertTrue(parse_qs(location.query)["continue"][0].startswith("/oauth/authorize?"))

    def test_stale_first_session_lookup_is_rechecked_when_minting_code(self):
        self.assertEqual(200, self.login().status_code)
        with self.store.connect() as db:
            db.execute("UPDATE web_sessions SET expires_at=?", (iso(utc_now() - timedelta(seconds=1)),))
        # Model a reset/expiry after the route's first account lookup. Code
        # issuance must still reject the stale cookie in its own transaction.
        with patch.object(main, "current_web_account", return_value=self.account):
            response = self.authorize()
        self.assertEqual(303, response.status_code)
        self.assertEqual("/login", urlsplit(response.headers["location"]).path)
        with self.store.connect() as db:
            self.assertEqual(0, db.execute("SELECT COUNT(*) FROM authorization_codes").fetchone()[0])


if __name__ == "__main__":
    unittest.main()
