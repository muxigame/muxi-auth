import base64
import json
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from fastapi import Request

from app import external_oauth, main
from app.external_oauth import ExternalOAuthError, ExternalProfile
from app.store import Store

ISSUER = "https://account.muxigame.com"


def id_token(**claims):
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"e30.{body}.sig"


class OidcProviderTests(unittest.TestCase):
    def setUp(self):
        self.settings = replace(external_oauth.settings, issuer=ISSUER,
                                microsoft_client_id="ms-app", microsoft_client_secret="ms-secret", microsoft_tenant="common",
                                google_client_id="g-app", google_client_secret="g-secret")
        p = patch.object(external_oauth, "settings", self.settings)
        p.start(); self.addCleanup(p.stop)

    def test_status_only_when_configured(self):
        self.assertTrue(external_oauth.provider_status()["microsoft"])
        with patch.object(external_oauth, "settings", replace(self.settings, google_client_secret="")):
            self.assertFalse(external_oauth.provider_status()["google"])
            with self.assertRaises(ExternalOAuthError):
                external_oauth.authorize_url("google", "s", "v" * 64)

    def test_authorize_urls(self):
        for provider, host in (("microsoft", "login.microsoftonline.com"), ("google", "accounts.google.com")):
            url = external_oauth.authorize_url(provider, "state-1", "v" * 64, binding=True)
            parts = urlsplit(url)
            q = parse_qs(parts.query)
            self.assertEqual(host, parts.netloc)
            self.assertEqual([f"{ISSUER}/external/{provider}/callback"], q["redirect_uri"])
            self.assertEqual(["S256"], q["code_challenge_method"])
            self.assertEqual(["select_account"], q["prompt"])
            self.assertNotIn("secret", url)
            self.assertNotIn("v" * 64, url)
        self.assertNotIn("prompt=", external_oauth.authorize_url("google", "s", "v" * 64))

    def test_bad_tenant_rejected(self):
        with patch.object(external_oauth, "settings", replace(self.settings, microsoft_tenant="../evil")):
            with self.assertRaises(ExternalOAuthError):
                external_oauth.authorize_url("microsoft", "s", "v" * 64)

    def exchange(self, provider, **claims):
        with patch.object(external_oauth, "_json_request", return_value={"access_token": "a", "id_token": id_token(**claims)}) as call:
            profile = external_oauth.exchange_profile(provider, "code", "v" * 64)
        form = parse_qs(call.call_args.args[0].data.decode())
        self.assertEqual(["v" * 64], form["code_verifier"])
        return profile

    def test_microsoft_profile(self):
        p = self.exchange("microsoft", aud="ms-app", iss="https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
                          exp=time.time() + 600, sub="abc", name="Alice", email="a@example.com", tid="9188040d-6c67-4c5b-b112-36a304b66dad")
        self.assertEqual(("microsoft", "microsoft:abc", "sub:abc", "Alice"), (p.provider, p.subject, p.upstream_subject, p.nickname))

    def test_google_profile(self):
        p = self.exchange("google", aud="g-app", iss="https://accounts.google.com", exp=time.time() + 600, sub="123", name="Bob")
        self.assertEqual("google:123", p.subject)

    def test_rejects_wrong_audience_issuer_expiry_and_missing_sub(self):
        good = dict(aud="g-app", iss="accounts.google.com", exp=time.time() + 600, sub="1")
        for bad in ({"aud": "other"}, {"iss": "https://evil.example"}, {"exp": time.time() - 3600}, {"sub": ""}):
            with self.assertRaises(ExternalOAuthError):
                self.exchange("google", **{**good, **bad})


class CallbackAndBindingTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.store = Store(Path(tmp.name) / "t.db")
        self.account, token = self.store.register("one@example.com", "PlayerOne", "玩家", "good-password-123")
        self.store.verify_email(token)
        self.session = self.store.create_web_session(self.account.id, 30)
        for target, value in ((main, "store"), ):
            p = patch.object(target, value, self.store); p.start(); self.addCleanup(p.stop)
        p = patch.object(main, "settings", replace(main.settings, issuer="http://testserver")); p.start(); self.addCleanup(p.stop)

    def request(self, session=None):
        return Request({"type": "http", "method": "GET", "path": "/", "headers": [(b"cookie", f"muxi_session={session or self.session}".encode())]})

    def bind(self, account, session, provider, subject, upstream):
        expected = self.store.binding_snapshot(account.id, provider, False)
        state, _ = self.store.create_external_state(provider, "/account", account_id=account.id, session=session, expected_id=expected)
        ticket = self.store.prepare_external_binding(self.store.consume_external_state_context(state),
                                                     {"subject": subject, "upstream_subject": upstream, "nickname": "n", "raw_profile": {}})
        self.store.finish_external_binding(ticket, account.id, session)

    def test_same_czl_account_may_hold_qq_and_wechat_on_different_accounts(self):
        # CZL merges a newly used QQ into whichever CZL account the browser is signed in to.
        second, _ = self.store.register("two@example.com", "PlayerTwo", "二", "good-password-123")
        s2 = self.store.create_web_session(second.id, 30)
        self.bind(self.account, self.session, "wechat", "czl:shared", "upstream_user_id:wx")
        self.bind(second, s2, "qq", "czl:shared", "upstream_user_id:qq")
        self.assertEqual(second.uid, self.store.external_account("qq", "czl:shared", upstream_subject="upstream_user_id:qq").uid)
        self.assertEqual(self.account.uid, self.store.external_account("wechat", "czl:shared", upstream_subject="upstream_user_id:wx").uid)

    def test_conflict_names_the_other_uid(self):
        second, _ = self.store.register("two@example.com", "PlayerTwo", "二", "good-password-123")
        s2 = self.store.create_web_session(second.id, 30)
        self.bind(second, s2, "qq", "czl:a", "upstream_user_id:qq")
        with self.assertRaisesRegex(ValueError, f"UID {second.uid}"):
            self.bind(self.account, self.session, "qq", "czl:b", "upstream_user_id:qq")

    def test_microsoft_and_google_bind_and_login(self):
        self.bind(self.account, self.session, "microsoft", "microsoft:abc", "sub:abc")
        self.bind(self.account, self.session, "google", "google:1", "sub:1")
        bindings = self.store.external_bindings(self.account.id)["bindings"]
        self.assertTrue(bindings["microsoft"]["bound"] and bindings["google"]["bound"])
        self.assertEqual(self.account.uid, self.store.external_account("google", "google:1", upstream_subject="sub:1").uid)
        # Two channels bound: either can be unlinked.
        self.store.unlink_external(self.account.id, "google", self.session)

    def test_callback_route_must_match_provider(self):
        state, _ = self.store.create_external_state("google", "/account")
        with patch.object(main, "exchange_profile") as exchange:
            response = main.external_czl_callback(self.request(), state, "code", "")
            exchange.assert_not_called()
        self.assertIn("invalid_state", response.headers["location"])

    def test_oidc_callback_new_user_goes_to_signup(self):
        state, _ = self.store.create_external_state("microsoft", "/account")
        profile = ExternalProfile("microsoft", "microsoft:new", "Alice", {"sub": "new"}, "sub:new")
        with patch.object(main, "exchange_profile", return_value=profile):
            response = main.external_oidc_callback("microsoft", self.request(), state, "code", "")
        self.assertTrue(response.headers["location"].startswith("/external/complete?ticket="))

    def test_failed_exchange_reports_reason(self):
        state, _ = self.store.create_external_state("qq", "/account", account_id=self.account.id, session=self.session)
        with patch.object(main, "exchange_profile", side_effect=external_oauth.ExternalIdentityUnclear("x")):
            response = main.external_czl_callback(self.request(), state, "code", "")
        self.assertEqual("/account?binding=failed&provider=qq&reason=unclear", response.headers["location"])


if __name__ == "__main__":
    unittest.main()
