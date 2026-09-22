from dataclasses import replace
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

from fastapi import Request

from app import external_oauth
from app.config import settings
from scripts.check_external_auth import check_redirect


ISSUER = "https://account.muxigame.com"
STATE = "test-state-with_-characters"
VERIFIER = "v" * 64


class ExternalEntryTests(unittest.TestCase):
    def setUp(self):
        self.settings = replace(
            settings,
            issuer=ISSUER,
            czl_client_id="test-client-id",
            czl_client_secret="never-include-this-secret",
            czl_authorize_endpoint="https://connect.czl.net/oauth2/authorize",
            czl_direct_upstream=True,
        )
        self.config_patch = patch.object(external_oauth, "settings", self.settings)
        self.config_patch.start()
        self.addCleanup(self.config_patch.stop)

    def entry(self, provider="qq", user_agent=""):
        return external_oauth.authorize_url(provider, STATE, VERIFIER, user_agent=user_agent)

    def inner(self, entry):
        return parse_qs(urlsplit(parse_qs(urlsplit(entry).query)["redirect"][0]).query)

    def test_qq_goes_to_provider_endpoint_without_login_screen(self):
        entry = self.entry()
        self.assertEqual("https", urlsplit(entry).scheme)
        self.assertEqual("connect.czl.net", urlsplit(entry).netloc)
        self.assertEqual("/api/auth/upstream/qq", urlsplit(entry).path)
        self.assertNotIn("device", parse_qs(urlsplit(entry).query))
        check_redirect("qq", 303, entry, ISSUER)

    def test_entire_authorization_request_survives_nested_encoding(self):
        inner = self.inner(self.entry())
        self.assertEqual([STATE], inner["state"])
        self.assertEqual([external_oauth.pkce_s256(VERIFIER)], inner["code_challenge"])
        self.assertEqual(["S256"], inner["code_challenge_method"])
        self.assertEqual([ISSUER + "/external/czl/callback"], inner["redirect_uri"])
        self.assertEqual(["openid profile email"], inner["scope"])
        self.assertEqual(["qq"], inner["upstream_providers"])
        self.assertEqual(["test-client-id"], inner["client_id"])
        self.assertEqual(["code"], inner["response_type"])

    def test_no_secret_or_verifier_leaks_in_nested_url(self):
        entry = self.entry()
        for _ in range(4):
            self.assertNotIn(self.settings.czl_client_secret, entry)
            self.assertNotIn(VERIFIER, entry)
            self.assertNotIn("client_secret=", entry)
            entry = unquote(entry)

    def test_wechat_desktop_routes_to_scan(self):
        entry = self.entry("wechat", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        self.assertEqual("/api/auth/upstream/wechat", urlsplit(entry).path)
        self.assertEqual(["pc"], parse_qs(urlsplit(entry).query)["device"])
        check_redirect("wechat", 303, entry, ISSUER)

    def test_wechat_mobile_follows_czl_device_selection(self):
        for agent in ("Mozilla/5.0 (iPhone) Mobile MicroMessenger", "Mozilla/5.0 (Linux; Android 14)"):
            with self.subTest(agent=agent):
                entry = self.entry("wechat", agent)
                self.assertEqual(["mobile"], parse_qs(urlsplit(entry).query)["device"])
                check_redirect("wechat", 303, entry, ISSUER)

    def test_fallback_keeps_standard_oauth_flow(self):
        with patch.object(external_oauth, "settings", replace(self.settings, czl_direct_upstream=False)):
            entry = self.entry()
        self.assertEqual("/oauth2/authorize", urlsplit(entry).path)
        self.assertEqual([STATE], parse_qs(urlsplit(entry).query)["state"])
        check_redirect("qq", 303, entry, ISSUER)

    def test_unknown_provider_is_rejected(self):
        with self.assertRaises(external_oauth.ExternalOAuthError):
            self.entry("qq/../../invalid")

    def test_unconfigured_credentials_still_fail_closed(self):
        with patch.object(external_oauth, "settings", replace(self.settings, czl_client_secret="")):
            with self.assertRaises(external_oauth.ExternalOAuthError):
                self.entry()

    def test_direct_mode_rejects_non_czl_authorization_origin(self):
        with patch.object(external_oauth, "settings", replace(self.settings, czl_authorize_endpoint="https://example.com/oauth2/authorize")):
            with self.assertRaises(external_oauth.ExternalOAuthError):
                self.entry()

    def test_readiness_rejects_wrong_upstream_route(self):
        with self.assertRaises(ValueError):
            check_redirect("qq", 303, self.entry().replace("/upstream/qq?", "/upstream/wechat?"), ISSUER)

    def test_readiness_rejects_cross_origin_continuation(self):
        outer = "https://connect.czl.net/api/auth/upstream/qq?"
        with self.assertRaises(ValueError):
            check_redirect("qq", 303, outer + urlencode({"redirect": "https://example.com/oauth2/authorize"}), ISSUER)

    def test_readiness_rejects_nested_secret(self):
        entry = self.entry()
        inner = parse_qs(urlsplit(entry).query)["redirect"][0] + "&client_secret=must-not-appear"
        with self.assertRaises(ValueError):
            check_redirect("qq", 303, "https://connect.czl.net/api/auth/upstream/qq?" + urlencode({"redirect": inner}), ISSUER)
        with self.assertRaises(ValueError):
            check_redirect("qq", 303, entry + "&code_verifier=must-not-appear", ISSUER)

    def test_readiness_rejects_ambiguous_redirect(self):
        with self.assertRaises(ValueError):
            check_redirect("qq", 303, self.entry() + "&redirect=https%3A%2F%2Fexample.com", ISSUER)

    def test_route_keeps_business_continuation_and_uses_mobile_header(self):
        from app.main import external_start
        request = Request({"type": "http", "headers": [(b"user-agent", b"Android Mobile")]})
        continuation = "/oauth/authorize?client_id=better-mc-web&state=original-state"
        with patch("app.main.store") as store:
            store.create_external_state.return_value = (STATE, VERIFIER)
            response = external_start("wechat", request, continuation)
            store.create_external_state.assert_called_once_with("wechat", continuation)
        self.assertEqual(303, response.status_code)
        self.assertEqual("no-store", response.headers["cache-control"])
        self.assertEqual(["mobile"], parse_qs(urlsplit(response.headers["location"]).query)["device"])
        self.assertEqual([STATE], self.inner(response.headers["location"])["state"])


if __name__ == "__main__":
    unittest.main()
