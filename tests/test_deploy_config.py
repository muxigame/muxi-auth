import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

from scripts.deploy_config import KEYS, merge_credentials, prepare
from scripts.check_external_auth import check_redirect


ISSUER = "https://account.muxigame.com"


class DeploymentConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.project = Path(self.tmp.name)
        self.env = self.project / ".env"
        self.original = b"MUXI_ISSUER=https://account.muxigame.com\nUNCHANGED=keep\n"
        self.env.write_bytes(self.original)
        self.compose = self.project / "compose.prod.yaml"
        self.compose.write_text("services: {}\n")

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def result(values):
        return subprocess.CompletedProcess([], 0, json.dumps({
            "services": {"muxi-auth": {"environment": values}}
        }), "")

    def test_no_ci_secrets_preserves_server_environment(self):
        values = dict(zip(KEYS, ["test-client", "test-secret"]))
        values["MUXI_ISSUER"] = ISSUER
        with patch("scripts.deploy_config.subprocess.run", return_value=self.result(values)):
            prepare(self.project, self.compose, {})
        self.assertEqual(self.original, self.env.read_bytes())

    def test_aliases_are_supported_for_existing_environment(self):
        values = {"Client_ID": "test-id", "Client_Secret": "test-secret", "MUXI_ISSUER": ISSUER}
        with patch("scripts.deploy_config.subprocess.run", return_value=self.result(values)):
            prepare(self.project, self.compose, {})

    def test_missing_production_credentials_fails(self):
        with patch("scripts.deploy_config.subprocess.run", return_value=self.result({"MUXI_ISSUER": ISSUER})):
            with self.assertRaises(ValueError):
                prepare(self.project, self.compose, {})
        self.assertEqual(self.original, self.env.read_bytes())

    def test_partial_ci_secret_pair_fails_without_writing(self):
        with self.assertRaises(ValueError):
            prepare(self.project, self.compose, {KEYS[0]: "test-id"})
        self.assertEqual(self.original, self.env.read_bytes())

    def test_complete_ci_pair_has_backup_and_preserves_other_keys(self):
        updates = dict(zip(KEYS, ["test-id", "test-secret"]))
        values = {**updates, "MUXI_ISSUER": ISSUER}
        with patch("scripts.deploy_config.subprocess.run", return_value=self.result(values)):
            prepare(self.project, self.compose, updates)
        self.assertIn("UNCHANGED=keep", self.env.read_text())
        backups = list((self.project / "incoming" / "config-backups").iterdir())
        self.assertEqual(1, len(backups))
        self.assertEqual(self.original, backups[0].read_bytes())

    def test_resolution_error_rolls_back_new_configuration(self):
        updates = dict(zip(KEYS, ["test-id", "test-secret"]))
        result = subprocess.CompletedProcess([], 1, "", "do not log resolved configuration")
        with patch("scripts.deploy_config.subprocess.run", return_value=result):
            with self.assertRaises(ValueError):
                prepare(self.project, self.compose, updates)
        self.assertEqual(self.original, self.env.read_bytes())

    def test_incorrect_callback_origin_fails(self):
        values = {**dict(zip(KEYS, ["test-id", "test-secret"])), "MUXI_ISSUER": "http://localhost:9000"}
        with patch("scripts.deploy_config.subprocess.run", return_value=self.result(values)):
            with self.assertRaises(ValueError):
                prepare(self.project, self.compose, {})

    def test_dotenv_quotes_dollar_signs_and_rejects_newlines(self):
        text = merge_credentials("KEEP=yes\n", {KEYS[1]: 'test-$literal-"quote"-\\'})
        self.assertIn('$$literal', text)
        self.assertIn('\\"quote\\"', text)
        with self.assertRaises(ValueError):
            merge_credentials("", {KEYS[1]: "bad\nvalue"})


class ExternalReadinessTests(unittest.TestCase):
    def url(self, provider="qq", **overrides):
        values = {
            "response_type": "code", "client_id": "test-id", "state": "test-state",
            "redirect_uri": ISSUER + "/external/czl/callback",
            "upstream_providers": provider, "code_challenge_method": "S256",
            "code_challenge": "test-challenge",
        }
        values.update(overrides)
        return "https://connect.czl.net/oauth2/authorize?" + urlencode(values)

    def test_qq_and_wechat_ready_redirects(self):
        for provider in ("qq", "wechat"):
            check_redirect(provider, 303, self.url(provider), ISSUER)

    def test_503_is_not_successful_deployment(self):
        with self.assertRaises(ValueError):
            check_redirect("qq", 503, "", ISSUER)

    def test_incorrect_callback_is_rejected(self):
        with self.assertRaises(ValueError):
            check_redirect("qq", 303, self.url(redirect_uri="https://example.com/callback"), ISSUER)

    def test_secret_in_authorization_url_is_rejected(self):
        with self.assertRaises(ValueError):
            check_redirect("qq", 303, self.url(client_secret="test-secret"), ISSUER)


if __name__ == "__main__":
    unittest.main()
